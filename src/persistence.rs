use crate::config_model::ServerConfig;
use kodegen_mcp_schema::McpError;
use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

// ============================================================================
// PROFILING INSTRUMENTATION
// ============================================================================

/// Counter for tracking config write frequency
static CONFIG_WRITE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Start time for calculating write rate
static CONFIG_WRITE_START: OnceLock<std::time::Instant> = OnceLock::new();

/// Counter for tracking config save failures (for observability)
///
/// Incremented atomically whenever the background saver fails to write config to disk.
/// Exposed via `ConfigManager::get_save_error_count()` for monitoring.
pub(crate) static CONFIG_SAVE_ERRORS: AtomicUsize = AtomicUsize::new(0);

// ============================================================================
// PERSISTENCE OPERATIONS
// ============================================================================

/// Save configuration to disk with profiling instrumentation
///
/// # Errors
/// Returns error if config cannot be serialized or written to disk
pub(crate) async fn save_to_disk(
    config: &Arc<RwLock<ServerConfig>>,
    config_path: &PathBuf,
) -> Result<(), McpError> {
    // Profiling instrumentation
    let start_time = CONFIG_WRITE_START.get_or_init(std::time::Instant::now);
    let count = CONFIG_WRITE_COUNT.fetch_add(1, Ordering::Relaxed);

    if count.is_multiple_of(10) {
        let elapsed = start_time.elapsed().as_secs();
        let rate = if elapsed > 0 {
            f64::from(u32::try_from(count).unwrap_or(u32::MAX)) / elapsed as f64 * 60.0
        } else {
            0.0
        };
        log::info!("Config writes: {count} total ({rate:.2}/min)");
    }

    // Existing save logic
    let json = {
        let config = config.read();
        serde_json::to_string_pretty(&*config)?
    };
    tokio::fs::write(config_path, json).await?;
    Ok(())
}

/// Background task that debounces config saves
///
/// Pattern copied from packages/utils/src/usage_tracker.rs:154-234
pub(crate) fn start_background_saver(
    config: Arc<RwLock<ServerConfig>>,
    config_path: PathBuf,
    mut save_receiver: tokio::sync::mpsc::UnboundedReceiver<()>,
) {
    tokio::spawn(async move {
        // Debounce: wait 300ms after last change
        const DEBOUNCE_MS: u64 = 300;

        let mut has_pending_save = false;
        let mut last_save_request = std::time::Instant::now();

        loop {
            tokio::select! {
                // Receive save request from set_value() or set_client_info()
                Some(()) = save_receiver.recv() => {
                    has_pending_save = true;
                    last_save_request = std::time::Instant::now();
                }

                // Check every 100ms if debounce period has passed
                () = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                    if has_pending_save && last_save_request.elapsed().as_millis() >= u128::from(DEBOUNCE_MS) {
                        // Perform batched save
                        let json = {
                            let cfg = config.read();
                            match serde_json::to_string_pretty(&*cfg) {
                                Ok(j) => j,
                                Err(e) => {
                                    log::error!("Failed to serialize config: {e}");
                                    continue;
                                }
                            }
                        };

                        if let Err(e) = tokio::fs::write(&config_path, json).await {
                            let error_count = CONFIG_SAVE_ERRORS.fetch_add(1, Ordering::Relaxed) + 1;
                            log::error!("Failed to save config (total failures: {error_count}): {e}");
                        }

                        has_pending_save = false;
                    }
                }

                // Channel closed (server shutdown)
                else => {
                    // Final flush before exit
                    if has_pending_save {
                        let json = {
                            let cfg = config.read();
                            serde_json::to_string_pretty(&*cfg).unwrap_or_default()
                        };
                        let _ = tokio::fs::write(&config_path, json).await;
                    }
                    break;
                }
            }
        }
    });
}

/// Get total count of config save failures since server start
///
/// This counter tracks background save failures (disk write errors).
/// Used for observability and monitoring config persistence issues.
#[must_use]
pub fn get_save_error_count() -> usize {
    CONFIG_SAVE_ERRORS.load(Ordering::Relaxed)
}
