use crate::config_model::ServerConfig;
use kodegen_mcp_schema::McpError;
use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, AtomicU64, AtomicBool, Ordering};
use tempfile::NamedTempFile;
use std::io::Write;

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

/// Save config with automatic backup rotation and atomic write
///
/// Backup strategy (Git-inspired):
/// - config.json          (current)
/// - config.json.backup   (N-1 generation)
/// - config.json.backup.1 (N-2 generation)
/// - config.json.backup.2 (N-3 generation)
/// - config.json.backup.3 (N-4 generation, oldest)
///
/// Write order ensures safety:
/// 1. Rotate existing backups (oldest deleted)
/// 2. Copy current config to .backup
/// 3. Atomic write new config
///
/// # Errors
/// Returns error if config cannot be serialized or written to disk
pub(crate) async fn save_to_disk(
    config: &Arc<RwLock<ServerConfig>>,
    config_path: &PathBuf,
) -> Result<(), McpError> {
    // Profiling instrumentation (keep existing code)
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

    // Serialize config BEFORE rotation/write
    let json = {
        let config = config.read();
        serde_json::to_string_pretty(&*config)?
    };
    
    // Create parent directory if missing
    if let Some(parent) = config_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    
    // STEP 1: Rotate backups BEFORE writing new config
    // This ensures we always have historical copies in case of corruption
    rotate_backups(config_path, 3).await?;
    
    // STEP 2: Atomic write using tempfile + fsync + atomic rename
    let config_path_clone = config_path.clone();
    let json_clone = json.clone();
    
    tokio::task::spawn_blocking(move || {
        // Write to temporary file in SAME DIRECTORY (ensures same filesystem)
        let parent = config_path_clone.parent().ok_or_else(|| {
            McpError::Other(anyhow::anyhow!("Config path has no parent directory"))
        })?;
        
        let mut temp_file = NamedTempFile::new_in(parent)?;
        
        // Write full content
        temp_file.write_all(json_clone.as_bytes())?;
        
        // CRITICAL: fsync to ensure data is on disk before rename
        temp_file.as_file().sync_all()?;
        
        // ATOMIC RENAME (POSIX atomic operation)
        temp_file.persist(&config_path_clone)?;
        
        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|e| McpError::Other(anyhow::anyhow!("Spawn blocking failed: {}", e)))??;
    
    Ok(())
}

/// Rotate backup files: .backup → .backup.1 → .backup.2 → .backup.3 → deleted
///
/// Rotation strategy (same as Git pack rotation):
/// - Delete oldest (.backup.3)
/// - Shift all numbered backups up by 1
/// - Move primary .backup to .backup.1
/// - Copy current config.json to .backup
///
/// # Arguments
/// * `config_path` - Path to config.json
/// * `max_backups` - Number of generations to keep (recommended: 3)
async fn rotate_backups(config_path: &PathBuf, max_backups: usize) -> Result<(), McpError> {
    // Rotate numbered backups: .backup.N → .backup.N+1
    // Start from highest number and work down to avoid overwriting
    for i in (1..max_backups).rev() {
        let old_backup = backup_path(config_path, Some(i));
        let new_backup = backup_path(config_path, Some(i + 1));
        
        if old_backup.exists() {
            // Ignore errors - backup might not exist, that's fine
            let _ = tokio::fs::rename(&old_backup, &new_backup).await;
        }
    }
    
    // Rotate primary backup: .backup → .backup.1
    let primary_backup = backup_path(config_path, None);
    let backup_1 = backup_path(config_path, Some(1));
    if primary_backup.exists() {
        let _ = tokio::fs::rename(&primary_backup, &backup_1).await;
    }
    
    // Copy current config to primary backup: config.json → config.json.backup
    // This creates the "last known good" backup
    if config_path.exists() {
        tokio::fs::copy(config_path, &primary_backup).await?;
    }
    
    Ok(())
}

/// Generate backup file path
///
/// # Arguments
/// * `config_path` - Original config.json path
/// * `index` - None for .backup, Some(N) for .backup.N
///
/// # Examples
/// ```
/// backup_path("/config/config.json", None)      → "/config/config.json.backup"
/// backup_path("/config/config.json", Some(1))   → "/config/config.json.backup.1"
/// backup_path("/config/config.json", Some(2))   → "/config/config.json.backup.2"
/// ```
pub(crate) fn backup_path(config_path: &std::path::Path, index: Option<usize>) -> PathBuf {
    match index {
        None => {
            let mut path = config_path.as_os_str().to_os_string();
            path.push(".backup");
            PathBuf::from(path)
        }
        Some(n) => {
            let mut path = config_path.as_os_str().to_os_string();
            path.push(format!(".backup.{}", n));
            PathBuf::from(path)
        }
    }
}

/// Save request with generation tracking
///
/// Used by set_value() and set_client_info() to request async saves.
/// The background saver only persists if the current generation is newer
/// than what's already on disk (prevents stale writes).
pub(crate) struct SaveRequest {
    /// Minimum generation number that must be persisted
    /// Any generation >= this value satisfies the request
    pub min_generation: u64,
}

/// Background task that debounces config saves with generation tracking
///
/// Prevents stale writes using optimistic concurrency control:
/// - Tracks `last_persisted_gen` to avoid redundant writes
/// - Only writes if `current_gen > last_persisted_gen`
/// - Reads config and generation atomically to prevent race conditions
pub(crate) fn start_background_saver(
    config: Arc<RwLock<ServerConfig>>,
    config_path: PathBuf,
    mut save_receiver: tokio::sync::mpsc::UnboundedReceiver<SaveRequest>,
    generation: Arc<AtomicU64>,
    saving: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        const DEBOUNCE_MS: u64 = 300;
        
        // Track the last generation we successfully persisted
        let mut last_persisted_gen: u64 = 0;
        
        // Track pending save requests
        let mut pending_gen: Option<u64> = None;
        let mut last_request_time = std::time::Instant::now();
        
        loop {
            tokio::select! {
                // Receive save request from set_value()
                Some(req) = save_receiver.recv() => {
                    // Update pending generation to MAX of all requests
                    // This ensures we eventually save the latest version
                    pending_gen = Some(
                        pending_gen
                            .map(|g| g.max(req.min_generation))
                            .unwrap_or(req.min_generation)
                    );
                    last_request_time = std::time::Instant::now();
                    log::trace!("Save requested for generation {}", req.min_generation);
                }
                
                // Check every 100ms if debounce period has passed
                () = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                    if let Some(required_gen) = pending_gen {
                        // Check if debounce period elapsed
                        if last_request_time.elapsed().as_millis() >= u128::from(DEBOUNCE_MS) {
                            // Only save if we haven't already persisted this generation
                            if required_gen > last_persisted_gen {
                                // CRITICAL: Read config and generation atomically
                                // This prevents the race condition from Race #1
                                let (json, read_gen) = {
                                    let cfg = config.read();
                                    let current_gen = generation.load(Ordering::SeqCst);
                                    
                                    let json = serde_json::to_string_pretty(&*cfg)
                                        .unwrap_or_else(|e| {
                                            log::error!("Failed to serialize config: {}", e);
                                            String::new()
                                        });
                                    
                                    (json, current_gen)
                                }; // ← Lock released here, but we have snapshot
                                
                                if json.is_empty() {
                                    pending_gen = None;
                                    continue; // Skip bad serialization
                                }
                                
                                // Signal file watcher to ignore events during save
                                saving.store(true, Ordering::SeqCst);
                                
                                // Perform save using save_to_disk (includes backup rotation)
                                if let Err(e) = save_to_disk(&config, &config_path).await {
                                    log::error!("Failed to save config: {}", e);
                                    CONFIG_SAVE_ERRORS.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    // Success - update last persisted generation
                                    last_persisted_gen = read_gen;
                                    log::debug!("Saved config generation {} to disk", read_gen);
                                }
                                
                                // Wait briefly for filesystem propagation before resuming watcher
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                saving.store(false, Ordering::SeqCst);
                            } else {
                                log::trace!(
                                    "Skipping save: generation {} already persisted",
                                    required_gen
                                );
                            }
                            
                            pending_gen = None;
                        }
                    }
                }
                
                // Channel closed (server shutdown)
                else => {
                    log::info!("Background saver shutting down");
                    
                    // Final flush before exit
                    if let Some(required_gen) = pending_gen
                        && required_gen > last_persisted_gen {
                            let _ = save_to_disk(&config, &config_path).await;
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
