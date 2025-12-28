use crate::config_model::ServerConfig;
use crate::env_loader::{load_allowed_dirs_from_env, load_denied_dirs_from_env};
use crate::persistence;
use crate::persistence::{backup_path, SaveRequest};
use crate::system_info::{ClientInfo, get_system_info, SystemInfo};
use crate::watcher::ConfigWatcher;
use crate::ConfigValueExt;
use kodegen_config::KodegenConfig;
use kodegen_mcp_schema::McpError;
use kodegen_mcp_schema::config::ConfigValue;
use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::Instant;
use anyhow::anyhow;

// ============================================================================
// SYSTEM INFO CACHING
// ============================================================================

/// Cached system info with timestamp for TTL-based refresh
///
/// Pattern: Similar to CONFIG_WRITE_START in persistence.rs
/// - OnceLock for static initialization
/// - Mutex for interior mutability
/// - 5-second TTL to balance freshness vs syscall overhead
static SYSTEM_INFO_CACHE: OnceLock<Mutex<(SystemInfo, Instant)>> = OnceLock::new();

/// Refresh interval for system info (5 seconds)
const SYSTEM_INFO_CACHE_TTL_SECS: u64 = 5;

/// Get system info with TTL-based caching
///
/// Avoids excessive syscalls by caching for 5 seconds.
/// First call initializes cache, subsequent calls refresh if stale.
fn get_cached_system_info() -> SystemInfo {
    let cache = SYSTEM_INFO_CACHE.get_or_init(|| {
        Mutex::new((get_system_info(), Instant::now()))
    });
    
    let mut guard = cache.lock().unwrap();
    
    // Refresh if cache is stale
    if guard.1.elapsed().as_secs() >= SYSTEM_INFO_CACHE_TTL_SECS {
        guard.0 = get_system_info();
        guard.1 = Instant::now();
    }
    
    guard.0.clone()
}

// ============================================================================
// CONFIG MANAGER
// ============================================================================

/// ## Lock Ordering Invariant
///
/// To prevent deadlock, ALL methods acquiring multiple locks MUST respect
/// this canonical ordering:
///
/// ```text
/// 1. reload_mutex (coarse-grained serialization)
/// 2. config (fine-grained data access)
/// ```
///
/// **CRITICAL**: Never hold `config` write lock while requesting `reload_mutex`.
///
/// ## Atomic Operation Ordering
///
/// Atomic operations follow happens-before relationships:
///
/// ```text
/// set_value() → increment generation → send SaveRequest
///     ↓
/// background_saver receives → read config + generation → write disk
/// ```
///
/// Sequential consistency (`Ordering::SeqCst`) ensures all threads see
/// generation increments in the same order.
///
/// ## Concurrent Safety
///
/// - `config`: RwLock allows multiple concurrent readers, single writer
/// - `generation`: AtomicU64 provides lock-free increment
/// - `saving`: AtomicBool prevents file watcher self-trigger
/// - `reload_mutex`: Serializes reload operations
/// - `save_sender`: UnboundedSender is lock-free
#[derive(Clone)]
pub struct ConfigManager {
    config: Arc<RwLock<ServerConfig>>,
    config_path: PathBuf,

    // Debouncing field for fire-and-forget saves
    save_sender: tokio::sync::mpsc::UnboundedSender<SaveRequest>,
    
    // NEW: Optimistic concurrency control fields
    /// Generation counter for tracking config versions
    /// Incremented atomically on every modification
    /// Used to prevent stale writes (see Race #1)
    generation: Arc<AtomicU64>,
    
    /// Flag to pause file watcher during programmatic saves
    /// Prevents self-trigger reload loop (see Race #2)
    saving: Arc<AtomicBool>,
    
    /// Mutex to serialize reload operations
    /// Prevents concurrent reloads (see Race #3)
    reload_mutex: Arc<tokio::sync::Mutex<()>>,
    
    // Optional file watcher for automatic config reload
    watcher: Option<Arc<ConfigWatcher>>,
}

impl ConfigManager {
    #[must_use]
    pub fn new() -> Self {
        let config_path = KodegenConfig::user_config_dir()
            .map(|dir| dir.join("config.json"))
            .unwrap_or_else(|_| PathBuf::from(".kodegen/config.json"));

        // Create channel for debounced saves
        let (save_sender, save_receiver) = tokio::sync::mpsc::unbounded_channel();

        let config = Arc::new(RwLock::new(ServerConfig::default()));
        
        // Initialize generation counter
        let generation = Arc::new(AtomicU64::new(0));
        let saving = Arc::new(AtomicBool::new(false));
        let reload_mutex = Arc::new(tokio::sync::Mutex::new(()));

        // Start background saver task with generation tracking
        persistence::start_background_saver(
            Arc::clone(&config),
            config_path.clone(),
            save_receiver,
            Arc::clone(&generation),
            Arc::clone(&saving),
        );

        Self {
            config,
            config_path,
            save_sender,
            generation,
            saving,
            reload_mutex,
            watcher: None,
        }
    }

    /// Initialize configuration from disk and environment variables
    ///
    /// # Errors
    /// Returns error if config directory cannot be created or config file cannot be read/written
    pub async fn init(&self) -> Result<(), McpError> {
        if let Some(config_dir) = self.config_path.parent() {
            tokio::fs::create_dir_all(config_dir).await?;
        }

        // Load from disk with automatic recovery cascade
        let mut loaded_config = load_with_recovery(&self.config_path).await?;

        // OVERRIDE with environment variables (for security)
        let env_allowed = load_allowed_dirs_from_env();
        let env_denied = load_denied_dirs_from_env();

        if !env_allowed.is_empty() {
            loaded_config.allowed_directories = env_allowed;
            log::info!(
                "Loaded {} allowed directories from KODEGEN_ALLOWED_DIRS",
                loaded_config.allowed_directories.len()
            );
        }

        if !env_denied.is_empty() {
            loaded_config.denied_directories = env_denied;
            log::info!(
                "Loaded {} denied directories from KODEGEN_DENIED_DIRS",
                loaded_config.denied_directories.len()
            );
        }

        // IMPORTANT: Re-detect shell on every startup (runtime detection)
        // User may have changed their shell preference between runs
        // Only update if detection result differs (preserves manual user customization)
        let detected_shell = crate::shell_detection::detect_user_shell();
        if loaded_config.default_shell != detected_shell {
            log::info!(
                "🔄 Shell preference changed: {} → {}",
                loaded_config.default_shell,
                detected_shell
            );
            loaded_config.default_shell = detected_shell;
        } else {
            log::debug!("✓ Shell preference unchanged: {}", detected_shell);
        }

        *self.config.write() = loaded_config;
        persistence::save_to_disk(&self.config, &self.config_path).await?;
        Ok(())
    }

    /// Reload configuration from disk
    ///
    /// Re-reads the config file and updates in-memory state.
    /// Serialized with mutex to prevent concurrent reloads (Race #3).
    /// Uses the same recovery cascade as init() to handle corruption.
    /// Environment variable overrides (KODEGEN_ALLOWED_DIRS, KODEGEN_DENIED_DIRS)
    /// are preserved and re-applied after loading.
    ///
    /// # Errors
    /// Returns error if config file cannot be read or parsed
    pub async fn reload(&self) -> Result<(), McpError> {
        // CRITICAL: Acquire reload mutex to prevent concurrent reloads
        // This solves Race #3: Concurrent Init + Reload
        let _guard = self.reload_mutex.lock().await;
        
        log::info!("Reloading configuration from {:?}", self.config_path);
        
        // Use recovery cascade (same as init)
        let mut loaded_config = load_with_recovery(&self.config_path).await?;
        
        // PRESERVE environment variable overrides (security critical)
        let env_allowed = load_allowed_dirs_from_env();
        let env_denied = load_denied_dirs_from_env();
        
        if !env_allowed.is_empty() {
            loaded_config.allowed_directories = env_allowed;
            log::info!(
                "Preserved {} allowed directories from KODEGEN_ALLOWED_DIRS",
                loaded_config.allowed_directories.len()
            );
        }
        
        if !env_denied.is_empty() {
            loaded_config.denied_directories = env_denied;
            log::info!(
                "Preserved {} denied directories from KODEGEN_DENIED_DIRS",
                loaded_config.denied_directories.len()
            );
        }
        
        // PRESERVE transient state (client connections are runtime-only)
        // These fields may not be persisted yet due to debouncing
        let (current_client, client_history) = {
            let cfg = self.config.read();
            (cfg.current_client.clone(), cfg.client_history.clone())
        };

        // Restore preserved state to loaded config
        loaded_config.current_client = current_client;
        loaded_config.client_history = client_history;

        // Update in-memory config atomically
        {
            let mut config = self.config.write();
            *config = loaded_config;
        }
        
        // Increment generation to mark this as a new version
        let new_gen = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        
        log::info!("Configuration reloaded successfully (generation {})", new_gen);
        Ok(())
    }

    /// Enable automatic config file watching
    ///
    /// Starts monitoring the config file for changes. When changes are detected
    /// (after 1-second debounce), automatically calls `reload()`.
    ///
    /// This is optional and should be enabled via CLI flag (e.g., `--watch-config`).
    ///
    /// # Errors
    /// Returns error if file watching cannot be initialized
    pub async fn enable_file_watching(&mut self) -> Result<(), McpError> {
        if self.watcher.is_some() {
            log::warn!("File watching already enabled");
            return Ok(());
        }
        
        // Create reload channel
        let (reload_tx, mut reload_rx) = tokio::sync::mpsc::unbounded_channel();
        
        // Start file watcher with saving flag
        let watcher = ConfigWatcher::new(
            self.config_path.clone(),
            reload_tx,
            Arc::clone(&self.saving),
        )
        .map_err(|e| McpError::Other(anyhow!("Failed to start file watcher: {}", e)))?;
        
        self.watcher = Some(Arc::new(watcher));
        
        // Spawn background task to handle reload signals
        let config_manager = self.clone();
        tokio::spawn(async move {
            while reload_rx.recv().await.is_some() {
                if let Err(e) = config_manager.reload().await {
                    log::error!("Config reload failed: {}", e);
                    // Continue running with old config (fail-safe)
                }
            }
        });
        
        log::info!("Config file watching enabled");
        Ok(())
    }

    #[must_use]
    pub fn get_config(&self) -> ServerConfig {
        let mut config = self.config.read().clone();
        
        // CRITICAL: Always provide fresh system info
        config.system_info = get_cached_system_info();
        
        config
    }

    #[must_use]
    pub fn get_file_read_line_limit(&self) -> usize {
        self.config.read().file_read_line_limit
    }

    #[must_use]
    pub fn get_file_write_line_limit(&self) -> usize {
        self.config.read().file_write_line_limit
    }

    #[must_use]
    pub fn get_blocked_commands(&self) -> Vec<String> {
        self.config.read().blocked_commands.clone()
    }

    #[must_use]
    pub fn get_fuzzy_search_threshold(&self) -> f64 {
        self.config.read().fuzzy_search_threshold
    }

    #[must_use]
    pub fn get_http_connection_timeout_secs(&self) -> u64 {
        self.config.read().http_connection_timeout_secs
    }

    #[must_use]
    pub fn get_path_validation_timeout_ms(&self) -> u64 {
        self.config.read().path_validation_timeout_ms
    }

    #[must_use]
    pub fn get_value(&self, key: &str) -> Option<ConfigValue> {
        let config = self.config.read();
        match key {
            "blocked_commands" => Some(ConfigValue::Array(config.blocked_commands.clone())),
            "default_shell" => Some(ConfigValue::String(config.default_shell.clone())),
            "allowed_directories" => Some(ConfigValue::Array(config.allowed_directories.clone())),
            "denied_directories" => Some(ConfigValue::Array(config.denied_directories.clone())),
            "file_read_line_limit" => Some(ConfigValue::Number(
                i64::try_from(config.file_read_line_limit).unwrap_or(i64::MAX),
            )),
            "file_write_line_limit" => Some(ConfigValue::Number(
                i64::try_from(config.file_write_line_limit).unwrap_or(i64::MAX),
            )),
            "fuzzy_search_threshold" => Some(ConfigValue::Number(
                (config.fuzzy_search_threshold * 100.0) as i64,
            )),
            "http_connection_timeout_secs" => Some(ConfigValue::Number(
                i64::try_from(config.http_connection_timeout_secs).unwrap_or(i64::MAX),
            )),
            "path_validation_timeout_ms" => Some(ConfigValue::Number(
                i64::try_from(config.path_validation_timeout_ms).unwrap_or(i64::MAX),
            )),
            _ => None,
        }
    }

    /// Set a configuration value by key
    ///
    /// Thread-safe with generation tracking to prevent lost updates.
    /// Increments generation counter atomically after modification.
    ///
    /// # Errors
    /// Returns error if the key is unknown, value type is invalid, or config cannot be saved
    pub async fn set_value(&self, key: &str, value: ConfigValue) -> Result<(), McpError> {
        // Perform modification and capture new generation atomically
        let new_generation = {
            let mut config = self.config.write();
            
            // Apply the configuration change
            match key {
                "blocked_commands" => {
                    config.blocked_commands = value.into_array().map_err(McpError::InvalidArguments)?;
                }
                "default_shell" => {
                    let shell_path = value.into_string().map_err(McpError::InvalidArguments)?;
                    
                    // Validate shell exists and is executable
                    crate::shell_detection::validate_shell_path(&shell_path)
                        .map_err(McpError::InvalidArguments)?;
                    
                    config.default_shell = shell_path;
                }
                "allowed_directories" => {
                    config.allowed_directories = value.into_array().map_err(McpError::InvalidArguments)?;
                }
                "denied_directories" => {
                    config.denied_directories = value.into_array().map_err(McpError::InvalidArguments)?;
                }
                "file_read_line_limit" => {
                    let num = value.into_number().map_err(McpError::InvalidArguments)?;
                    if num <= 0 {
                        return Err(McpError::InvalidArguments(
                            "file_read_line_limit must be positive".to_string(),
                        ));
                    }
                    config.file_read_line_limit = usize::try_from(num).map_err(|_| {
                        McpError::InvalidArguments(
                            "file_read_line_limit value out of range".to_string(),
                        )
                    })?;
                }
                "file_write_line_limit" => {
                    let num = value.into_number().map_err(McpError::InvalidArguments)?;
                    if num <= 0 {
                        return Err(McpError::InvalidArguments(
                            "file_write_line_limit must be positive".to_string(),
                        ));
                    }
                    config.file_write_line_limit = usize::try_from(num).map_err(|_| {
                        McpError::InvalidArguments(
                            "file_write_line_limit value out of range".to_string(),
                        )
                    })?;
                }
                "fuzzy_search_threshold" => {
                    let num = value.into_number().map_err(McpError::InvalidArguments)?;
                    if !(0..=100).contains(&num) {
                        return Err(McpError::InvalidArguments(
                            "fuzzy_search_threshold must be between 0 and 100".to_string(),
                        ));
                    }
                    config.fuzzy_search_threshold = (num as f64) / 100.0;
                }
                "http_connection_timeout_secs" => {
                    let num = value.into_number().map_err(McpError::InvalidArguments)?;
                    if num <= 0 {
                        return Err(McpError::InvalidArguments(
                            "http_connection_timeout_secs must be positive".to_string(),
                        ));
                    }
                    config.http_connection_timeout_secs = u64::try_from(num).map_err(|_| {
                        McpError::InvalidArguments(
                            "http_connection_timeout_secs value out of range".to_string(),
                        )
                    })?;
                }
                "path_validation_timeout_ms" => {
                    let num = value.into_number().map_err(McpError::InvalidArguments)?;
                    if num <= 0 {
                        return Err(McpError::InvalidArguments(
                            "path_validation_timeout_ms must be positive".to_string(),
                        ));
                    }
                    if num > 600_000 {
                        return Err(McpError::InvalidArguments(
                            "path_validation_timeout_ms cannot exceed 600000ms (10 minutes)".to_string(),
                        ));
                    }
                    config.path_validation_timeout_ms = u64::try_from(num).map_err(|_| {
                        McpError::InvalidArguments(
                            "path_validation_timeout_ms value out of range".to_string(),
                        )
                    })?;
                }
                _ => {
                    return Err(McpError::InvalidArguments(format!(
                        "Unknown config key: {key}"
                    )));
                }
            }
            
            // Validate entire config after modification
            config.validate_and_repair()
                .map_err(|e| McpError::Other(anyhow::anyhow!("Validation failed: {}", e)))?;
            
            // Increment generation AFTER successful modification
            // This ensures every config change gets a unique version number
            self.generation.fetch_add(1, Ordering::SeqCst) + 1
        }; // ← Lock released here

        // Request save with generation tracking
        // Fire-and-forget: failures logged but not propagated
        let _ = self.save_sender.send(SaveRequest {
            min_generation: new_generation,
        });
        
        log::debug!("Config modified, generation {}", new_generation);
        Ok(())
    }

    /// Store client information from MCP initialization
    ///
    /// Updates in-memory state immediately and queues async save to disk.
    /// Disk write errors are logged but not propagated (fire-and-forget pattern).
    /// Use `get_save_error_count()` to check for save failures.
    pub async fn set_client_info(&self, client_info: ClientInfo) {
        let new_generation = {
            let mut config = self.config.write();
            let now = chrono::Utc::now();

            // Update or create client history record
            let existing = config.client_history.iter_mut().find(|r| {
                r.client_info.name == client_info.name
                    && r.client_info.version == client_info.version
            });

            if let Some(record) = existing {
                // Update existing record's last_seen timestamp
                record.last_seen = now;
            } else {
                // BOUNDED GROWTH: Prune old entries before adding new one
                // Strategy: FIFO (First In, First Out) with batch removal
                // - Maximum: 100 entries
                // - Prune trigger: When reaching 100 entries
                // - Prune amount: Remove oldest 50 entries
                // - Result: Keeps 51 entries (50 old + 1 new)
                
                if config.client_history.len() >= 100 {
                    // Remove oldest 50 entries (indices 0..50)
                    // drain(0..50) removes and drops the first 50 elements
                    config.client_history.drain(0..50);
                    log::info!(
                        "Pruned client_history: removed 50 oldest entries, {} remaining",
                        config.client_history.len()
                    );
                }
                
                // Add new client record
                config.client_history.push(crate::system_info::ClientRecord {
                    client_info: client_info.clone(),
                    connected_at: now,
                    last_seen: now,
                });
            }

            // Set as current client
            config.current_client = Some(client_info);
            
            // Increment generation and return
            self.generation.fetch_add(1, Ordering::SeqCst) + 1
        };

        // Fire-and-forget debounced save with generation tracking
        let _ = self.save_sender.send(SaveRequest {
            min_generation: new_generation,
        });
    }

    /// Get current client information
    #[must_use]
    pub fn get_client_info(&self) -> Option<ClientInfo> {
        self.config.read().current_client.clone()
    }

    /// Get client connection history
    #[must_use]
    pub fn get_client_history(&self) -> Vec<crate::system_info::ClientRecord> {
        self.config.read().client_history.clone()
    }

    /// Get total count of config save failures since server start
    ///
    /// This counter tracks background save failures (disk write errors).
    /// Used for observability and monitoring config persistence issues.
    #[must_use]
    pub fn get_save_error_count() -> usize {
        persistence::get_save_error_count()
    }
}

// ============================================================================
// CONFIG RECOVERY HELPERS
// ============================================================================

/// Load config with automatic backup recovery cascade
///
/// Recovery strategy:
/// 1. Try main config.json
/// 2. Try config.json.backup (last known good)
/// 3. Try config.json.backup.1 (previous generation)
/// 4. Try config.json.backup.2 (older generation)
/// 5. Try config.json.backup.3 (oldest generation)
/// 6. Fall back to defaults with warning
///
/// On successful recovery from backup, automatically restore to main config file.
async fn load_with_recovery(config_path: &PathBuf) -> Result<ServerConfig, McpError> {
    // Try to load current config
    match try_load_config(config_path).await {
        Ok(config) => {
            log::info!("✓ Loaded config from {}", config_path.display());
            return Ok(config);
        }
        Err(e) => {
            log::error!(
                "✗ Failed to load config from {}: {}",
                config_path.display(),
                e
            );
            log::warn!("→ Attempting recovery from backup files...");
        }
    }
    
    // Try backups in order: .backup → .backup.1 → .backup.2 → .backup.3
    for backup_index in [None, Some(1), Some(2), Some(3)] {
        let backup_path_buf = backup_path(config_path, backup_index);
        
        if !backup_path_buf.exists() {
            continue;
        }
        
        log::info!("→ Trying backup: {}", backup_path_buf.display());
        
        match try_load_config(&backup_path_buf).await {
            Ok(config) => {
                log::warn!(
                    "✓ Recovered config from backup: {}",
                    backup_path_buf.display()
                );
                log::warn!(
                    "→ Restoring backup to main config file: {}",
                    config_path.display()
                );
                
                // Restore backup to main config location
                // This ensures the next startup uses the recovered config
                tokio::fs::copy(&backup_path_buf, config_path).await?;
                
                return Ok(config);
            }
            Err(e) => {
                log::error!(
                    "✗ Backup {} also corrupted: {}",
                    backup_path_buf.display(),
                    e
                );
            }
        }
    }
    
    // All backups failed - use defaults
    log::error!("❌ All config backups corrupted or missing!");
    log::error!("→ Main config: FAILED");
    log::error!("→ .backup: FAILED");
    log::error!("→ .backup.1: FAILED");
    log::error!("→ .backup.2: FAILED");
    log::error!("→ .backup.3: FAILED");
    log::warn!("🔄 Creating fresh config with defaults");
    log::warn!("⚠️  All previous settings and client history lost");
    
    Ok(ServerConfig::default())
}

/// Try to load and validate a config file
///
/// Performs both JSON parsing and semantic validation with automatic migration.
///
/// # Errors
/// Returns error if:
/// - File cannot be read
/// - JSON is malformed
/// - Migration fails
/// - Config values are invalid (validation fails)
async fn try_load_config(path: &PathBuf) -> Result<ServerConfig, anyhow::Error> {
    use anyhow::Context;
    
    let content = tokio::fs::read_to_string(path)
        .await
        .context("Failed to read config file")?;
    
    // Use migration framework (handles v0→v1 automatically and validates)
    let config = crate::migration::load_with_migration(&content)
        .context("Failed to load config with migration")?;
    
    Ok(config)
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}
