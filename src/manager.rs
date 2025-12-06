use crate::config_model::ServerConfig;
use crate::env_loader::{load_allowed_dirs_from_env, load_denied_dirs_from_env};
use crate::persistence;
use crate::system_info::ClientInfo;
use crate::ConfigValueExt;
use kodegen_config::KodegenConfig;
use kodegen_mcp_schema::McpError;
use kodegen_mcp_schema::config::ConfigValue;
use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;

// ============================================================================
// CONFIG MANAGER
// ============================================================================

#[derive(Clone)]
pub struct ConfigManager {
    config: Arc<RwLock<ServerConfig>>,
    config_path: PathBuf,

    // Debouncing field for fire-and-forget saves
    save_sender: tokio::sync::mpsc::UnboundedSender<()>,
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

        // Start background saver task
        persistence::start_background_saver(
            Arc::clone(&config),
            config_path.clone(),
            save_receiver,
        );

        Self {
            config,
            config_path,
            save_sender,
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

        // Load from disk or use defaults
        let mut loaded_config = match tokio::fs::read_to_string(&self.config_path).await {
            Ok(content) => serde_json::from_str::<ServerConfig>(&content)?,
            Err(_) => ServerConfig::default(),
        };

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

        *self.config.write() = loaded_config;
        persistence::save_to_disk(&self.config, &self.config_path).await?;
        Ok(())
    }

    #[must_use]
    pub fn get_config(&self) -> ServerConfig {
        self.config.read().clone()
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
    /// # Errors
    /// Returns error if the key is unknown, value type is invalid, or config cannot be saved
    pub async fn set_value(&self, key: &str, value: ConfigValue) -> Result<(), McpError> {
        {
            let mut config = self.config.write();
            match key {
                "blocked_commands" => {
                    config.blocked_commands = value.into_array().map_err(McpError::InvalidArguments)?;
                }
                "default_shell" => {
                    config.default_shell = value.into_string().map_err(McpError::InvalidArguments)?;
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
        }

        // Fire-and-forget debounced save
        let _ = self.save_sender.send(());
        Ok(())
    }

    /// Store client information from MCP initialization
    ///
    /// Updates in-memory state immediately and queues async save to disk.
    /// Disk write errors are logged but not propagated (fire-and-forget pattern).
    /// Use `get_save_error_count()` to check for save failures.
    pub async fn set_client_info(&self, client_info: ClientInfo) {
        {
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
                // Add new client record
                config.client_history.push(crate::system_info::ClientRecord {
                    client_info: client_info.clone(),
                    connected_at: now,
                    last_seen: now,
                });
            }

            // Set as current client
            config.current_client = Some(client_info);
        }

        // Fire-and-forget debounced save
        let _ = self.save_sender.send(());
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

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}
