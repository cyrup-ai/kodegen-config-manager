//! Server configuration types with business logic defaults

use serde::{Deserialize, Serialize};
use rmcp::schemars::{self, JsonSchema};
pub use kodegen_mcp_schema::config::{SystemInfo, ClientInfo, ClientRecord};

// ============================================================================
// SERVER CONFIGURATION
// ============================================================================

/// Complete server configuration with security settings, resource limits, and diagnostics
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ServerConfig {
    /// Schema version for migration (increment when format changes)
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,

    /// Commands that cannot be executed
    #[serde(default)]
    pub blocked_commands: Vec<String>,

    /// Default shell for command execution
    #[serde(default = "default_shell")]
    pub default_shell: String,

    /// Directories the server can access (empty = full access)
    #[serde(default)]
    pub allowed_directories: Vec<String>,

    /// Directories the server cannot access
    #[serde(default)]
    pub denied_directories: Vec<String>,

    /// Max lines for file read operations
    #[serde(default = "default_file_read_limit")]
    pub file_read_line_limit: usize,

    /// Max lines per file write operation
    #[serde(default = "default_file_write_limit")]
    pub file_write_line_limit: usize,

    /// Minimum similarity ratio (0.0-1.0) for fuzzy search suggestions
    #[serde(default = "default_fuzzy_threshold")]
    pub fuzzy_search_threshold: f64,

    /// HTTP connection timeout in seconds
    #[serde(default = "default_http_timeout")]
    pub http_connection_timeout_secs: u64,

    /// Path validation timeout in milliseconds (for slow network filesystems)
    #[serde(default = "default_path_timeout")]
    pub path_validation_timeout_ms: u64,

    /// Currently connected client (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_client: Option<ClientInfo>,

    /// History of all clients that have connected
    #[serde(default)]
    pub client_history: Vec<ClientRecord>,

    /// System diagnostic information (RUNTIME ONLY - not persisted)
    ///
    /// This is automatically refreshed on every `get_config()` call to provide
    /// current system state. Never saved to disk.
    ///
    /// See: [`crate::system_info::get_system_info()`]
    #[serde(skip, default = "crate::system_info::get_system_info")]
    pub system_info: SystemInfo,

    /// Total config save failures since server start
    #[serde(default)]
    pub save_error_count: usize,
}

// Default value functions for serde
fn default_schema_version() -> u32 {
    1  // Current version
}

fn default_shell() -> String {
    crate::shell_detection::detect_user_shell()
}

fn default_file_read_limit() -> usize {
    10_000
}

fn default_file_write_limit() -> usize {
    100_000
}

fn default_fuzzy_threshold() -> f64 {
    0.6
}

fn default_http_timeout() -> u64 {
    30
}

fn default_path_timeout() -> u64 {
    5000
}

impl ServerConfig {
    /// Current schema version (update when format changes)
    pub const CURRENT_SCHEMA_VERSION: u32 = 1;
    
    /// Validate config values after deserialization
    ///
    /// Called during load to catch invalid configs early.
    /// Fixes some issues automatically (auto-repair), fails on unrecoverable errors.
    ///
    /// # Auto-Repair (with warnings)
    /// - Empty shell → detect user's shell
    /// - Non-existent shell → detect user's shell
    ///
    /// # Hard Failures (returns Err)
    /// - Zero limits (file_read_line_limit, file_write_line_limit)
    /// - Invalid fuzzy threshold (<0.0 or >1.0)
    /// - Zero timeouts
    /// - Empty paths in allowed/denied directories
    pub fn validate_and_repair(&mut self) -> Result<(), String> {
        let mut warnings = Vec::new();
        
        // 1. Validate and fix shell
        if self.default_shell.is_empty() {
            warnings.push("default_shell is empty, auto-detecting".to_string());
            self.default_shell = crate::shell_detection::detect_user_shell();
        } else if let Err(e) = crate::shell_detection::validate_shell_path(&self.default_shell) {
            warnings.push(format!(
                "default_shell validation failed ({}), auto-detecting",
                e
            ));
            self.default_shell = crate::shell_detection::detect_user_shell();
        }
        
        // 2. Validate file limits (MUST be positive)
        if self.file_read_line_limit == 0 {
            return Err("file_read_line_limit cannot be zero".to_string());
        }
        
        if self.file_write_line_limit == 0 {
            return Err("file_write_line_limit cannot be zero".to_string());
        }
        
        // 3. Validate fuzzy threshold (MUST be 0.0-1.0)
        if !(0.0..=1.0).contains(&self.fuzzy_search_threshold) {
            return Err(format!(
                "fuzzy_search_threshold must be 0.0-1.0, got {}",
                self.fuzzy_search_threshold
            ));
        }
        
        // 4. Validate timeouts (MUST be positive)
        if self.http_connection_timeout_secs == 0 {
            return Err("http_connection_timeout_secs cannot be zero".to_string());
        }
        
        if self.path_validation_timeout_ms == 0 {
            return Err("path_validation_timeout_ms cannot be zero".to_string());
        }
        
        // 5. Validate directory paths (NO empty strings allowed)
        for dir in &self.allowed_directories {
            if dir.is_empty() {
                return Err("allowed_directories contains empty path".to_string());
            }
        }
        
        for dir in &self.denied_directories {
            if dir.is_empty() {
                return Err("denied_directories contains empty path".to_string());
            }
        }
        
        // Log warnings for auto-repairs
        for warning in warnings {
            log::warn!("Config validation: {}", warning);
        }
        
        Ok(())
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            schema_version: ServerConfig::CURRENT_SCHEMA_VERSION,
            blocked_commands: Vec::new(),
            default_shell: default_shell(),
            allowed_directories: Vec::new(),
            denied_directories: Vec::new(),
            file_read_line_limit: default_file_read_limit(),
            file_write_line_limit: default_file_write_limit(),
            fuzzy_search_threshold: default_fuzzy_threshold(),
            http_connection_timeout_secs: default_http_timeout(),
            path_validation_timeout_ms: default_path_timeout(),
            current_client: None,
            client_history: Vec::new(),
            // CHANGED: Call actual system info function instead of empty defaults
            system_info: crate::system_info::get_system_info(),
            save_error_count: 0,
        }
    }
}
