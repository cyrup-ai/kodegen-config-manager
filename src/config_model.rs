//! Server configuration types with business logic defaults

use serde::{Deserialize, Serialize};
use rmcp::schemars::{self, JsonSchema};
pub use kodegen_mcp_schema::config::{SystemInfo, MemoryInfo, ClientInfo, ClientRecord};

// ============================================================================
// SERVER CONFIGURATION
// ============================================================================

/// Complete server configuration with security settings, resource limits, and diagnostics
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ServerConfig {
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

    /// System diagnostic information (refreshed on every get_config call)
    pub system_info: SystemInfo,

    /// Total config save failures since server start
    #[serde(default)]
    pub save_error_count: usize,
}

// Default value functions for serde
fn default_shell() -> String {
    if cfg!(windows) {
        "powershell.exe".to_string()
    } else {
        "/bin/bash".to_string()
    }
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

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
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
            system_info: SystemInfo {
                platform: String::new(),
                arch: String::new(),
                os_version: String::new(),
                kernel_version: String::new(),
                hostname: String::new(),
                rust_version: String::new(),
                cpu_count: 0,
                memory: MemoryInfo {
                    total_mb: String::from("0 MB"),
                    available_mb: String::from("0 MB"),
                    used_mb: String::from("0 MB"),
                },
            },
            save_error_count: 0,
        }
    }
}
