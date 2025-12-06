mod config_model;
mod env_loader;
mod manager;
mod persistence;
pub mod system_info;

pub use config_model::ServerConfig;
pub use kodegen_mcp_schema::config::ConfigValue;
pub use manager::ConfigManager;
pub use system_info::get_system_info;

/// Extension trait for ConfigValue providing conversion methods
pub trait ConfigValueExt {
    fn into_string(self) -> Result<String, String>;
    fn into_number(self) -> Result<i64, String>;
    fn into_array(self) -> Result<Vec<String>, String>;
}

impl ConfigValueExt for ConfigValue {
    fn into_string(self) -> Result<String, String> {
        match self {
            Self::String(s) => Ok(s),
            _ => Err("Expected string value".to_string()),
        }
    }

    fn into_number(self) -> Result<i64, String> {
        match self {
            Self::Number(n) => Ok(n),
            _ => Err("Expected number value".to_string()),
        }
    }

    fn into_array(self) -> Result<Vec<String>, String> {
        match self {
            Self::Array(a) => Ok(a),
            _ => Err("Expected array value".to_string()),
        }
    }
}
