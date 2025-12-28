//! Config migration framework with schema versioning
//!
//! Provides automatic migration from old config versions to current version.
//! Migration is transparent to callers - load_with_migration() handles everything.

use crate::config_model::ServerConfig;
use serde_json::Value;
use anyhow::{Context, Result};

/// Config schema version enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigVersion {
    /// V0: Legacy configs with no schema_version field
    V0,
    /// V1: Current format with schema_version field
    V1,
}

/// Detect config version from raw JSON value
///
/// # Detection Logic
/// - Missing `schema_version` field → V0 (backward compatibility)
/// - `schema_version = 1` → V1 (current)
/// - Other values → Error (unsupported)
fn detect_version(raw: &Value) -> Result<ConfigVersion> {
    match raw.get("schema_version") {
        None => {
            log::info!("Config has no schema_version field, treating as v0 (legacy)");
            Ok(ConfigVersion::V0)
        }
        Some(v) => match v.as_u64() {
            Some(1) => Ok(ConfigVersion::V1),
            Some(other) => {
                anyhow::bail!(
                    "Unsupported config schema version: {}. This package supports versions 0-1.",
                    other
                );
            }
            None => {
                anyhow::bail!("Config schema_version field must be an integer, got: {:?}", v);
            }
        },
    }
}

/// Load config with automatic migration support
///
/// # Migration Flow
/// 1. Parse as generic JSON to detect version
/// 2. If v0 detected:
///    - Apply v0 → v1 transformation
///    - Validate and repair
/// 3. If v1 detected:
///    - Parse directly as ServerConfig
///    - Validate and repair
///
/// # Error Handling
/// - Parse errors → propagated immediately
/// - Validation errors → propagated after showing specific issue
/// - Unsupported versions → hard error
pub fn load_with_migration(json_str: &str) -> Result<ServerConfig> {
    // Parse as generic JSON first
    let mut value: Value = serde_json::from_str(json_str)
        .context("Failed to parse config JSON")?;
    
    // Determine current version
    let version = detect_version(&value)?;
    
    log::info!("Config schema version: {:?}", version);
    
    // Apply migrations in sequence
    let mut current_version = version;
    
    // Migration: v0 → v1 (add schema_version field)
    if current_version == ConfigVersion::V0 {
        log::info!("Migrating config: v0 → v1");
        migrate_v0_to_v1(&mut value)?;
        current_version = ConfigVersion::V1;
    }
    
    // Future migrations would go here:
    // if current_version == ConfigVersion::V1 {
    //     log::info!("Migrating config: v1 → v2");
    //     migrate_v1_to_v2(&mut value)?;
    //     current_version = ConfigVersion::V2;
    // }
    
    // Verify we're at current version
    let current_num = match current_version {
        ConfigVersion::V0 => 0,
        ConfigVersion::V1 => 1,
    };
    
    if current_num != ServerConfig::CURRENT_SCHEMA_VERSION as i32 {
        log::warn!(
            "Config version {} differs from supported version {}. Using anyway.",
            current_num,
            ServerConfig::CURRENT_SCHEMA_VERSION
        );
    }
    
    // Deserialize to typed config
    let mut config: ServerConfig = serde_json::from_value(value)
        .context("Failed to deserialize config after migration")?;
    
    // Validate and repair
    config.validate_and_repair()
        .map_err(|e| anyhow::anyhow!("Config validation failed: {}", e))?;
    
    Ok(config)
}

/// Migrate v0 (no schema_version) to v1
///
/// # Changes
/// - Add `schema_version: 1` field
/// - All existing fields preserved (backward compatible)
fn migrate_v0_to_v1(value: &mut Value) -> Result<()> {
    // Add schema_version field
    if let Some(obj) = value.as_object_mut() {
        obj.insert("schema_version".to_string(), serde_json::json!(1));
        log::info!("Added schema_version field to config");
    }
    
    Ok(())
}
