use sysinfo::System;

// Re-export types from mcp-schema (canonical definitions)
pub use kodegen_mcp_schema::config::{SystemInfo, MemoryInfo, ClientInfo, ClientRecord};

/// Get current system information
///
/// Collects cross-platform diagnostic data using the sysinfo crate.
/// All fields are guaranteed to be populated (using fallbacks if collection fails).
#[must_use]
pub fn get_system_info() -> SystemInfo {
    let mut sys = System::new_all();
    sys.refresh_all();

    // Memory information (sysinfo returns kilobytes)
    let total_kb = sys.total_memory();
    let available_kb = sys.available_memory();
    let used_kb = sys.used_memory();

    SystemInfo {
        // Platform from std::env (always available)
        platform: std::env::consts::OS.to_string(),

        // Architecture from std::env (always available)
        arch: std::env::consts::ARCH.to_string(),

        // OS version with fallback
        os_version: System::long_os_version()
            .unwrap_or_else(|| format!("{} (unknown version)", std::env::consts::OS)),

        // Kernel version with fallback
        kernel_version: System::kernel_version().unwrap_or_else(|| "unknown".to_string()),

        // Hostname with fallback
        hostname: System::host_name().unwrap_or_else(|| "unknown".to_string()),

        // Server version from build-time environment variable
        rust_version: env!("CARGO_PKG_VERSION").to_string(),

        // CPU count (number of logical cores)
        cpu_count: sys.cpus().len(),

        // Memory info converted to MB for readability
        memory: MemoryInfo {
            total_mb: format!("{} MB", total_kb / 1024),
            available_mb: format!("{} MB", available_kb / 1024),
            used_mb: format!("{} MB", used_kb / 1024),
        },
    }
}
