//! Runtime shell detection with multi-tier fallback strategy
//!
//! Detection Priority:
//! 1. SHELL environment variable (user preference)
//! 2. Platform-specific intelligent defaults (WSL-aware on Windows)
//! 3. Safe fallbacks (powershell.exe on Windows, /bin/sh on Unix)
//!
//! References:
//! - POSIX SHELL variable: https://pubs.opengroup.org/onlinepubs/9699919799/
//! - WSL environment detection: https://github.com/microsoft/WSL/issues/9719
//! - Windows shell detection: Git for Windows approach

use std::path::Path;
use std::env;

/// Detect user's preferred shell with multi-tier fallback
///
/// This function performs RUNTIME detection (not compile-time) by:
/// 1. Checking SHELL environment variable (Unix standard, works on Windows too)
/// 2. Validating the shell binary exists and is executable
/// 3. Falling back to platform-specific intelligent defaults
///
/// # Returns
/// Absolute path to shell executable (validated to exist)
///
/// # Platform Behavior
/// - **Unix/macOS**: Checks $SHELL, validates, falls back to /bin/bash or /bin/sh
/// - **Windows**: Checks $SHELL, detects WSL, searches PATH for shells, falls back to powershell.exe
/// - **WSL**: Detects via WSL_DISTRO_NAME, prefers Linux bash over Windows PowerShell
pub fn detect_user_shell() -> String {
    // Tier 1: SHELL environment variable (user preference)
    // This is the Unix standard but works on Windows too
    if let Ok(shell) = env::var("SHELL") {
        if is_valid_shell(&shell) {
            log::info!("✓ Detected shell from $SHELL environment variable: {}", shell);
            return shell;
        }
        log::warn!(
            "⚠ $SHELL={} is invalid (not found or not executable), falling back to defaults",
            shell
        );
    }
    
    // Tier 2: Platform-specific detection (RUNTIME, not compile-time)
    #[cfg(target_os = "windows")]
    {
        detect_windows_shell()
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        detect_unix_shell()
    }
}

/// Validate that a shell path is executable and exists
///
/// Public API for shell validation used by config validation.
///
/// # Validation Rules
/// 1. Path must exist
/// 2. Path must be a file (not directory)
/// 3. File must be executable (Unix only)
///
/// # Returns
/// - Ok(()) if shell is valid
/// - Err(message) with specific validation failure
pub fn validate_shell_path(path: &str) -> Result<(), String> {
    if is_valid_shell(path) {
        Ok(())
    } else {
        let path_obj = Path::new(path);
        
        if !path_obj.exists() {
            return Err(format!("Shell does not exist: {}", path));
        }
        
        if !path_obj.is_file() {
            return Err(format!("Shell path is not a file: {}", path));
        }
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(path_obj) {
                let mode = metadata.permissions().mode();
                if mode & 0o111 == 0 {
                    return Err(format!("Shell is not executable: {}", path));
                }
            }
        }
        
        Err(format!("Shell validation failed: {}", path))
    }
}

/// Validate shell path exists and is executable (internal helper)
///
/// Checks:
/// 1. Path exists in filesystem
/// 2. Path is a regular file (not a directory or symlink to directory)
/// 3. On Unix: File has executable permission bits set
///
/// # Arguments
/// * `shell_path` - Path to shell binary (absolute or relative)
///
/// # Returns
/// `true` if valid executable shell, `false` otherwise
fn is_valid_shell(shell_path: &str) -> bool {
    let path = Path::new(shell_path);
    
    // Must exist
    if !path.exists() {
        log::debug!("Shell validation failed: {} does not exist", shell_path);
        return false;
    }
    
    // Must be a file (not directory)
    if !path.is_file() {
        log::debug!("Shell validation failed: {} is not a regular file", shell_path);
        return false;
    }
    
    // Unix: Check executable permission bits (owner/group/other)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = path.metadata() {
            let mode = metadata.permissions().mode();
            // Check if ANY execute bit is set (user=0o100, group=0o010, other=0o001)
            // 0o111 = 0b001_001_001 (all three execute bits)
            if mode & 0o111 == 0 {
                log::debug!(
                    "Shell validation failed: {} has no execute permissions (mode: {:o})",
                    shell_path,
                    mode
                );
                return false;
            }
        } else {
            log::debug!("Shell validation failed: cannot read metadata for {}", shell_path);
            return false;
        }
    }
    
    // Windows: If file exists and is a file, assume it's executable
    // (Windows doesn't use Unix permission bits)
    #[cfg(windows)]
    {
        // Additional validation: check for common executable extensions
        if let Some(ext) = path.extension() {
            let ext_lower = ext.to_string_lossy().to_lowercase();
            if !["exe", "bat", "cmd", "ps1"].contains(&ext_lower.as_str()) {
                log::debug!(
                    "Shell validation failed: {} has non-executable extension .{}",
                    shell_path,
                    ext_lower
                );
                return false;
            }
        }
    }
    
    true
}

/// Detect shell on Windows with WSL awareness
///
/// Priority order:
/// 1. WSL bash (if WSL_DISTRO_NAME environment variable is set)
/// 2. Git Bash (bash.exe in PATH)
/// 3. PowerShell Core (pwsh.exe)
/// 4. Windows PowerShell (powershell.exe)
/// 5. Command Prompt (cmd.exe) - last resort
///
/// # WSL Detection
/// When running inside WSL, the WSL_DISTRO_NAME environment variable is set
/// (e.g., "Ubuntu", "Debian"). We prioritize Linux bash over Windows shells.
///
/// **Reference**: https://github.com/microsoft/WSL/issues/9719
/// Note: WSL_DISTRO_NAME may not be available when running as root with sudo,
/// but for normal user operations it's the most reliable WSL detection method.
#[cfg(target_os = "windows")]
fn detect_windows_shell() -> String {
    // Check common Windows shells in priority order
    let candidates: Vec<Option<String>> = vec![
        // 1. WSL bash (if inside WSL environment)
        // WSL_DISTRO_NAME is set to distribution name (Ubuntu, Debian, etc.)
        env::var("WSL_DISTRO_NAME")
            .ok()
            .and_then(|distro_name| {
                log::info!("🐧 WSL environment detected: {}", distro_name);
                which::which("bash").ok()
            })
            .map(|p| p.to_string_lossy().to_string()),
        
        // 2. Git Bash (common on Windows for developers)
        which::which("bash").ok().map(|p| {
            let path = p.to_string_lossy().to_string();
            log::debug!("Found bash.exe in PATH: {}", path);
            path
        }),
        
        // 3. PowerShell Core (modern, cross-platform PowerShell)
        which::which("pwsh").ok().map(|p| {
            let path = p.to_string_lossy().to_string();
            log::debug!("Found pwsh.exe in PATH: {}", path);
            path
        }),
        
        // 4. Windows PowerShell (pre-installed on all Windows)
        which::which("powershell").ok().map(|p| {
            let path = p.to_string_lossy().to_string();
            log::debug!("Found powershell.exe in PATH: {}", path);
            path
        }),
        
        // 5. Command Prompt (always available as last resort)
        Some("cmd.exe".to_string()),
    ];
    
    // Return first valid shell found
    for candidate in candidates.into_iter().flatten() {
        if is_valid_shell(&candidate) {
            log::info!("✓ Selected Windows shell: {}", candidate);
            return candidate;
        }
    }
    
    // Ultimate fallback (should never reach here)
    log::error!("⚠ No valid shell found on Windows! Using powershell.exe as emergency fallback");
    "powershell.exe".to_string()
}

/// Detect shell on Unix/Linux/macOS systems
///
/// Priority order:
/// 1. /bin/bash (most common default shell)
/// 2. /usr/bin/bash (alternative location on some distros)
/// 3. /bin/sh (POSIX shell, guaranteed to exist on all Unix systems)
/// 4. /usr/bin/sh (alternative POSIX location)
///
/// # POSIX Compliance
/// Per POSIX standard, /bin/sh MUST exist on all compliant Unix systems.
/// It may be a symlink to bash, dash, or another POSIX-compliant shell.
///
/// **Reference**: https://pubs.opengroup.org/onlinepubs/9699919799/
#[cfg(not(target_os = "windows"))]
fn detect_unix_shell() -> String {
    // Check common Unix shells in priority order
    let candidates = vec![
        "/bin/bash",        // Most common (GNU bash)
        "/usr/bin/bash",    // Alternative location (some BSDs)
        "/bin/sh",          // POSIX shell (always exists, may be symlink)
        "/usr/bin/sh",      // Alternative POSIX location
    ];
    
    for candidate in candidates {
        if is_valid_shell(candidate) {
            log::info!("✓ Selected Unix shell: {}", candidate);
            return candidate.to_string();
        }
    }
    
    // This should NEVER happen on valid Unix systems (POSIX guarantees /bin/sh)
    log::error!(
        "🚨 CRITICAL: No valid shell found on Unix system! This violates POSIX compliance."
    );
    log::error!("   Using /bin/sh as emergency fallback (may not work)");
    "/bin/sh".to_string()
}
