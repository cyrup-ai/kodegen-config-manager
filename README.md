<div align="center">
  <img src="assets/img/banner.png" alt="Kodegen AI Banner" width="100%" />
</div>

# kodegen-tools-config

> KODEGEN.ᴀɪ: Memory-efficient, Blazing-Fast, MCP tools for code generation agents.

[![License](https://img.shields.io/badge/license-Apache%202.0%20OR%20MIT-blue.svg)](LICENSE.md)
[![Rust](https://img.shields.io/badge/rust-nightly-orange.svg)](https://www.rust-lang.org/)

Configuration management MCP server for AI code generation agents. Part of the [KODEGEN.ᴀɪ](https://kodegen.ai) ecosystem.

## Features

- 🔧 **Dynamic Configuration Management** - Get and set server configuration via MCP tools
- 🔒 **Security Controls** - Manage blocked commands, allowed/denied directories
- 📊 **System Diagnostics** - Real-time system information (CPU, memory, platform)
- 🚀 **HTTP/HTTPS Support** - Flexible transport with optional TLS
- 🎯 **Client Tracking** - Track and manage MCP client connections
- ⚡ **Debounced Persistence** - Efficient config writes with 300ms debouncing

## Installation

### From Source

```bash
git clone https://github.com/cyrup-ai/kodegen-tools-config.git
cd kodegen-tools-config
cargo build --release
```

The compiled binary will be at `target/release/kodegen-config`.

### Prerequisites

- Rust nightly toolchain
- Cargo

## Usage

### Starting the Server

**HTTP (default):**
```bash
kodegen-config --http 127.0.0.1:3100
```

**HTTPS with TLS:**
```bash
kodegen-config --http 127.0.0.1:3100 \
  --tls-cert path/to/cert.pem \
  --tls-key path/to/key.pem
```

### Environment Variables

Override security-critical settings via environment variables:

**Unix/macOS:**
```bash
export KODEGEN_ALLOWED_DIRS="/home/user/projects:/home/user/workspace"
export KODEGEN_DENIED_DIRS="/home/user/secrets:/etc"
```

**Windows:**
```powershell
$env:KODEGEN_ALLOWED_DIRS="C:\Users\user\projects;C:\Users\user\workspace"
$env:KODEGEN_DENIED_DIRS="C:\Users\user\secrets;C:\Windows"
```

## MCP Tools

### `get_config`

Retrieve complete server configuration including security settings, resource limits, and system diagnostics.

**Example Request:**
```json
{
  "name": "get_config",
  "arguments": {}
}
```

**Example Response:**
```json
{
  "blocked_commands": ["rm", "sudo", "format"],
  "default_shell": "/bin/sh",
  "allowed_directories": [],
  "denied_directories": [],
  "file_read_line_limit": 1000,
  "file_write_line_limit": 50,
  "fuzzy_search_threshold": 0.7,
  "http_connection_timeout_secs": 5,
  "system_info": {
    "platform": "macos",
    "arch": "aarch64",
    "os_version": "14.0",
    "hostname": "macbook",
    "cpu_count": 8,
    "memory": {
      "total_mb": 16384,
      "available_mb": 8192,
      "used_mb": 8192
    }
  }
}
```

### `set_config_value`

Update a specific configuration value.

**Example Requests:**

```json
// Change file read limit
{
  "name": "set_config_value",
  "arguments": {
    "key": "file_read_line_limit",
    "value": 2500
  }
}

// Update blocked commands
{
  "name": "set_config_value",
  "arguments": {
    "key": "blocked_commands",
    "value": ["rm", "sudo", "dd", "format", "shutdown"]
  }
}

// Set allowed directories (empty array = full access)
{
  "name": "set_config_value",
  "arguments": {
    "key": "allowed_directories",
    "value": ["/home/user/projects"]
  }
}

// Adjust fuzzy search threshold (0-100)
{
  "name": "set_config_value",
  "arguments": {
    "key": "fuzzy_search_threshold",
    "value": 85
  }
}
```

## Configuration Keys

| Key | Type | Description | Default |
|-----|------|-------------|---------|
| `blocked_commands` | Array | Commands that cannot be executed | `["rm", "sudo", "format", ...]` |
| `default_shell` | String | Shell for command execution | `/bin/sh` (Unix) or `powershell.exe` (Windows) |
| `allowed_directories` | Array | Directories server can access (empty = full access) | `[]` |
| `denied_directories` | Array | Directories server cannot access | `[]` |
| `file_read_line_limit` | Number | Max lines for file read operations | `1000` |
| `file_write_line_limit` | Number | Max lines per file write operation | `50` |
| `fuzzy_search_threshold` | Number (0-100) | Minimum similarity for fuzzy search | `70` |
| `http_connection_timeout_secs` | Number | HTTP connection timeout | `5` |

## Configuration File

Configuration is persisted to `~/.kodegen/config.json` with automatic debounced writes (300ms).

**Example config.json:**
```json
{
  "blocked_commands": ["rm", "sudo"],
  "default_shell": "/bin/bash",
  "allowed_directories": ["/home/user/projects"],
  "denied_directories": [],
  "file_read_line_limit": 2000,
  "file_write_line_limit": 100,
  "fuzzy_search_threshold": 0.75,
  "http_connection_timeout_secs": 10,
  "client_history": [
    {
      "client_info": {
        "name": "claude-desktop",
        "version": "1.0.0"
      },
      "connected_at": "2025-01-15T10:30:00Z",
      "last_seen": "2025-01-15T12:45:00Z"
    }
  ]
}
```

## Development

### Build

```bash
cargo build
```

### Run Tests

```bash
# All tests
cargo test

# Specific test
cargo test test_name

# Integration example
cargo run --example config_demo
```

### Code Quality

```bash
# Format
cargo fmt

# Lint
cargo clippy

# Check
cargo check
```

## Architecture

This package implements its own HTTP server because it cannot depend on `kodegen_server_http` (which depends on this package's ConfigManager - circular dependency).

**Key Components:**
- **ConfigManager**: Thread-safe configuration with debounced persistence
- **GetConfigTool**: Retrieves configuration and live system diagnostics
- **SetConfigValueTool**: Updates configuration with validation
- **HTTP Server**: Axum-based MCP transport with CORS and TLS support

## License

Dual-licensed under your choice of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE.md) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE.md) or http://opensource.org/licenses/MIT)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Links

- [Homepage](https://kodegen.ai)
- [Repository](https://github.com/cyrup-ai/kodegen-tools-config)
- [Issue Tracker](https://github.com/cyrup-ai/kodegen-tools-config/issues)

---

Built with ❤️ by [KODEGEN.ᴀɪ](https://kodegen.ai)
