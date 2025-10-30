# CompilerCompilerFwCtl - Windows Firewall Control Utility

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)](https://www.microsoft.com/windows)

A portable, command-line utility for managing Windows Firewall rules, written in Rust. `CompilerFwCtl` provides a simplified interface that mimics the functionality of `netsh advfirewall firewall` while offering better ergonomics and safety.

## Features

- ✅ **Add firewall rules** with comprehensive parameter support
- ✅ **Delete rules** by name
- ✅ **Modify existing rules** (action, enabled state, profile)
- ✅ **List rules** with compact and verbose output modes
- ✅ **Reset firewall** to default settings
- ✅ **Native Windows Firewall integration** using COM APIs
- ✅ **Full compatibility** with rules created by `netsh`
- ✅ **Type-safe** and memory-safe implementation in Rust

## Installation

### Prerequisites

- Rust 1.70 or higher
- Windows operating system
- Administrator privileges (required for firewall modifications)

### Building from Source

```cmd
# Clone the repository
git clone https://github.com/daemondevin/CompilerFwCtl.git
cd CompilerFwCtl

# Build the project
cargo build --release

# The binary will be available at target/release/CompilerFwCtl.exe
```

### Installing

```cmd
# Install to cargo bin directory
cargo install --path .

# Or copy the binary to a directory in your PATH
copy target\release\CompilerFwCtl.exe C:\Tools\
```

## Usage

**Note:** All firewall modification commands require administrator privileges. Run your terminal as an Administrator.

### Basic Commands

#### Add a Rule

```cmd
# Block incoming traffic on port 8080
CompilerFwCtl add --name "Block Port 8080" --dir in --action block --protocol tcp --localport 8080

# Allow outbound HTTPS traffic
CompilerFwCtl add --name "Allow HTTPS" --dir out --action allow --protocol tcp --remoteport 443

# Block a specific application
CompilerFwCtl add --name "Block Notepad" --dir out --action block --program "C:\Windows\System32\notepad.exe"

# Add rule with description
CompilerFwCtl add --name "Web Server" --dir in --action allow --protocol tcp --localport 80,443 --description "Allow HTTP/HTTPS"
```

#### Show Rules

```cmd
# List all rules (compact view)
CompilerFwCtl show

# Show specific rule with full details
CompilerFwCtl show --name "Block Port 8080" --verbose

# List all rules in verbose mode
CompilerFwCtl show --verbose
```

#### Modify a Rule

```cmd
# Disable a rule without deleting it
CompilerFwCtl set --name "Block Port 8080" --enable no

# Change rule action from allow to block
CompilerFwCtl set --name "Web Server" --action block

# Change rule profile
CompilerFwCtl set --name "Web Server" --profile private
```

#### Delete a Rule

```cmd
# Remove a rule by name
CompilerFwCtl delete --name "Block Port 8080"
```

#### Reset Firewall

```cmd
# Reset all firewall rules to Windows defaults
CompilerFwCtl reset
```

## Command Reference

### `CompilerFwCtl add`

Add a new firewall rule.

**Required Arguments:**
- `--name, -n <NAME>` - Name of the rule
- `--dir, -d <DIRECTION>` - Direction: `in` or `out`
- `--action, -a <ACTION>` - Action: `allow` or `block`

**Optional Arguments:**
- `--protocol, -p <PROTOCOL>` - Protocol: `tcp`, `udp`, `icmpv4`, `icmpv6`, `any`, or protocol number (default: `any`)
- `--localport <PORT>` - Local port(s), e.g., `80`, `80,443`, `8000-9000`
- `--remoteport <PORT>` - Remote port(s)
- `--localip <ADDRESS>` - Local IP address(es)
- `--remoteip <ADDRESS>` - Remote IP address(es)
- `--program <PATH>` - Full path to program executable
- `--service <NAME>` - Windows service name
- `--profile <PROFILE>` - Profile: `domain`, `private`, `public`, or `any` (default: `any`)
- `--enable <yes|no>` - Enable the rule (default: `yes`)
- `--description <TEXT>` - Rule description

### `CompilerFwCtl delete`

Delete a firewall rule.

**Required Arguments:**
- `--name, -n <NAME>` - Name of the rule to delete

### `CompilerFwCtl set`

Modify an existing firewall rule.

**Required Arguments:**
- `--name, -n <NAME>` - Name of the rule to modify

**Optional Arguments:**
- `--action, -a <ACTION>` - New action: `allow` or `block`
- `--enable <yes|no>` - Enable or disable the rule
- `--profile <PROFILE>` - New profile: `domain`, `private`, `public`, or `any`

### `CompilerFwCtl show`

Display firewall rules.

**Optional Arguments:**
- `--name, -n <NAME>` - Filter by rule name
- `--verbose, -v` - Show detailed information for each rule

### `CompilerFwCtl reset`

Reset firewall to default Windows settings.

## Examples

### Web Server Configuration

```cmd
# Allow incoming HTTP and HTTPS
CompilerFwCtl add --name "Allow Web Traffic" --dir in --action allow --protocol tcp --localport 80,443 --profile public

# Block outbound traffic except DNS
CompilerFwCtl add --name "Block Outbound" --dir out --action block --protocol any
CompilerFwCtl add --name "Allow DNS" --dir out --action allow --protocol udp --remoteport 53
```

### Application-Specific Rules

```cmd
# Allow Firefox through firewall
CompilerFwCtl add --name "Firefox" --dir out --action allow --program "C:\Program Files\Mozilla Firefox\firefox.exe"

# Block a specific application
CompilerFwCtl add --name "Block Malware" --dir out --action block --program "C:\Temp\suspicious.exe"
```

### IP-Based Rules

```cmd
# Allow traffic from specific subnet
CompilerFwCtl add --name "Internal Network" --dir in --action allow --remoteip 192.168.1.0/24

# Block traffic to specific IP
CompilerFwCtl add --name "Block Bad IP" --dir out --action block --remoteip 203.0.113.0
```

### Service-Based Rules

```cmd
# Allow Remote Desktop
CompilerFwCtl add --name "RDP" --dir in --action allow --protocol tcp --localport 3389 --service TermService

# Allow Windows File Sharing
CompilerFwCtl add --name "SMB" --dir in --action allow --protocol tcp --localport 445 --profile private
```

## Comparison with netsh

| Feature | CompilerFwCtl | netsh advfirewall firewall |
|---------|-------|----------------------------|
| Add rule | `CompilerFwCtl add` | `netsh advfirewall firewall add rule` |
| Delete rule | `CompilerFwCtl delete` | `netsh advfirewall firewall delete rule` |
| Modify rule | `CompilerFwCtl set` | `netsh advfirewall firewall set rule` |
| List rules | `CompilerFwCtl show` | `netsh advfirewall firewall show rule` |
| Syntax | Modern CLI with `--flags` | Legacy syntax |
| Verbosity | Concise output | Verbose output |
| Type safety | Compile-time checks | Runtime validation |

### Migration Example

**netsh:**
```cmd
netsh advfirewall firewall add rule name="Web Server" dir=in action=allow protocol=TCP localport=80
```

**CompilerFwCtl:**
```cmd
CompilerFwCtl add --name "Web Server" --dir in --action allow --protocol tcp --localport 80
```

## Technical Details

### Architecture

- **Language:** Rust (safe, fast, memory-efficient)
- **CLI Framework:** [clap](https://github.com/clap-rs/clap) v4 with derive macros
- **Windows API:** Direct COM interface to `INetFwPolicy2` and `INetFwRule`
- **Platform Support:** Windows-only (uses platform-specific Windows Firewall APIs)

### Windows Firewall COM API

`CompilerFwCtl` uses the Windows Firewall COM API through the [windows-rs](https://github.com/microsoft/windows-rs) crate:

- `INetFwPolicy2` - Main policy interface
- `INetFwRule` - Individual rule manipulation
- `INetFwRules` - Rule collection management

All operations are performed directly on the Windows Firewall, ensuring full compatibility with other tools like Windows Defender Firewall GUI and `netsh`.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

```cmd
# Clone the repository
git clone https://github.com/daemondevin/CompilerFwCtl.git
cd CompilerFwCtl

# Run tests
cargo test

# Check code formatting
cargo fmt --check

# Run clippy lints
cargo clippy -- -D warnings

# Build and run
cargo run -- show
```

## Security Considerations

- **Administrator privileges required:** Modifying firewall rules requires elevated permissions
- **Rule validation:** Input parameters are validated before being applied
- **Safe defaults:** Rules are disabled by default unless explicitly enabled
- **No credential storage:** The tool doesn't store or transmit any credentials

## Troubleshooting

### "Access Denied" Error

**Solution:** Run the command prompt or terminal as Administrator.

```powershell
# PowerShell (Run as Administrator)
Start-Process powershell -Verb RunAs
```

### Rule Not Found

Ensure the rule name matches exactly (case-sensitive):

```cmd
# List all rules to find exact name
CompilerFwCtl show

# Use exact name when modifying
CompilerFwCtl set --name "Exact Rule Name" --enable no
```

### COM Initialization Failed

If you encounter COM initialization errors, ensure:
- You're running on Windows
- Windows Firewall service is running
- No other process is blocking COM initialization

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [windows-rs](https://github.com/microsoft/windows-rs) - Rust bindings for Windows APIs
- [clap](https://github.com/clap-rs/clap) - Command-line argument parsing
- Microsoft Windows Firewall API documentation

## Roadmap

- [ ] Support for rule groups
- [ ] Export/import rules to JSON/YAML
- [ ] Rule templates for common scenarios
- [ ] Interactive mode for guided rule creation
- [ ] Shell completion scripts (cmd, zsh, PowerShell)
- [ ] Dry-run mode for testing changes

