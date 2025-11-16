# ShadowRecon

[![CI](https://github.com/pallab-js/ShadowRecon/actions/workflows/ci.yml/badge.svg)](https://github.com/pallab-js/ShadowRecon/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange)](https://www.rust-lang.org/)

ShadowRecon is a powerful, modern network discovery and port/service scanning tool built in Rust. Designed as a more advanced and flexible alternative to traditional tools like nmap.

## Features

- **Multiple Scan Types**: TCP SYN, TCP Connect, UDP, FIN, NULL, XMAS, ACK, Window, and Maimon scans
- **Service Detection**: Basic, advanced, and full service fingerprinting with version detection
- **Network Discovery**: ICMP ping sweeps, ARP scanning, and traceroute capabilities
- **OS Fingerprinting**: Experimental OS detection based on TCP/IP characteristics (requires raw sockets)
- **Multiple Output Formats**: Text, JSON, XML, CSV, HTML reports, and grepable output
- **High Performance**: Async/await with parallel processing and configurable threading
- **Flexible Timing**: Multiple timing templates from paranoid to insane speeds
- **Advanced Options**: Decoy scanning, IP spoofing, packet fragmentation, and more
- **IPv6 Support**: Full IPv6 scanning capabilities
- **Extensible**: Modular design for easy addition of new features

## Installation

### Prerequisites

- **Rust 1.70+**: Install from [rustup.rs](https://rustup.rs/)
- **Network access**: Required for scanning
- **Root/Admin privileges**: Needed for raw socket scans (SYN, FIN, NULL, XMAS, ACK, Window, Maimon)
  - On Linux: Use `sudo` or set capabilities: `sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/shadowrecon`
  - On macOS: Run with `sudo` (may require additional permissions in System Preferences)
  - On Windows: Run as Administrator (raw sockets have limitations on Windows)
  - **Note**: TCP Connect scans (`-s T`) work without privileges but are less stealthy

### Installation Methods

#### From Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/pallab-js/ShadowRecon.git
cd ShadowRecon

# Build release binary
cargo build --release

# Binary will be at target/release/shadowrecon
# Optionally install globally:
sudo cp target/release/shadowrecon /usr/local/bin/
```

#### Via Cargo Install

```bash
# Install directly from GitHub
cargo install --git https://github.com/pallab-js/ShadowRecon --locked

# After installation, use:
shadowrecon <targets> -p <ports>
```

## Usage

### Basic Scanning

```bash
# Scan common ports on a single host
shadowrecon 192.168.1.1

# Scan specific ports
shadowrecon 192.168.1.1 -p 22,80,443,3389

# Scan a port range
shadowrecon 192.168.1.1 -p 1-1000

# Scan top 100 most common ports
shadowrecon 192.168.1.1 -p top-100
```

### Advanced Scanning

```bash
# Aggressive scan with OS detection and service versioning
shadowrecon 192.168.1.1 -A -O --service-version full

# Fast scan with high parallelism
shadowrecon 192.168.1.0/24 -T 5 -t 100

# Stealthy scan with slow timing
shadowrecon 192.168.1.1 -T 0 -s S

# UDP scanning
shadowrecon 192.168.1.1 -s U -p 53,67,68,123
```

### Output Formats

```bash
# JSON output
shadowrecon 192.168.1.1 -O json -o results.json

# XML output
shadowrecon 192.168.1.1 -O xml -o results.xml

# HTML report
shadowrecon 192.168.1.1 -O html -o results.html

# Grepable output (similar to nmap -oG)
shadowrecon 192.168.1.1 -O grep -o results.grep
```

## Command Line Options

### Target Specification
- `<targets>...`: Target IPs, hostnames, CIDR ranges, or files containing targets

### Port Selection
- `-p, --ports <ports>`: Port specification (single, range, list, or 'top-N')
  - Examples: `22`, `1-1000`, `22,80,443`, `top-100`

### Scan Types
- `-s, --scan-type <type>`: Scan technique
  - `S`: TCP SYN scan (stealthy, requires privileges)
  - `T`: TCP Connect scan (standard)
  - `U`: UDP scan
  - `F`: TCP FIN scan
  - `N`: TCP NULL scan
  - `X`: TCP XMAS scan
  - `A`: TCP ACK scan
  - `W`: TCP Window scan
  - `M`: TCP Maimon scan

### Timing and Performance
- `-T, --timing <0-5>`: Timing template (0=paranoid, 5=insane)
- `-t, --threads <num>`: Number of concurrent threads
- `--timeout <ms>`: Timeout for individual probes
- `--delay <ms>`: Delay between probes

### Service Detection
- `--service-version <mode>`: Service detection level
  - `none`: No service detection
  - `basic`: Banner grabbing
  - `advanced`: Extended fingerprinting
  - `full`: Comprehensive analysis with vulnerability checks

### Output Control
- `-o, --output <file>`: Output file
- `-O, --output-format <format>`: Output format (text, json, xml, csv, html, grep)
- `-v, --verbose`: Verbose output
- `-d, --debug`: Debug output

### Discovery Options
- `-P, --ping-sweep`: Perform ICMP ping sweep
- `--arp-scan`: Perform ARP scanning on local network
- `--traceroute`: Include traceroute information
- `--os-detection`: Attempt OS fingerprinting
- `-A, --aggressive`: Enable all discovery options

### Advanced Options
- `-D, --decoy <ips>`: Use decoy IPs (comma-separated)
- `--spoof-ip <ip>`: Spoof source IP address
- `-g, --source-port <port>`: Use specific source port
- `-e, --interface <iface>`: Bind to specific network interface
- `-f, --fragment`: Fragment packets
- `--randomize-hosts`: Randomize target host order
- `--randomize-ports`: Randomize target port order
- `-6, --ipv6`: Enable IPv6 scanning
- `-R, --resolve`: Resolve hostnames

## Examples

### Basic Port Scanning
```bash
# Scan common ports on a single host
shadowrecon 192.168.1.1 -p top-100

# Scan specific ports
shadowrecon 192.168.1.1 -p 22,80,443,3389

# Scan port range
shadowrecon 192.168.1.1 -p 1-1024
```

### Network Discovery and Port Scanning
```bash
# Scan entire subnet with service detection
shadowrecon 192.168.1.0/24 -p top-1000 --service-version basic

# Scan with hostname resolution
shadowrecon 192.168.1.0/24 -p 80,443 --resolve
```

### Comprehensive Security Assessment
```bash
# Aggressive scan with all features (requires root for some scan types)
sudo shadowrecon target.com -A -T 4 -O json -o security_audit.json

# Full service detection with vulnerability checks
shadowrecon target.com --service-version full -O json -o scan.json
```

### Firewall Testing
```bash
# ACK scan to test firewall filtering (requires root)
sudo shadowrecon 192.168.1.1 -s A -p 1-65535

# Fragment packets to evade detection
sudo shadowrecon 192.168.1.1 -s S -p 1-1000 --fragment
```

### Service Inventory
```bash
# CSV output for spreadsheet analysis
shadowrecon 10.0.0.0/8 -p 21,22,23,25,53,80,110,135,139,143,443,445,993,995,3389 -O csv -o services.csv

# HTML report for viewing
shadowrecon 192.168.1.0/24 -p top-100 --service-version advanced -O html -o report.html
```

### Stealth Scanning
```bash
# Slow, paranoid timing to avoid detection
shadowrecon target.com -T 0 -s S -p 1-1000

# SYN scan (stealthy, requires root)
sudo shadowrecon 192.168.1.1 -s S -p top-1000
```

### Script-Based Vulnerability Scanning
```bash
# Run all vulnerability scripts
shadowrecon target.com --script-scan -p 443,80,22

# Run specific vulnerability checks
shadowrecon target.com --script heartbleed,http-vulns,ftp-anon,dns-amplification,ntp-monlist -p 443,80,22,21,53,123
```

#### Available Vulnerability Scripts
- `heartbleed`: Checks for OpenSSL Heartbleed vulnerability (CVE-2014-0160)
- `smb-vulns`: Checks for common SMB vulnerabilities
- `http-vulns`: Checks for common HTTP vulnerabilities and missing security headers
- `ftp-anon`: Checks if FTP server allows anonymous access
- `dns-amplification`: Checks if DNS server can be used for amplification attacks
- `ntp-monlist`: Checks for NTP monlist command vulnerability (CVE-2013-5211)
- `ssh-weak`: Checks for weak SSH cryptographic algorithms
- `redis-unauth`: Checks for Redis unauthorized access
- `mongodb-unauth`: Checks for MongoDB unauthorized access
- `elasticsearch-unauth`: Checks for Elasticsearch unauthorized access

## Architecture

ShadowRecon is built with a modular architecture:

- **CLI Module** (`src/cli.rs`): Command line argument parsing and validation
- **Core Scanner** (`src/core/scanner.rs`): Main scanning orchestration
- **Discovery** (`src/discovery.rs`): Host discovery and network mapping
- **Scanning** (`src/scanning.rs`): Port scanning implementations
- **Service Detection** (`src/service.rs`): Service fingerprinting and version detection
- **Output** (`src/output.rs`): Multiple output format support
- **Types** (`src/types.rs`): Data structures and configuration

## Performance Characteristics

- **Async/Await**: Non-blocking I/O operations for high concurrency
- **Parallel Processing**: Configurable thread pools for optimal CPU utilization
- **Memory Efficient**: Streaming processing to handle large scan results

## Security & Legal Disclaimer

?? **IMPORTANT**: ShadowRecon is designed for authorized security testing and cybersecurity research only.

### Legal Notice

- **Unauthorized scanning is illegal** in most jurisdictions
- Only scan networks you own or have explicit written permission to test
- Users are solely responsible for ensuring their use complies with applicable laws
- The authors assume no liability for misuse of this tool

### Technical Security Notes

- Some scan types (SYN, FIN, NULL, XMAS, ACK, Window, Maimon) require raw socket access and root/admin privileges
- Connect scans (`-s T`) work without privileges but are less stealthy
- Use timing options appropriately to avoid overwhelming target systems
- All scan activities are logged for compliance and auditing purposes
- Be mindful of network policies and rate limits

## Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest features.

### Development Setup

```bash
git clone https://github.com/pallab-js/ShadowRecon.git
cd ShadowRecon
cargo test
cargo build --release
```

### Testing

```bash
# Run unit tests
cargo test

# Run with debug logging
RUST_LOG=shadowrecon=debug cargo run -- <args>
```

## Code of Conduct

This project follows a code of conduct to ensure a welcoming environment for all contributors. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by nmap and other network scanning tools
- Built with Rust's excellent networking and async ecosystem
- Thanks to the open source community for the many crates used in this project

## Examples

See [EXAMPLES.md](EXAMPLES.md) for detailed usage examples and common scenarios.

## Support

For issues, feature requests, or security concerns, please open an issue on [GitHub](https://github.com/pallab-js/ShadowRecon/issues).
