# ShadowRecon Usage Examples

This document provides practical examples for using ShadowRecon in various scenarios.

## Quick Start

```bash
# Basic scan - no privileges needed
shadowrecon 192.168.1.1 -p 1-1000

# Scan with JSON output
shadowrecon 192.168.1.1 -p 22,80,443 -O json

# Save HTML report
shadowrecon 192.168.1.1 -p top-100 -O html -o scan_report.html
```

## Common Use Cases

### 1. Quick Network Reconnaissance

```bash
# Scan common ports on local network
shadowrecon 192.168.1.0/24 -p top-100

# With service detection
shadowrecon 192.168.1.0/24 -p top-100 --service-version basic

# Include hostname resolution
shadowrecon 192.168.1.0/24 -p 80,443 --resolve
```

### 2. Comprehensive Security Audit

```bash
# Full scan with all features
sudo shadowrecon target.com \
  -p 1-65535 \
  --service-version full \
  --script-scan \
  --os-detection \
  -O json \
  -o full_audit.json

# Aggressive timing for speed
sudo shadowrecon 192.168.1.0/24 -p top-1000 -T 5 -t 100
```

### 3. Web Server Discovery

```bash
# Find all web servers on network
shadowrecon 10.0.0.0/8 -p 80,443,8080,8443 --service-version advanced -O csv -o webservers.csv

# HTTP-specific vulnerability checks
shadowrecon 192.168.1.0/24 -p 80,443 --script http-vulns -O json
```

### 4. Firewall Testing

```bash
# ACK scan to determine firewall rules (requires root)
sudo shadowrecon firewall.example.com -s A -p 1-65535

# Fragment packets to test IDS/IPS evasion
sudo shadowrecon target.com -s S -p 1-1000 --fragment

# Multiple decoy IPs (requires root)
sudo shadowrecon target.com -s S -p 1-1000 -D 192.168.1.1,192.168.1.2,192.168.1.3
```

### 5. Stealth Scanning

```bash
# Very slow, paranoid timing
shadowrecon target.com -T 0 -p 1-1000

# SYN scan with slow timing (requires root)
sudo shadowrecon target.com -s S -T 1 -p top-1000
```

### 6. Vulnerability Assessment

```bash
# Check for Heartbleed
shadowrecon target.com --script heartbleed -p 443

# Multiple vulnerability checks
shadowrecon target.com --script heartbleed,http-vulns,ssh-weak -p 443,80,22

# All vulnerability scripts
shadowrecon target.com --script-scan -p top-1000
```

### 7. Service Inventory

```bash
# Common services inventory
shadowrecon 192.168.1.0/24 \
  -p 21,22,23,25,53,80,110,135,139,143,443,445,993,995,3389 \
  --service-version advanced \
  -O csv \
  -o service_inventory.csv
```

### 8. Port Range Scanning

```bash
# Single port
shadowrecon 192.168.1.1 -p 22

# Port range
shadowrecon 192.168.1.1 -p 1-1024

# Comma-separated list
shadowrecon 192.168.1.1 -p 22,80,443,3389

# Top N most common ports
shadowrecon 192.168.1.1 -p top-100

# All ports (be careful - this is slow!)
shadowrecon 192.168.1.1 -p all
```

### 9. Multiple Target Formats

```bash
# Single IP
shadowrecon 192.168.1.1 -p 80

# CIDR notation
shadowrecon 192.168.1.0/24 -p top-100

# IP range
shadowrecon 192.168.1.10-20 -p 80,443

# Hostname
shadowrecon example.com -p 80,443

# From file (one target per line)
shadowrecon targets.txt -p top-100
```

### 10. Output Formats

```bash
# Text (default)
shadowrecon 192.168.1.1 -p 80

# JSON for programmatic processing
shadowrecon 192.168.1.1 -p 80 -O json -o results.json

# XML for tools that expect XML
shadowrecon 192.168.1.1 -p 80 -O xml -o results.xml

# CSV for spreadsheet import
shadowrecon 192.168.1.1 -p 80 -O csv -o results.csv

# HTML for viewing in browser
shadowrecon 192.168.1.1 -p 80 -O html -o results.html

# Grepable format (similar to nmap -oG)
shadowrecon 192.168.1.1 -p 80 -O grep -o results.grep
```

## Advanced Examples

### Traceroute Integration

```bash
# Include traceroute information
shadowrecon target.com -p 80 --traceroute
```

### IPv6 Scanning

```bash
# Scan IPv6 targets
shadowrecon 2001:db8::1 -6 -p 80,443
```

### Custom Timing

```bash
# Fast scan with custom timeout
shadowrecon target.com -p 1-1000 --timeout 1000 -T 5

# Slow scan with delay
shadowrecon target.com -p 1-1000 --delay 100 -T 1
```

### Verbose/Debug Output

```bash
# Verbose output
shadowrecon target.com -p 80 -v

# Debug output (very detailed)
shadowrecon target.com -p 80 -d
```

## Tips

1. **Start with connect scans** (`-s T`) - they don't require privileges
2. **Use top-N ports** for faster scans: `-p top-100`
3. **Combine with service detection** for richer results: `--service-version basic`
4. **Save output files** for later analysis: `-o results.json`
5. **Use appropriate timing** - aggressive scans can be detected
6. **Respect rate limits** - use delays for large scans
7. **Always have authorization** before scanning

## Troubleshooting

### "Raw socket creation failed"
- Solution: Use `-s T` for connect scans, or run with `sudo` for raw socket scans

### "No hosts found via discovery"
- Normal behavior if ping is blocked - tool will still scan specified targets

### Slow scans
- Increase threads: `-t 100`
- Use aggressive timing: `-T 5`
- Scan fewer ports: `-p top-50` instead of `-p 1-65535`

### Permission errors on Linux
- Set capabilities: `sudo setcap cap_net_raw,cap_net_admin+eip $(which shadowrecon)`
- Or use `sudo` each time
