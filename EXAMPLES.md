# ShadowRecon Usage Examples

This guide provides real-world scenarios and advanced usage patterns for ShadowRecon.

---

## ⚡ High-Speed Scanning

### 1. Rapid Subnet Inventory
Identify live hosts and open ports across a `/24` network in seconds using the interleaved pipeline.
```bash
sudo ./shadowrecon 192.168.1.0/24 -p 80,443,8080 -T 5 -oN inventory.txt
```

### 2. Full Port "RustScan" Speed
Scan all 65,535 ports at a high rate with aggressive timing.
```bash
sudo ./shadowrecon 10.0.0.5 -p all -T 5 --max-rate 5000
```

---

## 🛡️ Stealth & IDS Evasion

### 3. Fragmented SYN Scan
Bypass deep packet inspection by splitting probes into 8-byte fragments.
```bash
sudo ./shadowrecon target.com -sS -f --mtu 8
```

### 4. Decoy Masking
Generate noise traffic from decoys to hide your true scanning origin.
```bash
sudo ./shadowrecon target.com -sS -D 1.1.1.1,8.8.8.8,4.2.2.2 -g 53
```

### 5. Data Padding
Append random data to probes to evade signature-based firewall rules.
```bash
sudo ./shadowrecon 10.0.0.1 -sS --data-length 64
```

---

## 🧩 Professional Toolchain Integration

### 6. Full Service Fingerprinting
Use Nmap-compatible probes to identify versions and write to XML for Metasploit import.
```bash
sudo ./shadowrecon target.com -A --service-version full -oX report.xml
```

### 7. Multi-Format Output
Generate all standard reports (Normal, XML, Grepable) simultaneously.
```bash
sudo ./shadowrecon 172.16.0.0/16 --top-ports 100 -oA assessment_results
```

---

## 📜 Custom Lua Scripting (SSE)

### 8. Running Security Checks
Automatically load and run all scripts from the `scripts/` directory.
```bash
sudo ./shadowrecon target.com --script-scan
```

### 9. Targeted Lua Logic
Run specific built-in or custom logic against common web ports.
```bash
sudo ./shadowrecon target.com -p 80,443,8443 --script http-vulns
```

---

## 🌍 Advanced Protocols

### 10. IPv6 Discovery
Scan modern IPv6 nodes using multicast discovery.
```bash
sudo ./shadowrecon 2001:db8::/64 -6 -A
```

### 11. SCTP Telecom Recon
Identify SCTP services (INIT scan) on non-standard ports.
```bash
sudo ./shadowrecon 10.10.10.10 -sY -p 2905,38412,5060
```

---

## 💡 Pro-Tips

*   **Paranoid Scanning:** Use `-T 0` or `-T 1` for extremely slow scans that bypass many threshold-based IDS alerts.
*   **Source Port Manipulation:** Use `-g 53` or `-g 80` to make probes appear as common service traffic, often permitted through legacy firewalls.
*   **Top Ports:** Instead of scanning sequential ranges, use `--top-ports 1000` to find 90% of services in 10% of the time.
