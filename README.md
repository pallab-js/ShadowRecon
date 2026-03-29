# ShadowRecon

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](#)

**ShadowRecon** is a high-performance, next-generation network reconnaissance engine built in Rust. It combines the raw speed of modern scanners like `rustscan` with the deep accuracy and professional feature set of `nmap`.

Designed for red-teamers and network engineers, ShadowRecon utilizes an **Interleaved Event-Driven Pipeline** to overlap host discovery, port scanning, and service fingerprinting for maximum efficiency.

---

## 🚀 Key Advantages

### ⚡ Centralized High-Performance I/O
ShadowRecon uses a unified **Sniffer/Prober** architecture. Unlike traditional scanners that open a new socket per port, ShadowRecon manages all network traffic through a single BPF-filtered raw socket, drastically reducing kernel overhead and increasing throughput.

### 🧩 Nmap Ecosystem Compatibility
Seamlessly transition from Nmap. ShadowRecon natively parses and utilizes:
- `nmap-service-probes` for deep service versioning.
- `nmap-os-db` for heuristic-based OS fingerprinting.
- Supports Nmap-standard output formats (**XML, Grepable, Normal**).

### 🛡️ Advanced Evasion & Stealth
Bypass modern IDS/IPS systems with integrated evasion techniques:
- **IP Fragmentation:** Split probes into custom MTU sizes.
- **Decoy Scanning:** Mask your origin IP behind a cloud of decoy traffic.
- **Randomized Padding:** Append variable-length random data to every probe.
- **Adaptive Timing:** Dynamic congestion control based on real-time RTT tracking.

### 📜 Shadow Scripting Engine (SSE)
Extend the scanner with **Lua 5.4**. SSP exposes Rust's high-performance networking primitives directly to Lua, enabling community-driven vulnerability checks and custom reconnaissance logic.

---

## 🛠 Installation

### Prerequisites
- **Rust 1.75+**
- **Libpcap** (or WinPcap/Npcap on Windows)
- **Root/Admin Privileges** (Required for raw packet crafting and evasion features)

### Build from Source
```bash
git clone https://github.com/pallab-js/ShadowRecon.git
cd ShadowRecon
cargo build --release
```

---

## 📖 Usage Quickstart

### Professional Full Recon
Scan a target subnet aggressively with OS detection, service versioning, and Nmap XML output:
```bash
sudo ./shadowrecon 192.168.1.0/24 -A -oX results.xml
```

### Stealth Evasion Scan
SYN scan with IP fragmentation (MTU 8), decoy IPs, and random padding:
```bash
sudo ./shadowrecon target.com -sS -f --mtu 8 -D 1.1.1.1,8.8.8.8 --data-length 32
```

### High-Speed Service Inventory
Scan the top 1000 ports across a large range at a fixed rate:
```bash
sudo ./shadowrecon 10.0.0.0/8 --top-ports 1000 --max-rate 10000 -oG inventory.gnmap
```

---

## 📋 Command Reference

| Flag | Description |
| :--- | :--- |
| `-sS` | TCP SYN Scan (High speed, stealthy) |
| `-sT` | TCP Connect Scan (Unprivileged) |
| `-sU` | UDP Scan |
| `-sY / -sZ` | SCTP INIT / COOKIE-ECHO Scan |
| `-p` | Port range (e.g., `1-1024`, `80,443`, `all`) |
| `--top-ports` | Scan N most common ports |
| `-T <0-5>` | Timing template (Paranoid to Insane) |
| `-f / --mtu` | IP Fragmentation / Set MTU size |
| `-D` | Decoy IPs to mask origin |
| `-oA <base>` | Output in all standard formats (Normal, XML, Grep) |
| `-A` | Aggressive mode (OS, Service, Scripts, Traceroute) |

---

## ⚖️ Legal Disclaimer

**ShadowRecon is for authorized security testing only.** Unauthorized scanning of remote networks is illegal. The developers assume no liability for misuse or damage caused by this tool.

---

## 🤝 Contributing

Contributions are welcome. Please read our [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before submitting pull requests.

**ShadowRecon - The Precision Reconnaissance Engine.**
