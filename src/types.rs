use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Scan types supported by the scanner
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanType {
    /// TCP SYN scan (stealthy, requires raw sockets)
    Syn,
    /// TCP connect scan (standard, no privileges needed)
    Connect,
    /// UDP scan
    Udp,
    /// TCP FIN scan
    Fin,
    /// TCP NULL scan
    Null,
    /// TCP XMAS scan
    Xmas,
    /// ACK scan for firewall detection
    Ack,
    /// Window scan
    Window,
    /// Maimon scan
    Maimon,
}

/// Service detection modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceDetectionMode {
    /// No service detection
    None,
    /// Basic service detection (banner grabbing)
    Basic,
    /// Advanced service detection with version fingerprinting
    Advanced,
    /// Full service detection with vulnerability checks
    Full,
}

/// Output formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    /// Standard text output
    Text,
    /// JSON format
    Json,
    /// XML format
    Xml,
    /// CSV format
    Csv,
    /// HTML report
    Html,
    /// Greppable format
    Grep,
}

/// Port states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortState {
    /// Port is open
    Open,
    /// Port is closed
    Closed,
    /// Port is filtered (firewall)
    Filtered,
    /// Port state is unknown
    Unknown,
}

/// Operating system information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub name: String,
    pub version: Option<String>,
    pub family: Option<String>,
    pub accuracy: u8, // 0-100
    pub fingerprint: String,
}

/// Service information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub cpe: Option<String>,
    pub script_results: HashMap<String, String>,
}

/// Port information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String, // "tcp" or "udp"
    pub state: PortState,
    pub service: Option<ServiceInfo>,
    pub reason: String,
    pub ttl: Option<u8>,
}

/// Host information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub os: Option<OsInfo>,
    pub ports: Vec<PortInfo>,
    pub distance: Option<u8>, // Hop distance
    pub traceroute: Option<Vec<TracerouteHop>>, // Traceroute hops
    pub uptime: Option<Duration>,
    pub status: HostStatus,
}

/// Traceroute hop information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteHop {
    pub hop: u8,
    pub ip: IpAddr,
    pub rtt: Duration,
    pub hostname: Option<String>,
}

/// Host status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostStatus {
    Up,
    Down,
    Unknown,
}

/// Scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: Uuid,
    pub scanner: String,
    pub version: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub command_line: String,
    pub scan_info: ScanInfo,
    pub hosts: Vec<HostInfo>,
    pub runtime: Option<Duration>,
}

/// Scan information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanInfo {
    pub scan_type: ScanType,
    pub protocol: String,
    pub num_services: u32,
    pub services: Vec<u16>,
}

/// Scan configuration
#[derive(Debug, Clone)]
#[allow(dead_code)] // Many fields reserved for future features
pub struct ScanConfig {
    pub targets: Vec<String>,
    pub ports: PortRange,
    pub scan_type: ScanType,
    pub timing: TimingTemplate,
    pub service_detection: ServiceDetectionMode,
    pub output_format: OutputFormat,
    pub output_file: Option<String>,
    pub threads: usize,
    pub timeout: Duration,
    pub delay: Option<Duration>,
    pub max_retries: u32,
    pub spoof_ip: Option<IpAddr>,
    pub decoy_ips: Vec<IpAddr>,
    pub source_port: Option<u16>,
    pub interface: Option<String>,
    pub fragment_packets: bool,
    pub randomize_hosts: bool,
    pub randomize_ports: bool,
    pub verbose: bool,
    pub debug: bool,
    pub ipv6: bool,
    pub resolve_hostname: bool,
    pub scripts: Vec<String>,
    pub script_args: std::collections::HashMap<String, String>,
    pub traceroute: bool,
}

/// Port range specification
#[derive(Debug, Clone)]
pub enum PortRange {
    /// Single port
    Single(u16),
    /// Range of ports (start, end)
    Range(u16, u16),
    /// List of specific ports
    List(Vec<u16>),
    /// Top N most common ports
    Top(u16),
    /// All ports (1-65535)
    All,
}

impl PortRange {
    pub fn to_ports(&self) -> Vec<u16> {
        match self {
            PortRange::Single(port) => vec![*port],
            PortRange::Range(start, end) => (*start..=*end).collect(),
            PortRange::List(ports) => ports.clone(),
            PortRange::Top(n) => get_top_ports(*n),
            PortRange::All => (1..=65535).collect(),
        }
    }
}

/// Timing templates for scan speed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingTemplate {
    /// Paranoid: Very slow, avoids detection
    Paranoid,
    /// Sneaky: Slow scan
    Sneaky,
    /// Polite: Reduces load on target
    Polite,
    /// Normal: Default timing
    Normal,
    /// Aggressive: Faster scanning
    Aggressive,
    /// Insane: Very fast, may be unreliable
    Insane,
}

impl TimingTemplate {
    pub fn to_timing(&self) -> ScanTiming {
        match self {
            TimingTemplate::Paranoid => ScanTiming {
                initial_rtt_timeout: Duration::from_millis(100),
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(10),
                max_retries: 10,
                host_timeout: Duration::from_secs(1800), // 30 minutes
                scan_delay: Some(Duration::from_secs(5)),
                max_scan_delay: Some(Duration::from_secs(15)),
            },
            TimingTemplate::Sneaky => ScanTiming {
                initial_rtt_timeout: Duration::from_millis(100),
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(10),
                max_retries: 5,
                host_timeout: Duration::from_secs(900), // 15 minutes
                scan_delay: Some(Duration::from_secs(1)),
                max_scan_delay: Some(Duration::from_secs(10)),
            },
            TimingTemplate::Polite => ScanTiming {
                initial_rtt_timeout: Duration::from_millis(100),
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(5),
                max_retries: 3,
                host_timeout: Duration::from_secs(300), // 5 minutes
                scan_delay: Some(Duration::from_millis(100)),
                max_scan_delay: Some(Duration::from_millis(400)),
            },
            TimingTemplate::Normal => ScanTiming {
                initial_rtt_timeout: Duration::from_millis(100),
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(2),
                max_retries: 3,
                host_timeout: Duration::from_secs(60), // 1 minute
                scan_delay: None,
                max_scan_delay: None,
            },
            TimingTemplate::Aggressive => ScanTiming {
                initial_rtt_timeout: Duration::from_millis(50),
                min_rtt_timeout: Duration::from_millis(50),
                max_rtt_timeout: Duration::from_secs(1),
                max_retries: 2,
                host_timeout: Duration::from_secs(30), // 30 seconds
                scan_delay: None,
                max_scan_delay: None,
            },
            TimingTemplate::Insane => ScanTiming {
                initial_rtt_timeout: Duration::from_millis(25),
                min_rtt_timeout: Duration::from_millis(25),
                max_rtt_timeout: Duration::from_millis(500),
                max_retries: 1,
                host_timeout: Duration::from_secs(15), // 15 seconds
                scan_delay: None,
                max_scan_delay: None,
            },
        }
    }
}

/// Scan timing parameters
#[derive(Debug, Clone)]
pub struct ScanTiming {
    pub initial_rtt_timeout: Duration,
    pub min_rtt_timeout: Duration,
    pub max_rtt_timeout: Duration,
    pub max_retries: u32,
    pub host_timeout: Duration,
    pub scan_delay: Option<Duration>,
    pub max_scan_delay: Option<Duration>,
}

/// Network discovery options
#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub ping_sweep: bool,
    pub arp_scan: bool,
    pub traceroute: bool,
    pub reverse_dns: bool,
    pub os_detection: bool,
    pub service_version: bool,
    pub script_scan: bool,
    pub aggressive_timing: bool,
}

/// Script scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptResult {
    pub script_id: String,
    pub output: String,
    pub elements: HashMap<String, serde_json::Value>,
    pub vulnerabilities: Option<Vec<Vulnerability>>,
}

/// Vulnerability information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: VulnerabilitySeverity,
    pub cve: Option<String>,
    pub cvss_score: Option<f32>,
    pub references: Vec<String>,
}

/// Vulnerability severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnerabilitySeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Get the top N most common ports
fn get_top_ports(n: u16) -> Vec<u16> {
    // Most common ports based on nmap's top-ports list
    let common_ports = vec![
        80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
        1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113,
        81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
        26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
        631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000,
        513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128,
        444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9,
        5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
    ];

    common_ports.into_iter().take(n as usize).collect()
}