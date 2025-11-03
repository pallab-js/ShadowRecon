use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tokio::task;
use tracing::{info, warn};

use crate::types::{
    DiscoveryOptions, HostInfo, HostStatus, PortInfo, PortState, ScanConfig, ScanResult,
    ScanTiming,
};
use crate::discovery::{discover_hosts, resolve_hostnames};
use crate::scanning::{scan_ports, PortScanner};
use crate::service::{detect_services, ServiceDetector};
use crate::os_fingerprint::OsFingerprinter;
use crate::scripting::ScriptEngine;

/// Main scanner struct that orchestrates the entire scanning process
pub struct Scanner {
    pub config: Arc<ScanConfig>,
    timing: ScanTiming,
    semaphore: Arc<Semaphore>,
    port_scanner: PortScanner,
    service_detector: ServiceDetector,
    os_fingerprinter: OsFingerprinter,
    script_engine: ScriptEngine,
}

impl Scanner {
    /// Create a new scanner with the given configuration
    pub fn new(config: ScanConfig) -> Self {
        let timing = config.timing.to_timing();
        let semaphore = Arc::new(Semaphore::new(config.threads));
        let port_scanner = PortScanner::new(&config, &timing);
        let service_detector = ServiceDetector::new(&config);
        let os_fingerprinter = OsFingerprinter::new(&config, &timing);
        let script_engine = ScriptEngine::new(&config, &timing);
        Self {
            config: Arc::new(config),
            timing,
            semaphore,
            port_scanner,
            service_detector,
            os_fingerprinter,
            script_engine,
        }
    }

    /// Run the complete scan process
    pub async fn run_scan(&self, discovery_options: &DiscoveryOptions) -> anyhow::Result<ScanResult> {
        let start_time = chrono::Utc::now();
        let scan_start = Instant::now();

        info!("Starting ShadowRecon v{}", env!("CARGO_PKG_VERSION"));
        info!("Scan configuration: {:?}", self.config);

        // Step 1: Resolve target hostnames to IPs
        let target_ips = self.resolve_targets().await?;
        if target_ips.is_empty() {
            warn!("No valid targets found");
            return Ok(self.create_empty_result(start_time));
        }

        info!("Resolved {} target(s)", target_ips.len());

        // Step 2: Network discovery (find live hosts)
        let mut live_hosts = if discovery_options.ping_sweep || discovery_options.arp_scan {
            info!("Performing network discovery...");
            let discovered = discover_hosts(&target_ips, discovery_options, &self.timing).await?;
            if discovered.is_empty() {
                // If discovery found no hosts, scan all targets anyway
                // This handles cases where ping is blocked or ICMP doesn't work
                info!("No hosts found via discovery, proceeding with all targets");
                target_ips
                    .into_iter()
                    .map(|ip| HostInfo {
                        ip,
                        hostname: None,
                        mac: None,
                        os: None,
                        ports: Vec::new(),
                        distance: None,
                        traceroute: None,
                        uptime: None,
                        status: HostStatus::Unknown,
                    })
                    .collect()
            } else {
                discovered
            }
        } else {
            // Assume all targets are live if no discovery is performed
            target_ips
                .into_iter()
                .map(|ip| HostInfo {
                    ip,
                    hostname: None,
                    mac: None,
                    os: None,
                    ports: Vec::new(),
                    distance: None,
                    traceroute: None,
                    uptime: None,
                    status: HostStatus::Unknown,
                })
                .collect()
        };

        // Optional: traceroute to determine hop distance
        if discovery_options.traceroute {
            info!("Performing traceroute to determine hop distance...");
            let mut updated = Vec::with_capacity(live_hosts.len());
            for mut host in live_hosts {
                if let std::net::IpAddr::V4(_) = host.ip {
                    if let Ok(hops) = crate::discovery::traceroute(host.ip, 30, self.timing.max_rtt_timeout).await {
                        host.distance = Some((hops.len() as u8).min(u8::MAX));
                        host.traceroute = Some(hops.clone());
                        // Print hop-by-hop output
                        info!("Traceroute for {}:", host.ip);
                        for hop in &hops {
                            let hostname_str = hop.hostname.as_ref().map(|h| format!(" ({})", h)).unwrap_or_default();
                            info!("  {:>2}  {}{}  {:.2} ms", hop.hop, hop.ip, hostname_str, hop.rtt.as_secs_f64() * 1000.0);
                        }
                    }
                }
                updated.push(host);
            }
            live_hosts = updated;
        }

        info!("Found {} live host(s)", live_hosts.len());

        // Step 3: Resolve hostnames for discovered hosts
        if self.config.resolve_hostname {
            live_hosts = resolve_hostnames(live_hosts).await?;
        }

        // Step 4: Port scanning
        let ports_to_scan = self.config.ports.to_ports();
        info!("Scanning {} port(s) on {} host(s)", ports_to_scan.len(), live_hosts.len());

        live_hosts = self.scan_hosts_ports(live_hosts, &ports_to_scan).await?;

        // Step 5: Service detection
        if self.config.service_detection != crate::types::ServiceDetectionMode::None {
            info!("Performing service detection...");
            live_hosts = self.detect_services(live_hosts).await?;
        }

        // Step 6: OS detection (if enabled)
        if discovery_options.os_detection {
            info!("Performing OS detection...");
            live_hosts = self.os_fingerprinter.fingerprint_hosts(live_hosts).await?;
        }

        // Step 7: Script scanning (if enabled)
        if discovery_options.script_scan {
            info!("Running scripts...");
            live_hosts = self.script_engine.run_scripts(live_hosts).await?;
        }

        let end_time = chrono::Utc::now();
        let runtime = scan_start.elapsed();

        let result = ScanResult {
            id: uuid::Uuid::new_v4(),
            scanner: "ShadowRecon".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            start_time,
            end_time: Some(end_time),
            command_line: std::env::args().collect::<Vec<_>>().join(" "),
            scan_info: crate::types::ScanInfo {
                scan_type: self.config.scan_type,
                protocol: match self.config.scan_type {
                    crate::types::ScanType::Udp => "udp".to_string(),
                    _ => "tcp".to_string(),
                },
                num_services: ports_to_scan.len() as u32,
                services: ports_to_scan,
            },
            hosts: live_hosts,
            runtime: Some(runtime),
        };

        Ok(result)
    }

    /// Resolve target specifications to IP addresses
    async fn resolve_targets(&self) -> anyhow::Result<Vec<IpAddr>> {
        let mut ips = Vec::new();

        for target in &self.config.targets {
            // Handle CIDR notation
            if target.contains('/') {
                let network: ipnet::IpNet = target.parse()?;
                for ip in network.hosts() {
                    ips.push(ip);
                }
            }
            // Handle IP ranges (e.g., 192.168.1.1-192.168.1.10)
            else if target.contains('-') {
                // Support IPv4 ranges like 192.168.1.10-192.168.1.20 or 192.168.1.10-20
                let parts: Vec<&str> = target.split('-').collect();
                if parts.len() == 2 {
                    match (parts[0].parse::<IpAddr>(), parts[1].parse::<IpAddr>()) {
                        (Ok(IpAddr::V4(start_v4)), Ok(IpAddr::V4(end_v4))) => {
                            let (a, b, c, d1) = (start_v4.octets()[0], start_v4.octets()[1], start_v4.octets()[2], start_v4.octets()[3]);
                            let (e, f, g, d2) = (end_v4.octets()[0], end_v4.octets()[1], end_v4.octets()[2], end_v4.octets()[3]);
                            if a == e && b == f && c == g && d1 <= d2 {
                                for d in d1..=d2 { ips.push(IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))); }
                            } else {
                                warn!("Unsupported IPv4 range: {}-{}", start_v4, end_v4);
                            }
                        }
                        (Ok(IpAddr::V4(start_v4)), Err(_)) => {
                            // Second part may be just the last octet
                            if let Ok(end_last) = parts[1].parse::<u8>() {
                                let (a, b, c, d1) = (start_v4.octets()[0], start_v4.octets()[1], start_v4.octets()[2], start_v4.octets()[3]);
                                if d1 <= end_last {
                                    for d in d1..=end_last { ips.push(IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))); }
                                }
                            }
                        }
                        _ => {
                            warn!("IPv6 ranges not supported: {}", target);
                        }
                    }
                }
            }
            // Handle single IP or hostname
            else {
                match target.parse::<IpAddr>() {
                    Ok(ip) => ips.push(ip),
                    Err(_) => {
                        // Try to resolve as hostname
                        match dns_lookup::lookup_host(target) {
                            Ok(host_ips) => ips.extend(host_ips),
                            Err(e) => warn!("Failed to resolve {}: {}", target, e),
                        }
                    }
                }
            }
        }

        // Remove duplicates
        ips.sort();
        ips.dedup();

        Ok(ips)
    }

    /// Scan ports on multiple hosts concurrently
    async fn scan_hosts_ports(&self, hosts: Vec<HostInfo>, ports: &[u16]) -> anyhow::Result<Vec<HostInfo>> {
        let mut tasks = Vec::new();

        for host in hosts.into_iter() {
            let semaphore = Arc::clone(&self.semaphore);
            let ports = ports.to_vec();
            let port_scanner = self.port_scanner.clone();
            let timing = self.timing.clone();

            let task = task::spawn(async move {
                match semaphore.acquire().await {
                    Ok(_permit) => Self::scan_single_host_ports(host, ports, port_scanner, timing).await,
                    Err(e) => {
                        warn!("Semaphore acquire failed for port scan: {}", e);
                        Err(anyhow::anyhow!("Port scan skipped due to semaphore error"))
                    }
                }
            });

            tasks.push(task);
        }

        let mut results = Vec::new();
        for task in tasks {
            match task.await {
                Ok(result) => results.push(result?),
                Err(e) => warn!("Task panicked: {}", e),
            }
        }

        Ok(results)
    }

    /// Scan ports on a single host
    async fn scan_single_host_ports(
        mut host: HostInfo,
        ports: Vec<u16>,
        port_scanner: PortScanner,
        timing: ScanTiming,
    ) -> anyhow::Result<HostInfo> {
        let port_results = scan_ports(host.ip, &ports, &port_scanner, &timing).await?;

        host.ports = port_results.into_iter()
            .map(|(port, state)| PortInfo {
                port,
                protocol: "tcp".to_string(), // TODO: Support UDP
                state,
                service: None,
                reason: "syn-ack".to_string(), // TODO: Proper reason
                ttl: None,
            })
            .collect();

        host.status = if host.ports.iter().any(|p| p.state == PortState::Open) {
            HostStatus::Up
        } else {
            HostStatus::Unknown
        };

        Ok(host)
    }

    /// Detect services on hosts
    async fn detect_services(&self, hosts: Vec<HostInfo>) -> anyhow::Result<Vec<HostInfo>> {
        let mut tasks = Vec::new();

        for host in hosts.into_iter() {
            let semaphore = Arc::clone(&self.semaphore);
            let service_detector = self.service_detector.clone();

            let task = task::spawn(async move {
                match semaphore.acquire().await {
                    Ok(_permit) => Self::detect_host_services(host, service_detector).await,
                    Err(e) => {
                        warn!("Semaphore acquire failed for service detection: {}", e);
                        Err(anyhow::anyhow!("Service detection skipped due to semaphore error"))
                    }
                }
            });

            tasks.push(task);
        }

        let mut results = Vec::new();
        for task in tasks {
            match task.await {
                Ok(result) => results.push(result?),
                Err(e) => warn!("Service detection task panicked: {}", e),
            }
        }

        Ok(results)
    }

    /// Detect services on a single host
    async fn detect_host_services(
        mut host: HostInfo,
        service_detector: ServiceDetector,
    ) -> anyhow::Result<HostInfo> {
        for port_info in &mut host.ports {
            if port_info.state == PortState::Open {
                if let Some(service) = detect_services(host.ip, port_info.port, &service_detector).await? {
                    port_info.service = Some(service);
                }
            }
        }

        Ok(host)
    }

    /// Create an empty scan result
    fn create_empty_result(&self, start_time: chrono::DateTime<chrono::Utc>) -> ScanResult {
        ScanResult {
            id: uuid::Uuid::new_v4(),
            scanner: "ShadowRecon".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            start_time,
            end_time: Some(chrono::Utc::now()),
            command_line: std::env::args().collect::<Vec<_>>().join(" "),
            scan_info: crate::types::ScanInfo {
                scan_type: self.config.scan_type,
                protocol: "tcp".to_string(),
                num_services: 0,
                services: Vec::new(),
            },
            hosts: Vec::new(),
            runtime: Some(Duration::from_secs(0)),
        }
    }
}