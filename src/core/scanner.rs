use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{info, warn};

use crate::types::{
    DiscoveryOptions, ScanConfig, ScanResult,
};
use crate::service::ServiceDetector;
use crate::os_fingerprint::OsFingerprinter;
use crate::scripting::ScriptEngine;
use crate::v2::EngineV2;

/// Main scanner struct that orchestrates the entire scanning process
pub struct Scanner {
    pub config: Arc<ScanConfig>,
    service_detector: ServiceDetector,
    os_fingerprinter: OsFingerprinter,
    script_engine: ScriptEngine,
    engine_v2: Option<EngineV2>,
}

impl Scanner {
    /// Create a new scanner with the given configuration
    pub fn new(config: ScanConfig) -> Self {
        let timing = config.timing.to_timing();
        let service_detector = ServiceDetector::new(&config);
        let os_fingerprinter = OsFingerprinter::new(&config, &timing);
        let script_engine = ScriptEngine::new(&config, &timing);

        // Initialize V2 engine if performing a raw scan
        let engine_v2 = if matches!(config.scan_type, 
            crate::types::ScanType::Syn | 
            crate::types::ScanType::Fin | 
            crate::types::ScanType::Null | 
            crate::types::ScanType::Xmas | 
            crate::types::ScanType::Ack | 
            crate::types::ScanType::Window | 
            crate::types::ScanType::Maimon
        ) {
            match EngineV2::new(config.clone()) {
                Ok(engine) => {
                    info!("V2 High-Performance Engine initialized");
                    Some(engine)
                }
                Err(e) => {
                    warn!("Failed to initialize V2 engine: {}. Falling back to legacy engine.", e);
                    None
                }
            }
        } else {
            None
        };

        Self {
            config: Arc::new(config),
            service_detector,
            os_fingerprinter,
            script_engine,
            engine_v2,
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

        // Step 2-5: Interleaved Pipeline (Discovery -> Port Scan -> Service Detection)
        info!("Starting interleaved scanning pipeline...");
        let orchestrator = crate::v2::Orchestrator::new(
            Arc::clone(&self.config),
            self.engine_v2.clone(),
            self.service_detector.clone(),
            self.os_fingerprinter.clone(),
            self.script_engine.clone(),
        );

        let live_hosts = orchestrator.run_pipeline(target_ips, discovery_options.clone()).await?;

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
                num_services: self.config.ports.to_ports().len() as u32,
                services: self.config.ports.to_ports(),
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