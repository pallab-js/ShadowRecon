use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::warn;

use crate::types::{DiscoveryOptions, HostInfo, HostStatus, PortInfo, PortState, ScanConfig};
use crate::v2::EngineV2;
use crate::service::ServiceDetector;
use crate::os_fingerprint::OsFingerprinter;
use crate::scripting::ScriptEngine;

/// Events emitted during the scan process
#[derive(Debug)]
pub enum ScanEvent {
    HostDiscovered(HostInfo),
    PortDiscovered(IpAddr, PortInfo),
    ServiceDetected(IpAddr, u16, crate::types::ServiceInfo),
}

/// Orchestrates the interleaved scanning pipeline
pub struct Orchestrator {
    config: Arc<ScanConfig>,
    engine_v2: Option<EngineV2>,
    service_detector: Arc<ServiceDetector>,
    os_fingerprinter: Arc<OsFingerprinter>,
    script_engine: Arc<ScriptEngine>,
}

impl Orchestrator {
    pub fn new(
        config: Arc<ScanConfig>,
        engine_v2: Option<EngineV2>,
        service_detector: ServiceDetector,
        os_fingerprinter: OsFingerprinter,
        script_engine: ScriptEngine,
    ) -> Self {
        Self {
            config,
            engine_v2,
            service_detector: Arc::new(service_detector),
            os_fingerprinter: Arc::new(os_fingerprinter),
            script_engine: Arc::new(script_engine),
        }
    }

    /// Run the interleaved scan pipeline
    pub async fn run_pipeline(
        &self,
        targets: Vec<IpAddr>,
        discovery_options: DiscoveryOptions,
    ) -> anyhow::Result<Vec<HostInfo>> {
        let (tx, mut rx) = mpsc::channel(100);
        let mut hosts = std::collections::HashMap::new();

        // 1. Start Host Discovery
        let discovery_tx = tx.clone();
        let timing = self.config.timing.to_timing();
        let targets_clone = targets.clone();
        let disc_opts = discovery_options.clone();
        
        tokio::spawn(async move {
            if disc_opts.ping_sweep || disc_opts.arp_scan {
                match crate::discovery::discover_hosts(&targets_clone, &disc_opts, &timing).await {
                    Ok(discovered_hosts) => {
                        for host in discovered_hosts {
                            let _ = discovery_tx.send(ScanEvent::HostDiscovered(host)).await;
                        }
                    }
                    Err(e) => warn!("Discovery failed: {}", e),
                }
            } else {
                // Assume all live
                for ip in targets_clone {
                    let host = HostInfo {
                        ip,
                        status: HostStatus::Unknown,
                        ..Default::default()
                    };
                    let _ = discovery_tx.send(ScanEvent::HostDiscovered(host)).await;
                }
            }
        });

        // 2. Event Loop
        let mut active_tasks = 0;
        let (done_tx, mut done_rx) = mpsc::channel(100);

        loop {
            tokio::select! {
                Some(event) = rx.recv() => {
                    match event {
                        ScanEvent::HostDiscovered(host) => {
                            let ip = host.ip;
                            hosts.insert(ip, host);
                            
                            // Immediately start port scan for this host
                            active_tasks += 1;
                            let orchestrator = self.clone_ptrs();
                            let event_tx = tx.clone();
                            let done_tx = done_tx.clone();
                            let ports = self.config.ports.to_ports();
                            
                            tokio::spawn(async move {
                                orchestrator.process_host(ip, ports, event_tx).await;
                                let _ = done_tx.send(ip).await;
                            });
                        }
                        ScanEvent::PortDiscovered(ip, port_info) => {
                            if let Some(host) = hosts.get_mut(&ip) {
                                host.ports.push(port_info.clone());
                                
                                // Mark host as UP if any port is found (even if not open, seeing it means host is alive)
                                host.status = HostStatus::Up;
                                
                                // If port is open, immediately trigger service detection
                                if port_info.state == PortState::Open {
                                    let orchestrator = self.clone_ptrs();
                                    let event_tx = tx.clone();
                                    let port = port_info.port;
                                    let protocol = port_info.protocol.clone();
                                    
                                    tokio::spawn(async move {
                                        orchestrator.process_service(ip, port, protocol, event_tx).await;
                                    });
                                }
                            }
                        }
                        ScanEvent::ServiceDetected(ip, port, service) => {
                            if let Some(host) = hosts.get_mut(&ip) {
                                if let Some(p) = host.ports.iter_mut().find(|p| p.port == port) {
                                    p.service = Some(service);
                                }
                            }
                        }
                    }
                }
                Some(_) = done_rx.recv() => {
                    active_tasks -= 1;
                    if active_tasks == 0 {
                        // All hosts completed port scanning
                        // Note: In a true interleaved system, we'd wait for all subtasks (services, scripts) too.
                        // For now, this is a simplified completion check.
                        break;
                    }
                }
                else => break,
            }
        }

        // Finalize hosts (OS detection, Scripts - these can also be interleaved later)
        let mut final_hosts: Vec<HostInfo> = hosts.into_values().collect();
        
        if discovery_options.os_detection {
            final_hosts = self.os_fingerprinter.fingerprint_hosts(final_hosts).await?;
        }
        
        if discovery_options.script_scan {
            final_hosts = self.script_engine.run_scripts(final_hosts).await?;
        }

        Ok(final_hosts)
    }

    async fn process_host(&self, ip: IpAddr, ports: Vec<u16>, tx: mpsc::Sender<ScanEvent>) {
        if let Some(engine) = &self.engine_v2 {
            // High-performance V2 scan
            match engine.scan_ports(ip, &ports).await {
                Ok(results) => {
                    for (port, state) in results {
                        let info = PortInfo {
                            port,
                            protocol: "tcp".to_string(),
                            state,
                            service: None,
                            reason: "syn-ack".to_string(),
                            ttl: None,
                        };
                        
                        let _ = tx.send(ScanEvent::PortDiscovered(ip, info)).await;
                    }
                }
                Err(e) => warn!("V2 Port scan failed for {}: {}", ip, e),
            }
        } else {
            // Legacy/Connect scan
            let timing = self.config.timing.to_timing();
            let port_scanner = crate::scanning::PortScanner::new(&self.config, &timing);
            match crate::scanning::scan_ports(ip, &ports, &port_scanner, &timing).await {
                Ok(results) => {
                    for (port, state) in results {
                        let info = PortInfo {
                            port,
                            protocol: if matches!(self.config.scan_type, crate::types::ScanType::Udp) { "udp".to_string() } else { "tcp".to_string() },
                            state,
                            service: None,
                            reason: "response".to_string(),
                            ttl: None,
                        };
                        let _ = tx.send(ScanEvent::PortDiscovered(ip, info)).await;
                    }
                }
                Err(e) => warn!("Port scan failed for {}: {}", ip, e),
            }
        }
    }

    async fn process_service(&self, ip: IpAddr, port: u16, protocol: String, tx: mpsc::Sender<ScanEvent>) {
        let result = if protocol == "udp" {
            crate::service::detect_udp_service(ip, port, &self.service_detector).await
        } else {
            crate::service::detect_services(ip, port, &self.service_detector).await
        };

        if let Ok(Some(service)) = result {
            let _ = tx.send(ScanEvent::ServiceDetected(ip, port, service)).await;
        }
    }

    fn clone_ptrs(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            engine_v2: self.engine_v2.clone(),
            service_detector: Arc::clone(&self.service_detector),
            os_fingerprinter: Arc::clone(&self.os_fingerprinter),
            script_engine: Arc::clone(&self.script_engine),
        }
    }
}
