use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout};
use pnet::datalink;
use tracing::debug;

use crate::types::{PortState, ScanConfig};
use crate::v2::network::{Sniffer, Prober, AdaptiveTiming};

/// Advanced scanning engine (V2) with centralized I/O and adaptive timing
#[derive(Clone)]
pub struct EngineV2 {
    config: Arc<ScanConfig>,
    timing: AdaptiveTiming,
    sniffer: Arc<Sniffer>,
    prober: Arc<Prober>,
}

impl EngineV2 {
    /// Create a new V2 engine for the given configuration
    pub fn new(config: ScanConfig) -> anyhow::Result<Self> {
        let _timing_conf = config.timing.to_timing();
        let adaptive_timing = AdaptiveTiming::new(
            config.delay.unwrap_or(Duration::from_millis(1)),
            config.min_rate,
            config.max_rate
        );

        // Find a suitable network interface
        let interfaces = datalink::interfaces();
        let interface = if let Some(ref iface_name) = config.interface {
            interfaces.into_iter()
                .find(|iface| &iface.name == iface_name)
                .ok_or_else(|| anyhow::anyhow!("Interface {} not found", iface_name))?
        } else {
            interfaces.into_iter()
                .find(|iface| !iface.is_loopback() && iface.is_up() && !iface.ips.is_empty())
                // Fallback to first non-loopback even if it has no IPs
                .or_else(|| datalink::interfaces().into_iter().find(|iface| !iface.is_loopback() && iface.is_up()))
                // Last resort: any up interface
                .or_else(|| datalink::interfaces().into_iter().find(|iface| iface.is_up()))
                .ok_or_else(|| anyhow::anyhow!("No suitable network interface found"))?
        };

        // Open datalink channel
        let (tx, _rx) = match datalink::channel(&interface, Default::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => return Err(anyhow::anyhow!("Could not create datalink channel")),
        };

        let sniffer = Arc::new(Sniffer::new(interface.clone())?);
        let mut prober = Prober::new(interface, tx);
        
        // Configure evasion options
        prober.set_evasion_options(config.fragment_packets, config.mtu, config.data_length);
        if let Some(spoof_ip) = config.spoof_ip {
            if let std::net::IpAddr::V4(v4) = spoof_ip {
                prober.set_spoof_ipv4(v4);
            }
        }

        let prober = Arc::new(prober);

        // Start sniffer background task
        sniffer.start()?;

        Ok(Self {
            config: Arc::new(config),
            timing: adaptive_timing,
            sniffer,
            prober,
        })
    }

    /// Scan a range of ports on a target IP
    pub async fn scan_ports(&self, target: IpAddr, ports: &[u16]) -> anyhow::Result<Vec<(u16, PortState)>> {
        // Fallback to legacy engine for loopback addresses on certain OSs (like macOS)
        // because raw sockets on loopback are unreliable.
        // We also force a Connect scan for loopback if SYN was requested, as it's the only reliable way locally.
        if target.is_loopback() {
            let mut loopback_config = (*self.config).clone();
            if loopback_config.scan_type == crate::types::ScanType::Syn {
                loopback_config.scan_type = crate::types::ScanType::Connect;
            }
            
            let timing = self.config.timing.to_timing();
            let port_scanner = crate::scanning::PortScanner::new(&loopback_config, &timing);
            let results = crate::scanning::scan_ports(target, ports, &port_scanner, &timing).await?;
            return Ok(results.into_iter().collect());
        }

        let mut results = Vec::new();
        let mut tasks = Vec::new();

        // Use a semaphore for global task concurrency
        let threads = self.config.max_parallelism.unwrap_or(self.config.threads);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(threads));

        for &port in ports {
            let sniffer = Arc::clone(&self.sniffer);
            let prober = Arc::clone(&self.prober);
            let timing = self.timing.clone();
            let semaphore = Arc::clone(&semaphore);
            let scan_type = self.config.scan_type;
            let decoy_ips = self.config.decoy_ips.clone();

            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                
                // Add inter-packet delay
                sleep(timing.get_delay()).await;

                // Send decoy probes if configured
                for &_decoy_ip in &decoy_ips {
                    let decoy_source_port = rand::random::<u16>() % 64000 + 1024;
                    use pnet::packet::tcp::TcpFlags;
                    let decoy_flags = match scan_type {
                        crate::types::ScanType::Syn => TcpFlags::SYN,
                        _ => TcpFlags::SYN,
                    };
                    let _ = prober.send_tcp_probe(target, port, decoy_source_port, decoy_flags);
                }

                // Random local source port for real probe
                let source_port = rand::random::<u16>() % 64000 + 1024;

                // Get flags based on scan type
                use pnet::packet::tcp::TcpFlags;
                let flags = match scan_type {
                    crate::types::ScanType::Syn => TcpFlags::SYN,
                    crate::types::ScanType::Fin => TcpFlags::FIN,
                    crate::types::ScanType::Null => 0,
                    crate::types::ScanType::Xmas => TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG,
                    crate::types::ScanType::Ack => TcpFlags::ACK,
                    crate::types::ScanType::Window => TcpFlags::ACK,
                    crate::types::ScanType::Maimon => TcpFlags::FIN | TcpFlags::ACK,
                    _ => TcpFlags::SYN,
                };

                // Register expectation with sniffer
                let rx = sniffer.expect_tcp(target, source_port, port);

                // Send probe
                let start = Instant::now();
                if let Err(e) = prober.send_tcp_probe(target, port, source_port, flags) {
                    debug!("Failed to send probe to {}:{}: {}", target, port, e);
                    return (port, PortState::Unknown);
                }

                // Wait for response
                let timeout_dur = timing.get_timeout(target);
                match timeout(timeout_dur, rx).await {
                    Ok(Ok(response)) => {
                        let rtt = start.elapsed();
                        timing.update_rtt(target, rtt);
                        timing.speed_up();

                        // Process flags based on scan type
                        match scan_type {
                            crate::types::ScanType::Syn => {
                                if (response.flags & TcpFlags::SYN as u8 != 0) && (response.flags & TcpFlags::ACK as u8 != 0) {
                                    (port, PortState::Open)
                                } else if response.flags & TcpFlags::RST as u8 != 0 {
                                    (port, PortState::Closed)
                                } else {
                                    (port, PortState::Filtered)
                                }
                            }
                            crate::types::ScanType::Fin | crate::types::ScanType::Null | crate::types::ScanType::Xmas => {
                                if response.flags & TcpFlags::RST as u8 != 0 {
                                    (port, PortState::Closed)
                                } else {
                                    (port, PortState::Open) 
                                }
                            }
                            crate::types::ScanType::Ack => {
                                if response.flags & TcpFlags::RST as u8 != 0 {
                                    (port, PortState::Unfiltered)
                                } else {
                                    (port, PortState::Filtered)
                                }
                            }
                            crate::types::ScanType::Window => {
                                if response.flags & TcpFlags::RST as u8 != 0 {
                                    if response.window > 0 {
                                        (port, PortState::Open)
                                    } else {
                                        (port, PortState::Closed)
                                    }
                                } else {
                                    (port, PortState::Filtered)
                                }
                            }
                            _ => (port, PortState::Unknown),
                        }
                    }
                    _ => {
                        // Timeout or no response
                        timing.backoff();
                        match scan_type {
                            crate::types::ScanType::Syn => (port, PortState::Filtered),
                            crate::types::ScanType::Fin | crate::types::ScanType::Null | crate::types::ScanType::Xmas => (port, PortState::Open),
                            _ => (port, PortState::Filtered),
                        }
                    }
                }
            });

            tasks.push(task);
        }

        // Collect results
        for task in tasks {
            results.push(task.await?);
        }

        Ok(results)
    }
}
