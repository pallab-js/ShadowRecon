use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use tracing::warn;

/// Result of a captured TCP packet
#[derive(Debug, Clone)]
pub struct TcpResponse {
    pub flags: u8,
    #[allow(dead_code)]
    pub window: u16,
    #[allow(dead_code)]
    pub source_ip: IpAddr,
    #[allow(dead_code)]
    pub source_port: u16,
}

/// Registry for expecting packet responses
struct ResponseRegistry {
    // Key: (Target IP, Source Port, Dest Port)
    expectations: HashMap<(IpAddr, u16, u16), oneshot::Sender<TcpResponse>>,
}

/// A centralized sniffer that captures and dispatches network responses
pub struct Sniffer {
    interface: NetworkInterface,
    registry: Arc<Mutex<ResponseRegistry>>,
}

impl Sniffer {
    /// Create a new sniffer for the given interface
    pub fn new(interface: NetworkInterface) -> anyhow::Result<Self> {
        let registry = Arc::new(Mutex::new(ResponseRegistry {
            expectations: HashMap::new(),
        }));

        Ok(Self {
            interface,
            registry,
        })
    }

    /// Register an expectation for a TCP response and return a receiver
    pub fn expect_tcp(
        &self,
        target_ip: IpAddr,
        source_port: u16,
        dest_port: u16,
    ) -> oneshot::Receiver<TcpResponse> {
        let (tx, rx) = oneshot::channel();
        let mut registry = self.registry.lock().unwrap();
        registry.expectations.insert((target_ip, source_port, dest_port), tx);
        rx
    }

    /// Start the sniffer loop in a background task
    pub fn start(&self) -> anyhow::Result<()> {
        let registry = Arc::clone(&self.registry);
        let interface = self.interface.clone();

        let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => return Err(anyhow::anyhow!("Could not create datalink channel")),
        };

        std::thread::spawn(move || {
            loop {
                match rx.next() {
                    Ok(packet) => {
                        Self::process_packet(packet, &registry);
                    }
                    Err(e) => {
                        warn!("Sniffer read error: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    fn process_packet(packet: &[u8], registry: &Arc<Mutex<ResponseRegistry>>) {
        let eth = match EthernetPacket::new(packet) {
            Some(e) => e,
            None => return,
        };

        match eth.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                    Self::process_tcp(
                        IpAddr::V4(ipv4.get_source()),
                        ipv4.payload(),
                        registry
                    );
                }
            }
            EtherTypes::Ipv6 => {
                if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                    Self::process_tcp(
                        IpAddr::V6(ipv6.get_source()),
                        ipv6.payload(),
                        registry
                    );
                }
            }
            _ => {}
        }
    }

    fn process_tcp(source_ip: IpAddr, payload: &[u8], registry: &Arc<Mutex<ResponseRegistry>>) {
        if let Some(tcp) = TcpPacket::new(payload) {
            let dest_port = tcp.get_destination();
            let source_port = tcp.get_source();
            let flags = tcp.get_flags();
            let window = tcp.get_window();

            let mut reg = registry.lock().unwrap();
            // In a real response:
            // - source_ip is the target IP we scanned
            // - source_port is the port on the target (dest_port in our probe)
            // - dest_port is our local source_port
            if let Some(tx) = reg.expectations.remove(&(source_ip, dest_port, source_port)) {
                let _ = tx.send(TcpResponse {
                    flags: flags as u8,
                    window,
                    source_ip,
                    source_port,
                });
            }
        }
    }
}
