use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::sync::Arc;
use std::time::Instant;

use tokio::net::TcpStream as TokioTcpStream;
use tokio::time::{sleep, timeout};
use tracing::debug;
use pnet::packet::Packet as _;
use pnet::packet::tcp::TcpFlags;

use crate::types::{PortState, ScanConfig, ScanTiming, ScanType};

/// Port scanner that handles different scanning techniques
#[derive(Clone)]
pub struct PortScanner {
    config: Arc<ScanConfig>,
    timing: ScanTiming,
}

impl PortScanner {
    /// Create a new port scanner
    pub fn new(config: &ScanConfig, timing: &ScanTiming) -> Self {
        Self {
            config: Arc::new(config.clone()),
            timing: timing.clone(),
        }
    }

    /// Scan a single port on a target
    pub async fn scan_port(
        &self,
        target: IpAddr,
        port: u16,
    ) -> anyhow::Result<PortState> {
        match self.config.scan_type {
            ScanType::Connect => self.tcp_connect_scan(target, port).await,
            ScanType::Syn => self.tcp_syn_scan(target, port).await,
            ScanType::Udp => self.udp_scan(target, port).await,
            ScanType::Fin => self.tcp_fin_scan(target, port).await,
            ScanType::Null => self.tcp_null_scan(target, port).await,
            ScanType::Xmas => self.tcp_xmas_scan(target, port).await,
            ScanType::Ack => self.tcp_ack_scan(target, port).await,
            ScanType::Window => self.tcp_window_scan(target, port).await,
            ScanType::Maimon => self.tcp_maimon_scan(target, port).await,
        }
    }
}

/// Scan multiple ports on a target
pub async fn scan_ports(
    target: IpAddr,
    ports: &[u16],
    scanner: &PortScanner,
    timing: &ScanTiming,
) -> anyhow::Result<HashMap<u16, PortState>> {
    let mut results = HashMap::new();

    // For efficiency, scan ports concurrently
    let semaphore = Arc::new(tokio::sync::Semaphore::new(scanner.config.threads));

    let mut tasks = Vec::new();

    for &port in ports {
        let scanner = scanner.clone();
        let semaphore = Arc::clone(&semaphore);

        let timing_clone = timing.clone();
        let task = tokio::spawn(async move {
            if semaphore.acquire().await.is_err() {
                return (port, Ok(PortState::Unknown));
            }

            // Add delay between scans if configured
            if let Some(delay) = scanner.config.delay {
                sleep(delay).await;
            }

            let result = timeout(timing_clone.max_rtt_timeout, scanner.scan_port(target, port))
                .await
                .unwrap_or(Ok(PortState::Filtered));

            (port, result)
        });

        tasks.push(task);
    }

    // Collect results
    for task in tasks {
        match task.await {
            Ok((port, Ok(state))) => {
                results.insert(port, state);
            }
            Ok((port, Err(e))) => {
                debug!("Error scanning port {}: {}", port, e);
                results.insert(port, PortState::Unknown);
            }
            Err(e) => {
                debug!("Task panicked for port scan: {}", e);
            }
        }
    }

    Ok(results)
}

impl PortScanner {
    /// TCP Connect scan - full TCP handshake
    async fn tcp_connect_scan(
        &self,
        target: IpAddr,
        port: u16,
    ) -> anyhow::Result<PortState> {
        let addr = (target, port);

        match timeout(self.timing.max_rtt_timeout, TokioTcpStream::connect(addr)).await {
            Ok(Ok(_)) => Ok(PortState::Open),
            Ok(Err(e)) => {
                // Check error type to determine port state
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    Ok(PortState::Closed)
                } else if e.kind() == std::io::ErrorKind::TimedOut {
                    Ok(PortState::Filtered)
                } else {
                    Ok(PortState::Filtered)
                }
            }
            Err(_) => Ok(PortState::Filtered),
        }
    }

    /// TCP SYN scan - half-open scan (requires raw sockets)
    async fn tcp_syn_scan(
        &self,
        target: IpAddr,
        port: u16,
    ) -> anyhow::Result<PortState> {
        match target {
            IpAddr::V4(target_ip) => self.tcp_syn_scan_ipv4(target_ip, port).await,
            IpAddr::V6(target_ip) => self.tcp_syn_scan_ipv6(target_ip, port).await,
        }
    }

    /// IPv6 SYN scan implementation using raw sockets
    async fn tcp_syn_scan_ipv6(
        &self,
        target_ip: Ipv6Addr,
        port: u16,
    ) -> anyhow::Result<PortState> {
        use pnet::datalink::{self};
        use pnet::packet::ip::IpNextHeaderProtocols;
        use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
        use pnet::packet::ipv6::MutableIpv6Packet;
        use pnet::packet::Packet;

        // Get network interfaces
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| !iface.is_loopback() && iface.is_up())
            .ok_or_else(|| anyhow::anyhow!("No suitable network interface found"))?;

        let source_ip = get_local_ipv6(&interface)
            .ok_or_else(|| anyhow::anyhow!("Could not determine local IPv6 address"))?;

        // Create raw socket channel
        let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => return Err(anyhow::anyhow!("Could not create raw socket channel")),
        };

        // Generate random source port
        let source_port = rand::random::<u16>() % 65535 + 1024;
        let sequence_number = rand::random::<u32>();

        // Craft TCP SYN packet
        let mut tcp_buffer = [0u8; 40]; // TCP header size
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();

        tcp_packet.set_source(source_port);
        tcp_packet.set_destination(port);
        tcp_packet.set_sequence(sequence_number);
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_data_offset(5); // 5 * 4 = 20 bytes (no options)
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(65535);
        tcp_packet.set_checksum(0); // Will be calculated
        tcp_packet.set_urgent_ptr(0);

        // Calculate TCP checksum for IPv6
        let checksum = calculate_tcp_checksum_ipv6(&tcp_packet.to_immutable(), source_ip, target_ip);
        tcp_packet.set_checksum(checksum);

        // Craft IPv6 packet
        let mut ip_buffer = [0u8; 60]; // IPv6 header (40) + TCP header (20)
        let mut ip_packet = MutableIpv6Packet::new(&mut ip_buffer).unwrap();

        ip_packet.set_version(6);
        ip_packet.set_traffic_class(0);
        ip_packet.set_flow_label(0);
        ip_packet.set_payload_length(20); // TCP header length
        ip_packet.set_next_header(IpNextHeaderProtocols::Tcp);
        ip_packet.set_hop_limit(64);
        ip_packet.set_source(source_ip);
        ip_packet.set_destination(target_ip);
        ip_packet.set_payload(tcp_packet.packet());

        // Send the packet
        let _ = tx.send_to(ip_packet.packet(), None);

        // Wait for response with timeout
        let timeout_duration = self.timing.max_rtt_timeout;
        let start_time = std::time::Instant::now();

        while start_time.elapsed() < timeout_duration {
            match rx.next() {
                Ok(packet) => {
                    if let Some(response) = handle_syn_response_ipv6(&packet, source_port, port, target_ip, source_ip) {
                        return Ok(response);
                    }
                }
                Err(_) => break,
            }
        }

        Ok(PortState::Filtered)
    }

    /// IPv4 SYN scan implementation using raw sockets
    async fn tcp_syn_scan_ipv4(
        &self,
        target_ip: Ipv4Addr,
        port: u16,
    ) -> anyhow::Result<PortState> {
        use pnet::datalink::{self};
        use pnet::packet::ip::IpNextHeaderProtocols;
        use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
        use pnet::packet::ipv4::MutableIpv4Packet;
        use pnet::packet::Packet;

        // Get network interfaces
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| !iface.is_loopback() && iface.is_up())
            .ok_or_else(|| anyhow::anyhow!("No suitable network interface found"))?;

        let source_ip = get_local_ipv4(&interface)
            .ok_or_else(|| anyhow::anyhow!("Could not determine local IPv4 address"))?;

        // Create raw socket channel
        let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => return Err(anyhow::anyhow!("Could not create raw socket channel")),
        };

        // Generate random source port
        let source_port = rand::random::<u16>() % 65535 + 1024;
        let sequence_number = rand::random::<u32>();

        // Craft TCP SYN packet
        let mut tcp_buffer = [0u8; 40]; // TCP header size
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();

        tcp_packet.set_source(source_port);
        tcp_packet.set_destination(port);
        tcp_packet.set_sequence(sequence_number);
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_data_offset(5); // 5 * 4 = 20 bytes (no options)
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(65535);
        tcp_packet.set_checksum(0); // Will be calculated by kernel
        tcp_packet.set_urgent_ptr(0);

        // Calculate TCP checksum
        let checksum = calculate_tcp_checksum(&tcp_packet.to_immutable(), source_ip, target_ip);
        tcp_packet.set_checksum(checksum);

        // Craft IPv4 packet
        let mut ip_buffer = [0u8; 60]; // IPv4 header + TCP header
        let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();

        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(40); // IPv4 header (20) + TCP header (20)
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_packet.set_source(source_ip);
        ip_packet.set_destination(target_ip);

        // Copy TCP data into IP packet payload
        ip_packet.set_payload(tcp_packet.packet());

        // Calculate IP checksum
        let ip_checksum = calculate_ipv4_checksum(&ip_packet.to_immutable());
        ip_packet.set_checksum(ip_checksum);

        // Send the packet
        let _ = tx.send_to(ip_packet.packet(), None)
            .ok_or_else(|| anyhow::anyhow!("Failed to send SYN packet"))?;

        // Wait for response with timeout
        let timeout_duration = self.timing.max_rtt_timeout;
        let start_time = std::time::Instant::now();

        while start_time.elapsed() < timeout_duration {
            match rx.next() {
                Ok(packet) => {
                    if let Some(response) = handle_syn_response(&packet, source_port, port, target_ip, source_ip) {
                        return Ok(response);
                    }
                }
                Err(_) => break,
            }
        }

        Ok(PortState::Filtered)
    }

    /// UDP scan
    async fn udp_scan(
        &self,
        target: IpAddr,
        port: u16,
    ) -> anyhow::Result<PortState> {
        // Create UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(self.timing.max_rtt_timeout))?;

        let addr = (target, port);
        let test_payloads: &[&[u8]] = &[b"\r\n", b"\0", b"probe"]; // try a few payloads

        let mut attempts = 0u32;
        let max_attempts = self.timing.max_retries.max(1);
        while attempts < max_attempts {
            attempts += 1;
            let payload = test_payloads[(attempts as usize - 1) % test_payloads.len()];
            let _ = socket.send_to(payload, addr);

            let mut buf = [0; 1024];
            match socket.recv_from(&mut buf) {
                Ok(_) => return Ok(PortState::Open),
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::ConnectionRefused {
                        return Ok(PortState::Closed);
                    }
                    // TimedOut or other -> try again
                }
            }
        }

        // After retries with no response, classify as Filtered (more conservative than Open)
        Ok(PortState::Filtered)
    }

    /// TCP FIN scan - stealthy scan
    async fn tcp_fin_scan(
        &self,
        target: IpAddr,
        port: u16,
    ) -> anyhow::Result<PortState> {
        match target {
            IpAddr::V4(target_ip) => self.tcp_raw_scan_ipv4(target_ip, port, TcpFlags::FIN, |flags| {
                // Closed ports respond with RST, open/filtered ports ignore FIN
                (flags & TcpFlags::RST) != 0
            }).await,
            IpAddr::V6(target_ip) => self.tcp_raw_scan_ipv6(target_ip, port, TcpFlags::FIN, |flags| {
                (flags & TcpFlags::RST) != 0
            }).await,
        }
    }

    /// TCP NULL scan - stealthy scan with no flags
    async fn tcp_null_scan(
        &self,
        target: IpAddr,
        port: u16,
    ) -> anyhow::Result<PortState> {
        match target {
            IpAddr::V4(target_ip) => self.tcp_raw_scan_ipv4(target_ip, port, 0u8, |flags| {
                // Closed ports respond with RST, open/filtered ports ignore NULL
                flags & TcpFlags::RST != 0
            }).await,
            IpAddr::V6(target_ip) => self.tcp_raw_scan_ipv6(target_ip, port, 0u8, |flags| {
                flags & TcpFlags::RST != 0
            }).await,
        }
    }

    /// TCP XMAS scan - stealthy scan with FIN, PSH, URG flags
    async fn tcp_xmas_scan(
        &self,
        target: IpAddr,
        port: u16,
    ) -> anyhow::Result<PortState> {
        match target {
            IpAddr::V4(target_ip) => self.tcp_raw_scan_ipv4(target_ip, port, TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG, |flags| {
                // Closed ports respond with RST, open/filtered ports ignore XMAS
                flags & TcpFlags::RST != 0
            }).await,
            IpAddr::V6(target_ip) => self.tcp_raw_scan_ipv6(target_ip, port, TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG, |flags| {
                flags & TcpFlags::RST != 0
            }).await,
        }
    }

    /// TCP ACK scan - used for firewall detection
    async fn tcp_ack_scan(
        &self,
        target: IpAddr,
        port: u16,
    ) -> anyhow::Result<PortState> {
        match target {
            IpAddr::V4(target_ip) => self.tcp_raw_scan_ipv4(target_ip, port, TcpFlags::ACK, |flags| {
                // If we get RST, port is unfiltered (open or closed)
                // No response means filtered
                flags & TcpFlags::RST != 0
            }).await,
            IpAddr::V6(target_ip) => self.tcp_raw_scan_ipv6(target_ip, port, TcpFlags::ACK, |flags| {
                flags & TcpFlags::RST != 0
            }).await,
        }
    }

    /// TCP Window scan - variation of ACK scan
    async fn tcp_window_scan(
        &self,
        target: IpAddr,
        port: u16,
    ) -> anyhow::Result<PortState> {
        match target {
            IpAddr::V4(target_ip) => self.tcp_raw_scan_ipv4_with_window(target_ip, port).await,
            IpAddr::V6(target_ip) => self.tcp_raw_scan_ipv6_with_window(target_ip, port).await,
        }
    }

    /// TCP Maimon scan - FIN/ACK probe
    async fn tcp_maimon_scan(
        &self,
        target: IpAddr,
        port: u16,
    ) -> anyhow::Result<PortState> {
        match target {
            IpAddr::V4(target_ip) => self.tcp_raw_scan_ipv4(target_ip, port, TcpFlags::FIN | TcpFlags::ACK, |flags| {
                // Closed ports respond with RST, open/filtered ports ignore FIN+ACK
                flags & TcpFlags::RST != 0
            }).await,
            IpAddr::V6(target_ip) => self.tcp_raw_scan_ipv6(target_ip, port, TcpFlags::FIN | TcpFlags::ACK, |flags| {
                flags & TcpFlags::RST != 0
            }).await,
        }
    }

    /// Generic raw TCP scan for IPv4
    async fn tcp_raw_scan_ipv4<F>(
        &self,
        target_ip: Ipv4Addr,
        port: u16,
        flags: u8,
        check_response: F,
    ) -> anyhow::Result<PortState>
    where
        F: Fn(u8) -> bool,
    {
        use pnet::datalink::{self};
        use pnet::packet::ip::IpNextHeaderProtocols;
        use pnet::packet::tcp::MutableTcpPacket;
        use pnet::packet::ipv4::MutableIpv4Packet;
        use pnet::packet::Packet;

        // Get network interfaces
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| !iface.is_loopback() && iface.is_up())
            .ok_or_else(|| anyhow::anyhow!("No suitable network interface found"))?;

        let source_ip = get_local_ipv4(&interface)
            .ok_or_else(|| anyhow::anyhow!("Could not determine local IPv4 address"))?;

        // Create raw socket channel
        let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => return Err(anyhow::anyhow!("Could not create raw socket channel")),
        };

        // Generate random source port
        let source_port = rand::random::<u16>() % 65535 + 1024;
        let sequence_number = rand::random::<u32>();

        // Craft TCP packet with specified flags
        let mut tcp_buffer = [0u8; 40];
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();

        tcp_packet.set_source(source_port);
        tcp_packet.set_destination(port);
        tcp_packet.set_sequence(sequence_number);
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(flags);
        tcp_packet.set_window(65535);
        tcp_packet.set_checksum(0);
        tcp_packet.set_urgent_ptr(0);

        // Calculate TCP checksum
        let checksum = calculate_tcp_checksum(&tcp_packet.to_immutable(), source_ip, target_ip);
        tcp_packet.set_checksum(checksum);

        // Craft IPv4 packet
        let mut ip_buffer = [0u8; 60];
        let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();

        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(40);
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_packet.set_source(source_ip);
        ip_packet.set_destination(target_ip);
        ip_packet.set_payload(tcp_packet.packet());

        // Calculate IP checksum
        let ip_checksum = calculate_ipv4_checksum(&ip_packet.to_immutable());
        ip_packet.set_checksum(ip_checksum);

        // Send the packet
        let _ = tx.send_to(ip_packet.packet(), None)
            .ok_or_else(|| anyhow::anyhow!("Failed to send TCP packet"))?;

        // Wait for response
        let timeout_duration = self.timing.max_rtt_timeout;
        let start_time = std::time::Instant::now();

        while start_time.elapsed() < timeout_duration {
            match rx.next() {
                Ok(packet) => {
                    if let Some(response_flags) = handle_raw_tcp_response(&packet, source_port, port, target_ip, source_ip) {
                        if check_response(response_flags) {
                            return Ok(PortState::Closed);
                        }
                    }
                }
                Err(_) => break,
            }
        }

        // No RST received - port is open or filtered
        Ok(PortState::Filtered)
    }

    /// TCP Window scan implementation
    async fn tcp_raw_scan_ipv4_with_window(
        &self,
        target_ip: Ipv4Addr,
        port: u16,
    ) -> anyhow::Result<PortState> {
        use pnet::datalink;
        use pnet::packet::ip::IpNextHeaderProtocols;
        use pnet::packet::tcp::{MutableTcpPacket, TcpPacket, TcpFlags};
        use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Packet};
        use pnet::packet::Packet;

        // Get interface and source IP
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| !iface.is_loopback() && iface.is_up())
            .ok_or_else(|| anyhow::anyhow!("No suitable network interface found"))?;

        let source_ip = get_local_ipv4(&interface)
            .ok_or_else(|| anyhow::anyhow!("Could not determine local IPv4 address"))?;

        // Channel
        let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => return Err(anyhow::anyhow!("Could not create raw socket channel")),
        };

        // Source port and seq
        let source_port = rand::random::<u16>() % 65535 + 1024;
        let sequence_number = rand::random::<u32>();

        // Build TCP ACK
        let mut tcp_buffer = [0u8; 40];
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
        tcp_packet.set_source(source_port);
        tcp_packet.set_destination(port);
        tcp_packet.set_sequence(sequence_number);
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(TcpFlags::ACK);
        tcp_packet.set_window(65535);
        tcp_packet.set_checksum(0);
        tcp_packet.set_urgent_ptr(0);

        let checksum = calculate_tcp_checksum(&tcp_packet.to_immutable(), source_ip, target_ip);
        tcp_packet.set_checksum(checksum);

        // Build IPv4 packet
        let mut ip_buffer = [0u8; 60];
        let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(40);
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_packet.set_source(source_ip);
        ip_packet.set_destination(target_ip);
        ip_packet.set_payload(tcp_packet.packet());

        let ip_checksum = calculate_ipv4_checksum(&ip_packet.to_immutable());
        ip_packet.set_checksum(ip_checksum);

        // Send
        let _ = tx.send_to(ip_packet.packet(), None);

        // Wait for response and inspect window
        let timeout_duration = self.timing.max_rtt_timeout;
        let start_time = std::time::Instant::now();
        while start_time.elapsed() < timeout_duration {
            match rx.next() {
                Ok(frame) => {
                    // Ethernet -> IPv4 -> TCP
                    if let Some(eth) = pnet::packet::ethernet::EthernetPacket::new(frame) {
                        if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv4 { continue; }
                        if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                            if ipv4.get_source() != target_ip || ipv4.get_destination() != source_ip { continue; }
                            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                if tcp.get_source() != port || tcp.get_destination() != source_port { continue; }
                                let flags = tcp.get_flags();
                                let window = tcp.get_window();
                                // Window-scan heuristic: non-zero window suggests open, zero suggests closed
                                if flags & TcpFlags::RST != 0 {
                                    return Ok(PortState::Filtered); // unfiltered, but unknown open/closed; keep filtered semantics
                                }
                                return Ok(if window > 0 { PortState::Open } else { PortState::Closed });
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }

        Ok(PortState::Filtered)
    }

    /// Generic raw TCP scan for IPv6
    async fn tcp_raw_scan_ipv6<F>(
        &self,
        target_ip: Ipv6Addr,
        port: u16,
        flags: u8,
        check_response: F,
    ) -> anyhow::Result<PortState>
    where
        F: Fn(u8) -> bool,
    {
        use pnet::datalink::{self};
        use pnet::packet::ip::IpNextHeaderProtocols;
        use pnet::packet::tcp::{MutableTcpPacket, TcpPacket, TcpFlags};
        use pnet::packet::ipv6::{MutableIpv6Packet, Ipv6Packet};
        use pnet::packet::Packet;

        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| !iface.is_loopback() && iface.is_up())
            .ok_or_else(|| anyhow::anyhow!("No suitable network interface found"))?;

        let source_ip = get_local_ipv6(&interface)
            .ok_or_else(|| anyhow::anyhow!("Could not determine local IPv6 address"))?;

        let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => return Err(anyhow::anyhow!("Could not create raw socket channel")),
        };

        let source_port = rand::random::<u16>() % 65535 + 1024;
        let sequence_number = rand::random::<u32>();

        let mut tcp_buffer = [0u8; 40];
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer)
            .ok_or_else(|| anyhow::anyhow!("Failed to build TCP packet"))?;

        tcp_packet.set_source(source_port);
        tcp_packet.set_destination(port);
        tcp_packet.set_sequence(sequence_number);
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(flags);
        tcp_packet.set_window(65535);
        tcp_packet.set_checksum(0);
        tcp_packet.set_urgent_ptr(0);

        let checksum = calculate_tcp_checksum_ipv6(&tcp_packet.to_immutable(), source_ip, target_ip);
        tcp_packet.set_checksum(checksum);

        let mut ip_buffer = [0u8; 60];
        let mut ip_packet = MutableIpv6Packet::new(&mut ip_buffer)
            .ok_or_else(|| anyhow::anyhow!("Failed to build IPv6 packet"))?;

        ip_packet.set_version(6);
        ip_packet.set_payload_length(40);
        ip_packet.set_next_header(IpNextHeaderProtocols::Tcp);
        ip_packet.set_hop_limit(64);
        ip_packet.set_source(source_ip);
        ip_packet.set_destination(target_ip);
        ip_packet.set_payload(tcp_packet.packet());

        let _ = tx.send_to(ip_packet.packet(), None);

        let start = Instant::now();
        while start.elapsed() < self.timing.max_rtt_timeout {
            match rx.next() {
                Ok(frame) => {
                    if let Some(eth) = pnet::packet::ethernet::EthernetPacket::new(frame) {
                        if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv6 {
                            continue;
                        }
                        if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                            if ipv6.get_destination() != source_ip {
                                continue;
                            }
                            if ipv6.get_next_header() == IpNextHeaderProtocols::Tcp {
                                if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                                    if tcp.get_destination() == source_port {
                                        let response_flags = tcp.get_flags();
                                        if check_response(response_flags as u8) {
                                            return Ok(if (response_flags & TcpFlags::RST) != 0 {
                                                PortState::Closed
                                            } else {
                                                PortState::Open
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }

        Ok(PortState::Filtered)
    }

    /// TCP Window scan for IPv6
    async fn tcp_raw_scan_ipv6_with_window(
        &self,
        target_ip: Ipv6Addr,
        port: u16,
    ) -> anyhow::Result<PortState> {
        use pnet::datalink;
        use pnet::packet::ip::IpNextHeaderProtocols;
        use pnet::packet::tcp::{MutableTcpPacket, TcpPacket, TcpFlags};
        use pnet::packet::ipv6::{MutableIpv6Packet, Ipv6Packet};
        use pnet::packet::Packet;

        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| !iface.is_loopback() && iface.is_up())
            .ok_or_else(|| anyhow::anyhow!("No suitable network interface found"))?;

        let source_ip = get_local_ipv6(&interface)
            .ok_or_else(|| anyhow::anyhow!("Could not determine local IPv6 address"))?;

        let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => return Err(anyhow::anyhow!("Could not create raw socket channel")),
        };

        let source_port = rand::random::<u16>() % 65535 + 1024;
        let sequence_number = rand::random::<u32>();

        let mut tcp_buffer = [0u8; 40];
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer)
            .ok_or_else(|| anyhow::anyhow!("Failed to build TCP packet"))?;
        tcp_packet.set_source(source_port);
        tcp_packet.set_destination(port);
        tcp_packet.set_sequence(sequence_number);
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(TcpFlags::ACK);
        tcp_packet.set_window(65535);
        tcp_packet.set_checksum(0);
        tcp_packet.set_urgent_ptr(0);

        let checksum = calculate_tcp_checksum_ipv6(&tcp_packet.to_immutable(), source_ip, target_ip);
        tcp_packet.set_checksum(checksum);

        let mut ip_buffer = [0u8; 60];
        let mut ip_packet = MutableIpv6Packet::new(&mut ip_buffer)
            .ok_or_else(|| anyhow::anyhow!("Failed to build IPv6 packet"))?;
        ip_packet.set_version(6);
        ip_packet.set_payload_length(40);
        ip_packet.set_next_header(IpNextHeaderProtocols::Tcp);
        ip_packet.set_hop_limit(64);
        ip_packet.set_source(source_ip);
        ip_packet.set_destination(target_ip);
        ip_packet.set_payload(tcp_packet.packet());

        let _ = tx.send_to(ip_packet.packet(), None);

        let start = Instant::now();
        while start.elapsed() < self.timing.max_rtt_timeout {
            match rx.next() {
                Ok(frame) => {
                    if let Some(eth) = pnet::packet::ethernet::EthernetPacket::new(frame) {
                        if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv6 {
                            continue;
                        }
                        if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                            if ipv6.get_destination() != source_ip {
                                continue;
                            }
                            if ipv6.get_next_header() == IpNextHeaderProtocols::Tcp {
                                if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                                    if tcp.get_destination() == source_port {
                                        let flags = tcp.get_flags();
                                        if (flags & TcpFlags::RST) != 0 {
                                            let window = tcp.get_window();
                                            return Ok(if window > 0 {
                                                PortState::Open
                                            } else {
                                                PortState::Closed
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }

        Ok(PortState::Filtered)
    }
}


/// Get local IPv4 address for a network interface
fn get_local_ipv4(interface: &pnet::datalink::NetworkInterface) -> Option<std::net::Ipv4Addr> {
    for ip in &interface.ips {
        if let std::net::IpAddr::V4(addr) = ip.ip() {
            return Some(addr);
        }
    }
    None
}

/// Get local IPv6 address for a network interface
fn get_local_ipv6(interface: &pnet::datalink::NetworkInterface) -> Option<std::net::Ipv6Addr> {
    for ip in &interface.ips {
        if let std::net::IpAddr::V6(addr) = ip.ip() {
            // Skip link-local addresses for now
            if !addr.is_unicast_link_local() {
                return Some(addr);
            }
        }
    }
    None
}

/// Calculate TCP checksum (simplified)
fn calculate_tcp_checksum(
    tcp_packet: &pnet::packet::tcp::TcpPacket,
    source_ip: std::net::Ipv4Addr,
    dest_ip: std::net::Ipv4Addr,
) -> u16 {
    // RFC 793 TCP checksum using IPv4 pseudo-header
    let tcp_bytes = tcp_packet.packet();
    let tcp_len = tcp_bytes.len() as u32;

    fn sum16(data: &[u8]) -> u32 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += ((data[i] as u32) << 8) | data[i + 1] as u32;
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        sum
    }

    // Pseudo-header
    let src = source_ip.octets();
    let dst = dest_ip.octets();
    let mut sum: u32 = 0;
    sum += (((src[0] as u32) << 8) | (src[1] as u32))
        + (((src[2] as u32) << 8) | (src[3] as u32));
    sum += (((dst[0] as u32) << 8) | (dst[1] as u32))
        + (((dst[2] as u32) << 8) | (dst[3] as u32));
    sum += 6; // protocol
    sum += ((tcp_len >> 16) & 0xFFFF) + (tcp_len & 0xFFFF);

    // TCP header and data with checksum field zeroed
    let mut tcp_copy = tcp_bytes.to_vec();
    if tcp_copy.len() >= 18 {
        tcp_copy[16] = 0;
        tcp_copy[17] = 0;
    }
    sum += sum16(&tcp_copy);

    // Fold 32-bit to 16-bit
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Calculate TCP checksum for IPv6
fn calculate_tcp_checksum_ipv6(
    tcp_packet: &pnet::packet::tcp::TcpPacket,
    source_ip: std::net::Ipv6Addr,
    dest_ip: std::net::Ipv6Addr,
) -> u16 {
    use pnet::packet::Packet;
    let mut sum = 0u32;

    // Pseudo-header for IPv6 (RFC 2460): src(16) + dst(16) + length(4) + zero(3) + next header(1)
    let source_bytes = source_ip.octets();
    let dest_bytes = dest_ip.octets();

    // Add source address (16 bytes)
    for chunk in source_bytes.chunks(2) {
        sum += (chunk[0] as u32) << 8 | chunk[1] as u32;
    }

    // Add destination address (16 bytes)
    for chunk in dest_bytes.chunks(2) {
        sum += (chunk[0] as u32) << 8 | chunk[1] as u32;
    }

    // TCP segment length = header + payload
    let tcp_len = tcp_packet.packet().len() as u32;
    sum += (tcp_len >> 16) + (tcp_len & 0xFFFF);

    // Next header (TCP = 6)
    sum += 6;

    // TCP header and data
    let tcp_data = tcp_packet.packet();
    let mut i = 0;
    while i + 1 < tcp_data.len() {
        sum += (tcp_data[i] as u32) << 8 | tcp_data[i + 1] as u32;
        i += 2;
    }
    if i < tcp_data.len() {
        sum += (tcp_data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Calculate IPv4 checksum (simplified)
fn calculate_ipv4_checksum(ip_packet: &pnet::packet::ipv4::Ipv4Packet) -> u16 {
    // Standard IPv4 header checksum with checksum field zeroed
    let header_len = (ip_packet.get_header_length() * 4) as usize;
    let data = &ip_packet.packet()[..header_len];
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        if i == 10 { // checksum field
            i += 2;
            continue;
        }
        sum += ((data[i] as u32) << 8) | data[i + 1] as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Handle SYN scan response packet (IPv4)
fn handle_syn_response(
    packet: &[u8],
    source_port: u16,
    target_port: u16,
    target_ip: std::net::Ipv4Addr,
    source_ip: std::net::Ipv4Addr,
) -> Option<PortState> {
    use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::tcp::{TcpPacket, TcpFlags};
    use pnet::packet::Packet;

    // Parse Ethernet frame
    let ethernet = EthernetPacket::new(packet)?;
    if ethernet.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }

    // Parse IPv4 packet
    let ipv4 = Ipv4Packet::new(ethernet.payload())?;
    if ipv4.get_source() != target_ip || ipv4.get_destination() != source_ip {
        return None;
    }

    // Parse TCP packet
    let tcp = TcpPacket::new(ipv4.payload())?;
    if tcp.get_source() != target_port || tcp.get_destination() != source_port {
        return None;
    }

    let flags = tcp.get_flags();

    // Check TCP flags to determine port state
    if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
        // SYN+ACK response - port is open
        Some(PortState::Open)
    } else if flags & TcpFlags::RST != 0 {
        // RST response - port is closed
        Some(PortState::Closed)
    } else {
        None
    }
}

/// Handle SYN scan response packet (IPv6)
fn handle_syn_response_ipv6(
    packet: &[u8],
    source_port: u16,
    target_port: u16,
    target_ip: std::net::Ipv6Addr,
    source_ip: std::net::Ipv6Addr,
) -> Option<PortState> {
    use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
    use pnet::packet::ipv6::Ipv6Packet;
    use pnet::packet::tcp::{TcpPacket, TcpFlags};
    use pnet::packet::Packet;

    // Parse Ethernet frame
    let ethernet = EthernetPacket::new(packet)?;
    if ethernet.get_ethertype() != EtherTypes::Ipv6 {
        return None;
    }

    // Parse IPv6 packet
    let ipv6 = Ipv6Packet::new(ethernet.payload())?;
    if ipv6.get_source() != target_ip || ipv6.get_destination() != source_ip {
        return None;
    }

    // Parse TCP packet
    let tcp = TcpPacket::new(ipv6.payload())?;
    if tcp.get_source() != target_port || tcp.get_destination() != source_port {
        return None;
    }

    let flags = tcp.get_flags();

    // Check TCP flags to determine port state
    if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
        // SYN+ACK response - port is open
        Some(PortState::Open)
    } else if flags & TcpFlags::RST != 0 {
        // RST response - port is closed
        Some(PortState::Closed)
    } else {
        None
    }
}

/// Handle raw TCP response packet (for FIN, NULL, XMAS, ACK scans)
fn handle_raw_tcp_response(
    packet: &[u8],
    source_port: u16,
    target_port: u16,
    target_ip: std::net::Ipv4Addr,
    source_ip: std::net::Ipv4Addr,
) -> Option<u8> {
    use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::tcp::TcpPacket;
    use pnet::packet::Packet;

    // Parse Ethernet frame
    let ethernet = EthernetPacket::new(packet)?;
    if ethernet.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }

    // Parse IPv4 packet
    let ipv4 = Ipv4Packet::new(ethernet.payload())?;
    if ipv4.get_source() != target_ip || ipv4.get_destination() != source_ip {
        return None;
    }

    // Parse TCP packet
    let tcp = TcpPacket::new(ipv4.payload())?;
    if tcp.get_source() != target_port || tcp.get_destination() != source_port {
        return None;
    }

    Some(tcp.get_flags())
}