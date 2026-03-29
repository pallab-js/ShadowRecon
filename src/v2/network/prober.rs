use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use pnet::datalink::{DataLinkSender, NetworkInterface};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::Packet;
use anyhow::Result;

use crate::scanning::{calculate_tcp_checksum, calculate_tcp_checksum_ipv6, calculate_ipv4_checksum, get_local_ipv4, get_local_ipv6};

/// A centralized prober that sends network packets
pub struct Prober {
    tx: Arc<Mutex<Box<dyn DataLinkSender>>>,
    source_ipv4: Option<Ipv4Addr>,
    source_ipv6: Option<Ipv6Addr>,
    #[allow(dead_code)]
    source_mac: Option<[u8; 6]>,
    fragment: bool,
    mtu: usize,
    data_length: usize,
}

impl Prober {
    /// Create a new prober for the given interface
    pub fn new(interface: NetworkInterface, tx: Box<dyn DataLinkSender>) -> Self {
        let source_ipv4 = get_local_ipv4(&interface);
        let source_ipv6 = get_local_ipv6(&interface);
        let source_mac = interface.mac.map(|m| [m.0, m.1, m.2, m.3, m.4, m.5]);

        Self {
            tx: Arc::new(Mutex::new(tx)),
            source_ipv4,
            source_ipv6,
            source_mac,
            fragment: false,
            mtu: 1500,
            data_length: 0,
        }
    }

    /// Configure evasion options
    pub fn set_evasion_options(&mut self, fragment: bool, mtu: Option<usize>, data_length: Option<usize>) {
        self.fragment = fragment;
        if let Some(m) = mtu { self.mtu = m; }
        if let Some(d) = data_length { self.data_length = d; }
    }

    /// Set a spoofed source MAC
    #[allow(dead_code)]
    pub fn set_spoof_mac(&mut self, mac: [u8; 6]) {
        self.source_mac = Some(mac);
    }

    /// Set a spoofed source IPv4
    #[allow(dead_code)]
    pub fn set_spoof_ipv4(&mut self, ip: Ipv4Addr) {
        self.source_ipv4 = Some(ip);
    }

    /// Generic TCP probe sender
    pub fn send_tcp_probe(&self, target_ip: IpAddr, dest_port: u16, source_port: u16, flags: u8) -> Result<()> {
        match target_ip {
            IpAddr::V4(v4) => self.send_tcp_ipv4(v4, dest_port, source_port, flags),
            IpAddr::V6(v6) => self.send_tcp_ipv6(v6, dest_port, source_port, flags),
        }
    }

    fn send_tcp_ipv4(&self, target_ip: Ipv4Addr, dest_port: u16, source_port: u16, flags: u8) -> Result<()> {
        let source_ip = self.source_ipv4.ok_or_else(|| anyhow::anyhow!("No local IPv4 address"))?;
        
        let tcp_header_len = 20;
        let mut tcp_buffer = vec![0u8; tcp_header_len + self.data_length];
        
        // Add random padding if requested (before creating the packet to avoid borrow issues)
        if self.data_length > 0 {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut tcp_buffer[tcp_header_len..]);
        }

        {
            let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
            tcp_packet.set_source(source_port);
            tcp_packet.set_destination(dest_port);
            tcp_packet.set_sequence(rand::random::<u32>());
            tcp_packet.set_data_offset(5);
            tcp_packet.set_flags(flags);
            tcp_packet.set_window(65535);
            
            let checksum = calculate_tcp_checksum(&tcp_packet.to_immutable(), source_ip, target_ip);
            tcp_packet.set_checksum(checksum);
        }

        if self.fragment {
            let payload = &tcp_buffer;
            let mtu = (self.mtu.max(8) / 8) * 8; // Must be multiple of 8
            let identification = rand::random::<u16>();
            
            for (i, chunk) in payload.chunks(mtu).enumerate() {
                let is_last = (i + 1) * mtu >= payload.len();
                let offset = (i * mtu / 8) as u16;
                let mf_flag = if is_last { 0 } else { 0x2000 };
                
                let mut ip_buffer = vec![0u8; 20 + chunk.len()];
                let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
                ip_packet.set_version(4);
                ip_packet.set_header_length(5);
                ip_packet.set_total_length((20 + chunk.len()) as u16);
                ip_packet.set_identification(identification);
                ip_packet.set_fragment_offset(offset | mf_flag);
                ip_packet.set_ttl(64);
                ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
                ip_packet.set_source(source_ip);
                ip_packet.set_destination(target_ip);
                ip_packet.set_payload(chunk);
                
                let ip_checksum = calculate_ipv4_checksum(&ip_packet.to_immutable());
                ip_packet.set_checksum(ip_checksum);

                self.send_raw_packet(ip_packet.packet())?;
            }
            Ok(())
        } else {
            let mut ip_buffer = vec![0u8; 20 + tcp_buffer.len()];
            let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_total_length((20 + tcp_buffer.len()) as u16);
            ip_packet.set_ttl(64);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip_packet.set_source(source_ip);
            ip_packet.set_destination(target_ip);
            ip_packet.set_payload(&tcp_buffer);
            
            let ip_checksum = calculate_ipv4_checksum(&ip_packet.to_immutable());
            ip_packet.set_checksum(ip_checksum);

            self.send_raw_packet(ip_packet.packet())
        }
    }

    fn send_raw_packet(&self, packet: &[u8]) -> Result<()> {
        let mut tx = self.tx.lock().unwrap();
        tx.send_to(packet, None)
            .ok_or_else(|| anyhow::anyhow!("Failed to send packet"))?
            .map_err(|e| anyhow::anyhow!("Datalink send error: {}", e))
    }

    fn send_tcp_ipv6(&self, target_ip: Ipv6Addr, dest_port: u16, source_port: u16, flags: u8) -> Result<()> {
        let source_ip = self.source_ipv6.ok_or_else(|| anyhow::anyhow!("No local IPv6 address"))?;

        let tcp_header_len = 20;
        let mut tcp_buffer = vec![0u8; tcp_header_len + self.data_length];
        
        // Add random padding if requested (before creating the packet to avoid borrow issues)
        if self.data_length > 0 {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut tcp_buffer[tcp_header_len..]);
        }

        {
            let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
            tcp_packet.set_source(source_port);
            tcp_packet.set_destination(dest_port);
            tcp_packet.set_sequence(rand::random::<u32>());
            tcp_packet.set_data_offset(5);
            tcp_packet.set_flags(flags);
            tcp_packet.set_window(65535);

            let checksum = calculate_tcp_checksum_ipv6(&tcp_packet.to_immutable(), source_ip, target_ip);
            tcp_packet.set_checksum(checksum);
        }

        let mut ip_buffer = vec![0u8; 40 + tcp_buffer.len()];
        let mut ip_packet = MutableIpv6Packet::new(&mut ip_buffer).unwrap();
        ip_packet.set_version(6);
        ip_packet.set_payload_length(tcp_buffer.len() as u16);
        ip_packet.set_next_header(IpNextHeaderProtocols::Tcp);
        ip_packet.set_hop_limit(64);
        ip_packet.set_source(source_ip);
        ip_packet.set_destination(target_ip);
        ip_packet.set_payload(&tcp_buffer);

        self.send_raw_packet(ip_packet.packet())
    }
}
