use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::Packet;

use crate::types::{DiscoveryOptions, HostInfo, HostStatus, ScanTiming};

/// Check if the program has raw socket capabilities
pub fn check_raw_socket_permissions() -> (bool, String) {
    use pnet::datalink;
    
    let interfaces = datalink::interfaces();
    let interface = match interfaces
        .into_iter()
        .find(|iface| !iface.is_loopback() && iface.is_up())
    {
        Some(iface) => iface,
        None => return (false, "No suitable network interface found".to_string()),
    };
    
    // Try to create a raw socket channel to test permissions
    match datalink::channel(&interface, Default::default()) {
        Ok(_) => (true, String::new()),
        Err(e) => (
            false,
            format!("Raw socket creation failed: {}. Some scans may require root/administrator privileges.", e),
        ),
    }
}

/// Discover live hosts using various techniques
pub async fn discover_hosts(
    targets: &[IpAddr],
    options: &DiscoveryOptions,
    timing: &ScanTiming,
) -> anyhow::Result<Vec<HostInfo>> {
    let mut live_hosts = Vec::new();
    let mut host_map: HashMap<IpAddr, HostInfo> = HashMap::new();

    // Initialize host info for all targets
    for &ip in targets {
        host_map.insert(ip, HostInfo {
            ip,
            hostname: None,
            mac: None,
            os: None,
            ports: Vec::new(),
            distance: None,
            traceroute: None,
            uptime: None,
            status: HostStatus::Unknown,
        });
    }

    // Perform ARP scan for local network
    if options.arp_scan {
        tracing::info!("Performing ARP scan...");
        let arp_results = arp_scan(targets, timing).await?;
        for (ip, mac) in arp_results {
            if let Some(host) = host_map.get_mut(&ip) {
                host.mac = Some(mac);
                host.status = HostStatus::Up;
                live_hosts.push(host.clone());
            }
        }
    }

    // Perform ICMP ping sweep
    if options.ping_sweep {
        tracing::info!("Performing ICMP ping sweep...");
        let ping_results = icmp_ping_sweep(targets, timing).await?;
        for ip in ping_results {
            if let Some(host) = host_map.get_mut(&ip) {
                host.status = HostStatus::Up;
                if !live_hosts.iter().any(|h| h.ip == ip) {
                    live_hosts.push(host.clone());
                }
            }
        }
    }

    // If no discovery methods were used, assume all targets are live
    if !options.ping_sweep && !options.arp_scan {
        live_hosts = targets
            .iter()
            .filter_map(|&ip| host_map.get(&ip).cloned())
            .collect();
    }

    Ok(live_hosts)
}

/// Perform ARP scan to discover hosts on local network
async fn arp_scan(
    targets: &[IpAddr],
    timing: &ScanTiming,
) -> anyhow::Result<HashMap<IpAddr, String>> {
    let mut results = HashMap::new();

    // Get network interfaces
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| !iface.is_loopback() && iface.is_up())
        .ok_or_else(|| anyhow::anyhow!("No suitable network interface found"))?;

    // Get IPv4 targets
    let ipv4_targets: Vec<Ipv4Addr> = targets
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(addr) => Some(*addr),
            IpAddr::V6(_) => None,
        })
        .collect();

    if ipv4_targets.is_empty() {
        return Ok(results);
    }

    // Create raw socket channel for ARP
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => {
            tracing::warn!("Could not create raw socket for ARP scan");
            return Ok(results);
        }
    };

    let source_ip = get_local_ip(&interface)
        .ok_or_else(|| anyhow::anyhow!("Could not determine local IPv4 address"))?;
    let source_mac = get_interface_mac(&interface)
        .ok_or_else(|| anyhow::anyhow!("Could not determine local MAC address"))?;

    // Parse MAC address
    let mac_bytes: Vec<u8> = source_mac
        .split(':')
        .map(|s| u8::from_str_radix(s, 16).unwrap_or(0))
        .collect();
    if mac_bytes.len() != 6 {
        return Ok(results);
    }
    let source_mac_bytes: [u8; 6] = [mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]];

    let broadcast_mac: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    // Send ARP requests for each target
    for target_ip in &ipv4_targets {
        if let Err(e) = send_arp_request_sync(
            *target_ip,
            source_ip,
            source_mac_bytes,
            broadcast_mac,
            &mut tx,
        ) {
            tracing::debug!("Failed to send ARP request for {}: {}", target_ip, e);
        }
    }

    // Collect ARP responses
    let start_time = std::time::Instant::now();
    let timeout = timing.max_rtt_timeout * 2; // Give more time for ARP
    
    while start_time.elapsed() < timeout {
        match rx.next() {
            Ok(packet) => {
                if let Some((ip, mac)) = parse_arp_response(&packet, &source_mac_bytes) {
                    results.insert(IpAddr::V4(ip), mac);
                }
            }
            Err(_) => break,
        }
    }

    Ok(results)
}

/// Perform ICMP ping sweep
async fn icmp_ping_sweep(
    targets: &[IpAddr],
    timing: &ScanTiming,
) -> anyhow::Result<Vec<IpAddr>> {
    let mut live_hosts = Vec::new();
    let mut tasks = Vec::new();

    // Create tasks for each target
    for &target in targets {
        if let IpAddr::V4(target_ip) = target {
            let timeout_duration = timing.max_rtt_timeout;
            let task = tokio::spawn(async move {
                icmp_ping_host(target_ip, timeout_duration).await
                    .map(|is_alive| if is_alive { Some(target) } else { None })
                    .unwrap_or(None)
            });
            tasks.push(task);
        } else {
            // IPv6 ICMP echo
            let timeout_duration = timing.max_rtt_timeout;
            let task = tokio::spawn(async move {
                icmpv6_ping_host(match target { IpAddr::V6(ip) => ip, _ => unreachable!() }, timeout_duration)
                    .await
                    .map(|is_alive| if is_alive { Some(target) } else { None })
                    .unwrap_or(None)
            });
            tasks.push(task);
        }
    }

    // Collect results
    for task in tasks {
        if let Ok(Some(host)) = task.await {
            live_hosts.push(host);
        }
    }

    Ok(live_hosts)
}

/// Send ICMP echo request to a single host
async fn icmp_ping_host(
    target_ip: Ipv4Addr,
    timeout: Duration,
) -> anyhow::Result<bool> {
    use pnet::datalink::{self};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::icmp::echo_request::{MutableEchoRequestPacket};
    use pnet::packet::icmp::IcmpTypes;
    use pnet::packet::ipv4::MutableIpv4Packet;
    

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

    // Generate ICMP echo request
    let identifier = rand::random::<u16>();
    let sequence_number = rand::random::<u16>();
    let mut icmp_buffer = [0u8; 8]; // ICMP header (8 bytes for echo request)
    let mut icmp_packet = MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();

    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_icmp_code(pnet::packet::icmp::IcmpCode(0));
    icmp_packet.set_identifier(identifier);
    icmp_packet.set_sequence_number(sequence_number);
    icmp_packet.set_checksum(0); // Will be calculated

    // Calculate ICMP checksum
    let checksum = calculate_icmp_checksum(&icmp_packet.to_immutable());
    icmp_packet.set_checksum(checksum);

    // Craft IPv4 packet
    let mut ip_buffer = [0u8; 28]; // IPv4 header (20) + ICMP header (8)
    let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();

    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(28);
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ip_packet.set_source(source_ip);
    ip_packet.set_destination(target_ip);
    ip_packet.set_payload(icmp_packet.packet());

    // Calculate IP checksum
    let ip_checksum = calculate_ipv4_checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(ip_checksum);

    // Send the packet
    let _ = tx.send_to(ip_packet.packet(), None)
        .ok_or_else(|| anyhow::anyhow!("Failed to send ICMP packet"))?;

    // Wait for response
    let start_time = std::time::Instant::now();
    while start_time.elapsed() < timeout {
        match rx.next() {
            Ok(packet) => {
                if let Some(is_echo_reply) = handle_icmp_response(&packet, identifier, sequence_number, target_ip, source_ip) {
                    return Ok(is_echo_reply);
                }
            }
            Err(_) => break,
        }
    }

    Ok(false)
}

/// Calculate ICMP checksum
fn calculate_icmp_checksum(icmp_packet: &pnet::packet::icmp::echo_request::EchoRequestPacket) -> u16 {
    let mut sum = 0u32;
    let data = icmp_packet.packet();

    let mut i = 0;
    while i < data.len() - 1 {
        if i != 2 && i != 3 { // Skip checksum field
            sum += (data[i] as u32) << 8 | data[i + 1] as u32;
        }
        i += 2;
    }
    if data.len() % 2 == 1 {
        sum += (data[data.len() - 1] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Calculate IPv4 checksum
fn calculate_ipv4_checksum(ip_packet: &pnet::packet::ipv4::Ipv4Packet) -> u16 {
    let mut sum = 0u32;
    let header = ip_packet.packet();

    let mut i = 0;
    while i < header.len() - 1 {
        if i != 10 && i != 11 { // Skip checksum field
            sum += (header[i] as u32) << 8 | header[i + 1] as u32;
        }
        i += 2;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Handle ICMP response packet
fn handle_icmp_response(
    packet: &[u8],
    expected_id: u16,
    expected_seq: u16,
    target_ip: std::net::Ipv4Addr,
    source_ip: std::net::Ipv4Addr,
) -> Option<bool> {
    use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::icmp::echo_reply::EchoReplyPacket;
    use pnet::packet::icmp::IcmpTypes;

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

    // Parse ICMP packet
    let icmp_data = ipv4.payload();
    if icmp_data.len() < 8 {
        return None;
    }

    // Check if it's an echo reply
    if icmp_data[0] == IcmpTypes::EchoReply.0 {
        let echo_reply = EchoReplyPacket::new(icmp_data)?;
        if echo_reply.get_identifier() == expected_id && echo_reply.get_sequence_number() == expected_seq {
            return Some(true);
        }
    }

    None
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

/// Resolve hostnames for discovered hosts
pub async fn resolve_hostnames(
    hosts: Vec<HostInfo>,
) -> anyhow::Result<Vec<HostInfo>> {
    let mut resolved_hosts = Vec::new();

    for mut host in hosts {
        // Try reverse DNS lookup
        match dns_lookup::lookup_addr(&host.ip) {
            Ok(hostname) => {
                host.hostname = Some(hostname);
            }
            Err(_) => {
                // Keep hostname as None if lookup fails
            }
        }
        resolved_hosts.push(host);
    }

    Ok(resolved_hosts)
}

/// Perform traceroute to determine network distance
pub async fn traceroute(
    target: IpAddr,
    max_hops: u8,
    timeout: Duration,
) -> anyhow::Result<Vec<crate::types::TracerouteHop>> {
    let mut hops = Vec::new();

    match target {
        IpAddr::V4(target_ip) => {
            // Get network interface
            let interfaces = datalink::interfaces();
            let interface = interfaces
                .into_iter()
                .find(|iface| !iface.is_loopback() && iface.is_up())
                .ok_or_else(|| anyhow::anyhow!("No suitable network interface found"))?;

            let source_ip = get_local_ipv4(&interface)
                .ok_or_else(|| anyhow::anyhow!("Could not determine local IPv4 address"))?;

            // Use ICMP TTL exceeded messages for traceroute
            for ttl in 1..=max_hops {
                let _start_time = Instant::now();

                // Create ICMP echo request with increasing TTL
                match icmp_traceroute_probe_ipv4(target_ip, source_ip, ttl, &interface, timeout).await {
                    Ok(Some((hop_ip, rtt))) => {
                        // Try reverse DNS lookup for hop
                        let hostname = dns_lookup::lookup_addr(&IpAddr::V4(hop_ip)).ok();
                        hops.push(crate::types::TracerouteHop {
                            hop: ttl,
                            ip: IpAddr::V4(hop_ip),
                            rtt,
                            hostname,
                        });

                        // If we reached the target, stop
                        if hop_ip == target_ip {
                            break;
                        }
                    }
                    Ok(None) => {
                        // No response - indicate timeout
                        hops.push(crate::types::TracerouteHop {
                            hop: ttl,
                            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                            rtt: timeout,
                            hostname: None,
                        });
                        // Continue for a few more hops before giving up
                        if hops.len() >= 3 && hops[hops.len()-3].ip == IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Traceroute probe failed at hop {}: {}", ttl, e);
                        break;
                    }
                }

                // Small delay between hops
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        IpAddr::V6(target_ip) => {
            // Get network interface
            let interfaces = datalink::interfaces();
            let interface = interfaces
                .into_iter()
                .find(|iface| !iface.is_loopback() && iface.is_up())
                .ok_or_else(|| anyhow::anyhow!("No suitable network interface found"))?;

            let source_ip = get_local_ipv6(&interface)
                .ok_or_else(|| anyhow::anyhow!("Could not determine local IPv6 address"))?;

            // Use ICMPv6 for IPv6 traceroute
            for ttl in 1..=max_hops {
                match icmpv6_traceroute_probe(target_ip, source_ip, ttl, &interface, timeout).await {
                    Ok(Some((hop_ip, rtt))) => {
                        // Try reverse DNS lookup for hop
                        let hostname = dns_lookup::lookup_addr(&IpAddr::V6(hop_ip)).ok();
                        hops.push(crate::types::TracerouteHop {
                            hop: ttl,
                            ip: IpAddr::V6(hop_ip),
                            rtt,
                            hostname,
                        });

                        // If we reached the target, stop
                        if hop_ip == target_ip {
                            break;
                        }
                    }
                    Ok(None) => {
                        // No response - indicate timeout
                        hops.push(crate::types::TracerouteHop {
                            hop: ttl,
                            ip: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                            rtt: timeout,
                            hostname: None,
                        });
                        // Continue for a few more hops before giving up
                        if hops.len() >= 3 && hops[hops.len()-3].ip == IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED) {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("IPv6 traceroute probe failed at hop {}: {}", ttl, e);
                        break;
                    }
                }

                // Small delay between hops
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

    Ok(hops)
}

/// Send ICMP probe with specific TTL for IPv4 traceroute
async fn icmp_traceroute_probe_ipv4(
    target_ip: Ipv4Addr,
    source_ip: Ipv4Addr,
    ttl: u8,
    interface: &NetworkInterface,
    timeout: Duration,
) -> anyhow::Result<Option<(Ipv4Addr, Duration)>> {
    use pnet::datalink;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
    use pnet::packet::icmp::IcmpTypes;
    use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Packet};
    use pnet::packet::Packet;

    // Open datalink channel
    let (mut tx, mut rx) = match datalink::channel(interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => return Ok(None),
    };

    // Build ICMP Echo Request
    let identifier = rand::random::<u16>();
    let sequence_number = ttl as u16;
    let mut icmp_buffer = [0u8; 8];
    let mut icmp_packet = MutableEchoRequestPacket::new(&mut icmp_buffer)
        .ok_or_else(|| anyhow::anyhow!("Failed to build ICMP packet"))?;
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_icmp_code(pnet::packet::icmp::IcmpCode(0));
    icmp_packet.set_identifier(identifier);
    icmp_packet.set_sequence_number(sequence_number);
    icmp_packet.set_checksum(0);
    use crate::discovery::calculate_icmp_checksum;
    let checksum = calculate_icmp_checksum(&icmp_packet.to_immutable());
    // Use local helper since calculate_icmp_checksum is private; fallback simple sum
    // If super::calculate_icmp_checksum isn't accessible, compute locally
    #[allow(unused)]
    fn sum_icmp(p: &pnet::packet::icmp::echo_request::EchoRequestPacket) -> u16 {
        let data = p.packet();
        let mut sum = 0u32;
        let mut i = 0;
        while i + 1 < data.len() {
            if i != 2 { // skip checksum high byte position; low will be i+1
                sum += ((data[i] as u32) << 8) | data[i + 1] as u32;
            }
            i += 2;
        }
        if data.len() % 2 == 1 { sum += (data[data.len()-1] as u32) << 8; }
        while (sum >> 16) != 0 { sum = (sum & 0xFFFF) + (sum >> 16); }
        !(sum as u16)
    }
    let checksum = if checksum == 0 { sum_icmp(&icmp_packet.to_immutable()) } else { checksum };
    icmp_packet.set_checksum(checksum);

    // Build IPv4 packet with specific TTL
    let mut ip_buffer = [0u8; 28];
    let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer)
        .ok_or_else(|| anyhow::anyhow!("Failed to build IPv4 packet"))?;
    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(28);
    ip_packet.set_ttl(ttl);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ip_packet.set_source(source_ip);
    ip_packet.set_destination(target_ip);
    ip_packet.set_payload(icmp_packet.packet());
    // No checksum for brevity (kernel may fill) ? optional

    // Send
    let _ = tx.send_to(ip_packet.packet(), None);

    // Receive and parse response
    let start = Instant::now();
    while start.elapsed() < timeout {
        match rx.next() {
            Ok(frame) => {
                // Ethernet ? IPv4 ? ICMP
                if let Some(eth) = pnet::packet::ethernet::EthernetPacket::new(frame) {
                    if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv4 { continue; }
                    if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                        if ipv4.get_destination() != source_ip { continue; }
                        // Check for ICMP Time Exceeded (type 11) or Echo Reply (type 0)
                        if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                            let icmp_data = ipv4.payload();
                            if icmp_data.len() >= 8 {
                                let icmp_type = icmp_data[0];
                                // ICMP Time Exceeded (11) - intermediate hop
                                if icmp_type == 11 {
                                    return Ok(Some((ipv4.get_source(), start.elapsed())));
                                }
                                // ICMP Echo Reply (0) - reached target
                                if icmp_type == 0 && icmp_data.len() >= 8 {
                                    let reply_id = ((icmp_data[4] as u16) << 8) | icmp_data[5] as u16;
                                    let reply_seq = ((icmp_data[6] as u16) << 8) | icmp_data[7] as u16;
                                    if reply_id == identifier && reply_seq == sequence_number {
                                        return Ok(Some((target_ip, start.elapsed())));
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

    Ok(None)
}

/// Send ICMPv6 probe with specific hop limit for traceroute
async fn icmpv6_traceroute_probe(
    target_ip: std::net::Ipv6Addr,
    source_ip: std::net::Ipv6Addr,
    hop_limit: u8,
    interface: &NetworkInterface,
    timeout: Duration,
) -> anyhow::Result<Option<(std::net::Ipv6Addr, Duration)>> {
    use pnet::datalink;
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
    use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket;
    use pnet::packet::icmpv6::{Icmpv6Types};
    use pnet::packet::ipv6::{MutableIpv6Packet, Ipv6Packet};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::Packet;

    // Open channel
    let (mut tx, mut rx) = match datalink::channel(interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => return Ok(None),
    };

    // ICMPv6 Echo Request
    let mut icmp_buf = [0u8; 8];
    let mut icmp = MutableEchoRequestPacket::new(&mut icmp_buf).ok_or_else(|| anyhow::anyhow!("Failed to build ICMPv6"))?;
    icmp.set_icmpv6_type(Icmpv6Types::EchoRequest);
    icmp.set_identifier(rand::random::<u16>());
    let sequence_number = hop_limit as u16;
    icmp.set_sequence_number(sequence_number);
    icmp.set_checksum(0);

    // Compute ICMPv6 checksum
    let checksum = icmpv6_checksum(source_ip, target_ip, icmp.packet());
    icmp.set_checksum(checksum);

    // IPv6 packet
    let mut v6_buf = [0u8; 48]; // 40 header + 8 icmpv6
    let mut v6 = MutableIpv6Packet::new(&mut v6_buf).ok_or_else(|| anyhow::anyhow!("Failed to build IPv6"))?;
    v6.set_version(6);
    v6.set_traffic_class(0);
    v6.set_flow_label(0);
    v6.set_payload_length(8);
    v6.set_next_header(IpNextHeaderProtocols::Icmpv6);
    v6.set_hop_limit(hop_limit);
    v6.set_source(source_ip);
    v6.set_destination(target_ip);
    v6.set_payload(icmp.packet());

    // Send
    let _ = tx.send_to(v6.packet(), None);

    // Wait for response
    let start = Instant::now();
    while start.elapsed() < timeout {
        match rx.next() {
            Ok(frame) => {
                if let Some(eth) = EthernetPacket::new(frame) {
                    if eth.get_ethertype() != EtherTypes::Ipv6 { continue; }
                    if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                        if ipv6.get_destination() != source_ip { continue; }
                        // Check for ICMPv6 Time Exceeded (type 3) or Echo Reply (type 129)
                        let payload = ipv6.payload();
                        if payload.len() >= 8 {
                            let icmp_type = payload[0];
                            // ICMPv6 Time Exceeded (3) - intermediate hop
                            if icmp_type == 3 {
                                return Ok(Some((ipv6.get_source(), start.elapsed())));
                            }
                            // ICMPv6 Echo Reply (129) - reached target
                            if icmp_type == 129 {
                                let reply_id = ((payload[4] as u16) << 8) | payload[5] as u16;
                                let reply_seq = ((payload[6] as u16) << 8) | payload[7] as u16;
                                if reply_id == icmp.get_identifier() && reply_seq == sequence_number {
                                    return Ok(Some((target_ip, start.elapsed())));
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }

    Ok(None)
}

/// Compute ICMPv6 checksum
fn icmpv6_checksum(source: std::net::Ipv6Addr, dest: std::net::Ipv6Addr, payload: &[u8]) -> u16 {
    use std::net::Ipv6Addr;

    let mut sum: u32 = 0;

    // Add source address (16 bytes)
    let source_bytes = source.octets();
    for chunk in source_bytes.chunks(2) {
        sum += (chunk[0] as u32) << 8 | chunk[1] as u32;
    }

    // Add destination address (16 bytes)
    let dest_bytes = dest.octets();
    for chunk in dest_bytes.chunks(2) {
        sum += (chunk[0] as u32) << 8 | chunk[1] as u32;
    }

    // Add upper layer packet length
    let length = payload.len() as u32;
    sum += length;

    // Add next header (ICMPv6 = 58)
    sum += 58;

    // Add ICMPv6 header and data
    let mut i = 0;
    while i + 1 < payload.len() {
        sum += (payload[i] as u32) << 8 | payload[i + 1] as u32;
        i += 2;
    }
    if i < payload.len() {
        sum += (payload[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Send ICMPv6 echo to an IPv6 host using raw sockets
async fn icmpv6_ping_host(target_ip: std::net::Ipv6Addr, timeout: Duration) -> anyhow::Result<bool> {
    use pnet::datalink;
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
    use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket as MutableEcho6;
    use pnet::packet::icmpv6::{Icmpv6Types};
    use pnet::packet::ipv6::{MutableIpv6Packet, Ipv6Packet};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::Packet;

    // Choose interface and source IPv6 address
    let interfaces = datalink::interfaces();
    let interface = match interfaces.into_iter().find(|iface| !iface.is_loopback() && iface.is_up()) {
        Some(iface) => iface,
        None => return Ok(false),
    };
    let source_ip = match get_local_ipv6(&interface) {
        Some(ip) => ip,
        None => return Ok(false),
    };

    // Open channel
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => return Ok(false),
    };

    // ICMPv6 Echo Request
    let mut icmp_buf = [0u8; 8];
    let mut icmp = MutableEcho6::new(&mut icmp_buf).ok_or_else(|| anyhow::anyhow!("Failed to build ICMPv6"))?;
    icmp.set_icmpv6_type(Icmpv6Types::EchoRequest);
    icmp.set_identifier(rand::random::<u16>());
    icmp.set_sequence_number(1);
    icmp.set_checksum(0);

    // IPv6 packet
    let mut v6_buf = [0u8; 48]; // 40 header + 8 icmpv6
    let mut v6 = MutableIpv6Packet::new(&mut v6_buf).ok_or_else(|| anyhow::anyhow!("Failed to build IPv6"))?;
    v6.set_version(6);
    v6.set_traffic_class(0);
    v6.set_flow_label(0);
    v6.set_payload_length(8);
    v6.set_next_header(IpNextHeaderProtocols::Icmpv6);
    v6.set_hop_limit(64);
    v6.set_source(source_ip);
    v6.set_destination(target_ip);
    v6.set_payload(icmp.packet());

    // Compute ICMPv6 checksum with IPv6 pseudo-header
    let checksum = icmpv6_checksum(source_ip, target_ip, icmp.packet());
    // Set checksum directly into the original buffer and update payload
    // Safety: same length, same structure
    let mut icmp_final = MutableEcho6::new(&mut icmp_buf).ok_or_else(|| anyhow::anyhow!("Failed to access ICMPv6"))?;
    icmp_final.set_checksum(checksum);
    v6.set_payload(icmp_final.packet());

    // Send
    let _ = tx.send_to(v6.packet(), None);

    // Wait for reply
    let start = Instant::now();
    while start.elapsed() < timeout {
        match rx.next() {
            Ok(frame) => {
                if let Some(eth) = EthernetPacket::new(frame) {
                    if eth.get_ethertype() != EtherTypes::Ipv6 { continue; }
                    if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                        if ipv6.get_source() != target_ip || ipv6.get_destination() != source_ip { continue; }
                        // ICMPv6 Echo Reply type is 129
                        let payload = ipv6.payload();
                        if payload.first().copied() == Some(Icmpv6Types::EchoReply.0) {
                            return Ok(true);
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }
    Ok(false)
}


/// Send ARP request for a target IP (synchronous)
fn send_arp_request_sync(
    target_ip: Ipv4Addr,
    source_ip: Ipv4Addr,
    source_mac: [u8; 6],
    dest_mac: [u8; 6],
    tx: &mut Box<dyn pnet::datalink::DataLinkSender>,
) -> anyhow::Result<()> {
    // Build ARP packet
    let mut arp_buffer = [0u8; 28]; // ARP packet size
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer)
        .ok_or_else(|| anyhow::anyhow!("Failed to build ARP packet"))?;

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(pnet::util::MacAddr(source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]));
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(pnet::util::MacAddr(0, 0, 0, 0, 0, 0));
    arp_packet.set_target_proto_addr(target_ip);

    // Build Ethernet frame
    let mut ethernet_buffer = vec![0u8; 14 + 28]; // Ethernet header (14) + ARP (28)
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer)
        .ok_or_else(|| anyhow::anyhow!("Failed to build Ethernet packet"))?;

    ethernet_packet.set_destination(pnet::util::MacAddr(dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]));
    ethernet_packet.set_source(pnet::util::MacAddr(source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]));
    ethernet_packet.set_ethertype(EtherTypes::Arp);
    ethernet_packet.set_payload(arp_packet.packet());

    // Send ARP request
    let _ = tx
        .send_to(ethernet_packet.packet(), None)
        .ok_or_else(|| anyhow::anyhow!("Failed to send ARP packet"))?;

    Ok(())
}

/// Parse ARP response from received packet
fn parse_arp_response(
    packet: &[u8],
    _source_mac: &[u8; 6],
) -> Option<(Ipv4Addr, String)> {
    use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
    use pnet::packet::arp::{ArpPacket, ArpOperations};
    use pnet::packet::Packet;

    let ethernet = EthernetPacket::new(packet)?;
    if ethernet.get_ethertype() != EtherTypes::Arp {
        return None;
    }

    let arp = ArpPacket::new(ethernet.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }

    // Verify this is a response to our request
    let sender_mac = arp.get_sender_hw_addr();
    let sender_ip = arp.get_sender_proto_addr();

    // Format MAC address
    let mac_str = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        sender_mac.0, sender_mac.1, sender_mac.2,
        sender_mac.3, sender_mac.4, sender_mac.5
    );

    Some((sender_ip, mac_str))
}

/// Get the local IP address for a given interface
fn get_local_ip(interface: &NetworkInterface) -> Option<Ipv4Addr> {
    for ip in &interface.ips {
        if let std::net::IpAddr::V4(addr) = ip.ip() {
            return Some(addr);
        }
    }
    None
}

/// Get the MAC address for a given interface
fn get_interface_mac(interface: &NetworkInterface) -> Option<String> {
    interface.mac.map(|mac| format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac.0, mac.1, mac.2, mac.3, mac.4, mac.5))
}

/// Get the local IPv6 address for a given interface
fn get_local_ipv6(interface: &NetworkInterface) -> Option<std::net::Ipv6Addr> {
    for ip in &interface.ips {
        if let std::net::IpAddr::V6(addr) = ip.ip() {
            if !addr.is_unicast_link_local() {
                return Some(addr);
            }
        }
    }
    None
}