use clap::{Arg, ArgMatches, Command};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use crate::types::{
    DiscoveryOptions, OutputFormat, PortRange, ScanConfig, ScanType, ServiceDetectionMode,
    TimingTemplate,
};

/// Parse command line arguments into a ScanConfig
pub fn parse_args() -> Result<ScanConfig, Box<dyn std::error::Error>> {
    let app = create_app();
    let matches = app.get_matches();

    let config = ScanConfig {
        targets: parse_targets(&matches)?,
        ports: parse_ports(&matches)?,
        scan_type: parse_scan_type(&matches),
        timing: parse_timing(&matches),
        service_detection: parse_service_detection(&matches),
        output_format: parse_output_format(&matches),
        output_file: matches.get_one::<String>("output").cloned(),
        threads: matches
            .get_one::<String>("threads")
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(num_cpus::get),
        timeout: Duration::from_millis(
            matches
                .get_one::<String>("timeout")
                .and_then(|s| s.parse().ok())
                .unwrap_or(5000),
        ),
        delay: matches
            .get_one::<String>("delay")
            .and_then(|s| s.parse().ok())
            .map(Duration::from_millis),
        max_retries: matches
            .get_one::<String>("max-retries")
            .and_then(|s| s.parse().ok())
            .unwrap_or(3),
        spoof_ip: matches
            .get_one::<String>("spoof-ip")
            .and_then(|s| IpAddr::from_str(s).ok()),
        decoy_ips: parse_decoy_ips(&matches)?,
        source_port: matches
            .get_one::<String>("source-port")
            .and_then(|s| s.parse().ok()),
        interface: matches.get_one::<String>("interface").cloned(),
        fragment_packets: matches.get_flag("fragment"),
        randomize_hosts: matches.get_flag("randomize-hosts"),
        randomize_ports: matches.get_flag("randomize-ports"),
        verbose: matches.get_flag("verbose"),
        debug: matches.get_flag("debug"),
        ipv6: matches.get_flag("ipv6"),
        resolve_hostname: matches.get_flag("resolve"),
        scripts: parse_scripts(&matches),
        script_args: parse_script_args(&matches),
        traceroute: matches.get_flag("traceroute"),
    };

    Ok(config)
}

/// Create the CLI application with all arguments
fn create_app() -> Command {
    Command::new("shadowrecon")
        .version(env!("CARGO_PKG_VERSION"))
        .author("RustScan Team")
        .about("ShadowRecon - advanced network discovery and port/service scanning tool")
        .long_about(
            "ShadowRecon is a fast, modern port scanner built in Rust. \
             It aims to be more powerful and flexible than traditional tools like nmap."
        )
        .arg(
            Arg::new("targets")
                .help("Target specification (IP, hostname, CIDR, or file)")
                .required(true)
                .num_args(1..)
                .index(1)
        )
        .arg(
            Arg::new("ports")
                .short('p')
                .long("ports")
                .help("Port specification (single, range, list, or 'top-N')")
                .default_value("1-1000")
                .num_args(1)
        )
        .arg(
            Arg::new("scan-type")
                .short('s')
                .long("scan-type")
                .help("Scan type")
                .value_parser(["S", "T", "U", "F", "N", "X", "A", "W", "M"])
                .default_value("T")
                .num_args(1)
        )
        .arg(
            Arg::new("timing")
                .short('T')
                .long("timing")
                .help("Timing template")
                .value_parser(["0", "1", "2", "3", "4", "5"])
                .default_value("3")
                .num_args(1)
        )
        .arg(
            Arg::new("service-detection")
                .long("service-version")
                .help("Service detection mode")
                .value_parser(["none", "basic", "advanced", "full"])
                .default_value("basic")
                .num_args(1)
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("Output file")
                .num_args(1)
        )
        .arg(
            Arg::new("output-format")
                .short('O')
                .long("output-format")
                .help("Output format")
                .value_parser(["text", "json", "xml", "csv", "html", "grep"])
                .default_value("text")
                .num_args(1)
        )
        .arg(
            Arg::new("threads")
                .short('t')
                .long("threads")
                .help("Number of threads")
                .default_value("4")
                .num_args(1)
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .help("Timeout in milliseconds")
                .default_value("5000")
                .num_args(1)
        )
        .arg(
            Arg::new("delay")
                .long("delay")
                .help("Delay between probes in milliseconds")
                .num_args(1)
        )
        .arg(
            Arg::new("max-retries")
                .long("max-retries")
                .help("Maximum number of retries")
                .default_value("3")
                .num_args(1)
        )
        .arg(
            Arg::new("spoof-ip")
                .long("spoof-ip")
                .help("Spoof source IP address")
                .num_args(1)
        )
        .arg(
            Arg::new("decoy")
                .short('D')
                .long("decoy")
                .help("Use decoy IPs (comma-separated)")
                .num_args(1)
        )
        .arg(
            Arg::new("source-port")
                .short('g')
                .long("source-port")
                .help("Use given source port")
                .num_args(1)
        )
        .arg(
            Arg::new("interface")
                .short('e')
                .long("interface")
                .help("Use specified network interface")
                .num_args(1)
        )
        .arg(
            Arg::new("fragment")
                .short('f')
                .long("fragment")
                .help("Fragment packets")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("randomize-hosts")
                .long("randomize-hosts")
                .help("Randomize target host order")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("randomize-ports")
                .long("randomize-ports")
                .help("Randomize target port order")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("ipv6")
                .short('6')
                .long("ipv6")
                .help("Enable IPv6 scanning")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("resolve")
                .short('R')
                .long("resolve")
                .help("Resolve hostnames")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Verbose output")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("debug")
                .short('d')
                .long("debug")
                .help("Debug output")
                .action(clap::ArgAction::SetTrue)
        )
        // Discovery options
        .arg(
            Arg::new("ping-sweep")
                .short('P')
                .long("ping-sweep")
                .help("Perform ping sweep discovery")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("arp-scan")
                .long("arp-scan")
                .help("Perform ARP scan discovery")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("traceroute")
                .long("traceroute")
                .help("Perform traceroute")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("os-detection")
                .long("os-detection")
                .help("Perform OS detection")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("script-scan")
                .long("script-scan")
                .help("Perform script scanning")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("aggressive")
                .short('A')
                .long("aggressive")
                .help("Enable aggressive scanning (OS detection, version detection, script scanning, traceroute)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("script")
                .long("script")
                .help("Specify script(s) to run (comma-separated script IDs)")
                .num_args(1)
        )
        .arg(
            Arg::new("script-args")
                .long("script-args")
                .help("Arguments to pass to scripts (key=value pairs, comma-separated)")
                .num_args(1)
        )
}

/// Parse target specifications
fn parse_targets(matches: &ArgMatches) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let targets: Vec<String> = matches
        .get_many::<String>("targets")
        .unwrap()
        .cloned()
        .collect();

    let mut expanded_targets = Vec::new();

    for target in targets {
        // Check if target is a file
        if std::fs::metadata(&target).is_ok() {
            let contents = std::fs::read_to_string(&target)?;
            for line in contents.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') {
                    expanded_targets.push(line.to_string());
                }
            }
        } else {
            // Basic validation for target format
            if target.contains("..") {
                return Err("Invalid target format: '..' not allowed".into());
            }
            if target.len() > 253 {
                return Err("Target too long".into());
            }
            expanded_targets.push(target);
        }
    }

    if expanded_targets.is_empty() {
        return Err("No valid targets specified".into());
    }

    Ok(expanded_targets)
}

/// Parse port specifications
fn parse_ports(matches: &ArgMatches) -> Result<PortRange, Box<dyn std::error::Error>> {
    let port_str = matches.get_one::<String>("ports").unwrap();

    // Check for special cases
    if port_str.to_lowercase() == "all" {
        return Ok(PortRange::All);
    }

    if let Some(top_n) = port_str.strip_prefix("top-") {
        if let Ok(n) = top_n.parse::<u16>() {
            return Ok(PortRange::Top(n));
        }
    }

    // Check for range (start-end)
    if let Some((start, end)) = port_str.split_once('-') {
        let start = start.parse::<u16>()?;
        let end = end.parse::<u16>()?;
        if start <= end {
            return Ok(PortRange::Range(start, end));
        }
    }

    // Check for comma-separated list
    if port_str.contains(',') {
        let ports: Result<Vec<u16>, _> = port_str
            .split(',')
            .map(|s| s.trim().parse::<u16>())
            .collect();
        return Ok(PortRange::List(ports?));
    }

    // Single port
    let port = port_str.parse::<u16>()?;
    Ok(PortRange::Single(port))
}

/// Parse scan type
fn parse_scan_type(matches: &ArgMatches) -> ScanType {
    let scan_type = matches.get_one::<String>("scan-type").unwrap();

    match scan_type.as_str() {
        "S" => ScanType::Syn,
        "T" => ScanType::Connect,
        "U" => ScanType::Udp,
        "F" => ScanType::Fin,
        "N" => ScanType::Null,
        "X" => ScanType::Xmas,
        "A" => ScanType::Ack,
        "W" => ScanType::Window,
        "M" => ScanType::Maimon,
        _ => ScanType::Connect, // Default
    }
}

/// Parse timing template
fn parse_timing(matches: &ArgMatches) -> TimingTemplate {
    let timing = matches.get_one::<String>("timing").unwrap();

    match timing.as_str() {
        "0" => TimingTemplate::Paranoid,
        "1" => TimingTemplate::Sneaky,
        "2" => TimingTemplate::Polite,
        "3" => TimingTemplate::Normal,
        "4" => TimingTemplate::Aggressive,
        "5" => TimingTemplate::Insane,
        _ => TimingTemplate::Normal,
    }
}

/// Parse service detection mode
fn parse_service_detection(matches: &ArgMatches) -> ServiceDetectionMode {
    let mode = matches.get_one::<String>("service-detection");

    match mode.map(|s| s.as_str()) {
        Some("none") => ServiceDetectionMode::None,
        Some("basic") => ServiceDetectionMode::Basic,
        Some("advanced") => ServiceDetectionMode::Advanced,
        Some("full") => ServiceDetectionMode::Full,
        _ => ServiceDetectionMode::Basic,
    }
}

/// Parse output format
fn parse_output_format(matches: &ArgMatches) -> OutputFormat {
    let format = matches.get_one::<String>("output-format").unwrap();

    match format.as_str() {
        "json" => OutputFormat::Json,
        "xml" => OutputFormat::Xml,
        "csv" => OutputFormat::Csv,
        "html" => OutputFormat::Html,
        "grep" => OutputFormat::Grep,
        _ => OutputFormat::Text,
    }
}

/// Parse decoy IPs
fn parse_decoy_ips(matches: &ArgMatches) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
    let decoys = matches.get_one::<String>("decoy");

    match decoys {
        Some(decoy_str) => {
            let ips: Result<Vec<IpAddr>, _> = decoy_str
                .split(',')
                .map(|s| s.trim().parse::<IpAddr>())
                .collect();
            Ok(ips?)
        }
        None => Ok(Vec::new()),
    }
}

/// Create discovery options from command line arguments
pub fn create_discovery_options(matches: &ArgMatches) -> DiscoveryOptions {
    let aggressive = matches.get_flag("aggressive");

    DiscoveryOptions {
        ping_sweep: matches.get_flag("ping-sweep") || aggressive,
        arp_scan: matches.get_flag("arp-scan") || aggressive,
        traceroute: matches.get_flag("traceroute") || aggressive,
        reverse_dns: matches.get_flag("resolve"),
        os_detection: matches.get_flag("os-detection") || aggressive,
        service_version: {
            let mode = matches.get_one::<String>("service-detection").unwrap();
            matches!(mode.as_str(), "advanced" | "full")
        } || aggressive,
        script_scan: matches.get_flag("script-scan") || aggressive,
        aggressive_timing: {
            let timing = matches.get_one::<String>("timing").unwrap();
            matches!(timing.as_str(), "4" | "5")
        },
    }
}

/// Parse script specifications
fn parse_scripts(matches: &ArgMatches) -> Vec<String> {
    matches
        .get_one::<String>("script")
        .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default()
}

/// Parse script arguments
fn parse_script_args(matches: &ArgMatches) -> std::collections::HashMap<String, String> {
    matches
        .get_one::<String>("script-args")
        .map(|s| {
            s.split(',')
                .filter_map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    match (parts.next(), parts.next()) {
                        (Some(key), Some(value)) => Some((key.trim().to_string(), value.trim().to_string())),
                        _ => None,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}