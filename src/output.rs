use colored::*;
use serde_json;

use crate::types::{OutputFormat, ScanResult, PortState, HostStatus};

/// Trait for output formatters
pub trait OutputFormatter {
    fn format(&self, result: &ScanResult) -> anyhow::Result<()>;
}

/// Text output formatter
pub struct TextFormatter;

impl TextFormatter {
    pub fn new() -> Self {
        Self
    }

    fn print_banner(&self) {
        let banner = r#"
   _____ _               _                 _____                      
  / ____| |             | |               |  __ \                     
 | (___ | |__   __ _  __| | _____      __ | |__) |___  ___ ___  _ __  
  \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / |  _  // _ \/ __/ _ \| '_ \ 
  ____) | | | | (_| | (_| | (_) \ V  V /  | | \ \  __/ (_| (_) | | | |
 |_____/|_| |_|\__,_|\__,_|\___/ \_/\_/   |_|  \_\___|\___\___/|_| |_|
        "#;
        println!("{}", banner.bright_cyan().bold());
        println!("  {} v{}\n", "Advanced Network Discovery & Reconnaissance".italic(), env!("CARGO_PKG_VERSION"));
    }
}

impl OutputFormatter for TextFormatter {
    fn format(&self, result: &ScanResult) -> anyhow::Result<()> {
        self.print_banner();

        println!("{} {}", "▶".bright_blue(), "Scan Session Information".bold());
        let target_display = result.hosts.first().map(|h| h.ip.to_string()).unwrap_or_else(|| "Unknown".to_string());
        println!("  {} {}", "Target(s):".dimmed(), target_display);
        println!("  {} {}", "Started:".dimmed(), result.start_time.format("%Y-%m-%d %H:%M:%S UTC"));
        if let Some(runtime) = result.runtime {
            println!("  {} {:.2}s", "Runtime:".dimmed(), runtime.as_secs_f64());
        }
        println!();

        let up_hosts = result.hosts.iter().filter(|h| h.status == HostStatus::Up).count();
        println!("{} {} hosts scanned ({} up)", "▶".bright_blue(), result.hosts.len().to_string().bold(), up_hosts.to_string().green().bold());

        for host in &result.hosts {
            println!("\n{}", "─".repeat(80).dimmed());
            println!("{} {}", "HOST".bold(), host.ip.to_string().bright_white().bold());
            
            if let Some(ref hostname) = host.hostname {
                println!("  {} {}", "DNS:".dimmed(), hostname);
            }
            if let Some(ref mac) = host.mac {
                println!("  {} {}", "MAC:".dimmed(), mac);
            }
            if let Some(ref os) = host.os {
                println!("  {} {} ({}%)", "OS:".dimmed(), os.name.bright_magenta(), os.accuracy);
            }

            if !host.ports.is_empty() {
                println!();
                println!("  {:<10} {:<15} {:<15} {:<20}", "PORT".bold(), "STATE".bold(), "SERVICE".bold(), "VERSION".bold());
                println!("  {:<10} {:<15} {:<15} {:<20}", "────".dimmed(), "─────".dimmed(), "───────".dimmed(), "───────".dimmed());

                for port in &host.ports {
                    let state_str = format!("{:?}", port.state);
                    let state_color = match port.state {
                        PortState::Open => state_str.green(),
                        PortState::Closed => state_str.red(),
                        PortState::Filtered => state_str.yellow(),
                        PortState::Unfiltered => state_str.blue(),
                        PortState::Unknown => state_str.dimmed(),
                    };

                    let service = port.service.as_ref();
                    let service_name = service.map(|s| s.name.as_str()).unwrap_or("unknown");
                    let version = service.map(|s| s.version.as_deref().unwrap_or("")).unwrap_or("");
                    let product = service.map(|s| s.product.as_deref().unwrap_or("")).unwrap_or("");
                    
                    let full_version = if !product.is_empty() {
                        format!("{} {}", product, version)
                    } else {
                        version.to_string()
                    };

                    println!("  {:<10} {:<15} {:<15} {:<20}", 
                        format!("{}/{}", port.port, port.protocol),
                        state_color.bold(),
                        service_name,
                        full_version
                    );

                    // Print script results if any
                    if let Some(ref service_info) = port.service {
                        if !service_info.script_results.is_empty() {
                            for (id, output) in &service_info.script_results {
                                println!("    {} {}: {}", "└─".dimmed(), id.yellow(), output.italic());
                            }
                        }
                    }
                }
            }

            if let Some(ref traceroute) = host.traceroute {
                if !traceroute.is_empty() {
                    println!("\n  {}", "Traceroute:".dimmed());
                    for hop in traceroute {
                        let hostname_str = hop.hostname.as_ref().map(|h| format!(" ({})", h)).unwrap_or_default();
                        println!("    {:>2}  {:<15} {:<20} {:.2} ms", hop.hop, hop.ip, hostname_str, hop.rtt.as_secs_f64() * 1000.0);
                    }
                }
            }
        }

        println!("\n{}", "─".repeat(80).dimmed());
        if let Some(end_time) = result.end_time {
            println!("{} Scan finished at {}", "✔".green(), end_time.format("%Y-%m-%d %H:%M:%S UTC"));
        }
        
        Ok(())
    }
}

/// JSON output formatter
pub struct JsonFormatter;

impl JsonFormatter {
    pub fn new() -> Self {
        Self
    }
}

impl OutputFormatter for JsonFormatter {
    fn format(&self, result: &ScanResult) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(result)?;
        println!("{}", json);
        Ok(())
    }
}

/// XML output formatter (Nmap compatible)
pub struct XmlFormatter;

impl XmlFormatter {
    pub fn new() -> Self {
        Self
    }
}

impl OutputFormatter for XmlFormatter {
    fn format(&self, result: &ScanResult) -> anyhow::Result<()> {
        println!("{}", format_xml(result)?);
        Ok(())
    }
}

fn format_xml(result: &ScanResult) -> anyhow::Result<String> {
    use std::fmt::Write as _;
    let mut out = String::new();
    writeln!(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
    writeln!(out, "<!DOCTYPE nmaprun>")?;
    writeln!(out, "<?xml-stylesheet href=\"file:///usr/share/nmap/nmap.xsl\" type=\"text/xsl\"?>")?;
    
    let start_timestamp = result.start_time.timestamp();
    writeln!(out, "<nmaprun scanner=\"shadowrecon\" args=\"{}\" start=\"{}\" startstr=\"{}\" version=\"{}\" xmloutputversion=\"1.05\">",
             result.command_line, start_timestamp, result.start_time.to_rfc3339(), result.version)?;
    
    writeln!(out, "<scaninfo type=\"{}\" protocol=\"{}\" numservices=\"{}\" services=\"{}\"/>",
             format!("{:?}", result.scan_info.scan_type).to_lowercase(),
             result.scan_info.protocol,
             result.scan_info.num_services,
             result.scan_info.services.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","))?;
    
    writeln!(out, "<verbose level=\"1\"/>")?;
    writeln!(out, "<debugging level=\"0\"/>")?;

    for host in &result.hosts {
        let status = if host.status == crate::types::HostStatus::Up { "up" } else { "down" };
        writeln!(out, "<host starttime=\"{}\" endtime=\"{}\">", start_timestamp, result.end_time.map(|t| t.timestamp()).unwrap_or(start_timestamp))?;
        writeln!(out, "  <status state=\"{}\" reason=\"unknown\" reason_ttl=\"0\"/>", status)?;
        writeln!(out, "  <address addr=\"{}\" addrtype=\"{}\"/>", host.ip, if host.ip.is_ipv4() { "ipv4" } else { "ipv6" })?;
        
        if let Some(ref hostname) = host.hostname {
            writeln!(out, "  <hostnames><hostname name=\"{}\" type=\"user\"/></hostnames>", hostname)?;
        }

        writeln!(out, "  <ports>")?;
        for port in &host.ports {
            let state = format!("{:?}", port.state).to_lowercase();
            writeln!(out, "    <port protocol=\"{}\" portid=\"{}\">", port.protocol, port.port)?;
            writeln!(out, "      <state state=\"{}\" reason=\"{}\" reason_ttl=\"{}\"/>", state, port.reason, port.ttl.unwrap_or(0))?;
            
            if let Some(ref service) = port.service {
                let product = service.product.as_deref().unwrap_or("");
                let version = service.version.as_deref().unwrap_or("");
                let cpe = service.cpe.as_deref().unwrap_or("");
                writeln!(out, "      <service name=\"{}\" product=\"{}\" version=\"{}\" method=\"probed\" conf=\"10\">", 
                         service.name, product, version)?;
                if !cpe.is_empty() {
                    writeln!(out, "        <cpe>{}</cpe>", cpe)?;
                }
                writeln!(out, "      </service>")?;
            }
            writeln!(out, "    </port>")?;
        }
        writeln!(out, "  </ports>")?;
        
        if let Some(ref os) = host.os {
            writeln!(out, "  <os>")?;
            writeln!(out, "    <osmatch name=\"{}\" accuracy=\"{}\" line=\"0\">", os.name, os.accuracy)?;
            if let Some(ref family) = os.family {
                writeln!(out, "      <osclass type=\"general purpose\" vendor=\"unknown\" osfamily=\"{}\" osgen=\"unknown\" accuracy=\"{}\">", family, os.accuracy)?;
                writeln!(out, "      </osclass>")?;
            }
            writeln!(out, "    </osmatch>")?;
            writeln!(out, "  </os>")?;
        }

        if let Some(ref distance) = host.distance {
            writeln!(out, "  <distance value=\"{}\"/>", distance)?;
        }

        writeln!(out, "</host>")?;
    }

    let end_timestamp = result.end_time.map(|t| t.timestamp()).unwrap_or(start_timestamp);
    writeln!(out, "<runstats><finished time=\"{}\" timestr=\"{}\" elapsed=\"{:.2}\" summary=\"ShadowRecon done at {}\" exit=\"success\"/><hosts up=\"{}\" down=\"{}\" total=\"{}\"/>",
             end_timestamp,
             result.end_time.map(|t| t.to_rfc3339()).unwrap_or_default(),
             result.runtime.map(|r| r.as_secs_f64()).unwrap_or(0.0),
             result.end_time.map(|t| t.to_rfc3339()).unwrap_or_default(),
             result.hosts.iter().filter(|h| h.status == crate::types::HostStatus::Up).count(),
             result.hosts.iter().filter(|h| h.status == crate::types::HostStatus::Down).count(),
             result.hosts.len())?;
    writeln!(out, "</runstats>")?;
    writeln!(out, "</nmaprun>")?;
    Ok(out)
}

/// CSV output formatter
pub struct CsvFormatter;

impl CsvFormatter {
    pub fn new() -> Self {
        Self
    }
}

impl OutputFormatter for CsvFormatter {
    fn format(&self, result: &ScanResult) -> anyhow::Result<()> {
        println!("{}", format_csv(result)?);
        Ok(())
    }
}

fn format_csv(result: &ScanResult) -> anyhow::Result<String> {
    let mut out = String::from("IP,Hostname,MAC,Port,Protocol,State,Service,Version,Product\n");
    for host in &result.hosts {
        for port in &host.ports {
            let hostname = host.hostname.as_deref().unwrap_or("");
            let mac = host.mac.as_deref().unwrap_or("");
            let service = port.service.as_ref().map(|s| s.name.as_str()).unwrap_or("unknown");
            let version = port.service.as_ref().and_then(|s| s.version.as_deref()).unwrap_or("");
            let product = port.service.as_ref().and_then(|s| s.product.as_deref()).unwrap_or("");

            out.push_str(&format!("{},{},{},{},{},{:?},{},{},{}\n",
                host.ip, hostname, mac, port.port, port.protocol,
                port.state, service, version, product));
        }
    }
    Ok(out)
}

/// HTML output formatter
pub struct HtmlFormatter;

impl HtmlFormatter {
    pub fn new() -> Self {
        Self
    }
}

impl OutputFormatter for HtmlFormatter {
    fn format(&self, result: &ScanResult) -> anyhow::Result<()> {
        println!("{}", format_html(result)?);
        Ok(())
    }
}

fn format_html(result: &ScanResult) -> anyhow::Result<String> {
    use std::fmt::Write as _;
    let mut out = String::new();
    writeln!(out, "<!DOCTYPE html>")?;
    writeln!(out, "<html>")?;
    writeln!(out, "<head>")?;
    writeln!(out, "  <title>ShadowRecon Results</title>")?;
    writeln!(out, "  <style>")?;
    writeln!(out, "    body {{ font-family: Arial, sans-serif; margin: 20px; }}")?;
    writeln!(out, "    .header {{ background-color: #f0f0f0; padding: 10px; border-radius: 5px; }}")?;
    writeln!(out, "    .host {{ margin: 20px 0; border: 1px solid #ccc; border-radius: 5px; }}")?;
    writeln!(out, "    .host-header {{ background-color: #e0e0e0; padding: 10px; }}")?;
    writeln!(out, "    .port {{ margin: 5px; padding: 5px; background-color: #f9f9f9; }}")?;
    writeln!(out, "    .open {{ border-left: 5px solid #4CAF50; }}")?;
    writeln!(out, "    .closed {{ border-left: 5px solid #f44336; }}")?;
    writeln!(out, "    .filtered {{ border-left: 5px solid #ff9800; }}")?;
    writeln!(out, "    .unfiltered {{ border-left: 5px solid #2196F3; }}")?;
    writeln!(out, "  </style>")?;
    writeln!(out, "</head>")?;
    writeln!(out, "<body>")?;
    writeln!(out, "  <div class=\"header\">")?;
    writeln!(out, "    <h1>ShadowRecon Results</h1>")?;
    writeln!(out, "    <p>Scanner version: {}</p>", result.version)?;
    writeln!(out, "    <p>Scan started: {}</p>", result.start_time.format("%Y-%m-%d %H:%M:%S UTC"))?;
    if let Some(end_time) = result.end_time {
        writeln!(out, "    <p>Scan ended: {}</p>", end_time.format("%Y-%m-%d %H:%M:%S UTC"))?;
    }
    if let Some(runtime) = result.runtime {
        writeln!(out, "    <p>Scan runtime: {:.2}s</p>", runtime.as_secs_f64())?;
    }
    writeln!(out, "    <p>Command line: <code>{}</code></p>", result.command_line)?;
    writeln!(out, "  </div>")?;

    for host in &result.hosts {
        writeln!(out, "  <div class=\"host\">")?;
        writeln!(out, "    <div class=\"host-header\">")?;
        writeln!(out, "      <h2>{}", host.ip)?;
        if let Some(ref hostname) = host.hostname {
            writeln!(out, " ({})", hostname)?;
        }
        writeln!(out, "</h2>")?;
        if let Some(ref mac) = host.mac {
            writeln!(out, "      <p>MAC: {}</p>", mac)?;
        }
        writeln!(out, "      <p>Status: {:?}</p>", host.status)?;
        writeln!(out, "    </div>")?;

        writeln!(out, "    <div class=\"ports\">")?;
        for port in &host.ports {
            let css_class = match port.state {
                crate::types::PortState::Open => "port open",
                crate::types::PortState::Closed => "port closed",
                crate::types::PortState::Filtered => "port-filtered",
                crate::types::PortState::Unfiltered => "port-unfiltered",
                crate::types::PortState::Unknown => "port",
            };

            writeln!(out, "      <div class=\"{}\">", css_class)?;
            writeln!(out, "        <strong>Port {}/{}: {:?}</strong>", port.port, port.protocol, port.state)?;
            if let Some(ref service) = port.service {
                write!(out, " - {} {}", service.name, service.version.as_ref().unwrap_or(&"".to_string()))?;
                if let Some(ref product) = service.product {
                    write!(out, " ({})", product)?;
                }
                writeln!(out)?;
            }
            writeln!(out, "      </div>")?;
        }
        writeln!(out, "    </div>")?;
        writeln!(out, "  </div>")?;
    }

    writeln!(out, "</body>")?;
    writeln!(out, "</html>")?;
    Ok(out)
}

/// Grepable output formatter (Nmap compatible -oG)
pub struct GrepFormatter;

impl GrepFormatter {
    pub fn new() -> Self {
        Self
    }
}

impl OutputFormatter for GrepFormatter {
    fn format(&self, result: &ScanResult) -> anyhow::Result<()> {
        println!("{}", format_grep(result)?);
        Ok(())
    }
}

fn format_grep(result: &ScanResult) -> anyhow::Result<String> {
    use std::fmt::Write as _;
    let mut out = String::new();
    writeln!(out, "# ShadowRecon {} scan initiated {} as: {}",
             result.version,
             result.start_time.format("%a %b %d %H:%M:%S %Y"),
             result.command_line)?;

    for host in &result.hosts {
        let hostname = host.hostname.as_deref().unwrap_or("");
        let hostname_part = if hostname.is_empty() { String::new() } else { format!("({})", hostname) };
        let status = if host.status == crate::types::HostStatus::Up { "Up" } else { "Down" };

        write!(out, "Host: {} {} \tStatus: {}", host.ip, hostname_part, status)?;

        if !host.ports.is_empty() {
            write!(out, "\tPorts: ")?;
            let mut port_strings = Vec::new();
            for port in &host.ports {
                let state = if port.state == PortState::Open { "open" } 
                            else if port.state == PortState::Closed { "closed" }
                            else { "filtered" };
                let service = port.service.as_ref().map(|s| s.name.as_str()).unwrap_or("unknown");
                port_strings.push(format!("{}/{}/{}/ / {}//", port.port, state, port.protocol, service));
            }
            write!(out, "{}", port_strings.join(", "))?;
        }
        writeln!(out)?;
    }

    writeln!(out, "# ShadowRecon done at {}: {} IP address scanned",
             result.end_time.map(|t| t.format("%a %b %d %H:%M:%S %Y").to_string()).unwrap_or_else(|| "unknown".to_string()),
             result.hosts.len())?;
    Ok(out)
}

/// Create output formatter based on format type
pub fn create_formatter(format: OutputFormat) -> Box<dyn OutputFormatter> {
    match format {
        OutputFormat::Text => Box::new(TextFormatter::new()),
        OutputFormat::Json => Box::new(JsonFormatter::new()),
        OutputFormat::Xml => Box::new(XmlFormatter::new()),
        OutputFormat::Csv => Box::new(CsvFormatter::new()),
        OutputFormat::Html => Box::new(HtmlFormatter::new()),
        OutputFormat::Grep => Box::new(GrepFormatter::new()),
    }
}

/// Render the output to a String for file writing
pub fn format_to_string(result: &ScanResult, format: OutputFormat) -> anyhow::Result<String> {
    match format {
        OutputFormat::Json => Ok(serde_json::to_string_pretty(result)?),
        OutputFormat::Xml => format_xml(result),
        OutputFormat::Csv => format_csv(result),
        OutputFormat::Html => format_html(result),
        OutputFormat::Grep => format_grep(result),
        _ => {
            // Text rendering for file
            let mut out = String::new();
            use std::fmt::Write as _;
            writeln!(out, "ShadowRecon Results")?;
            writeln!(out, "Scanner version: {}", result.version)?;
            writeln!(out, "Scan started: {}", result.start_time.format("%Y-%m-%d %H:%M:%S UTC"))?;
            for host in &result.hosts {
                writeln!(out, "\nHost: {} Status: {:?}", host.ip, host.status)?;
                for port in &host.ports {
                    writeln!(out, "  Port {}/{} {:?}", port.port, port.protocol, port.state)?;
                }
            }
            Ok(out)
        }
    }
}
