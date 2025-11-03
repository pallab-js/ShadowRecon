
use colored::*;
use serde_json;

use crate::types::{OutputFormat, ScanResult};

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
}

impl OutputFormatter for TextFormatter {
    fn format(&self, result: &ScanResult) -> anyhow::Result<()> {
        println!("{}", "ShadowRecon Results".bold().underline());
        println!("Scanner version: {}", result.version);
        println!("Scan started: {}", result.start_time.format("%Y-%m-%d %H:%M:%S UTC"));
        if let Some(end_time) = result.end_time {
            println!("Scan ended: {}", end_time.format("%Y-%m-%d %H:%M:%S UTC"));
        }
        if let Some(runtime) = result.runtime {
            println!("Scan runtime: {:.2}s", runtime.as_secs_f64());
        }
        println!("Command line: {}", result.command_line);
        println!();

        println!("{} hosts scanned", result.hosts.len());

        for host in &result.hosts {
            println!();
            print_host_info(host);
            
            // Print traceroute if available
            if let Some(ref traceroute) = host.traceroute {
                if !traceroute.is_empty() {
                    println!("\nTraceroute:");
                    for hop in traceroute {
                        let hostname_str = hop.hostname.as_ref().map(|h| format!(" ({})", h)).unwrap_or_default();
                        println!("  {:>2}  {}{}  {:.2} ms", hop.hop, hop.ip, hostname_str, hop.rtt.as_secs_f64() * 1000.0);
                    }
                }
            }
        }

        println!();
        println!("Scan completed.");

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

/// XML output formatter
pub struct XmlFormatter;

impl XmlFormatter {
    pub fn new() -> Self {
        Self
    }
}

impl OutputFormatter for XmlFormatter {
    fn format(&self, result: &ScanResult) -> anyhow::Result<()> {
        // Simple XML output - in a real implementation, you'd use a proper XML library
        println!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        println!("<shadowrecon>");
        println!("  <scanner>{}</scanner>", result.scanner);
        println!("  <version>{}</version>", result.version);
        println!("  <start_time>{}</start_time>", result.start_time.to_rfc3339());
        if let Some(end_time) = result.end_time {
            println!("  <end_time>{}</end_time>", end_time.to_rfc3339());
        }
        if let Some(runtime) = result.runtime {
            println!("  <runtime>{:.2}</runtime>", runtime.as_secs_f64());
        }
        println!("  <command_line><![CDATA[{}]]></command_line>", result.command_line);

        println!("  <hosts>");
        for host in &result.hosts {
            println!("    <host>");
            println!("      <ip>{}</ip>", host.ip);
            if let Some(ref hostname) = host.hostname {
                println!("      <hostname>{}</hostname>", hostname);
            }
            if let Some(ref mac) = host.mac {
                println!("      <mac>{}</mac>", mac);
            }
            println!("      <status>{:?}</status>", host.status);

            println!("      <ports>");
            for port in &host.ports {
                println!("        <port number=\"{}\" protocol=\"{}\" state=\"{:?}\">",
                        port.port, port.protocol, port.state);
                if let Some(ref service) = port.service {
                    println!("          <service name=\"{}\">", service.name);
                    if let Some(ref version) = service.version {
                        println!("            <version>{}</version>", version);
                    }
                    if let Some(ref product) = service.product {
                        println!("            <product>{}</product>", product);
                    }
                    println!("          </service>");
                }
                println!("        </port>");
            }
            println!("      </ports>");
            println!("    </host>");
        }
        println!("  </hosts>");
        println!("</shadowrecon>");

        Ok(())
    }
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
        // CSV header
        println!("IP,Hostname,MAC,Port,Protocol,State,Service,Version,Product");

        for host in &result.hosts {
            for port in &host.ports {
                let hostname = host.hostname.as_ref().unwrap_or(&"".to_string()).clone();
                let mac = host.mac.as_ref().unwrap_or(&"".to_string()).clone();
                let service = port.service.as_ref().map(|s| s.name.clone()).unwrap_or_else(|| "".to_string());
                let version = port.service.as_ref().and_then(|s| s.version.clone()).unwrap_or_else(|| "".to_string());
                let product = port.service.as_ref().and_then(|s| s.product.clone()).unwrap_or_else(|| "".to_string());

                println!("{},{},{},{},{},{:?},{},{},{}",
                    host.ip, hostname, mac, port.port, port.protocol,
                    port.state, service, version, product);
            }
        }

        Ok(())
    }
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
        println!("<!DOCTYPE html>");
        println!("<html>");
        println!("<head>");
        println!("  <title>ShadowRecon Results</title>");
        println!("  <style>");
        println!("    body {{ font-family: Arial, sans-serif; margin: 20px; }}");
        println!("    .header {{ background-color: #f0f0f0; padding: 10px; border-radius: 5px; }}");
        println!("    .host {{ margin: 20px 0; border: 1px solid #ccc; border-radius: 5px; }}");
        println!("    .host-header {{ background-color: #e0e0e0; padding: 10px; }}");
        println!("    .port {{ margin: 5px; padding: 5px; background-color: #f9f9f9; }}");
        println!("    .open {{ border-left: 5px solid #4CAF50; }}");
        println!("    .closed {{ border-left: 5px solid #f44336; }}");
        println!("    .filtered {{ border-left: 5px solid #ff9800; }}");
        println!("  </style>");
        println!("</head>");
        println!("<body>");
        println!("  <div class=\"header\">");
        println!("    <h1>ShadowRecon Results</h1>");
        println!("    <p>Scanner version: {}</p>", result.version);
        println!("    <p>Scan started: {}</p>", result.start_time.format("%Y-%m-%d %H:%M:%S UTC"));
        if let Some(end_time) = result.end_time {
            println!("    <p>Scan ended: {}</p>", end_time.format("%Y-%m-%d %H:%M:%S UTC"));
        }
        if let Some(runtime) = result.runtime {
            println!("    <p>Scan runtime: {:.2}s</p>", runtime.as_secs_f64());
        }
        println!("    <p>Command line: <code>{}</code></p>", result.command_line);
        println!("  </div>");

        for host in &result.hosts {
            println!("  <div class=\"host\">");
            println!("    <div class=\"host-header\">");
            println!("      <h2>{}", host.ip);
            if let Some(ref hostname) = host.hostname {
                println!(" ({})", hostname);
            }
            println!("</h2>");
            if let Some(ref mac) = host.mac {
                println!("      <p>MAC: {}</p>", mac);
            }
            println!("      <p>Status: {:?}</p>", host.status);
            println!("    </div>");

            println!("    <div class=\"ports\">");
            for port in &host.ports {
                let css_class = match port.state {
                    crate::types::PortState::Open => "port open",
                    crate::types::PortState::Closed => "port closed",
                    crate::types::PortState::Filtered => "port filtered",
                    crate::types::PortState::Unknown => "port",
                };

                println!("      <div class=\"{}\">", css_class);
                println!("        <strong>Port {}/{}: {:?}</strong>", port.port, port.protocol, port.state);
                if let Some(ref service) = port.service {
                    println!(" - {} {}", service.name, service.version.as_ref().unwrap_or(&"".to_string()));
                    if let Some(ref product) = service.product {
                        println!(" ({})", product);
                    }
                }
                println!("      </div>");
            }
            println!("    </div>");
            println!("  </div>");
        }

        println!("</body>");
        println!("</html>");

        Ok(())
    }
}

/// Grepable output formatter (similar to nmap -oG)
pub struct GrepFormatter;

impl GrepFormatter {
    pub fn new() -> Self {
        Self
    }
}

impl OutputFormatter for GrepFormatter {
    fn format(&self, result: &ScanResult) -> anyhow::Result<()> {
        println!("# ShadowRecon {} scan initiated {} as: {}",
                result.version,
                result.start_time.format("%a %b %d %H:%M:%S %Y"),
                result.command_line);

        for host in &result.hosts {
            let hostname = host.hostname.as_ref().unwrap_or(&"".to_string()).clone();
            let hostname_part = if hostname.is_empty() { String::new() } else { format!("({})", hostname) };

            print!("Host: {} {} Status: {:?}", host.ip, hostname_part, host.status);

            if !host.ports.is_empty() {
                print!(" Ports:");
                for port in &host.ports {
                    let service = port.service.as_ref().map(|s| s.name.clone()).unwrap_or_else(|| "unknown".to_string());
                    print!(" {}/{:?}//{}/", port.port, port.state, service);
                }
            }

            println!();
        }

        println!("# ShadowRecon done at {}: {} IP address scanned",
                result.end_time.map(|t| t.format("%a %b %d %H:%M:%S %Y").to_string()).unwrap_or_else(|| "unknown".to_string()),
                result.hosts.len());

        Ok(())
    }
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
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(result)?;
            Ok(json)
        }
        OutputFormat::Xml => {
            let mut out = String::new();
            use std::fmt::Write as _;
            writeln!(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
            writeln!(out, "<shadowrecon>")?;
            writeln!(out, "  <scanner>{}</scanner>", result.scanner)?;
            writeln!(out, "  <version>{}</version>", result.version)?;
            writeln!(out, "  <start_time>{}</start_time>", result.start_time.to_rfc3339())?;
            if let Some(end_time) = result.end_time { writeln!(out, "  <end_time>{}</end_time>", end_time.to_rfc3339())?; }
            if let Some(runtime) = result.runtime { writeln!(out, "  <runtime>{:.2}</runtime>", runtime.as_secs_f64())?; }
            writeln!(out, "  <command_line><![CDATA[{}]]></command_line>", result.command_line)?;
            writeln!(out, "  <hosts>")?;
            for host in &result.hosts {
                writeln!(out, "    <host>")?;
                writeln!(out, "      <ip>{}</ip>", host.ip)?;
                if let Some(ref hostname) = host.hostname { writeln!(out, "      <hostname>{}</hostname>", hostname)?; }
                if let Some(ref mac) = host.mac { writeln!(out, "      <mac>{}</mac>", mac)?; }
                writeln!(out, "      <status>{:?}</status>", host.status)?;
                writeln!(out, "      <ports>")?;
                for port in &host.ports {
                    writeln!(out, "        <port number=\"{}\" protocol=\"{}\" state=\"{:?}\">", port.port, port.protocol, port.state)?;
                    if let Some(ref service) = port.service {
                        writeln!(out, "          <service name=\"{}\">", service.name)?;
                        if let Some(ref version) = service.version { writeln!(out, "            <version>{}</version>", version)?; }
                        if let Some(ref product) = service.product { writeln!(out, "            <product>{}</product>", product)?; }
                        writeln!(out, "          </service>")?;
                    }
                    writeln!(out, "        </port>")?;
                }
                writeln!(out, "      </ports>")?;
                writeln!(out, "    </host>")?;
            }
            writeln!(out, "  </hosts>")?;
            writeln!(out, "</shadowrecon>")?;
            Ok(out)
        }
        OutputFormat::Csv => {
            let mut out = String::from("IP,Hostname,MAC,Port,Protocol,State,Service,Version,Product\n");
            for host in &result.hosts {
                for port in &host.ports {
                    let hostname = host.hostname.as_deref().unwrap_or("");
                    let mac = host.mac.as_deref().unwrap_or("");
                    let service = port.service.as_ref().map(|s| s.name.as_str()).unwrap_or("unknown");
                    let version = port.service.as_ref().and_then(|s| s.version.as_deref()).unwrap_or("");
                    let product = port.service.as_ref().and_then(|s| s.product.as_deref()).unwrap_or("");
                    out.push_str(&format!("{},{},{},{},{},{:?},{},{},{}\n",
                        host.ip, hostname, mac, port.port, port.protocol, port.state, service, version, product));
                }
            }
            Ok(out)
        }
        OutputFormat::Html => {
            let mut out = String::new();
            use std::fmt::Write as _;
            writeln!(out, "<!DOCTYPE html>")?;
            writeln!(out, "<html><head><meta charset=\"utf-8\"><title>ShadowRecon Results</title></head><body>")?;
            writeln!(out, "<h1>ShadowRecon Results</h1>")?;
            writeln!(out, "<p>Scanner version: {}</p>", result.version)?;
            writeln!(out, "<p>Scan started: {}</p>", result.start_time.format("%Y-%m-%d %H:%M:%S UTC"))?;
            if let Some(end_time) = result.end_time { writeln!(out, "<p>Scan ended: {}</p>", end_time.format("%Y-%m-%d %H:%M:%S UTC"))?; }
            if let Some(runtime) = result.runtime { writeln!(out, "<p>Scan runtime: {:.2}s</p>", runtime.as_secs_f64())?; }
            for host in &result.hosts {
                writeln!(out, "<div><h2>{}</h2>", host.ip)?;
                if let Some(ref hostname) = host.hostname { writeln!(out, "<p>Hostname: {}</p>", hostname)?; }
                if let Some(ref mac) = host.mac { writeln!(out, "<p>MAC: {}</p>", mac)?; }
                writeln!(out, "<p>Status: {:?}</p>", host.status)?;
                writeln!(out, "<ul>")?;
                for port in &host.ports { 
                    let mut line = format!("<li>Port {}/{} {:?}", port.port, port.protocol, port.state);
                    if let Some(ref service) = port.service {
                        line.push_str(" - ");
                        line.push_str(&service.name);
                        if let Some(ref v) = service.version { line.push_str(&format!(" {}", v)); }
                        if let Some(ref p) = service.product { line.push_str(&format!(" ({})", p)); }
                    }
                    line.push_str("</li>");
                    writeln!(out, "{}", line)?;
                }
                writeln!(out, "</ul></div>")?;
            }
            writeln!(out, "</body></html>")?;
            Ok(out)
        }
        OutputFormat::Grep => {
            let mut out = String::new();
            use std::fmt::Write as _;
            writeln!(out, "# ShadowRecon {} scan initiated {} as: {}",
                     result.version,
                     result.start_time.format("%a %b %d %H:%M:%S %Y"),
                     result.command_line)?;
            for host in &result.hosts {
                let hostname = host.hostname.as_deref().unwrap_or("");
                let hostname_part = if hostname.is_empty() { String::new() } else { format!("({})", hostname) };
                write!(out, "Host: {} {} Status: {:?}", host.ip, hostname_part, host.status)?;
                if !host.ports.is_empty() {
                    out.push_str(" Ports:");
                    for port in &host.ports {
                        let service = port.service.as_ref().map(|s| s.name.as_str()).unwrap_or("unknown");
                        write!(out, " {}/{:?}//{}/", port.port, port.state, service)?;
                    }
                }
                out.push('\n');
            }
            writeln!(out, "# ShadowRecon done at {}: {} IP address scanned",
                     result.end_time.map(|t| t.format("%a %b %d %H:%M:%S %Y").to_string()).unwrap_or_else(|| "unknown".to_string()),
                     result.hosts.len())?;
            Ok(out)
        }
        // Fallback simple text rendering
        _ => {
            let mut s = String::new();
            use std::fmt::Write as _;
            writeln!(s, "RustScan Results")?;
            writeln!(s, "Scanner version: {}", result.version)?;
            writeln!(s, "Scan started: {}", result.start_time.format("%Y-%m-%d %H:%M:%S UTC"))?;
            if let Some(end_time) = result.end_time {
                writeln!(s, "Scan ended: {}", end_time.format("%Y-%m-%d %H:%M:%S UTC"))?;
            }
            if let Some(runtime) = result.runtime {
                writeln!(s, "Scan runtime: {:.2}s", runtime.as_secs_f64())?;
            }
            writeln!(s, "Command line: {}", result.command_line)?;
            writeln!(s)?;
            writeln!(s, "{} hosts scanned", result.hosts.len())?;
            for host in &result.hosts {
                writeln!(s)?;
                writeln!(s, "Host: {}", host.ip)?;
                if let Some(ref hostname) = host.hostname {
                    writeln!(s, "  Hostname: {}", hostname)?;
                }
                if let Some(ref mac) = host.mac {
                    writeln!(s, "  MAC Address: {}", mac)?;
                }
                writeln!(s, "  Status: {:?}", host.status)?;
                if !host.ports.is_empty() {
                    writeln!(s, "  Ports: {}", host.ports.len())?;
                    for port in &host.ports {
                        write!(s, "    PORT {}/{} {:?}", port.port, port.protocol, port.state)?;
                        if let Some(ref service) = port.service {
                            write!(s, " SERVICE {}", service.name)?;
                            if let Some(ref version) = service.version {
                                write!(s, " {}", version)?;
                            }
                            if let Some(ref product) = service.product {
                                write!(s, " ({})", product)?;
                            }
                        }
                        writeln!(s)?;
                    }
                } else {
                    writeln!(s, "  Ports: No ports found")?;
                }
            }
            writeln!(s)?;
            writeln!(s, "Scan completed.")?;
            Ok(s)
        }
    }
}

/// Print host information in a formatted way
fn print_host_info(host: &crate::types::HostInfo) {
    let status_color = match host.status {
        crate::types::HostStatus::Up => "green",
        crate::types::HostStatus::Down => "red",
        crate::types::HostStatus::Unknown => "yellow",
    };

    println!("{} {}",
        "Host:".bold(),
        host.ip.to_string().color(status_color).bold()
    );

    if let Some(ref hostname) = host.hostname {
        println!("  {} {}", "Hostname:".bold(), hostname);
    }

    if let Some(ref mac) = host.mac {
        println!("  {} {}", "MAC Address:".bold(), mac);
    }

    println!("  {} {:?}", "Status:".bold(), host.status);

    if !host.ports.is_empty() {
        println!("  {} {}", "Ports:".bold(), host.ports.len());
        for port in &host.ports {
            print_port_info(port);
        }
    } else {
        println!("  {} No ports found", "Ports:".bold());
    }
}

/// Print port information in a formatted way
fn print_port_info(port: &crate::types::PortInfo) {
    let state_color = match port.state {
        crate::types::PortState::Open => "green",
        crate::types::PortState::Closed => "red",
        crate::types::PortState::Filtered => "yellow",
        crate::types::PortState::Unknown => "grey",
    };

    print!("    {} {}/{} {:?}",
        "PORT".bold(),
        port.port.to_string().color(state_color).bold(),
        port.protocol,
        port.state
    );

    if let Some(ref service) = port.service {
        print!(" {} {}", "SERVICE".bold(), service.name);
        if let Some(ref version) = service.version {
            print!(" {}", version);
        }
        if let Some(ref product) = service.product {
            print!(" ({})", product);
        }
    }

    println!();
}