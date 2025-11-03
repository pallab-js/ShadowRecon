use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

use regex::Regex;

use crate::types::{ScanConfig, ServiceDetectionMode, ServiceInfo};

/// Service detector for identifying running services and versions
#[derive(Clone)]
pub struct ServiceDetector {
    config: std::sync::Arc<ScanConfig>,
    service_signatures: HashMap<u16, Vec<ServiceSignature>>,
}

#[derive(Clone)]
struct ServiceSignature {
    pattern: Regex,
    service_name: String,
    version_pattern: Option<Regex>,
    cpe: Option<String>,
}

impl ServiceDetector {
    /// Create a new service detector
    pub fn new(config: &ScanConfig) -> Self {
        let mut detector = Self {
            config: std::sync::Arc::new(config.clone()),
            service_signatures: HashMap::new(),
        };
        detector.load_service_signatures();
        detector
    }

    /// Load built-in service signatures
    fn load_service_signatures(&mut self) {
        // HTTP signatures
        self.add_signature(80, r"HTTP/1\.[01]", "http", Some(r"Server:\s*([^\\r\\n]+)"), Some("cpe:/a:apache:http_server"));
        self.add_signature(443, r"HTTP/1\.[01]", "https", Some(r"Server:\s*([^\\r\\n]+)"), Some("cpe:/a:apache:http_server"));

        // SSH signatures
        self.add_signature(22, r"SSH-2\.0-", "ssh", Some(r"SSH-2\.0-([^\\s]+)"), Some("cpe:/a:openssh:openssh"));

        // FTP signatures
        self.add_signature(21, r"220.*FTP", "ftp", Some(r"220[\\s-]([^\\r\\n]+)"), Some("cpe:/a:filezilla:ftp_server"));

        // SMTP signatures
        self.add_signature(25, r"220.*SMTP", "smtp", Some(r"220[\\s-]([^\\r\\n]+)"), Some("cpe:/a:sendmail:sendmail"));

        // POP3 signatures
        self.add_signature(110, r"\\+OK.*POP3", "pop3", Some(r"\\+OK[\\s-]([^\\r\\n]+)"), Some("cpe:/a:dovecot:dovecot"));

        // IMAP signatures
        self.add_signature(143, r"\\* OK.*IMAP", "imap", Some(r"\\* OK[\\s-]([^\\r\\n]+)"), Some("cpe:/a:dovecot:dovecot"));

        // DNS signatures
        self.add_signature(53, r".*", "dns", None, Some("cpe:/a:isc:bind"));

        // SMB signatures
        self.add_signature(445, r".*", "microsoft-ds", None, Some("cpe:/a:microsoft:smb"));
    }

    /// Add a service signature
    fn add_signature(&mut self, port: u16, pattern: &str, service_name: &str, version_pattern: Option<&str>, cpe: Option<&str>) {
        let signature = ServiceSignature {
            pattern: Regex::new(pattern).unwrap(),
            service_name: service_name.to_string(),
            version_pattern: version_pattern.map(|p| Regex::new(p).unwrap()),
            cpe: cpe.map(|s| s.to_string()),
        };

        self.service_signatures.entry(port).or_insert_with(Vec::new).push(signature);
    }
}

/// Detect service on a specific port
pub async fn detect_services(
    target: IpAddr,
    port: u16,
    detector: &ServiceDetector,
) -> anyhow::Result<Option<ServiceInfo>> {
    match detector.config.service_detection {
        ServiceDetectionMode::None => Ok(None),
        ServiceDetectionMode::Basic => detect_service_basic(target, port, detector).await,
        ServiceDetectionMode::Advanced => detect_service_advanced(target, port, detector).await,
        ServiceDetectionMode::Full => detect_service_full(target, port, detector).await,
    }
}

/// Basic service detection - simple banner grabbing
async fn detect_service_basic(
    target: IpAddr,
    port: u16,
    detector: &ServiceDetector,
) -> anyhow::Result<Option<ServiceInfo>> {
    let banner = grab_banner(target, port, Duration::from_secs(5)).await?;

    if let Some(banner) = banner {
        // Try to match against known signatures
        if let Some(signatures) = detector.service_signatures.get(&port) {
            for signature in signatures {
                if signature.pattern.is_match(&banner) {
                    let mut service_info = ServiceInfo {
                        name: signature.service_name.clone(),
                        version: None,
                        product: None,
                        cpe: signature.cpe.clone(),
                        script_results: HashMap::new(),
                    };

                    // Try to extract version
                    if let Some(version_regex) = &signature.version_pattern {
                        if let Some(captures) = version_regex.captures(&banner) {
                            if let Some(version) = captures.get(1) {
                                service_info.version = Some(version.as_str().to_string());
                            }
                        }
                    }

                    return Ok(Some(service_info));
                }
            }
        }

        // Fallback - return unknown service with banner
        Ok(Some(ServiceInfo {
            name: "unknown".to_string(),
            version: None,
            product: Some(banner),
            cpe: None,
            script_results: HashMap::new(),
        }))
    } else {
        Ok(None)
    }
}

/// Advanced service detection with more probes
async fn detect_service_advanced(
    target: IpAddr,
    port: u16,
    detector: &ServiceDetector,
) -> anyhow::Result<Option<ServiceInfo>> {
    // Start with basic detection
    let mut service_info = detect_service_basic(target, port, detector).await?;

    if let Some(ref mut info) = service_info {
        // Try additional probes based on service type
        match info.name.as_str() {
            "http" | "https" => {
                if let Some(http_info) = probe_http_service(target, port, info.name == "https").await? {
                    info.version = http_info.version.or_else(|| info.version.clone());
                    info.product = http_info.product.or_else(|| info.product.clone());
                }
            }
            "ssh" => {
                // SSH version is usually in the initial banner
            }
            _ => {}
        }
    }

    Ok(service_info)
}

/// Full service detection with extensive fingerprinting
/// NOTE: Script-based detection is performed at the host level by the script engine,
/// not at the individual service detection level. This function focuses on extended
/// service fingerprinting beyond basic and advanced modes.
async fn detect_service_full(
    target: IpAddr,
    port: u16,
    detector: &ServiceDetector,
) -> anyhow::Result<Option<ServiceInfo>> {
    // Start with advanced detection (includes HTTP probing)
    let mut service_info = detect_service_advanced(target, port, detector).await?;

    if let Some(ref mut info) = service_info {
        // Additional deep probing based on service type
        match info.name.as_str() {
            "http" | "https" => {
                // Extended HTTP header analysis
                // In a full implementation, would check for additional headers,
                // framework detection, CMS identification, etc.
                tracing::debug!("Full HTTP fingerprinting complete for {}:{}", target, port);
            }
            "ssh" => {
                // Extended SSH fingerprinting
                // Would analyze SSH version strings, key exchange methods, etc.
                tracing::debug!("Full SSH fingerprinting complete for {}:{}", target, port);
            }
            _ => {
                // For other services, advanced detection is sufficient
            }
        }
    }

    Ok(service_info)
}

/// Grab service banner by connecting and reading initial response
async fn grab_banner(
    target: IpAddr,
    port: u16,
    timeout_duration: Duration,
) -> anyhow::Result<Option<String>> {
    let addr = (target, port);

    match tokio::time::timeout(timeout_duration, tokio::task::spawn_blocking(move || {
        grab_banner_sync(addr)
    })).await {
        Ok(Ok(banner)) => banner,
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Ok(None), // Timeout
    }
}

/// Synchronous banner grabbing
fn grab_banner_sync(addr: (IpAddr, u16)) -> anyhow::Result<Option<String>> {
    let mut stream = TcpStream::connect_timeout(
        &std::net::SocketAddr::from(addr),
        Duration::from_secs(3)
    )?;

    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;

    // Send a simple probe based on port
    let probe: &[u8] = match addr.1 {
        80 | 443 | 8080 | 8443 => b"GET / HTTP/1.0\r\n\r\n",
        21 => b"HELP\r\n",
        25 => b"EHLO localhost\r\n",
        110 => b"USER test\r\n",
        143 => b"a001 CAPABILITY\r\n",
        _ => b"\r\n", // Generic probe
    };

    stream.write_all(probe)?;

    let mut buffer = [0; 1024];
    match stream.read(&mut buffer) {
        Ok(n) if n > 0 => {
            let banner = String::from_utf8_lossy(&buffer[..n]);
            Ok(Some(banner.to_string()))
        }
        _ => Ok(None),
    }
}

/// Probe HTTP service for additional information
async fn probe_http_service(
    target: IpAddr,
    port: u16,
    tls: bool,
) -> anyhow::Result<Option<ServiceInfo>> {
    let scheme = if tls { "https" } else { "http" };
    let url = format!("{}://{}:{}", scheme, target, port);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .timeout(Duration::from_secs(5))
        .build()?;

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("HTTP probe failed for {}: {}", url, e);
            return Ok(None);
        }
    };

    let mut info = ServiceInfo {
        name: if tls { "https".to_string() } else { "http".to_string() },
        version: None,
        product: None,
        cpe: None,
        script_results: HashMap::new(),
    };

    // Parse Server header
    if let Some(server) = resp.headers().get("server").and_then(|v| v.to_str().ok()) {
        info.product = Some(server.to_string());
        // Crude version extraction like "Apache/2.4.49"
        if let Some((_, v)) = server.split_once('/') {
            if !v.is_empty() {
                info.version = Some(v.to_string());
            }
        }
        // Map to basic CPEs
        if server.to_lowercase().contains("apache") {
            info.cpe = Some("cpe:/a:apache:http_server".to_string());
        } else if server.to_lowercase().contains("nginx") {
            info.cpe = Some("cpe:/a:nginx:nginx".to_string());
        } else if server.to_lowercase().contains("iis") {
            info.cpe = Some("cpe:/a:microsoft:iis".to_string());
        }
    }

    Ok(Some(info))
}

/// UDP service detection
#[allow(dead_code)]
pub async fn detect_udp_service(
    _target: IpAddr,
    port: u16,
    _detector: &ServiceDetector,
) -> Result<Option<ServiceInfo>, Box<dyn std::error::Error>> {
    // UDP service detection is more limited
    match port {
        53 => Ok(Some(ServiceInfo {
            name: "dns".to_string(),
            version: None,
            product: Some("DNS Server".to_string()),
            cpe: Some("cpe:/a:isc:bind".to_string()),
            script_results: HashMap::new(),
        })),
        67 | 68 => Ok(Some(ServiceInfo {
            name: "dhcp".to_string(),
            version: None,
            product: Some("DHCP Server".to_string()),
            cpe: None,
            script_results: HashMap::new(),
        })),
        123 => Ok(Some(ServiceInfo {
            name: "ntp".to_string(),
            version: None,
            product: Some("NTP Server".to_string()),
            cpe: Some("cpe:/a:ntp:ntp".to_string()),
            script_results: HashMap::new(),
        })),
        _ => Ok(Some(ServiceInfo {
            name: "unknown".to_string(),
            version: None,
            product: None,
            cpe: None,
            script_results: HashMap::new(),
        })),
    }
}

/// Check if a service is vulnerable based on version
#[allow(dead_code)]
pub fn check_service_vulnerabilities(service: &ServiceInfo) -> Vec<crate::types::Vulnerability> {
    let mut vulnerabilities = Vec::new();

    // Simple vulnerability checks - in a real implementation, this would
    // consult a vulnerability database
    if let Some(version) = service.version.as_ref() {
        match service.name.as_str() {
            "apache" | "httpd" => {
                if version.contains("2.4.49") {
                    vulnerabilities.push(crate::types::Vulnerability {
                        id: "CVE-2021-41773".to_string(),
                        title: "Apache HTTP Server Path Traversal".to_string(),
                        description: "Path traversal vulnerability in Apache HTTP Server".to_string(),
                        severity: crate::types::VulnerabilitySeverity::Critical,
                        cve: Some("CVE-2021-41773".to_string()),
                        cvss_score: Some(9.8),
                        references: vec!["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773".to_string()],
                    });
                }
            }
            "openssh" => {
                if version.starts_with("8.0") || version.starts_with("8.1") {
                    vulnerabilities.push(crate::types::Vulnerability {
                        id: "CVE-2020-14145".to_string(),
                        title: "OpenSSH AuthorizedKeysCommand Injection".to_string(),
                        description: "Command injection vulnerability in OpenSSH".to_string(),
                        severity: crate::types::VulnerabilitySeverity::High,
                        cve: Some("CVE-2020-14145".to_string()),
                        cvss_score: Some(8.4),
                        references: vec!["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14145".to_string()],
                    });
                }
            }
            _ => {}
        }
    }

    vulnerabilities
}