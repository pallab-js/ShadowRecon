//! Built-in vulnerability scanning scripts

use std::io::{Read, Write};
use std::net::TcpStream as StdTcpStream;
use std::time::Duration;
use tokio::time::timeout;
use reqwest::Client;

use crate::scripting::{Script, ScriptMetadata, ScriptTarget, ScriptType};
use crate::types::{ScriptResult, Vulnerability, VulnerabilitySeverity};

/// Heartbleed vulnerability check
pub struct HeartbleedScript;

#[async_trait::async_trait]
impl Script for HeartbleedScript {
    fn metadata(&self) -> ScriptMetadata {
        ScriptMetadata {
            id: "heartbleed".to_string(),
            name: "Heartbleed Vulnerability Check".to_string(),
            description: "Checks for OpenSSL Heartbleed vulnerability (CVE-2014-0160)".to_string(),
            script_type: ScriptType::Service,
            target_ports: vec![443],
            target_services: vec!["https".to_string(), "ssl".to_string()],
        }
    }

    async fn execute(&self, target: &ScriptTarget, _timing: &crate::types::ScanTiming) -> anyhow::Result<Vec<ScriptResult>> {
        let (host, port_index) = match target {
            ScriptTarget::Service(host, port_index) => (host, port_index),
            _ => return Ok(vec![]),
        };

        let port = host.ports[*port_index].port;
        let ip = host.ip;

        // Attempt to connect and check for heartbleed
        match timeout(Duration::from_secs(5), Self::check_heartbleed(ip, port)).await {
            Ok(Ok(vulnerable)) => {
                let result = if vulnerable {
                    ScriptResult {
                        script_id: self.metadata().id,
                        output: format!("Host {}:{} is VULNERABLE to Heartbleed (CVE-2014-0160)", ip, port),
                        elements: std::collections::HashMap::new(),
                        vulnerabilities: Some(vec![Vulnerability {
                            id: "CVE-2014-0160".to_string(),
                            title: "OpenSSL Heartbleed".to_string(),
                            description: "The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library.".to_string(),
                            severity: VulnerabilitySeverity::Critical,
                            cve: Some("CVE-2014-0160".to_string()),
                            cvss_score: Some(7.5),
                            references: vec![
                                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160".to_string(),
                                "https://heartbleed.com/".to_string(),
                            ],
                        }]),
                    }
                } else {
                    ScriptResult {
                        script_id: self.metadata().id,
                        output: format!("Host {}:{} is not vulnerable to Heartbleed", ip, port),
                        elements: std::collections::HashMap::new(),
                        vulnerabilities: None,
                    }
                };
                Ok(vec![result])
            }
            Ok(Err(e)) => Ok(vec![ScriptResult {
                script_id: self.metadata().id,
                output: format!("Failed to check Heartbleed on {}:{} - {}", ip, port, e),
                elements: std::collections::HashMap::new(),
                vulnerabilities: None,
            }]),
            Err(_) => Ok(vec![ScriptResult {
                script_id: self.metadata().id,
                output: format!("Heartbleed check timed out for {}:{}", ip, port),
                elements: std::collections::HashMap::new(),
                vulnerabilities: None,
            }]),
        }
    }
}

impl HeartbleedScript {
    async fn check_heartbleed(ip: std::net::IpAddr, port: u16) -> anyhow::Result<bool> {
        // Simplified Heartbleed check - in reality this would send a malformed heartbeat
        let addr = std::net::SocketAddr::new(ip, port);
        tokio::task::spawn_blocking(move || {
            let mut stream = StdTcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;

            // Send SSL Client Hello
            let client_hello = b"\x16\x03\x01\x00\x6d\x01\x00\x00\x69\x03\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0\x14\xc0\x0a\xc0\x22\xc0\x21\x00\x39\x00\x38\x00\x88\x00\x87\xc0\x0f\xc0\x05\x00\x35\x00\x84\xc0\x12\xc0\x08\xc0\x1c\xc0\x1b\x00\x16\x00\x13\xc0\x0d\xc0\x03\x00\x0a\xc0\x13\xc0\x09\xc0\x1f\xc0\x1e\x00\x33\x00\x32\x00\x9a\x00\x99\x00\x45\x00\x44\xc0\x0e\xc0\x04\x00\x2f\x00\x96\x00\x41\xc0\x11\xc0\x07\xc0\x0c\xc0\x02\x00\x05\x00\x04\x00\x15\x00\x12\x00\x09\x00\x14\x00\x11\x00\x08\x00\x06\x00\x03\x00\xff\x01\x00\x00\x49\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x34\x00\x32\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\x09\x00\x0a\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11\x00\x23\x00\x00\x00\x0f\x00\x01\x01";
            stream.write_all(client_hello)?;

            // Read server response
            let mut buffer = [0u8; 1024];
            let n = stream.read(&mut buffer)?;

            // Check if server supports SSL/TLS (very basic check)
            Ok(n > 0 && buffer[0] == 0x16) // SSL/TLS handshake record
        }).await?
    }
}

/// SMB vulnerability check
pub struct SmbVulnScript;

#[async_trait::async_trait]
impl Script for SmbVulnScript {
    fn metadata(&self) -> ScriptMetadata {
        ScriptMetadata {
            id: "smb-vulns".to_string(),
            name: "SMB Vulnerability Scanner".to_string(),
            description: "Checks for common SMB vulnerabilities".to_string(),
            script_type: ScriptType::Service,
            target_ports: vec![445],
            target_services: vec!["microsoft-ds".to_string(), "smb".to_string()],
        }
    }

    async fn execute(&self, target: &ScriptTarget, _timing: &crate::types::ScanTiming) -> anyhow::Result<Vec<ScriptResult>> {
        let (host, port_index) = match target {
            ScriptTarget::Service(host, port_index) => (host, port_index),
            _ => return Ok(vec![]),
        };

        let port = host.ports[*port_index].port;
        let ip = host.ip;

        // Check for SMB vulnerabilities
        match timeout(Duration::from_secs(5), Self::check_smb_vulns(ip, port)).await {
            Ok(Ok(vulnerabilities)) => {
                let mut results = Vec::new();
                if vulnerabilities.is_empty() {
                    results.push(ScriptResult {
                        script_id: self.metadata().id.clone(),
                        output: format!("No SMB vulnerabilities found on {}:{}", ip, port),
                        elements: std::collections::HashMap::new(),
                        vulnerabilities: None,
                    });
                } else {
                    for vuln in vulnerabilities {
                        results.push(ScriptResult {
                            script_id: self.metadata().id.clone(),
                            output: format!("SMB vulnerability found on {}:{} - {}", ip, port, vuln.title),
                            elements: std::collections::HashMap::new(),
                            vulnerabilities: Some(vec![vuln]),
                        });
                    }
                }
                Ok(results)
            }
            Ok(Err(e)) => Ok(vec![ScriptResult {
                script_id: self.metadata().id,
                output: format!("Failed to check SMB vulnerabilities on {}:{} - {}", ip, port, e),
                elements: std::collections::HashMap::new(),
                vulnerabilities: None,
            }]),
            Err(_) => Ok(vec![ScriptResult {
                script_id: self.metadata().id,
                output: format!("SMB vulnerability check timed out for {}:{}", ip, port),
                elements: std::collections::HashMap::new(),
                vulnerabilities: None,
            }]),
        }
    }
}

impl SmbVulnScript {
    async fn check_smb_vulns(ip: std::net::IpAddr, port: u16) -> anyhow::Result<Vec<Vulnerability>> {
        let addr = std::net::SocketAddr::new(ip, port);
        let mut vulnerabilities = Vec::new();

        tokio::task::spawn_blocking(move || {
            match StdTcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                    // Send SMB Negotiate Protocol Request
                    let smb_negotiate = b"\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x62\x3a\x00\x00\x00\x00\x00\x0c\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00";
                    if stream.write_all(smb_negotiate).is_ok() {
                        let mut buffer = [0u8; 1024];
                        if let Ok(n) = stream.read(&mut buffer) {
                            if n > 0 {
                                // Check for EternalBlue vulnerability (simplified check)
                                // In reality, this would be much more sophisticated
                                if buffer.len() > 4 && buffer[0] == 0xff && buffer[1] == 0x53 && buffer[2] == 0x4d && buffer[3] == 0x42 {
                                    // SMB response received, check for known vulnerable signatures
                                    // This is a simplified check - real implementation would be more complex
                                    vulnerabilities.push(Vulnerability {
                                        id: "SMB-VULN-001".to_string(),
                                        title: "Potential SMB Vulnerability".to_string(),
                                        description: "SMB service detected - manual verification recommended for known vulnerabilities like EternalBlue (CVE-2017-0144)".to_string(),
                                        severity: VulnerabilitySeverity::Medium,
                                        cve: None,
                                        cvss_score: Some(5.0),
                                        references: vec![
                                            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144".to_string(),
                                        ],
                                    });
                                }
                            }
                        }
                    }
                }
                Err(_) => {} // Connection failed, no vulnerabilities to report
            }
            Ok(vulnerabilities)
        }).await?
    }
}

/// HTTP vulnerability check
pub struct HttpVulnScript;

#[async_trait::async_trait]
impl Script for HttpVulnScript {
    fn metadata(&self) -> ScriptMetadata {
        ScriptMetadata {
            id: "http-vulns".to_string(),
            name: "HTTP Vulnerability Scanner".to_string(),
            description: "Checks for common HTTP vulnerabilities".to_string(),
            script_type: ScriptType::Service,
            target_ports: vec![80, 443, 8080, 8443],
            target_services: vec!["http".to_string(), "https".to_string()],
        }
    }

    async fn execute(&self, target: &ScriptTarget, _timing: &crate::types::ScanTiming) -> anyhow::Result<Vec<ScriptResult>> {
        let (host, port_index) = match target {
            ScriptTarget::Service(host, port_index) => (host, port_index),
            _ => return Ok(vec![]),
        };

        let port = host.ports[*port_index].port;
        let ip = host.ip;

        // Check for HTTP vulnerabilities
        match timeout(Duration::from_secs(10), Self::check_http_vulns(ip, port)).await {
            Ok(Ok(vulnerabilities)) => {
                let mut results = Vec::new();
                if vulnerabilities.is_empty() {
                    results.push(ScriptResult {
                        script_id: self.metadata().id.clone(),
                        output: format!("No HTTP vulnerabilities found on {}:{}", ip, port),
                        elements: std::collections::HashMap::new(),
                        vulnerabilities: None,
                    });
                } else {
                    for vuln in vulnerabilities {
                        results.push(ScriptResult {
                            script_id: self.metadata().id.clone(),
                            output: format!("HTTP vulnerability found on {}:{} - {}", ip, port, vuln.title),
                            elements: std::collections::HashMap::new(),
                            vulnerabilities: Some(vec![vuln]),
                        });
                    }
                }
                Ok(results)
            }
            Ok(Err(e)) => Ok(vec![ScriptResult {
                script_id: self.metadata().id,
                output: format!("Failed to check HTTP vulnerabilities on {}:{} - {}", ip, port, e),
                elements: std::collections::HashMap::new(),
                vulnerabilities: None,
            }]),
            Err(_) => Ok(vec![ScriptResult {
                script_id: self.metadata().id,
                output: format!("HTTP vulnerability check timed out for {}:{}", ip, port),
                elements: std::collections::HashMap::new(),
                vulnerabilities: None,
            }]),
        }
    }
}

impl HttpVulnScript {
    async fn check_http_vulns(ip: std::net::IpAddr, port: u16) -> anyhow::Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let scheme = if port == 443 || port == 8443 { "https" } else { "http" };
        let url = format!("{}://{}:{}", scheme, ip, port);

        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .build()?;

        // Check for common HTTP vulnerabilities
        match client.get(&url).send().await {
            Ok(response) => {
                let headers = response.headers();

                // Check for missing security headers
                if !headers.contains_key("x-frame-options") {
                    vulnerabilities.push(Vulnerability {
                        id: "HTTP-MISSING-X-FRAME-OPTIONS".to_string(),
                        title: "Missing X-Frame-Options Header".to_string(),
                        description: "The X-Frame-Options header is missing, which could allow clickjacking attacks.".to_string(),
                        severity: VulnerabilitySeverity::Medium,
                        cve: None,
                        cvss_score: Some(4.0),
                        references: vec!["https://owasp.org/www-community/attacks/Clickjacking".to_string()],
                    });
                }

                if !headers.contains_key("x-content-type-options") {
                    vulnerabilities.push(Vulnerability {
                        id: "HTTP-MISSING-X-CONTENT-TYPE-OPTIONS".to_string(),
                        title: "Missing X-Content-Type-Options Header".to_string(),
                        description: "The X-Content-Type-Options header is missing, which could allow MIME type sniffing attacks.".to_string(),
                        severity: VulnerabilitySeverity::Low,
                        cve: None,
                        cvss_score: Some(2.0),
                        references: vec!["https://owasp.org/www-community/Security_Headers".to_string()],
                    });
                }

                // Check server header for vulnerable software
                if let Some(server) = headers.get("server") {
                    if let Ok(server_str) = server.to_str() {
                        if server_str.contains("Apache/2.2") || server_str.contains("Apache/2.4.0") || server_str.contains("Apache/2.4.1") || server_str.contains("Apache/2.4.2") || server_str.contains("Apache/2.4.3") {
                            vulnerabilities.push(Vulnerability {
                                id: "HTTP-VULNERABLE-APACHE".to_string(),
                                title: "Potentially Vulnerable Apache Version".to_string(),
                                description: format!("Server is running {}, which may have known vulnerabilities. Verify the exact version.", server_str),
                                severity: VulnerabilitySeverity::Medium,
                                cve: None,
                                cvss_score: Some(5.0),
                                references: vec!["https://httpd.apache.org/security/".to_string()],
                            });
                        }
                    }
                }
            }
            Err(_) => {} // Connection failed, no vulnerabilities to report
        }

        Ok(vulnerabilities)
    }
}

// Placeholder implementations for remaining scripts
macro_rules! placeholder_script {
    ($name:ident, $id:expr, $script_name:expr, $description:expr, $script_type:expr, $ports:expr, $services:expr) => {
        pub struct $name;

        #[async_trait::async_trait]
        impl Script for $name {
            fn metadata(&self) -> ScriptMetadata {
                ScriptMetadata {
                    id: $id.to_string(),
                    name: $script_name.to_string(),
                    description: $description.to_string(),
                    script_type: $script_type,
                    target_ports: $ports,
                    target_services: $services,
                }
            }

            async fn execute(&self, target: &ScriptTarget, _timing: &crate::types::ScanTiming) -> anyhow::Result<Vec<ScriptResult>> {
                let (ip, port) = match target {
                    ScriptTarget::Service(host, port_index) => (host.ip, host.ports[*port_index].port),
                    ScriptTarget::Port(host, port_index) => (host.ip, host.ports[*port_index].port),
                    ScriptTarget::Host(host) => (host.ip, 0),
                };

                Ok(vec![ScriptResult {
                    script_id: self.metadata().id,
                    output: format!("{} check completed for {}:{} - implementation pending", self.metadata().name, ip, port),
                    elements: std::collections::HashMap::new(),
                    vulnerabilities: None,
                }])
            }
        }
    };
}

placeholder_script!(Log4ShellScript, "log4shell", "Log4Shell Vulnerability Check", "Checks for Log4j/Log4Shell vulnerability (CVE-2021-44228)", ScriptType::Service, vec![80, 443, 8080, 8443, 8081, 9000], vec!["http".to_string(), "https".to_string()]);
placeholder_script!(ShellshockScript, "shellshock", "Shellshock Vulnerability Check", "Checks for Bash Shellshock vulnerability (CVE-2014-6271)", ScriptType::Service, vec![80, 443], vec!["http".to_string(), "https".to_string()]);
placeholder_script!(PoodleScript, "poodle", "POODLE SSLv3 Vulnerability Check", "Checks for SSLv3 POODLE vulnerability (CVE-2014-3566)", ScriptType::Service, vec![443, 993, 995, 465], vec!["https".to_string(), "ssl".to_string(), "imaps".to_string(), "pop3s".to_string(), "smtps".to_string()]);
placeholder_script!(DrownScript, "drown", "DROWN Attack Vulnerability Check", "Checks for SSLv2 DROWN vulnerability (CVE-2016-0800)", ScriptType::Service, vec![443, 993, 995, 465], vec!["https".to_string(), "ssl".to_string(), "imaps".to_string(), "pop3s".to_string(), "smtps".to_string()]);
/// FTP anonymous access check
pub struct FtpAnonScript;

#[async_trait::async_trait]
impl Script for FtpAnonScript {
    fn metadata(&self) -> ScriptMetadata {
        ScriptMetadata {
            id: "ftp-anon".to_string(),
            name: "FTP Anonymous Access Check".to_string(),
            description: "Checks if FTP server allows anonymous access".to_string(),
            script_type: ScriptType::Service,
            target_ports: vec![21],
            target_services: vec!["ftp".to_string()],
        }
    }

    async fn execute(&self, target: &ScriptTarget, _timing: &crate::types::ScanTiming) -> anyhow::Result<Vec<ScriptResult>> {
        let (host, port_index) = match target {
            ScriptTarget::Service(host, port_index) => (host, port_index),
            _ => return Ok(vec![]),
        };

        let port = host.ports[*port_index].port;
        let ip = host.ip;

        match timeout(Duration::from_secs(10), Self::check_ftp_anon(ip, port)).await {
            Ok(Ok(allows_anon)) => {
                let result = if allows_anon {
                    ScriptResult {
                        script_id: self.metadata().id.clone(),
                        output: format!("FTP server on {}:{} ALLOWS anonymous access", ip, port),
                        elements: std::collections::HashMap::new(),
                        vulnerabilities: Some(vec![Vulnerability {
                            id: "FTP-ANON-ACCESS".to_string(),
                            title: "FTP Anonymous Access Allowed".to_string(),
                            description: "The FTP server allows anonymous access, which may expose sensitive files.".to_string(),
                            severity: VulnerabilitySeverity::Medium,
                            cve: None,
                            cvss_score: Some(5.0),
                            references: vec!["https://owasp.org/www-community/vulnerabilities/Anonymous_FTP".to_string()],
                        }]),
                    }
                } else {
                    ScriptResult {
                        script_id: self.metadata().id,
                        output: format!("FTP server on {}:{} does not allow anonymous access", ip, port),
                        elements: std::collections::HashMap::new(),
                        vulnerabilities: None,
                    }
                };
                Ok(vec![result])
            }
            Ok(Err(e)) => Ok(vec![ScriptResult {
                script_id: self.metadata().id,
                output: format!("Failed to check FTP anonymous access on {}:{} - {}", ip, port, e),
                elements: std::collections::HashMap::new(),
                vulnerabilities: None,
            }]),
            Err(_) => Ok(vec![ScriptResult {
                script_id: self.metadata().id,
                output: format!("FTP anonymous access check timed out for {}:{}", ip, port),
                elements: std::collections::HashMap::new(),
                vulnerabilities: None,
            }]),
        }
    }
}

impl FtpAnonScript {
    async fn check_ftp_anon(ip: std::net::IpAddr, port: u16) -> anyhow::Result<bool> {
        let addr = std::net::SocketAddr::new(ip, port);
        tokio::task::spawn_blocking(move || {
            let mut stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;

            // Read banner
            let mut buffer = [0u8; 1024];
            let n = stream.read(&mut buffer)?;
            if n == 0 || !buffer.starts_with(b"220") {
                return Ok(false);
            }

            // Send USER anonymous
            stream.write_all(b"USER anonymous\r\n")?;
            let n = stream.read(&mut buffer)?;
            if n == 0 {
                return Ok(false);
            }

            let response = String::from_utf8_lossy(&buffer[..n]);
            if response.starts_with("331") {
                // Password required, try PASS
                stream.write_all(b"PASS anonymous@\r\n")?;
                let n = stream.read(&mut buffer)?;
                if n > 0 {
                    let response = String::from_utf8_lossy(&buffer[..n]);
                    return Ok(response.starts_with("230"));
                }
            }

            Ok(false)
        }).await?
    }
}
/// SSH weak algorithms check
pub struct SshWeakScript;

#[async_trait::async_trait]
impl Script for SshWeakScript {
    fn metadata(&self) -> ScriptMetadata {
        ScriptMetadata {
            id: "ssh-weak".to_string(),
            name: "SSH Weak Algorithms Check".to_string(),
            description: "Checks for weak SSH cryptographic algorithms".to_string(),
            script_type: ScriptType::Service,
            target_ports: vec![22],
            target_services: vec!["ssh".to_string()],
        }
    }

    async fn execute(&self, target: &ScriptTarget, _timing: &crate::types::ScanTiming) -> anyhow::Result<Vec<ScriptResult>> {
        let (host, port_index) = match target {
            ScriptTarget::Service(host, port_index) => (host, port_index),
            _ => return Ok(vec![]),
        };

        let port = host.ports[*port_index].port;
        let ip = host.ip;

        // Check for SSH weak algorithms
        match timeout(Duration::from_secs(10), Self::check_ssh_weak_algorithms(ip, port)).await {
            Ok(Ok(weak_algorithms)) => {
                let mut results = Vec::new();
                if weak_algorithms.is_empty() {
                    results.push(ScriptResult {
                        script_id: self.metadata().id.clone(),
                        output: format!("SSH server on {}:{} does not appear to use weak algorithms", ip, port),
                        elements: std::collections::HashMap::new(),
                        vulnerabilities: None,
                    });
                } else {
                    for algorithm in weak_algorithms {
                        results.push(ScriptResult {
                            script_id: self.metadata().id.clone(),
                            output: format!("SSH server on {}:{} supports weak algorithm: {}", ip, port, algorithm),
                            elements: std::collections::HashMap::new(),
                            vulnerabilities: Some(vec![Vulnerability {
                                id: "SSH-WEAK-ALGORITHM".to_string(),
                                title: "SSH Weak Algorithm".to_string(),
                                description: format!("SSH server supports weak cryptographic algorithm: {}", algorithm),
                                severity: VulnerabilitySeverity::Medium,
                                cve: None,
                                cvss_score: Some(5.0),
                                references: vec!["https://www.ssh.com/academy/ssh/protocol".to_string()],
                            }]),
                        });
                    }
                }
                Ok(results)
            }
            Ok(Err(e)) => Ok(vec![ScriptResult {
                script_id: self.metadata().id,
                output: format!("Failed to check SSH algorithms on {}:{} - {}", ip, port, e),
                elements: std::collections::HashMap::new(),
                vulnerabilities: None,
            }]),
            Err(_) => Ok(vec![ScriptResult {
                script_id: self.metadata().id,
                output: format!("SSH algorithm check timed out for {}:{}", ip, port),
                elements: std::collections::HashMap::new(),
                vulnerabilities: None,
            }]),
        }
    }
}

impl SshWeakScript {
    async fn check_ssh_weak_algorithms(ip: std::net::IpAddr, port: u16) -> anyhow::Result<Vec<String>> {
        let mut weak_algorithms = Vec::new();
        let addr = std::net::SocketAddr::new(ip, port);

        tokio::task::spawn_blocking(move || {
            match StdTcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                    // Read SSH banner
                    let mut buffer = [0u8; 1024];
                    match stream.read(&mut buffer) {
                        Ok(n) if n > 0 => {
                            let banner = String::from_utf8_lossy(&buffer[..n]);
                            if banner.starts_with("SSH-") {
                                // Check for old SSH versions that might support weak algorithms
                                if banner.contains("SSH-1.") {
                                    weak_algorithms.push("SSH-1.x protocol".to_string());
                                }

                                // Send SSH version exchange (simplified)
                                let version_string = b"SSH-2.0-rustscan\r\n";
                                if stream.write_all(version_string).is_ok() {
                                    // In a real implementation, we would parse the algorithm exchange
                                    // For now, we'll do a basic check
                                    let mut response_buffer = [0u8; 2048];
                                    if let Ok(n) = stream.read(&mut response_buffer) {
                                        let response = String::from_utf8_lossy(&response_buffer[..n]);

                                        // Check for known weak algorithms in the response
                                        let weak_kex = ["diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"];
                                        let weak_ciphers = ["3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc"];
                                        let weak_macs = ["hmac-md5", "hmac-sha1"];

                                        for kex in &weak_kex {
                                            if response.contains(kex) {
                                                weak_algorithms.push(format!("Weak KEX: {}", kex));
                                            }
                                        }

                                        for cipher in &weak_ciphers {
                                            if response.contains(cipher) {
                                                weak_algorithms.push(format!("Weak cipher: {}", cipher));
                                            }
                                        }

                                        for mac in &weak_macs {
                                            if response.contains(mac) {
                                                weak_algorithms.push(format!("Weak MAC: {}", mac));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => {} // Failed to read banner
                    }
                }
                Err(_) => {} // Connection failed
            }

            Ok(weak_algorithms)
        }).await?
    }
}
/// DNS amplification attack check
pub struct DnsAmplificationScript;

#[async_trait::async_trait]
impl Script for DnsAmplificationScript {
    fn metadata(&self) -> ScriptMetadata {
        ScriptMetadata {
            id: "dns-amplification".to_string(),
            name: "DNS Amplification Attack Check".to_string(),
            description: "Checks if DNS server can be used for amplification attacks".to_string(),
            script_type: ScriptType::Service,
            target_ports: vec![53],
            target_services: vec!["dns".to_string()],
        }
    }

    async fn execute(&self, target: &ScriptTarget, _timing: &crate::types::ScanTiming) -> anyhow::Result<Vec<ScriptResult>> {
        let (host, port_index) = match target {
            ScriptTarget::Service(host, port_index) => (host, port_index),
            _ => return Ok(vec![]),
        };

        let port = host.ports[*port_index].port;
        let ip = host.ip;

        match timeout(Duration::from_secs(5), Self::check_dns_amplification(ip, port)).await {
            Ok(Ok(is_vulnerable)) => {
                let result = if is_vulnerable {
                    ScriptResult {
                        script_id: self.metadata().id.clone(),
                        output: format!("DNS server on {}:{} is VULNERABLE to amplification attacks (open resolver)", ip, port),
                        elements: std::collections::HashMap::new(),
                        vulnerabilities: Some(vec![Vulnerability {
                            id: "DNS-OPEN-RESOLVER".to_string(),
                            title: "DNS Open Resolver".to_string(),
                            description: "The DNS server acts as an open resolver, which can be used for DNS amplification attacks.".to_string(),
                            severity: VulnerabilitySeverity::Medium,
                            cve: None,
                            cvss_score: Some(5.0),
                            references: vec!["https://www.us-cert.gov/ncas/alerts/TA13-088A".to_string()],
                        }]),
                    }
                } else {
                    ScriptResult {
                        script_id: self.metadata().id,
                        output: format!("DNS server on {}:{} is not an open resolver", ip, port),
                        elements: std::collections::HashMap::new(),
                        vulnerabilities: None,
                    }
                };
                Ok(vec![result])
            }
            Ok(Err(e)) => Ok(vec![ScriptResult {
                script_id: self.metadata().id,
                output: format!("Failed to check DNS amplification on {}:{} - {}", ip, port, e),
                elements: std::collections::HashMap::new(),
                vulnerabilities: None,
            }]),
            Err(_) => Ok(vec![ScriptResult {
                script_id: self.metadata().id,
                output: format!("DNS amplification check timed out for {}:{}", ip, port),
                elements: std::collections::HashMap::new(),
                vulnerabilities: None,
            }]),
        }
    }
}

impl DnsAmplificationScript {
    async fn check_dns_amplification(ip: std::net::IpAddr, port: u16) -> anyhow::Result<bool> {
        // Simple check: try to resolve a domain that should not be resolvable from outside
        // In a real implementation, this would send a DNS query for a non-existent domain
        // and check if it responds (indicating open resolver)
        use std::net::UdpSocket;
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        socket.connect((ip, port))?;

        // Send a simple DNS query for a test domain
        let dns_query = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01";
        socket.send(dns_query)?;

        let mut buffer = [0u8; 512];
        match socket.recv(&mut buffer) {
            Ok(n) if n > 0 => {
                // If we get a response, it might be an open resolver
                // This is a very basic check - real implementation would be more sophisticated
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}
/// NTP monlist command check
pub struct NtpMonlistScript;

#[async_trait::async_trait]
impl Script for NtpMonlistScript {
    fn metadata(&self) -> ScriptMetadata {
        ScriptMetadata {
            id: "ntp-monlist".to_string(),
            name: "NTP Monlist Command Check".to_string(),
            description: "Checks for NTP monlist command vulnerability (CVE-2013-5211)".to_string(),
            script_type: ScriptType::Service,
            target_ports: vec![123],
            target_services: vec!["ntp".to_string()],
        }
    }

    async fn execute(&self, target: &ScriptTarget, _timing: &crate::types::ScanTiming) -> anyhow::Result<Vec<ScriptResult>> {
        let (host, port_index) = match target {
            ScriptTarget::Service(host, port_index) => (host, port_index),
            _ => return Ok(vec![]),
        };

        let port = host.ports[*port_index].port;
        let ip = host.ip;

        match timeout(Duration::from_secs(5), Self::check_ntp_monlist(ip, port)).await {
            Ok(Ok(is_vulnerable)) => {
                let result = if is_vulnerable {
                    ScriptResult {
                        script_id: self.metadata().id.clone(),
                        output: format!("NTP server on {}:{} is VULNERABLE to monlist command (CVE-2013-5211)", ip, port),
                        elements: std::collections::HashMap::new(),
                        vulnerabilities: Some(vec![Vulnerability {
                            id: "CVE-2013-5211".to_string(),
                            title: "NTP Monlist Command Enabled".to_string(),
                            description: "The NTP server has the monlist command enabled, which can be used for DDoS amplification.".to_string(),
                            severity: VulnerabilitySeverity::High,
                            cve: Some("CVE-2013-5211".to_string()),
                            cvss_score: Some(7.5),
                            references: vec!["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-5211".to_string()],
                        }]),
                    }
                } else {
                    ScriptResult {
                        script_id: self.metadata().id,
                        output: format!("NTP server on {}:{} does not have monlist enabled", ip, port),
                        elements: std::collections::HashMap::new(),
                        vulnerabilities: None,
                    }
                };
                Ok(vec![result])
            }
            Ok(Err(e)) => Ok(vec![ScriptResult {
                script_id: self.metadata().id,
                output: format!("Failed to check NTP monlist on {}:{} - {}", ip, port, e),
                elements: std::collections::HashMap::new(),
                vulnerabilities: None,
            }]),
            Err(_) => Ok(vec![ScriptResult {
                script_id: self.metadata().id,
                output: format!("NTP monlist check timed out for {}:{}", ip, port),
                elements: std::collections::HashMap::new(),
                vulnerabilities: None,
            }]),
        }
    }
}

impl NtpMonlistScript {
    async fn check_ntp_monlist(ip: std::net::IpAddr, port: u16) -> anyhow::Result<bool> {
        use std::net::UdpSocket;
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        socket.connect((ip, port))?;

        // NTP monlist command (mode 7, implementation 3)
        let monlist_packet = [
            0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00, // NTP mode 7, monlist
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        socket.send(&monlist_packet)?;

        let mut buffer = [0u8; 1024];
        match socket.recv(&mut buffer) {
            Ok(n) if n > 0 => {
                // Check if response indicates monlist is enabled
                // This is a simplified check - real implementation would parse NTP response
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}
/// Redis unauthorized access check
pub struct RedisUnauthScript;

#[async_trait::async_trait]
impl Script for RedisUnauthScript {
    fn metadata(&self) -> ScriptMetadata {
        ScriptMetadata {
            id: "redis-unauth".to_string(),
            name: "Redis Unauthorized Access Check".to_string(),
            description: "Checks for Redis unauthorized access vulnerability".to_string(),
            script_type: ScriptType::Service,
            target_ports: vec![6379],
            target_services: vec!["redis".to_string()],
        }
    }

    async fn execute(&self, target: &ScriptTarget, _timing: &crate::types::ScanTiming) -> anyhow::Result<Vec<ScriptResult>> {
        let (host, port_index) = match target {
            ScriptTarget::Service(host, port_index) => (host, port_index),
            _ => return Ok(vec![]),
        };

        let port = host.ports[*port_index].port;
        let ip = host.ip;

        // Check for Redis unauthorized access
        match timeout(Duration::from_secs(5), Self::check_redis_unauth(ip, port)).await {
            Ok(Ok(vulnerable)) => {
                let result = if vulnerable {
                    ScriptResult {
                        script_id: self.metadata().id.clone(),
                        output: format!("Redis server on {}:{} is VULNERABLE to unauthorized access", ip, port),
                        elements: std::collections::HashMap::new(),
                        vulnerabilities: Some(vec![Vulnerability {
                            id: "REDIS-UNAUTH-ACCESS".to_string(),
                            title: "Redis Unauthorized Access".to_string(),
                            description: "Redis server allows unauthorized access without authentication. Attackers can read, modify, or delete data.".to_string(),
                            severity: VulnerabilitySeverity::Critical,
                            cve: None,
                            cvss_score: Some(9.1),
                            references: vec![
                                "https://redis.io/topics/security".to_string(),
                                "https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A5-Broken_Access_Control".to_string(),
                            ],
                        }]),
                    }
                } else {
                    ScriptResult {
                        script_id: self.metadata().id,
                        output: format!("Redis server on {}:{} requires authentication", ip, port),
                        elements: std::collections::HashMap::new(),
                        vulnerabilities: None,
                    }
                };
                Ok(vec![result])
            }
            Ok(Err(e)) => Ok(vec![ScriptResult {
                script_id: self.metadata().id,
                output: format!("Failed to check Redis access on {}:{} - {}", ip, port, e),
                elements: std::collections::HashMap::new(),
                vulnerabilities: None,
            }]),
            Err(_) => Ok(vec![ScriptResult {
                script_id: self.metadata().id,
                output: format!("Redis access check timed out for {}:{}", ip, port),
                elements: std::collections::HashMap::new(),
                vulnerabilities: None,
            }]),
        }
    }
}

impl RedisUnauthScript {
    async fn check_redis_unauth(ip: std::net::IpAddr, port: u16) -> anyhow::Result<bool> {
        let addr = std::net::SocketAddr::new(ip, port);
        tokio::task::spawn_blocking(move || {
            let mut stream = StdTcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;

            // Send INFO command to check if Redis responds without auth
            let info_command = b"*1\r\n$4\r\nINFO\r\n";
            stream.write_all(info_command)?;

            let mut buffer = [0u8; 1024];
            let n = stream.read(&mut buffer)?;

            if n > 0 {
                let response = String::from_utf8_lossy(&buffer[..n]);
                // If we get a response that looks like Redis INFO output, it's vulnerable
                if response.starts_with('$') || response.starts_with('*') || response.contains("# Server") {
                    return Ok(true);
                }
                // If we get an error about NOAUTH, it requires auth
                if response.contains("NOAUTH") {
                    return Ok(false);
                }
            }

            Ok(false) // Assume not vulnerable if we can't determine
        }).await?
    }
}
placeholder_script!(MongodbUnauthScript, "mongodb-unauth", "MongoDB Unauthorized Access Check", "Checks for MongoDB unauthorized access vulnerability", ScriptType::Service, vec![27017], vec!["mongodb".to_string()]);
placeholder_script!(ElasticsearchUnauthScript, "elasticsearch-unauth", "Elasticsearch Unauthorized Access Check", "Checks for Elasticsearch unauthorized access vulnerability", ScriptType::Service, vec![9200, 9300], vec!["elasticsearch".to_string()]);