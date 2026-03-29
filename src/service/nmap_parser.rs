use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct NmapServiceProbe {
    pub protocol: String,
    #[allow(dead_code)]
    pub name: String,
    pub probe_string: Vec<u8>,
    pub matches: Vec<ServiceMatch>,
    pub soft_matches: Vec<ServiceMatch>,
    pub ports: Vec<u16>,
    pub sslports: Vec<u16>,
    pub rarity: u8,
    pub fallback: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ServiceMatch {
    pub service: String,
    pub pattern: Regex,
    #[allow(dead_code)]
    pub version_info: String,
}

pub struct NmapServiceProbeFile {
    pub probes: Vec<NmapServiceProbe>,
}

impl NmapServiceProbeFile {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut probes = Vec::new();
        let mut current_probe: Option<NmapServiceProbe> = None;

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with("Probe ") {
                if let Some(probe) = current_probe.take() {
                    probes.push(probe);
                }
                
                let parts: Vec<&str> = line.splitn(4, ' ').collect();
                if parts.len() >= 4 {
                    current_probe = Some(NmapServiceProbe {
                        protocol: parts[1].to_string(),
                        name: parts[2].to_string(),
                        probe_string: parse_nmap_string(parts[3]),
                        matches: Vec::new(),
                        soft_matches: Vec::new(),
                        ports: Vec::new(),
                        sslports: Vec::new(),
                        rarity: 0,
                        fallback: Vec::new(),
                    });
                }
            } else if let Some(ref mut probe) = current_probe {
                if line.starts_with("match ") {
                    if let Some(m) = parse_match(line, "match ") {
                        probe.matches.push(m);
                    }
                } else if line.starts_with("softmatch ") {
                    if let Some(m) = parse_match(line, "softmatch ") {
                        probe.soft_matches.push(m);
                    }
                } else if line.starts_with("ports ") {
                    probe.ports = parse_port_list(&line[6..]);
                } else if line.starts_with("sslports ") {
                    probe.sslports = parse_port_list(&line[9..]);
                } else if line.starts_with("rarity ") {
                    probe.rarity = line[7..].parse().unwrap_or(0);
                } else if line.starts_with("fallback ") {
                    probe.fallback = line[9..].split(',').map(|s| s.trim().to_string()).collect();
                }
            }
        }

        if let Some(probe) = current_probe {
            probes.push(probe);
        }

        Ok(Self { probes })
    }
}

fn parse_nmap_string(s: &str) -> Vec<u8> {
    // Basic nmap string parsing (supports \xHH, \r, \n, \t)
    // Format is usually q|...| where | is the delimiter
    if s.len() < 3 {
        return Vec::new();
    }
    let delimiter = s.chars().nth(1).unwrap();
    let end_index = s.rfind(delimiter).unwrap_or(s.len());
    let content = &s[2..end_index];
    
    let mut result = Vec::new();
    let mut i = 0;
    let chars: Vec<char> = content.chars().collect();
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            match chars[i + 1] {
                'r' => { result.push(b'\r'); i += 2; }
                'n' => { result.push(b'\n'); i += 2; }
                't' => { result.push(b'\t'); i += 2; }
                'x' => {
                    if i + 3 < chars.len() {
                        let hex = format!("{}{}", chars[i+2], chars[i+3]);
                        if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                            result.push(byte);
                            i += 4;
                            continue;
                        }
                    }
                    result.push(b'x');
                    i += 2;
                }
                '0'..='7' => {
                    // Octal
                    i += 2; // Stub for now
                }
                c => { result.push(c as u8); i += 2; }
            }
        } else {
            result.push(chars[i] as u8);
            i += 1;
        }
    }
    result
}

fn parse_match(line: &str, prefix: &str) -> Option<ServiceMatch> {
    // Format: match <service> <pattern> [<versioninfo>]
    // Pattern is usually m|...|flags
    let content = &line[prefix.len()..];
    let parts: Vec<&str> = content.splitn(2, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    let service = parts[0].to_string();
    let rest = parts[1];
    
    if rest.is_empty() {
        return None;
    }
    
    let delimiter = rest.chars().next().unwrap();
    let last_delim = rest.rfind(delimiter)?;
    let pattern_str = &rest[1..last_delim];
    let version_info = if last_delim + 1 < rest.len() {
        rest[last_delim + 1..].trim().to_string()
    } else {
        String::new()
    };

    // Nmap regex flags can be 'i', 's'
    // For now we just use case-insensitive if 'i' is there
    let flags = rest[last_delim + 1..].split(' ').next().unwrap_or("");
    let mut builder = regex::RegexBuilder::new(pattern_str);
    if flags.contains('i') {
        builder.case_insensitive(true);
    }
    if flags.contains('s') {
        builder.dot_matches_new_line(true);
    }

    match builder.build() {
        Ok(re) => Some(ServiceMatch {
            service,
            pattern: re,
            version_info,
        }),
        Err(_) => None,
    }
}

fn parse_port_list(s: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2 {
                if let (Ok(start), Ok(end)) = (range[0].parse::<u16>(), range[1].parse::<u16>()) {
                    for p in start..=end {
                        ports.push(p);
                    }
                }
            }
        } else if let Ok(port) = part.parse::<u16>() {
            ports.push(port);
        }
    }
    ports
}
