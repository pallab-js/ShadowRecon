use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct NmapOsFingerprint {
    pub name: String,
    pub classes: Vec<OsClass>,
    pub cpes: Vec<String>,
    pub tests: HashMap<String, HashMap<String, String>>,
}

#[derive(Debug, Clone)]
pub struct OsClass {
    #[allow(dead_code)]
    pub vendor: String,
    #[allow(dead_code)]
    pub family: String,
    #[allow(dead_code)]
    pub generation: String,
    #[allow(dead_code)]
    pub os_type: String,
}

pub struct NmapOsDb {
    pub fingerprints: Vec<NmapOsFingerprint>,
}

impl NmapOsDb {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut fingerprints = Vec::new();
        let mut current_fp: Option<NmapOsFingerprint> = None;

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with("Fingerprint ") {
                if let Some(fp) = current_fp.take() {
                    fingerprints.push(fp);
                }
                current_fp = Some(NmapOsFingerprint {
                    name: line[12..].to_string(),
                    classes: Vec::new(),
                    cpes: Vec::new(),
                    tests: HashMap::new(),
                });
            } else if let Some(ref mut fp) = current_fp {
                if line.starts_with("Class ") {
                    let parts: Vec<&str> = line[6..].split('|').collect();
                    if parts.len() >= 4 {
                        fp.classes.push(OsClass {
                            vendor: parts[0].trim().to_string(),
                            family: parts[1].trim().to_string(),
                            generation: parts[2].trim().to_string(),
                            os_type: parts[3].trim().to_string(),
                        });
                    }
                } else if line.starts_with("CPE ") {
                    fp.cpes.push(line[4..].trim().to_string());
                } else if let Some(open_paren) = line.find('(') {
                    if let Some(close_paren) = line.rfind(')') {
                        let test_name = line[..open_paren].to_string();
                        let test_content = &line[open_paren + 1..close_paren];
                        let mut test_map = HashMap::new();
                        for pair in test_content.split('|') {
                            let kv: Vec<&str> = pair.split('=').collect();
                            if kv.len() == 2 {
                                test_map.insert(kv[0].to_string(), kv[1].to_string());
                            }
                        }
                        fp.tests.insert(test_name, test_map);
                    }
                }
            }
        }

        if let Some(fp) = current_fp {
            fingerprints.push(fp);
        }

        Ok(Self { fingerprints })
    }
}
