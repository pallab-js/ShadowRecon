use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Semaphore;
use tracing::{debug, info};

use crate::types::{HostInfo, ScanConfig, ScanTiming, ScriptResult};

/// Scripting engine for custom vulnerability checks and extensions
pub struct ScriptEngine {
    config: Arc<ScanConfig>,
    timing: ScanTiming,
    semaphore: Arc<Semaphore>,
    scripts: HashMap<String, Box<dyn Script>>,
}

/// Script trait for implementing vulnerability checks
#[async_trait::async_trait]
pub trait Script: Send + Sync {
    /// Get script metadata
    fn metadata(&self) -> ScriptMetadata;

    /// Execute the script against a target
    async fn execute(&self, target: &ScriptTarget, timing: &ScanTiming) -> anyhow::Result<Vec<ScriptResult>>;
}

/// Script metadata
#[derive(Debug, Clone)]
#[allow(dead_code)] // Some fields reserved for future script types
pub struct ScriptMetadata {
    pub id: String,
    pub name: String,
    pub description: String,
    pub script_type: ScriptType,
    pub target_ports: Vec<u16>,
    pub target_services: Vec<String>,
}

/// Script types
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // Port and Host variants reserved for future implementation
pub enum ScriptType {
    Port,
    Host,
    Service,
}

/// Target for script execution
#[derive(Debug, Clone)]
pub enum ScriptTarget {
    Host(HostInfo),
    Port(HostInfo, usize), // host, port_index
    Service(HostInfo, usize), // host, port_index
}

impl ScriptEngine {
    /// Create a new script engine
    pub fn new(config: &ScanConfig, timing: &ScanTiming) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.threads.min(5))); // Limit script concurrency
        let mut engine = Self {
            config: Arc::new(config.clone()),
            timing: timing.clone(),
            semaphore,
            scripts: HashMap::new(),
        };

        engine.load_builtin_scripts();

        engine
    }

    /// Add a custom script
    pub fn add_script(&mut self, script: Box<dyn Script>) {
        let metadata = script.metadata();
        self.scripts.insert(metadata.id.clone(), script);
    }

    /// Run scripts against hosts
    pub async fn run_scripts(&self, hosts: Vec<HostInfo>) -> anyhow::Result<Vec<HostInfo>> {
        let mut results = Vec::new();

        for host in hosts {
            match self.semaphore.acquire().await {
                Ok(_permit) => {
                    let result = Self::run_scripts_on_host(host, &self.scripts, &self.timing, |script_id| self.should_execute_script(script_id)).await?;
                    results.push(result);
                }
                Err(e) => {
                    debug!("Semaphore acquire failed for scripting: {}", e);
                }
            }
        }

        Ok(results)
    }

    /// Run scripts on a single host
    async fn run_scripts_on_host<F>(
        mut host: HostInfo,
        scripts: &HashMap<String, Box<dyn Script>>,
        timing: &ScanTiming,
        should_execute: F,
    ) -> anyhow::Result<HostInfo>
    where
        F: Fn(&str) -> bool,
    {
        info!("Running scripts on host: {}", host.ip);

        // Collect script results for each port first, then apply them
        let mut port_script_results = Vec::new();

        for (port_index, port_info) in host.ports.iter().enumerate() {
            if port_info.state == crate::types::PortState::Open {
                for (script_id, script) in scripts.iter() {
                    if matches!(script.metadata().script_type, ScriptType::Port) && should_execute(script_id) {
                        // Check if script applies to this port
                        let metadata = script.metadata();
                        if metadata.target_ports.is_empty() || metadata.target_ports.contains(&port_info.port) {
                            let target = ScriptTarget::Port(host.clone(), port_index);
                            let results = script.execute(&target, timing).await?;
                            for result in results {
                                port_script_results.push((port_index, script_id.clone(), result));
                            }
                        }
                    }
                }
            }
        }

        // Apply port script results
        for (port_index, script_id, result) in port_script_results {
            if let Some(ref mut service) = host.ports[port_index].service {
                service.script_results.insert(script_id, result.output.clone());
            }
        }

        // Run host-specific scripts
        for (script_id, script) in scripts.iter() {
            if matches!(script.metadata().script_type, ScriptType::Host) && should_execute(script_id) {
                let target = ScriptTarget::Host(host.clone());
                let results = script.execute(&target, timing).await?;
                for result in results {
                    debug!("Host script {} result: {}", script.metadata().id, result.output);
                }
            }
        }

        // Service script execution
        for (port_index, port_info) in host.ports.iter().enumerate() {
            if port_info.state == crate::types::PortState::Open {
                if let Some(ref service) = port_info.service {
                    for (script_id, script) in scripts.iter() {
                        if matches!(script.metadata().script_type, ScriptType::Service) && should_execute(script_id) {
                            let metadata = script.metadata();
                            // Check if script applies to this service
                            if metadata.target_services.is_empty() ||
                               metadata.target_services.iter().any(|s| service.name.contains(s)) {
                                let target = ScriptTarget::Service(host.clone(), port_index);
                                let results = script.execute(&target, timing).await?;
                                for result in results {
                                    debug!("Service script {} result: {}", metadata.id, result.output);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(host)
    }

    /// Load built-in scripts
    fn load_builtin_scripts(&mut self) {
        // Add all built-in scripts
        self.add_script(Box::new(crate::scripting::scripts::HeartbleedScript));
        self.add_script(Box::new(crate::scripting::scripts::SmbVulnScript));
        self.add_script(Box::new(crate::scripting::scripts::HttpVulnScript));
        self.add_script(Box::new(crate::scripting::scripts::Log4ShellScript));
        self.add_script(Box::new(crate::scripting::scripts::ShellshockScript));
        self.add_script(Box::new(crate::scripting::scripts::PoodleScript));
        self.add_script(Box::new(crate::scripting::scripts::DrownScript));
        self.add_script(Box::new(crate::scripting::scripts::FtpAnonScript));
        self.add_script(Box::new(crate::scripting::scripts::SshWeakScript));
        self.add_script(Box::new(crate::scripting::scripts::DnsAmplificationScript));
        self.add_script(Box::new(crate::scripting::scripts::NtpMonlistScript));
        self.add_script(Box::new(crate::scripting::scripts::RedisUnauthScript));
        self.add_script(Box::new(crate::scripting::scripts::MongodbUnauthScript));
        self.add_script(Box::new(crate::scripting::scripts::ElasticsearchUnauthScript));
    }

    /// Check if a script should be executed based on user configuration
    fn should_execute_script(&self, script_id: &str) -> bool {
        // If no specific scripts are requested, execute all scripts
        if self.config.scripts.is_empty() {
            return true;
        }

        // Otherwise, only execute scripts that are explicitly requested
        self.config.scripts.contains(&script_id.to_string())
    }
}