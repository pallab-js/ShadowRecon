use std::process;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod cli;
mod core;
mod discovery;
mod os_fingerprint;
mod output;
mod scanning;
mod scripting;
mod service;
mod types;

use cli::parse_args;
use crate::core::scanner::Scanner;
use output::create_formatter;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "shadowrecon=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Parse command line arguments
    let config = match parse_args() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error parsing arguments: {}", e);
            process::exit(1);
        }
    };

    // Create discovery options based on config
    let discovery_options = crate::types::DiscoveryOptions {
        ping_sweep: false,
        arp_scan: false,
        traceroute: config.traceroute,
        reverse_dns: config.resolve_hostname,
        os_detection: false,
        service_version: matches!(config.service_detection, crate::types::ServiceDetectionMode::Advanced | crate::types::ServiceDetectionMode::Full),
        script_scan: !config.scripts.is_empty(),
        aggressive_timing: matches!(config.timing, crate::types::TimingTemplate::Aggressive | crate::types::TimingTemplate::Insane),
    };

    // Check raw socket permissions if needed
    if matches!(config.scan_type, crate::types::ScanType::Syn | 
                                crate::types::ScanType::Fin | 
                                crate::types::ScanType::Null | 
                                crate::types::ScanType::Xmas | 
                                crate::types::ScanType::Ack | 
                                crate::types::ScanType::Window | 
                                crate::types::ScanType::Maimon) {
        let (has_perms, msg) = crate::discovery::check_raw_socket_permissions();
        if !has_perms {
            tracing::warn!("{}", msg);
            tracing::warn!("Some scan types require elevated privileges. Consider using --scan-type connect for unprivileged scans.");
        }
    }

    // Create scanner
    let scanner = Scanner::new(config);

    // Run scan
    match scanner.run_scan(&discovery_options).await {
        Ok(result) => {
            tracing::info!("Scan completed successfully");

            // Output to console using the specified format
            let console_formatter = create_formatter(scanner.config.output_format);
            if let Err(e) = console_formatter.format(&result) {
                tracing::error!("Failed to format console output: {}", e);
            }

            // If output file is specified, write to file
            if let Some(output_file) = &scanner.config.output_file {
                let rendered = match output::format_to_string(&result, scanner.config.output_format) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("Falling back to JSON for file output due to format error: {}", e);
                        match output::format_to_string(&result, crate::types::OutputFormat::Json) {
                            Ok(s) => s,
                            Err(e2) => {
                                tracing::error!("Failed to render output for file: {}", e2);
                                String::new()
                            }
                        }
                    }
                };
                match std::fs::write(output_file, rendered) {
                    Ok(_) => tracing::info!("Results written to {}", output_file),
                    Err(e) => tracing::error!("Failed to write output file: {}", e),
                }
            }
        }
        Err(e) => {
            tracing::error!("Scan failed: {}", e);
            process::exit(1);
        }
    }
}
