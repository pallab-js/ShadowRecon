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
mod v2;

use cli::parse_args;
use crate::core::scanner::Scanner;
use output::create_formatter;

#[tokio::main]
async fn main() {
    // Parse command line arguments first to get logging levels
    let config = match parse_args() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error parsing arguments: {}", e);
            process::exit(1);
        }
    };

    // Initialize tracing based on verbosity
    let log_level = if config.debug {
        "shadowrecon=debug"
    } else if config.verbose {
        "shadowrecon=info"
    } else {
        "shadowrecon=warn"
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| log_level.into()),
        )
        .with(tracing_subscriber::fmt::layer()
            .with_target(false)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false)
            .compact()
        )
        .init();

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

            // If output files are specified, write to them
            for (format, output_file) in &scanner.config.output_files {
                let rendered = match output::format_to_string(&result, *format) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("Failed to render output for file {} in format {:?}: {}", output_file, format, e);
                        continue;
                    }
                };
                match std::fs::write(output_file, rendered) {
                    Ok(_) => tracing::info!("Results written to {}", output_file),
                    Err(e) => tracing::error!("Failed to write output file {}: {}", output_file, e),
                }
            }
        }
        Err(e) => {
            tracing::error!("Scan failed: {}", e);
            process::exit(1);
        }
    }
}
