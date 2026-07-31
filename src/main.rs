mod analysis;
mod audit;
mod guess;
mod cli;
mod db;
mod config;
mod io_ops;
mod report;
mod report_visual;
mod transport;
mod type_walk;
mod types;
mod utils;
mod traffic;

use std::path::Path;
use clap::Parser;
use colored::Colorize;

use cli::{Cli, Commands, OutputFormat};
use config::AppConfig;
use io_ops::{
    build_client, discover_auth_requirements, fetch_introspection, load_schema_from_file, probe_graphql_endpoint,
};
use guess::run_guess;
use report::{print_json_report, print_markdown_report, print_text_report};
use report_visual::write_visual_report;
use transport::Transport;
use types::ReportMeta;

fn print_banner(version: &str) {
    let banner = format!(
        r#"
  ___       _                                 _              
 |_ _|_ __ | |_ _ __ ___  ___ _ __   ___  ___| |_ _ __ ___  
  | || '_ \| __| '__/ _ \/ __| '_ \ / _ \/ __| __| '__/ _ \ 
  | || | | | |_| | | (_) \__ \ |_) |  __/ (__| |_| | |  __/ 
 |___|_| |_|\__|_|  \___/|___/ .__/ \___|\___|\__|_|  \___/ 
                             |_|                            
        "#
    );
    println!("{}", banner.bright_white().bold());
    println!(
        "  {} v{} {} {}\n",
        "introspectre".bright_black(),
        version.bright_cyan(),
        "—".bright_black(),
        "GraphQL Offensive Security Engine".bright_black()
    );
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.format == OutputFormat::Text {
        print_banner(env!("CARGO_PKG_VERSION"));
    }
    
    let mut config = if let Some(config_path) = &cli.config {
        match AppConfig::load_from_path(config_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{} {}", "  ✗ Error:".red().bold(), e);
                std::process::exit(1);
            }
        }
    } else {
        let default_config = Path::new("config.toml");
        if default_config.exists() {
            match AppConfig::load_from_path(default_config) {
                Ok(c) => c,
                Err(e) => {
                    if cli.verbose { eprintln!("  {} Failed to load default config.toml: {}", "!".yellow().bold(), e); }
                    AppConfig::default()
                }
            }
        } else {
            AppConfig::default()
        }
    };

    if let Err(e) = config.merge_wordlists(&cli.wordlist) {
        eprintln!("{} {}", "  ✗ Error:".red().bold(), e);
        std::process::exit(1);
    }

    // Merge manual seeds
    if let Some(seeds_path) = &cli.seeds {
        if let Err(e) = config.merge_seeds_from_path(seeds_path) {
            eprintln!("{} {}", "  ✗ Error:".red().bold(), e);
            std::process::exit(1);
        }
    } else {
        // Try default seeds.json if it exists
        let default_seeds = Path::new("seeds.json");
        if default_seeds.exists() {
            if let Err(e) = config.merge_seeds_from_path(default_seeds) {
                if cli.verbose { eprintln!("  {} Failed to load default seeds.json: {}", "!".yellow().bold(), e); }
            } else if cli.verbose {
                println!("  {} Automatically loaded {} seeds from seeds.json", "✓".green().bold(), config.audit.seeds.len());
            }
        }
    }

    let mut meta = ReportMeta {
        source: match &cli.command {
            Commands::Scan { url, .. } => url.clone(),
            Commands::Audit { url, .. } => url.clone(),
            Commands::Brute { url, .. } => url.clone(),
            Commands::File { path } => path.display().to_string(),
        },
        offline: matches!(&cli.command, Commands::File { .. }),
        static_only: match &cli.command {
            Commands::Scan { static_only, .. } => *static_only,
            _ => false,
        },
        auth_discovery_performed: false,
        auth_discovery: None,
    };

    if let Commands::Scan { url, headers, timeout, rate_limit_ms, probe_only: true, .. } = &cli.command {
        match io_ops::probe_graphql_endpoint(url, headers, *timeout, *rate_limit_ms, cli.token.as_deref(), cli.user_agent.as_deref(), cli.stealth, cli.transport).await {
            Ok(p) => {
                if cli.format == OutputFormat::Text {
                    let icon = if p.graphql_confirmed { "✓".green().bold() } else { "!".yellow().bold() };
                    println!("  {} {} (HTTP {})", icon, p.summary, p.http_status);
                } else {
                    println!("{}", serde_json::json!({ "graphql_confirmed": p.graphql_confirmed, "summary": p.summary, "http_status": p.http_status }));
                }
            }
            Err(e) => { eprintln!("{} {}", "  ✗ Probe failed:".red().bold(), e); std::process::exit(1); }
        }
        return;
    }

    // Resolved transport used for introspection, auth discovery, and the active
    // audit. `Auto` negotiation (see `probe_graphql_endpoint`) only runs for the
    // `Scan` command when `--probe-first` is enabled; everywhere else (or when
    // negotiation can't run) `Auto` simply falls back to `PostJson`, matching
    // today's default POST/JSON behavior.
    let mut resolved_transport = if cli.transport == Transport::Auto {
        Transport::PostJson
    } else {
        cli.transport
    };

    let schema = if let Some(schema_path) = &cli.use_schema {
        match load_schema_from_file(schema_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{} {}", "  ✗ Error:".red().bold(), e);
                std::process::exit(1);
            }
        }
    } else {
        match &cli.command {
            Commands::File { path } => match load_schema_from_file(path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{} {}", "  ✗ Error:".red().bold(), e);
                    std::process::exit(1);
                }
            },
            Commands::Scan {
                url,
                headers,
                timeout,
                probe_first,
                rate_limit_ms,
                ..
            } => {
                if *probe_first {
                    if cli.verbose {
                        println!("  {} Probing endpoint behavior with minimal __typename query...", "→".blue());
                    }
                    let probe = probe_graphql_endpoint(
                        url,
                        headers,
                        *timeout,
                        *rate_limit_ms,
                        cli.token.as_deref(),
                        cli.user_agent.as_deref(),
                        cli.stealth,
                        cli.transport,
                    )
                    .await;
                    match probe {
                        Ok(p) if p.graphql_confirmed => {
                            if cli.transport == Transport::Auto {
                                resolved_transport = p.resolved_transport;
                            }
                            if cli.verbose {
                                println!("  {} {} (HTTP {})", "✓".green().bold(), p.summary, p.http_status);
                            }
                        }
                        Ok(p) => {
                            if cli.transport == Transport::Auto {
                                resolved_transport = p.resolved_transport;
                            }
                            if cli.verbose {
                                eprintln!("  {} {} (HTTP {})", "!".yellow().bold(), p.summary, p.http_status);
                            }
                        }
                        Err(e) => {
                            if cli.verbose {
                                eprintln!("  {} Probe failed: {}", "!".yellow().bold(), e);
                            }
                        }
                    }
                }

                if cli.verbose {
                    println!("  {} Fetching introspection from {}...", "→".blue(), url);
                }
                match fetch_introspection(
                    url,
                    headers,
                    *timeout,
                    *rate_limit_ms,
                    cli.token.as_deref(),
                    cli.user_agent.as_deref(),
                    cli.stealth,
                    resolved_transport,
                )
                .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("{} {}", "  !".yellow().bold(), e);
                        eprintln!(
                            "  {} Introspection is disabled or blocked. Try the {} command to reconstruct the schema blindly.",
                            "→".blue(),
                            "brute".bright_white().bold()
                        );
                        std::process::exit(1);
                    }
                }
            }
            Commands::Audit {
                url,
                headers,
                timeout,
                rate_limit_ms,
                ..
            } => {
                if cli.verbose {
                    println!("  {} Fetching introspection from {}...", "→".blue(), url);
                }
                match fetch_introspection(
                    url,
                    headers,
                    *timeout,
                    *rate_limit_ms,
                    cli.token.as_deref(),
                    cli.user_agent.as_deref(),
                    cli.stealth,
                    resolved_transport,
                )
                .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("{} {}", "  !".yellow().bold(), e);
                        eprintln!(
                            "  {} Introspection is disabled or blocked. Try the {} command to reconstruct the schema blindly.",
                            "→".blue(),
                            "brute".bright_white().bold()
                        );
                        std::process::exit(1);
                    }
                }
            }
            Commands::Brute {
                url,
                headers,
                timeout,
                words,
                concurrency,
                dynamic_throttling,
                rate_limit_ms,
            } => {
                let client = build_client(*timeout, cli.user_agent.as_deref(), cli.stealth).unwrap();
                let wordlist: Vec<String> = if let Some(path) = words {
                    match std::fs::read_to_string(path) {
                        Ok(c) => c.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
                        Err(e) => { eprintln!("{} Failed to read wordlist: {}", "  ✗".red().bold(), e); std::process::exit(1); }
                    }
                } else {
                    let cfg = config.all_words();
                    if cfg.is_empty() { default_brute_wordlist() } else { cfg }
                };
                let parsed_headers = crate::utils::parse_extra_headers(headers);
                match run_guess(url, &client, &parsed_headers, &wordlist, *concurrency, *dynamic_throttling, *rate_limit_ms, cli.verbose).await {
                    Ok(s) => s,
                    Err(ce) => {
                        eprintln!("{} {}", "  ✗ Brute-force reconstruction failed:".red().bold(), ce);
                        std::process::exit(1);
                    }
                }
            }
        }
    };

    if let Commands::Scan {
        url,
        headers,
        timeout,
        rate_limit_ms,
        discover_auth,
        ..
    } = &cli.command
    {
        if *discover_auth {
            if cli.verbose {
                println!(
                    "  {} Discovering auth guards with unauthenticated knock probes...",
                    "→".blue()
                );
            }
            meta.auth_discovery_performed = true;
            match discover_auth_requirements(
                &schema,
                url,
                headers,
                *timeout,
                *rate_limit_ms,
                cli.user_agent.as_deref(),
                cli.stealth,
                resolved_transport,
            )
            .await
            {
                Ok(auth) => meta.auth_discovery = Some(auth),
                Err(e) => if cli.verbose { eprintln!("  {} Auth discovery failed: {}", "!".yellow().bold(), e) },
            }
        }
    }

    let (mut findings, stats) = analysis::analyze(&schema, &config.patterns, cli.token.as_deref());

    let mut learned_seeds = Vec::new();

    // --- Persistence: Save Scan Results & Process Seeds ---
    let db_path = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")).join("introspectre.db");
    match crate::db::ProjectDatabase::new(&db_path) {
        Ok(db) => {
            let project_name = url_to_project_name(&meta.source);
            match db.get_or_create_project(&project_name, &meta.source) {
                Ok(project_id) => {
                    // Save Scan
                    let schema_json = serde_json::to_string(&schema).unwrap_or_default();
                    let findings_json = serde_json::to_string(&findings).unwrap_or_default();
                    let stats_json = serde_json::to_string(&stats).unwrap_or_default();
                    if let Err(e) = db.save_scan(project_id, &schema_json, &findings_json, &stats_json) {
                         if cli.verbose { eprintln!("  {} Failed to save scan to database: {}", "!".yellow().bold(), e); }
                    }

                    // Process Seed Traffic
                    if let Some(traffic_path) = &cli.seed_traffic {
                        if cli.verbose { println!("  {} Processing seed traffic from {}...", "→".blue(), traffic_path.display()); }
                        match crate::traffic::parse_traffic_file(traffic_path) {
                            Ok(seeds) => {
                                let mut count = 0;
                                for seed in seeds {
                                    if let Err(e) = db.save_seed(project_id, &seed.field_name, &seed.type_name, &seed.value, &seed.source) {
                                        if cli.verbose { eprintln!("  {} Failed to save seed {}: {}", "!".yellow().bold(), seed.field_name, e); }
                                    } else {
                                        count += 1;
                                    }
                                }
                                if cli.verbose { println!("  {} Successfully learned {} data points from traffic.", "✓".green().bold(), count); }
                            },
                            Err(e) => eprintln!("  {} Failed to parse traffic file: {}", "!".yellow().bold(), e),
                        }
                    }

                    // Fetch all seeds for this project to include in the visual report
                    if let Ok(seeds) = db.get_seeds(project_id) {
                        learned_seeds = seeds;
                        for s in &learned_seeds {
                            // If it's a known type, use that as key, otherwise field name
                            let key = if s.type_name != "Unknown" { &s.type_name } else { &s.field_name };
                            if !config.audit.seeds.contains_key(key) {
                                // We need to ensure string values are quoted for GraphQL
                                // Since s.value currently has quotes stripped in traffic.rs, we might need to be smart
                                // but for now let's just insert it.
                                config.audit.seeds.insert(key.clone(), s.value.clone());
                            }
                        }
                    }

                },
                Err(e) => if cli.verbose { eprintln!("  {} Failed to get/create project in database: {}", "!".yellow().bold(), e); }
            }
        },
        Err(e) => if cli.verbose { eprintln!("  {} Failed to initialize database: {}", "!".yellow().bold(), e); }
    }

    let mut active_confirmed: Vec<crate::types::Finding> = Vec::new();

    if let Commands::Scan {
        url,
        headers,
        timeout,
        rate_limit_ms,
        dynamic_throttling,
        static_only,
        ..
    } = &cli.command
    {
        if !*static_only {
            let mut audit_report = match crate::audit::run_audit(
                &schema,
                url,
                headers,
                *timeout,
                *rate_limit_ms,
                *dynamic_throttling,
                0, // Scan uses default 0 evasion
                &config,
                &findings,
                false, // Scan doesn't batch probes
                5,
                &[],
                cli.user_agent.as_deref(),
                cli.stealth,
                resolved_transport,
                &cli.skip,
                &cli.only,
                cli.no_dos,
                &[], // Scan path: no --focus
                config.audit.max_targets_per_probe, // config default (auto-cap if None)
                config.audit.max_total_requests,
                cli.dry_run,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{} {}", "  ✗ Audit Error:".red().bold(), e);
                    std::process::exit(1);
                }
            };

            if let Some(min) = &cli.min_severity {
                audit_report.confirmed.retain(|f| f.severity >= *min);
                audit_report.unconfirmed.retain(|f| f.severity >= *min);
            }

            match cli.format {
                OutputFormat::Text => {
                    crate::audit::print_audit_text_report(&audit_report, cli.max_affected, cli.verbose)
                }
                OutputFormat::Json => crate::audit::print_audit_json_report(&audit_report),
                OutputFormat::Markdown => {
                    crate::audit::print_audit_markdown_report(&audit_report, cli.max_affected)
                }
            }

            // Collect confirmed active findings for the visual graph + exit code.
            // They are intentionally NOT merged into `findings` here: the active
            // audit report above and the passive text report below cover them
            // separately, so merging would print every confirmed finding twice.
            active_confirmed = audit_report.confirmed.clone();
        }
        // Static scans emit their single comprehensive report below (Final Reporting).
    } else if let Commands::Audit {
        url,
        headers,
        timeout,
        rate_limit_ms,
        dynamic_throttling,
        evasion,
        batch_probes,
        batch_size,
        idor_payloads,
        focus,
        max_targets,
        max_requests,
    } = &cli.command
    {
        let mut audit_report = match crate::audit::run_audit(
            &schema,
            url,
            headers,
            *timeout,
            *rate_limit_ms,
            *dynamic_throttling,
            *evasion,
            &config,
            &findings,
            *batch_probes,
            *batch_size,
            idor_payloads,
            cli.user_agent.as_deref(),
            cli.stealth,
            resolved_transport,
            &cli.skip,
            &cli.only,
            cli.no_dos,
            focus,
            (*max_targets).or(config.audit.max_targets_per_probe),
            (*max_requests).or(config.audit.max_total_requests),
            cli.dry_run,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{} {}", "  ✗ Audit Error:".red().bold(), e);
                std::process::exit(1);
            }
        };

        if let Some(min) = &cli.min_severity {
            audit_report.confirmed.retain(|f| f.severity >= *min);
            audit_report.unconfirmed.retain(|f| f.severity >= *min);
        }

        match cli.format {
            OutputFormat::Text => {
                crate::audit::print_audit_text_report(&audit_report, cli.max_affected, cli.verbose)
            }
            OutputFormat::Json => crate::audit::print_audit_json_report(&audit_report),
            OutputFormat::Markdown => {
                crate::audit::print_audit_markdown_report(&audit_report, cli.max_affected)
            }
        }

        // Collect confirmed active findings for the visual graph + exit code (see note above).
        active_confirmed = audit_report.confirmed.clone();
    }

    // --- Final Processing: Apply Heuristic Scoring ---
    analysis::scoring::apply_heuristics(&mut findings, &meta);

    if let Some(min) = &cli.min_severity {
        findings.retain(|f| f.severity >= *min);
    }

    // Combined set (scored passive findings + confirmed active findings) drives the
    // visual report and the process exit status, without double-printing in text.
    let mut visual_findings = findings.clone();
    visual_findings.extend(active_confirmed);

    // --- Final Reporting ---
    match cli.command {
        Commands::Scan { .. } | Commands::File { .. } => {
             match cli.format {
                OutputFormat::Text => {
                    print_text_report(&schema, &stats, &visual_findings, &meta, cli.max_affected, cli.verbose)
                }
                OutputFormat::Json => print_json_report(&schema, &stats, &visual_findings, &meta),
                OutputFormat::Markdown => {
                    print_markdown_report(&schema, &stats, &visual_findings, &meta, cli.max_affected)
                }
            }
        },
        _ => {}
    }

    if let Some(visual_path) = &cli.visualize {
        if let Err(e) = write_visual_report(visual_path, &schema, &visual_findings, &meta, &stats, &learned_seeds) {
            eprintln!("{} {}", "  ✗ Error:".red().bold(), e);
            std::process::exit(1);
        }
        if cli.format == OutputFormat::Text {
            eprintln!(
                "  {} Interactive visualization written to {}",
                "✓".green().bold(),
                visual_path.display().to_string().bright_white()
            );
        }
    }

    if visual_findings
        .iter()
        .any(|f| f.severity == crate::types::Severity::High || f.severity == crate::types::Severity::Medium)
    {
        std::process::exit(1);
    }
}

fn url_to_project_name(url: &str) -> String {
    url.trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or(url)
        .to_string()
}

fn default_brute_wordlist() -> Vec<String> {
    vec![
        "me", "users", "admin", "config", "settings", "login", "auth", "profile",
        "accounts", "nodes", "items", "search", "version", "health", "status",
        "debug", "internal", "root", "api", "v1", "v2", "db", "database",
        "file", "files", "upload", "download", "token", "tokens", "key", "keys",
        "secrets", "credentials", "passwords", "emails", "clients", "customers"
    ].into_iter().map(|s| s.to_string()).collect()
}
