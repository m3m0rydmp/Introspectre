#![allow(clippy::too_many_arguments)]

mod analysis;
mod audit;
mod guess;
mod cli;
mod db;
mod config;
mod discovery;
mod io_ops;
mod report;
mod report_visual;
mod types;
mod utils;
mod traffic;

use clap::Parser;
use colored::Colorize;

<<<<<<< HEAD
use analysis::analyze;
use audit::{
    print_audit_json_report, print_audit_markdown_report, print_audit_text_report, run_audit,
};
=======
>>>>>>> update-research-refs
use cli::{Cli, Commands, OutputFormat};
use config::AppConfig;
use discovery::run_discovery;
use io_ops::{
    build_client, discover_auth_requirements, fetch_introspection, load_schema_from_file, probe_graphql_endpoint,
};
use guess::run_guess;
use report::{print_json_report, print_markdown_report, print_text_report};
use report_visual::write_visual_report;
use types::ReportMeta;

<<<<<<< HEAD
=======
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
    println!("  {} v{}\n", "introspectre".bright_black(), version.bright_cyan());
}

>>>>>>> update-research-refs
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
        AppConfig::default()
    };

    if let Err(e) = config.merge_wordlists(&cli.wordlist) {
        eprintln!("{} {}", "  ✗ Error:".red().bold(), e);
        std::process::exit(1);
    }

<<<<<<< HEAD
    if let Commands::Audit {
        url,
        headers,
        timeout,
        rate_limit_ms,
        batch_probes,
        batch_size,
        idor_payloads,
    } = &cli.command
    {
        let schema =
            match fetch_introspection(url, headers, *timeout, *rate_limit_ms, cli.token.as_deref())
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{} {}", "  ✗ Error:".red().bold(), e);
                    std::process::exit(1);
                }
            };

        let (passive_findings, _) = analyze(&schema, &app_config.patterns, cli.token.as_deref());
        let report = match run_audit(
            &schema,
            url,
            headers,
            *timeout,
            *rate_limit_ms,
            &app_config,
            &passive_findings,
            idor_payloads,
            *batch_probes,
            *batch_size,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{} {}", "  ✗ Error:".red().bold(), e);
                std::process::exit(2);
            }
        };

        match cli.format {
            OutputFormat::Text => print_audit_text_report(&report, cli.max_affected, cli.verbose),
            OutputFormat::Json => print_audit_json_report(&report),
            OutputFormat::Markdown => print_audit_markdown_report(&report, cli.max_affected),
=======
    let mut meta = ReportMeta {
        source: match &cli.command {
            Commands::Scan { url, .. } => url.clone(),
            Commands::Audit { url, .. } => url.clone(),
            Commands::Discover { url, .. } => url.clone(),
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

    let schema = if let Some(schema_path) = &cli.use_schema {
        match load_schema_from_file(schema_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{} {}", "  ✗ Error:".red().bold(), e);
                std::process::exit(1);
            }
>>>>>>> update-research-refs
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
                    )
                    .await;
                    match probe {
                        Ok(p) if p.graphql_confirmed => {
                            if cli.verbose {
                                println!("  {} {} (HTTP {})", "✓".green().bold(), p.summary, p.http_status);
                            }
                        }
                        Ok(p) => {
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
<<<<<<< HEAD
                )
                .await
                {
                    Ok(r) => {
                        if cli.format == OutputFormat::Text {
                            let marker = if r.graphql_confirmed {
                                "✓".green().bold()
                            } else {
                                "!".yellow().bold()
                            };
                            eprintln!("  {} {} (HTTP {})", marker, r.summary, r.http_status);
                        }
                        probe_result = Some(r);
                    }
=======
                    cli.user_agent.as_deref(),
                    cli.stealth,
                )
                .await
                {
                    Ok(s) => s,
>>>>>>> update-research-refs
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
                concurrency,
                dynamic_throttling,
                rate_limit_ms,
            } => {
                let client = build_client(*timeout, cli.user_agent.as_deref(), cli.stealth).unwrap();
                let wordlist = config.all_words();
                let parsed_headers = crate::utils::parse_extra_headers(headers);
                match run_guess(url, &client, &parsed_headers, &wordlist, *concurrency, *dynamic_throttling, *rate_limit_ms, cli.verbose).await {
                    Ok(s) => s,
                    Err(ce) => {
                        eprintln!("{} {}", "  ✗ Brute-force reconstruction failed:".red().bold(), ce);
                        std::process::exit(1);
                    }
                }
            }
            Commands::Discover { url: _, .. } => {
                crate::types::GqlSchema {
                    query_type: None,
                    mutation_type: None,
                    subscription_type: None,
                    directives: None,
                    types: vec![],
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
<<<<<<< HEAD
                cli.token.as_deref(),
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    if let Some(probe) = &probe_result {
                        if probe.graphql_confirmed {
                            eprintln!(
                                "{} GraphQL appears to be running, but introspection could not be retrieved.",
                                "  ! Note:".yellow().bold()
                            );
                            if probe.auth_likely_required {
                                eprintln!(
                                    "{} Endpoint may be auth-gated. Retry with --token <JWT>.",
                                    "  ! Hint:".yellow().bold()
                                );
                            }
                            eprintln!(
                                "{} If this is expected, use `file <schema.json>` mode for offline static analysis.",
                                "  ! Hint:".yellow().bold()
                            );
                        } else if probe.content_type_or_json_issue {
                            eprintln!(
                                "{} Probe received non-GraphQL JSON behavior. Re-check endpoint path and required headers.",
                                "  ! Hint:".yellow().bold()
                            );
=======
                cli.user_agent.as_deref(),
                cli.stealth,
            )
            .await
            {
                Ok(auth) => meta.auth_discovery = Some(auth),
                Err(e) => if cli.verbose { eprintln!("  {} Auth discovery failed: {}", "!".yellow().bold(), e) },
            }
        }
    }

    if let Commands::Discover { url, wordlist, concurrency, dynamic_throttling, .. } = &cli.command {
         let client = match crate::io_ops::build_client(15, cli.user_agent.as_deref(), cli.stealth) {
             Ok(c) => c,
             Err(e) => {
                 eprintln!("{} {}", "  ✗ Error:".red().bold(), e);
                 std::process::exit(1);
             }
         };
         let discovered = match run_discovery(url, &client, wordlist.clone(), *concurrency, *dynamic_throttling, 0, cli.verbose).await {
             Ok(d) => d,
             Err(e) => {
                 eprintln!("{} {}", "  ✗ Error:".red().bold(), e);
                 std::process::exit(1);
             }
         };
         
         if discovered.is_empty() {
             println!("\n  {} No fields discovered.", "!".yellow().bold());
         } else {
             println!("\n  {} Discovered {} fields:", "✓".green().bold(), discovered.len());
             for d in discovered {
                 println!("    · {}", d.bright_white());
             }
         }
         return;
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
>>>>>>> update-research-refs
                        }
                    }

                    // Fetch all seeds for this project to include in the visual report
                    if let Ok(seeds) = db.get_seeds(project_id) {
                        learned_seeds = seeds;
                    }
                },
                Err(e) => if cli.verbose { eprintln!("  {} Failed to get/create project in database: {}", "!".yellow().bold(), e); }
            }
        },
        Err(e) => if cli.verbose { eprintln!("  {} Failed to initialize database: {}", "!".yellow().bold(), e); }
    }

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
            let audit_report = match crate::audit::run_audit(
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
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{} {}", "  ✗ Audit Error:".red().bold(), e);
                    std::process::exit(1);
                }
            };

            match cli.format {
                OutputFormat::Text => {
                    crate::audit::print_audit_text_report(&audit_report, cli.max_affected, cli.verbose)
                }
<<<<<<< HEAD
                match discover_auth_requirements(&schema, url, headers, *timeout, *rate_limit_ms)
                    .await
                {
                    Ok(r) => auth_discovery = Some(r),
                    Err(e) => {
                        if cli.format == OutputFormat::Text {
                            eprintln!("{} {}", "  ! Auth discovery skipped:".yellow().bold(), e);
                        }
                    }
=======
                OutputFormat::Json => crate::audit::print_audit_json_report(&audit_report),
                OutputFormat::Markdown => {
                    crate::audit::print_audit_markdown_report(&audit_report, cli.max_affected)
>>>>>>> update-research-refs
                }
            }

            // Add confirmed audit findings to the main findings list for the visual report
            findings.extend(audit_report.confirmed.clone());
        } else {
            // Static scan report
            match cli.format {
                OutputFormat::Text => {
                    print_text_report(&schema, &stats, &findings, &meta, cli.max_affected, cli.verbose)
                }
                OutputFormat::Json => print_json_report(&schema, &stats, &findings, &meta),
                OutputFormat::Markdown => {
                    print_markdown_report(&schema, &stats, &findings, &meta, cli.max_affected)
                }
            }
        }
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
    } = &cli.command
    {
        let audit_report = match crate::audit::run_audit(
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
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{} {}", "  ✗ Audit Error:".red().bold(), e);
                std::process::exit(1);
            }
        };

<<<<<<< HEAD
    let (mut findings, stats) = analyze(&schema, &app_config.patterns, cli.token.as_deref());
=======
        match cli.format {
            OutputFormat::Text => {
                crate::audit::print_audit_text_report(&audit_report, cli.max_affected, cli.verbose)
            }
            OutputFormat::Json => crate::audit::print_audit_json_report(&audit_report),
            OutputFormat::Markdown => {
                crate::audit::print_audit_markdown_report(&audit_report, cli.max_affected)
            }
        }
>>>>>>> update-research-refs

        // Add confirmed audit findings to the main findings list for the visual report
        findings.extend(audit_report.confirmed.clone());
    }

<<<<<<< HEAD
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(b.id)));
=======
    // --- Final Processing: Apply Heuristic Scoring ---
    analysis::scoring::apply_heuristics(&mut findings, &meta);
>>>>>>> update-research-refs

    // --- Final Reporting ---
    match cli.command {
        Commands::Scan { .. } | Commands::Audit { .. } | Commands::File { .. } => {
             match cli.format {
                OutputFormat::Text => {
                    print_text_report(&schema, &stats, &findings, &meta, cli.max_affected, cli.verbose)
                }
                OutputFormat::Json => print_json_report(&schema, &stats, &findings, &meta),
                OutputFormat::Markdown => {
                    print_markdown_report(&schema, &stats, &findings, &meta, cli.max_affected)
                }
            }
        },
        _ => {}
    }

    if let Some(visual_path) = &cli.visualize {
        if let Err(e) = write_visual_report(visual_path, &schema, &findings, &meta, &stats, &learned_seeds) {
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

    if findings
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
