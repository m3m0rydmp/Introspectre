mod analysis;
mod audit;
mod guess;
mod cli;
mod db;
mod config;
mod config_cmd;
mod fingerprint;
mod id_scheme;
mod io_ops;
mod progress;
mod report;
mod report_visual;
mod serve;
mod transport;
mod type_walk;
mod types;
mod utils;
mod traffic;
mod waf;

use std::path::Path;
use clap::Parser;
use colored::Colorize;

use cli::{Cli, Commands, OutputFormat};
use config::AppConfig;
use io_ops::{
    build_client, discover_auth_requirements, fetch_introspection, load_schema_from_file, probe_graphql_endpoint,
    FetchError,
};
use guess::run_guess;
use report::{print_json_report, print_markdown_report, print_text_report};
use transport::Transport;
use types::ReportMeta;

/// Merge the base `--header` list with session-reuse layers: HAR/Burp session
/// headers (`--seed-traffic`), same-origin `Origin`/`Referer` (`--stealth`), and
/// a raw `--challenge-cookie`. Base `--header` entries win on a name conflict. Returns
/// `key=value` strings for the existing header pipeline. This is what lets a
/// researcher reuse a browser session to get past a bot-management WAF.
fn effective_headers(base: &[String], cli: &Cli, url: &str) -> Vec<String> {
    let mut layers: Vec<String> = Vec::new();
    if let Some(tp) = &cli.seed_traffic {
        layers.extend(crate::traffic::extract_session_headers(tp, url));
    }
    if cli.stealth {
        layers.extend(crate::io_ops::same_origin_headers(url));
    }
    if let Some(c) = &cli.cookie {
        // Strip a leading "Cookie:" or "cookie:" prefix if the operator pasted
        // the full header value (e.g. copied from browser dev tools as-is).
        let trimmed = c.trim();
        let value = if trimmed.len() > 7 && trimmed[..7].eq_ignore_ascii_case("Cookie:") {
            trimmed[7..].trim()
        } else {
            trimmed
        };
        layers.push(format!("Cookie={}", value));
    }
    layers.extend(base.iter().cloned());
    // Dedupe by header name (case-insensitive); later layers (higher priority) win.
    let mut map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for h in layers {
        let key = h.splitn(2, '=').next().unwrap_or("").trim().to_ascii_lowercase();
        if !key.is_empty() {
            map.insert(key, h);
        }
    }
    map.into_values().collect()
}

/// Report an introspection failure honestly and exit. A bot-management wall is
/// distinguished from a genuinely disabled introspection surface, so the tool
/// stops recommending `brute` (which hits the same wall) when the real cause is
/// a WAF challenge.
fn fail_fetch(e: FetchError) -> ! {
    match e {
        FetchError::Blocked { vendor, hint } => {
            eprintln!(
                "{} Endpoint is behind {} bot management (HTTP challenge) — requests are blocked before reaching GraphQL, so this is not an introspection setting.",
                "  !".yellow().bold(),
                vendor
            );
            eprintln!("  {} {}", "→".blue(), hint);
        }
        FetchError::Introspection(msg) => {
            eprintln!("{} {}", "  !".yellow().bold(), msg);
            eprintln!(
                "  {} Introspection is disabled or blocked. Try the {} command to reconstruct the schema blindly.",
                "→".blue(),
                "brute".bright_white().bold()
            );
        }
    }
    std::process::exit(1);
}

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
        "GraphQL Offensive Security Tool".bright_black()
    );
}

#[tokio::main]
async fn main() {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let msg = e.to_string();
            let is_injection_err = msg.contains("--injection");
            let is_chain_err = msg.contains("--chain");
            // Only intercept when the flag is used on a non-audit subcommand
            // (legitimate parse errors within `audit` still get clap's default).
            if (is_injection_err || is_chain_err) && !msg.contains("audit") {
                let flags = if is_injection_err && is_chain_err {
                    "--injection and --chain are"
                } else if is_injection_err {
                    "--injection is"
                } else {
                    "--chain is"
                };
                eprintln!(
                    "{} {} only available with the {} command.",
                    "Error:".red().bold(),
                    flags,
                    "audit".bright_white().bold()
                );
                std::process::exit(2);
            }
            e.exit()
        }
    };

    // Global maintenance action: wipe the entire cache database. Runs with no subcommand,
    // behind a confirmation prompt.
    if cli.purge_db {
        std::process::exit(run_purge_db());
    }

    // `config` is a local, no-network maintenance command — handle it before the
    // banner and any config/schema work, then exit.
    if let Some(Commands::Config { action }) = &cli.command {
        std::process::exit(config_cmd::run(action, cli.config.as_deref()));
    }

    // Every other flow needs a subcommand. Bind by reference so `cli` stays whole (it's
    // still borrowed elsewhere, e.g. `effective_headers(&cli, …)`).
    let command = match cli.command.as_ref() {
        Some(c) => c,
        None => {
            eprintln!(
                "{} a subcommand is required (scan, audit, brute, file, config), or use {} to wipe the cache database. See {} for usage.",
                "  ✗ Error:".red().bold(),
                "--purge-db".bright_white(),
                "--help".bright_white(),
            );
            std::process::exit(2);
        }
    };

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

    // Out-of-band collaborator for blind-SSRF confirmation (CLI overrides config).
    if let Some(oob) = &cli.oob_url {
        config.audit.oob_url = Some(oob.clone());
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
        source: match command {
            Commands::Scan { url, .. } => url.clone(),
            Commands::Audit { url, .. } => url.clone(),
            Commands::Brute { url, .. } => url.clone(),
            Commands::File { path } => path.display().to_string(),
            Commands::Config { .. } => unreachable!("config handled before this point"),
        },
        offline: matches!(command, Commands::File { .. }),
        static_only: match command {
            Commands::Scan { static_only, .. } => *static_only,
            _ => false,
        },
        reconstructed: matches!(command, Commands::Brute { .. }),
        auth_discovery_performed: false,
        auth_discovery: None,
        server_fingerprint: None,
    };

    if let Commands::Scan { url, headers, timeout, rate_limit_ms, probe_only: true, .. } = command {
        let eff = effective_headers(headers, &cli, url);
        match io_ops::probe_graphql_endpoint(url, &eff, *timeout, *rate_limit_ms, cli.token.as_deref(), cli.user_agent.as_deref(), cli.stealth, cli.transport).await {
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
    // audit. `Auto` negotiation (see `probe_graphql_endpoint`) runs for the `Scan`
    // command when `--probe-first` is enabled and for the `Audit` command whenever
    // transport is `Auto`; everywhere else (or when negotiation can't run) `Auto`
    // falls back to `PostJson`, matching today's default POST/JSON behavior.
    let mut resolved_transport = if cli.transport == Transport::Auto {
        Transport::PostJson
    } else {
        cli.transport
    };

    // --- Cache handling (before any network schema acquisition) ---
    // scan (passive) and brute reuse the last cached schema for a target by
    // default, so a re-run (e.g. after forgetting --visualize) regenerates the
    // report without another round of requests. --purge-cache clears it first.
    // Live operations (scan --static-only false, audit) always fetch fresh.
    let mut from_cache = false;
    let mut cached_schema: Option<crate::types::GqlSchema> = None;
    if cli.use_schema.is_none() {
        let target_url = match command {
            Commands::Scan { url, .. } | Commands::Brute { url, .. } => Some(url.clone()),
            _ => None,
        };
        let cache_eligible = matches!(command, Commands::Brute { .. })
            || matches!(command, Commands::Scan { static_only: true, .. });
        if let Some(url) = target_url {
            let db_path = std::env::current_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
                .join("introspectre.db");
            if let Ok(db) = crate::db::ProjectDatabase::new(&db_path) {
                let project_name = url_to_project_name(&url);
                if let Ok(project_id) = db.get_or_create_project(&project_name, &url) {
                    if cli.purge_cache {
                        if let Ok(n) = db.purge_project_scans(project_id) {
                            eprintln!("  {} Purged {} cached scan(s) for {}.", "→".blue(), n, project_name);
                        }
                    } else if cache_eligible {
                        if let Ok(Some((schema_json, ts, fp_json))) = db.get_latest_scan(project_id) {
                            if let Ok(s) = serde_json::from_str::<crate::types::GqlSchema>(&schema_json) {
                                eprintln!(
                                    "  {} Using cached scan from {} — run with {} to refetch.",
                                    "→".blue(),
                                    ts.bright_white(),
                                    "--purge-cache".bright_white()
                                );
                                cached_schema = Some(s);
                                from_cache = true;
                                // Replay the cached server fingerprint (no network) so cached
                                // runs still show it.
                                if let Some(fj) = fp_json {
                                    if let Ok(fpr) =
                                        serde_json::from_str::<crate::fingerprint::ServerFingerprint>(&fj)
                                    {
                                        eprintln!("  {} Server: {}", "→".blue(), fpr.label().bright_white());
                                        meta.server_fingerprint = Some(fpr);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let schema = if let Some(s) = cached_schema {
        s
    } else if let Some(schema_path) = &cli.use_schema {
        match load_schema_from_file(schema_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{} {}", "  ✗ Error:".red().bold(), e);
                std::process::exit(1);
            }
        }
    } else {
        match command {
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
                let eff = effective_headers(headers, &cli, url);
                if *probe_first {
                    if cli.verbose {
                        println!("  {} Probing endpoint behavior with minimal __typename query...", "→".blue());
                    }
                    let probe = probe_graphql_endpoint(
                        url,
                        &eff,
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
                    &eff,
                    *timeout,
                    *rate_limit_ms,
                    cli.token.as_deref(),
                    cli.user_agent.as_deref(),
                    cli.stealth,
                    resolved_transport,
                    cli.verbose,
                    config.audit.max_type_walk_types,
                )
                .await
                {
                    Ok(s) => s,
                    Err(e) => fail_fetch(e),
                }
            }
            Commands::Audit {
                url,
                headers,
                timeout,
                rate_limit_ms,
                ..
            } => {
                let eff = effective_headers(headers, &cli, url);
                // Negotiate transport when --transport auto so type-walk and probes
                // use a transport the server actually accepts (mirrors scan --probe-first).
                if cli.transport == Transport::Auto {
                    if cli.verbose {
                        println!("  {} Probing endpoint behavior with minimal __typename query...", "→".blue());
                    }
                    let probe = probe_graphql_endpoint(
                        url,
                        &eff,
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
                            resolved_transport = p.resolved_transport;
                            if cli.verbose {
                                println!("  {} {} (HTTP {})", "✓".green().bold(), p.summary, p.http_status);
                            }
                        }
                        Ok(p) => {
                            resolved_transport = p.resolved_transport;
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
                    &eff,
                    *timeout,
                    *rate_limit_ms,
                    cli.token.as_deref(),
                    cli.user_agent.as_deref(),
                    cli.stealth,
                    resolved_transport,
                    cli.verbose,
                    config.audit.max_type_walk_types,
                )
                .await
                {
                    Ok(s) => s,
                    // Introspection blocked/disabled: rather than abort the whole audit, continue
                    // with an empty schema so the network / schema-independent probes still run
                    // (CSRF, introspection matrix, __typename, CORS, APQ). The schema-dependent
                    // fan-out probes just have no targets. A hard bot-wall is still fatal.
                    Err(FetchError::Blocked { vendor, hint }) => {
                        eprintln!(
                            "{} Endpoint is behind {} bot management (HTTP challenge) — requests are blocked before reaching GraphQL.",
                            "  !".yellow().bold(),
                            vendor
                        );
                        eprintln!("  {} {}", "→".blue(), hint);
                        std::process::exit(1);
                    }
                    Err(FetchError::Introspection(msg)) => {
                        eprintln!("{} {}", "  !".yellow().bold(), msg);
                        eprintln!(
                            "  {} Schema unavailable — running schema-independent probes only. For full coverage, reconstruct with {} or pass {}.",
                            "→".blue(),
                            "brute".bright_white().bold(),
                            "--use-schema <file>".bright_white()
                        );
                        types::GqlSchema {
                            query_type: None,
                            mutation_type: None,
                            subscription_type: None,
                            directives: None,
                            types: Vec::new(),
                        }
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
                    // Union of the curated built-in list + config-derived security
                    // terms (deduped). Previously the built-in was unreachable because
                    // config.all_words() always appends common words (never empty).
                    let mut seen = std::collections::HashSet::new();
                    default_brute_wordlist()
                        .into_iter()
                        .chain(config.all_words())
                        .filter(|w| seen.insert(w.clone()))
                        .collect()
                };
                if cli.verbose {
                    eprintln!("  {} brute: {} candidate field name(s) to probe.", "→".blue(), wordlist.len());
                }
                let eff = effective_headers(headers, &cli, url);
                let parsed_headers = crate::utils::parse_extra_headers(&eff);
                match run_guess(url, &client, &parsed_headers, &wordlist, *concurrency, *dynamic_throttling, *rate_limit_ms, cli.verbose).await {
                    Ok(s) => s,
                    Err(ce) => {
                        eprintln!("{} {}", "  ✗ Brute-force reconstruction failed:".red().bold(), ce);
                        std::process::exit(1);
                    }
                }
            }
            Commands::Config { .. } => unreachable!("config handled before this point"),
        }
    };

    if let Commands::Scan {
        url,
        headers,
        timeout,
        rate_limit_ms,
        discover_auth,
        ..
    } = command
    {
        if *discover_auth && !from_cache {
            if cli.verbose {
                println!(
                    "  {} Discovering auth guards with unauthenticated knock probes...",
                    "→".blue()
                );
            }
            meta.auth_discovery_performed = true;
            let eff = effective_headers(headers, &cli, url);
            match discover_auth_requirements(
                &schema,
                url,
                &eff,
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

    // --- Server framework fingerprinting (graphw00f-style, always-on) ---
    // A couple of benign recon probes to identify the GraphQL server stack.
    // Skipped for offline (`file`), cache-served runs, and `--no-fingerprint`.
    if !cli.no_fingerprint && !from_cache {
        let fp_target = match command {
            Commands::Scan { url, headers, timeout, rate_limit_ms, .. }
            | Commands::Audit { url, headers, timeout, rate_limit_ms, .. }
            | Commands::Brute { url, headers, timeout, rate_limit_ms, .. } => {
                Some((url, headers, *timeout, *rate_limit_ms))
            }
            _ => None,
        };
        if let Some((url, headers, timeout, rate_limit_ms)) = fp_target {
            if let Ok(client) = build_client(timeout, cli.user_agent.as_deref(), cli.stealth) {
                let eff = effective_headers(headers, &cli, url);
                let mut fp_headers = crate::utils::parse_extra_headers(&eff);
                if let Some(t) = &cli.token {
                    fp_headers.push(("Authorization".to_string(), format!("Bearer {}", t)));
                }
                if let Some(fpr) =
                    crate::fingerprint::detect_server(url, &client, &fp_headers, resolved_transport, rate_limit_ms, Some(&schema)).await
                {
                    // stderr (not stdout) so `--format json`/`markdown` stay clean.
                    eprintln!("  {} Server: {}", "→".blue(), fpr.label().bright_white());
                    meta.server_fingerprint = Some(fpr);
                }
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
                    // Save Scan (skip when we just served this schema from cache,
                    // to avoid piling up duplicate rows).
                    if !from_cache {
                        let schema_json = serde_json::to_string(&schema).unwrap_or_default();
                        let findings_json = serde_json::to_string(&findings).unwrap_or_default();
                        let stats_json = serde_json::to_string(&stats).unwrap_or_default();
                        let fp_json = meta.server_fingerprint.as_ref().and_then(|f| serde_json::to_string(f).ok());
                        if let Err(e) = db.save_scan(project_id, &schema_json, &findings_json, &stats_json, fp_json.as_deref()) {
                             if cli.verbose { eprintln!("  {} Failed to save scan to database: {}", "!".yellow().bold(), e); }
                        }
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
    } = command
    {
        if !*static_only {
            let eff = effective_headers(headers, &cli, url);
            let mut audit_report = match crate::audit::run_audit(
                &schema,
                url,
                &eff,
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
                cli.verbose,
                false, // scan --static-only false does not auto-chain
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{} {}", "  ✗ Audit Error:".red().bold(), e);
                    std::process::exit(1);
                }
            };
            audit_report.server_fingerprint = meta.server_fingerprint.clone();

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
        injection,
        chain,
        batch_probes,
        batch_size,
        idor_payloads,
        focus,
        max_targets,
        max_requests,
    } = command
    {
        // `--injection` (or naming an injection probe in `--only`) enables the injection-class
        // probes for this run, overriding the config default (which keeps them off).
        // `--chain` implies injection (it needs a confirmed SQLi to harvest from).
        let injection_ids = ["sql-injection", "os-command-injection", "ssrf", "xss"];
        if *injection || *chain || cli.only.iter().any(|o| injection_ids.contains(&o.as_str())) {
            config.audit.test_injection = true;
        }
        let eff = effective_headers(headers, &cli, url);
        let mut audit_report = match crate::audit::run_audit(
            &schema,
            url,
            &eff,
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
            cli.verbose,
            *chain,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{} {}", "  ✗ Audit Error:".red().bold(), e);
                std::process::exit(1);
            }
        };
        audit_report.server_fingerprint = meta.server_fingerprint.clone();

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
    // `brute` reconstructs a (partial) schema blindly; report it like scan/file so the
    // discovered fields and the passive analysis are actually shown (previously brute
    // printed nothing at default verbosity).
    match command {
        Commands::Scan { .. } | Commands::File { .. } | Commands::Brute { .. } => {
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

    if cli.visualize {
        // Launch the interactive visualizer web server. This blocks in the
        // foreground until the user presses Ctrl+C, then the process exits.
        let viz_db_path = std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join("introspectre.db");
        if let Err(e) = serve::serve_visualizer(
            &schema,
            &visual_findings,
            &meta,
            &stats,
            &learned_seeds,
            cli.port,
            viz_db_path,
            config.patterns.clone(),
        )
        .await
        {
            eprintln!("{} {}", "  ✗ Error:".red().bold(), e);
            std::process::exit(1);
        }
        return;
    }

    // CI "findings gate": exit non-zero when High/Medium findings are present, unless the
    // user opted out with --exit-zero (interactive / chained use).
    if !cli.exit_zero
        && visual_findings
            .iter()
            .any(|f| f.severity == crate::types::Severity::High || f.severity == crate::types::Severity::Medium)
    {
        std::process::exit(1);
    }
}

/// Wipe the entire cache database (`--purge-db`) after a prominent confirmation prompt.
/// Returns the process exit code. Non-interactive/piped input that isn't exactly `yes` aborts
/// safely, so this can never fire unattended.
fn run_purge_db() -> i32 {
    use std::io::Write;

    let db_path = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("introspectre.db");

    if !db_path.exists() {
        eprintln!("  {} No cache database at {} — nothing to purge.", "→".blue(), db_path.display());
        return 0;
    }

    let db = match crate::db::ProjectDatabase::new(&db_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("  {} Could not open {}: {}", "✗".red().bold(), db_path.display(), e);
            return 1;
        }
    };

    let (projects, scans, seeds) = db.counts().unwrap_or((0, 0, 0));
    if projects == 0 && scans == 0 && seeds == 0 {
        eprintln!("  {} Cache database is already empty.", "→".blue());
        return 0;
    }

    eprintln!();
    eprintln!("  {}", "⚠  DESTRUCTIVE — purge the ENTIRE Introspectre cache database".red().bold());
    eprintln!("     {}", db_path.display().to_string().bright_white());
    eprintln!(
        "     Permanently deletes {} target(s), {} cached scan(s), and {} learned seed(s).",
        projects.to_string().bright_white(),
        scans.to_string().bright_white(),
        seeds.to_string().bright_white(),
    );
    eprintln!("     {}", "This cannot be undone.".dimmed());
    eprint!("  Type {} to proceed (anything else aborts): ", "yes".bright_white().bold());
    let _ = std::io::stderr().flush();

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() || input.trim().to_lowercase() != "yes" {
        eprintln!("  {}", "Aborted — no changes made.".yellow());
        return 0;
    }

    match db.reset_all() {
        Ok(()) => {
            eprintln!(
                "  {} Purged the cache database ({} scan(s), {} seed(s), {} target(s) removed).",
                "✓".green().bold(),
                scans, seeds, projects
            );
            0
        }
        Err(e) => {
            eprintln!("  {} Failed to purge: {}", "✗".red().bold(), e);
            1
        }
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
    // A broad set of common GraphQL root-field names (Relay/graphql-ruby/Apollo
    // conventions, singular + plural). Deduplicated before use.
    let words = [
        // Viewer / identity
        "me", "viewer", "currentUser", "user", "users", "account", "accounts",
        "profile", "profiles", "session", "sessions", "identity", "whoami",
        // Relay
        "node", "nodes", "edges", "pageInfo",
        // Org / team / membership
        "organization", "organizations", "org", "orgs", "team", "teams",
        "member", "members", "membership", "memberships", "group", "groups",
        "role", "roles", "permission", "permissions", "invite", "invites",
        // Content / social
        "post", "posts", "comment", "comments", "message", "messages",
        "notification", "notifications", "feed", "activity", "activities",
        "tag", "tags", "category", "categories", "media", "asset", "assets",
        "image", "images", "video", "videos", "attachment", "attachments",
        // Commerce
        "order", "orders", "product", "products", "cart", "checkout",
        "payment", "payments", "invoice", "invoices", "subscription",
        "subscriptions", "plan", "plans", "price", "prices", "coupon",
        "coupons", "discount", "refund", "refunds", "transaction",
        "transactions", "wallet", "wallets", "balance", "card", "cards",
        // Projects / dev
        "project", "projects", "repository", "repositories", "repo", "repos",
        "issue", "issues", "pullRequest", "pullRequests", "commit", "commits",
        "branch", "branches", "release", "releases", "pipeline", "pipelines",
        "deployment", "deployments", "environment", "environments", "workflow",
        // Secrets / auth surface
        "apiKey", "apiKeys", "token", "tokens", "accessToken", "refreshToken",
        "key", "keys", "secret", "secrets", "credential", "credentials",
        "password", "passwords", "email", "emails", "phone", "webhook", "webhooks",
        "integration", "integrations", "connection", "connections",
        // Admin / internal / infra
        "admin", "internal", "debug", "root", "config", "configuration",
        "settings", "setting", "feature", "features", "featureFlag",
        "featureFlags", "flag", "flags", "audit", "auditLog", "auditLogs",
        "log", "logs", "metric", "metrics", "report", "reports", "export",
        "import", "job", "jobs", "task", "tasks", "queue", "event", "events",
        // Meta / infra
        "search", "version", "health", "status", "ping", "info", "meta",
        "schema", "api", "v1", "v2", "graphql", "db", "database",
        "file", "files", "upload", "download", "document", "documents",
        // People / CRM
        "client", "clients", "customer", "customers", "contact", "contacts",
        "lead", "leads", "company", "companies", "address", "addresses",
        "location", "locations", "country", "countries", "currency", "currencies",
        // Relay connection internals
        "cursor", "hasNextPage", "hasPreviousPage", "startCursor", "endCursor",
        "clientMutationId", "totalCount", "connection", "connections",
        // Prisma / Nexus-style roots
        "findMany", "findFirst", "findUnique", "findOne", "aggregate", "groupBy", "upsert",
        // Gaming / domain
        "game", "games", "app", "apps", "appId", "gameId", "packageId",
        "item", "items", "inventory", "trade", "trades", "tradeOffer",
        "market", "marketHashName", "asset", "assets", "assetId",
        "achievement", "achievements", "friend", "friends", "friendList",
        "leaderboard", "leaderboards", "score", "scores", "rank", "level",
        "badge", "badges", "stat", "stats", "match", "matches", "lobby",
        "server", "servers", "steamId", "accountId", "persona", "avatar",
        "playtime", "ban", "bans", "player", "players", "character", "characters",
        "quest", "quests", "reward", "rewards", "loadout", "skin", "skins",
        // Auth / lifecycle
        "signIn", "signUp", "signOut", "logout", "login", "register",
        "verify", "verification", "refresh", "authorize", "consent",
        // Content / social extras
        "like", "likes", "favorite", "favorites", "bookmark", "bookmarks",
        "follower", "followers", "following", "subscriber", "subscribers",
        "reaction", "reactions", "vote", "votes", "poll", "polls",
        "survey", "surveys", "ticket", "tickets", "thread", "threads",
        "channel", "channels", "room", "rooms", "conversation", "conversations",
        "draft", "drafts", "template", "templates", "form", "forms",
        "reply", "replies", "mention", "mentions", "hashtag", "hashtags",
        // Entities / infra extras
        "entity", "entities", "resource", "resources", "collection", "collections",
        "catalog", "catalogs", "preference", "preferences", "policy", "policies",
        "gdpr", "kyc", "review", "reviews", "rating", "ratings",
        "shipment", "shipments", "shipping", "tax", "taxes",
        "warehouse", "stock", "sku", "variant", "variants", "bundle", "bundles",
        "namespace", "namespaces", "tenant", "tenants", "workspace", "workspaces",
        "dashboard", "dashboards", "widget", "widgets", "chart", "charts",
    ];
    let mut seen = std::collections::HashSet::new();
    words
        .into_iter()
        .filter(|w| seen.insert(*w))
        .map(|s| s.to_string())
        .collect()
}
