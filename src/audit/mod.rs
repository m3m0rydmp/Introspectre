pub mod chain;
pub mod probes;
pub mod utils;
pub mod poc;
pub mod targets;

use crate::audit::probes::{
    probe_alias_dos, probe_batching, probe_complexity, probe_idor, probe_ssrf, probe_typename,
    probe_unauth_access, probe_verbose_error_disclosure, probe_sqli, probe_xss, probe_command_injection, probe_mutation_privesc,
    probe_csrf_methods, probe_dos_expansion,
    probe_introspection_matrix, probe_cors, probe_apq, probe_alias_cap, probe_node_idor,
};
use crate::config::AppConfig;
use crate::transport::Transport;
use crate::types::{
    AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, Severity,
};
use colored::Colorize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub source: String,
    pub passive_total_findings: usize,
    pub confirmed: Vec<Finding>,
    pub unconfirmed: Vec<Finding>,
    pub warnings: Vec<String>,
    /// Detected GraphQL server framework (set by the caller from `ReportMeta`).
    #[serde(default)]
    pub server_fingerprint: Option<crate::fingerprint::ServerFingerprint>,
}

/// DoS-class probe ids, gated together by `--no-dos`.
const DOS_CLASS_PROBE_IDS: &[&str] = &["alias-dos", "batching", "complexity", "dos-expansion"];

/// When no explicit `--max-targets` is given and any fan-out probe would exceed this many
/// targets, the audit auto-caps each probe to [`DEFAULT_LARGE_SCHEMA_CAP`] (ranked by
/// passive-finding severity) and warns. Mirrors the visual report's >150-element prompt.
const LARGE_SCHEMA_TARGET_THRESHOLD: usize = 200;
const DEFAULT_LARGE_SCHEMA_CAP: usize = 150;

/// Approximate request-per-target multipliers for the fan-out probes, used only by the
/// `--dry-run` estimator. `sqli` additionally scales with the payload count.
const SQLI_BASE_PAYLOADS: usize = 17;

/// Whether a probe with the given stable id should run, per `--only`, `--skip`,
/// and `--no-dos`. Matching is case-insensitive and trims whitespace so
/// comma-separated CLI values are forgiving of stray spaces.
fn probe_enabled(id: &str, only: &[String], skip: &[String], no_dos: bool, verbose: bool) -> bool {
    let norm = |s: &str| s.trim().to_lowercase();
    let id_norm = norm(id);

    if !only.is_empty() && !only.iter().any(|o| norm(o) == id_norm) {
        return false;
    }
    if skip.iter().any(|s| norm(s) == id_norm) {
        return false;
    }
    if no_dos && DOS_CLASS_PROBE_IDS.contains(&id_norm.as_str()) {
        return false;
    }
    if verbose {
        // Transient live status: which probe is running now (overwrites in place).
        crate::progress::transient(&format!("  {} audit: running {} probe...", "→".blue(), id));
    }
    true
}

/// Under `--verbose`, surface any confirmed findings added since `already` as
/// persistent lines (so the tester sees hits live during the run, not only in
/// the final summary). Returns the new confirmed count. All output is stderr.
fn report_new_confirmed(confirmed: &[Finding], already: usize, verbose: bool) -> usize {
    if verbose && confirmed.len() > already {
        for f in &confirmed[already..] {
            let where_ = f.affected.first().map(|a| a.to_string()).unwrap_or_default();
            crate::progress::persistent(&format!(
                "  {} FOUND: {} [{}]{}",
                "✓".green().bold(),
                f.title,
                f.id,
                if where_.is_empty() { String::new() } else { format!(" — {}", where_) }
            ));
        }
    }
    confirmed.len()
}

#[allow(clippy::too_many_arguments)]
pub async fn run_audit(
    schema: &GqlSchema,
    url: &str,
    extra_headers: &[String],
    timeout_secs: u64,
    rate_limit_ms: u64,
    dynamic_throttling: bool,
    evasion: u8,
    config: &AppConfig,
    passive_findings: &[Finding],
    batch_probes: bool,
    batch_size: u32,
    idor_payloads: &[String],
    user_agent: Option<&str>,
    stealth: bool,
    transport: Transport,
    skip: &[String],
    only: &[String],
    no_dos: bool,
    focus: &[String],
    max_targets: Option<usize>,
    max_requests: Option<usize>,
    dry_run: bool,
    verbose: bool,
    chain: bool,
) -> Result<AuditReport, String> {
    // Own a mutable copy of the config so the auto-chain step can inject harvested
    // credentials into `audit.seeds` mid-run (before the probes that consume them).
    let mut config = config.clone();

    // Every probe this audit could run, paired with whether config already
    // enables it. Used for both the dry-run preview and (combined with
    // `probe_enabled`) the actual gating below.
    let probe_defs: [(&str, bool); 19] = [
        ("typename", true),
        ("csrf", true),
        ("introspection-matrix", true),
        ("cors", true),
        ("apq", true),
        ("alias-cap", true),
        ("node-idor", true),
        ("error-disclosure", true),
        ("unauth", config.audit.test_unauth),
        ("idor", config.audit.test_idor),
        ("mutation-privesc", config.audit.test_idor),
        ("ssrf", config.audit.test_injection),
        ("sql-injection", config.audit.test_injection),
        ("os-command-injection", config.audit.test_injection),
        ("xss", config.audit.test_injection),
        ("complexity", config.audit.test_complexity),
        ("dos-expansion", config.audit.test_complexity),
        ("batching", config.audit.test_batching),
        ("alias-dos", config.audit.test_alias_dos),
    ];

    // Focus-only view used to size the schema before the cap is resolved.
    let focus_scope = targets::AuditScope::new(focus, None);

    // Resolve the effective per-probe target cap. An explicit `--max-targets` always wins
    // (`0` = unlimited); otherwise auto-cap large schemas so a default run can't self-DoS.
    let (resolved_max_targets, auto_capped) = if let Some(mt) = max_targets {
        (if mt == 0 { None } else { Some(mt) }, false)
    } else {
        let root = targets::count_root_fields(schema, &focus_scope);
        let inj = if config.audit.test_injection {
            targets::count_injection_targets(schema, targets::SQLI_LEAF_SCALARS, &focus_scope)
        } else {
            0
        };
        if root.max(inj) > LARGE_SCHEMA_TARGET_THRESHOLD {
            (Some(DEFAULT_LARGE_SCHEMA_CAP), true)
        } else {
            (None, false)
        }
    };
    let scope = targets::AuditScope::new(focus, resolved_max_targets);

    if dry_run {
        println!();
        println!(
            "  {}  {}",
            "introspectre".bold().bright_white(),
            "active audit (dry run)".bright_black()
        );
        println!("  {} {}", "Target:".bright_black(), url.bright_white());
        if !focus.is_empty() {
            println!("  {} {}", "Focus:".bright_black(), focus.join(", ").bright_white());
        }
        match resolved_max_targets {
            Some(cap) => println!(
                "  {} {} per probe{}",
                "Max targets:".bright_black(),
                cap.to_string().bright_white(),
                if auto_capped { " (auto, large schema)".yellow().to_string() } else { String::new() }
            ),
            None => println!("  {} {}", "Max targets:".bright_black(), "unlimited".bright_white()),
        }
        println!();

        // Cap a target count by the resolved per-probe limit (focus can only narrow further).
        let cap = |n: usize| resolved_max_targets.map(|m| n.min(m)).unwrap_or(n);
        let sqli_reqs_per = 1 + (SQLI_BASE_PAYLOADS + config.audit.custom_payloads.len()) * 2;
        let estimate = |id: &str| -> Option<usize> {
            match id {
                "unauth" => {
                    let t = cap(targets::count_root_fields(schema, &scope));
                    Some(if batch_probes && batch_size > 0 {
                        t.div_ceil(batch_size as usize)
                    } else {
                        t
                    })
                }
                "mutation-privesc" => Some(cap(targets::count_privesc_targets(schema, &scope))),
                "sql-injection" => {
                    Some(cap(targets::count_injection_targets(schema, targets::SQLI_LEAF_SCALARS, &scope)) * sqli_reqs_per)
                }
                "os-command-injection" => {
                    Some(cap(targets::count_injection_targets(schema, targets::CMDI_LEAF_SCALARS, &scope)) * 5)
                }
                "xss" => Some(cap(targets::count_scalar_arg_targets(schema, &scope)) * 3),
                _ => None,
            }
        };

        let mut would_run = 0usize;
        let mut total_est = 0usize;
        for (id, cfg_enabled) in probe_defs.iter() {
            if *cfg_enabled && probe_enabled(id, only, skip, no_dos, verbose) {
                would_run += 1;
                match estimate(id) {
                    Some(n) => {
                        total_est += n;
                        println!(
                            "  {} {}",
                            format!("[dry-run] {}", id).cyan(),
                            format!("~{} request(s)", n).bright_white()
                        );
                    }
                    None => {
                        total_est += 2; // O(1) probes send a handful of fixed requests
                        println!(
                            "  {} {}",
                            format!("[dry-run] {}", id).cyan(),
                            "bounded (O(1))".bright_black()
                        );
                    }
                }
            }
        }

        // Make config-disabled probes visible instead of silently omitting them.
        let disabled: Vec<&str> = probe_defs.iter().filter(|(_, en)| !*en).map(|(id, _)| *id).collect();
        if !disabled.is_empty() {
            println!(
                "  {} disabled by config: {} {}",
                "•".yellow(),
                disabled.join(", ").yellow(),
                "(injection probes: enable with --injection)".bright_black()
            );
        }

        let secs = (total_est as u64).saturating_mul(rate_limit_ms) / 1000;
        println!();
        println!(
            "  {} {} of {} probe(s) would run, ~{} total request(s) — about {}m {}s at {}ms spacing. No requests were sent.",
            "✓".green().bold(),
            would_run,
            probe_defs.len(),
            total_est.to_string().bright_white(),
            secs / 60,
            secs % 60,
            rate_limit_ms
        );

        return Ok(AuditReport {
            source: url.to_string(),
            passive_total_findings: passive_findings.len(),
            confirmed: Vec::new(),
            unconfirmed: Vec::new(),
            warnings: vec!["Dry run: no probes were executed and no requests were sent.".to_string()],
            server_fingerprint: None,
        });
    }

    let client = crate::io_ops::build_client(timeout_secs, user_agent, stealth)?;
    let mut confirmed: Vec<Finding> = Vec::new();
    let mut unconfirmed: Vec<Finding> = Vec::new();
    // Count of confirmed findings already surfaced live (for --verbose found-output).
    let mut reported = 0usize;
    let mut warnings: Vec<String> = Vec::new();

    // Scope + request budget shared by the fan-out probes (unauth, mutation-privesc, sqli,
    // xss, command-injection). Targets are ranked by any passive finding that already
    // touched them, then filtered by --focus and capped to --max-targets.
    let sev_index = targets::severity_index(passive_findings);
    let budget = targets::RequestBudget::new(max_requests);
    let scope_ctx = targets::ScopeCtx {
        sev_index: &sev_index,
        scope: &scope,
        budget: &budget,
    };

    // Fair-share the global `--max-requests` budget across the fan-out probes so an early probe
    // can't drain it before later ones run (e.g. sql-injection starving os-command-injection).
    // Each fan-out probe gets an equal slice; unused slack still falls back to the global cap.
    let fanout_ids = ["unauth", "mutation-privesc", "sql-injection", "os-command-injection", "xss"];
    let fanout_enabled = probe_defs
        .iter()
        .filter(|(id, cfg)| fanout_ids.contains(id) && *cfg && probe_enabled(id, only, skip, no_dos, verbose))
        .count();
    let fair_share: Option<usize> = match max_requests {
        Some(m) if m > 0 && fanout_enabled > 1 => Some(m.div_ceil(fanout_enabled).max(1)),
        _ => None,
    };

    if auto_capped {
        warnings.push(format!(
            "Large schema: auto-capped each fan-out probe to {} targets (ranked by passive-finding severity). Use --max-targets 0 for no cap, or --focus <Type> to aim the audit.",
            DEFAULT_LARGE_SCHEMA_CAP
        ));
    } else if let Some(cap) = resolved_max_targets {
        warnings.push(format!("Per-probe target cap: {} (--max-targets).", cap));
    }
    if !focus.is_empty() {
        warnings.push(format!("Focus filter active: {}.", focus.join(", ")));
    }
    if let Some(m) = max_requests {
        if m > 0 {
            warnings.push(format!("Global request budget: {} request(s) (--max-requests).", m));
        }
    }

    if !config.audit.test_injection {
        warnings.push(
            "Injection probes (sql-injection, os-command-injection, ssrf, xss) are DISABLED — enable with --injection (or `audit.test_injection = true` in config).".to_string(),
        );
    }

    if batch_probes {
        warnings.push(
            "Batch probing enabled: multiple safe probe operations will be combined into single requests."
                .to_string(),
        );
    }

    if dynamic_throttling {
        warnings.push("Dynamic throttling enabled: adjusting delays based on server response latency.".to_string());
    }

    if evasion > 0 {
        warnings.push(format!("Evasion testing enabled (Level {}): obfuscating probe queries to test WAF resilience.", evasion));
    }

    let mut throttler = if dynamic_throttling {
        Some(crate::audit::utils::Throttler::new(rate_limit_ms))
    } else {
        None
    };

    if probe_enabled("typename", only, skip, no_dos, verbose) {
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        if let Err(e) = probe_typename(
            &client,
            url,
            extra_headers,
            current_delay,
            evasion,
            transport,
            &mut confirmed,
            &mut unconfirmed,
        )
        .await
        {
            if verbose { eprintln!("  {} probe error: {}", "!".yellow().bold(), e); }
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
        reported = report_new_confirmed(&confirmed, reported, verbose);
    }


    // CSRF & Method Auditing
    if probe_enabled("csrf", only, skip, no_dos, verbose) {
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        if let Err(e) = probe_csrf_methods(
            schema,
            url,
            &client,
            extra_headers,
            current_delay,
            evasion,
            &mut confirmed,
            &mut unconfirmed,
        )
        .await
        {
            if verbose { eprintln!("  {} probe error: {}", "!".yellow().bold(), e); }
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
        reported = report_new_confirmed(&confirmed, reported, verbose);
    }

    // Introspection method matrix (schema-disclosure surface at each auth level)
    if probe_enabled("introspection-matrix", only, skip, no_dos, verbose) {
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        if let Err(e) = probe_introspection_matrix(
            url,
            &client,
            extra_headers,
            current_delay,
            evasion,
            transport,
            &mut confirmed,
            &mut unconfirmed,
        )
        .await
        {
            if verbose { eprintln!("  {} probe error: {}", "!".yellow().bold(), e); }
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
        reported = report_new_confirmed(&confirmed, reported, verbose);
    }

    // CORS / cross-origin policy
    if probe_enabled("cors", only, skip, no_dos, verbose) {
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        if let Err(e) = probe_cors(
            url, &client, extra_headers, current_delay, evasion, transport, &mut confirmed, &mut unconfirmed,
        )
        .await
        {
            if verbose { eprintln!("  {} probe error: {}", "!".yellow().bold(), e); }
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
        reported = report_new_confirmed(&confirmed, reported, verbose);
    }

    // Automatic Persisted Queries (APQ) support
    if probe_enabled("apq", only, skip, no_dos, verbose) {
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        if let Err(e) = probe_apq(url, &client, extra_headers, current_delay, &mut confirmed, &mut unconfirmed).await {
            if verbose { eprintln!("  {} probe error: {}", "!".yellow().bold(), e); }
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
        reported = report_new_confirmed(&confirmed, reported, verbose);
    }

    // Per-field alias cap (anti-amplification control characterisation)
    if probe_enabled("alias-cap", only, skip, no_dos, verbose) {
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        if let Err(e) = probe_alias_cap(
            url, &client, extra_headers, current_delay, evasion, transport, &mut confirmed, &mut unconfirmed,
        )
        .await
        {
            if verbose { eprintln!("  {} probe error: {}", "!".yellow().bold(), e); }
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
        reported = report_new_confirmed(&confirmed, reported, verbose);
    }

    if probe_enabled("node-idor", only, skip, no_dos, verbose) {
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        if let Err(e) = probe_node_idor(
            schema, url, &client, extra_headers, &config.audit.seeds, current_delay, evasion, transport,
            &mut confirmed, &mut unconfirmed,
        )
        .await
        {
            if verbose { eprintln!("  {} probe error: {}", "!".yellow().bold(), e); }
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
        reported = report_new_confirmed(&confirmed, reported, verbose);
    }

    if probe_enabled("error-disclosure", only, skip, no_dos, verbose) {
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        if let Err(e) = probe_verbose_error_disclosure(
            schema,
            url,
            &client,
            extra_headers,
            current_delay,
            evasion,
            batch_probes,
            batch_size,
            transport,
            &mut confirmed,
            &mut unconfirmed,
        )
        .await
        {
            if verbose { eprintln!("  {} probe error: {}", "!".yellow().bold(), e); }
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
        reported = report_new_confirmed(&confirmed, reported, verbose);
    }

    if config.audit.test_unauth && probe_enabled("unauth", only, skip, no_dos, verbose) {
        budget.start_probe(fair_share);
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        if let Err(e) = probe_unauth_access(
            schema,
            url,
            &client,
            extra_headers,
            current_delay,
            evasion,
            batch_probes,
            batch_size,
            &config.audit.seeds,
            transport,
            &scope_ctx,
            &mut confirmed,
            &mut unconfirmed,
        )
        .await
        {
            if verbose { eprintln!("  {} probe error: {}", "!".yellow().bold(), e); }
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
        reported = report_new_confirmed(&confirmed, reported, verbose);
    }

    if config.audit.test_idor {
        if probe_enabled("idor", only, skip, no_dos, verbose) {
            let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
            let start = std::time::Instant::now();
            if let Err(e) = probe_idor(
                schema,
                url,
                &client,
                extra_headers,
                current_delay,
                evasion,
                &config,
                passive_findings,
                transport,
                &mut confirmed,
                &mut unconfirmed,
                idor_payloads,
            )
            .await
            {
                if verbose { eprintln!("  {} probe error: {}", "!".yellow().bold(), e); }
            }
            if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
            reported = report_new_confirmed(&confirmed, reported, verbose);
        }

        // Mutation PrivEsc Probe
        if probe_enabled("mutation-privesc", only, skip, no_dos, verbose) {
            budget.start_probe(fair_share);
            let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
            let start = std::time::Instant::now();
            if let Err(e) = probe_mutation_privesc(
                schema,
                url,
                &client,
                extra_headers,
                current_delay,
                evasion,
                &config,
                transport,
                &scope_ctx,
                &mut confirmed,
                &mut unconfirmed,
            )
            .await
            {
                if verbose { eprintln!("  {} probe error: {}", "!".yellow().bold(), e); }
            }
            if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
            reported = report_new_confirmed(&confirmed, reported, verbose);
        }
    }

    if config.audit.test_injection {
        // If the schema is empty (introspection blocked and no --use-schema),
        // injection probes have nothing to target — skip them with a clear
        // message. Schema-independent probes (typename, CSRF, CORS, APQ, etc.)
        // still run.
        let schema_available = !schema.types.is_empty()
            && (schema.query_type.is_some() || schema.mutation_type.is_some());
        if !schema_available {
            warnings.push(
                "Injection probes skipped: no schema available (introspection blocked and no --use-schema). There are no types/fields/args to target.".to_string(),
            );
        } else {
        if probe_enabled("ssrf", only, skip, no_dos, verbose) {
            warnings.push(
                "SSRF probe safety warning: only run with explicit authorization from the target program."
                    .to_string(),
            );

            let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
            let start = std::time::Instant::now();
            if let Err(e) = probe_ssrf(
                schema,
                url,
                &client,
                extra_headers,
                current_delay,
                evasion,
                &config,
                passive_findings,
                transport,
                &mut confirmed,
                &mut unconfirmed,
            )
            .await
            {
                if verbose { eprintln!("  {} probe error: {}", "!".yellow().bold(), e); }
            }
            if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
            reported = report_new_confirmed(&confirmed, reported, verbose);
        }

        // SQLi Probe
        if probe_enabled("sql-injection", only, skip, no_dos, verbose) {
            budget.start_probe(fair_share);
            let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
            let start = std::time::Instant::now();
            if let Err(e) = probe_sqli(
                schema,
                url,
                &client,
                extra_headers,
                current_delay,
                evasion,
                &config,
                transport,
                &scope_ctx,
                &mut confirmed,
                &mut unconfirmed,
            )
            .await
            {
                if verbose { eprintln!("  {} probe error: {}", "!".yellow().bold(), e); }
            }
            if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
            reported = report_new_confirmed(&confirmed, reported, verbose);
        }

        // Auto-chain: on a confirmed SQLi, extract credentials and feed them into the seed map so
        // the following probes (e.g. command injection on an admin-gated sink) can authenticate.
        if chain
            && (confirmed.iter().any(|f| f.id == "sql-injection" || f.id == "sql-injection-inline"))
        {
            eprintln!(
                "  {} auto-chain: extracting credentials via the confirmed SQL injection...",
                "→".cyan()
            );
            let creds = chain::harvest_credentials(
                schema, url, &client, extra_headers, rate_limit_ms, evasion, transport, &config, &confirmed,
            )
            .await;
            if let Some((user, pass)) = creds.first().cloned() {
                // Feed the first recovered pair into the seed map by common arg names, without
                // overwriting anything the operator already supplied.
                for k in ["username", "user", "login", "email", "name"] {
                    config.audit.seeds.entry(k.to_string()).or_insert_with(|| user.clone());
                }
                for k in ["password", "passwd", "pass", "pwd"] {
                    config.audit.seeds.entry(k.to_string()).or_insert_with(|| pass.clone());
                }
                let listed = creds
                    .iter()
                    .take(10)
                    .map(|(u, p)| format!("{}:{}", u, chain::mask_secret(p)))
                    .collect::<Vec<_>>()
                    .join(", ");
                confirmed.push(Finding {
                    id: "credential-exposure",
                    severity: Severity::Critical,
                    title: "Credentials Extracted via SQL Injection (auto-chain)",
                    description: format!(
                        "### Analysis\nThe confirmed SQL injection was used to UNION-dump a credentials table. {} account(s) were recovered; the first pair was fed into the audit's seeds so subsequent probes can authenticate to reach protected functionality.\n\n### Evidence\n- Recovered (passwords masked): {}",
                        creds.len(), listed
                    ),
                    affected: vec![AffectedLocation::Type("Credentials Store".into())],
                    remediation: "Fix the SQL injection (parameterised queries / an ORM), store passwords only as salted hashes, and enforce least-privilege database access so a single injection cannot read the credentials table.",
                    first_step: Some("Re-run the UNION payload from the SQLi finding against the users table and confirm the returned username/password rows.".into()),
                    references: vec!["OWASP API8: Injection", "CWE-89: SQL Injection", "CWE-522: Insufficiently Protected Credentials"],
                    status: FindingStatus::Confirmed,
                    confidence: Confidence::Confirmed,
                    evidence_level: EvidenceLevel::Executed,
                    poc: None,
                });
                reported = report_new_confirmed(&confirmed, reported, verbose);
            } else {
                eprintln!(
                    "  {} auto-chain: no credentials recovered (unrecognised DB/table layout).",
                    "→".blue()
                );
            }
        }

        // Command Injection Probe
        if probe_enabled("os-command-injection", only, skip, no_dos, verbose) {
            budget.start_probe(fair_share);
            let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
            let start = std::time::Instant::now();
            if let Err(e) = probe_command_injection(
                schema,
                url,
                &client,
                extra_headers,
                current_delay,
                evasion,
                &config,
                transport,
                &scope_ctx,
                &mut confirmed,
                &mut unconfirmed,
            )
            .await
            {
                if verbose { eprintln!("  {} probe error: {}", "!".yellow().bold(), e); }
            }
            if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
            reported = report_new_confirmed(&confirmed, reported, verbose);
        }

        // XSS Probe
        if probe_enabled("xss", only, skip, no_dos, verbose) {
            budget.start_probe(fair_share);
            let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
            let start = std::time::Instant::now();
            if let Err(e) = probe_xss(
                schema,
                url,
                &client,
                extra_headers,
                current_delay,
                evasion,
                &config,
                transport,
                &scope_ctx,
                &mut confirmed,
                &mut unconfirmed,
            )
            .await
            {
                if verbose { eprintln!("  {} probe error: {}", "!".yellow().bold(), e); }
            }
            if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
            reported = report_new_confirmed(&confirmed, reported, verbose);
        }
        } // close else (schema_available)
    }

    if config.audit.test_complexity {
        if probe_enabled("complexity", only, skip, no_dos, verbose) {
            let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
            let start = std::time::Instant::now();
            if let Err(e) = probe_complexity(
                schema,
                &client,
                url,
                extra_headers,
                current_delay,
                evasion,
                transport,
                &mut confirmed,
                &mut unconfirmed,
            )
            .await
            {
                if verbose { eprintln!("  {} probe error: {}", "!".yellow().bold(), e); }
            }
            if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
            reported = report_new_confirmed(&confirmed, reported, verbose);
        }

        // Expanded DoS Probes
        if probe_enabled("dos-expansion", only, skip, no_dos, verbose) {
            let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
            let start = std::time::Instant::now();
            if let Err(e) = probe_dos_expansion(
                schema,
                url,
                &client,
                extra_headers,
                current_delay,
                evasion,
                passive_findings,
                transport,
                &mut confirmed,
                &mut unconfirmed,
            )
            .await
            {
                if verbose { eprintln!("  {} probe error: {}", "!".yellow().bold(), e); }
            }
            if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
            reported = report_new_confirmed(&confirmed, reported, verbose);
        }
    }

    if config.audit.test_batching && probe_enabled("batching", only, skip, no_dos, verbose) {
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        if let Err(e) = probe_batching(
            &client,
            url,
            extra_headers,
            current_delay,
            evasion,
            transport,
            &mut confirmed,
            &mut unconfirmed,
        )
        .await
        {
            if verbose { eprintln!("  {} probe error: {}", "!".yellow().bold(), e); }
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
        reported = report_new_confirmed(&confirmed, reported, verbose);
    }

    if config.audit.test_alias_dos && probe_enabled("alias-dos", only, skip, no_dos, verbose) {
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        if let Err(e) = probe_alias_dos(
            schema,
            url,
            &client,
            extra_headers,
            current_delay,
            evasion,
            &config.audit.seeds,
            transport,
            &mut confirmed,
            &mut unconfirmed,
        )
        .await
        {
            if verbose { eprintln!("  {} probe error: {}", "!".yellow().bold(), e); }
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
        reported = report_new_confirmed(&confirmed, reported, verbose);
    }

    // Erase any lingering transient probe-status line before reports print.
    let _ = reported; // last probe's update is intentionally not read further
    crate::progress::clear();

    if budget.was_hit() {
        warnings.push(format!(
            "Global request budget ({}) reached — some probe targets were not tested. Raise --max-requests or narrow --focus to cover them.",
            max_requests.unwrap_or(0)
        ));
    }

    Ok(AuditReport {
        source: url.to_string(),
        passive_total_findings: passive_findings.len(),
        confirmed: consolidate_findings(confirmed),
        unconfirmed: consolidate_findings(unconfirmed),
        warnings,
        server_fingerprint: None,
    })
}

fn consolidate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut consolidated: Vec<Finding> = Vec::new();
    for finding in findings {
        if let Some(existing) = consolidated.iter_mut().find(|f| f.id == finding.id) {
            for location in finding.affected {
                if !existing.affected.contains(&location) {
                    existing.affected.push(location);
                }
            }
        } else {
            consolidated.push(finding);
        }
    }
    consolidated
}

pub fn print_audit_text_report(report: &AuditReport, max_affected: usize, verbose: bool) {
    println!();
    println!(
        "  {}  {}",
        "introspectre".bold().bright_white(),
        "active audit".bright_black()
    );
    println!(
        "  {} {}",
        "Target:".bright_black(),
        report.source.bright_white()
    );
    if let Some(fp) = &report.server_fingerprint {
        println!("  {} {}", "Server:".bright_black(), fp.label().bright_white());
    }
    println!(
        "  {} {}",
        "Passive findings:".bright_black(),
        report.passive_total_findings
    );
    println!();

    if !report.warnings.is_empty() {
        println!("  {}", "Warnings".bold().yellow());
        for w in &report.warnings {
            println!("  {} {}", "!".yellow().bold(), w.yellow());
        }
        println!();
    }

    println!("  {}", "Confirmed Findings".bold().white());
    if report.confirmed.is_empty() {
        println!("  {} No confirmed active findings.", "✓".green().bold());
    } else {
        for f in &report.confirmed {
            println!(
                "  {} {} {}",
                "✖".red().bold(),
                f.title.bold().white(),
                format!("[{}]", f.id).bright_black()
            );
            println!("      {}", f.description.bright_white());
            crate::report::print_limited_affected_text(&f.affected, max_affected);
            if verbose {
                if let Some(poc) = &f.poc {
                    println!("      {}", "PoC:".bright_black());
                    for line in poc.lines() {
                        println!("        {}", line.bright_white());
                    }
                }
            }
            // sqlmap exploitation hand-off for confirmed injections — always shown
            // (it's the key actionable next step), line-by-line so it stays copy-pasteable.
            if let Some(guide) = crate::audit::poc::sqlmap_guide(f, &report.source) {
                println!("      {}", "Exploit (sqlmap):".bright_black());
                for line in guide.lines() {
                    println!("        {}", line.green());
                }
            }
            println!();
        }
    }

    println!("  {}", "Unconfirmed / Inconclusive".bold().white());
    if report.unconfirmed.is_empty() {
        println!("  {} No unconfirmed probe outcomes.", "✓".green().bold());
    } else {
        for f in &report.unconfirmed {
            println!(
                "  {} {} {}",
                "ℹ".cyan().bold(),
                f.title.bold().white(),
                format!("[{}]", f.id).bright_black()
            );
            println!("      {}", f.description.bright_white());
            crate::report::print_limited_affected_text(&f.affected, max_affected);
            println!();
        }
    }
}

pub fn print_audit_json_report(report: &AuditReport) {
    // Serialize each finding and attach the sqlmap exploitation guide (injections only).
    let enrich = |f: &Finding| {
        let mut v = serde_json::to_value(f).unwrap_or_else(|_| serde_json::json!({}));
        if let Some(g) = crate::audit::poc::sqlmap_guide(f, &report.source) {
            v["exploit_guide"] = serde_json::json!(g);
        }
        v
    };
    let confirmed: Vec<_> = report.confirmed.iter().map(enrich).collect();
    let unconfirmed: Vec<_> = report.unconfirmed.iter().map(enrich).collect();
    let output = serde_json::json!({
        "source": report.source,
        "server_fingerprint": report.server_fingerprint,
        "passive_total_findings": report.passive_total_findings,
        "confirmed_total": report.confirmed.len(),
        "unconfirmed_total": report.unconfirmed.len(),
        "warnings": report.warnings,
        "confirmed": confirmed,
        "unconfirmed": unconfirmed,
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

pub fn print_audit_markdown_report(report: &AuditReport, max_affected: usize) {
    println!("# GraphQL Active Audit Report\n");
    println!("- Source: {}", report.source);
    if let Some(fp) = &report.server_fingerprint {
        println!("- Server framework: {}", fp.label());
    }
    println!(
        "- Passive possibility findings: {}",
        report.passive_total_findings
    );
    println!("- Confirmed: {}", report.confirmed.len());
    println!("- Unconfirmed: {}\n", report.unconfirmed.len());

    if !report.warnings.is_empty() {
        println!("## Warnings\n");
        for w in &report.warnings {
            println!("- {}", w);
        }
        println!();
    }

    println!("## Confirmed Findings\n");
    if report.confirmed.is_empty() {
        println!("No confirmed active findings.\n");
    } else {
        for f in &report.confirmed {
            println!("### {} {}", f.id, f.title);
            println!();
            println!("- Severity: {}", f.severity);
            println!("- Confidence: CONFIRMED");
            println!();
            println!("{}", f.description);
            println!();
            if !f.affected.is_empty() {
                println!("#### Affected\n");
                crate::report::print_limited_affected_markdown(&f.affected, max_affected);
                println!();
            }
            if let Some(poc) = &f.poc {
                println!("#### PoC\n");
                println!("```graphql\n{}\n```\n", poc);
            }
            if let Some(guide) = crate::audit::poc::sqlmap_guide(f, &report.source) {
                println!("#### Exploit with sqlmap\n");
                println!("```bash\n{}\n```\n", guide);
            }
            println!("#### Remediation\n");
            println!("{}\n", f.remediation);
        }
    }

    println!("## Unconfirmed Findings\n");
    if report.unconfirmed.is_empty() {
        println!("No unconfirmed probe outcomes.\n");
    } else {
        for f in &report.unconfirmed {
            println!("### {} {}", f.id, f.title);
            println!();
            println!("- Severity: {}", f.severity);
            println!("- Confidence: POSSIBLE");
            println!();
            println!("{}", f.description);
            println!();
            if !f.affected.is_empty() {
                println!("#### Affected\n");
                crate::report::print_limited_affected_markdown(&f.affected, max_affected);
                println!();
            }
            println!("#### Remediation\n");
            println!("{}\n", f.remediation);
        }
    }
}

// `print_limited_affected_text` / `_markdown` live in `crate::report` and are
// shared here to avoid duplicated copies.
