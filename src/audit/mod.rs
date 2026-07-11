pub mod probes;
pub mod utils;
pub mod poc;

use crate::audit::probes::{
    probe_alias_dos, probe_batching, probe_complexity, probe_idor, probe_ssrf, probe_typename,
    probe_unauth_access, probe_verbose_error_disclosure, probe_sqli, probe_xss, probe_command_injection, probe_mutation_privesc,
    probe_engine_fingerprint, probe_csrf_methods, probe_dos_expansion,
};
use crate::config::AppConfig;
use crate::types::{Finding, GqlSchema};
use colored::Colorize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub source: String,
    pub passive_total_findings: usize,
    pub confirmed: Vec<Finding>,
    pub unconfirmed: Vec<Finding>,
    pub warnings: Vec<String>,
}

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
) -> Result<AuditReport, String> {
    let client = crate::io_ops::build_client(timeout_secs, user_agent, stealth)?;
    let mut confirmed: Vec<Finding> = Vec::new();
    let mut unconfirmed: Vec<Finding> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

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

    let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
    let start = std::time::Instant::now();
    if let Err(e) = probe_typename(
        &client,
        url,
        extra_headers,
        current_delay,
        evasion,
        &mut confirmed,
        &mut unconfirmed,
    )
    .await
    {
        eprintln!("  {} probe error: {}", "!".yellow().bold(), e);
    }
    if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }

    // Engine Fingerprinting
    let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
    let start = std::time::Instant::now();
    if let Err(e) = probe_engine_fingerprint(
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
        eprintln!("  {} probe error: {}", "!".yellow().bold(), e);
    }
    if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }

    // CSRF & Method Auditing
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
        eprintln!("  {} probe error: {}", "!".yellow().bold(), e);
    }
    if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }

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
        &mut confirmed,
        &mut unconfirmed,
    )
    .await
    {
        eprintln!("  {} probe error: {}", "!".yellow().bold(), e);
    }
    if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }

    if config.audit.test_unauth {
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
            &mut confirmed,
            &mut unconfirmed,
        )
        .await
        {
            eprintln!("  {} probe error: {}", "!".yellow().bold(), e);
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
    }

    if config.audit.test_idor {
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        if let Err(e) = probe_idor(
            schema,
            url,
            &client,
            extra_headers,
            current_delay,
            evasion,
            config,
            passive_findings,
            &mut confirmed,
            &mut unconfirmed,
            idor_payloads,
        )
        .await
        {
            eprintln!("  {} probe error: {}", "!".yellow().bold(), e);
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }

        // Mutation PrivEsc Probe
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        if let Err(e) = probe_mutation_privesc(
            schema,
            url,
            &client,
            extra_headers,
            current_delay,
            evasion,
            config,
            &mut confirmed,
            &mut unconfirmed,
        )
        .await
        {
            eprintln!("  {} probe error: {}", "!".yellow().bold(), e);
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
    }

    if config.audit.test_injection {
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
            config,
            passive_findings,
            &mut confirmed,
            &mut unconfirmed,
        )
        .await
        {
            eprintln!("  {} probe error: {}", "!".yellow().bold(), e);
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }

        // SQLi Probe
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        if let Err(e) = probe_sqli(
            schema,
            url,
            &client,
            extra_headers,
            current_delay,
            evasion,
            config,
            &mut confirmed,
            &mut unconfirmed,
        )
        .await
        {
            eprintln!("  {} probe error: {}", "!".yellow().bold(), e);
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }

        // Command Injection Probe
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        if let Err(e) = probe_command_injection(
            schema,
            url,
            &client,
            extra_headers,
            current_delay,
            evasion,
            config,
            &mut confirmed,
            &mut unconfirmed,
        )
        .await
        {
            eprintln!("  {} probe error: {}", "!".yellow().bold(), e);
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }

        // XSS Probe
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        if let Err(e) = probe_xss(
            schema,
            url,
            &client,
            extra_headers,
            current_delay,
            evasion,
            config,
            &mut confirmed,
            &mut unconfirmed,
        )
        .await
        {
            eprintln!("  {} probe error: {}", "!".yellow().bold(), e);
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
    }

    if config.audit.test_complexity {
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        if let Err(e) = probe_complexity(
            schema,
            &client,
            url,
            extra_headers,
            current_delay,
            evasion,
            &mut confirmed,
            &mut unconfirmed,
        )
        .await
        {
            eprintln!("  {} probe error: {}", "!".yellow().bold(), e);
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }

        // Expanded DoS Probes
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
            &mut confirmed,
            &mut unconfirmed,
        )
        .await
        {
            eprintln!("  {} probe error: {}", "!".yellow().bold(), e);
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
    }

    if config.audit.test_batching {
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        if let Err(e) = probe_batching(
            &client,
            url,
            extra_headers,
            current_delay,
            evasion,
            &mut confirmed,
            &mut unconfirmed,
        )
        .await
        {
            eprintln!("  {} probe error: {}", "!".yellow().bold(), e);
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
    }

    if config.audit.test_alias_dos {
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
            &mut confirmed,
            &mut unconfirmed,
        )
        .await
        {
            eprintln!("  {} probe error: {}", "!".yellow().bold(), e);
        }
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
    }

    Ok(AuditReport {
        source: url.to_string(),
        passive_total_findings: passive_findings.len(),
        confirmed: consolidate_findings(confirmed),
        unconfirmed: consolidate_findings(unconfirmed),
        warnings,
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
    let output = serde_json::json!({
        "source": report.source,
        "passive_total_findings": report.passive_total_findings,
        "confirmed_total": report.confirmed.len(),
        "unconfirmed_total": report.unconfirmed.len(),
        "warnings": report.warnings,
        "confirmed": report.confirmed,
        "unconfirmed": report.unconfirmed,
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

pub fn print_audit_markdown_report(report: &AuditReport, max_affected: usize) {
    println!("# GraphQL Active Audit Report\n");
    println!("- Source: {}", report.source);
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
