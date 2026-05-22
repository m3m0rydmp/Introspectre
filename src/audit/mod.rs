pub mod probes;
pub mod utils;
<<<<<<< HEAD

use crate::audit::probes::{
    probe_alias_dos, probe_batching, probe_complexity, probe_idor, probe_ssrf, probe_typename,
    probe_unauth_access, probe_verbose_error_disclosure,
};
use crate::audit::utils::build_client;
use crate::config::AppConfig;
use crate::types::{Finding, GqlSchema, Severity};
=======
pub mod poc;

use crate::audit::probes::{
    probe_alias_dos, probe_batching, probe_complexity, probe_idor, probe_ssrf, probe_typename,
    probe_unauth_access, probe_verbose_error_disclosure, probe_sqli, probe_xss, probe_mutation_privesc,
    probe_engine_fingerprint, probe_csrf_methods, probe_dos_expansion,
};
use crate::config::AppConfig;
use crate::types::{AffectedLocation, Finding, GqlSchema};
>>>>>>> update-research-refs
use colored::Colorize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
<<<<<<< HEAD
pub struct AuditFinding {
    pub id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub description: String,
    pub affected: Vec<String>,
    pub remediation: &'static str,
    pub evidence: &'static str,
    pub poc: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub source: String,
    pub passive_total_findings: usize,
    pub confirmed: Vec<AuditFinding>,
    pub unconfirmed: Vec<AuditFinding>,
=======
pub struct AuditReport {
    pub source: String,
    pub passive_total_findings: usize,
    pub confirmed: Vec<Finding>,
    pub unconfirmed: Vec<Finding>,
>>>>>>> update-research-refs
    pub warnings: Vec<String>,
}

pub async fn run_audit(
    schema: &GqlSchema,
    url: &str,
    extra_headers: &[String],
    timeout_secs: u64,
    rate_limit_ms: u64,
<<<<<<< HEAD
    config: &AppConfig,
    passive_findings: &[Finding],
    idor_payloads: &[String],
    batch_probes: bool,
    batch_size: u32,
) -> Result<AuditReport, String> {
    let client = build_client(timeout_secs)?;
    let mut confirmed: Vec<AuditFinding> = Vec::new();
    let mut unconfirmed: Vec<AuditFinding> = Vec::new();
=======
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
>>>>>>> update-research-refs
    let mut warnings: Vec<String> = Vec::new();

    if batch_probes {
        warnings.push(
            "Batch probing enabled: multiple safe probe operations will be combined into single requests."
                .to_string(),
        );
    }

<<<<<<< HEAD
=======
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
>>>>>>> update-research-refs
    probe_typename(
        &client,
        url,
        extra_headers,
<<<<<<< HEAD
        rate_limit_ms,
=======
        current_delay,
        evasion,
>>>>>>> update-research-refs
        &mut confirmed,
        &mut unconfirmed,
    )
    .await?;
<<<<<<< HEAD

=======
    if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }

    // Engine Fingerprinting
    let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
    let start = std::time::Instant::now();
    probe_engine_fingerprint(
        schema,
        url,
        &client,
        extra_headers,
        current_delay,
        evasion,
        &mut confirmed,
        &mut unconfirmed,
    )
    .await?;
    if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }

    // CSRF & Method Auditing
    let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
    let start = std::time::Instant::now();
    probe_csrf_methods(
        schema,
        url,
        &client,
        extra_headers,
        current_delay,
        evasion,
        &mut confirmed,
        &mut unconfirmed,
    )
    .await?;
    if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }

    let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
    let start = std::time::Instant::now();
>>>>>>> update-research-refs
    probe_verbose_error_disclosure(
        schema,
        url,
        &client,
        extra_headers,
<<<<<<< HEAD
        rate_limit_ms,
=======
        current_delay,
        evasion,
>>>>>>> update-research-refs
        batch_probes,
        batch_size,
        &mut confirmed,
        &mut unconfirmed,
    )
    .await?;
<<<<<<< HEAD

    if config.audit.test_unauth {
=======
    if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }

    if config.audit.test_unauth {
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
>>>>>>> update-research-refs
        probe_unauth_access(
            schema,
            url,
            &client,
            extra_headers,
<<<<<<< HEAD
            rate_limit_ms,
            batch_probes,
            batch_size,
=======
            current_delay,
            evasion,
            batch_probes,
            batch_size,
            &config.audit.seeds,
>>>>>>> update-research-refs
            &mut confirmed,
            &mut unconfirmed,
        )
        .await?;
<<<<<<< HEAD
    }

    if config.audit.test_idor {
=======
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
    }

    if config.audit.test_idor {
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
>>>>>>> update-research-refs
        probe_idor(
            schema,
            url,
            &client,
            extra_headers,
<<<<<<< HEAD
            rate_limit_ms,
=======
            current_delay,
            evasion,
>>>>>>> update-research-refs
            config,
            passive_findings,
            &mut confirmed,
            &mut unconfirmed,
            idor_payloads,
        )
        .await?;
<<<<<<< HEAD
=======
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }

        // Mutation PrivEsc Probe
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        probe_mutation_privesc(
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
        .await?;
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
>>>>>>> update-research-refs
    }

    if config.audit.test_injection {
        warnings.push(
            "SSRF probe safety warning: only run with explicit authorization from the target program."
                .to_string(),
        );
<<<<<<< HEAD
=======
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
>>>>>>> update-research-refs
        probe_ssrf(
            schema,
            url,
            &client,
            extra_headers,
<<<<<<< HEAD
            rate_limit_ms,
=======
            current_delay,
            evasion,
>>>>>>> update-research-refs
            config,
            passive_findings,
            &mut confirmed,
            &mut unconfirmed,
        )
        .await?;
<<<<<<< HEAD
    }

    if config.audit.test_complexity {
=======
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }

        // SQLi Probe
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        probe_sqli(
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
        .await?;
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }

        // XSS Probe
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        probe_xss(
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
        .await?;
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
    }

    if config.audit.test_complexity {
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
>>>>>>> update-research-refs
        probe_complexity(
            &client,
            url,
            extra_headers,
<<<<<<< HEAD
            rate_limit_ms,
=======
            current_delay,
            evasion,
>>>>>>> update-research-refs
            &mut confirmed,
            &mut unconfirmed,
        )
        .await?;
<<<<<<< HEAD
    }

    if config.audit.test_batching {
=======
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }

        // Expanded DoS Probes
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
        probe_dos_expansion(
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
        .await?;
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
    }

    if config.audit.test_batching {
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
>>>>>>> update-research-refs
        probe_batching(
            &client,
            url,
            extra_headers,
<<<<<<< HEAD
            rate_limit_ms,
=======
            current_delay,
            evasion,
>>>>>>> update-research-refs
            &mut confirmed,
            &mut unconfirmed,
        )
        .await?;
<<<<<<< HEAD
    }

    if config.audit.test_alias_dos {
=======
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
    }

    if config.audit.test_alias_dos {
        let current_delay = throttler.map(|t| t.delay_ms).unwrap_or(rate_limit_ms);
        let start = std::time::Instant::now();
>>>>>>> update-research-refs
        probe_alias_dos(
            schema,
            url,
            &client,
            extra_headers,
<<<<<<< HEAD
            rate_limit_ms,
=======
            current_delay,
            evasion,
            &config.audit.seeds,
>>>>>>> update-research-refs
            &mut confirmed,
            &mut unconfirmed,
        )
        .await?;
<<<<<<< HEAD
=======
        if let Some(t) = &mut throttler { t.adjust(start.elapsed().as_millis()); }
>>>>>>> update-research-refs
    }

    Ok(AuditReport {
        source: url.to_string(),
        passive_total_findings: passive_findings.len(),
        confirmed,
        unconfirmed,
        warnings,
    })
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
<<<<<<< HEAD
        "Candidates:".bright_black(),
=======
        "Possibilities:".bright_black(),
>>>>>>> update-research-refs
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
            print_limited_affected_text(&f.affected, max_affected);
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
            print_limited_affected_text(&f.affected, max_affected);
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
<<<<<<< HEAD
        "- Passive candidate findings: {}",
=======
        "- Passive possibility findings: {}",
>>>>>>> update-research-refs
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
                print_limited_affected_markdown(&f.affected, max_affected);
                println!();
            }
<<<<<<< HEAD
            if let Some(poc) = markdown_poc_for_audit_finding(f) {
                println!("#### PoC\n");
                println!("```graphql");
                println!("{}", poc);
                println!("```\n");
            } else if let Some(poc) = &f.poc {
                println!("#### PoC\n");
                println!("```bash");
                println!("{}", poc);
                println!("```\n");
=======
            if let Some(poc) = &f.poc {
                println!("#### PoC\n");
                println!("```graphql\n{}\n```\n", poc);
>>>>>>> update-research-refs
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
                print_limited_affected_markdown(&f.affected, max_affected);
                println!();
            }
            println!("#### Remediation\n");
            println!("{}\n", f.remediation);
        }
    }
}

<<<<<<< HEAD
fn print_limited_affected_text(affected: &[String], max_affected: usize) {
=======
fn print_limited_affected_text(affected: &[AffectedLocation], max_affected: usize) {
>>>>>>> update-research-refs
    let shown = if max_affected == 0 {
        affected.len()
    } else {
        affected.len().min(max_affected)
    };

    for a in affected.iter().take(shown) {
<<<<<<< HEAD
        println!("      {} {}", "·".bright_black(), a.bright_cyan());
=======
        println!("      {} {}", "·".bright_black(), a.to_string().bright_cyan());
>>>>>>> update-research-refs
    }

    let remaining = affected.len().saturating_sub(shown);
    if remaining > 0 {
        println!(
            "      {} {}",
            "·".bright_black(),
            format!(
                "... and {} more (use --max-affected 0 to show all)",
                remaining
            )
            .bright_black()
        );
    }
}

<<<<<<< HEAD
fn print_limited_affected_markdown(affected: &[String], max_affected: usize) {
=======
fn print_limited_affected_markdown(affected: &[AffectedLocation], max_affected: usize) {
>>>>>>> update-research-refs
    let shown = if max_affected == 0 {
        affected.len()
    } else {
        affected.len().min(max_affected)
    };

    for a in affected.iter().take(shown) {
        println!("- {}", a);
    }

    let remaining = affected.len().saturating_sub(shown);
    if remaining > 0 {
        println!(
            "- ... and {} more (use --max-affected 0 to show all)",
            remaining
        );
    }
}
<<<<<<< HEAD

fn markdown_poc_for_audit_finding(f: &AuditFinding) -> Option<String> {
    if f.id != "AUD-002" {
        return None;
    }

    let first = f.affected.first()?;
    let dot = first.find('.')?;
    let open = first.find('(')?;
    let close = first.find(')')?;
    if close <= open {
        return None;
    }

    let root = &first[..dot];
    let operation = &first[dot + 1..open];
    let arg = &first[open + 1..close];
    let keyword = if root == "Mutation" {
        "mutation"
    } else {
        "query"
    };
    Some(format!(
        "# Probe: IDOR on {}.{}\n{} {{\n  {}({}: \"VICTIM_ID\") {{\n    __typename\n  }}\n}}",
        root, operation, keyword, operation, arg
    ))
}
=======
>>>>>>> update-research-refs
