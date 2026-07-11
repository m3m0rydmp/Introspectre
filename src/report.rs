use colored::Colorize;
use crate::types::{AffectedLocation, Finding, ReportMeta, SchemaStats, Severity, INTROSPECTION_QUERY};

fn severity_icon(s: &Severity) -> colored::ColoredString {
    match s {
        Severity::Critical => "☣".magenta().bold(),
        Severity::High => "✖".red().bold(),
        Severity::Medium => "⚠".yellow().bold(),
        Severity::Low => "ℹ".cyan().bold(),
        Severity::Info => "·".bright_blue().bold(),
    }
}

fn wrap(s: &str, width: usize) -> Vec<String> {
    let mut result = Vec::new();
    for line in s.lines() {
        if line.trim().is_empty() {
            result.push(String::new());
            continue;
        }
        
        let mut current = String::new();
        for word in line.split_whitespace() {
            if !current.is_empty() && current.len() + word.len() + 1 > width {
                result.push(current.clone());
                current = word.to_string();
            } else {
                if !current.is_empty() {
                    current.push(' ');
                }
                current.push_str(word);
            }
        }
        if !current.is_empty() {
            result.push(current);
        }
    }
    result
}

pub fn print_limited_affected_text(affected: &[AffectedLocation], max_affected: usize) {
    let shown = if max_affected == 0 {
        affected.len()
    } else {
        affected.len().min(max_affected)
    };

    for a in affected.iter().take(shown) {
        println!("      {} {}", "·".bright_black(), a.to_string().bright_cyan());
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

pub fn print_limited_affected_markdown(affected: &[AffectedLocation], max_affected: usize) {
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

pub fn query_reference_for_finding(f: &Finding) -> Option<String> {
    match f.id {
        "introspection-enabled" => Some(INTROSPECTION_QUERY.trim().to_string()),
        _ => None,
    }
}

fn print_auth_discovery(meta: &ReportMeta) {
    if !meta.auth_discovery_performed {
        return;
    }

    if let Some(auth) = &meta.auth_discovery {
        println!();
        println!("  {}", "Auth Guard Discovery".bold().white());
        println!(
            "  Protected: {}  |  Public: {}  |  Inconclusive: {}",
            auth.protected.len().to_string().red().bold(),
            auth.public.len().to_string().green().bold(),
            auth.inconclusive.len().to_string().yellow().bold(),
        );

        if !auth.protected.is_empty() {
            println!("  {} Found protected root fields:", "→".bright_black());
            for p in &auth.protected {
                println!("    {} {}", "·".bright_black(), p.red());
            }
        }
    }
}

pub fn print_text_report(
    schema: &crate::types::GqlSchema,
    stats: &SchemaStats,
    findings: &[Finding],
    meta: &ReportMeta,
    max_affected: usize,
    verbose: bool,
) {
    println!();
    println!(
        "  {}  v{}",
        "introspectre".bold().bright_white(),
        env!("CARGO_PKG_VERSION").bright_black()
    );
    println!(
        "  {} {}",
        "Target:".bright_black(),
        meta.source.bright_white()
    );
    println!(
        "  {} {}",
        "Mode:  ".bright_black(),
        if meta.offline {
            "Offline static analysis".yellow()
        } else if meta.static_only {
            "Live scan (safe static strategy)".green()
        } else {
            "Live scan (active probes enabled)".yellow()
        }
    );

    println!();
    println!("  {}", "Schema Overview".bold().white());
    println!(
        "  Types: {}  |  Fields: {}  |  Queries: {}  |  Mutations: {}  |  Subs: {}",
        stats.total_types.to_string().bold(),
        stats.total_fields.to_string().bold(),
        stats.queries.to_string().green().bold(),
        stats.mutations.to_string().yellow().bold(),
        stats.subscriptions.to_string().red().bold(),
    );

    print_auth_discovery(meta);

    if findings.is_empty() {
        println!();
        println!("  {} No findings detected.", "✓".green().bold());
        println!();
        return;
    }

    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let med = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();
    let info = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();
    let crit = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();

    println!();
    println!("  {}", "Findings Summary".bold().white());
    print!("  ");
    if crit > 0 {
        print!("{} CRITICAL  ", crit.to_string().magenta().bold());
    }
    if high > 0 {
        print!("{} HIGH  ", high.to_string().red().bold());
    }
    if med > 0 {
        print!("{} MEDIUM  ", med.to_string().yellow().bold());
    }
    if low > 0 {
        print!("{} LOW  ", low.to_string().cyan().bold());
    }
    if info > 0 {
        print!("{} INFO  ", info.to_string().bright_blue().bold());
    }
    println!("({} total)", findings.len());
    println!();

    for f in findings {
        println!(
            "  {} {} {}",
            severity_icon(&f.severity),
            f.title.bold().white(),
            format!("[{}]", f.id).bright_black()
        );

        let status_color = match &f.status {
            crate::types::FindingStatus::Confirmed => "confirmed".green(),
            crate::types::FindingStatus::Possible => "possible".yellow(),
            crate::types::FindingStatus::Inferred => "inferred".bright_black(),
        };
        println!("      Status   : {}", status_color);

        // Sanitize description for text output (remove markdown artifacts)
        let clean_desc = f.description
            .replace("### [ VULNERABILITY DETAILS ]", "[ VULNERABILITY DETAILS ]")
            .replace("### [ DATABASE ERROR ]", "[ DATABASE ERROR ]")
            .replace("### [ ANALYSIS ]", "[ ANALYSIS ]")
            .replace("**", "")
            .replace("`", "");

        for line in wrap(&clean_desc, 72) {
            if !line.is_empty() {
                println!("      {}", line.bright_white());
            } else {
                println!();
            }
        }

        if !f.affected.is_empty() {
            println!("      {}", "Affected:".bright_black());
            print_limited_affected_text(&f.affected, max_affected);
        }

        if let Some(first_step) = &f.first_step {
            println!("      {}", "First Step:".bright_black());
            for line in wrap(&first_step.replace("`", ""), 72) {
                println!("      {}", line.cyan());
            }
        }

        println!("      {}", "Remediation:".bright_black());
        let clean_remedy = f.remediation.replace("**", "").replace("`", "");
        for line in wrap(&clean_remedy, 72) {
            println!("      {}", line.green());
        }

        if verbose {
            if !f.references.is_empty() {
                println!("      {}", "References:".bright_black());
                for r in &f.references {
                    println!("      {} {}", "↗".bright_black(), r.bright_black());
                }
            }

            if let Some(query_ref) = query_reference_for_finding(f) {
                println!("      {}", "Query Reference:".bright_black());
                for line in query_ref.lines() {
                    println!("        {}", line.bright_blue());
                }
            }

            if let Some(poc) = crate::audit::poc::generate_reproduction_steps(f, schema, &meta.source) {
                println!("      {}", "Reproduction (PoC):".bright_black());
                for line in poc.lines() {
                    println!("        {}", line.bright_white());
                }
            }
        }

        println!();
    }
}

pub fn print_json_report(_schema: &crate::types::GqlSchema, stats: &SchemaStats, findings: &[Finding], meta: &ReportMeta) {
    let findings_with_queries: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "id": f.id,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "affected": f.affected,
                "remediation": f.remediation,
                "first_step": f.first_step,
                "status": f.status,
                "references": f.references,
                "confidence": f.confidence,
                "evidence_level": f.evidence_level,
                "poc": f.poc,
                "query_reference": query_reference_for_finding(f),
            })
        })
        .collect();

    let output = serde_json::json!({
        "source": meta.source,
        "analysis_mode": {
            "offline": meta.offline,
            "static_only_recommendation": meta.static_only,
            "confidence": if meta.offline { "potential_or_highly_likely" } else { "live_introspection_validated" }
        },
        "schema_stats": stats,
        "auth_discovery": meta.auth_discovery,
        "total_findings": findings.len(),
        "counts": {
            "critical": findings.iter().filter(|f| f.severity == Severity::Critical).count(),
            "high": findings.iter().filter(|f| f.severity == Severity::High).count(),
            "medium": findings.iter().filter(|f| f.severity == Severity::Medium).count(),
            "low": findings.iter().filter(|f| f.severity == Severity::Low).count(),
            "info": findings.iter().filter(|f| f.severity == Severity::Info).count(),
        },
        "findings": findings_with_queries,
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

pub fn print_markdown_report(
    schema: &crate::types::GqlSchema,
    stats: &SchemaStats,
    findings: &[Finding],
    meta: &ReportMeta,
    max_affected: usize,
) {
    println!("# GraphQL Security Analyzer Report\n");
    println!("- Source: {}", meta.source);
    println!("- Mode: {}", if meta.offline { "offline" } else { "live" });
    println!("- Findings: {}\n", findings.len());

    println!("## Schema Overview\n");
    println!("- Total types: {}", stats.total_types);
    println!("- Queries: {}", stats.queries);
    println!("- Mutations: {}", stats.mutations);
    println!("- Subscriptions: {}", stats.subscriptions);
    println!("- Total fields: {}", stats.total_fields);
    println!("- Deprecated fields: {}\n", stats.deprecated_fields);

    if findings.is_empty() {
        println!("No findings detected.");
        return;
    }

    for f in findings {
        println!("## {} {}", f.id, f.title);
        println!();
        println!("- Severity: {}", f.severity);
        println!("- Status: {}", f.status);
        println!();
        println!("{}", f.description);
        println!();

        if !f.affected.is_empty() {
            println!("### Affected\n");
            print_limited_affected_markdown(&f.affected, max_affected);
            println!();
        }

        if let Some(first_step) = &f.first_step {
            println!("### First Step Recommendation\n");
            println!("{}\n", first_step);
        }

        if let Some(poc) = crate::audit::poc::generate_reproduction_steps(f, schema, &meta.source) {
            println!("### Reproduction (PoC)\n");
            if poc.starts_with("curl") {
                println!("```bash\n{}\n```\n", poc);
            } else {
                println!("```graphql\n{}\n```\n", poc);
            }
        }

        println!("### Remediation\n");
        println!("{}\n", f.remediation);
    }
}
