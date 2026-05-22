use colored::Colorize;
use crate::types::{AffectedLocation, Finding, ReportMeta, SchemaStats, Severity, INTROSPECTION_QUERY};

<<<<<<< HEAD
use crate::types::{Confidence, Finding, ReportMeta, SchemaStats, Severity, INTROSPECTION_QUERY};

fn severity_icon(s: &Severity) -> colored::ColoredString {
    match s {
=======
fn severity_icon(s: &Severity) -> colored::ColoredString {
    match s {
        Severity::Critical => "☣".magenta().bold(),
>>>>>>> update-research-refs
        Severity::High => "✖".red().bold(),
        Severity::Medium => "⚠".yellow().bold(),
        Severity::Low => "ℹ".cyan().bold(),
        Severity::Info => "·".bright_blue().bold(),
<<<<<<< HEAD
    }
}

fn confidence_label(c: &Confidence) -> &'static str {
    match c {
        Confidence::Theoretical => "[THEORETICAL]",
        Confidence::Possible => "[POSSIBLE]",
        Confidence::Confirmed => "[CONFIRMED]",
=======
>>>>>>> update-research-refs
    }
}

fn wrap(s: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in s.split_whitespace() {
        if !current.is_empty() && current.len() + word.len() + 1 > width {
            lines.push(current.clone());
            current = word.to_string();
        } else {
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn print_limited_affected_text(affected: &[AffectedLocation], max_affected: usize) {
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

fn print_limited_affected_markdown(affected: &[AffectedLocation], max_affected: usize) {
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
        "GQL-001" => Some(INTROSPECTION_QUERY.trim().to_string()),
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
<<<<<<< HEAD
        "  {}  {}",
        "introspectre".bold().bright_white(),
        "v1.0.0".bright_black()
=======
        "  {}  v{}",
        "introspectre".bold().bright_white(),
        env!("CARGO_PKG_VERSION").bright_black()
>>>>>>> update-research-refs
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
<<<<<<< HEAD
=======
    let crit = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
>>>>>>> update-research-refs

    println!();
    println!("  {}", "Findings Summary".bold().white());
    print!("  ");
<<<<<<< HEAD
=======
    if crit > 0 {
        print!("{} CRITICAL  ", crit.to_string().magenta().bold());
    }
>>>>>>> update-research-refs
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
<<<<<<< HEAD

        let evidence_color = match &f.evidence_level {
            crate::types::EvidenceLevel::Executed => "executed".green(),
            crate::types::EvidenceLevel::Inferred => "inferred".yellow(),
            crate::types::EvidenceLevel::Inconclusive => "inconclusive".bright_black(),
        };
        println!("      Evidence : {}", evidence_color);

=======

        let status_color = match &f.status {
            crate::types::FindingStatus::Confirmed => "confirmed".green(),
            crate::types::FindingStatus::Possible => "possible".yellow(),
            crate::types::FindingStatus::Inferred => "inferred".bright_black(),
        };
        println!("      Status   : {}", status_color);

>>>>>>> update-research-refs
        for line in wrap(&f.description, 64) {
            println!("      {}", line.bright_white());
        }

        if !f.affected.is_empty() {
            println!("      {}", "Affected:".bright_black());
            print_limited_affected_text(&f.affected, max_affected);
        }

<<<<<<< HEAD
=======
        if let Some(first_step) = &f.first_step {
            println!("      {}", "First Step:".bright_black());
            for line in wrap(first_step, 64) {
                println!("      {}", line.cyan());
            }
        }

>>>>>>> update-research-refs
        println!("      {}", "Remediation:".bright_black());
        for line in wrap(f.remediation, 64) {
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

<<<<<<< HEAD
            if let Some(poc) = &f.poc {
                println!("      {}", "PoC:".bright_black());
=======
            if let Some(poc) = crate::audit::poc::generate_reproduction_steps(f, schema, &meta.source) {
                println!("      {}", "Reproduction (PoC):".bright_black());
>>>>>>> update-research-refs
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

<<<<<<< HEAD
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn write_html_report(
    path: &PathBuf,
    stats: &SchemaStats,
    findings: &[Finding],
    meta: &ReportMeta,
) -> Result<(), String> {
    let mut items = String::new();
    for f in findings {
        let severity_class = match f.severity {
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        };

        let affected = if f.affected.is_empty() {
            "<li>None</li>".to_string()
        } else {
            f.affected
                .iter()
                .map(|a| format!("<li>{}</li>", escape_html(a)))
                .collect::<Vec<_>>()
                .join("")
        };

        let references = f
            .references
            .iter()
            .map(|r| format!("<li>{}</li>", escape_html(r)))
            .collect::<Vec<_>>()
            .join("");

        let query_html = query_reference_for_finding(f)
            .map(|q| {
                format!(
                    "<h4>Executed Query Reference</h4><pre>{}</pre>",
                    escape_html(&q)
                )
            })
            .unwrap_or_default();

        let evidence_label = match &f.evidence_level {
            crate::types::EvidenceLevel::Executed => {
                "<span style=\"color:#72d6c9; font-weight:bold;\">Executed</span>"
            }
            crate::types::EvidenceLevel::Inferred => {
                "<span style=\"color:#ffd166; font-weight:bold;\">Inferred</span>"
            }
            crate::types::EvidenceLevel::Inconclusive => {
                "<span style=\"color:#9ca9bd; font-weight:bold;\">Inconclusive</span>"
            }
        };

        items.push_str(&format!(
            "<article class=\"card {}\"><h3>[{}] {} <span class=\"id\">{} {}</span></h3><p><strong>Evidence:</strong> {}</p><p>{}</p><h4>Affected</h4><ul>{}</ul><h4>Remediation</h4><p>{}</p><h4>References</h4><ul>{}</ul>{}</article>",
            severity_class,
            escape_html(&f.severity.to_string()),
            escape_html(f.title),
            escape_html(f.id),
            escape_html(confidence_label(&f.confidence)),
            evidence_label,
            escape_html(&f.description),
            affected,
            escape_html(f.remediation),
            references,
            query_html,
        ));
    }

    let auth_section = if let Some(auth) = &meta.auth_discovery {
        let protected = auth
            .protected
            .iter()
            .map(|s| format!("<li>{}</li>", escape_html(s)))
            .collect::<Vec<_>>()
            .join("");
        format!(
            "<section class=\"strategy\"><strong>Auth Discovery:</strong> Protected={} Public={} Inconclusive={}{}{} </section>",
            auth.protected.len(),
            auth.public.len(),
            auth.inconclusive.len(),
            if auth.protected.is_empty() { "" } else { "<h4>Protected root fields</h4><ul>" },
            if auth.protected.is_empty() { "".to_string() } else { format!("{} </ul>", protected) }
        )
    } else {
        String::new()
    };

    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\" /><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" /><title>GraphQL Analyzer Report</title><style>:root{{--bg:#0c1118;--panel:#121a24;--text:#e7edf7;--muted:#9ca9bd;--high:#ff6b6b;--med:#ffd166;--low:#72d6c9;--info:#6ea8fe;--accent:#6ea8fe;}}*{{box-sizing:border-box;}}body{{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;color:var(--text);background:radial-gradient(circle at top right,#1a2a3a,var(--bg));}}header{{padding:24px;border-bottom:1px solid #243244;background:rgba(0,0,0,.15);}}h1{{margin:0;font-size:1.5rem;}}.meta{{color:var(--muted);margin-top:8px;}}.grid{{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));margin:20px;}}.stat{{background:var(--panel);padding:14px;border-radius:12px;border:1px solid #243244;}}.cards{{display:grid;gap:14px;margin:20px;}}.card{{background:var(--panel);padding:16px;border-radius:12px;border:1px solid #243244;}}.card.high{{border-left:6px solid var(--high);}}.card.medium{{border-left:6px solid var(--med);}}.card.low{{border-left:6px solid var(--low);}}.card.info{{border-left:6px solid var(--info);}}.id{{color:var(--muted);font-weight:400;font-size:.9rem;}}h3{{margin:0 0 10px;}}h4{{margin:12px 0 8px;color:var(--accent);}}p,li{{line-height:1.45;}}pre{{background:#0b0f15;border:1px solid #1f2b3a;padding:10px;border-radius:8px;overflow:auto;white-space:pre-wrap;}}.strategy{{margin:20px;padding:14px;border:1px dashed #355074;border-radius:12px;color:var(--muted);}}</style></head><body><header><h1>GraphQL Security Analyzer</h1><div class=\"meta\">Source: {} | Mode: {}</div></header><section class=\"strategy\">{}</section>{}<section class=\"grid\"><div class=\"stat\"><strong>Total Types</strong><br />{}</div><div class=\"stat\"><strong>Queries</strong><br />{}</div><div class=\"stat\"><strong>Mutations</strong><br />{}</div><div class=\"stat\"><strong>Subscriptions</strong><br />{}</div><div class=\"stat\"><strong>Total Fields</strong><br />{}</div><div class=\"stat\"><strong>Deprecated</strong><br />{}</div></section><div class=\"cards\">{}</div></body></html>",
        escape_html(&meta.source),
        if meta.offline { "Offline" } else { "Live" },
        if meta.offline {
            "Offline schema analysis only. Findings are potential or highly likely based on static structure."
        } else {
            "Static-first GraphQL analysis with safety guards and optional minimal auth discovery probes."
        },
        auth_section,
        stats.total_types,
        stats.queries,
        stats.mutations,
        stats.subscriptions,
        stats.total_fields,
        stats.deprecated_fields,
        items
    );

    fs::write(path, html).map_err(|e| format!("Failed to write HTML report to {:?}: {}", path, e))
}

=======
>>>>>>> update-research-refs
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
<<<<<<< HEAD

fn markdown_poc_for_finding(f: &Finding) -> Option<String> {
    if f.id != "GQL-013" {
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
    let query_keyword = if root == "Mutation" {
        "mutation"
    } else {
        "query"
    };

    Some(format!(
        "# Probe: IDOR on {}.{}\n{} {{\n  {}({}: \"VICTIM_ID\") {{\n    __typename\n  }}\n}}",
        root, operation, query_keyword, operation, arg
    ))
}
=======
>>>>>>> update-research-refs
