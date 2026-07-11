use crate::types::{AffectedLocation, Finding, FindingStatus, ReportMeta, Severity};

pub fn apply_heuristics(findings: &mut Vec<Finding>, meta: &ReportMeta) {
    let mut escalations = Vec::new();

    // 1. Identify "Public" fields from auth discovery
    let public_fields: Vec<String> = if let Some(auth) = &meta.auth_discovery {
        auth.public.clone()
    } else {
        Vec::new()
    };

    for f in findings.iter_mut() {
        let old_severity = f.severity.clone();
        let mut reasons = Vec::new();

        // Rule A: Confirmed High-Impact Findings -> CRITICAL
        // If an active probe confirmed a High severity issue (like IDOR or SSRF on sensitive fields)
        if f.status == FindingStatus::Confirmed && f.severity == Severity::High {
            let is_very_sensitive = f.description.to_lowercase().contains("sensitive") 
                || f.description.to_lowercase().contains("credential")
                || f.description.to_lowercase().contains("token");
            
            if is_very_sensitive {
                f.severity = Severity::Critical;
                reasons.push("Confirmed active exploit on sensitive data path".to_string());
            }
        }

        // Rule B: Public Exposure of Sensitive Paths -> Escalate
        // If passive analysis found a sensitive field AND auth discovery confirmed it is PUBLIC.
        // Evaluated ONCE per finding (presence-based), not per affected location, so a finding
        // with multiple public locations only bumps a single severity level.
        let any_public = f.affected.iter().any(|loc| {
            let loc_str = match loc {
                AffectedLocation::Field(t, fi) => format!("{}.{}", t, fi),
                AffectedLocation::Argument(t, fi, _) => format!("{}.{}", t, fi),
                _ => String::new(),
            };
            !loc_str.is_empty() && public_fields.contains(&loc_str)
        });

        if any_public {
            if f.severity < Severity::High {
                f.severity = Severity::High;
                reasons.push("Field confirmed PUBLIC via auth discovery".to_string());
            } else if f.severity == Severity::High {
                f.severity = Severity::Critical;
                reasons.push("Sensitive field confirmed PUBLIC — immediate risk, sensitive public path".to_string());
            }
        }

        // Rule C: Administrative Type Correlation
        // If a finding affects a type that looks like an internal/admin type
        for loc in &f.affected {
            let type_name = match loc {
                AffectedLocation::Type(t) => t,
                AffectedLocation::Field(t, _) => t,
                AffectedLocation::Argument(t, _, _) => t,
            };

            // Word-segment match so "Config" does not fire on "ConfigurationOption".
            let admin_words = ["admin", "internal", "debug", "system", "config", "setup"];
            let name_tokens = crate::utils::tokenize_identifier(type_name);
            let is_admin_type = name_tokens
                .iter()
                .any(|t| admin_words.contains(&t.as_str()));

            if is_admin_type && f.severity < Severity::High {
                f.severity = Severity::High;
                reasons.push(format!("Finding affects administrative type '{}'", type_name));
            }
        }

        if f.severity != old_severity {
            let reason_summary = reasons.join("; ");
            escalations.push(format!("[{}] {} -> {} ({})", f.id, old_severity, f.severity, reason_summary));
            f.description = format!("{} [Escalated: {}]", f.description, reason_summary);
        }
    }
}
