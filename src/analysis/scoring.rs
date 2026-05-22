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
        // If passive analysis found a sensitive field AND auth discovery confirmed it is PUBLIC
        for loc in &f.affected {
            let loc_str = match loc {
                AffectedLocation::Field(t, fi) => format!("{}.{}", t, fi),
                AffectedLocation::Argument(t, fi, _) => format!("{}.{}", t, fi),
                _ => String::new(),
            };

            if !loc_str.is_empty() && public_fields.contains(&loc_str) {
                if f.severity < Severity::High {
                    f.severity = Severity::High;
                    reasons.push(format!("Field '{}' confirmed PUBLIC via auth discovery", loc_str));
                } else if f.severity == Severity::High {
                    f.severity = Severity::Critical;
                    reasons.push(format!("Sensitive field '{}' confirmed PUBLIC — immediate risk", loc_str));
                }
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

            let is_admin_type = ["Admin", "Internal", "Debug", "System", "Config", "Setup"]
                .iter()
                .any(|&a| type_name.to_lowercase().contains(&a.to_lowercase()));

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
