use crate::audit::utils::{
<<<<<<< HEAD
    effective_headers, extract_verbose_error_hint, post_graphql, typo_variant,
};
use crate::audit::AuditFinding;
use crate::types::{GqlSchema, Severity};
=======
    effective_headers, extract_verbose_error_hint, post_graphql_ext, typo_variant,
};
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, Severity};
>>>>>>> update-research-refs
use reqwest::Client;

pub async fn probe_verbose_error_disclosure(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
<<<<<<< HEAD
    _batch_probes: bool,
    _batch_size: u32,
    confirmed: &mut Vec<AuditFinding>,
    unconfirmed: &mut Vec<AuditFinding>,
=======
    evasion_level: u8,
    _batch_probes: bool,
    _batch_size: u32,
    confirmed: &mut Vec<Finding>,
    unconfirmed: &mut Vec<Finding>,
>>>>>>> update-research-refs
) -> Result<(), String> {
    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let binding = schema.fields_for_type(query_name);
    let Some(first_field) = binding.first() else {
        return Ok(());
    };

    let typo = typo_variant(&first_field.name);
    let typo = if typo == first_field.name {
        format!("{}_typo", first_field.name)
    } else {
        typo
    };

    let query = format!("query {{ {} }}", typo);
<<<<<<< HEAD
    let resp = post_graphql(
=======
    let resp = post_graphql_ext(
>>>>>>> update-research-refs
        client,
        url,
        &effective_headers(extra_headers, None, false),
        &query,
<<<<<<< HEAD
        rate_limit_ms,
    )
=======
        None,
        rate_limit_ms,
        evasion_level,
    )

>>>>>>> update-research-refs
    .await?;

    let hint_source = if resp.errors_text.is_empty() {
        &resp.raw_text
    } else {
        &resp.errors_text
    };

    if let Some(hint) = extract_verbose_error_hint(hint_source) {
<<<<<<< HEAD
        confirmed.push(AuditFinding {
=======
        confirmed.push(Finding {
>>>>>>> update-research-refs
            id: "AUD-005",
            severity: Severity::Low,
            title: "Verbose GraphQL Error Disclosure",
            description: "Endpoint returned field/argument suggestions (for example 'Did you mean ...') for invalid queries, which can aid schema enumeration.".to_string(),
<<<<<<< HEAD
            affected: vec![format!("Query.{} -> {}", typo, hint)],
            remediation: "Use generic production validation errors and disable suggestion hints outside development environments.",
            evidence: "confirmed",
            poc: None,
        });
    } else {
        unconfirmed.push(AuditFinding {
=======
            affected: vec![AffectedLocation::Field("Query".into(), typo)],
            remediation: "Use generic production validation errors and disable suggestion hints outside development environments.",
            first_step: Some(format!("Execute an invalid query like '{}' and check if the 'errors' array contains suggestions.", query)),
            references: vec!["CWE-200: Information Exposure"],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
            poc: Some(hint),
        });
    } else {
        unconfirmed.push(Finding {
>>>>>>> update-research-refs
            id: "AUD-005",
            severity: Severity::Low,
            title: "Verbose GraphQL Error Disclosure Probe Inconclusive",
            description: "No suggestion-style verbose validation hint was observed for the typo probe. The server may already sanitize errors or require different malformed payloads.".to_string(),
<<<<<<< HEAD
            affected: vec![format!("query {{ {} }}", typo)],
            remediation: "Confirm production error policy by testing multiple malformed field and argument variants across query and mutation roots.",
            evidence: "inconclusive",
=======
            affected: vec![AffectedLocation::Field("Query".into(), typo)],
            remediation: "Confirm production error policy by testing multiple malformed field and argument variants across query and mutation roots.",
            first_step: Some("Manually test different malformed queries (e.g., wrong argument types) to see if the server ever leaks schema hints.".into()),
            references: vec!["CWE-200: Information Exposure"],
            status: FindingStatus::Possible,
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inconclusive,
>>>>>>> update-research-refs
            poc: None,
        });
    }

    Ok(())
}
