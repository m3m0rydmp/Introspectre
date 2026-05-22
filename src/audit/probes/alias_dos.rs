<<<<<<< HEAD
use crate::audit::utils::{effective_headers, post_graphql};
use crate::audit::AuditFinding;
use crate::types::{GqlSchema, Severity};
use reqwest::Client;
=======
use crate::audit::utils::{build_field_call, effective_headers, find_best_probe_target, post_graphql_ext};
use crate::types::{AffectedLocation, Finding, FindingStatus, Confidence, EvidenceLevel, Severity, GqlSchema};
use reqwest::Client;
use std::collections::HashMap;
>>>>>>> update-research-refs

pub async fn probe_alias_dos(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
<<<<<<< HEAD
    confirmed: &mut Vec<AuditFinding>,
    unconfirmed: &mut Vec<AuditFinding>,
) -> Result<(), String> {
    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let binding = schema.fields_for_type(query_name);
    let Some(first_field) = binding.first() else {
        return Ok(());
    };

    // Build a query with 100 aliases of the same field
    let mut alias_parts = Vec::new();
    for i in 0..100 {
        alias_parts.push(format!("a{}: {}", i, first_field.name));
    }
    let query = format!("query {{ {} }}", alias_parts.join(", "));

    let resp = post_graphql(
=======
    evasion_level: u8,
    seed_map: &HashMap<String, String>,
    confirmed: &mut Vec<Finding>,
    unconfirmed: &mut Vec<Finding>,
) -> Result<(), String> {
    let Some(target_field) = find_best_probe_target(schema) else {
        return Ok(());
    };

    // Build a valid field call fragment (including arguments and sub-selections)
    let field_fragment = build_field_call(
        schema,
        target_field,
        &HashMap::new(),
        seed_map,
        false,
    );

    // Build a query with 100 aliases of the same field
    let mut alias_parts = Vec::new();
    for i in 0..100 {
        alias_parts.push(format!("a{}: {}", i, field_fragment));
    }
    let query = format!("query {{ {} }}", alias_parts.join(", "));

    let resp = post_graphql_ext(
>>>>>>> update-research-refs
        client,
        url,
        &effective_headers(extra_headers, None, false),
        &query,
<<<<<<< HEAD
        rate_limit_ms,
=======
        None,
        rate_limit_ms,
        evasion_level,
>>>>>>> update-research-refs
    )
    .await?;

    if resp.status == 200 && resp.data.is_some() {
<<<<<<< HEAD
        confirmed.push(AuditFinding {
            id: "AUD-008",
            severity: Severity::Medium,
            title: "Alias-Based DoS Possible",
            description: "The server accepted and executed a query with 100 aliases. Large numbers of aliases can be used to exhaust server resources by triggering many resolver executions in a single request.".to_string(),
            affected: vec![url.to_string()],
            remediation: "Implement a limit on the maximum number of aliases allowed in a single GraphQL operation.",
            evidence: "confirmed",
            poc: Some(format!("query {{ a1: {0}, a2: {0}, ... a100: {0} }}", first_field.name)),
        });
    } else if resp.status == 400 || !resp.errors_text.is_empty() {
        unconfirmed.push(AuditFinding {
            id: "AUD-008",
            severity: Severity::Low,
            title: "Alias-Based DoS Limited / Inconclusive",
            description: format!("The server rejected or returned errors for a 100-alias query (HTTP {}). This suggests some level of alias or complexity limiting is in place.", resp.status),
            affected: vec![url.to_string()],
            remediation: "Verify the specific alias or complexity limits and ensure they are appropriately restrictive.",
            evidence: "inconclusive",
            poc: None,
=======
        confirmed.push(Finding {
            id: "AUD-008",
            severity: Severity::Medium,
            title: "Alias-Based DoS Possible",
            description: format!("The server accepted and executed a query with 100 aliases of the field '{}'. Large numbers of aliases can be used to exhaust server resources by triggering many resolver executions in a single request.", target_field.name),
            affected: vec![AffectedLocation::Field("Query".into(), target_field.name.clone())],
            remediation: "Implement a limit on the maximum number of aliases allowed in a single GraphQL operation.",
            first_step: Some("Manually execute the provided PoC query and observe the response time and server resource usage.".into()),
            references: vec!["CWE-770", "OWASP-A04"],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
            poc: Some(format!("query {{ a1: {0}, a2: {0}, ... a100: {0} }}", field_fragment)),
        });
    } else if resp.status == 400 || !resp.errors_text.is_empty() {
        let is_validation = resp.errors_text.to_lowercase().contains("validation")
            || resp.errors_text.to_lowercase().contains("syntax")
            || resp.errors_text.to_lowercase().contains("required");

        let (title, status, confidence, evidence_level, description) = if is_validation {
            (
                "Alias-Based DoS Inconclusive (Syntax Error)",
                FindingStatus::Possible,
                Confidence::Possible,
                EvidenceLevel::Inconclusive,
                format!("The server rejected the 100-alias query with a validation/syntax error (HTTP {}). This suggests the generated payload was semantically invalid for the target field '{}', and the server's alias limits were not actually tested.", resp.status, target_field.name),
            )
        } else {
            (
                "Alias-Based DoS Limited / Protected",
                FindingStatus::Possible,
                Confidence::Theoretical,
                EvidenceLevel::Inferred,
                format!("The server rejected the 100-alias query (HTTP {}). This suggests some level of alias or complexity limiting is in place.", resp.status),
            )
        };

        unconfirmed.push(Finding {
            id: "AUD-008",
            severity: Severity::Low,
            title,
            description,
            affected: vec![AffectedLocation::Field("Query".into(), target_field.name.clone())],
            remediation: "Verify the specific alias or complexity limits and ensure they are appropriately restrictive.",
            first_step: Some("Test with a smaller number of aliases (e.g., 10, 20) to determine the exact threshold.".into()),
            references: vec!["CWE-770"],
            status,
            confidence,
            evidence_level,
            poc: Some(query),
>>>>>>> update-research-refs
        });
    }

    Ok(())
}
