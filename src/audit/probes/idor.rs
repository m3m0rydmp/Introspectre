use crate::audit::utils::{
    build_operation_query, effective_headers, field_non_null_data, find_root_field,
<<<<<<< HEAD
    parse_candidate, post_graphql,
};
use crate::audit::AuditFinding;
use crate::config::AppConfig;
use crate::types::{Finding, GqlSchema, Severity};
=======
};
use crate::config::AppConfig;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, Severity};
>>>>>>> update-research-refs
use reqwest::Client;
use std::collections::HashMap;

pub async fn probe_idor(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
<<<<<<< HEAD
    config: &AppConfig,
    passive_findings: &[Finding],
    confirmed: &mut Vec<AuditFinding>,
    unconfirmed: &mut Vec<AuditFinding>,
=======
    evasion_level: u8,
    config: &AppConfig,
    passive_findings: &[Finding],
    confirmed: &mut Vec<Finding>,
    unconfirmed: &mut Vec<Finding>,
>>>>>>> update-research-refs
    idor_payloads: &[String],
) -> Result<(), String> {
    let idor_finding = passive_findings.iter().find(|f| f.id == "GQL-013");
    let Some(idor) = idor_finding else {
        return Ok(());
    };

    if config.session.auth_header.trim().is_empty() || config.session.owned_ids.is_empty() {
<<<<<<< HEAD
        unconfirmed.push(AuditFinding {
=======
        unconfirmed.push(Finding {
>>>>>>> update-research-refs
            id: "AUD-002",
            severity: Severity::Medium,
            title: "IDOR Probe Skipped (Missing Session Config)",
            description: "IDOR probing requires session.auth_header and at least one session.owned_ids value in config.".to_string(),
<<<<<<< HEAD
            affected: vec!["session.auth_header / session.owned_ids".to_string()],
            remediation: "Provide a valid authenticated header and owned IDs in config before running audit with test_idor enabled.",
            evidence: "inconclusive",
=======
            affected: vec![AffectedLocation::Type("Session Configuration".into())],
            remediation: "Provide a valid authenticated header and owned IDs in config before running audit with test_idor enabled.",
            first_step: Some("Update your config.toml with a valid 'session.auth_header' and 'session.owned_ids'.".into()),
            references: vec!["OWASP API1: Broken Object Level Authorization"],
            status: FindingStatus::Possible,
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inconclusive,
>>>>>>> update-research-refs
            poc: None,
        });
        return Ok(());
    }

    let headers = effective_headers(
        extra_headers,
        Some(config.session.auth_header.as_str()),
        true,
    );
<<<<<<< HEAD
    let mut confirmed_labels: Vec<String> = Vec::new();
    let mut inconclusive_labels: Vec<String> = Vec::new();

    for candidate in &idor.affected {
        let Some((root, field_name, arg_name)) = parse_candidate(candidate) else {
            continue;
        };
=======
    let mut confirmed_locations: Vec<AffectedLocation> = Vec::new();
    let mut inconclusive_locations: Vec<AffectedLocation> = Vec::new();

    for location in &idor.affected {
        let (root, field_name, arg_name) = match location {
            AffectedLocation::Argument(r, f, a) => (r, f, a),
            _ => continue,
        };

>>>>>>> update-research-refs
        let Some(field) = find_root_field(schema, root.as_str(), field_name.as_str()) else {
            continue;
        };

        let op = if root == "Mutation" {
            "mutation"
        } else {
            "query"
        };

        let mut baseline_payload: Option<String> = None;
        for owned in &config.session.owned_ids {
            let mut overrides = HashMap::new();
<<<<<<< HEAD
            overrides.insert(arg_name.clone(), format!("\"{}\"", owned));
            let query = build_operation_query(schema, op, field, &overrides, true);
            let resp = post_graphql(client, url, &headers, &query, rate_limit_ms).await?;
=======
            overrides.insert(arg_name.clone(), serde_json::Value::String(owned.clone()));
            let gql_op = build_operation_query(schema, op, field, &overrides, &config.audit.seeds, true);
            let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op.query, Some(gql_op.variables), rate_limit_ms, evasion_level).await?;
>>>>>>> update-research-refs
            if let Some(data) = field_non_null_data(&resp.data, &field.name) {
                baseline_payload = Some(data.to_string());
                break;
            }
        }

        let Some(baseline) = baseline_payload else {
<<<<<<< HEAD
            inconclusive_labels.push(format!("{}.{}({})", root, field_name, arg_name));
=======
            inconclusive_locations.push(location.clone());
>>>>>>> update-research-refs
            continue;
        };

        let mutated_values = if !idor_payloads.is_empty() {
<<<<<<< HEAD
            idor_payloads.iter().map(|s| format!("\"{}\"", s)).collect()
        } else {
            vec![
                "\"1\"".to_string(),
                "\"2\"".to_string(),
                "\"3\"".to_string(),
            ]
        };

        let mut candidate_confirmed = false;
        for mutated in mutated_values {
            let mut overrides = HashMap::new();
            overrides.insert(arg_name.clone(), mutated);
            let query = build_operation_query(schema, op, field, &overrides, true);
            let resp = post_graphql(client, url, &headers, &query, rate_limit_ms).await?;
=======
            idor_payloads.iter().map(|s| serde_json::Value::String(s.clone())).collect()
        } else {
            vec![
                serde_json::Value::String("1".to_string()),
                serde_json::Value::String("2".to_string()),
                serde_json::Value::String("3".to_string()),
            ]
        };

        let mut possibility_confirmed = false;
        for mutated in mutated_values {
            let mut overrides = HashMap::new();
            overrides.insert(arg_name.clone(), mutated);
            let gql_op = build_operation_query(schema, op, field, &overrides, &config.audit.seeds, true);
            let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op.query, Some(gql_op.variables), rate_limit_ms, evasion_level).await?;
>>>>>>> update-research-refs

            if let Some(data) = field_non_null_data(&resp.data, &field.name) {
                let payload = data.to_string();
                if payload != baseline {
<<<<<<< HEAD
                    confirmed_labels.push(format!("{}.{}({})", root, field_name, arg_name));
                    candidate_confirmed = true;
=======
                    confirmed_locations.push(location.clone());
                    possibility_confirmed = true;
>>>>>>> update-research-refs
                    break;
                }
            }
        }

<<<<<<< HEAD
        if !candidate_confirmed {
            inconclusive_labels.push(format!("{}.{}({})", root, field_name, arg_name));
        }
    }

    if !confirmed_labels.is_empty() {
        let poc = confirmed_labels
            .first()
            .and_then(|label| parse_candidate(label))
            .map(|(root, field_name, arg_name)| {
=======
        if !possibility_confirmed {
            inconclusive_locations.push(location.clone());
        }
    }

    if !confirmed_locations.is_empty() {
        let poc = confirmed_locations
            .first()
            .map(|loc| {
                let (root, field_name) = match loc {
                    AffectedLocation::Argument(r, f, _) => (r.as_str(), f.as_str()),
                    _ => ("Query", "field"),
                };
                let arg_name = match loc {
                    AffectedLocation::Argument(_, _, a) => a.as_str(),
                    _ => "id",
                };
>>>>>>> update-research-refs
                let keyword = if root == "Mutation" { "mutation" } else { "query" };
                format!(
                    "# IDOR confirmed: {}.{}\n{} {{\n  {}({}: \"VICTIM_ID\") {{\n    id\n    __typename\n  }}\n}}",
                    root, field_name, keyword, field_name, arg_name
                )
            });

<<<<<<< HEAD
        confirmed.push(AuditFinding {
=======
        confirmed.push(Finding {
>>>>>>> update-research-refs
            id: "AUD-002",
            severity: Severity::High,
            title: "IDOR Behavior Confirmed",
            description: format!(
                "{} ID-based operation(s) returned differing data for mutated identifiers using an authenticated session.",
<<<<<<< HEAD
                confirmed_labels.len()
            ),
            affected: confirmed_labels,
            remediation: "Enforce object-level authorization checks by ownership on every ID-based resolver path.",
            evidence: "confirmed",
=======
                confirmed_locations.len()
            ),
            affected: confirmed_locations,
            remediation: "Enforce object-level authorization checks by ownership on every ID-based resolver path.",
            first_step: Some("Manually attempt to query a resource using an ID that does not belong to your account and verify if it returns sensitive data.".into()),
            references: vec!["OWASP API1: Broken Object Level Authorization", "CWE-639: Authorization Bypass Through User-Controlled Key"],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
>>>>>>> update-research-refs
            poc,
        });
    }

<<<<<<< HEAD
    if !inconclusive_labels.is_empty() {
        unconfirmed.push(AuditFinding {
=======
    if !inconclusive_locations.is_empty() {
        unconfirmed.push(Finding {
>>>>>>> update-research-refs
            id: "AUD-002",
            severity: Severity::Medium,
            title: "IDOR Probe Inconclusive",
            description: format!(
<<<<<<< HEAD
                "{} IDOR candidate(s) could not be confirmed with current owned IDs and default mutation set.",
                inconclusive_labels.len()
            ),
            affected: inconclusive_labels,
            remediation: "Expand candidate IDs and include operation-specific payloads to increase probe coverage.",
            evidence: "inconclusive",
=======
                "{} IDOR possibility(s) could not be confirmed with current owned IDs and default mutation set.",
                inconclusive_locations.len()
            ),
            affected: inconclusive_locations,
            remediation: "Expand possibility IDs and include operation-specific payloads to increase probe coverage.",
            first_step: Some("Provide additional 'idor_payloads' or 'owned_ids' in your config to improve probe precision.".into()),
            references: vec!["OWASP API1: Broken Object Level Authorization"],
            status: FindingStatus::Possible,
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inconclusive,
>>>>>>> update-research-refs
            poc: None,
        });
    }

    Ok(())
}
