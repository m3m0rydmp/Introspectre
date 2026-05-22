use crate::audit::utils::{
<<<<<<< HEAD
    build_operation_query, effective_headers, find_root_field, parse_candidate, post_graphql,
};
use crate::audit::AuditFinding;
use crate::config::AppConfig;
use crate::types::{Finding, GqlSchema, Severity};
=======
    build_operation_query, effective_headers, find_root_field,
};
use crate::config::AppConfig;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, Severity};
>>>>>>> update-research-refs
use reqwest::Client;
use std::collections::HashMap;

pub async fn probe_ssrf(
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
) -> Result<(), String> {
    let ssrf_finding = passive_findings.iter().find(|f| f.id == "GQL-014");
    let Some(ssrf) = ssrf_finding else {
        return Ok(());
    };

    let headers = effective_headers(
        extra_headers,
        Some(config.session.auth_header.as_str()),
        true,
    );
<<<<<<< HEAD
    let mut confirmed_labels: Vec<String> = Vec::new();
    let mut inconclusive_labels: Vec<String> = Vec::new();

    for candidate in &ssrf.affected {
        let Some((root, field_name, arg_name)) = parse_candidate(candidate) else {
            continue;
        };
=======
    let mut confirmed_locations: Vec<AffectedLocation> = Vec::new();
    let mut inconclusive_locations: Vec<AffectedLocation> = Vec::new();

    for location in &ssrf.affected {
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

        let mut baseline_overrides = HashMap::new();
<<<<<<< HEAD
        baseline_overrides.insert(arg_name.clone(), "\"https://example.com/\"".to_string());
        let baseline_query = build_operation_query(schema, op, field, &baseline_overrides, false);
        let baseline_resp =
            post_graphql(client, url, &headers, &baseline_query, rate_limit_ms).await?;
        let baseline_ms = baseline_resp.elapsed_ms;

        let payloads = [
            "\"http://169.254.169.254/latest/meta-data/\"",
            "\"http://127.0.0.1:80\"",
=======
        baseline_overrides.insert(arg_name.clone(), serde_json::Value::String("https://example.com/".to_string()));
        let gql_op_base = build_operation_query(schema, op, field, &baseline_overrides, &config.audit.seeds, false);
        let baseline_resp =
            crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op_base.query, Some(gql_op_base.variables), rate_limit_ms, evasion_level).await?;
        let baseline_ms = baseline_resp.elapsed_ms;

        let payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:80",
>>>>>>> update-research-refs
        ];

        let mut suspicious = false;
        for payload in payloads {
            let mut overrides = HashMap::new();
<<<<<<< HEAD
            overrides.insert(arg_name.clone(), payload.to_string());
            let query = build_operation_query(schema, op, field, &overrides, false);
            let resp = post_graphql(client, url, &headers, &query, rate_limit_ms).await?;
=======
            overrides.insert(arg_name.clone(), serde_json::Value::String(payload.to_string()));
            let gql_op = build_operation_query(schema, op, field, &overrides, &config.audit.seeds, false);
            let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op.query, Some(gql_op.variables), rate_limit_ms, evasion_level).await?;
>>>>>>> update-research-refs

            let delayed = resp.elapsed_ms > baseline_ms + 1500;
            let aws_keywords = ["meta-data", "instance-id", "ami-id", "security-credentials"]
                .iter()
                .any(|k| resp.raw_text.to_lowercase().contains(k));

            if delayed || aws_keywords {
                suspicious = true;
                break;
            }
        }

        if suspicious {
<<<<<<< HEAD
            confirmed_labels.push(format!("{}.{}({})", root, field_name, arg_name));
        } else {
            inconclusive_labels.push(format!("{}.{}({})", root, field_name, arg_name));
        }
    }

    if !confirmed_labels.is_empty() {
        confirmed.push(AuditFinding {
=======
            confirmed_locations.push(location.clone());
        } else {
            inconclusive_locations.push(location.clone());
        }
    }

    if !confirmed_locations.is_empty() {
        confirmed.push(Finding {
>>>>>>> update-research-refs
            id: "AUD-003",
            severity: Severity::High,
            title: "SSRF Behavior Suspected/Confirmed",
            description: format!(
                "{} operation(s) showed timing/content indicators consistent with SSRF payload handling.",
<<<<<<< HEAD
                confirmed_labels.len()
            ),
            affected: confirmed_labels,
            remediation: "Block internal destinations (loopback, link-local, RFC1918), enforce URL allow-lists, and isolate outbound fetch logic.",
            evidence: "confirmed",
=======
                confirmed_locations.len()
            ),
            affected: confirmed_locations,
            remediation: "Block internal destinations (loopback, link-local, RFC1918), enforce URL allow-lists, and isolate outbound fetch logic.",
            first_step: Some("Provide a URL to a listener you control (like Burp Collaborator) and check if the server makes an outbound request.".into()),
            references: vec!["OWASP API8: Injection", "CWE-918: Server-Side Request Forgery (SSRF)"],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
>>>>>>> update-research-refs
            poc: None,
        });
    }

<<<<<<< HEAD
    if !inconclusive_labels.is_empty() {
        unconfirmed.push(AuditFinding {
=======
    if !inconclusive_locations.is_empty() {
        unconfirmed.push(Finding {
>>>>>>> update-research-refs
            id: "AUD-003",
            severity: Severity::Medium,
            title: "SSRF Probe Inconclusive",
            description: format!(
<<<<<<< HEAD
                "{} SSRF candidate(s) did not show clear SSRF indicators under default payload probes.",
                inconclusive_labels.len()
            ),
            affected: inconclusive_labels,
            remediation: "Try operation-specific payload shaping and monitor egress logs for outbound callbacks.",
            evidence: "inconclusive",
=======
                "{} SSRF possibility(s) did not show clear SSRF indicators under default payload probes.",
                inconclusive_locations.len()
            ),
            affected: inconclusive_locations,
            remediation: "Try operation-specific payload shaping and monitor egress logs for outbound callbacks.",
            first_step: Some("Manually test different protocols (like gopher:// or file://) if the server doesn't respond to HTTP payloads.".into()),
            references: vec!["OWASP API8: Injection"],
            status: FindingStatus::Possible,
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inconclusive,
>>>>>>> update-research-refs
            poc: None,
        });
    }

    Ok(())
}
