use colored::Colorize;
use crate::audit::utils::{
    build_operation_query, effective_headers, find_root_field,
};
use crate::config::AppConfig;
use crate::transport::Transport;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, Severity};
use reqwest::Client;
use std::collections::HashMap;

pub async fn probe_ssrf(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    evasion_level: u8,
    config: &AppConfig,
    passive_findings: &[Finding],
    transport: Transport,
    confirmed: &mut Vec<Finding>,
    unconfirmed: &mut Vec<Finding>,
) -> Result<(), String> {
    let ssrf_finding = passive_findings.iter().find(|f| f.id == "ssrf-surface");
    let Some(ssrf) = ssrf_finding else {
        return Ok(());
    };

    let headers = effective_headers(
        extra_headers,
        Some(config.session.auth_header.as_str()),
        true,
    );
    let mut confirmed_locations: Vec<AffectedLocation> = Vec::new();
    let mut inconclusive_locations: Vec<AffectedLocation> = Vec::new();

    for location in &ssrf.affected {
        let (root, field_name, arg_name) = match location {
            AffectedLocation::Argument(r, f, a) => (r, f, a),
            _ => continue,
        };

        let Some(field) = find_root_field(schema, root.as_str(), field_name.as_str()) else {
            continue;
        };
        let op = if root == "Mutation" {
            "mutation"
        } else {
            "query"
        };
        let is_mutation = op == "mutation";

        eprintln!("  {} Testing SSRF Injection on {}.{}({})...", "→".cyan(), root, field_name, arg_name);

        let mut baseline_overrides = HashMap::new();
        baseline_overrides.insert(arg_name.clone(), serde_json::Value::String("https://example.com/".to_string()));
        let gql_op_base = build_operation_query(schema, op, field, &baseline_overrides, &config.audit.seeds, false);
        let baseline_resp =
            crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op_base.query, Some(gql_op_base.variables), rate_limit_ms, evasion_level, transport, is_mutation).await?;
        let baseline_ms = baseline_resp.elapsed_ms;

        let payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:80",
        ];

        let mut suspicious = false;
        for payload in payloads {
            let mut overrides = HashMap::new();
            overrides.insert(arg_name.clone(), serde_json::Value::String(payload.to_string()));
            let gql_op = build_operation_query(schema, op, field, &overrides, &config.audit.seeds, false);
            let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op.query, Some(gql_op.variables), rate_limit_ms, evasion_level, transport, is_mutation).await?;

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
            confirmed_locations.push(location.clone());
        } else {
            inconclusive_locations.push(location.clone());
        }
    }

    if !confirmed_locations.is_empty() {
        confirmed.push(Finding {
            id: "ssrf",
            severity: Severity::High,
            title: "SSRF Behavior Suspected/Confirmed",
            description: format!(
                "{} operation(s) showed timing/content indicators consistent with SSRF payload handling.",
                confirmed_locations.len()
            ),
            affected: confirmed_locations,
            remediation: "Block internal destinations (loopback, link-local, RFC1918), enforce URL allow-lists, and isolate outbound fetch logic.",
            first_step: Some("Provide a URL to a listener you control (like Burp Collaborator) and check if the server makes an outbound request.".into()),
            references: vec!["OWASP API8: Injection", "CWE-918: Server-Side Request Forgery (SSRF)"],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
            poc: None,
        });
    }

    if !inconclusive_locations.is_empty() {
        unconfirmed.push(Finding {
            id: "ssrf",
            severity: Severity::Medium,
            title: "SSRF Probe Inconclusive",
            description: format!(
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
            poc: None,
        });
    }

    Ok(())
}
