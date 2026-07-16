use crate::audit::utils::{effective_headers, post_graphql_ext};
use crate::transport::Transport;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, Severity};
use reqwest::Client;
use serde_json::Value;

pub async fn probe_typename(
    client: &Client,
    url: &str,
    extra_headers: &[String],
    rate_limit_ms: u64,
    evasion_level: u8,
    transport: Transport,
    confirmed: &mut Vec<Finding>,
    unconfirmed: &mut Vec<Finding>,
) -> Result<(), String> {
    let typename_resp = post_graphql_ext(
        client,
        url,
        &effective_headers(extra_headers, None, false),
        "query { __typename }",
        None,
        rate_limit_ms,
        evasion_level,
        transport,
        false,
    )

    .await?;

    if extract_typename(&typename_resp.data).as_deref() == Some("Query") {
        confirmed.push(Finding {
            id: "graphql-confirmed",
            severity: Severity::Low,
            title: "GraphQL Confirmed via __typename Probe",
            description: "Endpoint responded with data.__typename=Query without introspection query usage. This confirms GraphQL behavior even if introspection is disabled.".to_string(),
            affected: vec![AffectedLocation::Type("Endpoint".into())],
            remediation: "Restrict endpoint exposure and require authorization where appropriate. Keep introspection disabled in production unless explicitly needed.",
            first_step: Some(format!("Send a manual POST request to {} with the body {{\"query\": \"{{ __typename }}\"}} to confirm the endpoint type.", url)),
            references: vec!["CWE-200: Information Exposure"],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
            poc: None,
        });
    } else {
        unconfirmed.push(Finding {
            id: "graphql-confirmed",
            severity: Severity::Low,
            title: "GraphQL __typename Probe Inconclusive",
            description: format!(
                "Endpoint did not return data.__typename=Query (HTTP {}). GraphQL may still be present behind auth or non-standard routing.",
                typename_resp.status
            ),
            affected: vec![AffectedLocation::Type("Endpoint".into())],
            remediation: "Validate endpoint path, auth requirements, and gateway routing before deeper active probes.",
            first_step: Some("Check if the endpoint requires a specific path (e.g., /graphql, /api/graphql) or an authentication token.".into()),
            references: vec!["CWE-200: Information Exposure"],
            status: FindingStatus::Possible,
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inconclusive,
            poc: None,
        });
    }
    Ok(())
}

fn extract_typename(data: &Option<Value>) -> Option<String> {
    data.as_ref()
        .and_then(|d| d.get("__typename"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}
