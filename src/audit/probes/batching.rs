<<<<<<< HEAD
use crate::audit::utils::effective_headers;
use crate::audit::AuditFinding;
use crate::types::Severity;
use reqwest::Client;
use std::time::Duration;
=======
use crate::audit::utils::{effective_headers, post_batched_graphql_ext, GqlOperation};
use crate::types::{AffectedLocation, Finding, FindingStatus, Confidence, EvidenceLevel, Severity};
use reqwest::Client;
>>>>>>> update-research-refs

pub async fn probe_batching(
    client: &Client,
    url: &str,
    extra_headers: &[String],
    rate_limit_ms: u64,
<<<<<<< HEAD
    confirmed: &mut Vec<AuditFinding>,
    unconfirmed: &mut Vec<AuditFinding>,
) -> Result<(), String> {
    if rate_limit_ms > 0 {
        tokio::time::sleep(Duration::from_millis(rate_limit_ms)).await;
    }

    let headers = effective_headers(extra_headers, None, false);
    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "Introspectre/1.0 (Active-Audit-Probe)");

    for (k, v) in headers {
        req = req.header(k, v);
    }

    let body = serde_json::json!([
        { "query": "{ __typename }" },
        { "query": "{ __typename }" }
    ]);

    let resp = req.json(&body).send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let raw_text = resp.text().await.unwrap_or_default();

    let is_batched = if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw_text) {
        parsed.is_array() && parsed.as_array().unwrap().len() == 2
    } else {
        false
    };

    if is_batched {
        confirmed.push(AuditFinding {
=======
    evasion_level: u8,
    confirmed: &mut Vec<Finding>,
    unconfirmed: &mut Vec<Finding>,
) -> Result<(), String> {
    let headers = effective_headers(extra_headers, None, false);
    let ops = vec![
        GqlOperation { query: "{ __typename }".to_string(), variables: serde_json::json!({}) },
        GqlOperation { query: "{ __typename }".to_string(), variables: serde_json::json!({}) },
    ];

    let responses = post_batched_graphql_ext(
        client,
        url,
        &headers,
        &ops,
        rate_limit_ms,
        evasion_level,
    )
    .await?;

    let is_batched = responses.len() == 2;
    let status = responses.first().map(|r| r.status).unwrap_or(0);

    if is_batched {
        confirmed.push(Finding {
>>>>>>> update-research-refs
            id: "AUD-007",
            severity: Severity::Medium,
            title: "Query Batching Enabled",
            description: "The GraphQL endpoint accepts an array of queries in a single HTTP request (array-based batching). This can be abused for brute-force or volumetric DoS attacks.".to_string(),
<<<<<<< HEAD
            affected: vec![url.to_string()],
            remediation: "Disable array-based query batching if not required by your frontend clients, or enforce strict rate limits and complexity budgets per HTTP request.",
            evidence: "confirmed",
            poc: Some("[\n  {\"query\": \"{ __typename }\"},\n  {\"query\": \"{ __typename }\"}\n]".to_string()),
        });
    } else {
        unconfirmed.push(AuditFinding {
=======
            affected: vec![AffectedLocation::Type("Query".into())],
            remediation: "Disable array-based query batching if not required by your frontend clients, or enforce strict rate limits and complexity budgets per HTTP request.",
            first_step: Some("Send a JSON array containing two simple queries to the endpoint and check if the response is also a JSON array.".into()),
            references: vec!["CWE-770", "OWASP-A04"],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
            poc: Some("[\n  {\"query\": \"{ __typename }\"},\n  {\"query\": \"{ __typename }\"}\n]".to_string()),
        });
    } else {
        unconfirmed.push(Finding {
>>>>>>> update-research-refs
            id: "AUD-007",
            severity: Severity::Low,
            title: "Query Batching Disabled / Inconclusive",
            description: format!("The server did not respond with an array of results to a batched query array (HTTP {}).", status),
<<<<<<< HEAD
            affected: vec![url.to_string()],
            remediation: "Ensure that other forms of batching (e.g., query aliasing) are also restricted or monitored.",
            evidence: "inconclusive",
=======
            affected: vec![AffectedLocation::Type("Query".into())],
            remediation: "Ensure that other forms of batching (e.g., query aliasing) are also restricted or monitored.",
            first_step: Some("Confirm if the endpoint expects a different batching format or if batching is intentionally disabled.".into()),
            references: vec!["CWE-770"],
            status: FindingStatus::Possible,
            confidence: Confidence::Possible,
            evidence_level: EvidenceLevel::Inconclusive,
>>>>>>> update-research-refs
            poc: None,
        });
    }

    Ok(())
}
