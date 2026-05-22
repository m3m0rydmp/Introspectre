<<<<<<< HEAD
use crate::audit::utils::{effective_headers, post_graphql};
use crate::audit::AuditFinding;
use crate::types::Severity;
=======
use crate::audit::utils::{effective_headers, post_graphql_ext};
use crate::types::{AffectedLocation, Finding, FindingStatus, Confidence, EvidenceLevel, Severity};
>>>>>>> update-research-refs
use reqwest::Client;

pub async fn probe_complexity(
    client: &Client,
    url: &str,
    extra_headers: &[String],
    rate_limit_ms: u64,
<<<<<<< HEAD
    confirmed: &mut Vec<AuditFinding>,
    unconfirmed: &mut Vec<AuditFinding>,
) -> Result<(), String> {
    let query = "query { a: __typename, b: __typename, c: __typename }";
    let resp = post_graphql(
        client,
        url,
        &effective_headers(extra_headers, None, false),
        query,
        rate_limit_ms,
=======
    evasion_level: u8,
    confirmed: &mut Vec<Finding>,
    unconfirmed: &mut Vec<Finding>,
) -> Result<(), String> {
    let query = "query { a: __typename, b: __typename, c: __typename }";
    let resp = post_graphql_ext(
        client,
        url,
        &effective_headers(extra_headers, None, false),
        &query,
        None,
        rate_limit_ms,
        evasion_level,
>>>>>>> update-research-refs
    )
    .await?;

    let mut complexity_detected = false;
    let mut details = String::new();

    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&resp.raw_text) {
        if let Some(extensions) = data.get("extensions") {
            if extensions.get("complexity").is_some()
                || extensions.get("cost").is_some()
                || extensions.get("depth").is_some()
            {
                complexity_detected = true;
                details = "Found complexity/cost info in extensions.".to_string();
            }
        }
    }

    if complexity_detected {
<<<<<<< HEAD
        confirmed.push(AuditFinding {
=======
        confirmed.push(Finding {
>>>>>>> update-research-refs
            id: "AUD-006",
            severity: Severity::Low,
            title: "Query Complexity/Cost Info Exposed",
            description: format!("The server returns query complexity or cost information in the 'extensions' field. {}", details),
<<<<<<< HEAD
            affected: vec![url.to_string()],
            remediation: "Ensure that complexity information does not reveal sensitive internal limit details to unauthenticated users.",
            evidence: "confirmed",
            poc: Some(query.to_string()),
        });
    } else {
        unconfirmed.push(AuditFinding {
=======
            affected: vec![AffectedLocation::Type("Query".into())],
            remediation: "Ensure that complexity information does not reveal sensitive internal limit details to unauthenticated users.",
            first_step: Some("Review the 'extensions' field in the GraphQL response for 'complexity', 'cost', or 'depth' keys.".into()),
            references: vec!["CWE-200"],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
            poc: Some(query.to_string()),
        });
    } else {
        unconfirmed.push(Finding {
>>>>>>> update-research-refs
            id: "AUD-006",
            severity: Severity::Low,
            title: "Complexity Probe Inconclusive",
            description: "No complexity or cost information was detected in the response extensions.".to_string(),
<<<<<<< HEAD
            affected: vec![url.to_string()],
            remediation: "Confirm if complexity limiting is implemented by manually testing deeply nested queries.",
            evidence: "inconclusive",
=======
            affected: vec![AffectedLocation::Type("Query".into())],
            remediation: "Confirm if complexity limiting is implemented by manually testing deeply nested queries.",
            first_step: Some("Manually test deeply nested or complex queries to see if the server enforces any limits.".into()),
            references: vec!["CWE-200"],
            status: FindingStatus::Possible,
            confidence: Confidence::Possible,
            evidence_level: EvidenceLevel::Inconclusive,
>>>>>>> update-research-refs
            poc: None,
        });
    }

    Ok(())
}
