use crate::audit::utils::{effective_headers, post_graphql_ext};
use crate::transport::Transport;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, Severity};
use reqwest::Client;

pub async fn probe_complexity(
    _schema: &GqlSchema,
    client: &Client,
    url: &str,
    extra_headers: &[String],
    rate_limit_ms: u64,
    evasion_level: u8,
    transport: Transport,
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
        transport,
        false,
    )
    .await?;

    let mut complexity_detected = false;
    let mut details = String::new();
    let mut exposed_limit: Option<String> = None;

    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&resp.raw_text) {
        if let Some(extensions) = data.get("extensions") {
            if extensions.get("complexity").is_some()
                || extensions.get("cost").is_some()
                || extensions.get("depth").is_some()
            {
                complexity_detected = true;
                details = "Found complexity/cost info in extensions.".to_string();
            }
            exposed_limit = find_exposed_complexity_limit(extensions);
        }
    }

    if complexity_detected {
        confirmed.push(Finding {
            id: "complexity-info-exposed",
            severity: Severity::Low,
            title: "Query Complexity/Cost Info Exposed",
            description: format!("The server returns query complexity or cost information in the 'extensions' field. {}", details),
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
            id: "complexity-info-exposed",
            severity: Severity::Low,
            title: "Complexity Probe Inconclusive",
            description: "No complexity or cost information was detected in the response extensions.".to_string(),
            affected: vec![AffectedLocation::Type("Query".into())],
            remediation: "Confirm if complexity limiting is implemented by manually testing deeply nested queries.",
            first_step: Some("Manually test deeply nested or complex queries to see if the server enforces any limits.".into()),
            references: vec!["CWE-200"],
            status: FindingStatus::Possible,
            confidence: Confidence::Possible,
            evidence_level: EvidenceLevel::Inconclusive,
            poc: None,
        });
    }

    // --- Enforcement test: does the server actually reject a deep query? ---
    let mut inner = String::from("name");
    for _ in 0..15 {
        inner = format!("ofType {{ {} }}", inner);
    }
    let deep_query = format!(
        "query {{ __schema {{ types {{ name fields {{ name type {{ {} }} }} }} }} }}",
        inner
    );

    let deep_resp = post_graphql_ext(
        client,
        url,
        &effective_headers(extra_headers, None, false),
        &deep_query,
        None,
        rate_limit_ms,
        evasion_level,
        transport,
        false,
    )
    .await?;

    if is_complexity_limit_error(&deep_resp.errors_text) || is_complexity_limit_error(&deep_resp.raw_text) {
        let limit_note = match &exposed_limit {
            Some(v) => format!(" The server also exposes an explicit complexity/depth limit value: {}.", v),
            None => String::new(),
        };
        confirmed.push(Finding {
            id: "complexity-limit",
            severity: Severity::Info,
            title: "Query Complexity/Depth Limiting Enforced",
            description: format!(
                "A deliberately deep introspection query (~15 levels of nested '__Type.ofType') was rejected by the server, indicating that a query depth and/or complexity limit is actively enforced.{}",
                limit_note
            ),
            affected: vec![AffectedLocation::Type("Query".into())],
            remediation: "No action required; this is a positive security control. Periodically re-verify the limit remains enforced after schema or server changes.",
            first_step: Some("Send a deeply nested query and confirm it is rejected with a complexity/depth error.".into()),
            references: vec!["OWASP API4: Lack of Resources"],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
            poc: Some(deep_query.chars().take(300).collect()),
        });
    } else if deep_resp.status == 200 && deep_resp.data.is_some() && exposed_limit.is_none() {
        confirmed.push(Finding {
            id: "complexity-limit",
            severity: Severity::Medium,
            title: "No Query Depth/Complexity Limit Enforced (DoS Risk)",
            description: "A deliberately deep introspection query (~15 levels of nested '__Type.ofType') was accepted and executed successfully (HTTP 200 with data) instead of being rejected. This indicates the server does not enforce a maximum query depth or a static query-cost limit, leaving it exposed to depth/complexity-based denial-of-service attacks.".to_string(),
            affected: vec![AffectedLocation::Type("Query".into())],
            remediation: "Enforce a maximum query depth and/or a static query-cost limit",
            first_step: Some("Send the PoC deeply nested query and observe that the server executes it without error instead of rejecting it.".into()),
            references: vec!["OWASP API4: Lack of Resources", "CWE-770: Allocation of Resources Without Limits"],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
            poc: Some(deep_query.chars().take(300).collect()),
        });
    } else {
        unconfirmed.push(Finding {
            id: "complexity-limit",
            severity: Severity::Low,
            title: "Complexity/Depth Enforcement Probe Inconclusive",
            description: "Could not conclusively determine whether the server enforces a query depth/complexity limit (introspection may be disabled, or the response could not be classified as either a rejection or a successful execution).".to_string(),
            affected: vec![AffectedLocation::Type("Query".into())],
            remediation: "Manually test deeply nested queries to determine whether depth/complexity limiting is enforced.",
            first_step: Some("Manually send a deeply nested query and inspect the response status and error content.".into()),
            references: vec!["OWASP API4: Lack of Resources"],
            status: FindingStatus::Possible,
            confidence: Confidence::Possible,
            evidence_level: EvidenceLevel::Inconclusive,
            poc: None,
        });
    }

    Ok(())
}

/// Recognize an exposed complexity/depth limit or cost value anywhere in the
/// `extensions` object of a GraphQL response. Checks known engine-specific
/// keys (Hygraph, Apollo) as well as generic depth/cost keys, case-insensitively.
fn find_exposed_complexity_limit(extensions: &serde_json::Value) -> Option<String> {
    const KEYS: [&str; 7] = [
        "effective-complexity-limit",
        "complexity-cost-left",
        "cost",
        "complexity",
        "depth",
        "maxdepth",
        "maxquerydepth",
    ];

    fn walk(value: &serde_json::Value, out: &mut Option<String>) {
        if out.is_some() {
            return;
        }
        match value {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    let lk = k.to_lowercase();
                    if KEYS.iter().any(|key| lk.contains(key)) {
                        if !v.is_object() && !v.is_array() {
                            *out = Some(format!("{}={}", k, v));
                            return;
                        }
                    }
                    walk(v, out);
                    if out.is_some() {
                        return;
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    walk(v, out);
                    if out.is_some() {
                        return;
                    }
                }
            }
            _ => {}
        }
    }

    let mut out = None;
    walk(extensions, &mut out);
    out
}

fn is_complexity_limit_error(text: &str) -> bool {
    let t = text.to_lowercase();
    [
        "complexity",
        "query is too",
        "too complex",
        "maximum query depth",
        "depth limit",
        "exceeds maximum",
        "query is too large",
        "maxquerydepth",
        "operation is too",
        "cost limit",
        "query cost",
    ]
    .iter()
    .any(|p| t.contains(p))
}
