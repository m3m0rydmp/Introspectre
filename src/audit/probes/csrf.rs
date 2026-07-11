use crate::audit::utils::effective_headers;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, Severity};
use reqwest::Client;

pub async fn probe_csrf_methods(
    _schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    _evasion_level: u8,
    confirmed: &mut Vec<Finding>,
    _unconfirmed: &mut Vec<Finding>,
) -> Result<(), String> {
    let headers_vec = effective_headers(extra_headers, None, false);
    let test_query = "{ __typename }";

    // 1. Test GET Method
    if rate_limit_ms > 0 { tokio::time::sleep(std::time::Duration::from_millis(rate_limit_ms)).await; }
    let encoded_query = urlencoding::encode(test_query);
    let get_url = format!("{}?query={}", url, encoded_query);
    
    let mut get_req = client.get(&get_url);
    for (k, v) in &headers_vec {
        get_req = get_req.header(k, v);
    }
    let get_resp = get_req.send().await;

    if let Ok(resp) = get_resp {
        if resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("Query") {
                confirmed.push(Finding {
                    id: "csrf-get-method",
                    severity: Severity::Medium,
                    title: "GraphQL GET Method Support (CSRF Risk)",
                    description: "The GraphQL endpoint accepts queries via GET requests. This significantly increases the risk of CSRF attacks, as queries can be triggered via simple HTML tags (e.g., <img src='...'>) or links.".to_string(),
                    affected: vec![AffectedLocation::Type("Endpoint HTTP Methods".into())],
                    remediation: "Disable GET method support for the GraphQL endpoint. Only allow POST requests with 'application/json' content type.",
                    first_step: Some(format!("Try to access the URL '{}' in a browser to see if it returns the GraphQL response data.", get_url)),
                    references: vec!["OWASP API Security Top 10", "CWE-352: Cross-Site Request Forgery"],
                    status: FindingStatus::Confirmed,
                    confidence: Confidence::Confirmed,
                    evidence_level: EvidenceLevel::Executed,
                    poc: Some(format!("GET {}", get_url)),
                });
            }
        }
    }

    // 2. Test URL-Encoded POST (Bypasses many JSON-only CSRF protections)
    if rate_limit_ms > 0 { tokio::time::sleep(std::time::Duration::from_millis(rate_limit_ms)).await; }
    let post_body = format!("query={}", encoded_query);
    
    let mut post_req = client.post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(post_body.clone());
        
    for (k, v) in &headers_vec {
        post_req = post_req.header(k, v);
    }
    let post_url_resp = post_req.send().await;

    if let Ok(resp) = post_url_resp {
        if resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("Query") {
                confirmed.push(Finding {
                    id: "csrf-form-post",
                    severity: Severity::Medium,
                    title: "GraphQL URL-Encoded POST Support (CSRF Risk)",
                    description: "The GraphQL endpoint accepts queries via POST requests with 'application/x-www-form-urlencoded' content type. This allows standard HTML forms to trigger GraphQL operations, bypassing JSON-based CSRF protections.".to_string(),
                    affected: vec![AffectedLocation::Type("Endpoint HTTP Content-Types".into())],
                    remediation: "Strictly enforce 'application/json' content type and reject any other POST body formats.",
                    first_step: Some("Create a simple HTML <form> that submits to the GraphQL endpoint with a 'query' parameter and see if the server processes it.".into()),
                    references: vec!["OWASP API Security Top 10", "CWE-352: Cross-Site Request Forgery"],
                    status: FindingStatus::Confirmed,
                    confidence: Confidence::Confirmed,
                    evidence_level: EvidenceLevel::Executed,
                    poc: Some(format!("POST {} (Content-Type: application/x-www-form-urlencoded)\nBody: {}", url, post_body)),
                });
            }
        }
    }

    Ok(())
}
