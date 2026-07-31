use crate::audit::utils::effective_headers;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, Severity};
use reqwest::Client;

/// Detects Apollo Automatic Persisted Queries (APQ). Sends the `persistedQuery` extension
/// with a hash but no `query`; an APQ-capable server replies `PersistedQueryNotFound`
/// (rather than a generic "must provide a query" error). APQ is a legitimate feature but
/// adds cache-poisoning / query-registration surface worth noting during an assessment.
pub async fn probe_apq(
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    confirmed: &mut Vec<Finding>,
    _unconfirmed: &mut Vec<Finding>,
) -> Result<(), String> {
    if rate_limit_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(rate_limit_ms)).await;
    }

    let body = serde_json::json!({
        "extensions": {
            "persistedQuery": {
                "version": 1,
                "sha256Hash": "0000000000000000000000000000000000000000000000000000000000000000"
            }
        }
    });

    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
        .json(&body);
    for (k, v) in &effective_headers(extra_headers, None, false) {
        req = req.header(k, v);
    }

    let Ok(resp) = req.send().await else { return Ok(()) };
    let text = resp.text().await.unwrap_or_default();

    if text.contains("PersistedQueryNotFound") || text.contains("PERSISTED_QUERY_NOT_FOUND") {
        confirmed.push(Finding {
            id: "apq-supported",
            severity: Severity::Info,
            title: "Automatic Persisted Queries (APQ) Supported",
            description: "The endpoint accepts the Apollo `persistedQuery` extension (it returned `PersistedQueryNotFound` for an unknown hash). APQ lets clients register and replay queries by hash — extra caching/registration surface. Review whether unregistered hashes can be poisoned and whether APQ bypasses any query allow-listing or complexity controls.".to_string(),
            affected: vec![AffectedLocation::Type("Persisted Queries (APQ)".into())],
            remediation: "If APQ is not required, disable it. If it is, ensure the persisted-query cache cannot be poisoned by unauthenticated clients and that APQ requests are still subject to the same auth, complexity, and rate-limit controls as normal queries.",
            first_step: Some("Send a `persistedQuery` request with a known query + its sha256 hash to register it, then replay by hash only; verify auth/complexity controls still apply.".into()),
            references: vec!["CWE-524: Use of Cache Containing Sensitive Information", "OWASP API8: Security Misconfiguration"],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
            poc: Some("POST (Content-Type: application/json)\n{\"extensions\":{\"persistedQuery\":{\"version\":1,\"sha256Hash\":\"<hash>\"}}}".into()),
        });
    }

    Ok(())
}
