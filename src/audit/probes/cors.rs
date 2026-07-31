use crate::audit::utils::effective_headers;
use crate::transport::Transport;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, Severity};
use reqwest::Client;

/// Tests cross-origin request policy: sends the GraphQL endpoint a benign query carrying a
/// hostile `Origin` and inspects the reflected `Access-Control-Allow-Origin` (ACAO) /
/// `Access-Control-Allow-Credentials` (ACAC). A reflected origin **plus** credentials means
/// any site can make authenticated cross-origin reads against the API (account takeover
/// primitive); a wildcard ACAO is permissive but cannot carry credentials.
#[allow(clippy::too_many_arguments)]
pub async fn probe_cors(
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    evasion_level: u8,
    transport: Transport,
    confirmed: &mut Vec<Finding>,
    _unconfirmed: &mut Vec<Finding>,
) -> Result<(), String> {
    let evil = "https://introspectre-evil.example";
    let test_origins = [evil, "null"];
    let query = "{ __typename }";

    for origin in test_origins {
        let mut headers = effective_headers(extra_headers, None, false);
        headers.push(("Origin".to_string(), origin.to_string()));

        let resp = crate::audit::utils::post_graphql_ext(
            client, url, &headers, query, None, rate_limit_ms, evasion_level, transport, false,
        )
        .await?;

        let acao = resp.headers.get("access-control-allow-origin").cloned();
        let acac = resp
            .headers
            .get("access-control-allow-credentials")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let Some(acao) = acao else { continue };

        let reflected = acao == origin;
        let wildcard = acao == "*";
        if !reflected && !wildcard {
            continue; // ACAO is present but pinned to a fixed allowed origin — safe.
        }

        let (severity, note) = if reflected && acac {
            (
                Severity::High,
                "reflects the request Origin AND allows credentials — any site can make authenticated cross-origin reads (account-takeover primitive)",
            )
        } else if reflected {
            (
                Severity::Medium,
                "reflects arbitrary request Origins (no credentials), exposing responses to any site",
            )
        } else {
            (
                Severity::Low,
                "returns a wildcard `*` — permissive, though credentials cannot be sent with `*`",
            )
        };

        confirmed.push(Finding {
            id: "cors-misconfiguration",
            severity,
            title: "Permissive CORS Policy",
            description: format!(
                "With `Origin: {}` the endpoint responded `Access-Control-Allow-Origin: {}`{}. It {}.",
                origin,
                acao,
                if acac { ", Access-Control-Allow-Credentials: true" } else { "" },
                note
            ),
            affected: vec![AffectedLocation::Type("CORS Policy".into())],
            remediation: "Do not reflect the request Origin. Allow-list only trusted origins, and never combine a reflected/`*` ACAO with `Access-Control-Allow-Credentials: true`.",
            first_step: Some(format!(
                "Reproduce with: curl -i -X POST {} -H 'Origin: {}' -H 'Content-Type: application/json' -d '{{\"query\":\"{{ __typename }}\"}}' and inspect the Access-Control-* response headers.",
                url, origin
            )),
            references: vec!["CWE-942: Permissive Cross-domain Policy", "OWASP API8: Security Misconfiguration"],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
            poc: Some(format!("POST {}\nOrigin: {}\n\n{{ __typename }}", url, origin)),
        });
        // One representative finding is enough; stop after the first permissive origin.
        break;
    }

    Ok(())
}
