use crate::audit::utils::{effective_headers, post_graphql_ext};
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, Severity};
use reqwest::Client;

pub async fn probe_engine_fingerprint(
    _schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    evasion_level: u8,
    confirmed: &mut Vec<Finding>,
    _unconfirmed: &mut Vec<Finding>,
) -> Result<(), String> {
    let headers = effective_headers(extra_headers, None, false);

    // 1. Malformed Query for Error Signatures
    let malformed = "query { malformed_field_for_fingerprint }";
    let resp = post_graphql_ext(client, url, &headers, malformed, None, rate_limit_ms, evasion_level).await?;
    
    let mut engine: &'static str = "Unknown";
    let mut confidence = Confidence::Theoretical;
    let mut reasons = Vec::new();

    let err_text = resp.raw_text.to_lowercase();

    // Check headers first (most reliable)
    let has_hasura_header = resp.headers.keys().any(|k| k.to_lowercase().contains("hasura"));
    
    if has_hasura_header || err_text.contains("hasura") {
        engine = "Hasura";
        confidence = Confidence::Confirmed;
        reasons.push("Detected Hasura-specific headers or error signatures".to_string());
    } else if err_text.contains("graphqllocations") || (err_text.contains("extensions") && err_text.contains("code")) {
        engine = "Apollo Server";
        confidence = Confidence::Possible;
        reasons.push("Error format matches Apollo Server (extensions.code structure)".to_string());
    } else if err_text.contains("graphene") || (err_text.contains("syntax error") && err_text.contains("line 1, column 9")) {
        engine = "Graphene (Python)";
        confidence = Confidence::Possible;
        reasons.push("Error signatures suggest Graphene implementation".to_string());
    } else if err_text.contains("appsync") {
        engine = "AWS AppSync";
        confidence = Confidence::Confirmed;
        reasons.push("Detected AppSync-specific identifiers".to_string());
    }

    if engine != "Unknown" {
        confirmed.push(Finding {
            id: "AUD-FING-001",
            severity: Severity::Info,
            title: "GraphQL Engine Identified",
            description: format!(
                "The underlying GraphQL technology appears to be {}. Fingerprinting helps tailor payloads and identifies implementation-specific risks. Reasons: {}",
                engine, reasons.join(", ")
            ),
            affected: vec![AffectedLocation::Type("Server Engine".into())],
            remediation: "This is a reconnaissance finding. Ensure your engine is up-to-date and follows security best practices (e.g., disabling introspection in production).",
            first_step: Some(format!("Research known vulnerabilities and security configurations for {} to further harden the endpoint.", engine)),
            references: vec!["graphw00f", "GraphQL-Threat-Matrix"],
            status: FindingStatus::Confirmed,
            confidence,
            evidence_level: EvidenceLevel::Executed,
            poc: Some(resp.raw_text.chars().take(200).collect()),
        });
    }

    Ok(())
}
