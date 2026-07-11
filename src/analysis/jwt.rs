use crate::config::PatternConfig;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, Severity};
use crate::utils::matches_pattern;
use base64::prelude::*;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

fn decode_b64(input: &str) -> Option<Vec<u8>> {
    let padded = match input.len() % 4 {
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        _ => input.to_string(),
    };
    BASE64_URL_SAFE.decode(&padded).ok()
}

pub fn check_jwt(token: Option<&str>, patterns: &PatternConfig, findings: &mut Vec<Finding>) {
    let token = match token {
        Some(t) => t,
        None => return,
    };

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return;
    }

    let header_bytes = match decode_b64(parts[0]) {
        Some(b) => b,
        None => return,
    };
    let payload_bytes = match decode_b64(parts[1]) {
        Some(b) => b,
        None => return,
    };

    let header: Value = match serde_json::from_slice(&header_bytes) {
        Ok(v) => v,
        Err(_) => return,
    };
    let payload: Value = match serde_json::from_slice(&payload_bytes) {
        Ok(v) => v,
        Err(_) => return,
    };

    if let Some(alg) = header.get("alg").and_then(|v| v.as_str()) {
        if alg.to_lowercase() == "none" {
            findings.push(Finding {
                id: "jwt-alg-none",
                severity: Severity::High,
                title: "JWT Algorithm None",
                description: "The supplied JWT declares the 'none' algorithm in its header (decoded locally). If the server also accepts unsigned tokens, this enables full authentication bypass — but that must be verified against the server; this finding alone only reflects the token you provided.".to_string(),
                affected: vec![AffectedLocation::Type("JWT Header".into())],
                remediation: "Ensure your JWT library requires an explicit algorithm and rejects 'none'.",
                first_step: Some("Attempt to access a protected endpoint by removing the signature and setting the alg to 'none' in your token.".into()),
                references: vec!["RFC 8725", "OWASP API Security Top 10"],
                status: FindingStatus::Possible,
                confidence: Confidence::Possible,
                evidence_level: EvidenceLevel::Inferred,
                poc: None,
            });
        }
    }

    if let Some(exp) = payload.get("exp").and_then(|v| v.as_u64()) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if exp < now {
            findings.push(Finding {
                id: "jwt-expired",
                severity: Severity::Low,
                title: "Provided JWT is Expired",
                description: "The supplied JWT has an 'exp' claim in the past (decoded locally). Active probes that rely on this token may fail or yield false negatives due to authentication errors.".to_string(),
                affected: vec![AffectedLocation::Type("JWT Payload".into())],
                remediation: "Provide a fresh token to ensure accurate active probing.",
                first_step: Some("Obtain a fresh, valid JWT and re-run the scan to ensure active probes function correctly.".into()),
                references: vec![],
                status: FindingStatus::Possible,
                confidence: Confidence::Possible,
                evidence_level: EvidenceLevel::Inferred,
                poc: None,
            });
        }
    }

    let mut sensitive_claims = Vec::new();
    if let Some(obj) = payload.as_object() {
        for key in obj.keys() {
            if matches_pattern(key, &patterns.sensitive_fields.names) {
                sensitive_claims.push(key.clone());
            }
        }
    }

    if !sensitive_claims.is_empty() {
        findings.push(Finding {
            id: "jwt-sensitive-claims",
            severity: Severity::Medium,
            title: "Sensitive Data in JWT Claims",
            description: "The supplied JWT payload contains claims with names suggesting sensitive data (decoded locally). JWTs are merely encoded (not encrypted), so anyone possessing the token can read these fields.".to_string(),
            affected: sensitive_claims.iter().map(|k| AffectedLocation::Argument("JWT".into(), "Payload".into(), k.clone())).collect(),
            remediation: "Remove sensitive information from JWTs. Use them only for opaque user identifiers and roles, loading sensitive data server-side.",
            first_step: Some("Review the payload of your token to ensure no secrets or sensitive internal flags are exposed.".into()),
            references: vec!["CWE-312: Cleartext Storage of Sensitive Information"],
            status: FindingStatus::Possible,
            confidence: Confidence::Possible,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PatternConfig;
    use crate::types::Severity;

    #[test]
    fn test_jwt_alg_none() {
        // {"alg":"none","typ":"JWT"}.{"sub":"1234567890","name":"John Doe","iat":1516239022}.
        let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";
        let patterns = PatternConfig::default();
        let mut findings = Vec::new();

        check_jwt(Some(token), &patterns, &mut findings);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "jwt-alg-none");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_jwt_expired() {
        // Header: {"alg":"HS256","typ":"JWT"}
        // Payload: {"sub":"123","exp":1000} (Expired in 1970)
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJleHAiOjEwMDB9.sig";
        let patterns = PatternConfig::default();
        let mut findings = Vec::new();

        check_jwt(Some(token), &patterns, &mut findings);

        // Might be more than 1 if "sig" matches a sensitive pattern (unlikely but possible)
        assert!(findings.iter().any(|f| f.id == "jwt-expired"));
    }

    #[test]
    fn test_jwt_sensitive_claims() {
        // Payload: {"sub":"123","password":"secret_value"}
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJwYXNzd29yZCI6InNlY3JldF92YWx1ZSJ9.sig";
        let mut patterns = PatternConfig::default();
        patterns.sensitive_fields.names = vec!["password".to_string()];
        let mut findings = Vec::new();

        check_jwt(Some(token), &patterns, &mut findings);

        assert!(findings.iter().any(|f| f.id == "jwt-sensitive-claims"));
        assert!(findings
            .iter()
            .any(|f| f.affected.iter().any(|a| matches!(a, AffectedLocation::Argument(_, _, field) if field == "password"))));
    }

    #[test]
    fn test_jwt_invalid_format() {
        let token = "invalid.token";
        let patterns = PatternConfig::default();
        let mut findings = Vec::new();

        check_jwt(Some(token), &patterns, &mut findings);
        assert_eq!(findings.len(), 0);
    }
}
