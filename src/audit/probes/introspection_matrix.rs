use crate::audit::utils::effective_headers;
use crate::transport::Transport;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlError, Severity};
use reqwest::Client;

/// One introspection vector tested at up to two auth levels.
struct Row {
    name: &'static str,
    unauth_open: bool,
    auth_open: Option<bool>, // None when no auth header was supplied to compare against
}

/// Probes the *introspection method matrix*: rather than a binary "introspection on/off",
/// report which of `__schema`, `__type`, and field-suggestion ("did you mean?") leakage are
/// reachable, and — when a token is supplied — whether they are open **unauthenticated** vs.
/// only with auth. Unauthenticated schema disclosure on an otherwise auth-gated API is the
/// notable case (e.g. `__schema` blocked but `__type` open to anonymous users).
#[allow(clippy::too_many_arguments)]
pub async fn probe_introspection_matrix(
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    evasion_level: u8,
    transport: Transport,
    confirmed: &mut Vec<Finding>,
    _unconfirmed: &mut Vec<Finding>,
) -> Result<(), String> {
    let has_auth = crate::utils::parse_extra_headers(extra_headers)
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("Authorization"));

    let vectors: [(&'static str, &'static str, fn(&crate::audit::utils::ProbeResponse) -> bool); 3] = [
        (
            "__schema",
            "{ __schema { queryType { name } } }",
            |r| data_has(r, "__schema"),
        ),
        (
            "__type",
            "{ __type(name: \"Query\") { name kind } }",
            |r| data_has(r, "__type"),
        ),
        (
            "field-suggestions",
            "{ __introspectre_no_such_field_xyz }",
            |r| !suggestions(r).is_empty(),
        ),
    ];

    let mut rows: Vec<Row> = Vec::new();
    for (name, query, is_open) in vectors {
        let unauth_headers = effective_headers(extra_headers, None, false);
        let unauth = crate::audit::utils::post_graphql_ext(
            client, url, &unauth_headers, query, None, rate_limit_ms, evasion_level, transport, false,
        )
        .await?;
        let unauth_open = is_open(&unauth);

        let auth_open = if has_auth {
            let auth_headers = effective_headers(extra_headers, None, true);
            let authed = crate::audit::utils::post_graphql_ext(
                client, url, &auth_headers, query, None, rate_limit_ms, evasion_level, transport, false,
            )
            .await?;
            Some(is_open(&authed))
        } else {
            None
        };

        rows.push(Row { name, unauth_open, auth_open });
    }

    // Summarise.
    let unauth_schema_disclosed = rows
        .iter()
        .any(|r| (r.name == "__schema" || r.name == "__type") && r.unauth_open);
    let suggestions_leak = rows.iter().any(|r| r.name == "field-suggestions" && r.unauth_open);
    let any_open = rows.iter().any(|r| r.unauth_open || r.auth_open == Some(true));

    if !any_open {
        // Nothing reachable at any level — introspection is genuinely locked down.
        return Ok(());
    }

    let matrix: String = rows
        .iter()
        .map(|r| {
            let auth = match r.auth_open {
                Some(true) => ", authenticated: OPEN",
                Some(false) => ", authenticated: blocked",
                None => "",
            };
            format!("{}: unauthenticated {}{}", r.name, if r.unauth_open { "OPEN" } else { "blocked" }, auth)
        })
        .collect::<Vec<_>>()
        .join(" · ");

    let severity = if unauth_schema_disclosed {
        Severity::Medium
    } else if suggestions_leak {
        Severity::Low
    } else {
        Severity::Info
    };

    let headline = if unauth_schema_disclosed {
        "Schema is disclosed to unauthenticated callers via introspection."
    } else if suggestions_leak {
        "Field names leak to unauthenticated callers via \"did you mean?\" suggestions."
    } else {
        "Introspection is reachable (authenticated only)."
    };

    confirmed.push(Finding {
        id: "introspection-matrix",
        severity,
        title: "Introspection Method Matrix",
        description: format!(
            "{} Method reachability — {}. Even when `__schema` is disabled, `__type` or field-suggestion errors can reconstruct the schema; unauthenticated disclosure hands an attacker a full attack-surface map for free.",
            headline, matrix
        ),
        affected: vec![AffectedLocation::Type("Introspection".into())],
        remediation: "Disable ALL introspection surfaces in production — `__schema`, `__type`, and field-suggestion (\"did you mean\") error hints — and require authentication before any schema metadata is returned. Disabling only `__schema` is insufficient.",
        first_step: Some("Re-run each vector (`__schema`, `__type(name:\"Query\")`, a bogus field) with and without an Authorization header to confirm which are exposed anonymously.".into()),
        references: vec!["CWE-200: Information Exposure", "OWASP API Security Top 10"],
        status: FindingStatus::Confirmed,
        confidence: Confidence::Confirmed,
        evidence_level: EvidenceLevel::Executed,
        poc: Some("# Unauthenticated (no Authorization header):\nquery { __type(name: \"Query\") { name fields { name } } }".into()),
    });

    Ok(())
}

fn data_has(r: &crate::audit::utils::ProbeResponse, key: &str) -> bool {
    r.data
        .as_ref()
        .and_then(|d| d.get(key))
        .map(|v| !v.is_null())
        .unwrap_or(false)
}

fn suggestions(r: &crate::audit::utils::ProbeResponse) -> Vec<String> {
    let errors: Vec<GqlError> = serde_json::from_str(&r.errors_text).unwrap_or_default();
    let mut out = Vec::new();
    for e in errors {
        out.extend(crate::utils::parse_did_you_mean(&e.message));
    }
    out
}
