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

    // Also flag an exposed in-browser GraphQL IDE (GraphiQL/Playground/Altair/Voyager), a recon
    // convenience for attackers that often ships enabled by mistake.
    if let Some((ide_url, ide)) = detect_ide(client, url, extra_headers, rate_limit_ms).await {
        confirmed.push(Finding {
            id: "graphiql-exposed",
            severity: Severity::Low,
            title: "GraphQL IDE Exposed",
            description: format!(
                "An in-browser GraphQL IDE ({}) is served at `{}`. It gives an attacker an interactive console — schema browsing, autocompletion, and query execution — and usually signals a non-production hardening gap.",
                ide, ide_url
            ),
            affected: vec![AffectedLocation::Type("GraphQL IDE".into())],
            remediation: "Disable the GraphQL IDE (GraphiQL/Playground/Altair/Voyager) in production, or require authentication to reach it.",
            first_step: Some(format!("Open {} in a browser and confirm the IDE loads.", ide_url)),
            references: vec!["CWE-200: Information Exposure", "OWASP API Security Top 10"],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
            poc: Some(format!("# Open in a browser:\n{}", ide_url)),
        });
    }

    Ok(())
}

/// Best-effort detection of an exposed in-browser GraphQL IDE. Tries the endpoint itself and a few
/// sibling paths with a plain `GET` (`Accept: text/html`), and matches well-known IDE markers in the
/// returned HTML. Returns `(url, ide_name)` on the first hit. Any supplied headers (e.g. `--challenge-cookie`)
/// are forwarded, so an IDE gated behind a cookie/session is still detectable when the operator has one.
async fn detect_ide(
    client: &Client,
    endpoint: &str,
    extra_headers: &[String],
    rate_limit_ms: u64,
) -> Option<(String, String)> {
    let mut candidates: Vec<String> = vec![endpoint.to_string()];
    if let Some(base) = endpoint.strip_suffix("/graphql") {
        for p in ["/graphiql", "/playground", "/altair", "/voyager", "/console"] {
            candidates.push(format!("{}{}", base, p));
        }
    } else {
        for p in ["/graphiql", "/playground"] {
            candidates.push(format!("{}{}", endpoint.trim_end_matches('/'), p));
        }
    }

    let extra = crate::utils::parse_extra_headers(extra_headers);
    for cand in candidates {
        if rate_limit_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(rate_limit_ms)).await;
        }
        let mut req = client.get(&cand).header("Accept", "text/html");
        for (k, v) in &extra {
            req = req.header(k, v);
        }
        let Ok(resp) = req.send().await else { continue };
        if !resp.status().is_success() {
            continue;
        }
        let is_html = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains("html"))
            .unwrap_or(false);
        let body = resp.text().await.unwrap_or_default();
        let lower = body.to_lowercase();
        if !(is_html || lower.contains("<!doctype html") || lower.contains("<html")) {
            continue;
        }
        let ide = if lower.contains("graphiql") {
            "GraphiQL"
        } else if lower.contains("graphql playground") || lower.contains("graphql-playground") {
            "GraphQL Playground"
        } else if lower.contains("altair") {
            "Altair"
        } else if lower.contains("voyager") {
            "GraphQL Voyager"
        } else {
            continue;
        };
        return Some((cand, ide.to_string()));
    }
    None
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
