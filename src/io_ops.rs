use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use colored::Colorize;
use futures::stream::{futures_unordered::FuturesUnordered, StreamExt};
use reqwest::Client;
use serde::Deserialize;

use crate::transport::{build_graphql_request, Transport};
use crate::types::{
    AuthDiscoveryResult, GqlError, GqlField, GqlSchema, IntrospectionResponse, INTROSPECTION_QUERY,
};
use crate::utils::parse_extra_headers;

#[derive(Debug, Clone)]
pub struct EndpointProbeResult {
    pub graphql_confirmed: bool,
    pub http_status: u16,
    pub summary: String,
    pub resolved_transport: Transport,
}

/// A small pool of current, realistic browser User-Agent strings. The tool
/// deliberately avoids advertising itself via the User-Agent header; instead
/// one of these is picked at random so outbound requests blend in with
/// ordinary browser traffic.
const BROWSER_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
];

/// Pick a realistic browser User-Agent at random (seeded from the current
/// time). Used as the default so requests don't advertise this tool.
fn default_user_agent() -> &'static str {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    BROWSER_USER_AGENTS[(nanos as usize) % BROWSER_USER_AGENTS.len()]
}

pub fn build_client(
    timeout_secs: u64,
    user_agent_override: Option<&str>,
    stealth: bool,
) -> Result<Client, String> {
    // `pool_max_idle_per_host(0)` disables keep-alive connection reuse. Some
    // servers (notably Flask/werkzeug dev servers, e.g. DVGA) mishandle pooled
    // keep-alive connections, which makes reqwest fail with "error decoding
    // response body" on an otherwise valid response. A fresh connection per
    // request avoids that at a small performance cost.
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .pool_max_idle_per_host(0);

    // `stealth` no longer changes the User-Agent selection: the default is
    // already a randomized, non-branded browser UA, so both cases use it.
    let ua = user_agent_override
        .map(str::to_string)
        .unwrap_or_else(|| default_user_agent().to_string());
    let _ = stealth;

    builder = builder.user_agent(ua);

    builder.build().map_err(|e| e.to_string())
}

pub async fn fetch_introspection(
    url: &str,
    extra_headers: &[String],
    timeout_secs: u64,
    rate_limit_ms: u64,
    token: Option<&str>,
    user_agent: Option<&str>,
    stealth: bool,
    transport: Transport,
) -> Result<GqlSchema, String> {
    let client = build_client(timeout_secs, user_agent, stealth)?;
    let vectors = vec![
        ("Full Introspection", INTROSPECTION_QUERY.to_string()),
        ("Partial (Types only)", "query { __schema { types { name kind fields { name } } } }".to_string()),
        ("Type-specific (Query)", "query { __type(name: \"Query\") { name kind fields { name type { name kind } } } }".to_string()),
    ];

    let mut last_error = String::new();

    for (name, query) in vectors {
        // Introspection queries are never mutations.
        let mut req = build_graphql_request(&client, url, transport, &query, None, false);

        for (k, v) in parse_extra_headers(extra_headers) {
            req = req.header(k, v);
        }

        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }

        if rate_limit_ms > 0 {
            tokio::time::sleep(Duration::from_millis(rate_limit_ms)).await;
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                last_error = format!("Request failed: {}", e);
                continue;
            }
        };

        let status = resp.status();
        if !status.is_success() {
            last_error = format!("HTTP {}: server returned an error.", status);
            continue;
        }

        let parsed: IntrospectionResponse = match resp.json().await {
            Ok(p) => p,
            Err(e) => {
                last_error = format!("Failed to parse response as JSON: {}", e);
                continue;
            }
        };

        if let Some(errors) = parsed.errors {
            let msgs: Vec<_> = errors.iter().map(|e| e.message.to_lowercase()).collect();
            let all = msgs.join("; ");
            last_error = format!("GraphQL errors ({}): {}", name, all);
            continue;
        }

        if let Some(data) = parsed.data {
            return Ok(data.schema);
        } else {
            last_error = "Response contained no data.".to_string();
        }
    }

    // Every `__schema`-based vector failed. Before giving up, try a
    // `__type`-walk reconstruction: many APIs disable only `__schema` and leave
    // `__type` reachable, from which the whole schema can be rebuilt one type at
    // a time. Build a parsed header list mirroring the auth handling above.
    let mut walk_headers = parse_extra_headers(extra_headers);
    if let Some(t) = token {
        walk_headers.push(("Authorization".to_string(), format!("Bearer {}", t)));
    }
    if let Ok(schema) = crate::type_walk::reconstruct_via_type_walk(
        &client,
        url,
        &walk_headers,
        rate_limit_ms,
        transport,
        true,
    )
    .await
    {
        eprintln!(
            "  {} `__schema` blocked; reconstructed {} types via `__type`-walk (partial schema).",
            "→".blue(),
            schema.types.len()
        );
        return Ok(schema);
    }

    Err(format!(
        "All introspection vectors failed. Last error: {}",
        last_error
    ))
}

pub async fn probe_graphql_endpoint(
    url: &str,
    extra_headers: &[String],
    timeout_secs: u64,
    rate_limit_ms: u64,
    token: Option<&str>,
    user_agent: Option<&str>,
    stealth: bool,
    transport: Transport,
) -> Result<EndpointProbeResult, String> {
    let client = build_client(timeout_secs, user_agent, stealth)?;

    if transport != Transport::Auto {
        return probe_with_transport(&client, url, extra_headers, token, rate_limit_ms, transport).await;
    }

    // Auto-negotiation: try PostJson first (today's default behavior), then
    // fall back to Get, then Form, keeping the first transport whose knock
    // request comes back as recognizable GraphQL (or a clear auth gate).
    let candidates = [Transport::PostJson, Transport::Get, Transport::Form];
    let mut fallback: Option<EndpointProbeResult> = None;
    let mut last_error = String::new();

    for (i, candidate) in candidates.iter().enumerate() {
        let is_last = i == candidates.len() - 1;
        match probe_with_transport(&client, url, extra_headers, token, rate_limit_ms, *candidate).await {
            Ok(result) if result.graphql_confirmed || result.http_status == 401 || result.http_status == 403 => {
                return Ok(result);
            }
            Ok(result) => {
                if fallback.is_none() {
                    fallback = Some(result);
                }
                if is_last {
                    break;
                }
            }
            Err(e) => {
                last_error = e;
                if is_last && fallback.is_none() {
                    return Err(last_error);
                }
            }
        }
    }

    Ok(fallback.unwrap_or(EndpointProbeResult {
        graphql_confirmed: false,
        http_status: 0,
        summary: format!(
            "Auto transport negotiation failed for post-json, get, and form. Last error: {}",
            last_error
        ),
        resolved_transport: Transport::PostJson,
    }))
}

/// Send the minimal `__typename` knock query over a single, concrete
/// transport and classify the response. Shared by the explicit-transport
/// path and the `Auto` negotiation loop above.
async fn probe_with_transport(
    client: &Client,
    url: &str,
    extra_headers: &[String],
    token: Option<&str>,
    rate_limit_ms: u64,
    transport: Transport,
) -> Result<EndpointProbeResult, String> {
    let mut req = build_graphql_request(client, url, transport, "query ProbeTypename { __typename }", None, false);

    for (k, v) in parse_extra_headers(extra_headers) {
        req = req.header(k, v);
    }

    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {}", t));
    }

    if rate_limit_ms > 0 {
        tokio::time::sleep(Duration::from_millis(rate_limit_ms)).await;
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("Probe request failed: {}", e))?;

    let status = resp.status();
    if status.as_u16() == 401 || status.as_u16() == 403 {
        return Ok(EndpointProbeResult {
            graphql_confirmed: false,
            http_status: status.as_u16(),
            summary: format!(
                "HTTP {} from probe endpoint. This path may be GraphQL but requires authentication.",
                status
            ),
            resolved_transport: transport,
        });
    }

    let parsed: Result<ProbeResponse, _> = resp.json().await;
    let parsed = match parsed {
        Ok(p) => p,
        Err(_) => {
            return Ok(EndpointProbeResult {
                graphql_confirmed: false,
                http_status: status.as_u16(),
                summary: "Probe did not return valid GraphQL JSON. Check endpoint path and Content-Type handling."
                    .to_string(),
                resolved_transport: transport,
            })
        }
    };

    if let Some(data) = &parsed.data {
        if data.get("__typename").is_some() {
            return Ok(EndpointProbeResult {
                graphql_confirmed: true,
                http_status: status.as_u16(),
                summary: "GraphQL confirmed via __typename probe.".to_string(),
                resolved_transport: transport,
            });
        }
    }

    if let Some(errors) = parsed.errors {
        let messages = errors
            .iter()
            .map(|e| e.message.to_lowercase())
            .collect::<Vec<_>>()
            .join(" | ");

        if is_auth_error(&messages) {
            return Ok(EndpointProbeResult {
                graphql_confirmed: true,
                http_status: status.as_u16(),
                summary: "GraphQL confirmed, but auth is likely required for full access."
                    .to_string(),
                resolved_transport: transport,
            });
        }

        let graphql_error_signals = [
            "cannot query field",
            "syntax error",
            "selection set",
            "unknown argument",
            "graphql",
        ];
        if graphql_error_signals.iter().any(|s| messages.contains(s)) {
            return Ok(EndpointProbeResult {
                graphql_confirmed: true,
                http_status: status.as_u16(),
                summary: "Endpoint behaves like GraphQL (GraphQL-formatted errors observed)."
                    .to_string(),
                resolved_transport: transport,
            });
        }

        return Ok(EndpointProbeResult {
            graphql_confirmed: false,
            http_status: status.as_u16(),
            summary: format!("Probe returned inconclusive errors: {}", messages),
            resolved_transport: transport,
        });
    }

    Ok(EndpointProbeResult {
        graphql_confirmed: false,
        http_status: status.as_u16(),
        summary: "Probe response was inconclusive (no GraphQL data/errors).".to_string(),
        resolved_transport: transport,
    })
}

pub fn load_schema_from_file(path: &PathBuf) -> Result<GqlSchema, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("Cannot read file {:?}: {}", path, e))?;

    let value: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {}", e))?;

    let schema_val = value
        .get("data")
        .and_then(|d| d.get("__schema"))
        .or_else(|| value.get("__schema"))
        .or_else(|| value.get("schema"))
        .ok_or(
            "Could not find `__schema` key in JSON. Ensure this is a GraphQL introspection result.",
        )?;

    serde_json::from_value(schema_val.clone()).map_err(|e| format!("Failed to parse schema: {}", e))
}

#[derive(Debug, Deserialize)]
struct ProbeResponse {
    data: Option<serde_json::Value>,
    errors: Option<Vec<GqlError>>,
}

fn type_kind(schema: &GqlSchema, field: &GqlField) -> Option<String> {
    let name = field
        .field_type
        .as_ref()
        .and_then(|t| t.unwrap_type_name())?;
    schema
        .types
        .iter()
        .find(|t| t.name.as_deref() == Some(name.as_str()))
        .and_then(|t| t.kind.clone())
}

fn knock_query(schema: &GqlSchema, op: &str, field: &GqlField) -> String {
    let selection = match type_kind(schema, field).as_deref() {
        Some("OBJECT") | Some("INTERFACE") | Some("UNION") => " { __typename }",
        _ => "",
    };
    format!("{} {{ {}{} }}", op, field.name, selection)
}

fn is_auth_error(msg: &str) -> bool {
    let m = msg.to_lowercase();
    let auth_signals = [
        "not authenticated",
        "unauthorized",
        "forbidden",
        "auth required",
        "authentication",
        "bearer",
        "jwt",
        "token",
    ];
    auth_signals.iter().any(|s| m.contains(s))
}

fn is_public_likely_error(msg: &str) -> bool {
    let m = msg.to_lowercase();
    let signals = [
        "required",
        "missing",
        "argument",
        "unknown argument",
        "sub selection",
        "selection set",
        "cannot query field",
    ];
    signals.iter().any(|s| m.contains(s))
}

pub async fn discover_auth_requirements(
    schema: &GqlSchema,
    url: &str,
    extra_headers: &[String],
    timeout_secs: u64,
    rate_limit_ms: u64,
    user_agent: Option<&str>,
    stealth: bool,
    transport: Transport,
) -> Result<AuthDiscoveryResult, String> {
    let client = build_client(timeout_secs, user_agent, stealth)?;
    let mut result = AuthDiscoveryResult::new();

    let mut targets: Vec<(String, String, String)> = Vec::new();
    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let mutation_name = schema.mutation_type.as_ref().map(|m| m.name.as_str());

    for f in schema.fields_for_type(query_name) {
        targets.push((
            "query".to_string(),
            "Query".to_string(),
            knock_query(schema, "query", f),
        ));
    }
    for f in schema.fields_for_type(mutation_name) {
        targets.push((
            "mutation".to_string(),
            "Mutation".to_string(),
            knock_query(schema, "mutation", f),
        ));
    }

    let max_knocks = 80usize;
    if targets.len() > max_knocks {
        for (_, root, _) in targets.iter().skip(max_knocks) {
            result
                .inconclusive
                .push(format!("{} (skipped: probe limit reached)", root));
        }
        targets.truncate(max_knocks);
    }

    let parsed_headers = parse_extra_headers(extra_headers);
    let mut futures = FuturesUnordered::new();

    let concurrency_limit = 5;
    let url_owned = url.to_string();

    for (op_keyword, root, query) in targets {
        while futures.len() >= concurrency_limit {
            if let Some(res) = futures.next().await {
                process_discovery_result(res, &mut result);
            }
        }

        let client = client.clone();
        let url = url_owned.clone();
        let headers = parsed_headers.clone();
        let is_mutation = op_keyword == "mutation";

        futures.push(tokio::spawn(async move {
            if rate_limit_ms > 0 {
                tokio::time::sleep(Duration::from_millis(rate_limit_ms)).await;
            }

            let mut req = build_graphql_request(&client, &url, transport, &query, None, is_mutation);
            for (k, v) in headers {
                req = req.header(k, v);
            }

            let field_part = query.split_whitespace().nth(2).unwrap_or("unknown");
            let label = format!("{}.{}", root, field_part);

            let resp = req.send().await;

            match resp {
                Ok(r) => {
                    let status = r.status().as_u16();
                    if status == 401 || status == 403 {
                        return (label, status, None);
                    }
                    let parsed: Result<ProbeResponse, _> = r.json().await;
                    (label, status, Some(parsed))
                }
                Err(_) => (label, 0, None),
            }
        }));
    }

    while let Some(res) = futures.next().await {
        process_discovery_result(res, &mut result);
    }

    Ok(result)
}

type DiscoveryResult = (String, u16, Option<Result<ProbeResponse, reqwest::Error>>);

fn process_discovery_result(
    res: Result<DiscoveryResult, tokio::task::JoinError>,
    result: &mut AuthDiscoveryResult,
) {
    if let Ok((label, status, parsed_opt)) = res {
        if status == 401 || status == 403 {
            result.protected.push(label);
            return;
        }

        if status == 0 {
            result
                .inconclusive
                .push(format!("{} (network error)", label));
            return;
        }

        if let Some(parsed_res) = parsed_opt {
            match parsed_res {
                Ok(parsed) => {
                    if let Some(errors) = parsed.errors {
                        let messages = errors
                            .iter()
                            .map(|e| e.message.to_lowercase())
                            .collect::<Vec<_>>()
                            .join(" | ");

                        if is_auth_error(&messages) {
                            result.protected.push(label);
                        } else if is_public_likely_error(&messages) {
                            result.public.push(label);
                        } else {
                            result
                                .inconclusive
                                .push(format!("{} (graphql error: {})", label, messages));
                        }
                    } else if parsed.data.is_some() {
                        result.public.push(label);
                    } else {
                        result.inconclusive.push(format!("{} (no data)", label));
                    }
                }
                Err(_) => {
                    result
                        .inconclusive
                        .push(format!("{} (non-JSON response)", label));
                }
            }
        } else {
            result
                .inconclusive
                .push(format!("{} (unknown error)", label));
        }
    }
}
