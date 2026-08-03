//! GraphQL **server framework** fingerprinting (graphw00f-style).
//!
//! Different GraphQL server implementations answer malformed/edge-case queries
//! with distinctive error phrasings and headers. This module sends a couple of
//! benign, discriminating probes and matches the responses to a framework +
//! language, so the operator knows what stack they're testing (and, later, so
//! payloads/probes can be tuned per ecosystem).
//!
//! It is **heuristic** — like graphw00f — and honest: it returns `None` rather
//! than guess when nothing matches confidently. Detection is safe reconnaissance
//! (a few invalid queries; no injection or DoS).

use std::collections::HashMap;

use crate::transport::Transport;
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// A detected GraphQL server framework. Owned `String` fields so it round-trips
/// through the scan cache (`Deserialize`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerFingerprint {
    pub framework: String,
    pub language: String,
    /// "confirmed" (a highly specific signal) or "likely" (a shared-family signal).
    pub confidence: String,
    pub evidence: Vec<String>,
}

impl ServerFingerprint {
    /// Compact one-line label, e.g. `graphql-ruby (Ruby) [likely]`.
    pub fn label(&self) -> String {
        format!("{} ({}) [{}]", self.framework, self.language, self.confidence)
    }
}

fn fp(framework: &str, language: &str, confidence: &str, why: &str) -> ServerFingerprint {
    ServerFingerprint {
        framework: framework.to_string(),
        language: language.to_string(),
        confidence: confidence.to_string(),
        evidence: vec![why.to_string()],
    }
}

/// Pure matcher: classify a framework from response headers (lowercased keys)
/// and a lowercased haystack of the probe responses' error/raw text. Ordered
/// most-specific-first; the generic graphql-js family is the last resort.
pub fn classify(headers: &HashMap<String, String>, haystack: &str) -> Option<ServerFingerprint> {
    let h = |k: &str| headers.get(k).map(|s| s.as_str()).unwrap_or("");
    let cookies = h("set-cookie");
    let hay = haystack;

    // --- Header / hosted signals (most reliable) ---
    // Hasura: dedicated version header, x-hasura-*, or its distinctive error codes.
    if !h("x-graphql-engine-version").is_empty()
        || headers.keys().any(|k| k.starts_with("x-hasura"))
        || hay.contains("query_root")
        || hay.contains("constraint-violation")
        || hay.contains("validation-failed")
    {
        return Some(fp("Hasura", "Haskell", "confirmed", "Hasura header / query_root / validation-failed"));
    }
    // Apollo Server: apollo-* headers, persisted-query, or BAD_USER_INPUT — near-certain.
    if !h("apollo-require-preflight").is_empty()
        || !h("apollo-cache-control").is_empty()
        || !h("apollo-graphql-preview").is_empty()
        || hay.contains("persisted_query_not_found")
        || hay.contains("persistedquerynotfound")
        || hay.contains("bad_user_input")
    {
        return Some(fp(
            "Apollo Server / graphql-js",
            "JavaScript / TypeScript",
            "confirmed",
            "Apollo header / persisted-query / BAD_USER_INPUT",
        ));
    }
    if !h("x-amzn-requestid").is_empty() || !h("x-amzn-errortype").is_empty() || hay.contains("misdirectedrequest") {
        return Some(fp("AWS AppSync", "N/A (hosted)", "confirmed", "x-amzn AppSync headers"));
    }
    if hay.contains("wpgraphql") || !h("x-graphql-keys").is_empty() {
        return Some(fp("WPGraphQL", "PHP (WordPress)", "confirmed", "WPGraphQL markers"));
    }
    // Absinthe (Elixir) is commonly served by Cowboy.
    if h("server").contains("cowboy") {
        return Some(fp("Absinthe", "Elixir", "likely", "Cowboy (Elixir) server header"));
    }

    // --- Highly distinctive error phrasings ---
    // graphql-ruby: "Field 'x' doesn't exist on type 'Query'" / "Parse error on" / alias cap.
    if hay.contains("doesn't exist on type") || hay.contains("parse error on") || hay.contains("aliased too many times") {
        return Some(fp("graphql-ruby", "Ruby", "confirmed", "graphql-ruby error phrasing"));
    }
    // graphql-java family (also Spring GraphQL, Netflix DGS).
    if hay.contains("validation error of type") || hay.contains("fieldundefined") || hay.contains("invalidsyntax") {
        return Some(fp("graphql-java (Spring / DGS)", "Java / Kotlin", "confirmed", "graphql-java validation error"));
    }
    // Hot Chocolate (.NET): backtick-quoted "The field `x` does not exist on the type `Query`."
    if hay.contains("does not exist on the type") {
        return Some(fp("Hot Chocolate", "C# / .NET", "confirmed", "Hot Chocolate field error"));
    }
    // Sangria (Scala).
    if hay.contains("query does not pass validation") || hay.contains("violations:") {
        return Some(fp("Sangria", "Scala", "confirmed", "Sangria validation phrasing"));
    }
    // Absinthe (Elixir) exposes the default "RootQueryType".
    if hay.contains("rootquerytype") {
        return Some(fp("Absinthe", "Elixir", "confirmed", "Absinthe RootQueryType"));
    }
    // gqlgen (Go).
    if hay.contains("expected at least one definition") {
        return Some(fp("gqlgen", "Go", "likely", "gqlgen parse phrasing"));
    }
    // Ariadne (Python).
    if hay.contains("the query must be a string") {
        return Some(fp("Ariadne", "Python", "likely", "Ariadne 'query must be a string'"));
    }
    // Tartiflette (Python).
    if hay.contains("tartiflette") || hay.contains("< unknown > field") {
        return Some(fp("Tartiflette", "Python", "likely", "Tartiflette markers"));
    }
    // Graphene (Python) parse-error format: "Syntax Error GraphQL (1:1) ...".
    if hay.contains("syntax error graphql") {
        return Some(fp("Graphene", "Python", "likely", "Graphene 'Syntax Error GraphQL' format"));
    }
    // Mercurius (Fastify, JS).
    if hay.contains("unknown query") || cookies.contains("mercurius") {
        return Some(fp("Mercurius", "JavaScript / TypeScript", "likely", "Mercurius phrasing"));
    }

    // --- graphql-js family (Apollo Server / Yoga / express-graphql). Last resort. ---
    let js_family = hay.contains("graphql_validation_failed")
        || hay.contains("graphql_parse_failed")
        || (hay.contains("cannot query field") && hay.contains("did you mean"))
        || hay.contains("cannot query field");
    if js_family {
        // webonyx graphql-php tags errors with "category":"graphql".
        if hay.contains("\"category\":\"graphql\"") || hay.contains("category: graphql") {
            return Some(fp("graphql-php / Lighthouse", "PHP", "likely", "graphql-php 'category: graphql'"));
        }
        // Yoga/Envelop often expose these extension hints.
        if hay.contains("envelop") || hay.contains("graphql-yoga") || hay.contains("yoga") {
            return Some(fp("GraphQL Yoga / Envelop", "JavaScript / TypeScript", "likely", "Yoga/Envelop markers"));
        }
        let mut f = fp(
            "Apollo Server / graphql-js",
            "JavaScript / TypeScript",
            "likely",
            "graphql-js validation/parse error family",
        );
        if hay.contains("apollo") {
            f.confidence = "confirmed".to_string();
            f.evidence.push("Apollo marker present".to_string());
        }
        return Some(f);
    }

    None
}

/// Classify from the *schema shape* alone (no network) — auto-generated naming
/// conventions and custom scalars are strong, reliable signals for several
/// ecosystems. Runs before the active probes.
pub fn classify_from_schema(schema: &crate::types::GqlSchema) -> Option<ServerFingerprint> {
    let has_scalar = |name: &str| {
        schema.types.iter().any(|t| {
            t.kind.as_deref() == Some("SCALAR") && t.name.as_deref() == Some(name)
        })
    };
    let mutation_name = schema.mutation_type.as_ref().map(|m| m.name.as_str());
    let mut_fields: Vec<&str> = schema.fields_for_type(mutation_name).iter().map(|f| f.name.as_str()).collect();
    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let q_fields: Vec<&str> = schema.fields_for_type(query_name).iter().map(|f| f.name.as_str()).collect();

    // Hasura: auto-generated `_by_pk` / `insert_*` / `update_*` mutations and
    // Postgres scalars (`timestamptz`, `jsonb`, `uuid`).
    if has_scalar("timestamptz")
        || has_scalar("jsonb")
        || mut_fields.iter().any(|n| {
            n.ends_with("_by_pk") || n.starts_with("insert_") || n.starts_with("update_") || n.starts_with("delete_")
        })
    {
        return Some(fp("Hasura", "Haskell", "confirmed", "Hasura auto-generated schema (_by_pk / timestamptz)"));
    }
    // Strapi: pluralized UsersPermissions* types.
    if schema.types.iter().any(|t| t.name.as_deref().map(|n| n.contains("UsersPermissions")).unwrap_or(false)) {
        return Some(fp("Strapi", "JavaScript / TypeScript", "confirmed", "Strapi UsersPermissions types"));
    }
    // Prisma / Nexus: findMany / findUnique / findFirst root fields.
    if q_fields.iter().any(|n| n.starts_with("findMany") || n.starts_with("findUnique") || n.starts_with("findFirst")) {
        return Some(fp("Prisma / Nexus", "JavaScript / TypeScript", "likely", "Prisma-style findMany/findUnique fields"));
    }
    None
}

/// The two discriminating probes (invalid keyword + unknown field). Kept small
/// and benign.
const PROBE_QUERIES: &[&str] = &[
    "queryy { __typename }",
    "query { __introspectre_nonexistent_field }",
];

/// Send the probes and classify the server framework, or `None` if unknown.
/// A `schema` (when available) is consulted first — schema-shape signals are
/// reliable and free (no requests).
pub async fn detect_server(
    url: &str,
    client: &Client,
    headers: &[(String, String)],
    transport: Transport,
    rate_limit_ms: u64,
    schema: Option<&crate::types::GqlSchema>,
) -> Option<ServerFingerprint> {
    // Schema-shape signals first (free). A "confirmed" schema hit wins outright;
    // a weaker one is kept as a fallback if the probes don't identify anything.
    let schema_hit = schema.and_then(classify_from_schema);
    if let Some(f) = &schema_hit {
        if f.confidence == "confirmed" {
            return Some(f.clone());
        }
    }

    let mut haystack = String::new();
    let mut merged_headers: HashMap<String, String> = HashMap::new();

    for q in PROBE_QUERIES {
        if let Ok(resp) = crate::audit::utils::post_graphql_ext(
            client, url, headers, q, None, rate_limit_ms, 0, transport, false,
        )
        .await
        {
            haystack.push('\n');
            haystack.push_str(&resp.errors_text);
            haystack.push('\n');
            haystack.push_str(&resp.raw_text);
            for (k, v) in resp.headers {
                merged_headers
                    .entry(k.to_ascii_lowercase())
                    .or_insert_with(|| v.to_ascii_lowercase());
            }
        }
    }

    classify(&merged_headers, &haystack.to_ascii_lowercase()).or(schema_hit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn detects_graphql_ruby() {
        let hay = "{\"errors\":[{\"message\":\"field 'x' doesn't exist on type 'query'\"}]}";
        assert_eq!(classify(&hdr(&[]), hay).unwrap().framework, "graphql-ruby");
    }

    #[test]
    fn detects_graphql_java() {
        let hay = "{\"errors\":[{\"message\":\"validation error of type fieldundefined: field 'x'\"}]}";
        let f = classify(&hdr(&[]), hay).unwrap();
        assert!(f.framework.contains("graphql-java"));
        assert_eq!(f.language, "Java / Kotlin");
    }

    #[test]
    fn detects_hot_chocolate() {
        let hay = "the field `x` does not exist on the type `query`.";
        assert_eq!(classify(&hdr(&[]), hay).unwrap().framework, "Hot Chocolate");
    }

    #[test]
    fn detects_hasura_via_header() {
        let f = classify(&hdr(&[("x-hasura-role", "admin")]), "").unwrap();
        assert_eq!(f.framework, "Hasura");
        assert_eq!(f.confidence, "confirmed");
    }

    #[test]
    fn detects_absinthe_rootquerytype() {
        let hay = "cannot query field \"x\" on type \"rootquerytype\". did you mean";
        assert_eq!(classify(&hdr(&[]), hay).unwrap().framework, "Absinthe");
    }

    #[test]
    fn falls_back_to_graphql_js_family() {
        let hay = "{\"errors\":[{\"message\":\"cannot query field \\\"x\\\" on type \\\"query\\\". did you mean\",\"extensions\":{\"code\":\"graphql_validation_failed\"}}]}";
        let f = classify(&hdr(&[]), hay).unwrap();
        assert!(f.framework.contains("Apollo") || f.framework.contains("graphql-js"));
    }

    #[test]
    fn unknown_yields_none() {
        // A plain, non-distinctive JSON error must not be force-labeled.
        assert!(classify(&hdr(&[("server", "nginx")]), "{\"errors\":[{\"message\":\"unauthorized\"}]}").is_none());
    }
}
