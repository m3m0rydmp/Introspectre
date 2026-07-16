use clap::ValueEnum;
use reqwest::{Client, RequestBuilder};
use serde_json::Value;

/// GraphQL transport used to deliver a request to the target endpoint.
/// `Auto` means "negotiate the best-working transport" — negotiation itself
/// happens in `io_ops::probe_graphql_endpoint`, not in this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Transport {
    /// Detect the best-working transport automatically.
    #[value(name = "auto")]
    Auto,
    /// Standard `POST` with a JSON body (the default GraphQL transport).
    #[value(name = "post-json")]
    PostJson,
    /// `GET` with `query`/`variables` in the query string. Cannot carry mutations.
    #[value(name = "get")]
    Get,
    /// `POST` with an `application/x-www-form-urlencoded` body.
    #[value(name = "form")]
    Form,
    /// `POST` with a raw `application/graphql` body (query only, no variables).
    #[value(name = "graphql")]
    Graphql,
}

/// Build a GraphQL request for the given transport, setting only the HTTP
/// method, `Content-Type`, and body. The caller adds auth/extra headers and
/// calls `.send()`.
///
/// `Auto` is treated the same as `PostJson` here — auto-negotiation happens
/// one level up, in `io_ops::probe_graphql_endpoint`, which resolves `Auto`
/// to a concrete transport before the rest of the run uses it.
pub fn build_graphql_request(
    client: &Client,
    url: &str,
    transport: Transport,
    query: &str,
    variables: Option<&Value>,
    is_mutation: bool,
) -> RequestBuilder {
    match transport {
        Transport::PostJson | Transport::Auto => post_json_request(client, url, query, variables),
        Transport::Get => {
            if is_mutation {
                // GET can't safely carry mutations (spec / CSRF concerns) — fall back to POST+JSON.
                return post_json_request(client, url, query, variables);
            }
            let mut params: Vec<(&str, String)> = vec![("query", query.to_string())];
            if let Some(vars) = variables {
                if !vars.is_null() {
                    params.push(("variables", vars.to_string()));
                }
            }
            client.get(url).query(&params)
        }
        Transport::Form => {
            let mut body = format!("query={}", urlencoding::encode(query));
            if let Some(vars) = variables {
                if !vars.is_null() {
                    body.push_str(&format!("&variables={}", urlencoding::encode(&vars.to_string())));
                }
            }
            client
                .post(url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body)
        }
        Transport::Graphql => {
            // Raw `application/graphql` bodies carry the query only — if
            // variables were supplied they can't be represented and are dropped.
            client
                .post(url)
                .header("Content-Type", "application/graphql")
                .body(query.to_string())
        }
    }
}

fn post_json_request(client: &Client, url: &str, query: &str, variables: Option<&Value>) -> RequestBuilder {
    let body = match variables {
        Some(vars) => serde_json::json!({ "query": query, "variables": vars }),
        None => serde_json::json!({ "query": query }),
    };
    client.post(url).header("Content-Type", "application/json").json(&body)
}
