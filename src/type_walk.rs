//! Blind schema reconstruction via `__type`-walk.
//!
//! Many hardened GraphQL APIs "disable introspection" by removing only the
//! `__schema` root field while leaving `__type` reachable — often even to
//! unauthenticated callers. In that case `fetch_introspection`'s `__schema`
//! vectors all fail, but the schema is still fully reconstructable one type at
//! a time: `__type(name:"Query")` yields the root fields, each field's return
//! type points at another type, and a breadth-first walk over those names
//! rebuilds the graph.
//!
//! This module performs that walk and assembles a [`GqlSchema`] that the rest
//! of the analysis pipeline consumes exactly as if it had come from `__schema`.
//! It reuses the audit transport layer (`post_graphql_ext`) so transport,
//! rate-limiting, and response parsing behave identically to the active probes.

use crate::audit::utils::post_graphql_ext;
use crate::transport::Transport;
use crate::types::{GqlSchema, GqlType, NamedRef};
use colored::Colorize;
use reqwest::Client;
use serde_json::Value;
use std::collections::{HashSet, VecDeque};

// The reconstruction cap (default 1000, config `audit.max_type_walk_types`,
// 0 = unlimited) is passed in by the caller — see `reconstruct_via_type_walk`.

/// Standard built-in scalars that never need a `__type` round-trip.
const BUILTIN_SCALARS: &[&str] = &["String", "Int", "Float", "Boolean", "ID"];

/// True for names we should not spend a request on: introspection meta-types
/// (`__Type`, `__Schema`, …) and the standard built-in scalars.
fn is_builtin(name: &str) -> bool {
    name.starts_with("__") || BUILTIN_SCALARS.contains(&name)
}

/// Build a bounded `ofType` reference selection with `depth` levels of wrapper
/// nesting. GraphQL wraps list/non-null modifiers as nested `ofType`, so a real
/// type like `[T!]!` needs ~3 levels; depth 4 covers realistic wrappers while
/// staying under servers that cap introspection nesting (e.g. an `ofType`
/// depth-3 guard).
fn type_ref_selection(depth: u8) -> String {
    if depth == 0 {
        "kind name".to_string()
    } else {
        format!("kind name ofType {{ {} }}", type_ref_selection(depth - 1))
    }
}

/// The per-type introspection query, mirroring the `FullType` fragment used for
/// `__schema` but scoped to a single named type and with a bounded `ofType`
/// nesting (`ref_depth`).
fn type_query(name: &str, ref_depth: u8) -> String {
    let r = type_ref_selection(ref_depth);
    format!(
        "{{ __type(name: \"{name}\") {{ kind name description \
         fields(includeDeprecated: true) {{ name description isDeprecated deprecationReason \
         args {{ name type {{ {r} }} }} type {{ {r} }} }} \
         inputFields {{ name type {{ {r} }} }} \
         enumValues(includeDeprecated: true) {{ name isDeprecated }} \
         interfaces {{ {r} }} \
         possibleTypes {{ {r} }} }} }}"
    )
}

/// Push `name` onto the walk queue unless it is a built-in or already seen.
fn seed(name: String, queue: &mut VecDeque<String>, visited: &mut HashSet<String>) {
    if !is_builtin(&name) && visited.insert(name.clone()) {
        queue.push_back(name);
    }
}

/// Collect the referenced type names reachable from a parsed [`GqlType`] —
/// field return types, field-argument types, input-field types, and union
/// `possibleTypes` — using the existing wrapper-unwrapping logic. Built-ins are
/// filtered by the caller via [`seed`].
fn collect_neighbours(t: &GqlType) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(fields) = &t.fields {
        for f in fields {
            if let Some(ft) = &f.field_type {
                if let Some(n) = ft.unwrap_type_name() {
                    out.push(n);
                }
            }
            if let Some(args) = &f.args {
                for a in args {
                    if let Some(at) = &a.arg_type {
                        if let Some(n) = at.unwrap_type_name() {
                            out.push(n);
                        }
                    }
                }
            }
        }
    }
    if let Some(input_fields) = &t.input_fields {
        for inf in input_fields {
            if let Some(ft) = &inf.field_type {
                if let Some(n) = ft.unwrap_type_name() {
                    out.push(n);
                }
            }
        }
    }
    if let Some(possible) = &t.possible_types {
        for pt in possible {
            if let Some(n) = pt.unwrap_type_name() {
                out.push(n);
            }
        }
    }
    out
}

/// Interface names implemented by a type. Interfaces are not stored on
/// [`GqlType`], so they are read straight from the raw JSON purely to keep the
/// walk reaching interface types (whose fields are analysis-relevant).
fn interface_names(raw: &Value) -> Vec<String> {
    raw.get("interfaces")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|it| it.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Discover the real query root type name via top-level `{ __typename }`, which
/// resolves to the query root object's name even when it has been renamed away
/// from the conventional `Query`.
async fn discover_query_root(
    client: &Client,
    url: &str,
    headers: &[(String, String)],
    rate_limit_ms: u64,
    transport: Transport,
) -> Option<String> {
    let resp = post_graphql_ext(
        client, url, headers, "{ __typename }", None, rate_limit_ms, 0, transport, false,
    )
    .await
    .ok()?;
    resp.data
        .as_ref()?
        .get("__typename")?
        .as_str()
        .map(String::from)
}

/// A low-complexity `__type` query: type kind/name and each field's name + return
/// type (with a short `ofType` chain), plus input-field types. Drops args,
/// enum values, interfaces, possibleTypes, and descriptions — enough to rebuild
/// the type graph even on servers that reject the full `FullType` query via a
/// query **depth/complexity** limit (as DVGA's "Deep Recursion" guard does).
fn type_query_minimal(name: &str) -> String {
    format!(
        "{{ __type(name: \"{name}\") {{ kind name \
         fields {{ name type {{ kind name ofType {{ kind name }} }} }} \
         inputFields {{ name type {{ kind name ofType {{ kind name }} }} }} }} }}"
    )
}

/// Fetch one type by name, returning the raw `__type` JSON object on success.
/// Tries the full reference selection at depth 4, then depth 2, then a stripped
/// **minimal** query. It advances to the next (shallower/simpler) attempt on
/// *either* a GraphQL error (e.g. an introspection nesting/complexity cap) *or* a
/// transport error (some servers reset the connection on an over-deep query),
/// only giving up on a type when it's genuinely absent (null with no error).
async fn fetch_type(
    client: &Client,
    url: &str,
    headers: &[(String, String)],
    rate_limit_ms: u64,
    transport: Transport,
    name: &str,
) -> Option<Value> {
    let attempts = [type_query(name, 4), type_query(name, 2), type_query_minimal(name)];
    let last = attempts.len() - 1;
    for (i, query) in attempts.iter().enumerate() {
        match post_graphql_ext(
            client, url, headers, query, None, rate_limit_ms, 0, transport, false,
        )
        .await
        {
            Ok(resp) => {
                if let Some(t) = resp.data.as_ref().and_then(|d| d.get("__type")) {
                    if !t.is_null() {
                        return Some(t.clone());
                    }
                }
                // `__type` is null/absent. Only conclude the type genuinely does not
                // exist on the **final** (simplest) attempt with no server error.
                // Earlier attempts that come back empty may just have been rejected by
                // a depth/complexity guard (clean GraphQL error) or a swallowed
                // decode error (empty body) — fall through to the next, simpler query.
                if resp.errors_text.is_empty() && i == last {
                    return None;
                }
            }
            // Transport-level failure (e.g. the server reset the connection on an
            // over-deep query): try the next, simpler attempt rather than give up.
            Err(_) => continue,
        }
    }
    None
}

/// Reconstruct a schema by walking `__type` breadth-first from the root types.
///
/// `headers` must already be parsed and include an `Authorization` header when
/// a token is in play (the caller in `io_ops` handles that). Returns `Err` only
/// when nothing at all could be reconstructed, so the caller can fall back to
/// its existing "introspection disabled" messaging.
pub async fn reconstruct_via_type_walk(
    client: &Client,
    url: &str,
    headers: &[(String, String)],
    rate_limit_ms: u64,
    transport: Transport,
    verbose: bool,
    max_types: usize,
) -> Result<GqlSchema, String> {
    // 0 = unlimited; otherwise use the configured cap.
    let cap = if max_types == 0 { usize::MAX } else { max_types };

    // Shown by default (not just under --verbose): the user should always know
    // introspection fell back to the slower `__type`-walk.
    crate::progress::persistent(&format!(
        "  {} `__schema` blocked — attempting `__type`-walk reconstruction...",
        "→".blue()
    ));

    let query_root =
        discover_query_root(client, url, headers, rate_limit_ms, transport)
            .await
            .unwrap_or_else(|| "Query".to_string());

    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();

    // Seed the discovered query root plus the conventional root names (in case
    // mutation/subscription are present under standard names).
    for root in [
        query_root.clone(),
        "Query".to_string(),
        "Mutation".to_string(),
        "Subscription".to_string(),
    ] {
        seed(root, &mut queue, &mut visited);
    }

    let mut types: Vec<GqlType> = Vec::new();
    let mut resolved: HashSet<String> = HashSet::new();
    let mut capped = false;

    while let Some(name) = queue.pop_front() {
        if types.len() >= cap {
            capped = true;
            break;
        }

        if verbose {
            // Transient: high-frequency live status, overwrites itself in place.
            crate::progress::transient(&format!(
                "  {} `__type`-walk: fetching {} ({} types, {} queued)",
                "→".blue(),
                name,
                types.len(),
                queue.len()
            ));
        }

        let raw = match fetch_type(client, url, headers, rate_limit_ms, transport, &name).await {
            Some(v) => v,
            None => continue,
        };

        let parsed: GqlType = match serde_json::from_value(raw.clone()) {
            Ok(t) => t,
            Err(_) => continue,
        };

        resolved.insert(name.clone());
        for n in collect_neighbours(&parsed) {
            seed(n, &mut queue, &mut visited);
        }
        for n in interface_names(&raw) {
            seed(n, &mut queue, &mut visited);
        }
        types.push(parsed);
    }

    // Erase any lingering transient status line before the caller prints its
    // persistent summary.
    crate::progress::clear();

    if types.is_empty() {
        return Err("`__type`-walk reconstruction found no types.".to_string());
    }

    // Shown by default: a partial schema is important enough that the user
    // should always see it (and know the cap is configurable), not only under
    // --verbose. Cancel and raise `audit.max_type_walk_types` in config (0 =
    // unlimited) to reconstruct the full schema.
    if capped {
        crate::progress::persistent(&format!(
            "  {} `__type`-walk hit the {}-type cap; schema is PARTIAL. Raise `audit.max_type_walk_types` in your config (0 = unlimited) and re-run to reconstruct more.",
            "!".yellow().bold(),
            cap
        ));
    }

    let query_type = if resolved.contains(&query_root) {
        Some(NamedRef { name: query_root })
    } else if resolved.contains("Query") {
        Some(NamedRef { name: "Query".to_string() })
    } else {
        None
    };
    let mutation_type = resolved
        .contains("Mutation")
        .then(|| NamedRef { name: "Mutation".to_string() });
    let subscription_type = resolved
        .contains("Subscription")
        .then(|| NamedRef { name: "Subscription".to_string() });

    Ok(GqlSchema {
        query_type,
        mutation_type,
        subscription_type,
        directives: None,
        types,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ref_selection_nests_to_depth() {
        assert_eq!(type_ref_selection(0), "kind name");
        assert_eq!(type_ref_selection(1), "kind name ofType { kind name }");
        assert_eq!(
            type_ref_selection(2),
            "kind name ofType { kind name ofType { kind name } }"
        );
    }

    #[test]
    fn type_query_targets_the_named_type() {
        let q = type_query("User", 4);
        assert!(q.contains("__type(name: \"User\")"));
        assert!(q.contains("inputFields"));
        assert!(q.contains("possibleTypes"));
        assert!(q.contains("enumValues"));
    }

    #[test]
    fn builtins_are_skipped() {
        assert!(is_builtin("String"));
        assert!(is_builtin("Int"));
        assert!(is_builtin("__Type"));
        assert!(!is_builtin("User"));
        assert!(!is_builtin("SecretObject"));
    }

    #[test]
    fn parses_a_type_payload_and_collects_neighbours() {
        // A representative `data.__type` object as returned by a real server:
        // a Query root whose `user(id: ID!)` field returns a `User`, plus a
        // list field returning `[Post!]!` and a filter input.
        let raw = serde_json::json!({
            "kind": "OBJECT",
            "name": "Query",
            "description": null,
            "fields": [
                {
                    "name": "user",
                    "description": null,
                    "isDeprecated": false,
                    "deprecationReason": null,
                    "args": [
                        { "name": "id", "type": { "kind": "NON_NULL", "name": null,
                            "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } } }
                    ],
                    "type": { "kind": "OBJECT", "name": "User", "ofType": null }
                },
                {
                    "name": "posts",
                    "description": null,
                    "isDeprecated": false,
                    "deprecationReason": null,
                    "args": [
                        { "name": "filter", "type": { "kind": "INPUT_OBJECT", "name": "PostFilter", "ofType": null } }
                    ],
                    "type": { "kind": "NON_NULL", "name": null, "ofType": {
                        "kind": "LIST", "name": null, "ofType": {
                            "kind": "NON_NULL", "name": null, "ofType": {
                                "kind": "OBJECT", "name": "Post", "ofType": null } } } }
                }
            ],
            "inputFields": null,
            "enumValues": null,
            "interfaces": [ { "kind": "INTERFACE", "name": "Node", "ofType": null } ],
            "possibleTypes": null
        });

        let parsed: GqlType = serde_json::from_value(raw.clone()).expect("parses");
        assert_eq!(parsed.name.as_deref(), Some("Query"));
        assert_eq!(parsed.fields.as_ref().unwrap().len(), 2);

        let mut neighbours = collect_neighbours(&parsed);
        neighbours.extend(interface_names(&raw));
        // Built-in `ID` is present in the raw refs; the walk filters it at seed
        // time, so it may appear here but must never be the *only* thing.
        assert!(neighbours.contains(&"User".to_string()));
        assert!(neighbours.contains(&"Post".to_string()));
        assert!(neighbours.contains(&"PostFilter".to_string()));
        assert!(neighbours.contains(&"Node".to_string()));
    }

    #[test]
    fn seed_dedups_and_filters_builtins() {
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        seed("User".to_string(), &mut queue, &mut visited);
        seed("User".to_string(), &mut queue, &mut visited); // duplicate
        seed("String".to_string(), &mut queue, &mut visited); // built-in
        seed("__Type".to_string(), &mut queue, &mut visited); // introspection meta

        assert_eq!(queue.len(), 1);
        assert_eq!(queue.pop_front().as_deref(), Some("User"));
    }
}
