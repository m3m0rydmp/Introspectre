use crate::types::{GqlSchema, GqlType, GqlField, GqlTypeRef, NamedRef};
use crate::audit::utils::post_graphql;
use reqwest::Client;
use std::collections::{HashMap, HashSet};
use colored::Colorize;
use futures::stream::{StreamExt, futures_unordered::FuturesUnordered};

/// True when a GraphQL error indicates the probed field does **not** exist on
/// the type. Covers the phrasings used by the common server implementations —
/// Apollo/graphql-js ("Cannot query field"), graphql-ruby ("doesn't exist on
/// type"), and others ("not defined", "undefinedField"). Anything else (e.g. a
/// "must have selections" or "argument required" error) means the field *does*
/// exist and our probe was merely incomplete.
fn field_missing(errors_text: &str) -> bool {
    let e = errors_text.to_ascii_lowercase();
    e.contains("cannot query field")
        || e.contains("doesn't exist on type")
        || e.contains("does not exist on type")
        || e.contains("undefinedfield")
        || e.contains("not defined")
}

/// The first identifier appearing after `marker` in `s`, skipping any leading
/// non-identifier characters (quotes, `[`, spaces) so it also works on wrapped
/// type refs like `"[User!]!"`.
fn first_ident_after(s: &str, marker: &str) -> Option<String> {
    let idx = s.find(marker)?;
    let rest = &s[idx + marker.len()..];
    let rest = rest.trim_start_matches(|c: char| !(c.is_alphanumeric() || c == '_'));
    let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Extract a leaked object return type from a "must have a selection" error,
/// which servers emit when an object-typed field is queried with no subfields.
/// Handles graphql-ruby ("field 'x' returns User but has no selections") and
/// graphql-js ("Field 'x' of type 'User' must have a selection of subfields").
/// Returns `None` when the message carries no such leak.
fn parse_return_type(errors_text: &str) -> Option<String> {
    if errors_text.contains("has no selections") {
        if let Some(t) = first_ident_after(errors_text, "returns ") {
            return Some(t);
        }
    }
    if errors_text.contains("must have a selection") {
        if let Some(t) = first_ident_after(errors_text, "of type ") {
            return Some(t);
        }
    }
    None
}

pub async fn run_guess(
    url: &str,
    client: &Client,
    headers: &[(String, String)],
    wordlist: &[String],
    initial_concurrency: usize,
    dynamic_throttling: bool,
    rate_limit_ms: u64,
    verbose: bool,
) -> Result<GqlSchema, String> {
    if verbose {
        println!("  {} Starting blind schema reconstruction (brute mode)...", "→".blue());
    }
    
    // field name -> optional leaked return type (None = type unknown).
    let mut discovered: HashMap<String, Option<String>> = HashMap::new();
    let record = |name: String, ret: Option<String>, map: &mut HashMap<String, Option<String>>| {
        if name.is_empty() {
            return;
        }
        let slot = map.entry(name).or_insert(None);
        if ret.is_some() {
            *slot = ret; // upgrade an unknown type once we learn it
        }
    };

    let mut type_map: HashMap<String, GqlType> = HashMap::new();

    // Probe root fields from the wordlist.
    let mut futures = FuturesUnordered::new();
    let mut current_concurrency = initial_concurrency;

    for word in wordlist {
        while futures.len() >= current_concurrency {
            if let Some(res) = futures.next().await {
                let res: Result<Result<Option<(String, Option<String>, Vec<String>, u128)>, ()>, tokio::task::JoinError> = res;
                if let Ok(Ok(Some((field, ret_type, suggestions, elapsed_ms)))) = res {
                    record(field, ret_type, &mut discovered);
                    for s in suggestions {
                        record(s, None, &mut discovered);
                    }

                    if dynamic_throttling {
                        if elapsed_ms > 1500 && current_concurrency > 1 {
                            current_concurrency -= 1;
                        } else if elapsed_ms < 500 && current_concurrency < initial_concurrency * 2 {
                            current_concurrency += 1;
                        }
                    }
                }
            }
        }

        if verbose {
            // Transient: overwrites in place; shows the current probe + tally.
            crate::progress::transient(&format!(
                "  {} brute: probing '{}' ({} fields discovered)",
                "→".blue(),
                word,
                discovered.len()
            ));
        }

        let word_clone = word.clone();
        let client_clone = client.clone();
        let url_clone = url.to_string();
        let headers_clone = headers.to_owned();

        futures.push(tokio::spawn(async move {
            // Probe WITHOUT a selection set: this is a validation-only query (no
            // resolver runs), a non-existent field errors "doesn't exist", and an
            // object field errors "must have selections" — which leaks its return
            // type. Scalar fields simply resolve and return data.
            let query = format!("{{ {} }}", word_clone);
            let resp = post_graphql(&client_clone, &url_clone, &headers_clone, &query, rate_limit_ms).await;

            match resp {
                Ok(r) => {
                    let mut suggestions = Vec::new();
                    // A field exists if it resolved (returned data) or the error
                    // is anything OTHER than a "field doesn't exist" error — e.g.
                    // a "must have selections"/"argument required" error, which
                    // only a real field produces.
                    let exists = r.data.is_some()
                        || (!r.errors_text.is_empty() && !field_missing(&r.errors_text));
                    // graphql-ruby leaks the object return type in the selection
                    // error ("returns User but has no selections").
                    let return_type = parse_return_type(&r.errors_text);
                    let elapsed_ms = r.elapsed_ms;

                    // Parse suggestions from errors
                    let errors: Vec<crate::types::GqlError> = serde_json::from_str(&r.errors_text).unwrap_or_default();
                    for err_obj in errors {
                        suggestions.extend(crate::utils::parse_did_you_mean(&err_obj.message));
                    }

                    if exists {
                        Ok(Some((word_clone, return_type, suggestions, elapsed_ms)))
                    } else if !suggestions.is_empty() {
                        // Even if the word didn't exist, its suggestions are gold.
                        Ok(Some(("".to_string(), None, suggestions, elapsed_ms)))
                    } else {
                        Err(())
                    }
                },
                Err(_) => Err(()),
            }
        }));
    }

    while let Some(res) = futures.next().await {
        let res: Result<Result<Option<(String, Option<String>, Vec<String>, u128)>, ()>, tokio::task::JoinError> = res;
        if let Ok(Ok(Some((field, ret_type, suggestions, _)))) = res {
            record(field, ret_type, &mut discovered);
            for s in suggestions {
                record(s, None, &mut discovered);
            }
        }
    }

    crate::progress::clear();
    // Always report what was reconstructed (brute's whole purpose) — previously this only
    // showed under --verbose, so a default run looked like it did nothing.
    crate::progress::persistent(&format!(
        "  {} brute: reconstruction complete — {} candidate field(s) discovered.",
        "✓".green(),
        discovered.len()
    ));
    if !discovered.is_empty() {
        let mut names: Vec<&str> = discovered.keys().map(|s| s.as_str()).collect();
        names.sort_unstable();
        let shown = names.iter().take(40).cloned().collect::<Vec<_>>().join(", ");
        let more = if names.len() > 40 {
            format!(" … (+{} more)", names.len() - 40)
        } else {
            String::new()
        };
        crate::progress::persistent(&format!("    {}{}", shown.bright_white(), more));
    }

    // Build the Query fields, using leaked return types where known (falling back
    // to an opaque String scalar otherwise), and add stub object types for each
    // referenced return type so the graph has real nodes to point at.
    let mut referenced_types: HashSet<String> = HashSet::new();
    let gql_fields: Vec<GqlField> = discovered
        .into_iter()
        .map(|(name, ret)| {
            let field_type = match &ret {
                Some(tn) => {
                    referenced_types.insert(tn.clone());
                    GqlTypeRef { kind: Some("OBJECT".to_string()), name: Some(tn.clone()), of_type: None }
                }
                None => GqlTypeRef { kind: Some("SCALAR".to_string()), name: Some("String".to_string()), of_type: None },
            };
            GqlField { name, is_deprecated: None, deprecation_reason: None, field_type: Some(field_type), args: None }
        })
        .collect();

    type_map.insert(
        "Query".to_string(),
        GqlType {
            kind: Some("OBJECT".to_string()),
            name: Some("Query".to_string()),
            description: None,
            fields: Some(gql_fields),
            input_fields: None,
            enum_values: None,
            possible_types: None,
        },
    );

    for tn in referenced_types {
        if tn == "Query" {
            continue;
        }
        type_map.entry(tn.clone()).or_insert_with(|| GqlType {
            kind: Some("OBJECT".to_string()),
            name: Some(tn.clone()),
            description: None,
            fields: Some(vec![]),
            input_fields: None,
            enum_values: None,
            possible_types: None,
        });
    }

    Ok(GqlSchema {
        query_type: Some(NamedRef { name: "Query".to_string() }),
        mutation_type: None,
        subscription_type: None,
        directives: None,
        types: type_map.into_values().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_covers_apollo_and_graphql_ruby() {
        assert!(field_missing("Cannot query field \"userz\" on type \"Query\"."));
        assert!(field_missing("Field 'userz' doesn't exist on type 'Query' (Did you mean `user`?)"));
        assert!(field_missing("Field 'x' is not defined"));
        // A selection/argument error on a REAL field is not "missing".
        assert!(!field_missing("Field must have selections (field 'user' returns User but has no selections)"));
        assert!(!field_missing(""));
    }

    #[test]
    fn parses_leaked_return_type() {
        // graphql-ruby
        assert_eq!(
            parse_return_type("Field must have selections (field 'user' returns User but has no selections. Did you mean 'user { ... }'?)"),
            Some("User".to_string())
        );
        assert_eq!(
            parse_return_type("field 'config' returns Config but has no selections"),
            Some("Config".to_string())
        );
        // graphql-js
        assert_eq!(
            parse_return_type("Field \"user\" of type \"User\" must have a selection of subfields. Did you mean \"user { ... }\"?"),
            Some("User".to_string())
        );
        // wrapped type ref
        assert_eq!(
            parse_return_type("Field \"cards\" of type \"[Card!]!\" must have a selection of subfields."),
            Some("Card".to_string())
        );
        // not a selection error
        assert_eq!(parse_return_type("Field 'userz' doesn't exist on type 'Query'"), None);
    }
}
