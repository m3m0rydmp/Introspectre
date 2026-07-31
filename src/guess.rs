use crate::types::{GqlSchema, GqlType, GqlField, GqlTypeRef, NamedRef};
use crate::audit::utils::post_graphql;
use reqwest::Client;
use std::collections::{HashSet, VecDeque};
use colored::Colorize;
use futures::stream::{StreamExt, futures_unordered::FuturesUnordered};

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
    
    let mut discovered_fields = HashSet::new();
    let mut type_map: std::collections::HashMap<String, GqlType> = std::collections::HashMap::new();
    
    // Initial guess for root fields
    let mut queue = VecDeque::new();
    queue.push_back("Query".to_string());

    // Simple implementation for now: probe root fields from wordlist
    let mut futures = FuturesUnordered::new();
    let mut current_concurrency = initial_concurrency;

    for word in wordlist {
        while futures.len() >= current_concurrency {
            if let Some(res) = futures.next().await {
                let res: Result<Result<Option<(String, Vec<String>, u128)>, ()>, tokio::task::JoinError> = res;
                if let Ok(Ok(Some((field, suggestions, elapsed_ms)))) = res {
                    if !field.is_empty() {
                        discovered_fields.insert(field);
                    }
                    for s in suggestions {
                        discovered_fields.insert(s);
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

        let word_clone = word.clone();
        let client_clone = client.clone();
        let url_clone = url.to_string();
        let headers_clone = headers.to_owned();

        futures.push(tokio::spawn(async move {
            let query = format!("query {{ {} {{ __typename }} }}", word_clone);
            let resp = post_graphql(&client_clone, &url_clone, &headers_clone, &query, rate_limit_ms).await;
            
            match resp {
                Ok(r) => {
                    let mut suggestions = Vec::new();
                    let exists = r.data.is_some()
                        || (!r.errors_text.is_empty()
                            && !r.errors_text.contains("Cannot query field")
                            && !r.errors_text.contains("not defined"));
                    let elapsed_ms = r.elapsed_ms;
                    
                    // Parse suggestions from errors
                    let errors: Vec<crate::types::GqlError> = serde_json::from_str(&r.errors_text).unwrap_or_default();
                    for err_obj in errors {
                        suggestions.extend(crate::utils::parse_did_you_mean(&err_obj.message));
                    }

                    if exists {
                        Ok(Some((word_clone, suggestions, elapsed_ms)))
                    } else if !suggestions.is_empty() {
                         // Even if the word didn't exist, suggestions are gold
                         Ok(Some(("".to_string(), suggestions, elapsed_ms)))
                    } else {
                        Err(())
                    }
                },
                Err(_) => Err(()),
            }
        }));
    }

    while let Some(res) = futures.next().await {
        let res: Result<Result<Option<(String, Vec<String>, u128)>, ()>, tokio::task::JoinError> = res;
        if let Ok(Ok(Some((field, suggestions, _)))) = res {
            if !field.is_empty() {
                discovered_fields.insert(field);
            }
            for s in suggestions {
                discovered_fields.insert(s);
            }
        }
    }

    let gql_fields: Vec<GqlField> = discovered_fields.into_iter().map(|name| GqlField {
        name,
        is_deprecated: None,
        deprecation_reason: None,
        field_type: Some(GqlTypeRef {
            kind: Some("SCALAR".to_string()), // We don't know the type, assume scalar or unknown
            name: Some("String".to_string()),
            of_type: None,
        }),
        args: None,
    }).collect();

    let query_type = GqlType {
        kind: Some("OBJECT".to_string()),
        name: Some("Query".to_string()),
        description: None,
        fields: Some(gql_fields),
        input_fields: None,
        enum_values: None,
        possible_types: None,
    };

    type_map.insert("Query".to_string(), query_type);

    Ok(GqlSchema {
        query_type: Some(NamedRef { name: "Query".to_string() }),
        mutation_type: None,
        subscription_type: None,
        directives: None,
        types: type_map.into_values().collect(),
    })
}
