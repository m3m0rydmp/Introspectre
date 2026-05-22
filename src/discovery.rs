use crate::audit::utils::post_graphql;
use reqwest::Client;
use std::path::PathBuf;
use futures::stream::{StreamExt, futures_unordered::FuturesUnordered};
use colored::Colorize;

pub async fn run_discovery(
    url: &str,
    client: &Client,
    wordlist_path: Option<PathBuf>,
    initial_concurrency: usize,
    dynamic_throttling: bool,
    rate_limit_ms: u64,
    verbose: bool,
) -> Result<Vec<String>, String> {
    let words = if let Some(path) = wordlist_path {
        std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read wordlist: {}", e))?
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<String>>()
    } else {
        vec![
            "me", "users", "admin", "config", "settings", "login", "auth", "profile",
            "accounts", "nodes", "items", "search", "version", "health", "status",
            "debug", "internal", "root", "api", "v1", "v2", "db", "database",
            "file", "files", "upload", "download", "token", "tokens", "key", "keys",
            "secrets", "credentials", "passwords", "emails", "clients", "customers"
        ].into_iter().map(|s| s.to_string()).collect()
    };

    if verbose {
        println!("{} Starting blind field discovery on {} using {} words...", "→".blue(), url, words.len());
    }

    let mut discovered = Vec::new();
    let mut futures = FuturesUnordered::new();
    
    let words_count = words.len();
    let mut processed = 0;
    let mut current_concurrency = initial_concurrency;

    for word in words {
        while futures.len() >= current_concurrency {
            if let Some(res) = futures.next().await {
                let res: Result<Result<(String, u128), ()>, tokio::task::JoinError> = res;
                if let Ok(Ok((found_word, elapsed_ms))) = res {
                    if !found_word.is_empty() {
                        discovered.push(found_word);
                    }
                    if dynamic_throttling {
                        if elapsed_ms > 1500 && current_concurrency > 1 {
                            current_concurrency -= 1;
                        } else if elapsed_ms < 500 && current_concurrency < initial_concurrency * 2 {
                            current_concurrency += 1;
                        }
                    }
                }
                processed += 1;
                if verbose && processed % 10 == 0 {
                    print!("\r  Progress: {}/{} (concurrency: {})", processed, words_count, current_concurrency);
                    use std::io::Write;
                    std::io::stdout().flush().unwrap();
                }
            }
        }

        let word_clone = word.clone();
        let client_clone = client.clone();
        let url_clone = url.to_string();

        futures.push(tokio::spawn(async move {
            let query = format!("query {{ {} {{ __typename }} }}", word_clone);
            let headers = vec![]; 
            let resp = post_graphql(&client_clone, &url_clone, &headers, &query, rate_limit_ms).await;
            
            match resp {
                Ok(r) => {
                    let exists = r.data.is_some() || 
                                (!r.errors_text.is_empty() && 
                                 !r.errors_text.contains("Cannot query field") &&
                                 !r.errors_text.contains("not defined"));
                    
                    if exists {
                        Ok((word_clone, r.elapsed_ms))
                    } else {
                        Ok(("".to_string(), r.elapsed_ms))
                    }
                },
                Err(_) => Err(()),
            }
        }));
    }

    while let Some(res) = futures.next().await {
        let res: Result<Result<(String, u128), ()>, tokio::task::JoinError> = res;
        if let Ok(Ok((found_word, _))) = res {
            if !found_word.is_empty() {
                discovered.push(found_word);
            }
        }
    }
    if verbose {
        println!("\r  Progress: {}/{}", words_count, words_count);
    }

    Ok(discovered)
}
