use colored::Colorize;
use crate::audit::utils::{
    build_operation_query, effective_headers
};
use crate::config::AppConfig;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, Severity};
use reqwest::Client;
use std::collections::HashMap;

pub async fn probe_command_injection(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    evasion_level: u8,
    config: &AppConfig,
    confirmed: &mut Vec<Finding>,
    _unconfirmed: &mut Vec<Finding>,
) -> Result<(), String> {
    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let mutation_name = schema.mutation_type.as_ref().map(|m| m.name.as_str());

    let mut targets = Vec::new();
    for (op, root) in [("query", query_name), ("mutation", mutation_name)] {
        for field in schema.fields_for_type(root) {
            if let Some(args) = &field.args {
                for arg in args {
                    // Skip args with no type info instead of panicking on a partial schema.
                    let Some(arg_type) = arg.arg_type.as_ref() else { continue; };
                    let paths = find_injectable_paths(schema, arg_type, &arg.name);
                    for path in paths {
                        targets.push((op, root.unwrap_or("?"), field, arg, path));
                    }
                }
            }
        }
    }

    let headers = effective_headers(extra_headers, None, false);
    
    // Time-based detection payloads
    let payloads = [
        ("; sleep 5", 5000),
        ("| sleep 5", 5000),
        ("`sleep 5` project", 5000),
        ("$(sleep 5)", 5000),
        ("&& sleep 5", 5000),
    ];

    for (op, root, field, arg, path) in targets {
        eprintln!("  {} Testing Command Injection on {}.{}({})...", "→".cyan(), root, field.name, path);
        for (payload, expected_delay_ms) in &payloads {
            let mut overrides = HashMap::new();
            let payload_val = serde_json::Value::String(payload.to_string());
            overrides.insert(arg.name.clone(), build_nested_value(&path, &arg.name, payload_val));
            
            let gql_op = build_operation_query(schema, op, field, &overrides, &config.audit.seeds, false);
            
            let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op.query, Some(gql_op.variables), rate_limit_ms, evasion_level).await?;
            // Use the response's own network timing, which EXCLUDES the pre-request
            // rate-limit sleep. Timing the whole call would count the throttle delay and
            // false-positive on every argument whenever rate_limit_ms is large (>= 5s).
            let elapsed = resp.elapsed_ms as u128;

            // Time-based signal: the payload requested a ~5s shell sleep.
            if elapsed >= *expected_delay_ms as u128 {
                confirmed.push(Finding {
                    id: "os-command-injection",
                    severity: Severity::Critical,
                    title: "OS Command Injection (Time-Based) Confirmed",
                    description: format!(
                        "### Analysis\n\
                         The server response was delayed by a significant amount when a time-based payload was injected. This indicates the input is being executed directly in a shell environment.\n\n\
                         ### Evidence\n\
                         - **Argument Path**: `{}` in `{}.{}`\n\
                         - **Trigger Payload**: `{}`\n\
                         - **Measured Latency**: {}ms (Expected: {}ms)",
                        path, root, field.name, payload, elapsed, expected_delay_ms
                    ),
                    affected: vec![AffectedLocation::Argument(root.into(), field.name.clone(), path.clone())],
                    remediation: "Never pass user input directly to system commands or shell executors. Use language-native APIs for file operations and process execution, and strictly validate all input against an allow-list.",
                    first_step: Some(format!("Execute the PoC query and observe the response delay of approximately {} seconds.", expected_delay_ms / 1000)),
                    references: vec!["CWE-78: OS Command Injection", "OWASP API8: Injection"],
                    status: FindingStatus::Confirmed,
                    confidence: Confidence::Confirmed,
                    evidence_level: EvidenceLevel::Executed,
                    poc: Some(gql_op.query),
                });
                break; // Found one for this path, move to next target
            }
        }
    }

    Ok(())
}

fn find_injectable_paths(schema: &GqlSchema, arg_type: &crate::types::GqlTypeRef, current_path: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let type_name = arg_type.unwrap_type_name();
    
    if let Some(tn) = type_name {
        if tn == "String" || tn == "ID" {
            paths.push(current_path.to_string());
        } else if let Some(gql_type) = schema.find_type(&tn) {
            if gql_type.kind.as_deref() == Some("INPUT_OBJECT") {
                if let Some(fields) = &gql_type.input_fields {
                    for f in fields {
                        if let Some(ft) = &f.field_type {
                            let sub_path = format!("{}.{}", current_path, f.name);
                            paths.extend(find_injectable_paths(schema, ft, &sub_path));
                        }
                    }
                }
            }
        }
    }
    paths
}

fn build_nested_value(full_path: &str, arg_name: &str, value: serde_json::Value) -> serde_json::Value {
    let relative_path = if full_path.starts_with(arg_name) {
        if full_path.len() > arg_name.len() {
            &full_path[arg_name.len() + 1..]
        } else {
            ""
        }
    } else {
        full_path
    };

    if relative_path.is_empty() {
        return value;
    }

    let parts: Vec<&str> = relative_path.split('.').collect();
    let mut current = value;

    for &part in parts.iter().rev() {
        let mut map = serde_json::Map::new();
        map.insert(part.to_string(), current);
        current = serde_json::Value::Object(map);
    }

    current
}
