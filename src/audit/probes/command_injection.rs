use colored::Colorize;
use crate::audit::targets::{build_nested_value, find_injectable_paths};
use crate::audit::utils::{
    build_operation_query, effective_headers
};
use crate::config::AppConfig;
use crate::transport::Transport;
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
    transport: Transport,
    ctx: &crate::audit::targets::ScopeCtx<'_>,
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
                    let paths = find_injectable_paths(schema, arg_type, &arg.name, crate::audit::targets::CMDI_LEAF_SCALARS);
                    for path in paths {
                        targets.push((op, root.unwrap_or("?"), field, arg, path));
                    }
                }
            }
        }
    }

    // Focus / rank by passive severity / cap to --max-targets before probing.
    let targets = crate::audit::targets::scope_targets(
        targets,
        ctx.sev_index,
        ctx.scope,
        |t| (t.1.to_string(), t.2.name.clone()),
    );

    let headers = effective_headers(extra_headers, None, false);
    
    // Time-based detection payloads
    let payloads = [
        ("; sleep 5", 5000),
        ("| sleep 5", 5000),
        ("`sleep 5` project", 5000),
        ("$(sleep 5)", 5000),
        ("&& sleep 5", 5000),
    ];

    'targets: for (op, root, field, arg, path) in targets {
        let is_mutation = op == "mutation";
        eprintln!("  {} Testing Command Injection on {}.{}({})...", "→".cyan(), root, field.name, path);
        for (payload, expected_delay_ms) in &payloads {
            if !ctx.budget.try_consume() { break 'targets; }
            let mut overrides = HashMap::new();
            let payload_val = serde_json::Value::String(payload.to_string());
            overrides.insert(arg.name.clone(), build_nested_value(&path, &arg.name, payload_val));

            let gql_op = build_operation_query(schema, op, field, &overrides, &config.audit.seeds, false);

            let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op.query, Some(gql_op.variables), rate_limit_ms, evasion_level, transport, is_mutation).await?;
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
