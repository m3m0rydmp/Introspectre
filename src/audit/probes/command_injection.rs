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

    // Focus / rank (command-execution name affinity first, then passive severity) / cap.
    // The affinity boost keeps an obvious sink like `systemDebug(arg)` from being starved by the
    // budget behind passively-flagged but non-vulnerable fields.
    let targets = crate::audit::targets::scope_targets_prioritized(
        targets,
        ctx.sev_index,
        ctx.scope,
        |t| (t.1.to_string(), t.2.name.clone()),
        |t| crate::audit::targets::name_affinity(
            &format!("{} {} {}", t.2.name, t.3.name, t.4),
            crate::audit::targets::CMDI_KEYWORDS,
        ),
    );

    let headers = effective_headers(extra_headers, None, false);
    
    // Time-based detection payloads. Bare shell-metacharacter payloads cover input that flows
    // straight into a shell; the `host:port`-prefixed variants survive apps that PARSE the input
    // first (e.g. `host, port = ip.split(':')`) before the vulnerable `os.system` call — a very
    // common shape for connectivity / ping / nc sinks. Seed-prefixed variants (added per-target
    // when a known-good value exists for the argument) preserve a valid base value so the
    // injection still reaches the shell.
    const SLEEP_MS: u128 = 5000;
    let base_payloads: &[&str] = &[
        "; sleep 5",
        "| sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
        "&& sleep 5",
        "127.0.0.1:80; sleep 5",
        "127.0.0.1:80 && sleep 5",
    ];

    'targets: for (op, root, field, arg, path) in targets {
        let is_mutation = op == "mutation";
        eprintln!("  {} Testing Command Injection on {}.{}({})...", "→".cyan(), root, field.name, path);

        // Per-target payloads: the base set plus seed-prefixed variants when a known-good value
        // exists for this argument, so structured inputs still land the injection in the shell.
        let mut payloads: Vec<String> = base_payloads.iter().map(|s| s.to_string()).collect();
        if let Some(seed) = config.audit.seeds.get(&arg.name) {
            let seed = seed.trim_matches('"');
            payloads.push(format!("{}; sleep 5", seed));
            payloads.push(format!("{}$(sleep 5)", seed));
        }

        for payload in &payloads {
            if !ctx.budget.try_consume() { break 'targets; }
            let mut overrides = HashMap::new();
            let payload_val = serde_json::Value::String(payload.clone());
            overrides.insert(arg.name.clone(), build_nested_value(&path, &arg.name, payload_val));

            let gql_op = build_operation_query(schema, op, field, &overrides, &config.audit.seeds, false);
            let gql_vars_retry = gql_op.variables.clone(); // cloned before first move

            let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op.query, Some(gql_op.variables), rate_limit_ms, evasion_level, transport, is_mutation).await?;
            // Use the response's own network timing, which EXCLUDES the pre-request
            // rate-limit sleep. Timing the whole call would count the throttle delay and
            // false-positive on every argument whenever rate_limit_ms is large (>= 5s).
            let elapsed = resp.elapsed_ms as u128;

            // Time-based signal: the payload requested a ~5s shell sleep.
            if elapsed >= SLEEP_MS {
                // Retry the SAME payload once to rule out network jitter. A single anomalous
                // slow response (cold start, load spike, TCP retransmit) can coincidentally
                // look like a shell sleep — if the second attempt doesn't reproduce the delay,
                // the first was a fluke.
                if !ctx.budget.try_consume() { break 'targets; }
                let retry_resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op.query, Some(gql_vars_retry), rate_limit_ms, evasion_level, transport, is_mutation).await?;
                let retry_elapsed = retry_resp.elapsed_ms as u128;
                if retry_elapsed < SLEEP_MS {
                    // First attempt was jitter — the delay didn't reproduce.
                    continue;
                }

                // Scale test: send a SHORTER sleep (3s) to verify the delay scales linearly
                // with the injected sleep duration. A real shell execution will show ~3s for
                // sleep 3 and ~5s for sleep 5; coincidental latency won't fake this relationship.
                let scale_payload = payload.replace("sleep 5", "sleep 3");
                if scale_payload == *payload {
                    // Payload didn't contain "sleep 5" (e.g. it's a bare `$(sleep 5)` variant
                    // that already passed retry). That's fine — the retry alone is sufficient
                    // for non-sleep-based payloads.
                } else {
                    if !ctx.budget.try_consume() { break 'targets; }
                    let mut scale_overrides = HashMap::new();
                    let scale_val = serde_json::Value::String(scale_payload.clone());
                    scale_overrides.insert(arg.name.clone(), build_nested_value(&path, &arg.name, scale_val));
                    let scale_op = build_operation_query(schema, op, field, &scale_overrides, &config.audit.seeds, false);
                    let scale_resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &scale_op.query, Some(scale_op.variables), rate_limit_ms, evasion_level, transport, is_mutation).await?;
                    let scale_elapsed = scale_resp.elapsed_ms as u128;
                    // sleep 3 should produce ~3s delay; require at least 2500ms (allow 500ms jitter).
                    // If it doesn't scale down, the original 5s was likely not a real execution.
                    if scale_elapsed < 2500 {
                        continue;
                    }
                }

                // Build evidence response blocks so the analyst can see the raw server responses
                // that triggered both the primary and retry detections (not just the PoC query).
                let evidence_primary = crate::audit::poc::truncated_body(&resp.raw_text, 600);
                let evidence_retry = crate::audit::poc::truncated_body(&retry_resp.raw_text, 600);
                let evidence_block = format!(
                    "### Evidence Responses\n\
                     **Primary payload response** ({}ms):\n```\n{}\n```\n\
                     **Retry payload response** ({}ms):\n```\n{}\n```",
                    elapsed, evidence_primary, retry_elapsed, evidence_retry
                );

                confirmed.push(Finding {
                    id: "os-command-injection",
                    severity: Severity::Critical,
                    title: "OS Command Injection (Time-Based) Confirmed",
                    description: format!(
                        "### Analysis\n\
                         The server response was delayed by a significant amount when a time-based payload was injected, and the delay **reproduced on retry**. This indicates the input is being executed directly in a shell environment.\n\n\
                         ### Evidence\n\
                         - **Argument Path**: `{}` in `{}.{}`\n\
                         - **Trigger Payload**: `{}`\n\
                         - **Primary Latency**: {}ms\n\
                         - **Retry Latency**: {}ms (reproduced — not jitter)\n\
                         - **Expected**: {}ms\n\n{}",
                        path, root, field.name, payload,
                        elapsed, retry_elapsed, SLEEP_MS,
                        evidence_block
                    ),
                    affected: vec![AffectedLocation::Argument(root.into(), field.name.clone(), path.clone())],
                    remediation: "Never pass user input directly to system commands or shell executors. Use language-native APIs for file operations and process execution, and strictly validate all input against an allow-list.",
                    first_step: Some(format!("Execute the PoC query and observe the response delay of approximately {} seconds. Re-run to confirm the delay is consistent.", SLEEP_MS / 1000)),
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
