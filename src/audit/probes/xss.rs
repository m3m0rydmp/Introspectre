use colored::Colorize;
use crate::audit::utils::{
    build_field_call, effective_headers,
};
use crate::config::AppConfig;
use crate::transport::Transport;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, Severity};
use reqwest::Client;
use std::collections::HashMap;

pub async fn probe_xss(
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
    for (op_keyword, root_type) in [("query", query_name), ("mutation", mutation_name)] {
        for field in schema.fields_for_type(root_type) {
            if let Some(args) = &field.args {
                for arg in args {
                    let type_name = arg.arg_type.as_ref().and_then(|t| t.unwrap_type_name());
                    if let Some(tn) = type_name {
                        // Target all common scalars, as reflection often happens in type-mismatch errors
                        let scalars = ["String", "Int", "Float", "Boolean", "ID"];
                        if scalars.contains(&tn.as_str()) {
                            targets.push((op_keyword, root_type.unwrap_or("?"), field, arg));
                        }
                    }
                }
            }
        }
    }

    // Focus / rank (XSS-reflection name affinity first, then passive severity) / cap.
    let targets = crate::audit::targets::scope_targets_prioritized(
        targets,
        ctx.sev_index,
        ctx.scope,
        |t| (t.1.to_string(), t.2.name.clone()),
        |t| crate::audit::targets::name_affinity(
            &format!("{} {}", t.2.name, t.3.name),
            crate::audit::targets::XSS_KEYWORDS,
        ),
    );

    let headers = effective_headers(extra_headers, None, false);
    let payloads = [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ];

    'targets: for (op_keyword, root_name, field, arg) in targets {
        let is_mutation = op_keyword == "mutation";
        eprintln!("  {} Testing XSS Injection on {}.{}({})...", "→".cyan(), root_name, field.name, arg.name);
        let mut confirmed_for_arg = false;

        for payload in payloads {
            if !ctx.budget.try_consume() { break 'targets; }
            // Test both Variable-based and Inlined payloads
            // Inlined payloads are often reflected in "Invalid Value" or "Type Mismatch" errors
            let mut overrides = HashMap::new();
            overrides.insert(arg.name.clone(), format!("\"{}\"", payload)); // Quoted for inlined reflection

            let inlined_call = build_field_call(schema, field, &overrides, &config.audit.seeds, false);
            let query = format!("{} {{ {} }}", op_keyword, inlined_call);

            let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &query, None, rate_limit_ms, evasion_level, transport, is_mutation).await?;

            // Check for reflection in data or errors
            // Use escaped payload matching if necessary, but most reflection is direct
            let reflected_in_data = resp.data.as_ref().map(|d| d.to_string().contains(payload)).unwrap_or(false);
            let reflected_in_errors = resp.errors_text.contains(payload);

            // GraphQL APIs respond with application/json, so reflection in JSON data or
            // error messages is not exploitable as XSS unless the response is actually
            // rendered as HTML. Only report when the content-type indicates HTML.
            let is_html = resp
                .headers
                .get("content-type")
                .map(|c| c.to_lowercase().contains("html"))
                .unwrap_or(false);

            if (reflected_in_data || reflected_in_errors) && !is_html {
                continue;
            }

            if reflected_in_data || reflected_in_errors {
                let severity = if reflected_in_data { Severity::High } else { Severity::Medium };
                let location_desc = if reflected_in_data { "response data" } else { "error messages" };

                confirmed.push(Finding {
                    id: "xss-reflection",
                    severity,
                    title: "Cross-Site Scripting (XSS) Reflection Confirmed",
                    description: format!(
                        "### Analysis\n\
                         A test payload was reflected unsanitized in the backend response. This typically occurs when the GraphQL engine reflects invalid input values in error messages or when a resolver echoes input back to the user without proper encoding.\n\n\
                         If this data is rendered in a web browser (e.g., in a management dashboard or an API explorer) without proper escaping, it can lead to reflected Cross-Site Scripting (XSS).\n\n\
                         ### Evidence\n\
                         - **Reflected Payload**: `{}`\n\
                         - **Reflection Point**: {}\n\
                         - **Source Field**: `{}.{}({})`",
                        payload, location_desc, root_name, field.name, arg.name
                    ),
                    affected: vec![AffectedLocation::Argument(root_name.into(), field.name.clone(), arg.name.clone())],
                    remediation: "Ensure all user-provided data is properly encoded before being included in the response (either in 'data' or 'errors'). Most GraphQL implementations reflect input in 'errors' by default; ensure your error handling logic sanitizes these values or disables detailed error messages in production.",
                    first_step: Some(format!("Execute the PoC query and check if the payload '{}' appears exactly in the JSON response.", payload)),
                    references: vec!["CWE-79: Cross-site Scripting", "OWASP API8: Injection"],
                    status: FindingStatus::Confirmed,
                    confidence: Confidence::Confirmed,
                    evidence_level: EvidenceLevel::Executed,
                    poc: Some(query),
                });
                confirmed_for_arg = true;
                break;
            }
        }

        if confirmed_for_arg {
            continue;
        }
    }

    Ok(())
}
