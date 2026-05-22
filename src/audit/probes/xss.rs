use crate::audit::utils::{
    build_operation_query, effective_headers,
};
use crate::config::AppConfig;
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
                    let type_name = arg.arg_type.as_ref().and_then(|t| t.unwrap_type_name());
                    if let Some(tn) = type_name {
                        if tn == "String" {
                            targets.push((op, root.unwrap_or("?"), field, arg));
                        }
                    }
                }
            }
        }
    }

    let headers = effective_headers(extra_headers, None, false);
    let payloads = [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ];

    for (op, root, field, arg) in targets {
        let mut confirmed_for_arg = false;

        for payload in payloads {
            let mut overrides = HashMap::new();
            overrides.insert(arg.name.clone(), serde_json::Value::String(payload.to_string()));
            
            let gql_op = build_operation_query(schema, op, field, &overrides, &config.audit.seeds, false);
            let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op.query, Some(gql_op.variables), rate_limit_ms, evasion_level).await?;

            // Check for reflection in data or errors
            let reflected_in_data = resp.data.as_ref().map(|d| d.to_string().contains(payload)).unwrap_or(false);
            let reflected_in_errors = resp.errors_text.contains(payload);

            if reflected_in_data || reflected_in_errors {
                let severity = if reflected_in_data { Severity::High } else { Severity::Medium };
                let location_desc = if reflected_in_data { "response data" } else { "error messages" };

                confirmed.push(Finding {
                    id: "AUD-010",
                    severity,
                    title: "Cross-Site Scripting (XSS) Reflection Confirmed",
                    description: format!(
                        "The payload '{}' was reflected unsanitized in the {} via argument '{}.{}({})'. This can lead to stored or reflected XSS if the response is rendered in a web browser without proper encoding.",
                        payload, location_desc, root, field.name, arg.name
                    ),
                    affected: vec![AffectedLocation::Argument(root.into(), field.name.clone(), arg.name.clone())],
                    remediation: "Ensure all user-provided data is properly encoded before being included in the response (either in 'data' or 'errors'). Use a context-aware encoding library.",
                    first_step: Some(format!("Execute the PoC query and check if the payload '{}' appears exactly in the JSON response.", payload)),
                    references: vec!["CWE-79: Cross-site Scripting", "OWASP API8: Injection"],
                    status: FindingStatus::Confirmed,
                    confidence: Confidence::Confirmed,
                    evidence_level: EvidenceLevel::Executed,
                    poc: Some(gql_op.query),
                });
                confirmed_for_arg = true;
                break;
            }
        }

        if !confirmed_for_arg {
             // Inconclusive for this arg
        }
    }

    Ok(())
}
