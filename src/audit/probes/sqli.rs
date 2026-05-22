use crate::audit::utils::{
    build_operation_query, effective_headers, is_sql_error,
};
use crate::config::AppConfig;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, Severity};
use reqwest::Client;
use std::collections::HashMap;

pub async fn probe_sqli(
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
                        if tn == "String" || tn == "ID" {
                            targets.push((op, root.unwrap_or("?"), field, arg));
                        }
                    }
                }
            }
        }
    }

    let headers = effective_headers(extra_headers, None, false);
    let payloads = [
        "'",
        "''",
        "') OR 1=1--",
        "\" OR 1=1--",
        "' UNION SELECT NULL--",
    ];

    for (op, root, field, arg) in targets {
        let mut confirmed_for_arg = false;

        for payload in payloads {
            let mut overrides = HashMap::new();
            overrides.insert(arg.name.clone(), serde_json::Value::String(payload.to_string()));
            
            let gql_op = build_operation_query(schema, op, field, &overrides, &config.audit.seeds, false);
            let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op.query, Some(gql_op.variables), rate_limit_ms, evasion_level).await?;

            if is_sql_error(&resp.errors_text) {
                confirmed.push(Finding {
                    id: "AUD-009",
                    severity: Severity::High,
                    title: "SQL Injection (Error-Based) Confirmed",
                    description: format!(
                        "The argument '{}.{}({})' is vulnerable to SQL injection. Injecting '{}' triggered a database-specific error message: {}",
                        root, field.name, arg.name, payload, resp.errors_text
                    ),
                    affected: vec![AffectedLocation::Argument(root.into(), field.name.clone(), arg.name.clone())],
                    remediation: "Use parameterized queries or an ORM that handles sanitization automatically. Never concatenate user input into SQL strings.",
                    first_step: Some(format!("Try to trigger the same error manually by sending the payload '{}' to the {} argument.", payload, arg.name)),
                    references: vec!["CWE-89: SQL Injection", "OWASP API8: Injection"],
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
