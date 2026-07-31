use crate::audit::targets::{build_nested_value, find_injectable_paths};
use crate::audit::utils::{
    build_operation_query, effective_headers, is_sql_error,
};
use crate::config::AppConfig;
use crate::transport::Transport;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, Severity};
use reqwest::Client;
use std::collections::HashMap;
use colored::Colorize;

pub async fn probe_sqli(
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
                    if let Some(at) = &arg.arg_type {
                        // Find all injectable paths (including nested fields in InputObjects)
                        let paths = find_injectable_paths(schema, at, &arg.name, crate::audit::targets::SQLI_LEAF_SCALARS);
                        for path in paths {
                            targets.push((op, root.unwrap_or("?"), field, arg, path));
                        }
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
    
    // Mix of SQL, NoSQL, and Template Injection payloads
    let mut internal_payloads = vec![
        // Classic SQL
        (serde_json::json!("'"), "'".to_string()),
        (serde_json::json!("''"), "''".to_string()),
        (serde_json::json!("' -- -"), "' -- - (MySQL/MariaDB)".to_string()),
        (serde_json::json!("') OR 1=1--"), "') OR 1=1--".to_string()),
        (serde_json::json!("\" OR 1=1--"), "\" OR 1=1--".to_string()),
        (serde_json::json!("0 OR 1=1"), "0 OR 1=1 (Numeric)".to_string()),
        
        // NoSQL / MongoDB
        (serde_json::json!({ "$ne": null }), "{\"$ne\": null}".to_string()),
        (serde_json::json!({ "$gt": "" }), "{\"$gt\": \"\"}".to_string()),
        (serde_json::json!({ "$regex": ".*" }), "{\"$regex\": \".*\"}".to_string()),
        (serde_json::json!({ "$where": "sleep(5000)" }), "{\"$where\": \"sleep(5000)\"}".to_string()),
        
        // Template Injection (SSTI)
        (serde_json::json!("{{7*7}}"), "{{7*7}} (SSTI)".to_string()),
        (serde_json::json!("${7*7}"), "${7*7} (SSTI)".to_string()),
        (serde_json::json!("<%= 7*7 %>"), "<%= 7*7 %> (SSTI)".to_string()),

        // PostgreSQL Specific
        (serde_json::json!("' AND 1=(SELECT COUNT(*) FROM users); --"), "PostgreSQL COUNT Error".to_string()),
        (serde_json::json!("' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INT)--"), "PostgreSQL Type Cast Error".to_string()),

        // Polyglots / HTB Specific
        (serde_json::json!("' || 1==1//"), "' || 1==1//".to_string()),
        (serde_json::json!("admin' || '1'=='1"), "admin' || '1'=='1'".to_string()),
    ];

    // Add custom payloads from config
    for cp in &config.audit.custom_payloads {
        let val = serde_json::from_str(cp).unwrap_or(serde_json::Value::String(cp.clone()));
        internal_payloads.push((val, cp.clone()));
    }

    'targets: for (op, root, field, arg, path) in targets {
        let is_mutation = op == "mutation";
        eprintln!("  {} Testing SQLi/NoSQLi/SSTI Injection on {}.{}({})...", "→".cyan(), root, field.name, path);

        // Baseline: Send a dummy value first
        if !ctx.budget.try_consume() { break 'targets; }
        let dummy_val = serde_json::Value::String("INTROSPECTRE_DUMMY_123".to_string());
        let mut dummy_overrides = HashMap::new();
        dummy_overrides.insert(arg.name.clone(), build_nested_value(&path, &arg.name, dummy_val));
        let dummy_gql = build_operation_query(schema, op, field, &dummy_overrides, &config.audit.seeds, false);
        let dummy_resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &dummy_gql.query, Some(dummy_gql.variables.clone()), rate_limit_ms, evasion_level, transport, is_mutation).await?;

        for (payload_val, payload_str) in &internal_payloads {
            // 1. Variable-based Test
            if !ctx.budget.try_consume() { break 'targets; }
            let mut overrides = HashMap::new();
            overrides.insert(arg.name.clone(), build_nested_value(&path, &arg.name, payload_val.clone()));

            let gql_op = build_operation_query(schema, op, field, &overrides, &config.audit.seeds, false);
            let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op.query, Some(gql_op.variables), rate_limit_ms, evasion_level, transport, is_mutation).await?;

            // 1a. Error-based Detection
            if is_sql_error(&resp.errors_text) {
                confirmed.push(Finding {
                    id: "sql-injection",
                    severity: Severity::High,
                    title: "Database Injection (SQL/NoSQL) Confirmed",
                    description: format!(
                        "### Analysis\n\
                         The backend returned a database-specific error message when processing the payload. This indicates direct concatenation or operator interpretation of user input.\n\n\
                         ### Evidence\n\
                         - **Argument Path**: `{}` in `{}.{}`\n\
                         - **Trigger Payload**: `{}`\n\n\
                         **Database Error**:\n```\n{}\n```",
                        path, root, field.name, payload_str, resp.errors_text
                    ),
                    affected: vec![AffectedLocation::Argument(root.into(), field.name.clone(), path.clone())],
                    remediation: "Use parameterized queries or an ORM/ODM that handles sanitization automatically. For NoSQL, ensure input is cast to the expected type and not allowed to contain operator objects.\n\n\
                         Suggested Manual Test Vectors:\n\
                         - `' OR 1=1 -- -` (Auth Bypass)\n\
                         - `' UNION SELECT NULL,NULL -- -` (Data Extraction)\n\
                         - `{\"$ne\": null}` (NoSQL Logic Bypass)\n\
                         - `{\"$where\": \"sleep(5000)\"}` (NoSQL Time-based)",
                    first_step: Some(format!("Try to trigger the same error manually by sending the payload `{}` to the {} field.", payload_str, path)),
                    references: vec!["CWE-89: SQL Injection", "CWE-943: NoSQL Injection", "OWASP API8: Injection"],
                    status: FindingStatus::Confirmed,
                    confidence: Confidence::Confirmed,
                    evidence_level: EvidenceLevel::Executed,
                    poc: Some(gql_op.query),
                });
                break;
            }

            // 1b. SSTI Detection (Look for reflected '49')
            if payload_str.contains("7*7") && resp.raw_text.contains("49") && !dummy_resp.raw_text.contains("49") {
                 confirmed.push(Finding {
                    id: "ssti",
                    severity: Severity::High,
                    title: "Server-Side Template Injection (SSTI) Confirmed",
                    description: format!(
                        "Argument Path: `{}` in `{}.{}`\n\
                         Trigger Payload: `{}`\n\n\
                         Evidence: The payload `7*7` was evaluated on the server and the result `49` was reflected in the response body.\n\n\
                         Analysis: This indicates the argument is passed directly to a template engine (e.g. Jinja2, ERB, Mako) which evaluates expressions.",
                        path, root, field.name, payload_str
                    ),
                    affected: vec![AffectedLocation::Argument(root.into(), field.name.clone(), path.clone())],
                    remediation: "Never allow user input to be passed to a template engine's render or evaluate function. Use safe, sandboxed template contexts or avoid dynamic templates for user-controlled data.",
                    first_step: Some(format!("Send the payload `{}` and verify that '49' appears in the response body.", payload_str)),
                    references: vec!["CWE-94: Improper Control of Generation of Code", "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine"],
                    status: FindingStatus::Confirmed,
                    confidence: Confidence::Confirmed,
                    evidence_level: EvidenceLevel::Executed,
                    poc: Some(gql_op.query),
                });
                break;
            }

            // 1c. Boolean-based / Data Leakage Detection (NoSQL specific)
            if (payload_str.contains("$") || payload_str.contains("OR")) && !resp.data.is_none() && resp.data != dummy_resp.data {
                 // Check if it's a non-null vs null situation or different data
                 if dummy_resp.data.is_none() || dummy_resp.data.as_ref().map(|d| d.is_null()).unwrap_or(true) {
                    confirmed.push(Finding {
                        id: "blind-injection",
                        severity: Severity::Critical,
                        title: "Blind Injection Confirmed (Data Leak)",
                        description: format!(
                            "### Analysis\n\
                             The argument is vulnerable to blind injection. The injected payload bypassed a query filter or logic check, allowing data to be leaked that is normally inaccessible.\n\n\
                             ### Evidence\n\
                             - **Argument Path**: `{}` in `{}.{}`\n\
                             - **Trigger Payload**: `{}`\n\
                             - **Dummy Response**: Null/Error\n\
                             - **Injection Response**: Valid Data (Success)",
                            path, root, field.name, payload_str
                        ),
                        affected: vec![AffectedLocation::Argument(root.into(), field.name.clone(), path.clone())],
                        remediation: "Strictly validate all input types. Never allow user input to be passed as an object to a NoSQL query or concatenated into SQL. Ensure all inputs are properly escaped and typed.",
                        first_step: Some(format!("Compare the response of a normal query with the response when sending `{}` as the value for {}.", payload_str, path)),
                        references: vec!["CWE-943: NoSQL Injection", "CWE-89: SQL Injection", "OWASP API8: Injection"],
                        status: FindingStatus::Confirmed,
                        confidence: Confidence::Confirmed,
                        evidence_level: EvidenceLevel::Executed,
                        poc: Some(gql_op.query),
                    });
                        break;
                 }
            }

            // 2. Inlined-query Test (Some resolvers fail only when inlined)
            if !ctx.budget.try_consume() { break 'targets; }
            let mut inlined_overrides = HashMap::new();
            let nested_val = build_nested_value(&path, &arg.name, payload_val.clone());
            inlined_overrides.insert(arg.name.clone(), json_to_graphql(&nested_val));

            let inlined_call = crate::audit::utils::build_field_call(schema, field, &inlined_overrides, &config.audit.seeds, false);
            let inlined_query = format!("{} {{ {} }}", op, inlined_call);

            let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &inlined_query, None, rate_limit_ms, evasion_level, transport, is_mutation).await?;
            if is_sql_error(&resp.errors_text) {
                confirmed.push(Finding {
                    id: "sql-injection-inline",
                    severity: Severity::High,
                    title: "Database Injection (Inlined) Confirmed",
                    description: format!(
                        "### Analysis\n\
                         The backend returned a database error when the payload was embedded directly in the query string. This indicates inconsistent sanitization logic between Inlined values and Variables.\n\n\
                         ### Evidence\n\
                         - **Argument Path**: `{}` in `{}.{}`\n\
                         - **Trigger Payload**: `{}` (Inlined)\n\n\
                         **Database Error**:\n```\n{}\n```",
                        path, root, field.name, payload_str, resp.errors_text
                    ),
                    affected: vec![AffectedLocation::Argument(root.into(), field.name.clone(), path.clone())],
                    remediation: "Use parameterized queries/variables instead of inlining values in query strings. Ensure all inputs are strictly typed and sanitized.",
                    first_step: Some(format!("Send the inlined PoC query manually and observe the database error response.")),
                    references: vec!["CWE-89: SQL Injection", "OWASP API8: Injection"],
                    status: FindingStatus::Confirmed,
                    confidence: Confidence::Confirmed,
                    evidence_level: EvidenceLevel::Executed,
                    poc: Some(inlined_query),
                });
                break;
            }
        }
    }

    Ok(())
}

fn json_to_graphql(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => format!("\"{}\"", s.replace("\"", "\\\"")),
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(json_to_graphql).collect();
            format!("[{}]", items.join(", "))
        }
        serde_json::Value::Object(obj) => {
            let fields: Vec<String> = obj.iter()
                .map(|(k, v)| format!("{}: {}", k, json_to_graphql(v)))
                .collect();
            format!("{{ {} }}", fields.join(", "))
        }
    }
}

