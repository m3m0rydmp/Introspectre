use crate::transport::{build_graphql_request, Transport};
use crate::types::{GqlField, GqlSchema, GqlTypeRef};
use reqwest::Client;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct Throttler {
    pub delay_ms: u64,
    pub min_delay_ms: u64,
    pub max_delay_ms: u64,
}

impl Throttler {
    pub fn new(initial: u64) -> Self {
        Self {
            delay_ms: initial,
            min_delay_ms: (initial / 4).max(10),
            max_delay_ms: 10000,
        }
    }

    pub fn adjust(&mut self, elapsed_ms: u128) {
        if elapsed_ms > 2000 {
            // Slow down if response is slow (> 2s)
            self.delay_ms = (self.delay_ms as f64 * 1.5).min(self.max_delay_ms as f64) as u64;
        } else if elapsed_ms < 400 && self.delay_ms > self.min_delay_ms {
            // Speed up slightly if response is very fast (< 400ms)
            self.delay_ms = (self.delay_ms as f64 * 0.9).max(self.min_delay_ms as f64) as u64;
        }
    }
}

/// Tiny time-seeded linear congruential generator used to make obfuscation
/// output non-deterministic (byte-different across runs) without pulling in
/// a `rand` dependency. Not cryptographically meaningful — purely for
/// signature-breaking noise.
fn obfuscation_seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos as u64) | 1
}

fn next_rand(seed: &mut u64) -> u64 {
    // Numerical Recipes LCG constants.
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    *seed >> 33
}

/// Returns `true` roughly 1-in-`n` times, driven by `seed`.
fn rand_chance(seed: &mut u64, n: u32) -> bool {
    (next_rand(seed) as u32) % n.max(1) == 0
}

/// Random lowercase-alphanumeric token of length `len`, e.g. for comment noise.
fn rand_token(seed: &mut u64, len: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..len)
        .map(|_| CHARS[(next_rand(seed) as usize) % CHARS.len()] as char)
        .collect()
}

/// Reformats `query` so it is byte-different from the original while remaining
/// semantically identical GraphQL, in order to slip past naive signature/regex
/// based WAFs. This does NOT help against WAFs that actually parse GraphQL or
/// normalize whitespace/commas before matching.
///
/// - Level 1: whitespace jitter + insignificant commas (GraphQL treats `,` as
///   whitespace) inserted only at existing token boundaries.
/// - Level 2: adds randomized `# <token>` end-of-line comments (instead of a
///   fixed string) and occasionally an inline comment right after `{`.
/// - Level 3: CRLF line endings plus random leading/trailing comment noise.
pub fn obfuscate_query(query: &str, level: u8) -> String {
    if level == 0 {
        return query.to_string();
    }

    let mut seed = obfuscation_seed();

    // Level 1: whitespace jitter + insignificant commas. String-literal aware
    // so we never touch bytes inside a `"..."` argument value.
    let mut result = String::with_capacity(query.len() * 2);
    let mut in_string = false;
    let mut escape = false;

    for c in query.chars() {
        if in_string {
            result.push(c);
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }

        match c {
            '"' => {
                in_string = true;
                result.push(c);
            }
            '{' => {
                result.push_str(" {\n  ");
            }
            '}' => {
                result.push_str("\n} ");
                if rand_chance(&mut seed, 2) {
                    result.push(',');
                }
            }
            ' ' => {
                result.push_str("  ");
                if rand_chance(&mut seed, 4) {
                    result.push(',');
                }
            }
            _ => result.push(c),
        }
    }

    // Level 2: randomized end-of-line comment tokens, plus an occasional
    // inline comment injected right after an opening brace.
    if level >= 2 {
        let lines: Vec<String> = result
            .lines()
            .map(|l| {
                if l.trim().is_empty() {
                    l.to_string()
                } else if l.trim_end().ends_with('{') && rand_chance(&mut seed, 3) {
                    format!("{}\n  # {}", l, rand_token(&mut seed, 6))
                } else {
                    format!("{} # {}", l, rand_token(&mut seed, 6))
                }
            })
            .collect();
        result = lines.join("\n");
    }

    // Level 3: CRLF line endings + random leading/trailing comment noise.
    if level >= 3 {
        result = result.replace('\n', "\r\n");
        let lead = rand_token(&mut seed, 8);
        let trail = rand_token(&mut seed, 8);
        result = format!("\r\n# {}\r\n{}\r\n# {}\r\n", lead, result, trail);
    }

    result
}

#[derive(Debug)]
pub struct ProbeResponse {
    pub status: u16,
    pub elapsed_ms: u128,
    pub data: Option<Value>,
    pub errors_text: String,
    pub raw_text: String,
    pub headers: HashMap<String, String>,
}

pub fn parse_header_kv(value: &str) -> Option<(String, String)> {
    let mut parts = value.splitn(2, '=');
    let key = parts.next().unwrap_or("").trim();
    let val = parts.next().unwrap_or("").trim();
    if key.is_empty() {
        None
    } else {
        Some((key.to_string(), val.to_string()))
    }
}

pub fn effective_headers(
    base_headers: &[String],
    session_auth_header: Option<&str>,
    include_auth: bool,
) -> Vec<(String, String)> {
    let mut parsed = crate::utils::parse_extra_headers(base_headers);
    if !include_auth {
        parsed.retain(|(k, _)| !k.eq_ignore_ascii_case("Authorization"));
    }

    if include_auth {
        if let Some(auth_header) = session_auth_header {
            if let Some((k, v)) = parse_header_kv(auth_header) {
                parsed.retain(|(existing, _)| !existing.eq_ignore_ascii_case(&k));
                parsed.push((k, v));
            }
        }
    }

    parsed
}

pub async fn post_graphql(
    client: &Client,
    url: &str,
    headers: &[(String, String)],
    query: &str,
    rate_limit_ms: u64,
) -> Result<ProbeResponse, String> {
    post_graphql_ext(client, url, headers, query, None, rate_limit_ms, 0, Transport::PostJson, false).await
}

pub async fn post_graphql_ext(
    client: &Client,
    url: &str,
    headers: &[(String, String)],
    query: &str,
    variables: Option<Value>,
    rate_limit_ms: u64,
    evasion_level: u8,
    transport: Transport,
    is_mutation: bool,
) -> Result<ProbeResponse, String> {
    if rate_limit_ms > 0 {
        tokio::time::sleep(Duration::from_millis(rate_limit_ms)).await;
    }

    let final_query = if evasion_level > 0 {
        obfuscate_query(query, evasion_level)
    } else {
        query.to_string()
    };

    let mut req = build_graphql_request(client, url, transport, &final_query, variables.as_ref(), is_mutation);

    for (k, v) in headers {
        req = req.header(k, v);
    }

    let built = req;
    let started = Instant::now();
    // Retry once on a transient connection error (e.g. a single-threaded dev
    // server dropping a pooled keep-alive connection) so one flaky request does
    // not abort the whole audit.
    let resp = match built.try_clone() {
        Some(first) => match first.send().await {
            Ok(r) => r,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(250)).await;
                built.send().await.map_err(|e| e.to_string())?
            }
        },
        None => built.send().await.map_err(|e| e.to_string())?,
    };
    let elapsed_ms = started.elapsed().as_millis();
    let status = resp.status().as_u16();

    let mut headers = HashMap::new();
    for (name, value) in resp.headers().iter() {
        if let Ok(v) = value.to_str() {
            headers.insert(name.to_string(), v.to_string());
        }
    }

    let raw_text = resp.text().await.unwrap_or_default();

    let parsed = serde_json::from_str::<Value>(&raw_text).ok();
    let data = parsed.as_ref().and_then(|v| v.get("data")).cloned();
    let errors_text = parsed
        .as_ref()
        .and_then(|v| v.get("errors"))
        .map(|v| v.to_string())
        .unwrap_or_default();

    Ok(ProbeResponse {
        status,
        elapsed_ms,
        data,
        errors_text,
        raw_text,
        headers,
    })
}

pub async fn post_batched_graphql_ext(
    client: &Client,
    url: &str,
    headers: &[(String, String)],
    operations: &[GqlOperation],
    rate_limit_ms: u64,
    evasion_level: u8,
    transport: Transport,
) -> Result<Vec<ProbeResponse>, String> {
    // Batched requests are always a JSON array body sent over POST — no other
    // transport can carry a batch, so `transport` is accepted only for call-site
    // symmetry with `post_graphql_ext` and is otherwise ignored here.
    let _ = transport;

    if rate_limit_ms > 0 {
        tokio::time::sleep(Duration::from_millis(rate_limit_ms)).await;
    }

    let mut req = client
        .post(url)
        .header("Content-Type", "application/json");

    for (k, v) in headers {
        req = req.header(k, v);
    }

    let ops_json: Vec<serde_json::Value> = operations
        .iter()
        .map(|op| {
            let final_q = if evasion_level > 0 {
                obfuscate_query(&op.query, evasion_level)
            } else {
                op.query.clone()
            };
            serde_json::json!({ "query": final_q, "variables": op.variables })
        })
        .collect();

    let body = serde_json::json!(ops_json);
    let built = req.json(&body);
    let started = Instant::now();
    // Retry once on a transient connection error (e.g. a single-threaded dev
    // server dropping a pooled keep-alive connection) so one flaky request does
    // not abort the whole audit.
    let resp = match built.try_clone() {
        Some(first) => match first.send().await {
            Ok(r) => r,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(250)).await;
                built.send().await.map_err(|e| e.to_string())?
            }
        },
        None => built.send().await.map_err(|e| e.to_string())?,
    };
    let elapsed_ms = started.elapsed().as_millis();
    let status = resp.status().as_u16();

    let mut headers_map = HashMap::new();
    for (name, value) in resp.headers().iter() {
        if let Ok(v) = value.to_str() {
            headers_map.insert(name.to_string(), v.to_string());
        }
    }

    let raw_text = resp.text().await.unwrap_or_default();

    let parsed: Result<Vec<Value>, _> = serde_json::from_str(&raw_text);
    let responses = match parsed {
        Ok(arr) => arr,
        Err(_) => {
            return match serde_json::from_str::<Value>(&raw_text) {
                Ok(single) => Ok(vec![ProbeResponse {
                    status,
                    elapsed_ms,
                    data: single.get("data").cloned(),
                    errors_text: single
                        .get("errors")
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| {
                            // If no errors field but status is error, use raw_text as error hint
                            if status >= 400 { raw_text.clone() } else { String::new() }
                        }),
                    raw_text,
                    headers: headers_map,
                }]),
                Err(_) => {
                    // Raw non-JSON response (likely a 500 error or stack trace)
                    Ok(vec![ProbeResponse {
                        status,
                        elapsed_ms,
                        data: None,
                        errors_text: raw_text.clone(),
                        raw_text,
                        headers: headers_map,
                    }])
                }
            };
        }
    };

    Ok(responses
        .into_iter()
        .map(|v| ProbeResponse {
            status,
            elapsed_ms,
            data: v.get("data").cloned(),
            errors_text: v.get("errors").map(|e| e.to_string()).unwrap_or_default(),
            raw_text: v.to_string(),
            headers: headers_map.clone(),
        })
        .collect())
}

pub fn is_auth_error(message: &str) -> bool {
    let m = message.to_lowercase();
    [
        "not authenticated",
        "unauthorized",
        "forbidden",
        "auth required",
        "authentication",
        "bearer",
        "jwt",
        "token",
    ]
    .iter()
    .any(|s| m.contains(s))
}

pub fn is_validation_error(message: &str) -> bool {
    let m = message.to_lowercase();
    [
        "validation",
        "invalid value",
        "expected type",
        "must not be null",
        "required",
        "unknown argument",
        "field",
        "syntax error",
    ]
    .iter()
    .any(|s| m.contains(s))
}

pub fn is_sql_error(message: &str) -> bool {
    let m = message.to_lowercase();
    [
        "sqlstate",
        "mysql",
        "postgresql",
        "sqlite",
        "column",
        "table",
        "database",
        "relation",
        "pg_sleep",
        "dbms_pipe",
        "near \"'\"",
        "unterminated quoted string",
        "you have an error in your sql syntax",
        "check the manual that corresponds to your mariadb server",
        // Python / SQLAlchemy / PHP patterns
        "pymysql",
        "sqlalchemy",
        "sqlite3",
        "pdoexception",
        "psycopg2",
        "pg8000",
        // NoSQL / MongoDB patterns
        "mongodb",
        "mongodb.driver",
        "bsonobj",
        "nosql",
        "documentdb",
        "cursorid",
        "$gt",
        "$ne",
        "$in",
        "$regex",
        "canonicalize",
        "nedb",
        "nedb-core",
        // Generic DB / JS patterns
        "objectid",
        "invalid object id",
        "cast to number failed",
        "cast to string failed",
        "unexpected token",
    ]
    .iter()
    .any(|s| m.contains(s))
}

pub fn field_non_null_data(data: &Option<Value>, field_name: &str) -> Option<Value> {
    data.as_ref()
        .and_then(|d| d.get(field_name))
        .filter(|v| !v.is_null())
        .cloned()
}

pub fn field_kind(schema: &GqlSchema, field: &GqlField) -> Option<String> {
    let field_type_name = field
        .field_type
        .as_ref()
        .and_then(|t| t.unwrap_type_name())?;
    schema
        .types
        .iter()
        .find(|t| t.name.as_deref() == Some(field_type_name.as_str()))
        .and_then(|t| t.kind.clone())
}

pub fn field_type_name(schema: &GqlSchema, field: &GqlField) -> Option<String> {
    let name = field
        .field_type
        .as_ref()
        .and_then(|t| t.unwrap_type_name())?;
    schema
        .types
        .iter()
        .find(|t| t.name.as_deref() == Some(name.as_str()))
        .and_then(|t| t.name.clone())
}

pub fn base_selection(schema: &GqlSchema, field: &GqlField) -> String {
    match field_kind(schema, field).as_deref() {
        Some("OBJECT") | Some("INTERFACE") | Some("UNION") => "{ __typename }".to_string(),
        _ => String::new(),
    }
}

pub fn idor_selection(schema: &GqlSchema, field: &GqlField) -> String {
    let type_name = match field_type_name(schema, field) {
        Some(n) => n,
        None => return base_selection(schema, field),
    };

    let gql_type = match schema.find_type(&type_name) {
        Some(t) => t,
        None => return base_selection(schema, field),
    };

    let preferred = [
        "id",
        "userId",
        "ownerId",
        "email",
        "username",
        "name",
        "description",
        "title",
        "status",
        "active",
        "role",
        "roles",
        "permissions",
        "__typename",
    ];

    if gql_type.kind.as_deref() == Some("INTERFACE") || gql_type.kind.as_deref() == Some("UNION") {
        let mut fragments = Vec::new();
        if let Some(possibles) = &gql_type.possible_types {
            for pt in possibles {
                if let Some(pt_name) = pt.unwrap_type_name() {
                    let inner_fields = schema.fields_for_type(Some(&pt_name));
                    let mut selected = Vec::new();
                    for key in preferred {
                        if inner_fields.iter().any(|f| f.name == key) || key == "__typename" {
                            selected.push(key.to_string());
                        }
                    }
                    if !selected.is_empty() {
                        fragments.push(format!("... on {} {{ {} }}", pt_name, selected.join(" ")));
                    }
                }
            }
        }

        if fragments.is_empty() {
            return "{ __typename }".to_string();
        }
        return format!("{{ __typename {} }}", fragments.join(" "));
    }

    let fields = schema.fields_for_type(Some(type_name.as_str()));
    if fields.is_empty() {
        return base_selection(schema, field);
    }

    let mut selected: Vec<String> = Vec::new();
    for key in preferred {
        if key == "__typename" {
            selected.push("__typename".to_string());
            continue;
        }
        if fields.iter().any(|f| f.name == key) {
            selected.push(key.to_string());
        }
    }

    if selected.is_empty() {
        return base_selection(schema, field);
    }

    format!("{{ {} }}", selected.join(" "))
}

pub fn resolve_complex_default(
    schema: &GqlSchema,
    type_ref: &GqlTypeRef,
    field_name: &str,
    depth: usize,
    mut seen_types: HashSet<String>,
    seed_map: &HashMap<String, String>,
) -> String {
    if depth > 5 {
        return "null".to_string();
    }

    let kind = type_ref.kind.as_deref().unwrap_or("");
    match kind {
        "NON_NULL" => {
            if let Some(inner) = &type_ref.of_type {
                return resolve_complex_default(schema, inner, field_name, depth, seen_types, seed_map);
            }
        }
        "LIST" => {
            if let Some(inner) = &type_ref.of_type {
                let val = resolve_complex_default(schema, inner, field_name, depth, seen_types, seed_map);
                return format!("[{}]", val);
            }
        }
        _ => {}
    }

    // Most specific: a seed keyed by the argument/input-field **name** (e.g. `username`,
    // `password`, `token`, `id`). This lets an operator supply distinct known values for
    // sibling arguments of the same scalar type — e.g. valid credentials so an auth-gated
    // sink can be reached — which a type-name seed alone cannot express.
    if let Some(seeded) = seed_map.get(field_name) {
        return seeded.clone();
    }

    if let Some(name) = &type_ref.name {
        // Then a seed keyed by the type name.
        if let Some(seeded) = seed_map.get(name) {
            return seeded.clone();
        }

        let synthesized = crate::utils::synthesize_value(field_name, name);
        if synthesized != "null" {
            return synthesized;
        }

        if let Some(gql_type) = schema.find_type(name) {
            match gql_type.kind.as_deref() {
                Some("INPUT_OBJECT") => {
                    if seen_types.contains(name) {
                        return "{}".to_string();
                    }
                    seen_types.insert(name.clone());

                    let mut parts = Vec::new();
                    if let Some(fields) = &gql_type.input_fields {
                        for f in fields {
                            let val = f
                                .field_type
                                .as_ref()
                                .map(|tr| {
                                    resolve_complex_default(
                                        schema,
                                        tr,
                                        &f.name,
                                        depth + 1,
                                        seen_types.clone(),
                                        seed_map,
                                    )
                                })
                                .unwrap_or_else(|| "null".to_string());
                            parts.push(format!("{}: {}", f.name, val));
                        }
                    }
                    return format!("{{ {} }}", parts.join(", "));
                }
                Some("ENUM") => {
                    if let Some(vals) = &gql_type.enum_values {
                        if let Some(v) = vals.first() {
                            return v.name.clone();
                        }
                    }
                    return "ENUM_VAL".to_string();
                }
                _ => {}
            }
        }
    }
    "null".to_string()
}

#[derive(Debug, Clone)]
pub struct GqlOperation {
    pub query: String,
    pub variables: Value,
}

pub fn deep_merge(target: &mut Value, source: &Value) {
    match (target, source) {
        (Value::Object(target_map), Value::Object(source_map)) => {
            for (key, value) in source_map {
                deep_merge(target_map.entry(key.clone()).or_insert(Value::Null), value);
            }
        }
        (target, source) => {
            *target = source.clone();
        }
    }
}

pub fn build_variable_operation_query(
    schema: &GqlSchema,
    op_keyword: &str,
    field: &GqlField,
    arg_overrides: &HashMap<String, Value>,
    seed_map: &HashMap<String, String>,
    use_idor_selection: bool,
) -> GqlOperation {
    let mut var_defs = Vec::new();
    let mut args_calls = Vec::new();
    let mut variables = serde_json::Map::new();

    if let Some(args) = &field.args {
        for arg in args {
            let type_name = arg.arg_type.as_ref()
                .and_then(|tr| tr.unwrap_type_name())
                .unwrap_or_else(|| "String".to_string());

            let is_required = arg.arg_type.as_ref()
                .map_or(false, |tr| tr.kind.as_deref() == Some("NON_NULL"));

            let var_type = if is_required { format!("{}!", type_name) } else { type_name };

            var_defs.push(format!("${}: {}", arg.name, var_type));
            args_calls.push(format!("{}: ${}", arg.name, arg.name));

            // Generate default value
            let default_str = arg.arg_type.as_ref()
                .map(|tr| resolve_complex_default(schema, tr, &arg.name, 0, HashSet::new(), seed_map))
                .unwrap_or_else(|| "null".to_string());

            let mut val = serde_json::from_str(&default_str).unwrap_or_else(|_| {
                if default_str.starts_with('\"') && default_str.ends_with('\"') {
                    Value::String(default_str[1..default_str.len()-1].to_string())
                } else {
                    Value::String(default_str)
                }
            });

            // Deep merge override if exists
            if let Some(ovr) = arg_overrides.get(&arg.name) {
                deep_merge(&mut val, ovr);
            }

            variables.insert(arg.name.clone(), val);
        }
    }
    let args_block = if args_calls.is_empty() {
        String::new()
    } else {
        format!("({})", args_calls.join(", "))
    };

    let selection = if use_idor_selection {
        idor_selection(schema, field)
    } else {
        base_selection(schema, field)
    };

    let op_name = format!("Introspectre_{}_{}", op_keyword, field.name);
    let var_def_block = if var_defs.is_empty() {
        String::new()
    } else {
        format!("({})", var_defs.join(", "))
    };

    let query = format!(
        "{} {}{} {{\n  {}{} {}\n}}",
        op_keyword, op_name, var_def_block, field.name, args_block, selection
    );

    GqlOperation {
        query,
        variables: Value::Object(variables),
    }
}

pub fn build_field_call(
    schema: &GqlSchema,
    field: &GqlField,
    arg_overrides: &HashMap<String, String>,
    seed_map: &HashMap<String, String>,
    use_idor_selection: bool,
) -> String {
    let mut args_rendered: Vec<String> = Vec::new();
    if let Some(args) = &field.args {
        for arg in args {
            let value = arg_overrides.get(&arg.name).cloned().unwrap_or_else(|| {
                arg.arg_type
                    .as_ref()
                    .map(|tr| {
                        resolve_complex_default(schema, tr, &arg.name, 0, HashSet::new(), seed_map)
                    })
                    .unwrap_or_else(|| "null".to_string())
            });
            args_rendered.push(format!("{}: {}", arg.name, value));
        }
    }

    let args_block = if args_rendered.is_empty() {
        String::new()
    } else {
        format!("({})", args_rendered.join(", "))
    };

    let selection = if use_idor_selection {
        idor_selection(schema, field)
    } else {
        base_selection(schema, field)
    };

    format!("{}{} {}", field.name, args_block, selection)
}

pub fn build_operation_query(
    schema: &GqlSchema,
    op_keyword: &str,
    field: &GqlField,
    arg_overrides: &HashMap<String, Value>,
    seed_map: &HashMap<String, String>,
    use_idor_selection: bool,
) -> GqlOperation {
    build_variable_operation_query(schema, op_keyword, field, arg_overrides, seed_map, use_idor_selection)
}

pub fn find_best_probe_target<'a>(schema: &'a GqlSchema) -> Option<&'a GqlField> {
    let query_type_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let fields = schema.fields_for_type(query_type_name);

    // 1. Prioritize Scalars with zero required arguments
    for &field in &fields {
        let has_required_args = field.args.as_ref().map_or(false, |args| {
            args.iter().any(|a| {
                a.arg_type
                    .as_ref()
                    .map_or(false, |tr| tr.kind.as_deref() == Some("NON_NULL"))
            })
        });

        if !has_required_args {
            if let Some(kind) = field_kind(schema, field) {
                if kind == "SCALAR" || kind == "ENUM" {
                    return Some(field);
                }
            }
        }
    }

    // 2. Fallback to any Scalar
    for &field in &fields {
        if let Some(kind) = field_kind(schema, field) {
            if kind == "SCALAR" || kind == "ENUM" {
                return Some(field);
            }
        }
    }

    // 3. Last resort: any field (likely an Object)
    fields.first().copied()
}

pub fn typo_variant(name: &str) -> String {
    if name.ends_with('s') && name.len() > 1 {
        name[..name.len() - 1].to_string()
    } else {
        format!("{}s", name)
    }
}

pub fn extract_verbose_error_hint(message: &str) -> Option<String> {
    let normalized = message.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return None;
    }

    let lower = normalized.to_lowercase();
    let looks_verbose = lower.contains("did you mean")
        || lower.contains("cannot query field")
        || lower.contains("unknown argument")
        || lower.contains("perhaps you meant");

    if !looks_verbose {
        return None;
    }

    let max_len = 220usize;
    if normalized.len() <= max_len {
        Some(normalized)
    } else {
        Some(format!("{}...", &normalized[..max_len]))
    }
}

pub fn find_root_field<'a>(
    schema: &'a GqlSchema,
    root: &str,
    field_name: &str,
) -> Option<&'a GqlField> {
    let type_name = match root {
        "Query" => schema.query_type.as_ref().map(|q| q.name.as_str()),
        "Mutation" => schema.mutation_type.as_ref().map(|m| m.name.as_str()),
        _ => None,
    };

    schema
        .fields_for_type(type_name)
        .into_iter()
        .find(|f| f.name == field_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfuscation_preserves_core_and_differs() {
        let input = "query { user(id: 1) { id name } }";
        let result = obfuscate_query(input, 3);

        assert_ne!(result, input);
        assert!(!result.is_empty());
        assert!(result.contains("user"));
        assert!(result.contains("id"));
        assert!(result.contains("name"));
    }

    #[test]
    fn obfuscation_level_zero_is_identity() {
        let input = "query { user(id: 1) { id name } }";
        assert_eq!(obfuscate_query(input, 0), input);
    }

    #[test]
    fn obfuscation_does_not_touch_string_literals() {
        let input = r#"query { search(term: "hello world") { id } }"#;
        let result = obfuscate_query(input, 3);
        assert!(result.contains("\"hello world\""));
    }
}
