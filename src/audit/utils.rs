<<<<<<< HEAD
use crate::types::{GqlField, GqlSchema};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant};

=======
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

pub fn obfuscate_query(query: &str, level: u8) -> String {
    if level == 0 {
        return query.to_string();
    }

    let mut result = query.to_string();

    // Level 1: Simple whitespace obfuscation
    if level >= 1 {
        result = result.replace(' ', "  ");
        result = result.replace('{', " {\n  ");
        result = result.replace('}', "\n} ");
    }

    // Level 2: Comment injection
    if level >= 2 {
        let lines: Vec<String> = result
            .lines()
            .map(|l| {
                if l.trim().is_empty() {
                    l.to_string()
                } else {
                    format!("{} # {}", l, "abc") // simple comment
                }
            })
            .collect();
        result = lines.join("\n");
    }

    // Level 3: Aggressive line endings
    if level >= 3 {
        result = result.replace("\n", "\r\n");
        result = format!("\n\n{}\n\n", result);
    }

    result
}

>>>>>>> update-research-refs
#[derive(Debug)]
pub struct ProbeResponse {
    pub status: u16,
    pub elapsed_ms: u128,
    pub data: Option<Value>,
    pub errors_text: String,
    pub raw_text: String,
<<<<<<< HEAD
}

pub fn build_client(timeout_secs: u64) -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| e.to_string())
}

pub fn parse_extra_headers(extra_headers: &[String]) -> Vec<(String, String)> {
    extra_headers
        .iter()
        .filter_map(|kv| {
            let mut parts = kv.splitn(2, '=');
            let key = parts.next().unwrap_or("").trim();
            let val = parts.next().unwrap_or("").trim();
            if key.is_empty() {
                None
            } else {
                Some((key.to_string(), val.to_string()))
            }
        })
        .collect()
=======
    pub headers: HashMap<String, String>,
>>>>>>> update-research-refs
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
<<<<<<< HEAD
    let mut parsed = parse_extra_headers(base_headers);
=======
    let mut parsed = crate::utils::parse_extra_headers(base_headers);
>>>>>>> update-research-refs
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
<<<<<<< HEAD
=======
    post_graphql_ext(client, url, headers, query, None, rate_limit_ms, 0).await
}

pub async fn post_graphql_ext(
    client: &Client,
    url: &str,
    headers: &[(String, String)],
    query: &str,
    variables: Option<Value>,
    rate_limit_ms: u64,
    evasion_level: u8,
) -> Result<ProbeResponse, String> {
>>>>>>> update-research-refs
    if rate_limit_ms > 0 {
        tokio::time::sleep(Duration::from_millis(rate_limit_ms)).await;
    }

<<<<<<< HEAD
    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "Introspectre/1.0 (Security-Audit-Only)");
=======
    let final_query = if evasion_level > 0 {
        obfuscate_query(query, evasion_level)
    } else {
        query.to_string()
    };

    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "Introspectre/0.6.0 (Security-Audit-Only)");
>>>>>>> update-research-refs

    for (k, v) in headers {
        req = req.header(k, v);
    }

<<<<<<< HEAD
    let body = serde_json::json!({ "query": query });
=======
    let body = if let Some(vars) = variables {
        serde_json::json!({ "query": final_query, "variables": vars })
    } else {
        serde_json::json!({ "query": final_query })
    };

>>>>>>> update-research-refs
    let started = Instant::now();
    let resp = req.json(&body).send().await.map_err(|e| e.to_string())?;
    let elapsed_ms = started.elapsed().as_millis();
    let status = resp.status().as_u16();
<<<<<<< HEAD
=======

    let mut headers = HashMap::new();
    for (name, value) in resp.headers().iter() {
        if let Ok(v) = value.to_str() {
            headers.insert(name.to_string(), v.to_string());
        }
    }

>>>>>>> update-research-refs
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
<<<<<<< HEAD
    })
}

pub async fn post_batched_graphql(
    client: &Client,
    url: &str,
    headers: &[(String, String)],
    queries: &[String],
    rate_limit_ms: u64,
=======
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
>>>>>>> update-research-refs
) -> Result<Vec<ProbeResponse>, String> {
    if rate_limit_ms > 0 {
        tokio::time::sleep(Duration::from_millis(rate_limit_ms)).await;
    }

    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
<<<<<<< HEAD
        .header("User-Agent", "Introspectre/1.0 (Security-Audit-Batched)");
=======
        .header("User-Agent", "Introspectre/0.6.0 (Security-Audit-Batched)");
>>>>>>> update-research-refs

    for (k, v) in headers {
        req = req.header(k, v);
    }

<<<<<<< HEAD
    let operations: Vec<serde_json::Value> = queries
        .iter()
        .map(|q| serde_json::json!({ "query": q }))
        .collect();

    let body = serde_json::json!(operations);
=======
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
>>>>>>> update-research-refs
    let started = Instant::now();
    let resp = req.json(&body).send().await.map_err(|e| e.to_string())?;
    let elapsed_ms = started.elapsed().as_millis();
    let status = resp.status().as_u16();
<<<<<<< HEAD
=======

    let mut headers_map = HashMap::new();
    for (name, value) in resp.headers().iter() {
        if let Ok(v) = value.to_str() {
            headers_map.insert(name.to_string(), v.to_string());
        }
    }

>>>>>>> update-research-refs
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
                        .unwrap_or_default(),
                    raw_text,
<<<<<<< HEAD
=======
                    headers: headers_map,
>>>>>>> update-research-refs
                }]),
                Err(_) => Err("Failed to parse batched response".to_string()),
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
<<<<<<< HEAD
=======
            headers: headers_map.clone(),
>>>>>>> update-research-refs
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

<<<<<<< HEAD
=======
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
    ]
    .iter()
    .any(|s| m.contains(s))
}

>>>>>>> update-research-refs
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

<<<<<<< HEAD
=======
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

>>>>>>> update-research-refs
    let fields = schema.fields_for_type(Some(type_name.as_str()));
    if fields.is_empty() {
        return base_selection(schema, field);
    }

<<<<<<< HEAD
    let preferred = ["id", "userId", "ownerId", "email", "username", "__typename"];
=======
>>>>>>> update-research-refs
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

<<<<<<< HEAD
pub fn default_literal(type_name: Option<String>) -> String {
    match type_name.unwrap_or_default().as_str() {
        "Int" => "1".to_string(),
        "Float" => "1.0".to_string(),
        "Boolean" => "true".to_string(),
        "ID" => "\"1\"".to_string(),
        "String" => "\"sample\"".to_string(),
        other if other.contains("ID") => "\"1\"".to_string(),
        _ => "\"sample\"".to_string(),
    }
}

pub fn build_operation_query(
    schema: &GqlSchema,
    op_keyword: &str,
    field: &GqlField,
    arg_overrides: &HashMap<String, String>,
=======
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

    if let Some(name) = &type_ref.name {
        // Check seed map first
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

pub fn build_variable_operation_query(
    schema: &GqlSchema,
    op_keyword: &str,
    field: &GqlField,
    arg_overrides: &HashMap<String, Value>, // Using Value now for variables
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
            
            let val = if let Some(ovr) = arg_overrides.get(&arg.name) {
                ovr.clone()
            } else {
                let s = arg.arg_type.as_ref()
                    .map(|tr| resolve_complex_default(schema, tr, &arg.name, 0, HashSet::new(), seed_map))
                    .unwrap_or_else(|| "null".to_string());
                // Try to parse as JSON if it's a complex default, otherwise it's a string/literal
                serde_json::from_str(&s).unwrap_or(Value::String(s.replace("\"", "")))
            };
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
>>>>>>> update-research-refs
    use_idor_selection: bool,
) -> String {
    let mut args_rendered: Vec<String> = Vec::new();
    if let Some(args) = &field.args {
        for arg in args {
            let value = arg_overrides.get(&arg.name).cloned().unwrap_or_else(|| {
<<<<<<< HEAD
                default_literal(arg.arg_type.as_ref().and_then(|t| t.unwrap_type_name()))
=======
                arg.arg_type
                    .as_ref()
                    .map(|tr| {
                        resolve_complex_default(schema, tr, &arg.name, 0, HashSet::new(), seed_map)
                    })
                    .unwrap_or_else(|| "null".to_string())
>>>>>>> update-research-refs
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

<<<<<<< HEAD
    format!(
        "{} {{ {}{} {} }}",
        op_keyword, field.name, args_block, selection
    )
}

pub fn has_required_args(field: &GqlField) -> bool {
    field
        .args
        .as_ref()
        .map(|args| {
            args.iter()
                .any(|a| a.arg_type.as_ref().and_then(|t| t.kind.as_deref()) == Some("NON_NULL"))
        })
        .unwrap_or(false)
=======
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
>>>>>>> update-research-refs
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

<<<<<<< HEAD
pub fn parse_candidate(label: &str) -> Option<(String, String, String)> {
    let dot = label.find('.')?;
    let open = label.find('(')?;
    let close = label.find(')')?;
    if close <= open || open <= dot {
        return None;
    }

    let root = label[..dot].to_string();
    let field = label[dot + 1..open].to_string();
    let arg = label[open + 1..close].to_string();
    Some((root, field, arg))
}

=======
>>>>>>> update-research-refs
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
