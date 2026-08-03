use serde::Serialize;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

use crate::types::{AuthDiscoveryResult, Finding, GqlSchema, ReportMeta, SchemaStats, Severity};

/// Cap on how deep a root→type query path may nest before we fall back to a bare
/// selection fragment, so a pathological schema can't produce absurd queries.
const MAX_PATH_DEPTH: usize = 6;

#[derive(Serialize)]
struct VisualNode {
    id: String,
    label: String,
    kind: String,
    #[serde(rename = "isSensitive")]
    is_sensitive: bool,
    #[serde(rename = "authRequired")]
    auth_required: bool,
    risk: String,
    #[serde(rename = "isRoot")]
    is_root: bool,
    #[serde(rename = "opType")]
    op_type: Option<String>,
    /// A complete, runnable `query { … }` (or `mutation`/`subscription`) that reaches this
    /// node via the shortest path from a root operation. `None` for root types (their queries
    /// live per field on the outgoing edges) and for types unreachable from any root.
    #[serde(rename = "sampleQuery", skip_serializing_if = "Option::is_none")]
    sample_query: Option<String>,
    /// For ENUM nodes, the value names — so the schema tree can list them.
    #[serde(rename = "enumValues", skip_serializing_if = "Option::is_none")]
    enum_values: Option<Vec<String>>,
}

#[derive(Serialize)]
struct VisualArg {
    name: String,
    #[serde(rename = "isRequired")]
    is_required: bool,
    #[serde(rename = "sampleValue")]
    sample_value: String,
    #[serde(rename = "typeName")]
    type_name: String,
}

#[derive(Serialize)]
struct VisualEdge {
    source: String,
    target: String,
    label: String,
    #[serde(rename = "isDeprecated")]
    is_deprecated: bool,
    args: Vec<VisualArg>,
    weight: f64,
    /// A ready-to-run operation template — set only on edges from a root type
    /// (Query/Mutation/Subscription) so the detail panel can show a per-field sample query.
    #[serde(skip_serializing_if = "Option::is_none")]
    sample: Option<String>,
}

#[derive(Serialize)]
struct VisualGraph {
    nodes: Vec<VisualNode>,
    edges: Vec<VisualEdge>,
}

fn resolve_input_sample(schema: &GqlSchema, type_ref: &crate::types::GqlTypeRef, field_name: &str, depth: usize) -> String {
    if depth > 3 { return "{}".to_string(); }
    
    let kind = type_ref.kind.as_deref().unwrap_or("");
    if kind == "NON_NULL" || kind == "LIST" {
        if let Some(inner) = &type_ref.of_type {
            return resolve_input_sample(schema, inner, field_name, depth);
        }
    }

    if let Some(name) = &type_ref.name {
        let synthesized = crate::utils::synthesize_value(field_name, name);
        if synthesized != "null" {
            return synthesized;
        }

        if let Some(gql_type) = schema.find_type(name) {
            if gql_type.kind.as_deref() == Some("INPUT_OBJECT") {
                let mut parts = Vec::new();
                if let Some(fields) = &gql_type.input_fields {
                    for f in fields.iter().take(5) { 
                        let val = f.field_type.as_ref()
                            .map(|tr| resolve_input_sample(schema, tr, &f.name, depth + 1))
                            .unwrap_or_else(|| "null".to_string());
                        parts.push(format!("{}: {}", f.name, val));
                    }
                }
                return format!("{{ {} }}", parts.join(", "));
            } else if gql_type.kind.as_deref() == Some("ENUM") {
                 if let Some(vals) = &gql_type.enum_values {
                     if let Some(v) = vals.first() {
                         return v.name.clone();
                     }
                 }
                 return "ENUM_VAL".to_string();
            }
        }
    }
    "null".to_string()
}

pub fn generate_query_template(
    schema: &GqlSchema,
    auth: Option<&AuthDiscoveryResult>,
    type_name: &str,
    field_name: &str,
    seeds: &[crate::traffic::TrafficSeed],
    injection_payload: Option<&str>,
) -> serde_json::Value {
    let err_val = |msg: &str| serde_json::json!({ "literal": msg, "variable": msg });
    
    let gql_type = match schema.find_type(type_name) {
        Some(t) => t,
        None => return err_val(&format!("# Type {} not found", type_name)),
    };

    let field = match gql_type
        .fields
        .as_ref()
        .and_then(|fs| fs.iter().find(|f| f.name == field_name))
    {
        Some(f) => f,
        None => return err_val(&format!("# Field {}.{} not found", type_name, field_name)),
    };

    let operation_type = if type_name
        == schema
            .mutation_type
            .as_ref()
            .map(|t| t.name.as_str())
            .unwrap_or("Mutation")
    {
        "mutation"
    } else if type_name
        == schema
            .subscription_type
            .as_ref()
            .map(|t| t.name.as_str())
            .unwrap_or("Subscription")
    {
        "subscription"
    } else {
        "query"
    };

    let mut literal_query = String::new();
    let mut var_query_body = String::new();
    let mut var_defs = Vec::new();

    literal_query.push_str(operation_type);
    literal_query.push_str(" {\n");
    literal_query.push_str(&format!("  {}", field_name));

    var_query_body.push_str(&format!("  {}", field_name));

    if let Some(args) = &field.args {
        if !args.is_empty() {
            literal_query.push('(');
            var_query_body.push('(');
            let mut arg_parts_lit = Vec::new();
            let mut arg_parts_var = Vec::new();
            for arg in args {
                let type_name_val = arg.arg_type.as_ref().and_then(|t| t.unwrap_type_name()).unwrap_or_else(|| "String".to_string());
                
                let mut placeholder = match type_name_val.as_str() {
                    "String" => "\"VALUE\"".to_string(),
                    "Int" => "0".to_string(),
                    "Float" => "0.0".to_string(),
                    "Boolean" => "false".to_string(),
                    "ID" => "\"ID\"".to_string(),
                    _ => "null".to_string(),
                };

                let mut annotation = String::new();
                
                // Prioritize injection payload for reproduction templates
                if let Some(payload) = injection_payload {
                    placeholder = if type_name_val == "String" || type_name_val == "ID" {
                        format!("\"{}\"", payload)
                    } else {
                        payload.to_string()
                    };
                    annotation = " # [Injection Payload]".to_string();
                } else if let Some(seed) = seeds.iter().find(|s| s.field_name == arg.name) {
                    placeholder = if type_name_val == "String" || type_name_val == "ID" {
                        format!("\"{}\"", seed.value)
                    } else {
                        seed.value.clone()
                    };
                    annotation = format!(" # [Source: {}]", seed.source);
                }

                arg_parts_lit.push(format!("{}: {}{}", arg.name, placeholder, annotation));
                arg_parts_var.push(format!("{}: ${}", arg.name, arg.name));
                var_defs.push(format!("${}: {}", arg.name, type_name_val));
            }
            literal_query.push_str(&arg_parts_lit.join(", "));
            literal_query.push(')');
            
            var_query_body.push_str(&arg_parts_var.join(", "));
            var_query_body.push(')');
        }
    }

    if let Some(field_type) = &field.field_type {
        if let Some(inner_type_name) = field_type.unwrap_type_name() {
            if let Some(inner_type) = schema.find_type(&inner_type_name) {
                if inner_type.kind.as_deref() == Some("OBJECT")
                    || inner_type.kind.as_deref() == Some("INTERFACE")
                    || inner_type.kind.as_deref() == Some("UNION")
                {
                    let type_select = " {\n".to_string() + 
                        &format!("    {}\n", inner_type
                        .fields
                        .as_ref()
                        .and_then(|fs| {
                            fs.iter()
                                .find(|f| f.name == "id" || f.name == "uuid" || f.name == "name")
                        })
                        .map(|f| f.name.as_str())
                        .unwrap_or("__typename")) + "  }";
                    
                    literal_query.push_str(&type_select);
                    var_query_body.push_str(&type_select);
                }
            }
        }
    }

    literal_query.push_str("\n}");
    
    let var_query = if !var_defs.is_empty() {
        let mut unique_defs = Vec::new();
        for def in var_defs {
            if !unique_defs.contains(&def) {
                unique_defs.push(def);
            }
        }
        format!("{} Explore({}) {{\n{}\n}}", operation_type, unique_defs.join(", "), var_query_body)
    } else {
        format!("{} Explore {{\n{}\n}}", operation_type, var_query_body)
    };

    let lit_final = query_template_with_auth_hint(schema, auth, type_name, field_name, literal_query);
    let var_final = query_template_with_auth_hint(schema, auth, type_name, field_name, var_query);

    serde_json::json!({
        "literal": lit_final,
        "variable": var_final
    })
}

fn query_template_with_auth_hint(
    schema: &GqlSchema,
    auth: Option<&AuthDiscoveryResult>,
    type_name: &str,
    field_name: &str,
    mut query: String,
) -> String {
    let is_root = schema
        .query_type
        .as_ref()
        .map(|t| t.name.as_str() == type_name)
        .unwrap_or(false)
        || schema
            .mutation_type
            .as_ref()
            .map(|t| t.name.as_str() == type_name)
            .unwrap_or(false);

    if is_root {
        let label = format!("{}.{}", type_name, field_name);
        let requires_auth = auth.map(|a| a.protected.contains(&label)).unwrap_or(false);

        if requires_auth {
            query.insert_str(0, "# [AUTH REQUIRED] This field was confirmed to require authentication.\n# Header: Authorization: Bearer <TOKEN>\n\n");
        } else {
            query.insert_str(
                0,
                "# Hint: This root field might require authentication.\n\n",
            );
        }
    }
    query
}

/// Up to 8 selectable field lines for an object-like type (composite fields get a nested
/// `{ id }`/`{ __typename }`). The shared building block for both the leaf selection of a
/// path query and the bare-fragment fallback.
fn selection_field_lines(schema: &GqlSchema, type_name: &str) -> Vec<String> {
    let fields = match schema.find_type(type_name).and_then(|t| t.fields.as_ref()) {
        Some(f) if !f.is_empty() => f,
        _ => return vec!["__typename".to_string()],
    };
    let mut lines = Vec::new();
    for f in fields.iter().take(8) {
        let inner = f.field_type.as_ref().and_then(|t| t.unwrap_type_name());
        let child = inner.as_ref().and_then(|n| schema.find_type(n));
        let is_composite = child
            .map(|t| matches!(t.kind.as_deref(), Some("OBJECT") | Some("INTERFACE") | Some("UNION")))
            .unwrap_or(false);
        if is_composite {
            let child_sel = child
                .and_then(|t| t.fields.as_ref())
                .and_then(|fs| fs.iter().find(|cf| cf.name == "id" || cf.name == "uuid" || cf.name == "name"))
                .map(|cf| cf.name.clone())
                .unwrap_or_else(|| "__typename".to_string());
            lines.push(format!("{} {{ {} }}", f.name, child_sel));
        } else {
            lines.push(f.name.clone());
        }
    }
    lines
}

/// A bare selection fragment (`{\n  id\n  … }`) for an object-like type — the fallback shown
/// when a type is not reachable from any root operation.
fn sample_selection(schema: &GqlSchema, type_name: &str) -> String {
    let body = selection_field_lines(schema, type_name)
        .iter()
        .map(|l| format!("  {}", l))
        .collect::<Vec<_>>()
        .join("\n");
    format!("{{\n{}\n}}", body)
}

/// The cost of *entering* a field on a query path: 1 for the hop itself, plus a penalty for each
/// **required** argument (scalar/enum/ID `+1`, `INPUT_OBJECT`/list-of-input `+3`). Optional args add
/// nothing — they can be omitted. So a trivial `userById(id: ID!)` beats `search(input: In!)`, and an
/// arg-free (or optional-only) field beats both, even when they sit at the same depth.
fn field_arg_cost(schema: &GqlSchema, field: &crate::types::GqlField) -> u32 {
    let args = match &field.args {
        Some(a) if !a.is_empty() => a,
        _ => return 0,
    };
    let mut cost = 0;
    for arg in args {
        let required = arg
            .arg_type
            .as_ref()
            .map(|t| t.kind.as_deref() == Some("NON_NULL"))
            .unwrap_or(false);
        if !required {
            continue;
        }
        let type_name = arg.arg_type.as_ref().and_then(|t| t.unwrap_type_name()).unwrap_or_default();
        let kind = schema.find_type(&type_name).and_then(|t| t.kind.clone()).unwrap_or_default();
        cost += if kind == "INPUT_OBJECT" { 3 } else { 1 };
    }
    cost
}

/// Multi-source **Dijkstra** from the root operation types over `type --field--> returnType` edges,
/// with edge weight `1 + field_arg_cost(field)`. Returns a parent map
/// `target_type -> (source_type, field_name)` giving the **cheapest** (fewest-hops, then
/// simplest-args) path from a root to each reachable type. Root types have no entry.
fn compute_query_paths(schema: &GqlSchema) -> HashMap<String, (String, String)> {
    let mut parent: HashMap<String, (String, String)> = HashMap::new();
    let mut dist: HashMap<String, u32> = HashMap::new();
    let mut heap: BinaryHeap<Reverse<(u32, String)>> = BinaryHeap::new();

    for root in [
        schema.query_type.as_ref(),
        schema.mutation_type.as_ref(),
        schema.subscription_type.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if dist.insert(root.name.clone(), 0).is_none() {
            heap.push(Reverse((0, root.name.clone())));
        }
    }

    while let Some(Reverse((d, type_name))) = heap.pop() {
        if d > *dist.get(&type_name).unwrap_or(&u32::MAX) {
            continue; // stale heap entry
        }
        let gql_type = match schema.find_type(&type_name) {
            Some(t) => t,
            None => continue,
        };
        if let Some(fields) = &gql_type.fields {
            for f in fields {
                if let Some(ret) = f.field_type.as_ref().and_then(|t| t.unwrap_type_name()) {
                    if ret.starts_with("__") {
                        continue;
                    }
                    let nd = d + 1 + field_arg_cost(schema, f);
                    if nd < *dist.get(&ret).unwrap_or(&u32::MAX) {
                        dist.insert(ret.clone(), nd);
                        parent.insert(ret.clone(), (type_name.clone(), f.name.clone()));
                        heap.push(Reverse((nd, ret)));
                    }
                }
            }
        }
    }
    parent
}

/// Render a field's **required** arguments (`(id: "…")`) using learned seeds where the arg name
/// matches, else a synthesized sample value. Optional args are omitted to keep the generated query
/// minimal and satisfiable. Empty string when the field has no required args.
fn render_field_args(
    schema: &GqlSchema,
    source_type: &str,
    field_name: &str,
    seeds: &[crate::traffic::TrafficSeed],
) -> String {
    let args = match schema
        .find_type(source_type)
        .and_then(|t| t.fields.as_ref())
        .and_then(|fs| fs.iter().find(|f| f.name == field_name))
        .and_then(|f| f.args.as_ref())
    {
        Some(a) if !a.is_empty() => a,
        _ => return String::new(),
    };

    let parts: Vec<String> = args
        .iter()
        .filter(|arg| {
            arg.arg_type
                .as_ref()
                .map(|t| t.kind.as_deref() == Some("NON_NULL"))
                .unwrap_or(false)
        })
        .map(|arg| {
            let type_name = arg
                .arg_type
                .as_ref()
                .and_then(|t| t.unwrap_type_name())
                .unwrap_or_else(|| "String".to_string());
            let value = if let Some(seed) = seeds.iter().find(|s| s.field_name == arg.name) {
                if type_name == "String" || type_name == "ID" {
                    format!("\"{}\"", seed.value)
                } else {
                    seed.value.clone()
                }
            } else {
                arg.arg_type
                    .as_ref()
                    .map(|tr| resolve_input_sample(schema, tr, &arg.name, 0))
                    .unwrap_or_else(|| "\"VALUE\"".to_string())
            };
            format!("{}: {}", arg.name, value)
        })
        .collect();

    if parts.is_empty() {
        String::new()
    } else {
        format!("({})", parts.join(", "))
    }
}

/// Build a complete, runnable operation reaching `target` from a root, using the BFS `parent`
/// map. Object-like leaves get a nested selection; scalar/enum leaves are the field itself.
/// Returns `None` when `target` is a root type, unreachable, or deeper than [`MAX_PATH_DEPTH`].
fn build_query_from_path(
    schema: &GqlSchema,
    parent: &HashMap<String, (String, String)>,
    target: &str,
    seeds: &[crate::traffic::TrafficSeed],
) -> Option<String> {
    // Walk the parent chain from target up to a root; `chain` ends up [(root, f1), … , (tN-1, fLeaf)].
    let mut chain: Vec<(String, String)> = Vec::new();
    let mut cur = target.to_string();
    let mut guard: HashSet<String> = HashSet::new();
    while let Some((src, field)) = parent.get(&cur) {
        if !guard.insert(cur.clone()) {
            break;
        }
        chain.push((src.clone(), field.clone()));
        cur = src.clone();
    }
    if chain.is_empty() || chain.len() > MAX_PATH_DEPTH {
        return None;
    }

    let root = cur; // the last source reached is the root operation type
    let op = if schema.mutation_type.as_ref().map(|t| t.name.as_str()) == Some(root.as_str()) {
        "mutation"
    } else if schema.subscription_type.as_ref().map(|t| t.name.as_str()) == Some(root.as_str()) {
        "subscription"
    } else {
        "query"
    };

    chain.reverse(); // now root → … → leaf
    let fields_with_args: Vec<String> = chain
        .iter()
        .map(|(src, f)| format!("{}{}", f, render_field_args(schema, src, f, seeds)))
        .collect();

    let target_kind = schema.find_type(target).and_then(|t| t.kind.clone()).unwrap_or_default();
    let leaf_lines = if matches!(target_kind.as_str(), "OBJECT" | "INTERFACE" | "UNION") {
        selection_field_lines(schema, target)
    } else {
        Vec::new()
    };

    let n = fields_with_args.len();
    let mut out = format!("{} {{\n", op);
    for (i, fa) in fields_with_args.iter().enumerate() {
        let ind = "  ".repeat(i + 1);
        if i + 1 < n {
            out.push_str(&format!("{}{} {{\n", ind, fa));
        } else if leaf_lines.is_empty() {
            out.push_str(&format!("{}{}\n", ind, fa)); // scalar/enum leaf: field itself
        } else {
            out.push_str(&format!("{}{} {{\n", ind, fa));
            let lind = "  ".repeat(i + 2);
            for l in &leaf_lines {
                out.push_str(&format!("{}{}\n", lind, l));
            }
            out.push_str(&format!("{}}}\n", ind));
        }
    }
    // Close the intermediate (non-leaf) field braces, then the operation brace.
    for i in (0..n.saturating_sub(1)).rev() {
        out.push_str(&format!("{}}}\n", "  ".repeat(i + 1)));
    }
    out.push('}');
    Some(out)
}

fn get_risk_level(type_name: &str, findings: &[Finding]) -> String {
    let mut max_severity = Severity::Info;
    let mut found = false;

    for f in findings {
        for loc in &f.affected {
            let matches = match loc {
                crate::types::AffectedLocation::Type(t) => t == type_name,
                crate::types::AffectedLocation::Field(t, _) => t == type_name,
                crate::types::AffectedLocation::Argument(t, _, _) => t == type_name,
            };
            if matches {
                found = true;
                if f.severity > max_severity {
                    max_severity = f.severity.clone();
                }
            }
        }
    }

    if !found {
        return "neutral".to_string();
    }

    match max_severity {
        Severity::Critical => "critical".to_string(),
        Severity::High => "high".to_string(),
        Severity::Medium => "medium".to_string(),
        Severity::Low => "low".to_string(),
        Severity::Info => "info".to_string(),
    }
}

/// Assemble the full visualization payload (graph, findings, seeds, stats, meta,
/// server fingerprint) as a single JSON value. This is served verbatim by the
/// local visualizer web server at `GET /api/schema`; the frontend fetches it on
/// load instead of having the data baked into an HTML file.
pub fn build_payload(
    schema: &GqlSchema,
    findings: &[Finding],
    meta: &ReportMeta,
    stats: &SchemaStats,
    seeds: &[crate::traffic::TrafficSeed],
) -> serde_json::Value {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    // Shortest root→type paths (single multi-source BFS), so every reachable node can carry a
    // complete runnable query rather than a bare selection fragment.
    let query_paths = compute_query_paths(schema);

    // 1. Create a node for EVERY type in the schema (including SCALARs)
    for gql_type in &schema.types {
        let name = match &gql_type.name {
            Some(n) if n.starts_with("__") => continue,
            Some(n) => n,
            None => continue,
        };

        let kind = gql_type.kind.as_deref().unwrap_or("UNKNOWN");
        let risk = get_risk_level(name, findings);

        let mut is_sensitive = false;
        let sensitive_keywords = [
            "password", "token", "secret", "email", "phone", "address", "key",
        ];
        if let Some(fields) = &gql_type.fields {
            for f in fields {
                if sensitive_keywords
                    .iter()
                    .any(|&k| f.name.to_lowercase().contains(k))
                {
                    is_sensitive = true;
                    break;
                }
            }
        }

        let auth_required = meta
            .auth_discovery
            .as_ref()
            .map(|a| a.protected.iter().any(|p| p.starts_with(name)))
            .unwrap_or(false);

        let mut op_type = None;
        let is_root = if schema.query_type.as_ref().map(|t| &t.name == name).unwrap_or(false) {
            op_type = Some("query".to_string());
            true
        } else if schema.mutation_type.as_ref().map(|t| &t.name == name).unwrap_or(false) {
            op_type = Some("mutation".to_string());
            true
        } else if schema.subscription_type.as_ref().map(|t| &t.name == name).unwrap_or(false) {
            op_type = Some("subscription".to_string());
            true
        } else {
            false
        };

        // A complete query reaching this node from a root (non-root types only). If the type
        // is unreachable from any root, fall back to a bare selection fragment for object-likes.
        let sample_query = if is_root {
            None
        } else {
            build_query_from_path(schema, &query_paths, name, seeds).or_else(|| {
                if matches!(kind, "OBJECT" | "INTERFACE" | "UNION") {
                    Some(sample_selection(schema, name))
                } else {
                    None
                }
            })
        };

        // Enum value names, so the schema tree can list them.
        let enum_values = if kind == "ENUM" {
            gql_type
                .enum_values
                .as_ref()
                .map(|vs| vs.iter().map(|v| v.name.clone()).collect())
        } else {
            None
        };

        nodes.push(VisualNode {
            id: name.clone(),
            label: name.clone(),
            kind: kind.to_string(),
            is_sensitive,
            auth_required,
            risk,
            is_root,
            op_type,
            sample_query,
            enum_values,
        });

        // 2. Create an edge for EVERY field connection (Return Types)
        if let Some(fields) = &gql_type.fields {
            for f in fields {
                if let Some(target_name) = f.field_type.as_ref().and_then(|t| t.unwrap_type_name()) {
                    if target_name.starts_with("__") {
                        continue;
                    }
                    
                    let mut weight = 1.0;
                    let mut args_info = Vec::new();
                    if let Some(args) = &f.args {
                        for arg in args {
                            let is_required = arg
                                .arg_type
                                .as_ref()
                                .map(|t| t.kind.as_deref() == Some("NON_NULL"))
                                .unwrap_or(false);
                            
                            weight += if is_required { 0.8 } else { 0.3 };

                            let sample_value = arg.arg_type.as_ref()
                                .map(|tr| resolve_input_sample(schema, tr, &arg.name, 0))
                                .unwrap_or_else(|| "\"VALUE\"".to_string());

                            let arg_type_name = arg.arg_type.as_ref()
                                .and_then(|t| t.unwrap_type_name())
                                .unwrap_or_else(|| "String".to_string());

                            args_info.push(VisualArg {
                                name: arg.name.clone(),
                                is_required,
                                sample_value,
                                type_name: arg_type_name.clone(),
                            });

                            // ALSO create an edge from the parent type to the argument type if it's an OBJECT or INPUT_OBJECT
                            if let Some(arg_gql_type) = schema.find_type(&arg_type_name) {
                                let arg_kind = arg_gql_type.kind.as_deref().unwrap_or("");
                                if arg_kind == "OBJECT" || arg_kind == "INPUT_OBJECT" || arg_kind == "ENUM" {
                                     edges.push(VisualEdge {
                                        source: name.clone(),
                                        target: arg_type_name,
                                        label: format!("{}({})", f.name, arg.name),
                                        is_deprecated: false,
                                        args: vec![],
                                        weight: 0.5, // Lighter weight for argument connections
                                        sample: None,
                                    });
                                }
                            }
                        }
                    }

                    if f.is_deprecated.unwrap_or(false) {
                        weight += 2.0;
                    }

                    // Root-operation fields get a ready-to-run query template (with seed
                    // values + auth hints), so the detail panel can show a per-field sample.
                    let sample = if is_root {
                        generate_query_template(schema, meta.auth_discovery.as_ref(), name, &f.name, seeds, None)
                            .get("literal")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    } else {
                        None
                    };

                    edges.push(VisualEdge {
                        source: name.clone(),
                        target: target_name,
                        label: f.name.clone(),
                        is_deprecated: f.is_deprecated.unwrap_or(false),
                        args: args_info,
                        weight,
                        sample,
                    });
                }
            }
        }

        // 3. Create edges for INPUT_OBJECT fields (connecting inputs to scalars/enums)
        if gql_type.kind.as_deref() == Some("INPUT_OBJECT") {
            if let Some(input_fields) = &gql_type.input_fields {
                for f in input_fields {
                    if let Some(target_name) = f.field_type.as_ref().and_then(|t| t.unwrap_type_name()) {
                        edges.push(VisualEdge {
                            source: name.clone(),
                            target: target_name,
                            label: f.name.clone(),
                            is_deprecated: false,
                            args: vec![],
                            weight: 1.0,
                            sample: None,
                        });
                    }
                }
            }
        }
    }

    let graph = VisualGraph { nodes, edges };

    let mut finding_details = Vec::new();
    for f in findings {
        let templates: Vec<serde_json::Value> = f
            .affected
            .iter()
            .map(|loc| {
                match loc {
                    crate::types::AffectedLocation::Field(t, fi) |
                    crate::types::AffectedLocation::Argument(t, fi, _) => {
                        // Extract payload from PoC if it's an injection
                        let payload = if f.title.to_lowercase().contains("injection") {
                            f.poc.as_ref().and_then(|poc| {
                                poc.split('"').nth(1) // Very naive extraction, but better than nothing
                            })
                        } else {
                            None
                        };
                        generate_query_template(schema, meta.auth_discovery.as_ref(), t, fi, seeds, payload)
                    }
                    _ => {
                        let msg = format!("# No template for {}", loc);
                        serde_json::json!({ "literal": msg, "variable": msg })
                    }
                }
            })
            .collect();

        finding_details.push(serde_json::json!({
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "description": f.description,
            "remediation": f.remediation,
            "first_step": f.first_step,
            "status": f.status,
            "references": f.references,
            "affected": f.affected.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            "templates": templates,
            "poc": f.poc,
            "exploit_guide": crate::audit::poc::sqlmap_guide(f, &meta.source),
        }));
    }
    serde_json::json!({
        "graph": graph,
        "findings": finding_details,
        "seeds": seeds,
        "stats": stats,
        "meta": meta,
        "source": meta.source,
        "serverFingerprint": meta.server_fingerprint.as_ref().map(|f| f.label()),
    })
}
