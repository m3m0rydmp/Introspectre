use serde::Serialize;
use std::fs;
use std::path::PathBuf;

use crate::types::{AuthDiscoveryResult, Finding, GqlSchema, ReportMeta, SchemaStats, Severity};

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

pub fn write_visual_report(
    path: &PathBuf,
    schema: &GqlSchema,
    findings: &[Finding],
    meta: &ReportMeta,
    stats: &SchemaStats,
    seeds: &[crate::traffic::TrafficSeed],
) -> Result<(), String> {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

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

        nodes.push(VisualNode {
            id: name.clone(),
            label: name.clone(),
            kind: kind.to_string(),
            is_sensitive,
            auth_required,
            risk,
            is_root,
            op_type,
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
                                    });
                                }
                            }
                        }
                    }

                    if f.is_deprecated.unwrap_or(false) {
                        weight += 2.0;
                    }

                    edges.push(VisualEdge {
                        source: name.clone(),
                        target: target_name,
                        label: f.name.clone(),
                        is_deprecated: f.is_deprecated.unwrap_or(false),
                        args: args_info,
                        weight,
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
                        });
                    }
                }
            }
        }
    }

    let graph = VisualGraph { nodes, edges };
    let graph_json = serde_json::to_string(&graph).map_err(|e| e.to_string())?;

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
        }));
    }
    let findings_json = serde_json::to_string(&finding_details).map_err(|e| e.to_string())?;
    let seeds_json = serde_json::to_string(seeds).unwrap_or_else(|_| "[]".to_string());
    let stats_json = serde_json::to_string(stats).unwrap_or_default();
    let meta_json = serde_json::to_string(meta).unwrap_or_default();

    // Vendored graph libraries, inlined so the report renders with no network access.
    // Load order matters: graphology (the graph data structure), then graphology-library
    // (layout algorithms like ForceAtlas2, built against the graphology global), then
    // sigma (the WebGL renderer, which renders a graphology graph instance directly).
    let vendor_js = format!(
        "<script>{}</script>\n<script>{}</script>\n<script>{}</script>",
        include_str!("vendor/graphology.umd.min.js"),
        include_str!("vendor/graphology-library.min.js"),
        include_str!("vendor/sigma.min.js"),
    );

    let html = include_str!("visual_template.html")
        .replace("{{VENDOR_JS}}", &vendor_js)
        .replace("{{GRAPH_DATA}}", &escape_for_script(&graph_json))
        .replace("{{FINDINGS_DATA}}", &escape_for_script(&findings_json))
        .replace("{{SOURCE}}", &escape_for_script(&meta.source))
        .replace("{{STATS}}", &escape_for_script(&stats_json))
        .replace("{{META}}", &escape_for_script(&meta_json))
        .replace("{{SEEDS_DATA}}", &escape_for_script(&seeds_json));

    fs::write(path, html).map_err(|e| format!("Failed to write visual report: {}", e))
}

/// Escapes a string that will be spliced directly into an inline `<script>` block (or into
/// an HTML attribute like `{{SOURCE}}`'s usages), preventing a `</script>` (or `{{...}}`
/// placeholder-shaped) substring inside untrusted data from prematurely closing the tag or
/// being mistaken for another template token. Replacing `</` with `<\/` is valid inside both
/// JSON string literals and raw text and does not change the parsed value.
fn escape_for_script(s: &str) -> String {
    s.replace("</", "<\\/")
}
