use crate::audit::utils::{
    build_operation_query, effective_headers, field_non_null_data, is_auth_error,
};
use crate::config::AppConfig;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, Severity};
use reqwest::Client;
use std::collections::HashMap;

pub async fn probe_mutation_privesc(
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
    let mutation_name = schema.mutation_type.as_ref().map(|m| m.name.as_str());
    let mutation_fields = schema.fields_for_type(mutation_name);

    let priv_patterns = [
        "role", "admin", "privilege", "permission", "isAdmin", "is_admin",
        "superuser", "super_user", "rank", "level", "access", "staff", "owner",
    ];

    let headers = effective_headers(
        extra_headers,
        Some(config.session.auth_header.as_str()),
        true,
    );

    for field in mutation_fields {
        if let Some(args) = &field.args {
            for arg in args {
                let mut targets = Vec::new();

                // 1. Direct argument check
                if priv_patterns.iter().any(|&p| arg.name.to_lowercase().contains(p)) {
                    targets.push((arg.name.clone(), arg.arg_type.as_ref()));
                }

                // 2. Input Object field check (Mass Assignment)
                if let Some(type_name) = arg.arg_type.as_ref().and_then(|t| t.unwrap_type_name()) {
                    if let Some(it) = schema.find_type(&type_name) {
                        if let Some(input_fields) = &it.input_fields {
                            for ifield in input_fields {
                                if priv_patterns.iter().any(|&p| ifield.name.to_lowercase().contains(p)) {
                                    targets.push((format!("{}.{}", arg.name, ifield.name), ifield.field_type.as_ref()));
                                }
                            }
                        }
                    }
                }

                for (path, field_type) in targets {
                    let Some(ft) = field_type else { continue; };
                    let tn = ft.unwrap_type_name().unwrap_or_else(|| "String".to_string());

                    let payload = match tn.as_str() {
                        "Boolean" => serde_json::Value::Bool(true),
                        "Int" | "Float" => serde_json::Value::Number(99.into()),
                        _ => serde_json::Value::String("admin".to_string()),
                    };

                    let mut overrides = HashMap::new();
                    // Handle nested paths for input objects
                    if path.contains('.') {
                        let parts: Vec<&str> = path.split('.').collect();
                        let mut inner_obj = serde_json::Map::new();
                        inner_obj.insert(parts[1].to_string(), payload.clone());
                        overrides.insert(parts[0].to_string(), serde_json::Value::Object(inner_obj));
                    } else {
                        overrides.insert(path.clone(), payload.clone());
                    }

                    let gql_op = build_operation_query(schema, "mutation", field, &overrides, &config.audit.seeds, false);
                    let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op.query, Some(gql_op.variables), rate_limit_ms, evasion_level).await?;

                    let success = field_non_null_data(&resp.data, &field.name).is_some() 
                        && !is_auth_error(&resp.errors_text);

                    if success {
                        confirmed.push(Finding {
                            id: "AUD-011",
                            severity: Severity::High,
                            title: "Potential Mutation Privilege Escalation / Mass Assignment",
                            description: format!(
                                "The mutation '{}.{}' accepted an escalated value '{}' for the sensitive field '{}'. This suggests the server may not be properly validating or restricting this field, potentially allowing unauthorized privilege changes or mass assignment.",
                                "Mutation", field.name, payload, path
                            ),
                            affected: vec![AffectedLocation::Argument("Mutation".into(), field.name.clone(), path.clone())],
                            remediation: "Implement strict allow-lists for mutation input fields. Use specific 'Update' input types that exclude sensitive administrative fields. Enforce field-level authorization in resolvers.",
                            first_step: Some(format!("Execute the PoC mutation and verify if the sensitive field '{}' was actually updated in the database or reflected in the response.", path)),
                            references: vec!["OWASP API6: Mass Assignment", "CWE-915: Improperly Controlled Modification"],
                            status: FindingStatus::Confirmed,
                            confidence: Confidence::Confirmed,
                            evidence_level: EvidenceLevel::Executed,
                            poc: Some(gql_op.query),
                        });
                        break; // Move to next field if one arg is confirmed
                    }
                }
            }
        }
    }

    Ok(())
}
