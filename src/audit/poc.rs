use crate::types::{AffectedLocation, Finding, GqlSchema};
use serde_json::json;

pub fn generate_reproduction_steps(
    finding: &Finding,
    schema: &GqlSchema,
    url: &str,
) -> Option<String> {
    // 1. If an active probe already provided a high-quality PoC, use it.
    if let Some(poc) = &finding.poc {
        if poc.starts_with("curl") || poc.starts_with("#") || poc.starts_with("query") || poc.starts_with("mutation") {
            return Some(poc.clone());
        }
    }

    // 2. Otherwise, attempt to synthesize one from the affected locations.
    let loc = finding.affected.first()?;

    match loc {
        AffectedLocation::Field(type_name, field_name) | AffectedLocation::Argument(type_name, field_name, _) => {
            let op_type = if type_name == "Mutation" || schema.mutation_type.as_ref().map(|t| &t.name == type_name).unwrap_or(false) {
                "mutation"
            } else if type_name == "Subscription" || schema.subscription_type.as_ref().map(|t| &t.name == type_name).unwrap_or(false) {
                "subscription"
            } else {
                "query"
            };

            // Simple synthesized query
            let mut poc = format!("{} {{\n  {}", op_type, field_name);
            
            // Add basic selection if it's an object/interface
            if let Some(field) = schema.find_type(type_name).and_then(|t| t.fields.as_ref()).and_then(|fs| fs.iter().find(|f| &f.name == field_name)) {
                if let Some(ft) = &field.field_type {
                    if let Some(itn) = ft.unwrap_type_name() {
                        if let Some(it) = schema.find_type(&itn) {
                            if it.kind.as_deref() == Some("OBJECT") || it.kind.as_deref() == Some("INTERFACE") {
                                poc.push_str(" { id }");
                            }
                        }
                    }
                }
            }

            poc.push_str("\n}");

            // Wrap in curl for CLI users
            let curl = format!(
                "curl -X POST {} \\\n  -H 'Content-Type: application/json' \\\n  -d '{}'",
                url,
                json!({ "query": poc }).to_string()
            );

            Some(curl)
        }
        AffectedLocation::Type(type_name) => {
            if type_name == "Endpoint" {
                 return Some(format!("curl -X POST {} -H 'Content-Type: application/json' -d '{{\"query\":\"{{ __typename }}\"}}'", url));
            }
            Some(format!("# Review type '{}' in the visual report or schema file.", type_name))
        }
    }
}
