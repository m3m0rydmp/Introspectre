use crate::types::{AffectedLocation, Finding, GqlSchema};
use serde_json::json;

/// Truncate a response body string to `max_len` characters for inclusion in
/// evidence blocks. Appends "…" when truncated.
pub fn truncated_body(raw: &str, max_len: usize) -> String {
    if raw.len() <= max_len {
        raw.to_string()
    } else {
        format!("{}…", &raw[..max_len])
    }
}

/// Injection finding ids that sqlmap can take further (SQL/NoSQL).
const SQLMAP_TARGET_IDS: &[&str] = &["sql-injection", "sql-injection-inline", "blind-injection"];

/// For a confirmed SQL/NoSQL injection finding, build a ready-to-run **sqlmap**
/// command tailored to the endpoint and the injectable argument. Introspectre
/// *confirms* the flaw; sqlmap *exploits/extracts* it — this is the hand-off.
/// Returns `None` for non-injection findings.
pub fn sqlmap_guide(finding: &Finding, url: &str) -> Option<String> {
    if !SQLMAP_TARGET_IDS.contains(&finding.id) {
        return None;
    }

    // The injectable argument (leaf) from the first Argument location.
    let arg = finding.affected.iter().find_map(|loc| match loc {
        AffectedLocation::Argument(_, _, path) => path.rsplit('.').next().map(|s| s.to_string()),
        _ => None,
    });
    let arg = arg.unwrap_or_else(|| "<arg>".to_string());

    // The confirmed GraphQL operation, collapsed to a single JSON-safe line.
    let query_line = finding
        .poc
        .as_deref()
        .map(|q| q.split_whitespace().collect::<Vec<_>>().join(" "))
        .unwrap_or_else(|| "<paste the confirmed query>".to_string());
    // JSON-escape for embedding inside the --data string.
    let query_json = query_line.replace('\\', "\\\\").replace('"', "\\\"");

    Some(format!(
        "# Introspectre confirmed the injection; use sqlmap to exploit / extract data.\n\
         # Direct (variable-based) — the injectable value `{arg}` is marked with * :\n\
         sqlmap -u \"{url}\" --batch --method=POST \\\n\
        \x20 --headers=\"Content-Type: application/json\" \\\n\
        \x20 --data='{{\"query\":\"{query}\",\"variables\":{{\"{arg}\":\"*\"}}}}' \\\n\
        \x20 --level=5 --risk=3\n\
         #\n\
         # Or via a saved request (covers inlined / nested-input cases): capture the\n\
         # vulnerable request to req.txt, replace the injectable value with * , then run:\n\
         #   sqlmap -r req.txt --batch --level=5 --risk=3\n\
         # If the endpoint needs auth, add:  --cookie=\"...\"  or  -H \"Authorization: Bearer <token>\"",
        arg = arg,
        url = url,
        query = query_json
    ))
}

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
