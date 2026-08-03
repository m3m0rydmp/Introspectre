//! Active Relay `node(id:)` IDOR probe.
//!
//! The passive `node-idor-surface` analyzer flags that a global-object fetcher
//! exists. This probe goes one step further, safely and on the tester's own
//! data: it obtains a real global id (from `--seeds`, else by fetching one of
//! the tester's own accessible objects), base64-decodes it to classify the id
//! **scheme** (see `id_scheme`), and — if the scheme is sequentially
//! enumerable — reports a high-confidence IDOR with a concrete adjacent-id PoC.
//! It also runs a conservative `node(id){ …on OtherType{…} }` **type-confusion**
//! check to detect cross-type field leakage. No cross-tenant data is touched:
//! every id used is one the tester can already read.

use std::collections::HashMap;

use reqwest::Client;
use serde_json::Value;

use crate::audit::utils::{effective_headers, post_graphql_ext};
use crate::id_scheme::{adjacent_id, classify_global_id, IdScheme};
use crate::transport::Transport;
use crate::types::{
    AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, Severity,
};

/// Max own-object fetch attempts when no seed id is supplied.
const MAX_FETCH_ATTEMPTS: usize = 8;

fn unquote(s: &str) -> String {
    s.trim().trim_matches('"').trim().to_string()
}

fn arg_is_required(kind: Option<&str>) -> bool {
    kind == Some("NON_NULL")
}

/// The object type embedded in a decoded id, if any (for choosing a *different*
/// type to attempt confusion against).
fn scheme_type(scheme: &IdScheme) -> Option<&str> {
    match scheme {
        IdScheme::GidNumeric { type_name, .. }
        | IdScheme::TypedNumeric { type_name, .. }
        | IdScheme::TypedUuid { type_name } => Some(type_name),
        _ => None,
    }
}

/// Pull the first `id` string out of a `{ field { id } }` (object or list) result.
fn extract_id(data: Option<&Value>, field: &str) -> Option<String> {
    match data?.get(field)? {
        Value::Object(o) => o.get("id")?.as_str().map(String::from),
        Value::Array(a) => a
            .iter()
            .find_map(|e| e.get("id").and_then(|x| x.as_str()).map(String::from)),
        _ => None,
    }
}

/// Best-effort: fetch a real global id from one of the tester's own accessible
/// objects — a root field returning an object (or list) that has an `id` field
/// and takes no required arguments.
#[allow(clippy::too_many_arguments)]
async fn fetch_sample_id(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    headers: &[(String, String)],
    rate_limit_ms: u64,
    evasion: u8,
    transport: Transport,
) -> Option<String> {
    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let mut attempts = 0;
    for f in schema.fields_for_type(query_name) {
        if attempts >= MAX_FETCH_ATTEMPTS {
            break;
        }
        let return_type = match f.field_type.as_ref().and_then(|t| t.unwrap_type_name()) {
            Some(rt) => rt,
            None => continue,
        };
        let ty = match schema.find_type(&return_type) {
            Some(t) => t,
            None => continue,
        };
        if ty.kind.as_deref() != Some("OBJECT") {
            continue;
        }
        let has_id = ty
            .fields
            .as_ref()
            .map(|fl| fl.iter().any(|x| x.name == "id"))
            .unwrap_or(false);
        if !has_id {
            continue;
        }
        let needs_args = f
            .args
            .as_ref()
            .map(|a| a.iter().any(|arg| arg_is_required(arg.arg_type.as_ref().and_then(|t| t.kind.as_deref()))))
            .unwrap_or(false);
        if needs_args {
            continue;
        }
        attempts += 1;
        let q = format!("{{ {} {{ id }} }}", f.name);
        if let Ok(resp) = post_graphql_ext(client, url, headers, &q, None, rate_limit_ms, evasion, transport, false).await {
            if let Some(id) = extract_id(resp.data.as_ref(), &f.name) {
                if !id.trim().is_empty() {
                    return Some(id);
                }
            }
        }
    }
    None
}

/// Choose a Node type (other than `avoid`) that exposes a scalar field, to
/// attempt a type-confusion cast against.
fn pick_confusion_target<'a>(
    schema: &'a GqlSchema,
    node_types: &'a [String],
    avoid: Option<&str>,
) -> Option<(&'a str, String)> {
    for tn in node_types {
        if Some(tn.as_str()) == avoid {
            continue;
        }
        let ty = schema.find_type(tn)?;
        let field = ty.fields.as_ref()?.iter().find(|f| {
            // a leaf-ish scalar field: unwraps to a SCALAR/ENUM kind
            f.field_type
                .as_ref()
                .and_then(|t| t.unwrap_kind())
                .map(|k| k == "SCALAR" || k == "ENUM")
                .unwrap_or(false)
                && f.name != "id"
        })?;
        return Some((tn.as_str(), field.name.clone()));
    }
    None
}

#[allow(clippy::too_many_arguments)]
pub async fn probe_node_idor(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    seeds: &HashMap<String, String>,
    rate_limit_ms: u64,
    evasion: u8,
    transport: Transport,
    confirmed: &mut Vec<Finding>,
    unconfirmed: &mut Vec<Finding>,
) -> Result<(), String> {
    // Only relevant when a global-object fetcher exists.
    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let query_fields = schema.fields_for_type(query_name);
    let has_node = query_fields.iter().any(|f| {
        f.name == "node"
            && f.args.as_ref().map(|a| a.iter().any(|x| x.name == "id")).unwrap_or(false)
    });
    if !has_node {
        return Ok(());
    }

    let node_types: Vec<String> = schema
        .types
        .iter()
        .find(|t| t.kind.as_deref() == Some("INTERFACE") && t.name.as_deref() == Some("Node"))
        .and_then(|t| t.possible_types.as_ref())
        .map(|pts| pts.iter().filter_map(|r| r.name.clone()).collect())
        .unwrap_or_default();

    let headers = effective_headers(extra_headers, None, false);

    // 1. Obtain a sample global id: prefer a seeded one, else fetch our own.
    let mut sample: Option<String> = seeds
        .values()
        .map(|v| unquote(v))
        .find(|v| !matches!(classify_global_id(v), IdScheme::Opaque) && !v.is_empty());
    if sample.is_none() {
        sample = fetch_sample_id(schema, url, client, &headers, rate_limit_ms, evasion, transport).await;
    }

    let Some(sample_id) = sample else {
        // Surface exists but we have no id to analyse — nudge the user.
        unconfirmed.push(Finding {
            id: "node-idor",
            severity: Severity::Info,
            title: "Node IDOR — sample global id needed",
            description: "A Relay `node(id:)` global fetcher is present, but no real global id was available to analyse its predictability (no usable seed and no id-bearing object was fetchable unauthenticated). Provide a real id to classify the scheme.".to_string(),
            affected: vec![AffectedLocation::Field("Query".into(), "node".into())],
            remediation: "Issue signed/opaque, non-enumerable global ids and enforce object-level authorization in `node(id:)`.",
            first_step: Some("Re-run with `--seeds` (or `--seed-traffic` a HAR) providing a real global id so the id scheme can be decoded and tested.".into()),
            references: vec!["OWASP API1: Broken Object Level Authorization", "CWE-639"],
            status: FindingStatus::Inferred,
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inconclusive,
            poc: Some("query { node(id: \"<REAL_GLOBAL_ID>\") { id __typename } }".into()),
        });
        return Ok(());
    };

    // 2. Classify id predictability.
    let scheme = classify_global_id(&sample_id);
    if scheme.is_enumerable() {
        let adj = adjacent_id(&sample_id).unwrap_or_else(|| sample_id.clone());
        confirmed.push(Finding {
            id: "node-idor",
            severity: Severity::High,
            title: "Enumerable Global-Object IDs (node IDOR)",
            description: format!(
                "A real global id decodes to a {} scheme. Combined with the `node(id:)` fetcher, any object is trivially enumerable by decoding one id, changing the counter, and re-encoding — a broken-object-authorization (IDOR/BOLA) primitive unless `node(id:)` enforces per-object authorization. The scheme was decoded from a real id, so predictability is confirmed; authorization enforcement still needs the two-identity check below.",
                scheme.label()
            ),
            affected: vec![AffectedLocation::Field("Query".into(), "node".into())],
            remediation: "Issue signed/opaque, non-enumerable global ids (e.g. HMAC-tagged), and enforce the same object-level authorization in `node(id:)` as in each type-specific resolver.",
            first_step: Some(format!(
                "Request the ADJACENT object below as a different identity (or logged out): `node(id: \"{}\")`. Private data returned to an unauthorized viewer = confirmed broken object authorization. Use only ids you are authorized to test.",
                adj
            )),
            references: vec![
                "OWASP API1: Broken Object Level Authorization",
                "CWE-639: Authorization Bypass Through User-Controlled Key",
            ],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
            poc: Some(format!("query {{ node(id: \"{}\") {{ id __typename }} }}   # adjacent object to the tester's own", adj)),
        });
    } else {
        unconfirmed.push(Finding {
            id: "node-idor",
            severity: Severity::Info,
            title: "Global-Object IDs Appear Non-Enumerable",
            description: format!(
                "A real global id decodes to a {} scheme, which is not trivially enumerable. The `node(id:)` surface still warrants an object-level authorization check, but id guessing is not a practical enumeration vector here.",
                scheme.label()
            ),
            affected: vec![AffectedLocation::Field("Query".into(), "node".into())],
            remediation: "Keep ids opaque/signed; continue to enforce object-level authorization in `node(id:)`.",
            first_step: Some("Confirm `node(id:)` still authorizes per object (a leaked or shared id should not grant access across identities).".into()),
            references: vec!["OWASP API1: Broken Object Level Authorization"],
            status: FindingStatus::Inferred,
            confidence: Confidence::Possible,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

    // 3. Conservative type-confusion check on our own id: cast to a different
    //    Node type and see if a field of that unrelated type resolves non-null.
    if let Some((target_type, target_field)) = pick_confusion_target(schema, &node_types, scheme_type(&scheme)) {
        let q = format!(
            "{{ node(id: \"{}\") {{ __typename ...on {} {{ {} }} }} }}",
            sample_id, target_type, target_field
        );
        if let Ok(resp) = post_graphql_ext(client, url, &headers, &q, None, rate_limit_ms, evasion, transport, false).await {
            if let Some(node) = resp.data.as_ref().and_then(|d| d.get("node")) {
                let tname = node.get("__typename").and_then(|v| v.as_str()).unwrap_or("");
                let leaked = node.get(&target_field).map(|v| !v.is_null()).unwrap_or(false);
                if leaked && !tname.is_empty() && tname != target_type {
                    confirmed.push(Finding {
                        id: "node-type-confusion",
                        severity: Severity::High,
                        title: "node(id:) Cross-Type Field Leak (Type Confusion)",
                        description: format!(
                            "`node(id:)` returned a `{}` field (declared on unrelated type `{}`) for an object whose real `__typename` is `{}`. Resolving one type's fields on another type's object is a type-confusion / object-authorization flaw that can leak fields the caller should not reach.",
                            target_field, target_type, tname
                        ),
                        affected: vec![AffectedLocation::Field("Query".into(), "node".into())],
                        remediation: "Ensure inline-fragment (`...on Type`) resolution is type-checked against the object's real type, and that field resolvers verify the parent object type.",
                        first_step: Some("Re-run the PoC and compare `__typename` to the leaked field's declaring type; confirm the field returns another type's data.".into()),
                        references: vec!["CWE-843: Type Confusion", "OWASP API1: Broken Object Level Authorization"],
                        status: FindingStatus::Confirmed,
                        confidence: Confidence::Possible,
                        evidence_level: EvidenceLevel::Executed,
                        poc: Some(q),
                    });
                }
            }
        }
    }

    Ok(())
}
