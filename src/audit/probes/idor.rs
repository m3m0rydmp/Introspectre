use crate::audit::utils::{
    build_operation_query, effective_headers, field_non_null_data, find_root_field,
};
use crate::config::AppConfig;
use crate::transport::Transport;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, Severity};
use reqwest::Client;
use std::collections::HashMap;

pub async fn probe_idor(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    evasion_level: u8,
    config: &AppConfig,
    passive_findings: &[Finding],
    transport: Transport,
    _confirmed: &mut Vec<Finding>,
    unconfirmed: &mut Vec<Finding>,
    idor_payloads: &[String],
) -> Result<(), String> {
    let idor_finding = passive_findings.iter().find(|f| f.id == "idor-surface");
    let Some(idor) = idor_finding else {
        return Ok(());
    };

    // Without session config we can't do authenticated cross-tenant testing, but we can still run
    // a SAFE, read-only unauthenticated check: does an ID-taking **query** field return DISTINCT
    // objects for different IDs with no auth? If so the objects are enumerable by guessing IDs —
    // a live BOLA/IDOR surface (for genuinely public resources it may be intended; the finding
    // says so). We deliberately skip mutations here to avoid changing server state.
    if config.session.auth_header.trim().is_empty() || config.session.owned_ids.is_empty() {
        return probe_idor_unauthenticated(
            schema, url, client, extra_headers, rate_limit_ms, evasion_level, config, idor,
            transport, unconfirmed, idor_payloads,
        )
        .await;
    }

    let headers = effective_headers(
        extra_headers,
        Some(config.session.auth_header.as_str()),
        true,
    );
    let mut confirmed_locations: Vec<AffectedLocation> = Vec::new();
    let mut inconclusive_locations: Vec<AffectedLocation> = Vec::new();

    for location in &idor.affected {
        let (root, field_name, arg_name) = match location {
            AffectedLocation::Argument(r, f, a) => (r, f, a),
            _ => continue,
        };

        let Some(field) = find_root_field(schema, root.as_str(), field_name.as_str()) else {
            continue;
        };

        let op = if root == "Mutation" {
            "mutation"
        } else {
            "query"
        };
        let is_mutation = op == "mutation";

        let mut baseline_payload: Option<String> = None;
        for owned in &config.session.owned_ids {
            let mut overrides = HashMap::new();
            overrides.insert(arg_name.clone(), serde_json::Value::String(owned.clone()));
            let gql_op = build_operation_query(schema, op, field, &overrides, &config.audit.seeds, true);
            let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op.query, Some(gql_op.variables), rate_limit_ms, evasion_level, transport, is_mutation).await?;
            if let Some(data) = field_non_null_data(&resp.data, &field.name) {
                baseline_payload = Some(data.to_string());
                break;
            }
        }

        let Some(baseline) = baseline_payload else {
            inconclusive_locations.push(location.clone());
            continue;
        };

        let mutated_values = if !idor_payloads.is_empty() {
            idor_payloads.iter().map(|s| serde_json::Value::String(s.clone())).collect()
        } else {
            vec![
                serde_json::Value::String("1".to_string()),
                serde_json::Value::String("2".to_string()),
                serde_json::Value::String("3".to_string()),
            ]
        };

        let mut possibility_confirmed = false;
        for mutated in mutated_values {
            let mut overrides = HashMap::new();
            overrides.insert(arg_name.clone(), mutated);
            let gql_op = build_operation_query(schema, op, field, &overrides, &config.audit.seeds, true);
            let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op.query, Some(gql_op.variables), rate_limit_ms, evasion_level, transport, is_mutation).await?;

            if let Some(data) = field_non_null_data(&resp.data, &field.name) {
                let payload = data.to_string();
                if payload != baseline {
                    confirmed_locations.push(location.clone());
                    possibility_confirmed = true;
                    break;
                }
            }
        }

        if !possibility_confirmed {
            inconclusive_locations.push(location.clone());
        }
    }

    if !confirmed_locations.is_empty() {
        let poc = confirmed_locations
            .first()
            .map(|loc| {
                let (root, field_name) = match loc {
                    AffectedLocation::Argument(r, f, _) => (r.as_str(), f.as_str()),
                    _ => ("Query", "field"),
                };
                let arg_name = match loc {
                    AffectedLocation::Argument(_, _, a) => a.as_str(),
                    _ => "id",
                };
                let keyword = if root == "Mutation" { "mutation" } else { "query" };
                format!(
                    "# IDOR confirmed: {}.{}\n{} {{\n  {}({}: \"VICTIM_ID\") {{\n    id\n    __typename\n  }}\n}}",
                    root, field_name, keyword, field_name, arg_name
                )
            });

        unconfirmed.push(Finding {
            id: "idor",
            severity: Severity::Medium,
            title: "Potential IDOR (Ownership Unverified)",
            description: format!(
                "### Analysis\n\
                 {} ID-based operation(s) returned data that DIFFERED from the owned-ID baseline when non-owned identifiers were supplied in an authenticated session. This is a lead, not proof: the server may be resolving objects by ID without an ownership check, or the probed IDs may reference legitimately public resources. Manual verification is required to confirm a real authorization bypass.\n\n\
                 ### Evidence\n\
                 - **Operations returning cross-ID data**: {}\n\
                 - **Indicator**: response payload varied between the owned ID and injected IDs.",
                confirmed_locations.len(),
                confirmed_locations.len()
            ),
            affected: confirmed_locations,
            remediation: "Enforce object-level authorization checks by ownership on every ID-based resolver path.",
            first_step: Some("Manually query a resource using an ID that does NOT belong to your account and confirm whether it returns data you should not be able to see.".into()),
            references: vec!["OWASP API1: Broken Object Level Authorization", "CWE-639: Authorization Bypass Through User-Controlled Key"],
            status: FindingStatus::Possible,
            confidence: Confidence::Possible,
            evidence_level: EvidenceLevel::Inferred,
            poc,
        });
    }

    if !inconclusive_locations.is_empty() {
        unconfirmed.push(Finding {
            id: "idor",
            severity: Severity::Medium,
            title: "IDOR Probe Inconclusive",
            description: format!(
                "{} IDOR possibility(s) could not be confirmed with current owned IDs and default mutation set.",
                inconclusive_locations.len()
            ),
            affected: inconclusive_locations,
            remediation: "Expand possibility IDs and include operation-specific payloads to increase probe coverage.",
            first_step: Some("Provide additional 'idor_payloads' or 'owned_ids' in your config to improve probe precision.".into()),
            references: vec!["OWASP API1: Broken Object Level Authorization"],
            status: FindingStatus::Possible,
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inconclusive,
            poc: None,
        });
    }

    Ok(())
}

/// Safe, unauthenticated IDOR surface check used when no session config is available.
/// For each ID-taking **query** field flagged by the passive `idor-surface`, request it with a few
/// candidate IDs and see whether it returns **distinct** objects — i.e. objects are readable by
/// guessing/incrementing an ID with no authentication. Read-only (no mutations); a lead, not proof.
#[allow(clippy::too_many_arguments)]
async fn probe_idor_unauthenticated(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    evasion_level: u8,
    config: &AppConfig,
    idor: &Finding,
    transport: Transport,
    unconfirmed: &mut Vec<Finding>,
    idor_payloads: &[String],
) -> Result<(), String> {
    let headers = effective_headers(extra_headers, None, false);
    let candidate_ids: Vec<String> = if !idor_payloads.is_empty() {
        idor_payloads.to_vec()
    } else {
        vec!["1".to_string(), "2".to_string(), "3".to_string()]
    };

    let mut enumerable: Vec<AffectedLocation> = Vec::new();
    let mut poc: Option<String> = None;

    for location in &idor.affected {
        let AffectedLocation::Argument(root, field_name, arg_name) = location else {
            continue;
        };
        // Read-only: only probe query fields unauthenticated (never mutations)...
        if root == "Mutation" {
            continue;
        }
        // ...and skip query fields whose names imply a side effect (e.g. DVGA's `readAndBurn`
        // destroys the paste on read), so this probe never changes server state.
        let fname = field_name.to_lowercase();
        if ["burn", "delete", "remove", "destroy", "consume", "revoke", "purge", "reset", "drop", "expire"]
            .iter()
            .any(|k| fname.contains(k))
        {
            continue;
        }
        let Some(field) = find_root_field(schema, root.as_str(), field_name.as_str()) else {
            continue;
        };

        let mut distinct: Vec<String> = Vec::new();
        for id in &candidate_ids {
            let mut overrides = HashMap::new();
            overrides.insert(arg_name.clone(), serde_json::Value::String(id.clone()));
            let gql_op = build_operation_query(schema, "query", field, &overrides, &config.audit.seeds, true);
            let resp = crate::audit::utils::post_graphql_ext(
                client, url, &headers, &gql_op.query, Some(gql_op.variables), rate_limit_ms, evasion_level, transport, false,
            )
            .await?;
            if let Some(data) = field_non_null_data(&resp.data, &field.name) {
                let s = data.to_string();
                if !distinct.contains(&s) {
                    distinct.push(s);
                }
            }
        }

        // Two or more distinct objects for different IDs → enumerable, unauthenticated access.
        if distinct.len() >= 2 {
            enumerable.push(location.clone());
            if poc.is_none() {
                poc = Some(format!(
                    "# Unauthenticated, enumerable object access: {}.{}\n# Same query, different IDs return different objects — no auth header sent.\nquery {{\n  {}({}: \"1\") {{ id __typename }}\n}}\nquery {{\n  {}({}: \"2\") {{ id __typename }}\n}}",
                    root, field_name, field_name, arg_name, field_name, arg_name
                ));
            }
        }
    }

    if !enumerable.is_empty() {
        let n = enumerable.len();
        unconfirmed.push(Finding {
            id: "idor",
            severity: Severity::Medium,
            title: "Unauthenticated Enumerable Object Access",
            description: format!(
                "### Analysis\n\
                 {} ID-taking query field(s) returned **distinct objects for different IDs with no authentication** — objects are readable by guessing or incrementing an identifier. For genuinely public resources this may be intended; for anything user- or tenant-scoped it is a Broken Object Level Authorization (BOLA/IDOR) exposure. This is a lead, not proof of a cross-tenant bypass — verify whether these objects should be private.\n\n\
                 ### Evidence\n\
                 - **Fields returning distinct objects across IDs (unauthenticated)**: {}\n\
                 - Tested IDs: {}",
                n, n, candidate_ids.join(", ")
            ),
            affected: enumerable,
            remediation: "Enforce object-level authorization on every ID-based resolver: verify the caller is allowed to read the specific object, and prefer unguessable identifiers (UUIDs) over sequential integers.",
            first_step: Some("Query one of these fields with an ID that does not belong to you (or that you were never given) and confirm you can read the object.".into()),
            references: vec!["OWASP API1: Broken Object Level Authorization", "CWE-639: Authorization Bypass Through User-Controlled Key"],
            status: FindingStatus::Possible,
            confidence: Confidence::Possible,
            evidence_level: EvidenceLevel::Inferred,
            poc,
        });
    } else {
        unconfirmed.push(Finding {
            id: "idor",
            severity: Severity::Medium,
            title: "IDOR: unauthenticated probe inconclusive",
            description: "Ran a safe read-only enumeration check (no session config supplied) but ID-taking query fields did not return distinct objects for the tested IDs. For authenticated cross-tenant IDOR testing, set `session.auth_header` + `session.owned_ids` in config; for non-numeric IDs, pass `--idor-payloads`.".to_string(),
            affected: vec![AffectedLocation::Type("Session Configuration".into())],
            remediation: "Provide `session.auth_header` and `session.owned_ids` to enable authenticated ownership testing.",
            first_step: Some("Add `session.auth_header` and `session.owned_ids` to config.toml, or pass `--idor-payloads <ids>` for non-sequential identifiers.".into()),
            references: vec!["OWASP API1: Broken Object Level Authorization"],
            status: FindingStatus::Possible,
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inconclusive,
            poc: None,
        });
    }

    Ok(())
}
