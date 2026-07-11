use crate::audit::utils::{
    build_operation_query, effective_headers, field_non_null_data,
    is_auth_error, is_validation_error, GqlOperation,
};
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlField, GqlSchema, Severity};
use reqwest::Client;
use std::collections::HashMap;

pub async fn probe_unauth_access(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    evasion_level: u8,
    batch_probes: bool,
    batch_size: u32,
    seed_map: &HashMap<String, String>,
    confirmed: &mut Vec<Finding>,
    unconfirmed: &mut Vec<Finding>,
) -> Result<(), String> {
    let mut confirmed_locations: Vec<AffectedLocation> = Vec::new();
    let mut inconclusive_locations: Vec<AffectedLocation> = Vec::new();
    let mut auth_blocked = 0usize;
    let mut validation_failures = 0usize;
    let mut attempted = 0usize;

    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let mutation_name = schema.mutation_type.as_ref().map(|m| m.name.as_str());

    let mut targets: Vec<(&str, &str, &GqlField)> = Vec::new();
    for f in schema.fields_for_type(query_name) {
        targets.push(("query", "Query", f));
    }
    for f in schema.fields_for_type(mutation_name) {
        targets.push(("mutation", "Mutation", f));
    }

    let headers = effective_headers(extra_headers, None, false);

    if batch_probes && batch_size > 0 {
        let batch_size_usize = batch_size as usize;
        let mut query_batch: Vec<(GqlOperation, &str, &str, &GqlField)> = Vec::new();

        for (op, root, field) in targets {
            attempted += 1;
            let gql_op = build_operation_query(schema, op, field, &HashMap::new(), seed_map, false);
            query_batch.push((gql_op, op, root, field));

            if query_batch.len() >= batch_size_usize {
                let batch_ops: Vec<GqlOperation> = query_batch.iter().map(|(o, _, _, _)| o.clone()).collect();
                let responses = crate::audit::utils::post_batched_graphql_ext(client, url, &headers, &batch_ops, rate_limit_ms, evasion_level).await?;

                for (idx, (_, _, root, field)) in query_batch.iter().enumerate() {
                    let loc = AffectedLocation::Field((*root).into(), field.name.clone());
                    if let Some(resp) = responses.get(idx) {
                        if field_non_null_data(&resp.data, &field.name).is_some() {
                            confirmed_locations.push(loc);
                        } else if resp.status == 401 || resp.status == 403 || is_auth_error(&resp.errors_text) {
                            auth_blocked += 1;
                        } else if is_validation_error(&resp.errors_text) {
                            validation_failures += 1;
                        } else {
                            inconclusive_locations.push(loc);
                        }
                    }
                }
                query_batch.clear();
            }
        }

        if !query_batch.is_empty() {
            let batch_ops: Vec<GqlOperation> = query_batch.iter().map(|(o, _, _, _)| o.clone()).collect();
            let responses = crate::audit::utils::post_batched_graphql_ext(client, url, &headers, &batch_ops, rate_limit_ms, evasion_level).await?;

            for (idx, (_, _, root, field)) in query_batch.iter().enumerate() {
                let loc = AffectedLocation::Field((*root).into(), field.name.clone());
                if let Some(resp) = responses.get(idx) {
                    if field_non_null_data(&resp.data, &field.name).is_some() {
                        confirmed_locations.push(loc);
                    } else if resp.status == 401 || resp.status == 403 || is_auth_error(&resp.errors_text) {
                        auth_blocked += 1;
                    } else if is_validation_error(&resp.errors_text) {
                        validation_failures += 1;
                    } else {
                        inconclusive_locations.push(loc);
                    }
                }
            }
        }
    } else {
        for (op, root, field) in targets {
            attempted += 1;
            let gql_op = build_operation_query(schema, op, field, &HashMap::new(), seed_map, false);
            let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op.query, Some(gql_op.variables), rate_limit_ms, evasion_level).await?;
            let loc = AffectedLocation::Field(root.into(), field.name.clone());

            if field_non_null_data(&resp.data, &field.name).is_some() {
                confirmed_locations.push(loc);
                continue;
            }

            if resp.status == 401 || resp.status == 403 || is_auth_error(&resp.errors_text) {
                auth_blocked += 1;
                continue;
            }

            if is_validation_error(&resp.errors_text) {
                validation_failures += 1;
                continue;
            }

            inconclusive_locations.push(loc);
        }
    }

    // Drop trivially-public / introspection roots to cut noise: these routinely
    // return data without auth by design (server metadata, health checks, etc.).
    let trivial = ["typename", "version", "health", "status", "ping", "time", "hello", "info"];
    confirmed_locations.retain(|loc| {
        if let AffectedLocation::Field(_, name) = loc {
            let toks = crate::utils::tokenize_identifier(name);
            !(name.starts_with("__") || toks.iter().any(|t| trivial.contains(&t.as_str())))
        } else {
            true
        }
    });

    if !confirmed_locations.is_empty() {
        let poc = confirmed_locations.first().map(|loc| {
            let field = match loc {
                AffectedLocation::Field(_, f) => f,
                _ => "fieldName",
            };
            format!(
                "curl -X POST {} \\\n  -H 'Content-Type: application/json' \\\n  -d '{{\"query\":\"{{ {} {{ id }} }}\"}}'",
                url, field
            )
        });

        confirmed.push(Finding {
            id: "unauthenticated-access",
            severity: Severity::Medium,
            title: "Unauthenticated Data Access (Review Sensitivity)",
            description: format!(
                "{} root operation(s) returned non-null data without an Authorization header (attempted {}; {} blocked by auth). This is an executed observation, not a proven vulnerability: some roots return public data by design. Review whether the exposed data is meant to be public — if it is sensitive or user-scoped, this is a broken-authorization issue.",
                confirmed_locations.len(),
                attempted,
                auth_blocked
            ),
            affected: confirmed_locations,
            remediation: "Require authentication and resolver-level authorization checks before returning non-public data for root operations.",
            first_step: Some("Manually test one of the operations using curl (see PoC) and judge whether the returned data should require authentication.".into()),
            references: vec!["OWASP API5: Broken Function Level Authorization"],
            status: FindingStatus::Possible,
            confidence: Confidence::Possible,
            evidence_level: EvidenceLevel::Executed,
            poc,
        });
    }

    if !inconclusive_locations.is_empty() {
        unconfirmed.push(Finding {
            id: "unauthenticated-access",
            severity: Severity::Medium,
            title: "Unauthenticated Access Probe Inconclusive",
            description: format!(
                "{} operation(s) returned non-auth errors or null data in unauthenticated probe mode (attempted {}; {} blocked by auth; {} validation failures ignored).",
                inconclusive_locations.len(),
                attempted,
                auth_blocked,
                validation_failures
            ),
            affected: inconclusive_locations,
            remediation: "Review resolver authorization behavior and test manually with operation-specific payloads.",
            first_step: Some("Check if these operations return 'null' for unauthenticated users as a design choice, or if they require specific arguments to return data.".into()),
            references: vec!["OWASP API5: Broken Function Level Authorization"],
            status: FindingStatus::Possible,
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inconclusive,
            poc: None,
        });
    }

    Ok(())
}
