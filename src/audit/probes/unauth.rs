use crate::audit::utils::{
<<<<<<< HEAD
    build_operation_query, effective_headers, field_non_null_data, has_required_args,
    is_auth_error, is_validation_error, post_graphql, post_batched_graphql,
};
use crate::audit::AuditFinding;
use crate::types::{GqlField, GqlSchema, Severity};
=======
    build_operation_query, effective_headers, field_non_null_data,
    is_auth_error, is_validation_error, GqlOperation,
};
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlField, GqlSchema, Severity};
>>>>>>> update-research-refs
use reqwest::Client;
use std::collections::HashMap;

pub async fn probe_unauth_access(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
<<<<<<< HEAD
    batch_probes: bool,
    batch_size: u32,
    confirmed: &mut Vec<AuditFinding>,
    unconfirmed: &mut Vec<AuditFinding>,
) -> Result<(), String> {
    let mut confirmed_access: Vec<String> = Vec::new();
    let mut inconclusive: Vec<String> = Vec::new();
    let mut skipped_required_args = 0usize;
=======
    evasion_level: u8,
    batch_probes: bool,
    batch_size: u32,
    seed_map: &HashMap<String, String>,
    confirmed: &mut Vec<Finding>,
    unconfirmed: &mut Vec<Finding>,
) -> Result<(), String> {
    let mut confirmed_locations: Vec<AffectedLocation> = Vec::new();
    let mut inconclusive_locations: Vec<AffectedLocation> = Vec::new();
    let skipped_required_args = 0usize;
>>>>>>> update-research-refs
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
<<<<<<< HEAD
        let mut query_batch: Vec<(String, &str, &str, &GqlField)> = Vec::new();

        for (op, root, field) in targets {
            if has_required_args(field) {
                skipped_required_args += 1;
                continue;
            }

            attempted += 1;
            let query = build_operation_query(schema, op, field, &HashMap::new(), false);
            query_batch.push((query, op, root, field));

            if query_batch.len() >= batch_size_usize {
                let batch_queries: Vec<String> = query_batch.iter().map(|(q, _, _, _)| q.clone()).collect();
                let responses = post_batched_graphql(client, url, &headers, &batch_queries, rate_limit_ms).await?;

                for (idx, (_, _, root, field)) in query_batch.iter().enumerate() {
                    let label = format!("{}.{}", root, field.name);
                    if let Some(resp) = responses.get(idx) {
                        if field_non_null_data(&resp.data, &field.name).is_some() {
                            confirmed_access.push(label);
=======
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
>>>>>>> update-research-refs
                        } else if resp.status == 401 || resp.status == 403 || is_auth_error(&resp.errors_text) {
                            auth_blocked += 1;
                        } else if is_validation_error(&resp.errors_text) {
                            validation_failures += 1;
                        } else {
<<<<<<< HEAD
                            inconclusive.push(label);
=======
                            inconclusive_locations.push(loc);
>>>>>>> update-research-refs
                        }
                    }
                }
                query_batch.clear();
            }
        }

        if !query_batch.is_empty() {
<<<<<<< HEAD
            let batch_queries: Vec<String> = query_batch.iter().map(|(q, _, _, _)| q.clone()).collect();
            let responses = post_batched_graphql(client, url, &headers, &batch_queries, rate_limit_ms).await?;

            for (idx, (_, _, root, field)) in query_batch.iter().enumerate() {
                let label = format!("{}.{}", root, field.name);
                if let Some(resp) = responses.get(idx) {
                    if field_non_null_data(&resp.data, &field.name).is_some() {
                        confirmed_access.push(label);
=======
            let batch_ops: Vec<GqlOperation> = query_batch.iter().map(|(o, _, _, _)| o.clone()).collect();
            let responses = crate::audit::utils::post_batched_graphql_ext(client, url, &headers, &batch_ops, rate_limit_ms, evasion_level).await?;

            for (idx, (_, _, root, field)) in query_batch.iter().enumerate() {
                let loc = AffectedLocation::Field((*root).into(), field.name.clone());
                if let Some(resp) = responses.get(idx) {
                    if field_non_null_data(&resp.data, &field.name).is_some() {
                        confirmed_locations.push(loc);
>>>>>>> update-research-refs
                    } else if resp.status == 401 || resp.status == 403 || is_auth_error(&resp.errors_text) {
                        auth_blocked += 1;
                    } else if is_validation_error(&resp.errors_text) {
                        validation_failures += 1;
                    } else {
<<<<<<< HEAD
                        inconclusive.push(label);
=======
                        inconclusive_locations.push(loc);
>>>>>>> update-research-refs
                    }
                }
            }
        }
    } else {
        for (op, root, field) in targets {
<<<<<<< HEAD
            if has_required_args(field) {
                skipped_required_args += 1;
                continue;
            }

            attempted += 1;
            let query = build_operation_query(schema, op, field, &HashMap::new(), false);
            let resp = post_graphql(client, url, &headers, &query, rate_limit_ms).await?;
            let label = format!("{}.{}", root, field.name);

            if field_non_null_data(&resp.data, &field.name).is_some() {
                confirmed_access.push(label);
=======
            attempted += 1;
            let gql_op = build_operation_query(schema, op, field, &HashMap::new(), seed_map, false);
            let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op.query, Some(gql_op.variables), rate_limit_ms, evasion_level).await?;
            let loc = AffectedLocation::Field(root.into(), field.name.clone());

            if field_non_null_data(&resp.data, &field.name).is_some() {
                confirmed_locations.push(loc);
>>>>>>> update-research-refs
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

<<<<<<< HEAD
            inconclusive.push(label);
        }
    }

    if !confirmed_access.is_empty() {
        let poc = confirmed_access.first().map(|label| {
            let field = label.split('.').nth(1).unwrap_or("fieldName");
=======
            inconclusive_locations.push(loc);
        }
    }

    if !confirmed_locations.is_empty() {
        let poc = confirmed_locations.first().map(|loc| {
            let field = match loc {
                AffectedLocation::Field(_, f) => f,
                _ => "fieldName",
            };
>>>>>>> update-research-refs
            format!(
                "curl -X POST {} \\\n  -H 'Content-Type: application/json' \\\n  -d '{{\"query\":\"{{ {} {{ id }} }}\"}}'",
                url, field
            )
        });

<<<<<<< HEAD
        confirmed.push(AuditFinding {
=======
        confirmed.push(Finding {
>>>>>>> update-research-refs
            id: "AUD-001",
            severity: Severity::High,
            title: "Unauthenticated Access Confirmed",
            description: format!(
                "{} query/mutation root operation(s) returned non-null data without Authorization (attempted {} no-required-arg operations; {} blocked by auth; {} skipped due required args).",
<<<<<<< HEAD
                confirmed_access.len(),
=======
                confirmed_locations.len(),
>>>>>>> update-research-refs
                attempted,
                auth_blocked,
                skipped_required_args
            ),
<<<<<<< HEAD
            affected: confirmed_access,
            remediation: "Require authentication and resolver-level authorization checks before returning data for all root operations.",
            evidence: "confirmed",
=======
            affected: confirmed_locations,
            remediation: "Require authentication and resolver-level authorization checks before returning data for all root operations.",
            first_step: Some("Manually test one of the confirmed operations using curl (see PoC) to verify it returns data without a token.".into()),
            references: vec!["OWASP API5: Broken Function Level Authorization"],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
>>>>>>> update-research-refs
            poc,
        });
    }

<<<<<<< HEAD
    if !inconclusive.is_empty() {
        unconfirmed.push(AuditFinding {
=======
    if !inconclusive_locations.is_empty() {
        unconfirmed.push(Finding {
>>>>>>> update-research-refs
            id: "AUD-001",
            severity: Severity::Medium,
            title: "Unauthenticated Access Probe Inconclusive",
            description: format!(
                "{} operation(s) returned non-auth errors or null data in unauthenticated probe mode (attempted {}; {} blocked by auth; {} skipped due required args; {} validation failures ignored).",
<<<<<<< HEAD
                inconclusive.len(),
=======
                inconclusive_locations.len(),
>>>>>>> update-research-refs
                attempted,
                auth_blocked,
                skipped_required_args,
                validation_failures
            ),
<<<<<<< HEAD
            affected: inconclusive,
            remediation: "Review resolver authorization behavior and test manually with operation-specific payloads.",
            evidence: "inconclusive",
=======
            affected: inconclusive_locations,
            remediation: "Review resolver authorization behavior and test manually with operation-specific payloads.",
            first_step: Some("Check if these operations return 'null' for unauthenticated users as a design choice, or if they require specific arguments to return data.".into()),
            references: vec!["OWASP API5: Broken Function Level Authorization"],
            status: FindingStatus::Possible,
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inconclusive,
>>>>>>> update-research-refs
            poc: None,
        });
    }

    Ok(())
}
