use crate::audit::utils::{effective_headers, find_best_probe_target, post_graphql_ext};
use crate::transport::Transport;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, Severity};
use reqwest::Client;

pub async fn probe_dos_expansion(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    evasion_level: u8,
    passive_findings: &[Finding],
    transport: Transport,
    confirmed: &mut Vec<Finding>,
    _unconfirmed: &mut Vec<Finding>,
) -> Result<(), String> {
    let headers = effective_headers(extra_headers, None, false);

    // 1. Baseline Request
    let Some(target) = find_best_probe_target(schema) else { return Ok(()); };
    let baseline_query = format!("query {{ {} }}", target.name);
    let baseline_resp = post_graphql_ext(client, url, &headers, &baseline_query, None, rate_limit_ms, evasion_level, transport, false).await?;
    let baseline_ms = baseline_resp.elapsed_ms;

    // 2. Directive Overloading Test
    let mut directives = String::new();
    for _ in 0..100 {
        directives.push_str(" @include(if:true)");
    }
    let directive_query = format!("query {{ {}{} }}", target.name, directives);
    let dir_resp = post_graphql_ext(client, url, &headers, &directive_query, None, rate_limit_ms, evasion_level, transport, false).await?;
    
    if dir_resp.elapsed_ms > baseline_ms + 2000 || dir_resp.status == 500 || dir_resp.status == 503 {
         confirmed.push(Finding {
            id: "directive-overloading",
            severity: Severity::Medium,
            title: "GraphQL Directive Overloading (DoS Risk)",
            description: "The endpoint processed a query with 100+ duplicated directives, resulting in a significant performance degradation or server error.".to_string(),
            affected: vec![AffectedLocation::Type("Query Execution Engine".into())],
            remediation: "Implement a maximum directive count per query and use server-side complexity analysis.",
            first_step: Some("Execute a query with many @include or @skip directives and monitor the server response time.".into()),
            references: vec!["OWASP API4", "CWE-400"],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
            poc: Some(directive_query.chars().take(300).collect()),
        });
    }

    // 3. Field Duplication Test (aliased).
    // Repeating the SAME field name is collapsed to a single resolver call by
    // spec-compliant servers, so it tests nothing. Aliasing each occurrence
    // (a0:, a1:, ...) forces the server to resolve all 500 distinct selections.
    let mut fields = String::new();
    for i in 0..500 {
        fields.push_str(&format!(" a{}: {}", i, target.name));
    }
    let field_dup_query = format!("query {{{} }}", fields);
    let field_resp = post_graphql_ext(client, url, &headers, &field_dup_query, None, rate_limit_ms, evasion_level, transport, false).await?;

    if field_resp.elapsed_ms > baseline_ms + 2000 || field_resp.status == 500 || field_resp.status == 503 {
        confirmed.push(Finding {
            id: "field-duplication",
            severity: Severity::Medium,
            title: "GraphQL Field Duplication (DoS Risk)",
            description: "The endpoint processed a query with 500 aliased duplicates of a single field, resulting in significant resource consumption. Aliasing prevents the server from collapsing the duplicates, so each was resolved independently.".to_string(),
            affected: vec![AffectedLocation::Type("Query Parser / Executor".into())],
            remediation: "Enforce a maximum field/alias count per query and implement strict complexity limits.",
            first_step: Some("Manually send a query that selects a safe scalar field 500 times using distinct aliases (a0:, a1:, ...).".into()),
            references: vec!["OWASP API4", "CWE-400"],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
            poc: Some(field_dup_query.chars().take(300).collect()),
        });
    }

    // 4. Recursive Query Verification (passive-to-active).
    // Walk a cycle detected by static analysis (recursive-type-refs) — direct OR indirect
    // (A -> B -> A) — building progressively deeper nested queries along it and
    // ramping depth until the server shows strain (latency spike or 5xx).
    if let Some(circular) = passive_findings.iter().find(|f| f.id == "recursive-type-refs") {
        let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
        'cycle: for loc in &circular.affected {
            let cycle_str = match loc {
                AffectedLocation::Type(t) => t,
                _ => continue,
            };

            // The static analyzer records a canonical closed path like "A → B → A".
            // Reduce it to the repeating type sequence [A, B].
            let mut seq: Vec<&str> = cycle_str.split(" → ").collect();
            if seq.len() >= 2 && seq.first() == seq.last() {
                seq.pop();
            }
            if seq.is_empty() {
                continue;
            }

            // Need a Query root field returning the cycle's entry type.
            let Some(start_field) = field_returning(schema, query_name, seq[0]) else {
                continue;
            };
            let start_name = start_field.name.clone();

            for &depth in &[4usize, 8, 12] {
                let Some(selection) = build_cycle_selection(schema, &seq, depth) else {
                    continue 'cycle;
                };
                let recurse_query = format!("query {{ {} {} }}", start_name, selection);
                let rec_resp = post_graphql_ext(client, url, &headers, &recurse_query, None, rate_limit_ms, evasion_level, transport, false).await?;

                if rec_resp.elapsed_ms > baseline_ms + 2500 || rec_resp.status == 500 || rec_resp.status == 503 {
                    confirmed.push(Finding {
                        id: "unbounded-query-depth",
                        severity: Severity::High,
                        title: "Recursive Query Depth Unbounded (DoS)",
                        description: format!(
                            "The server processed (or errored on) a {}-level deeply nested query following the recursive type path '{}'. This indicates query-depth limiting is missing or too permissive, allowing depth-based resource exhaustion.",
                            depth, cycle_str
                        ),
                        affected: vec![loc.clone()],
                        remediation: "Implement strict query-depth limiting (recommended max 7-10) and complexity-aware validation.",
                        first_step: Some("Execute the PoC recursive query and observe whether the server returns all nested levels or times out / errors.".into()),
                        references: vec!["OWASP API4: Lack of Resources", "CWE-400: Uncontrolled Resource Consumption"],
                        status: FindingStatus::Confirmed,
                        confidence: Confidence::Confirmed,
                        evidence_level: EvidenceLevel::Executed,
                        poc: Some(recurse_query),
                    });
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Find a field on `type_name` whose (unwrapped) return type is `target`.
fn field_returning<'a>(
    schema: &'a GqlSchema,
    type_name: Option<&str>,
    target: &str,
) -> Option<&'a crate::types::GqlField> {
    schema.fields_for_type(type_name).into_iter().find(|f| {
        f.field_type
            .as_ref()
            .and_then(|ft| ft.unwrap_type_name())
            .as_deref()
            == Some(target)
    })
}

/// Build a nested selection set that walks `seq` cyclically for `depth` levels,
/// e.g. for seq [A,B]: `{ fieldAtoB { fieldBtoA { fieldAtoB { __typename } } } }`.
/// Returns None if any link in the cycle can't be resolved to a field.
fn build_cycle_selection(schema: &GqlSchema, seq: &[&str], depth: usize) -> Option<String> {
    let mut field_names: Vec<String> = Vec::with_capacity(depth);
    for i in 0..depth {
        let cur = seq[i % seq.len()];
        let nxt = seq[(i + 1) % seq.len()];
        let f = field_returning(schema, Some(cur), nxt)?;
        field_names.push(f.name.clone());
    }
    let mut sel = String::from("{ __typename }");
    for fname in field_names.iter().rev() {
        sel = format!("{{ {} {} }}", fname, sel);
    }
    Some(sel)
}
