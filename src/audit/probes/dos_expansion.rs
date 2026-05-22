use crate::audit::utils::{effective_headers, find_best_probe_target, post_graphql_ext};
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
    confirmed: &mut Vec<Finding>,
    _unconfirmed: &mut Vec<Finding>,
) -> Result<(), String> {
    let headers = effective_headers(extra_headers, None, false);
    
    // 1. Baseline Request
    let Some(target) = find_best_probe_target(schema) else { return Ok(()); };
    let baseline_query = format!("query {{ {} }}", target.name);
    let baseline_resp = post_graphql_ext(client, url, &headers, &baseline_query, None, rate_limit_ms, evasion_level).await?;
    let baseline_ms = baseline_resp.elapsed_ms;

    // 2. Directive Overloading Test
    let mut directives = String::new();
    for _ in 0..100 {
        directives.push_str(" @include(if:true)");
    }
    let directive_query = format!("query {{ {}{} }}", target.name, directives);
    let dir_resp = post_graphql_ext(client, url, &headers, &directive_query, None, rate_limit_ms, evasion_level).await?;
    
    if dir_resp.elapsed_ms > baseline_ms + 2000 || dir_resp.status == 500 || dir_resp.status == 503 {
         confirmed.push(Finding {
            id: "AUD-DOS-004",
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

    // 3. Field Duplication Test
    let mut fields = String::new();
    for _ in 0..500 {
        fields.push_str(&format!(" {} ", target.name));
    }
    let field_dup_query = format!("query {{ {} }}", fields);
    let field_resp = post_graphql_ext(client, url, &headers, &field_dup_query, None, rate_limit_ms, evasion_level).await?;

    if field_resp.elapsed_ms > baseline_ms + 2000 || field_resp.status == 500 || field_resp.status == 503 {
        confirmed.push(Finding {
            id: "AUD-DOS-005",
            severity: Severity::Medium,
            title: "GraphQL Field Duplication (DoS Risk)",
            description: "The endpoint processed a query with 500+ duplicated fields, resulting in significant resource consumption.".to_string(),
            affected: vec![AffectedLocation::Type("Query Parser / Executer".into())],
            remediation: "Enforce a maximum field count per query and implement strict complexity limits.",
            first_step: Some("Manually send a query that repeats a safe scalar field 500+ times.".into()),
            references: vec!["OWASP API4", "CWE-400"],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
            poc: Some(field_dup_query.chars().take(300).collect()),
        });
    }

    // 4. Recursive Query Verification (Passive-to-Active)
    if let Some(circular) = passive_findings.iter().find(|f| f.id == "GQL-003") {
        for loc in &circular.affected {
            let type_name = match loc {
                AffectedLocation::Type(t) => t,
                _ => continue,
            };

            // Attempt to find a field in Query that returns this type, or skip
            let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
            let query_fields = schema.fields_for_type(query_name);
            let start_field = query_fields.iter().find(|f| {
                f.field_type.as_ref().and_then(|ft| ft.unwrap_type_name()).as_deref() == Some(type_name)
            });

            if let Some(f) = start_field {
                // Find a field on the type that loops back to itself (simple recursion)
                let self_fields = schema.fields_for_type(Some(type_name));
                let recurse_field = self_fields.iter().find(|sf| {
                     sf.field_type.as_ref().and_then(|ft| ft.unwrap_type_name()).as_deref() == Some(type_name)
                });

                if let Some(rf) = recurse_field {
                    // Build a 10-level nested query
                    let nested = format!("{{ id __typename {0} {{ id __typename {0} {{ id __typename {0} {{ id __typename {0} {{ id __typename {0} {{ id __typename {0} {{ id __typename {0} {{ id __typename {0} {{ id __typename {0} {{ id __typename }} }} }} }} }} }} }} }} }} }}", rf.name);
                    let recurse_query = format!("query {{ {} {} }}", f.name, nested);
                    
                    let rec_resp = post_graphql_ext(client, url, &headers, &recurse_query, None, rate_limit_ms, evasion_level).await?;
                    if rec_resp.elapsed_ms > baseline_ms + 2500 || rec_resp.status == 500 {
                         confirmed.push(Finding {
                            id: "AUD-DOS-006",
                            severity: Severity::High,
                            title: "Recursive Query Unbounded (DoS Confirmed)",
                            description: format!("The server successfully processed or timed out on a 10-level deeply nested recursive query following the '{}' path. This confirms that query depth limiting is missing or too permissive.", type_name),
                            affected: vec![loc.clone()],
                            remediation: "Implement strict query depth limiting (max 7-10) and use complexity-aware validation.",
                            first_step: Some(format!("Execute the PoC recursive query and verify if the server returns data for all levels or times out.")),
                            references: vec!["OWASP API4", "CWE-400"],
                            status: FindingStatus::Confirmed,
                            confidence: Confidence::Confirmed,
                            evidence_level: EvidenceLevel::Executed,
                            poc: Some(recurse_query),
                        });
                    }
                }
            }
        }
    }

    Ok(())
}
