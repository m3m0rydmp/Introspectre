<<<<<<< HEAD
use crate::analysis::utils::matches_pattern;
use crate::config::PatternConfig;
use crate::types::{Confidence, EvidenceLevel, Finding, GqlSchema, Severity};
use std::collections::HashSet;
=======
use crate::utils::matches_pattern;
use crate::config::PatternConfig;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, Severity};
>>>>>>> update-research-refs

pub fn check_access_control(
    schema: &GqlSchema,
    patterns: &PatternConfig,
    findings: &mut Vec<Finding>,
) {
    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let mutation_name = schema.mutation_type.as_ref().map(|m| m.name.as_str());
    let subscription_name = schema.subscription_type.as_ref().map(|s| s.name.as_str());

    let directives = schema.directives.as_deref().unwrap_or(&[]);
    let has_auth_directives = directives.iter().any(|d| {
        patterns
            .auth_directives
            .names
            .iter()
            .any(|a| d.name.to_lowercase().contains(&a.to_lowercase()))
    });

    let mutation_fields = schema.fields_for_type(mutation_name);
    if !mutation_fields.is_empty() && !has_auth_directives {
        findings.push(Finding {
            id: "GQL-004",
            severity: Severity::Medium,
            title: "No Authorization Directives Found on Mutations",
            description: format!(
                "{} mutation(s) are present but no authorization directives (@auth, @isAuthenticated, @hasRole, etc.) appear in the schema. Mutations may lack declarative access control.",
                mutation_fields.len()
            ),
            affected: mutation_fields
                .iter()
<<<<<<< HEAD
                .map(|f| format!("Mutation.{}", f.name))
                .take(20)
                .collect(),
            remediation: "Use schema-level auth directives (graphql-shield, graphql-authz, or server-specific auth plugins). Every mutation that modifies data should require explicit authorization.",
=======
                .map(|f| AffectedLocation::Field("Mutation".into(), f.name.clone()))
                .take(20)
                .collect(),
            remediation: "Use schema-level auth directives (graphql-shield, graphql-authz, or server-specific auth plugins). Every mutation that modifies data should require explicit authorization.",
            first_step: Some("Check the server's documentation or configuration to see how mutations are protected if not through directives.".into()),
>>>>>>> update-research-refs
            references: vec![
                "OWASP API1: Broken Object Level Authorization",
                "OWASP API5: Broken Function Level Authorization",
            ],
<<<<<<< HEAD
=======
            status: FindingStatus::Inferred,
>>>>>>> update-research-refs
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

    let sub_fields = schema.fields_for_type(subscription_name);
    if !sub_fields.is_empty() {
        findings.push(Finding {
            id: "GQL-005",
            severity: Severity::Medium,
            title: "Subscriptions Exposed",
            description: format!(
                "{} subscription(s) found. Unauthenticated or rate-unlimited subscriptions allow attackers to maintain persistent WebSocket connections, drain server resources, or exfiltrate streaming data.",
                sub_fields.len()
            ),
            affected: sub_fields
                .iter()
<<<<<<< HEAD
                .map(|f| format!("Subscription.{}", f.name))
                .collect(),
            remediation: "Require authentication for all subscriptions. Enforce per-user connection limits and rate-limit subscription creation. Validate all subscription filter payloads server-side.",
            references: vec!["CWE-770: Allocation of Resources Without Limits"],
=======
                .map(|f| AffectedLocation::Field("Subscription".into(), f.name.clone()))
                .collect(),
            remediation: "Require authentication for all subscriptions. Enforce per-user connection limits and rate-limit subscription creation. Validate all subscription filter payloads server-side.",
            first_step: Some("Attempt to connect to the subscription endpoint without a token to see if it allows the connection.".into()),
            references: vec!["CWE-770: Allocation of Resources Without Limits"],
            status: FindingStatus::Inferred,
>>>>>>> update-research-refs
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

    if mutation_fields.len() > 20 {
        findings.push(Finding {
            id: "GQL-006",
            severity: Severity::Medium,
            title: "Large Mutation Attack Surface",
            description: format!(
                "{} mutations are exposed. A large mutation surface increases the probability of missing access controls, mass-assignment vulnerabilities, and IDOR issues.",
                mutation_fields.len()
            ),
<<<<<<< HEAD
            affected: vec![format!("{} total mutations", mutation_fields.len())],
            remediation: "Audit each mutation for authorization requirements. Consider splitting schemas by role/context, or use persisted/allow-listed queries to limit operations.",
            references: vec!["OWASP API6: Mass Assignment", "CWE-915: Improperly Controlled Modification"],
=======
            affected: vec![AffectedLocation::Type("Mutation".into())],
            remediation: "Audit each mutation for authorization requirements. Consider splitting schemas by role/context, or use persisted/allow-listed queries to limit operations.",
            first_step: Some("Focus your audit on high-impact mutations like those that modify users, roles, or financial data.".into()),
            references: vec!["OWASP API6: Mass Assignment", "CWE-915: Improperly Controlled Modification"],
            status: FindingStatus::Inferred,
>>>>>>> update-research-refs
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

    let idor_arg_matches = |arg_name: &str| {
        let lower = arg_name.to_lowercase();
        matches!(lower.as_str(), "id" | "uuid" | "userid" | "documentid")
            || lower.ends_with("id")
            || lower.ends_with("_id")
    };

<<<<<<< HEAD
    let mut idor_candidates: HashSet<String> = HashSet::new();
=======
    let mut idor_possibilities: Vec<AffectedLocation> = Vec::new();
>>>>>>> update-research-refs
    let query_fields = schema.fields_for_type(query_name);
    for (root_name, fields) in [("Query", &query_fields), ("Mutation", &mutation_fields)] {
        for field in fields {
            if let Some(args) = &field.args {
                for arg in args {
                    if idor_arg_matches(&arg.name) {
<<<<<<< HEAD
                        idor_candidates
                            .insert(format!("{}.{}({})", root_name, field.name, arg.name));
=======
                        idor_possibilities.push(AffectedLocation::Argument(root_name.into(), field.name.clone(), arg.name.clone()));
>>>>>>> update-research-refs
                    }
                }
            }
        }
    }

<<<<<<< HEAD
    if !idor_candidates.is_empty() {
        let mut sorted_candidates: Vec<String> = idor_candidates.into_iter().collect();
        sorted_candidates.sort();
        findings.push(Finding {
            id: "GQL-013",
            severity: Severity::Medium,
            title: "IDOR Candidate Detection",
            description: format!(
                "{} query/mutation argument(s) appear to accept object identifiers. These are potential BOLA/IDOR candidates if ownership checks are missing server-side.",
                sorted_candidates.len()
            ),
            affected: sorted_candidates.into_iter().take(30).collect(),
            remediation: "Enforce object-level authorization on every resolver that accepts identifiers (id, uuid, *Id, *_id). Validate caller ownership before returning or mutating records.",
            references: vec!["OWASP API1: Broken Object Level Authorization", "CWE-639: Authorization Bypass Through User-Controlled Key"],
=======
    if !idor_possibilities.is_empty() {
        findings.push(Finding {
            id: "GQL-013",
            severity: Severity::Medium,
            title: "IDOR Possibility Detection",
            description: format!(
                "{} query/mutation argument(s) appear to accept object identifiers. These are potential BOLA/IDOR possibilities if ownership checks are missing server-side.",
                idor_possibilities.len()
            ),
            affected: idor_possibilities.into_iter().take(30).collect(),
            remediation: "Enforce object-level authorization on every resolver that accepts identifiers (id, uuid, *Id, *_id). Validate caller ownership before returning or mutating records.",
            first_step: Some("Identify a field that takes an ID and attempt to query it with an ID belonging to a different user.".into()),
            references: vec!["OWASP API1: Broken Object Level Authorization", "CWE-639: Authorization Bypass Through User-Controlled Key"],
            status: FindingStatus::Inferred,
>>>>>>> update-research-refs
            confidence: Confidence::Possible,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

<<<<<<< HEAD
    let mut ssrf_candidates: HashSet<String> = HashSet::new();
=======
    let mut ssrf_possibilities: Vec<AffectedLocation> = Vec::new();
>>>>>>> update-research-refs
    for (root_name, fields) in [("Query", &query_fields), ("Mutation", &mutation_fields)] {
        for field in fields {
            if let Some(args) = &field.args {
                for arg in args {
                    if matches_pattern(&arg.name, &patterns.ssrf_args.names) {
<<<<<<< HEAD
                        ssrf_candidates
                            .insert(format!("{}.{}({})", root_name, field.name, arg.name));
=======
                        ssrf_possibilities.push(AffectedLocation::Argument(root_name.into(), field.name.clone(), arg.name.clone()));
>>>>>>> update-research-refs
                    }
                }
            }
        }
    }

<<<<<<< HEAD
    if !ssrf_candidates.is_empty() {
        let mut sorted_candidates: Vec<String> = ssrf_candidates.into_iter().collect();
        sorted_candidates.sort();
        findings.push(Finding {
            id: "GQL-014",
            severity: Severity::Medium,
            title: "SSRF Candidate Detection",
            description: format!(
                "{} query/mutation argument(s) match SSRF-related URL/webhook patterns. If backend services fetch these values, SSRF may be possible.",
                sorted_candidates.len()
            ),
            affected: sorted_candidates.into_iter().take(30).collect(),
            remediation: "Block internal network destinations, enforce strict URL allow-lists, and isolate outbound fetchers. Never allow resolver-controlled requests to metadata or loopback addresses.",
            references: vec!["OWASP API8: Injection", "CWE-918: Server-Side Request Forgery (SSRF)"],
=======
    if !ssrf_possibilities.is_empty() {
        findings.push(Finding {
            id: "GQL-014",
            severity: Severity::Medium,
            title: "SSRF Possibility Detection",
            description: format!(
                "{} query/mutation argument(s) match SSRF-related URL/webhook patterns. If backend services fetch these values, SSRF may be possible.",
                ssrf_possibilities.len()
            ),
            affected: ssrf_possibilities.into_iter().take(30).collect(),
            remediation: "Block internal network destinations, enforce strict URL allow-lists, and isolate outbound fetchers. Never allow resolver-controlled requests to metadata or loopback addresses.",
            first_step: Some("Provide a URL to a Burp Collaborator or similar listener to see if the server makes an outbound request.".into()),
            references: vec!["OWASP API8: Injection", "CWE-918: Server-Side Request Forgery (SSRF)"],
            status: FindingStatus::Inferred,
>>>>>>> update-research-refs
            confidence: Confidence::Possible,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }
}
