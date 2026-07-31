use crate::utils::matches_pattern;
use crate::config::PatternConfig;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlField, GqlSchema, Severity};

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
            id: "mutations-missing-auth",
            severity: Severity::Medium,
            title: "No Authorization Directives Found on Mutations",
            description: format!(
                "{} mutation(s) are present but no authorization directives (@auth, @isAuthenticated, @hasRole, etc.) appear in the schema. Mutations may lack declarative access control.",
                mutation_fields.len()
            ),
            affected: mutation_fields
                .iter()
                .map(|f| AffectedLocation::Field("Mutation".into(), f.name.clone()))
                .take(20)
                .collect(),
            remediation: "Use schema-level auth directives (graphql-shield, graphql-authz, or server-specific auth plugins). Every mutation that modifies data should require explicit authorization.",
            first_step: Some("Check the server's documentation or configuration to see how mutations are protected if not through directives.".into()),
            references: vec![
                "OWASP API1: Broken Object Level Authorization",
                "OWASP API5: Broken Function Level Authorization",
            ],
            status: FindingStatus::Inferred,
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

    let sub_fields = schema.fields_for_type(subscription_name);
    if !sub_fields.is_empty() {
        findings.push(Finding {
            id: "subscriptions-exposed",
            severity: Severity::Medium,
            title: "Subscriptions Exposed",
            description: format!(
                "{} subscription(s) found. Unauthenticated or rate-unlimited subscriptions allow attackers to maintain persistent WebSocket connections, drain server resources, or exfiltrate streaming data.",
                sub_fields.len()
            ),
            affected: sub_fields
                .iter()
                .map(|f| AffectedLocation::Field("Subscription".into(), f.name.clone()))
                .collect(),
            remediation: "Require authentication for all subscriptions. Enforce per-user connection limits and rate-limit subscription creation. Validate all subscription filter payloads server-side.",
            first_step: Some("Attempt to connect to the subscription endpoint without a token to see if it allows the connection.".into()),
            references: vec!["CWE-770: Allocation of Resources Without Limits"],
            status: FindingStatus::Inferred,
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

    if mutation_fields.len() > 20 {
        findings.push(Finding {
            id: "large-mutation-surface",
            severity: Severity::Medium,
            title: "Large Mutation Attack Surface",
            description: format!(
                "{} mutations are exposed. A large mutation surface increases the probability of missing access controls, mass-assignment vulnerabilities, and IDOR issues.",
                mutation_fields.len()
            ),
            affected: vec![AffectedLocation::Type("Mutation".into())],
            remediation: "Audit each mutation for authorization requirements. Consider splitting schemas by role/context, or use persisted/allow-listed queries to limit operations.",
            first_step: Some("Focus your audit on high-impact mutations like those that modify users, roles, or financial data.".into()),
            references: vec!["OWASP API6: Mass Assignment", "CWE-915: Improperly Controlled Modification"],
            status: FindingStatus::Inferred,
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

    let mut idor_possibilities: Vec<AffectedLocation> = Vec::new();
    let query_fields = schema.fields_for_type(query_name);
    for (root_name, fields) in [("Query", &query_fields), ("Mutation", &mutation_fields)] {
        for field in fields {
            if let Some(args) = &field.args {
                for arg in args {
                    if idor_arg_matches(&arg.name) {
                        idor_possibilities.push(AffectedLocation::Argument(root_name.into(), field.name.clone(), arg.name.clone()));
                    }
                }
            }
        }
    }

    // Also flag root query/mutation fields that return a SINGLE object (not a list)
    // and take exactly ONE required scalar argument matching a unique-selector name
    // (username, slug, email, etc). These are lookups-by-unique-key just like
    // id-based lookups and are equally susceptible to BOLA/IDOR if ownership isn't
    // checked server-side, even though the argument name doesn't look like an "id".
    let unique_selector_patterns: Vec<String> = ["username", "user", "slug", "handle", "email", "name", "key"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    for (root_name, fields) in [("Query", &query_fields), ("Mutation", &mutation_fields)] {
        for field in fields {
            let Some(field_type) = &field.field_type else { continue };
            if field_type.is_list() {
                continue;
            }
            let is_object_return = matches!(field_type.unwrap_kind().as_deref(), Some("OBJECT") | Some("INTERFACE"));
            if !is_object_return {
                continue;
            }
            let Some(args) = &field.args else { continue };
            let required_args: Vec<&crate::types::GqlArg> = args
                .iter()
                .filter(|a| {
                    a.arg_type
                        .as_ref()
                        .map(|t| t.kind.as_deref() == Some("NON_NULL"))
                        .unwrap_or(false)
                })
                .collect();
            if required_args.len() != 1 {
                continue;
            }
            let arg = required_args[0];
            let is_scalar = arg
                .arg_type
                .as_ref()
                .map(|t| matches!(t.unwrap_kind().as_deref(), Some("SCALAR") | Some("ENUM")))
                .unwrap_or(false);
            if !is_scalar {
                continue;
            }
            if matches_pattern(&arg.name, &unique_selector_patterns) {
                let loc = AffectedLocation::Argument(root_name.into(), field.name.clone(), arg.name.clone());
                if !idor_possibilities.contains(&loc) {
                    idor_possibilities.push(loc);
                }
            }
        }
    }

    if !idor_possibilities.is_empty() {
        findings.push(Finding {
            id: "idor-surface",
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
            confidence: Confidence::Possible,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

    let mut ssrf_possibilities: Vec<AffectedLocation> = Vec::new();
    for (root_name, fields) in [("Query", &query_fields), ("Mutation", &mutation_fields)] {
        for field in fields {
            if let Some(args) = &field.args {
                for arg in args {
                    if matches_pattern(&arg.name, &patterns.ssrf_args.names) {
                        ssrf_possibilities.push(AffectedLocation::Argument(root_name.into(), field.name.clone(), arg.name.clone()));
                    }
                }
            }
        }
    }

    if !ssrf_possibilities.is_empty() {
        findings.push(Finding {
            id: "ssrf-surface",
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
            confidence: Confidence::Possible,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }
}

/// Detects a Relay-style global object fetcher: a `Node` interface plus a root
/// `node(id:)` / `nodes(ids:)` field. A single opaque endpoint that returns any object by
/// its global id is an enumerable BOLA/IDOR surface when those ids are unsigned/predictable
/// (e.g. base64 of `Type:<int>` or `gid://host/Type/<int>`). Schema-only — the logged-in
/// vs. logged-out confirmation is left to a manual two-session test.
pub fn check_node_idor(schema: &GqlSchema, findings: &mut Vec<Finding>) {
    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let query_fields = schema.fields_for_type(query_name);

    let field_has_arg =
        |f: &GqlField, arg: &str| f.args.as_ref().map(|a| a.iter().any(|x| x.name == arg)).unwrap_or(false);

    let node_field = query_fields
        .iter()
        .copied()
        .find(|f| f.name == "node" && field_has_arg(f, "id"));
    let nodes_field = query_fields
        .iter()
        .copied()
        .find(|f| f.name == "nodes" && (field_has_arg(f, "ids") || field_has_arg(f, "id")));

    // Without a `node`/`nodes` global fetcher there is no enumerable surface to flag.
    if node_field.is_none() && nodes_field.is_none() {
        return;
    }

    let node_iface = schema.types.iter().find(|t| {
        t.kind.as_deref() == Some("INTERFACE") && t.name.as_deref() == Some("Node")
    });

    // The Node interface's `possibleTypes` enumerates every type reachable through `node(id:)`.
    let impls: Vec<String> = node_iface
        .and_then(|t| t.possible_types.as_ref())
        .map(|pts| pts.iter().filter_map(|r| r.name.clone()).collect())
        .unwrap_or_default();

    let impl_note = if impls.is_empty() {
        String::new()
    } else {
        format!(
            " The global fetcher can reach {} object type(s) (e.g. {}).",
            impls.len(),
            impls.iter().take(6).cloned().collect::<Vec<_>>().join(", ")
        )
    };

    let mut affected = Vec::new();
    if node_field.is_some() {
        affected.push(AffectedLocation::Field("Query".into(), "node".into()));
    }
    if nodes_field.is_some() {
        affected.push(AffectedLocation::Field("Query".into(), "nodes".into()));
    }

    findings.push(Finding {
        id: "node-idor-surface",
        severity: Severity::Medium,
        title: "Relay Global-Object (node) Fetch Surface",
        description: format!(
            "A Relay-style global object fetcher is exposed (a `Node` interface{} plus a root `node(id:)`/`nodes(ids:)` field).{} A single opaque endpoint that returns any object by its global id is an enumerable BOLA/IDOR surface if those ids are unsigned or predictable — base64 of `Type:<int>` or `gid://host/Type/<int>` schemes are directly enumerable.",
            if node_iface.is_some() { "" } else { " (implicit — no `Node` interface found, but a global fetcher is present)" },
            impl_note
        ),
        affected,
        remediation: "Ensure `node(id:)` enforces the same object-level authorization as each type-specific resolver, and issue signed/opaque, non-enumerable global ids. Confirm safety by requesting a global id you own while logged out or as a different identity.",
        first_step: Some("Decode a real global id (usually base64) to reveal its `Type:<int>` scheme, then request an adjacent id via `node(id:)` as a different identity to test ownership enforcement.".into()),
        references: vec![
            "OWASP API1: Broken Object Level Authorization",
            "CWE-639: Authorization Bypass Through User-Controlled Key",
        ],
        status: FindingStatus::Inferred,
        confidence: Confidence::Possible,
        evidence_level: EvidenceLevel::Inferred,
        poc: Some("query { node(id: \"<GLOBAL_ID>\") { id __typename } }".into()),
    });
}
