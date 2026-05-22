<<<<<<< HEAD
use crate::analysis::utils::{matches_pattern, user_types};
use crate::config::PatternConfig;
use crate::types::{Confidence, EvidenceLevel, Finding, GqlSchema, GqlType, Severity};
=======
use crate::utils::{matches_pattern, user_types};
use crate::config::PatternConfig;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, GqlType, Severity};
>>>>>>> update-research-refs
use std::collections::{HashMap, HashSet};

pub fn check_information_exposure(
    schema: &GqlSchema,
    patterns: &PatternConfig,
    findings: &mut Vec<Finding>,
) {
    let types = user_types(schema);
    let type_map: HashMap<&str, &GqlType> = schema
        .types
        .iter()
        .filter_map(|t| t.name.as_deref().map(|n| (n, t)))
        .collect();

    let has_introspection = schema.types.iter().any(|t| {
        t.name
            .as_deref()
            .map(|n| n.starts_with("__"))
            .unwrap_or(false)
    });
    if has_introspection {
        findings.push(Finding {
            id: "GQL-001",
            severity: Severity::Info,
            title: "Introspection Enabled",
            description: "GraphQL introspection is enabled. Attackers can enumerate all types, fields, queries, and mutations — essentially a free schema map for targeting attacks.".into(),
<<<<<<< HEAD
            affected: vec!["__schema".into(), "__type".into()],
            remediation: "Disable introspection in production (set `introspection: false` in your server config). Allow-list only via internal tooling or developer environments.",
            references: vec!["CWE-200: Information Exposure", "OWASP API Security Top 10"],
=======
            affected: vec![AffectedLocation::Field("__schema".into(), "types".into()), AffectedLocation::Field("__schema".into(), "directives".into())],
            remediation: "Disable introspection in production (set `introspection: false` in your server config). Allow-list only via internal tooling or developer environments.",
            first_step: Some("Run an introspection query manually to see if it returns the full schema structure.".into()),
            references: vec!["CWE-200: Information Exposure", "OWASP API Security Top 10"],
            status: FindingStatus::Inferred,
>>>>>>> update-research-refs
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

<<<<<<< HEAD
    let mut sensitive: Vec<String> = Vec::new();
=======
    let mut sensitive: Vec<AffectedLocation> = Vec::new();
>>>>>>> update-research-refs
    for t in &types {
        let type_name = t.name.as_deref().unwrap_or("?");
        if let Some(fields) = &t.fields {
            for f in fields {
                if matches_pattern(&f.name, &patterns.sensitive_fields.names) {
<<<<<<< HEAD
                    sensitive.push(format!("{}.{}", type_name, f.name));
=======
                    sensitive.push(AffectedLocation::Field(type_name.into(), f.name.clone()));
>>>>>>> update-research-refs
                }
            }
        }
        if let Some(input_fields) = &t.input_fields {
            for f in input_fields {
                if matches_pattern(&f.name, &patterns.sensitive_fields.names) {
<<<<<<< HEAD
                    sensitive.push(format!("{}(input).{}", type_name, f.name));
=======
                    sensitive.push(AffectedLocation::Field(type_name.into(), f.name.clone()));
>>>>>>> update-research-refs
                }
            }
        }
    }
    if !sensitive.is_empty() {
        findings.push(Finding {
            id: "GQL-002",
            severity: Severity::High,
            title: "Sensitive Field Names Exposed",
            description: format!(
                "{} field(s) with names suggesting sensitive data (passwords, tokens, secrets, keys, etc.) are present in the schema. These may be accessible without authorization.",
                sensitive.len()
            ),
            affected: sensitive.into_iter().take(25).collect(),
            remediation: "Add field-level authorization for all sensitive fields. Consider masking, omitting from schema entirely, or using opaque identifiers.",
<<<<<<< HEAD
            references: vec!["OWASP API3: Excessive Data Exposure", "CWE-312: Cleartext Storage"],
=======
            first_step: Some("Query one of the highlighted sensitive fields with a dummy value to check for authorization errors.".into()),
            references: vec!["OWASP API3: Excessive Data Exposure", "CWE-312: Cleartext Storage"],
            status: FindingStatus::Inferred,
>>>>>>> update-research-refs
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

<<<<<<< HEAD
    let mut deprecated: Vec<String> = Vec::new();
=======
    let mut deprecated: Vec<AffectedLocation> = Vec::new();
>>>>>>> update-research-refs
    for t in &types {
        let type_name = t.name.as_deref().unwrap_or("?");
        if let Some(fields) = &t.fields {
            for f in fields {
                if f.is_deprecated.unwrap_or(false) {
<<<<<<< HEAD
                    let reason = f.deprecation_reason.as_deref().unwrap_or("no reason");
                    deprecated.push(format!("{}.{} ({})", type_name, f.name, reason));
=======
                    deprecated.push(AffectedLocation::Field(type_name.into(), f.name.clone()));
>>>>>>> update-research-refs
                }
            }
        }
    }

    if !deprecated.is_empty() {
        findings.push(Finding {
            id: "GQL-007",
            severity: Severity::Low,
            title: "Deprecated Fields Still Queryable",
            description: format!(
                "{} deprecated field(s) remain accessible. These may have weaker validation, outdated authorization logic, or expose legacy data paths.",
                deprecated.len()
            ),
            affected: deprecated.into_iter().take(20).collect(),
            remediation: "Remove deprecated fields or block access server-side. If kept for backward compatibility, ensure they have equivalent security controls to new fields.",
<<<<<<< HEAD
            references: vec!["CWE-477: Use of Obsolete Function"],
=======
            first_step: Some("Attempt to query a deprecated field to see if the server still resolves it or returns a warning.".into()),
            references: vec!["CWE-477: Use of Obsolete Function"],
            status: FindingStatus::Inferred,
>>>>>>> update-research-refs
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

<<<<<<< HEAD
    let sensitive_enums: Vec<String> = types
=======
    let sensitive_enums: Vec<AffectedLocation> = types
>>>>>>> update-research-refs
        .iter()
        .filter(|t| t.kind.as_deref() == Some("ENUM"))
        .filter(|t| {
            let name_sensitive = t
                .name
                .as_deref()
                .map(|n| matches_pattern(n, &patterns.sensitive_fields.names))
                .unwrap_or(false);
            let values_sensitive = t
                .enum_values
                .as_ref()
                .map(|vs| {
                    vs.iter()
                        .any(|v| matches_pattern(&v.name, &patterns.sensitive_fields.names))
                })
                .unwrap_or(false);
            name_sensitive || values_sensitive
        })
        .map(|t| {
<<<<<<< HEAD
            let values = t
                .enum_values
                .as_ref()
                .map(|vs| {
                    vs.iter()
                        .map(|v| v.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            format!("{}: [{}]", t.name.as_deref().unwrap_or("?"), values)
=======
            AffectedLocation::Type(t.name.clone().unwrap_or_default())
>>>>>>> update-research-refs
        })
        .collect();

    if !sensitive_enums.is_empty() {
        findings.push(Finding {
            id: "GQL-008",
            severity: Severity::Low,
            title: "Enums With Sensitive Values Exposed",
            description: format!(
                "{} enum type(s) expose names suggesting internal roles, permissions, or states. Attackers can enumerate valid states to assist privilege escalation or IDOR attacks.",
                sensitive_enums.len()
            ),
            affected: sensitive_enums,
            remediation: "Avoid exposing internal role/permission enums publicly. Use opaque identifiers and validate enum values strictly server-side.",
<<<<<<< HEAD
            references: vec!["CWE-200: Information Exposure"],
=======
            first_step: Some("Review the enum values in the schema to see if they expose internal business logic or roles.".into()),
            references: vec!["CWE-200: Information Exposure"],
            status: FindingStatus::Inferred,
>>>>>>> update-research-refs
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

<<<<<<< HEAD
    let bloated: Vec<String> = types
=======
    let bloated: Vec<AffectedLocation> = types
>>>>>>> update-research-refs
        .iter()
        .filter(|t| t.kind.as_deref() == Some("OBJECT"))
        .filter(|t| {
            let n = t.name.as_deref().unwrap_or("");
            !["Query", "Mutation", "Subscription"].contains(&n)
                && t.fields.as_ref().map(|f| f.len() > 30).unwrap_or(false)
        })
        .map(|t| {
<<<<<<< HEAD
            format!(
                "{} ({} fields)",
                t.name.as_deref().unwrap_or("?"),
                t.fields.as_ref().map(|f| f.len()).unwrap_or(0)
            )
=======
            AffectedLocation::Type(t.name.clone().unwrap_or_default())
>>>>>>> update-research-refs
        })
        .collect();

    if !bloated.is_empty() {
        findings.push(Finding {
            id: "GQL-009",
            severity: Severity::Low,
            title: "Over-Exposed Object Types (Field Bloat)",
            description: format!(
                "{} object type(s) expose more than 30 fields. Overly wide types increase the risk of unintentional data exposure and make authorization auditing harder.",
                bloated.len()
            ),
            affected: bloated,
            remediation: "Apply principle of least privilege to schema design. Split types by role (e.g. UserPublic vs UserAdmin). Add field-level resolvers with auth checks.",
<<<<<<< HEAD
            references: vec!["OWASP API3: Excessive Data Exposure"],
=======
            first_step: Some("Inspect one of the bloated types to see if it contains internal fields that shouldn't be public.".into()),
            references: vec!["OWASP API3: Excessive Data Exposure"],
            status: FindingStatus::Inferred,
>>>>>>> update-research-refs
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

    let mutation_name = schema.mutation_type.as_ref().map(|t| t.name.as_str());
    let mutation_fields = schema.fields_for_type(mutation_name);
<<<<<<< HEAD
    let mut untyped_mutations: Vec<String> = Vec::new();
=======
    let mut untyped_mutations: Vec<AffectedLocation> = Vec::new();
>>>>>>> update-research-refs
    for f in &mutation_fields {
        let is_untyped = f
            .args
            .as_ref()
            .map(|args| {
                args.iter().any(|a| {
                    a.arg_type
                        .as_ref()
                        .and_then(|t| t.unwrap_type_name())
                        .map(|n| n == "String" || n == "ID")
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);

        if is_untyped {
<<<<<<< HEAD
            untyped_mutations.push(format!("Mutation.{}", f.name));
=======
            untyped_mutations.push(AffectedLocation::Field("Mutation".into(), f.name.clone()));
>>>>>>> update-research-refs
        }
    }

    if !untyped_mutations.is_empty() {
        findings.push(Finding {
            id: "GQL-011",
            severity: Severity::Low,
            title: "Mutations Accept Raw String / ID Arguments",
            description: format!(
                "{} mutation(s) accept raw String or ID arguments. Without custom scalars or input validation, these are potential injection vectors (SQLi, NoSQLi, SSRF).",
                untyped_mutations.len()
            ),
            affected: untyped_mutations.into_iter().take(20).collect(),
            remediation: "Replace generic String/ID arguments with typed Input objects and custom scalars (e.g. EmailAddress, URL, UUID). Validate all inputs server-side regardless of scalar type.",
<<<<<<< HEAD
            references: vec!["CWE-20: Improper Input Validation", "OWASP API8: Injection"],
=======
            first_step: Some("Test one of these mutations with unexpected characters (like single quotes) to check for injection vulnerabilities.".into()),
            references: vec!["CWE-20: Improper Input Validation", "OWASP API8: Injection"],
            status: FindingStatus::Inferred,
>>>>>>> update-research-refs
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

<<<<<<< HEAD
    let debug_types: Vec<String> = types
=======
    let debug_types: Vec<AffectedLocation> = types
>>>>>>> update-research-refs
        .iter()
        .filter(|t| {
            t.name
                .as_deref()
                .map(|n| matches_pattern(n, &patterns.debug_types.names))
                .unwrap_or(false)
        })
<<<<<<< HEAD
        .map(|t| t.name.as_deref().unwrap_or("?").to_string())
=======
        .map(|t| AffectedLocation::Type(t.name.clone().unwrap_or_default()))
>>>>>>> update-research-refs
        .collect();

    if !debug_types.is_empty() {
        findings.push(Finding {
            id: "GQL-012",
            severity: Severity::Medium,
            title: "Debug / Admin / Internal Types Exposed",
            description: format!(
                "{} type name(s) suggest internal, debug, or admin functionality is exposed in the public schema. These are high-value targets for attackers.",
                debug_types.len()
            ),
            affected: debug_types,
            remediation: "Remove internal/debug types from the public schema. Use schema stitching or type visibility rules to expose only what external clients need.",
<<<<<<< HEAD
            references: vec!["CWE-489: Active Debug Code", "OWASP API7: Security Misconfiguration"],
=======
            first_step: Some("Try to query a field on one of these debug types to see if it requires special permissions.".into()),
            references: vec!["CWE-489: Active Debug Code", "OWASP API7: Security Misconfiguration"],
            status: FindingStatus::Inferred,
>>>>>>> update-research-refs
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

<<<<<<< HEAD
    let mut mass_assignment: Vec<String> = Vec::new();
=======
    let mut mass_assignment: Vec<AffectedLocation> = Vec::new();
>>>>>>> update-research-refs
    for f in &mutation_fields {
        if let Some(args) = &f.args {
            for arg in args {
                if let Some(input_type_name) =
                    arg.arg_type.as_ref().and_then(|t| t.unwrap_type_name())
                {
                    if let Some(input_type) = type_map.get(input_type_name.as_str()) {
                        if let Some(input_fields) = &input_type.input_fields {
                            for input_field in input_fields {
                                if matches_pattern(
                                    &input_field.name,
                                    &patterns.sensitive_fields.names,
                                ) {
<<<<<<< HEAD
                                    mass_assignment.push(format!(
                                        "Mutation.{}({}).{}",
                                        f.name, arg.name, input_field.name
                                    ));
=======
                                    mass_assignment.push(AffectedLocation::Argument("Mutation".into(), f.name.clone(), input_field.name.clone()));
>>>>>>> update-research-refs
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if !mass_assignment.is_empty() {
        findings.push(Finding {
            id: "GQL-017",
            severity: Severity::Medium,
            title: "Potential Mass Assignment in Mutation Input",
            description: format!(
                "{} mutation input field(s) match sensitive naming patterns. If these fields are not explicitly protected by server-side logic, attackers may be able to modify sensitive state (e.g. roles, permissions, internal flags) by including them in the mutation payload.",
                mass_assignment.len()
            ),
            affected: mass_assignment.into_iter().take(25).collect(),
            remediation: "Use specific 'Update' input types that only include user-editable fields. Never bind raw input objects directly to database models (Mass Assignment). Implement strict field-level validation and authorization.",
<<<<<<< HEAD
            references: vec!["OWASP API6: Mass Assignment", "CWE-915: Improperly Controlled Modification"],
=======
            first_step: Some("Attempt to include one of these sensitive fields in a mutation request to see if the server accepts and processes it.".into()),
            references: vec!["OWASP API6: Mass Assignment", "CWE-915: Improperly Controlled Modification"],
            status: FindingStatus::Inferred,
>>>>>>> update-research-refs
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

    let mut mutation_name_set: HashSet<String> = HashSet::new();
    for m in &mutation_fields {
        mutation_name_set.insert(m.name.to_lowercase());
    }

<<<<<<< HEAD
    let mut operation_gap_candidates: HashSet<String> = HashSet::new();
=======
    let mut operation_gap_possibilities: Vec<AffectedLocation> = Vec::new();
>>>>>>> update-research-refs
    for m in &mutation_fields {
        let lower = m.name.to_lowercase();
        if !lower.starts_with("create") {
            continue;
        }

        let resource = &m.name["create".len()..];
        if resource.is_empty() {
            continue;
        }

        let resource_lower = resource.to_lowercase();
        let update_lower = format!("update{}", resource_lower);
        let delete_lower = format!("delete{}", resource_lower);

<<<<<<< HEAD
        let mut missing_ops: Vec<String> = Vec::new();
        if !mutation_name_set.contains(&update_lower) {
            missing_ops.push(format!("update{}", resource));
        }
        if !mutation_name_set.contains(&delete_lower) {
            missing_ops.push(format!("delete{}", resource));
        }

        if !missing_ops.is_empty() {
            operation_gap_candidates.insert(format!(
                "Mutation.{} (missing: {})",
                m.name,
                missing_ops.join(", ")
            ));
        }
    }

    if !operation_gap_candidates.is_empty() {
=======
        let mut missing = false;
        if !mutation_name_set.contains(&update_lower) || !mutation_name_set.contains(&delete_lower) {
            missing = true;
        }

        if missing {
            operation_gap_possibilities.push(AffectedLocation::Field("Mutation".into(), m.name.clone()));
        }
    }

    if !operation_gap_possibilities.is_empty() {
>>>>>>> update-research-refs
        findings.push(Finding {
            id: "GQL-015",
            severity: Severity::Low,
            title: "Undocumented Operation Name Gaps",
            description: format!(
                "{} create* mutation(s) are missing expected update/delete counterparts. This can indicate hidden or inconsistent operation design worth deeper review.",
<<<<<<< HEAD
                operation_gap_candidates.len()
            ),
            affected: operation_gap_candidates.into_iter().take(30).collect(),
            remediation: "Review mutation lifecycle consistency (create/update/delete) per resource and ensure undocumented operations are not exposed elsewhere with weaker controls.",
            references: vec!["OWASP API9: Improper Inventory Management"],
=======
                operation_gap_possibilities.len()
            ),
            affected: operation_gap_possibilities.into_iter().take(30).collect(),
            remediation: "Review mutation lifecycle consistency (create/update/delete) per resource and ensure undocumented operations are not exposed elsewhere with weaker controls.",
            first_step: Some("Check if update/delete operations exist for these resources but are named differently or hidden.".into()),
            references: vec!["OWASP API9: Improper Inventory Management"],
            status: FindingStatus::Inferred,
>>>>>>> update-research-refs
            confidence: Confidence::Possible,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

<<<<<<< HEAD
    let mut leakage_candidates: Vec<String> = Vec::new();
=======
    let mut leakage_possibilities: Vec<AffectedLocation> = Vec::new();
>>>>>>> update-research-refs
    for t in &types {
        if t.kind.as_deref() != Some("OBJECT") {
            continue;
        }

        let type_name = t.name.as_deref().unwrap_or("");
        if type_name.is_empty() || ["Query", "Mutation", "Subscription"].contains(&type_name) {
            continue;
        }

<<<<<<< HEAD
        let mut user_fields: HashSet<String> = HashSet::new();
        let mut cross_fields: HashSet<String> = HashSet::new();
=======
        let mut user_fields = false;
        let mut cross_fields = false;
>>>>>>> update-research-refs

        if let Some(fields) = &t.fields {
            for f in fields {
                let lower = f.name.to_lowercase();
                if patterns
                    .user_scope_hints
                    .names
                    .iter()
                    .any(|h| lower.contains(&h.to_lowercase()))
                {
<<<<<<< HEAD
                    user_fields.insert(f.name.clone());
=======
                    user_fields = true;
>>>>>>> update-research-refs
                }
                if patterns
                    .cross_domain_hints
                    .names
                    .iter()
                    .any(|h| lower.contains(&h.to_lowercase()))
                {
<<<<<<< HEAD
                    cross_fields.insert(f.name.clone());
=======
                    cross_fields = true;
>>>>>>> update-research-refs
                }
            }
        }

<<<<<<< HEAD
        if !user_fields.is_empty() && !cross_fields.is_empty() {
            let mut u_vec: Vec<String> = user_fields.into_iter().collect();
            let mut c_vec: Vec<String> = cross_fields.into_iter().collect();
            u_vec.sort();
            c_vec.sort();
            leakage_candidates.push(format!(
                "{} (user-scoped: {}; cross-domain: {})",
                type_name,
                u_vec.join(", "),
                c_vec.join(", ")
            ));
        }
    }

    if !leakage_candidates.is_empty() {
=======
        if user_fields && cross_fields {
            leakage_possibilities.push(AffectedLocation::Type(type_name.into()));
        }
    }

    if !leakage_possibilities.is_empty() {
>>>>>>> update-research-refs
        findings.push(Finding {
            id: "GQL-016",
            severity: Severity::Medium,
            title: "Cross-Object Field Leakage Heuristic",
            description: format!(
                "{} object type(s) combine user-ownership fields with cross-domain/private resource fields, which can indicate over-broad object exposure.",
<<<<<<< HEAD
                leakage_candidates.len()
            ),
            affected: leakage_candidates.into_iter().take(25).collect(),
            remediation: "Split multi-domain objects into least-privilege response types and enforce field-level authorization per ownership domain before serialization.",
            references: vec!["OWASP API3: Excessive Data Exposure", "OWASP API1: Broken Object Level Authorization"],
=======
                leakage_possibilities.len()
            ),
            affected: leakage_possibilities.into_iter().take(25).collect(),
            remediation: "Split multi-domain objects into least-privilege response types and enforce field-level authorization per ownership domain before serialization.",
            first_step: Some("Review the fields on these types to see if they mix private user data with public or cross-domain data.".into()),
            references: vec!["OWASP API3: Excessive Data Exposure", "OWASP API1: Broken Object Level Authorization"],
            status: FindingStatus::Inferred,
>>>>>>> update-research-refs
            confidence: Confidence::Possible,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }
}
