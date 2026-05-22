<<<<<<< HEAD
use crate::analysis::utils::user_types;
use crate::types::{Confidence, EvidenceLevel, Finding, GqlSchema, GqlType, Severity};
=======
use crate::utils::user_types;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, GqlType, Severity};
>>>>>>> update-research-refs
use std::collections::{HashMap, HashSet};

pub fn check_dos(schema: &GqlSchema, findings: &mut Vec<Finding>) {
    let types = user_types(schema);
    let type_map: HashMap<&str, &GqlType> = types
        .iter()
        .filter_map(|t| t.name.as_deref().map(|n| (n, *t)))
        .collect();

<<<<<<< HEAD
    let mut circular_set: HashSet<String> = HashSet::new();
    for t in &types {
        let type_name = match t.name.as_deref() {
            Some(n) => n,
            None => continue,
        };
        if let Some(fields) = &t.fields {
            for f in fields {
                if let Some(ref tr) = f.field_type {
                    if let Some(ref_name) = tr.unwrap_type_name() {
                        if ref_name == type_name {
                            circular_set.insert(format!("{}.{} → {}", type_name, f.name, ref_name));
                        } else if let Some(other) = type_map.get(ref_name.as_str()) {
                            if let Some(other_fields) = &other.fields {
                                for of in other_fields {
                                    if let Some(ref otr) = of.field_type {
                                        if otr.unwrap_type_name().as_deref() == Some(type_name) {
                                            let mut pair = [type_name, ref_name.as_str()];
                                            pair.sort();
                                            circular_set.insert(format!(
                                                "{} ↔ {} (mutual recursion)",
                                                pair[0], pair[1]
                                            ));
                                        }
                                    }
                                }
=======
    // 1. Advanced Cycle Detection (Graph-Based DFS)
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for t in &types {
        if let Some(name) = t.name.as_deref() {
            let mut refs = Vec::new();
            if let Some(fields) = &t.fields {
                for f in fields {
                    if let Some(ref tr) = f.field_type {
                        if let Some(ref_name) = tr.unwrap_type_name() {
                            // Find the actual &str from the map to ensure it lives long enough
                            if let Some((&k, _)) = type_map.get_key_value(ref_name.as_str()) {
                                refs.push(k);
>>>>>>> update-research-refs
                            }
                        }
                    }
                }
            }
<<<<<<< HEAD
        }
    }

    if !circular_set.is_empty() {
=======
            adj.insert(name, refs);
        }
    }

    let mut circular_paths: Vec<AffectedLocation> = Vec::new();
    let type_names: Vec<&str> = adj.keys().cloned().collect();

    for start_node in type_names {
        let mut visited = HashSet::new();
        let mut path = Vec::new();
        let mut raw_paths = HashSet::new();
        find_cycles_dfs(start_node, &adj, &mut visited, &mut path, &mut raw_paths);
        for p in raw_paths {
            circular_paths.push(AffectedLocation::Type(p));
        }
    }

    if !circular_paths.is_empty() {
>>>>>>> update-research-refs
        findings.push(Finding {
            id: "GQL-003",
            severity: Severity::High,
            title: "Circular / Recursive Type References (DoS Risk)",
            description: format!(
<<<<<<< HEAD
                "{} circular or mutually-recursive type reference(s) found. Attackers can craft deeply nested queries that exhaust CPU and memory (unbounded query depth attack).",
                circular_set.len()
            ),
            affected: circular_set.into_iter().take(15).collect(),
            remediation: "Implement query depth limiting (recommended max: 7-10 levels). Use graphql-depth-limit, graphql-query-complexity, or built-in server options. Set a hard timeout on query execution.",
            references: vec!["CWE-400: Uncontrolled Resource Consumption", "OWASP API4: Lack of Resources"],
=======
                "{} circular reference path(s) detected. Attackers can craft deeply nested queries that exhaust CPU and memory (unbounded query depth attack).",
                circular_paths.len()
            ),
            affected: circular_paths.into_iter().take(20).collect(),
            remediation: "Implement query depth limiting (recommended max: 7-10 levels). Use server-side complexity analysis and set strict execution timeouts.",
            first_step: Some("Construct a query that follows one of the circular paths to a depth of 10+ and monitor the server response time.".into()),
            references: vec!["CWE-400: Uncontrolled Resource Consumption", "OWASP API4: Lack of Resources"],
            status: FindingStatus::Inferred,
>>>>>>> update-research-refs
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

<<<<<<< HEAD
    let mut dos_list_inflation: Vec<String> = Vec::new();
=======
    // 2. Nested List Inflation Risk (Existing logic refined)
    let mut dos_list_inflation: Vec<AffectedLocation> = Vec::new();
>>>>>>> update-research-refs
    for t in &types {
        let type_name = t.name.as_deref().unwrap_or("?");
        if let Some(fields) = &t.fields {
            for f in fields {
                if let Some(ref tr) = f.field_type {
                    let is_listish = tr.kind.as_deref() == Some("LIST")
                        || tr.kind.as_deref() == Some("NON_NULL");
                    if is_listish {
                        if let Some(inner_name) = tr.unwrap_type_name() {
                            let nested_list_count = schema
                                .fields_for_type(Some(&inner_name))
                                .iter()
                                .filter(|nf| {
                                    nf.field_type
                                        .as_ref()
                                        .map(|nt| nt.kind.as_deref() == Some("LIST"))
                                        .unwrap_or(false)
                                })
                                .count();

                            if nested_list_count > 0 {
<<<<<<< HEAD
                                dos_list_inflation.push(format!(
                                    "{}.{} returns {}, with {} nested list field(s)",
                                    type_name, f.name, inner_name, nested_list_count
                                ));
=======
                                dos_list_inflation.push(AffectedLocation::Field(type_name.into(), f.name.clone()));
>>>>>>> update-research-refs
                            }
                        }
                    }
                }
            }
        }
    }

    if !dos_list_inflation.is_empty() {
        findings.push(Finding {
            id: "GQL-DOS-001",
            severity: Severity::Medium,
            title: "Nested List Inflation Risk",
            description: format!(
                "{} list-returning field(s) fan out into additional list fields on related types. This enables exponential response growth from a single query.",
                dos_list_inflation.len()
            ),
            affected: dos_list_inflation.into_iter().take(20).collect(),
            remediation: "Implement strict pagination limits and query-cost analysis. Cap result sizes and enforce maximum complexity per request.",
<<<<<<< HEAD
            references: vec!["OWASP API4: Lack of Resources", "CWE-770: Allocation of Resources Without Limits"],
=======
            first_step: Some("Query a list field and its nested list sub-fields with large 'first' or 'limit' arguments to see if the server restricts the output.".into()),
            references: vec!["OWASP API4: Lack of Resources", "CWE-770: Allocation of Resources Without Limits"],
            status: FindingStatus::Inferred,
>>>>>>> update-research-refs
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

<<<<<<< HEAD
    let mut self_recursive_fields: Vec<String> = Vec::new();
    for t in &types {
        let type_name = t.name.as_deref().unwrap_or("");
        if type_name.is_empty() {
            continue;
        }
        if let Some(fields) = &t.fields {
            for f in fields {
                if let Some(ref tr) = f.field_type {
                    if tr.unwrap_type_name().as_deref() == Some(type_name) {
                        self_recursive_fields.push(format!("{}.{}", type_name, f.name));
                    }
                }
            }
        }
    }

    if !self_recursive_fields.is_empty() {
        findings.push(Finding {
            id: "GQL-DOS-002",
            severity: Severity::High,
            title: "Unbounded Recursive Relationship",
            description: format!(
                "{} self-referencing field(s) detected. Without max depth checks, attackers can submit deeply nested queries that exhaust CPU and memory.",
                self_recursive_fields.len()
            ),
            affected: self_recursive_fields.into_iter().take(20).collect(),
            remediation: "Enforce a max query depth rule (commonly 5-10), apply complexity scoring, and enforce execution timeouts.",
            references: vec!["CWE-400: Uncontrolled Resource Consumption", "OWASP API4: Lack of Resources"],
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let query_fields = schema.fields_for_type(query_name);
    let list_queries: Vec<String> = query_fields
=======
    // 3. Batch / List Query Abuse (Existing logic)
    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let query_fields = schema.fields_for_type(query_name);
    let list_queries: Vec<AffectedLocation> = query_fields
>>>>>>> update-research-refs
        .iter()
        .filter(|f| {
            let n = f.name.to_lowercase();
            n.starts_with("list")
                || n.starts_with("all")
                || n.starts_with("search")
                || n.starts_with("find")
                || n.ends_with('s')
                || f.field_type
                    .as_ref()
                    .and_then(|t| t.unwrap_type_name())
                    .map(|n| n.contains("Connection") || n.contains("List"))
                    .unwrap_or(false)
        })
<<<<<<< HEAD
        .map(|f| format!("Query.{}", f.name))
=======
        .map(|f| AffectedLocation::Field("Query".into(), f.name.clone()))
>>>>>>> update-research-refs
        .collect();

    if list_queries.len() > 4 {
        findings.push(Finding {
            id: "GQL-010",
            severity: Severity::Low,
            title: "Batch / List Query Abuse Surface",
            description: format!(
                "{} list or search queries detected. Attackers can send a single GraphQL request with many aliased list queries to enumerate data in bulk, bypassing REST-style per-endpoint rate limits.",
                list_queries.len()
            ),
            affected: list_queries.into_iter().take(15).collect(),
            remediation: "Implement complexity-aware rate limiting that accounts for GraphQL aliasing. Limit the number of aliases per request. Add pagination limits with enforced maximums.",
<<<<<<< HEAD
            references: vec!["CWE-770: Resource Exhaustion", "OWASP API4: Lack of Resources"],
=======
            first_step: Some("Try sending a single request with 5+ aliased calls to the same list query to see if the server processes all of them.".into()),
            references: vec!["CWE-770: Resource Exhaustion", "OWASP API4: Lack of Resources"],
            status: FindingStatus::Inferred,
>>>>>>> update-research-refs
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

<<<<<<< HEAD
    let mut unpaginated_lists: Vec<String> = Vec::new();
=======
    // 4. Unpaginated List Field (Existing logic)
    let mut unpaginated_lists: Vec<AffectedLocation> = Vec::new();
>>>>>>> update-research-refs
    for t in &types {
        let type_name = t.name.as_deref().unwrap_or("");
        if type_name.is_empty() {
            continue;
        }
        if let Some(fields) = &t.fields {
            for f in fields {
                if let Some(ref tr) = f.field_type {
                    if tr.kind.as_deref() == Some("LIST") {
                        let mut has_pagination = false;
                        if let Some(args) = &f.args {
                            for arg in args {
                                let arg_lower = arg.name.to_lowercase();
                                if [
                                    "first", "last", "limit", "offset", "after", "before", "page",
                                    "size",
                                ]
                                .iter()
                                .any(|&p| arg_lower.contains(p))
                                {
                                    has_pagination = true;
                                    break;
                                }
                            }
                        }
                        if !has_pagination {
<<<<<<< HEAD
                            unpaginated_lists.push(format!("{}.{}", type_name, f.name));
=======
                            unpaginated_lists.push(AffectedLocation::Field(type_name.into(), f.name.clone()));
>>>>>>> update-research-refs
                        }
                    }
                }
            }
        }
    }

    if !unpaginated_lists.is_empty() {
        findings.push(Finding {
            id: "GQL-DOS-003",
            severity: Severity::Medium,
            title: "Unpaginated List Field",
            description: format!(
                "{} field(s) return a list but lack common pagination arguments (first, limit, offset, etc.). This can lead to resource exhaustion if the underlying dataset is large.",
                unpaginated_lists.len()
            ),
            affected: unpaginated_lists.into_iter().take(20).collect(),
            remediation: "Enforce pagination on all list-returning fields. Use Cursor-based pagination (Relay) or Offset-based pagination with a strictly enforced maximum 'limit' (e.g. 100).",
<<<<<<< HEAD
            references: vec!["OWASP API4: Lack of Resources", "CWE-770: Allocation of Resources Without Limits"],
=======
            first_step: Some("Query one of the unpaginated lists and see if the server returns an unexpectedly large number of records.".into()),
            references: vec!["OWASP API4: Lack of Resources", "CWE-770: Allocation of Resources Without Limits"],
            status: FindingStatus::Inferred,
>>>>>>> update-research-refs
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }
}
<<<<<<< HEAD
=======

fn find_cycles_dfs<'a>(
    node: &'a str,
    adj: &HashMap<&'a str, Vec<&'a str>>,
    visited: &mut HashSet<&'a str>,
    path: &mut Vec<&'a str>,
    circular_paths: &mut HashSet<String>,
) {
    if let Some(idx) = path.iter().position(|&x| x == node) {
        // Cycle detected
        let mut cycle: Vec<&str> = path[idx..].to_vec();
        cycle.push(node);
        
        // Canonicalize cycle string (A -> B -> A and B -> A -> B should be same)
        // For simplicity, we just sort them if we wanted pure set, but path order matters.
        // We'll just store the path as a string.
        let path_str = cycle.join(" → ");
        circular_paths.insert(path_str);
        return;
    }

    if visited.contains(node) {
        return;
    }

    path.push(node);
    if let Some(neighbors) = adj.get(node) {
        for &neighbor in neighbors {
            find_cycles_dfs(neighbor, adj, visited, path, circular_paths);
        }
    }
    path.pop();
    visited.insert(node);
}
>>>>>>> update-research-refs
