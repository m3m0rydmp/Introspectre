use crate::utils::user_types;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, GqlType, Severity};
use std::collections::{HashMap, HashSet};

pub fn check_dos(schema: &GqlSchema, findings: &mut Vec<Finding>) {
    let types = user_types(schema);
    let type_map: HashMap<&str, &GqlType> = types
        .iter()
        .filter_map(|t| t.name.as_deref().map(|n| (n, *t)))
        .collect();

    // 1. Cycle Detection (three-color DFS: linear-time, canonical dedup, bounded).
    // The previous implementation restarted a full path-enumerating DFS from every
    // node, which could be exponential (and hang) on large or densely connected
    // schemas, and recorded each cycle under multiple rotations. This walks each
    // node once and records each cycle a single time.
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for t in &types {
        if let Some(name) = t.name.as_deref() {
            let mut refs = Vec::new();
            if let Some(fields) = &t.fields {
                for f in fields {
                    if let Some(ref tr) = f.field_type {
                        if let Some(ref_name) = tr.unwrap_type_name() {
                            // Anchor to the &str owned by the map so lifetimes hold.
                            if let Some((&k, _)) = type_map.get_key_value(ref_name.as_str()) {
                                refs.push(k);
                            }
                        }
                    }
                }
            }
            adj.insert(name, refs);
        }
    }

    const MAX_CYCLES: usize = 50;
    let mut cycles: HashSet<String> = HashSet::new();
    let mut color: HashMap<&str, u8> = HashMap::new();
    let mut stack: Vec<&str> = Vec::new();
    let mut node_names: Vec<&str> = adj.keys().cloned().collect();
    node_names.sort_unstable();
    for start_node in node_names {
        if cycles.len() >= MAX_CYCLES {
            break;
        }
        if color.get(start_node).copied().unwrap_or(0) == 0 {
            find_cycles_dfs(start_node, &adj, &mut color, &mut stack, &mut cycles, MAX_CYCLES);
        }
    }

    let circular_paths: Vec<AffectedLocation> =
        cycles.into_iter().map(AffectedLocation::Type).collect();

    if !circular_paths.is_empty() {
        findings.push(Finding {
            id: "recursive-type-refs",
            severity: Severity::High,
            title: "Circular / Recursive Type References (DoS Risk)",
            description: format!(
                "{} circular reference path(s) detected. Attackers can craft deeply nested queries that exhaust CPU and memory (unbounded query depth attack).",
                circular_paths.len()
            ),
            affected: circular_paths.into_iter().take(20).collect(),
            remediation: "Implement query depth limiting (recommended max: 7-10 levels). Use server-side complexity analysis and set strict execution timeouts.",
            first_step: Some("Construct a query that follows one of the circular paths to a depth of 10+ and monitor the server response time.".into()),
            references: vec!["CWE-400: Uncontrolled Resource Consumption", "OWASP API4: Lack of Resources"],
            status: FindingStatus::Inferred,
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

    // 2. Nested List Inflation Risk (Existing logic refined)
    let mut dos_list_inflation: Vec<AffectedLocation> = Vec::new();
    for t in &types {
        let type_name = t.name.as_deref().unwrap_or("?");
        if let Some(fields) = &t.fields {
            for f in fields {
                if let Some(ref tr) = f.field_type {
                    if tr.is_list() {
                        if let Some(inner_name) = tr.unwrap_type_name() {
                            let nested_list_count = schema
                                .fields_for_type(Some(&inner_name))
                                .iter()
                                .filter(|nf| {
                                    nf.field_type
                                        .as_ref()
                                        .map(|nt| nt.is_list())
                                        .unwrap_or(false)
                                })
                                .count();

                            if nested_list_count > 0 {
                                dos_list_inflation.push(AffectedLocation::Field(type_name.into(), f.name.clone()));
                            }
                        }
                    }
                }
            }
        }
    }

    if !dos_list_inflation.is_empty() {
        findings.push(Finding {
            id: "nested-list-inflation",
            severity: Severity::Medium,
            title: "Nested List Inflation Risk",
            description: format!(
                "{} list-returning field(s) fan out into additional list fields on related types. This enables exponential response growth from a single query.",
                dos_list_inflation.len()
            ),
            affected: dos_list_inflation.into_iter().take(20).collect(),
            remediation: "Implement strict pagination limits and query-cost analysis. Cap result sizes and enforce maximum complexity per request.",
            first_step: Some("Query a list field and its nested list sub-fields with large 'first' or 'limit' arguments to see if the server restricts the output.".into()),
            references: vec!["OWASP API4: Lack of Resources", "CWE-770: Allocation of Resources Without Limits"],
            status: FindingStatus::Inferred,
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

    // 3. Batch / List Query Abuse (Existing logic)
    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let query_fields = schema.fields_for_type(query_name);
    let list_queries: Vec<AffectedLocation> = query_fields
        .iter()
        .filter(|f| {
            let n = f.name.to_lowercase();
            n.starts_with("list")
                || n.starts_with("all")
                || n.starts_with("search")
                || n.starts_with("find")
                || f.field_type
                    .as_ref()
                    .map(|t| t.is_list())
                    .unwrap_or(false)
                || f.field_type
                    .as_ref()
                    .and_then(|t| t.unwrap_type_name())
                    .map(|n| n.contains("Connection") || n.contains("List"))
                    .unwrap_or(false)
        })
        .map(|f| AffectedLocation::Field("Query".into(), f.name.clone()))
        .collect();

    if list_queries.len() > 4 {
        findings.push(Finding {
            id: "bulk-query-surface",
            severity: Severity::Low,
            title: "Batch / List Query Abuse Surface",
            description: format!(
                "{} list or search queries detected. Attackers can send a single GraphQL request with many aliased list queries to enumerate data in bulk, bypassing REST-style per-endpoint rate limits.",
                list_queries.len()
            ),
            affected: list_queries.into_iter().take(15).collect(),
            remediation: "Implement complexity-aware rate limiting that accounts for GraphQL aliasing. Limit the number of aliases per request. Add pagination limits with enforced maximums.",
            first_step: Some("Try sending a single request with 5+ aliased calls to the same list query to see if the server processes all of them.".into()),
            references: vec!["CWE-770: Resource Exhaustion", "OWASP API4: Lack of Resources"],
            status: FindingStatus::Inferred,
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

    // 4. Unpaginated List Field (Existing logic)
    let mut unpaginated_lists: Vec<AffectedLocation> = Vec::new();
    for t in &types {
        let type_name = t.name.as_deref().unwrap_or("");
        if type_name.is_empty() {
            continue;
        }
        if let Some(fields) = &t.fields {
            for f in fields {
                if let Some(ref tr) = f.field_type {
                    if tr.is_list() {
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
                            unpaginated_lists.push(AffectedLocation::Field(type_name.into(), f.name.clone()));
                        }
                    }
                }
            }
        }
    }

    if !unpaginated_lists.is_empty() {
        findings.push(Finding {
            id: "unpaginated-list-field",
            severity: Severity::Medium,
            title: "Unpaginated List Field",
            description: format!(
                "{} field(s) return a list but lack common pagination arguments (first, limit, offset, etc.). This can lead to resource exhaustion if the underlying dataset is large.",
                unpaginated_lists.len()
            ),
            affected: unpaginated_lists.into_iter().take(20).collect(),
            remediation: "Enforce pagination on all list-returning fields. Use Cursor-based pagination (Relay) or Offset-based pagination with a strictly enforced maximum 'limit' (e.g. 100).",
            first_step: Some("Query one of the unpaginated lists and see if the server returns an unexpectedly large number of records.".into()),
            references: vec!["OWASP API4: Lack of Resources", "CWE-770: Allocation of Resources Without Limits"],
            status: FindingStatus::Inferred,
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }
}

fn find_cycles_dfs<'a>(
    node: &'a str,
    adj: &HashMap<&'a str, Vec<&'a str>>,
    color: &mut HashMap<&'a str, u8>, // 0 = unvisited, 1 = on stack, 2 = done
    stack: &mut Vec<&'a str>,
    cycles: &mut HashSet<String>,
    cap: usize,
) {
    color.insert(node, 1);
    stack.push(node);

    if let Some(neighbors) = adj.get(node) {
        for &nb in neighbors {
            if cycles.len() >= cap {
                break;
            }
            match color.get(nb).copied().unwrap_or(0) {
                1 => {
                    // Back-edge to a node still on the stack: reconstruct the cycle.
                    if let Some(pos) = stack.iter().position(|&x| x == nb) {
                        cycles.insert(canonical_cycle(&stack[pos..]));
                    }
                }
                0 => find_cycles_dfs(nb, adj, color, stack, cycles, cap),
                _ => {}
            }
        }
    }

    stack.pop();
    color.insert(node, 2);
}

/// Canonicalize a cycle so all rotations map to one key (A→B→A and B→A→B are the
/// same cycle), then render it as a readable closed path for display.
fn canonical_cycle(cycle: &[&str]) -> String {
    if cycle.is_empty() {
        return String::new();
    }
    let min_idx = cycle
        .iter()
        .enumerate()
        .min_by_key(|(_, &s)| s)
        .map(|(i, _)| i)
        .unwrap_or(0);
    let mut rotated: Vec<&str> = (0..cycle.len())
        .map(|k| cycle[(min_idx + k) % cycle.len()])
        .collect();
    rotated.push(rotated[0]); // close the loop for display
    rotated.join(" → ")
}
