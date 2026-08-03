//! Shared target scoping, risk-ranking, and request budgeting for the active audit.
//!
//! On a large schema the fan-out probes (`unauth`, `mutation_privesc`, `sqli`, `xss`,
//! `command_injection`) would otherwise enumerate their entire target set — potentially
//! tens of thousands of requests — with no upper bound. Every one of those probes now
//! passes its freshly built target list through [`scope_targets`], which:
//!
//!   1. filters to a `--focus`ed subset of types/fields (if any),
//!   2. ranks the survivors by the severity of any passive finding that already touched
//!      them (so the most interesting fields are probed first), and
//!   3. truncates to a per-probe `--max-targets` cap.
//!
//! A single shared [`RequestBudget`] additionally caps the *total* number of requests the
//! high-fan-out probes may send (`--max-requests`), so a run can be bounded even when the
//! per-probe caps individually look small.

use crate::types::{AffectedLocation, Finding, GqlSchema, GqlTypeRef, Severity};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Scope/limit controls resolved once from the CLI + config and applied uniformly to
/// every fan-out probe's target list.
#[derive(Debug, Clone, Default)]
pub struct AuditScope {
    /// Lowercased focus entries, each either a bare type (`"user"`, `"query"`) or a
    /// fully-qualified `"type.field"` (`"query.user"`). Empty = probe everything.
    pub focus: Vec<String>,
    /// Per-probe cap on the number of targets kept after ranking. `None` = unlimited.
    pub max_targets: Option<usize>,
}

impl AuditScope {
    pub fn new(focus: &[String], max_targets: Option<usize>) -> Self {
        let focus = focus
            .iter()
            .map(|f| f.trim().to_lowercase())
            .filter(|f| !f.is_empty())
            .collect();
        Self { focus, max_targets }
    }

    /// Whether a `Type`/`Type.field` target passes the `--focus` filter. A focus entry
    /// matches when it equals the root type (`"query"` / `"mutation"` — keeps that whole
    /// root), equals the qualified `"type.field"`, or appears as a substring of the field
    /// name (`"user"` keeps `Query.user`, `Mutation.updateUser`, …).
    pub fn matches_focus(&self, type_name: &str, field_name: &str) -> bool {
        if self.focus.is_empty() {
            return true;
        }
        let ty = type_name.to_lowercase();
        let field = field_name.to_lowercase();
        let full = format!("{}.{}", ty, field);
        self.focus
            .iter()
            .any(|f| *f == ty || *f == full || field.contains(f.as_str()))
    }
}

/// The three run-wide scoping controls bundled together, so each fan-out probe takes a
/// single extra parameter instead of three. Built once in `run_audit` and shared by `&`.
pub struct ScopeCtx<'a> {
    pub sev_index: &'a HashMap<String, Severity>,
    pub scope: &'a AuditScope,
    pub budget: &'a RequestBudget,
}

/// Build a `"Type.field"` → max-[`Severity`] index from the passive findings, so active
/// probes can rank their targets by prior evidence instead of a flat schema order.
pub fn severity_index(passive: &[Finding]) -> HashMap<String, Severity> {
    let mut idx: HashMap<String, Severity> = HashMap::new();
    for f in passive {
        for loc in &f.affected {
            let key = match loc {
                AffectedLocation::Type(t) => t.clone(),
                AffectedLocation::Field(t, fi) => format!("{}.{}", t, fi),
                AffectedLocation::Argument(t, fi, _) => format!("{}.{}", t, fi),
            };
            idx.entry(key)
                .and_modify(|s| {
                    if f.severity > *s {
                        *s = f.severity.clone();
                    }
                })
                .or_insert_with(|| f.severity.clone());
        }
    }
    idx
}

/// Rank score for a `Type`/`Type.field` target: the higher of a full-field match and a
/// bare-type match in the passive severity index. Untouched targets score 0.
fn rank_score(sev_index: &HashMap<String, Severity>, type_name: &str, field_name: &str) -> u8 {
    let sev_rank = |s: &Severity| match s {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
    };
    let full = format!("{}.{}", type_name, field_name);
    let a = sev_index.get(&full).map(sev_rank).unwrap_or(0);
    let b = sev_index.get(type_name).map(sev_rank).unwrap_or(0);
    a.max(b)
}

/// Command/injection keyword sets used to prioritize likely sinks — see [`name_affinity`].
/// A sink whose field/arg/path name matches these ranks ahead of passively-flagged but
/// non-vulnerable fields, so a budget-capped run still reaches it.
pub const CMDI_KEYWORDS: &[&str] = &[
    "cmd", "command", "exec", "run", "shell", "ping", "host", "hostname", "debug", "diag",
    "diagnostic", "system", "os", "proc", "process", "spawn", "subprocess", "bash", "sh",
];
pub const SQLI_KEYWORDS: &[&str] = &[
    "filter", "query", "search", "where", "order", "sort", "id", "name", "email", "user", "login",
];
pub const XSS_KEYWORDS: &[&str] = &[
    "html", "content", "body", "message", "comment", "title", "description", "bio", "name", "text",
];

/// Count how many `keywords` appear (as lowercase substrings) in `haystack` — a cheap
/// name-based affinity signal for how likely a target is to be a real sink for a given probe.
pub fn name_affinity(haystack: &str, keywords: &[&str]) -> i32 {
    let hay = haystack.to_lowercase();
    keywords.iter().filter(|k| hay.contains(*k)).count() as i32
}

/// Apply `--focus`, passive-severity ranking, and the per-probe `--max-targets` cap to a
/// probe's target list. `key` extracts `(type_name, field_name)` from each target so the
/// same routine works across the probes' differently-shaped target tuples.
pub fn scope_targets<T>(
    targets: Vec<T>,
    sev_index: &HashMap<String, Severity>,
    scope: &AuditScope,
    key: impl Fn(&T) -> (String, String),
) -> Vec<T> {
    scope_targets_prioritized(targets, sev_index, scope, key, |_| 0)
}

/// Like [`scope_targets`], but ranks by `(priority desc, then passive-severity desc)`. Injection
/// probes pass a name-affinity `priority` so likely sinks are probed first even under a tight
/// `--max-requests`/`--max-targets` budget (which otherwise starves an obvious sink that no passive
/// finding happened to touch).
pub fn scope_targets_prioritized<T>(
    targets: Vec<T>,
    sev_index: &HashMap<String, Severity>,
    scope: &AuditScope,
    key: impl Fn(&T) -> (String, String),
    priority: impl Fn(&T) -> i32,
) -> Vec<T> {
    // 1. Focus filter.
    let mut kept: Vec<T> = targets
        .into_iter()
        .filter(|t| {
            let (ty, fi) = key(t);
            scope.matches_focus(&ty, &fi)
        })
        .collect();

    // 2. Rank by name affinity first, then passive severity, both descending. Stable sort keeps
    //    the original schema order among equally-ranked targets.
    kept.sort_by(|a, b| {
        let (at, af) = key(a);
        let (bt, bf) = key(b);
        priority(b).cmp(&priority(a)).then_with(|| {
            rank_score(sev_index, &bt, &bf).cmp(&rank_score(sev_index, &at, &af))
        })
    });

    // 3. Per-probe cap.
    if let Some(max) = scope.max_targets {
        if max < kept.len() {
            kept.truncate(max);
        }
    }

    kept
}

/// A shared, run-wide cap on the number of requests the high-fan-out probes may send.
/// `--max-requests 0` (or unset) means unlimited. The audit runs its probes sequentially,
/// so a plain load/store under `Relaxed` ordering is sufficient; the atomic is only for
/// `Sync` so the budget can be shared behind `&`.
#[derive(Debug)]
pub struct RequestBudget {
    remaining: AtomicUsize,
    unlimited: bool,
    hit: AtomicBool,
    /// Optional per-probe fair-share cap (`usize::MAX` = none). Prevents an early fan-out probe
    /// (e.g. `sql-injection`) from draining the whole global budget before later probes
    /// (e.g. `os-command-injection`) get a turn. Set via [`RequestBudget::start_probe`].
    probe_cap: AtomicUsize,
    probe_used: AtomicUsize,
}

impl RequestBudget {
    pub fn new(max: Option<usize>) -> Self {
        match max {
            None | Some(0) => Self {
                remaining: AtomicUsize::new(0),
                unlimited: true,
                hit: AtomicBool::new(false),
                probe_cap: AtomicUsize::new(usize::MAX),
                probe_used: AtomicUsize::new(0),
            },
            Some(n) => Self {
                remaining: AtomicUsize::new(n),
                unlimited: false,
                hit: AtomicBool::new(false),
                probe_cap: AtomicUsize::new(usize::MAX),
                probe_used: AtomicUsize::new(0),
            },
        }
    }

    /// Begin a fan-out probe with an optional fair-share request cap. Resets the per-probe
    /// counter. `None` clears the cap (probe limited only by the global budget).
    pub fn start_probe(&self, cap: Option<usize>) {
        self.probe_cap.store(cap.unwrap_or(usize::MAX), Ordering::Relaxed);
        self.probe_used.store(0, Ordering::Relaxed);
    }

    /// Claim one request slot. Returns `false` (without consuming) once the global budget is
    /// spent or the current probe's fair share is used up, signalling the caller to stop and
    /// record what it skipped. (Sequential audit → `Relaxed` is sufficient.)
    pub fn try_consume(&self) -> bool {
        // Per-probe fair-share cap: reaching it stops this probe but is not a global "hit".
        let cap = self.probe_cap.load(Ordering::Relaxed);
        if cap != usize::MAX && self.probe_used.load(Ordering::Relaxed) >= cap {
            return false;
        }

        if !self.unlimited {
            let cur = self.remaining.load(Ordering::Relaxed);
            if cur == 0 {
                self.hit.store(true, Ordering::Relaxed);
                return false;
            }
            self.remaining.store(cur - 1, Ordering::Relaxed);
        }
        if cap != usize::MAX {
            self.probe_used
                .store(self.probe_used.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
        }
        true
    }

    /// Whether the budget was ever reached during the run (some probe stopped early).
    pub fn was_hit(&self) -> bool {
        self.hit.load(Ordering::Relaxed)
    }
}

/// Leaf scalar types the `sqli` probe treats as injectable (numeric args can carry
/// SQL/NoSQL operators too).
pub const SQLI_LEAF_SCALARS: &[&str] = &["String", "ID", "Int", "Float", "Long"];
/// Leaf scalar types the `command_injection` probe treats as injectable (shell vectors
/// are string-typed).
pub const CMDI_LEAF_SCALARS: &[&str] = &["String", "ID"];

/// Maximum input-object nesting the injection path walk descends before giving up — bounds
/// both the recursion and the combinatorial path count on deeply nested input graphs.
const MAX_INJECT_DEPTH: usize = 6;

/// Recursively collect the injectable argument paths reachable from an argument,
/// descending into `INPUT_OBJECT` fields and keeping leaves whose type is in
/// `leaf_scalars`. Shared by the `sqli` and `command_injection` probes (and the dry-run
/// estimator) so the target math stays identical across them.
///
/// Recursive/self-referential input objects (common in filter inputs, e.g. `AND: [Self]`)
/// are guarded against with a visited-type set on the current path plus a depth cap, so a
/// cyclic schema can never blow the stack.
pub fn find_injectable_paths(
    schema: &GqlSchema,
    arg_type: &GqlTypeRef,
    current_path: &str,
    leaf_scalars: &[&str],
) -> Vec<String> {
    let mut visited = Vec::new();
    walk_injectable_paths(schema, arg_type, current_path, leaf_scalars, &mut visited, 0)
}

fn walk_injectable_paths(
    schema: &GqlSchema,
    arg_type: &GqlTypeRef,
    current_path: &str,
    leaf_scalars: &[&str],
    visited: &mut Vec<String>,
    depth: usize,
) -> Vec<String> {
    let mut paths = Vec::new();
    if depth > MAX_INJECT_DEPTH {
        return paths;
    }
    let type_name = arg_type.unwrap_type_name();

    if let Some(tn) = type_name {
        if leaf_scalars.contains(&tn.as_str()) {
            paths.push(current_path.to_string());
        } else if let Some(gql_type) = schema.find_type(&tn) {
            if gql_type.kind.as_deref() == Some("INPUT_OBJECT") {
                // Cycle guard: don't re-enter an input type already on this path.
                if visited.iter().any(|v| v == &tn) {
                    return paths;
                }
                visited.push(tn.clone());
                if let Some(fields) = &gql_type.input_fields {
                    for f in fields {
                        if let Some(ft) = &f.field_type {
                            let sub_path = format!("{}.{}", current_path, f.name);
                            paths.extend(walk_injectable_paths(
                                schema, ft, &sub_path, leaf_scalars, visited, depth + 1,
                            ));
                        }
                    }
                }
                visited.pop();
            }
        }
    }
    paths
}

/// Wrap a scalar `value` in the nested object structure described by a dotted `full_path`
/// (e.g. `"input.filter.name"`), relative to the top-level `arg_name`. Shared by `sqli`
/// and `command_injection`.
pub fn build_nested_value(full_path: &str, arg_name: &str, value: serde_json::Value) -> serde_json::Value {
    let relative_path = if full_path.starts_with(arg_name) {
        if full_path.len() > arg_name.len() {
            &full_path[arg_name.len() + 1..]
        } else {
            ""
        }
    } else {
        full_path
    };

    if relative_path.is_empty() {
        return value;
    }

    let parts: Vec<&str> = relative_path.split('.').collect();
    let mut current = value;

    for &part in parts.iter().rev() {
        let mut map = serde_json::Map::new();
        map.insert(part.to_string(), current);
        current = serde_json::Value::Object(map);
    }

    current
}

/// The display names of the two probeable root types (`"Query"`, `"Mutation"`), matching
/// how the fan-out probes key their targets for focus/ranking.
fn root_names(schema: &GqlSchema) -> Vec<String> {
    let mut v = Vec::new();
    if let Some(q) = &schema.query_type {
        v.push(q.name.clone());
    }
    if let Some(m) = &schema.mutation_type {
        v.push(m.name.clone());
    }
    v
}

/// Number of root query+mutation fields the `unauth` probe would test under `scope` (one
/// request each, or one per `batch_size` when batched).
pub fn count_root_fields(schema: &GqlSchema, scope: &AuditScope) -> usize {
    let mut n = 0;
    for root in root_names(schema) {
        for field in schema.fields_for_type(Some(root.as_str())) {
            if scope.matches_focus(&root, &field.name) {
                n += 1;
            }
        }
    }
    n
}

/// Number of injectable argument paths under `scope` — the target count for the `sqli` /
/// `command_injection` probes (pass the probe's leaf-scalar set).
pub fn count_injection_targets(schema: &GqlSchema, leaf_scalars: &[&str], scope: &AuditScope) -> usize {
    let mut n = 0;
    for root in root_names(schema) {
        for field in schema.fields_for_type(Some(root.as_str())) {
            if !scope.matches_focus(&root, &field.name) {
                continue;
            }
            if let Some(args) = &field.args {
                for arg in args {
                    if let Some(at) = &arg.arg_type {
                        n += find_injectable_paths(schema, at, &arg.name, leaf_scalars).len();
                    }
                }
            }
        }
    }
    n
}

/// Privilege-escalation patterns the `mutation_privesc` probe matches against argument /
/// input-field names.
pub const PRIVESC_PATTERNS: &[&str] = &[
    "role", "admin", "privilege", "permission", "isadmin", "is_admin", "superuser",
    "super_user", "rank", "level", "access", "staff", "owner",
];

/// Number of mutation fields under `scope` that expose at least one privilege-looking
/// argument or input-object field — the `mutation_privesc` probe sends at most one request
/// per such field (it breaks after the first accepted arg).
pub fn count_privesc_targets(schema: &GqlSchema, scope: &AuditScope) -> usize {
    let Some(m) = schema.mutation_type.as_ref().map(|m| m.name.clone()) else {
        return 0;
    };
    let matches = |name: &str| {
        let lower = name.to_lowercase();
        PRIVESC_PATTERNS.iter().any(|p| lower.contains(p))
    };
    let mut n = 0;
    for field in schema.fields_for_type(Some(m.as_str())) {
        if !scope.matches_focus(&m, &field.name) {
            continue;
        }
        let Some(args) = &field.args else { continue };
        let hit = args.iter().any(|arg| {
            if matches(&arg.name) {
                return true;
            }
            if let Some(tn) = arg.arg_type.as_ref().and_then(|t| t.unwrap_type_name()) {
                if let Some(it) = schema.find_type(&tn) {
                    if let Some(fields) = &it.input_fields {
                        return fields.iter().any(|f| matches(&f.name));
                    }
                }
            }
            false
        });
        if hit {
            n += 1;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn focus_matching() {
        let s = AuditScope::new(&["query.user".to_string()], None);
        assert!(s.matches_focus("Query", "user"), "qualified should match");
        assert!(!s.matches_focus("Query", "team"), "different field should not match");

        let bare = AuditScope::new(&["user".to_string()], None);
        assert!(bare.matches_focus("Query", "user"), "substring exact");
        assert!(bare.matches_focus("Mutation", "updateUser"), "substring in field");

        let root = AuditScope::new(&["mutation".to_string()], None);
        assert!(root.matches_focus("Mutation", "anything"), "whole-root match");
        assert!(!root.matches_focus("Query", "anything"), "other root excluded");

        let empty = AuditScope::new(&[], None);
        assert!(empty.matches_focus("Query", "x"), "empty focus matches all");
    }
}

/// Number of scalar root arguments under `scope` — the `xss` probe's target count.
pub fn count_scalar_arg_targets(schema: &GqlSchema, scope: &AuditScope) -> usize {
    let scalars = ["String", "Int", "Float", "Boolean", "ID"];
    let mut n = 0;
    for root in root_names(schema) {
        for field in schema.fields_for_type(Some(root.as_str())) {
            if !scope.matches_focus(&root, &field.name) {
                continue;
            }
            if let Some(args) = &field.args {
                for arg in args {
                    if let Some(tn) = arg.arg_type.as_ref().and_then(|t| t.unwrap_type_name()) {
                        if scalars.contains(&tn.as_str()) {
                            n += 1;
                        }
                    }
                }
            }
        }
    }
    n
}
