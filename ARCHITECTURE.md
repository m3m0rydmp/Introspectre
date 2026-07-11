# Introspectre: Technical Architecture

This document describes Introspectre's internal design: how it models a GraphQL schema, how the passive and active phases fit together, and how the visual report is built. For a list of what the tool does, see the [README](./README.md#key-features).

## 1. The Core Engine Loop

Introspectre moves through a layered pipeline, from safe observation to active probing:

1. **Reconnaissance (passive)**: retrieve the schema — via live introspection, a local JSON file, or blind discovery — and parse it into an in-memory graph.
2. **Static analysis (heuristic)**: walk the graph looking for structural risk (circular references, exposed sensitive fields, missing auth markers, mass-assignment-prone inputs) without sending a single request to the target.
3. **Active probing (opt-in)**: only after the schema is mapped does Introspectre send active payloads, using values drawn from the Seed Vault so probes are shaped like real data rather than generic fuzz strings. This phase runs under `audit`, or under `scan` when `--static-only false` is passed.

`scan` is passive-only by default; the transition into phase 3 always requires an explicit flag or a dedicated `audit` invocation — the tool never sends offensive payloads implicitly.

---

## 2. Graph-Centric Schema Model

Introspectre represents a GraphQL schema as a **field-centric weighted directed multigraph** rather than a flat endpoint list:

* **Nodes** — GraphQL fields (e.g., `Query.user`, `Mutation.registerUser`), not types. Fields are the actual unit of attack surface in GraphQL.
* **Edges** — traversals from a field to the fields of its return type.
* **Weights** — an estimated computational cost per field (scalars are cheap, objects and lists are progressively more expensive), used to model resource exhaustion.

This model supports two structural analyses used throughout the tool:

* **Optimal pathfinding**: computing the least-cost (or, for the report's "trace to root" action, the actual) path from an entry point to any field, so a researcher can see exactly how to reach a sensitive node.
* **Complexity prediction**: walking weighted distances from the root to flag which query paths are disproportionately expensive, informing which paths get prioritized for DoS-related checks.

Circular type relationships (e.g., `User -> Post -> User`) are detected as cycles in this graph — the same structure that enables unbounded query depth is what the graph traversal flags.

---

## 3. Passive Analysis + Active Audit Pipeline

The static analyzer and the active prober share the same schema graph but operate independently:

* **Static analyzer** (`src/analysis/`) walks type and field metadata offline: naming heuristics for sensitive fields, presence/absence of configured auth directives, deprecated-field usage, and recursive descent into `INPUT_OBJECT` structures to surface mass-assignment candidates several levels deep.
* **Active prober** (`src/audit/probes/`) is a set of independent probe modules (injection, IDOR, SSRF, DoS, fingerprinting, etc.) that each consume the schema graph plus the Seed Vault and return a common `Finding` structure — the report layer doesn't need to know which probe produced a finding.
* **Seed Vault**: when traffic logs (HAR/Burp XML) or a `--seeds` file are supplied, Introspectre extracts realistic values (UUIDs, emails, IDs) and persists them locally (SQLite). Probes query the vault before falling back to generic synthesized values, which matters because many APIs reject obviously fake input at the validation layer before it ever reaches vulnerable logic.
* **Throttling**: request pacing is either a fixed `--rate-limit-ms` delay or, with `--dynamic-throttling`, adjusted continuously based on observed server latency, so active runs stay under the radar of naive rate limiting and don't degrade target availability.

---

## 4. How Attacks Reach a GraphQL Field

In a classic web app, payloads ride in URL parameters, form fields, headers, or cookies. GraphQL usually exposes a single `POST /graphql` endpoint that speaks only JSON, so every payload instead travels inside a **field argument** of an operation. Two properties make testing this different from a web app, and Introspectre's probes are built around both.

**Two delivery vectors — inline vs. variables.** The same argument value can be baked literally into the query text, or bound through a typed GraphQL variable. A filter that sanitizes one path frequently misses the other, so the injection probes send both (reported as `sql-injection-inline` vs `sql-injection`):

```graphql
# Inline — value is part of the query string
query { user(username: "admin' OR '1'='1") { id } }

# Variable — value is carried in a separate JSON map
query ($u: String!) { user(username: $u) { id } }
# variables: { "u": "admin' OR '1'='1" }
```

**Nested input objects.** Arguments are often `INPUT_OBJECT`s whose own fields — sometimes several levels deep — are the real injection or mass-assignment points. The prober recurses into these input trees rather than only testing top-level scalar arguments:

```graphql
mutation { updateUser(input: { profile: { bio: "<payload here>" } }) { id } }
```

With that framing, each class is delivered as follows:

* **SQL / NoSQL injection** — a string argument the resolver forwards into a backend query. SQLi uses quote-breaking / `UNION` / boolean strings (`x' OR 1=1-- -`); NoSQL uses operator objects (a variable whose value is `{"$ne": null}` or `{"$regex": "…"}`). Confirmation is by database error signatures (e.g. `pymysql.err`), boolean/response differences, or a reflected marker.
* **OS command injection** — a string argument that reaches a shell or `subprocess` call. There is no visible command output, so Introspectre uses **time-based** payloads and measures the response delay:

  ```graphql
  query { systemDiagnostics(arg: "127.0.0.1; sleep 5") { output } }
  ```
* **SSTI (template injection)** — a string argument rendered by a server-side template engine; a math payload such as `{{7*7}}` or `${7*7}` that returns `49` confirms evaluation.
* **Cross-Site Scripting — stored, not reflected.** This is the biggest departure from web-app XSS. A GraphQL endpoint returns `application/json`, so an HTML/JS payload in the *response* is inert. The realistic path is **stored** XSS: a mutation writes an HTML payload into a field (`createPaste(content: "<script>…</script>")`) that a *downstream* web client later renders unescaped. Introspectre therefore only reports XSS when the reflection lands in an actual **HTML response context**, not when a payload is merely echoed inside a JSON error — which avoids a very common false positive.
* **CSRF** — GraphQL is CSRF-resistant by default: a mutation needs `POST` with `Content-Type: application/json`, which is not a browser "simple request" and triggers a CORS preflight a cross-site page cannot satisfy. It becomes exploitable only when the server *also* honours a state-changing operation over a **simple request** — a `GET` with `?query=mutation{…}`, or a `POST` with `application/x-www-form-urlencoded`. Those can be fired by a plain cross-origin `<form>` or `<img>`. The probes (`csrf-get-method`, `csrf-form-post`) test exactly whether those two shapes are accepted; the "payload" is the mutation itself, smuggled through a method the browser will send cross-site.
* **SSRF** — a URL / host / port argument that the resolver fetches server-side. The probe supplies internal targets and watches for cloud-metadata keywords or a timing signal:

  ```graphql
  mutation { importPaste(host: "169.254.169.254", path: "/latest/meta-data/") { result } }
  ```
* **IDOR / BOLA** — not an injected string at all: the "payload" is simply a *different valid identifier* in an argument (`paste(id: 2)` when `2` is not yours). Introspectre establishes a baseline with an owned id, swaps in other ids, and compares the responses.
* **Mass assignment / privilege escalation** — a privileged input field (`role`, `isAdmin`) added to a mutation's input object even though no UI exposes it; a server that binds the whole object accepts it silently.

---

## 5. Visual Reporting

The HTML report (built on Cytoscape.js) renders the same field-centric multigraph interactively, and is fully self-contained — the report's JS dependencies are embedded at build time, so the generated file works offline with no external CDN request.

* **Isolate mode**: given a selected node, the report computes the upstream path back to the root and the full downstream closure of reachable terminal fields, hiding everything else.
* **Embedded proofs**: findings surfaced during an active run are attached to their corresponding graph nodes, each with a ready-to-run reproduction query and the payload that triggered it inlined — no separate cross-referencing between report and terminal output required.

---

## 6. Design Principles

* **Asynchronous core**: built on `tokio` and `reqwest` for parallelized, non-blocking network I/O during active runs.
* **Modular layout**: the codebase separates concerns strictly —
  * `src/analysis/` — offline, passive heuristics only; no network access.
  * `src/audit/probes/` — active, network-based probe modules, each independent and individually addable.
* **Persistent state**: `rusqlite` backs local persistence (`introspectre.db`) for the Seed Vault and session state across runs.
