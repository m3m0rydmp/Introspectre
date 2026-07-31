# Introspectre: Usage Guide

This is the detailed, case-by-case guide to running Introspectre. For what the tool does, see the [README](./README.md); for how it's built, see [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## 1. Core Workflow

| Command | Role |
| :--- | :--- |
| `scan` | Retrieves the schema and runs passive analysis. Passive-only by default. |
| `audit` | Sends active payloads to attempt to confirm vulnerabilities. |
| `brute` | Blind schema reconstruction when introspection is disabled: probes field names (optional `-w` wordlist) and harvests "Did you mean?" suggestions. |
| `file` | Analyzes a saved introspection JSON file offline; no network requests. |

`brute` handles the case where introspection is off and you have no schema file: it probes candidate field names (from `-w`, your config wordlists, or a built-in default) and simultaneously harvests GraphQL's "Did you mean?" error suggestions, reconstructing what it can into a schema that then feeds the normal analysis.

---

## 2. Basic Scanning

`scan` is the entry point. It retrieves the schema and performs passive analysis to surface structural risk (e.g., potential DoS paths, exposed sensitive fields) before any offensive payload is sent.

> [!NOTE]
> `--static-only` defaults to `true`. `scan` will **not** send active probes unless you pass `--static-only false`, or you run `audit` separately.

### Case: Introspection is enabled
```bash
introspectre scan http://target.com/graphql
```

### Case: Introspection is disabled, but you have a schema file
If you have a `schema.json` (from a developer, a leak, or a prior `brute` run), point Introspectre at it directly:
```bash
introspectre scan http://target.com/graphql --use-schema ./schema.json
```

### Case: You want active probes as part of the same run
```bash
introspectre scan http://target.com/graphql --static-only false --visualize report.html
```

---

## 3. Active Auditing

`audit` performs active probing: it takes the schema (live, from a file, or from a prior `brute` run) and sends payloads to attempt to confirm behavior — injection, IDOR, SSRF, privilege escalation, and DoS-related checks.

> [!WARNING]
> **`audit` sends offensive payloads** (SQL injection strings, XSS scripts, and similar). Never run it against a target without explicit authorization. See [Legal & Ethical Use](./README.md#legal--ethical-use).

### Case: Standard assessment
```bash
introspectre audit http://target.com/graphql
```

### Case: Authenticated assessment
Many vulnerability classes (IDOR/BOLA in particular) only surface once the server knows who is asking. Supply a session token:
```bash
introspectre audit http://target.com/graphql -H "Authorization=Bearer <your-token>"
```

### Case: Testing WAF resilience
`--evasion` applies increasing levels of query obfuscation (comments, casing, fragmentation):
```bash
introspectre audit http://target.com/graphql --evasion 2
```

### Query obfuscation (`--evasion`)

`--evasion <0-3>` reformats the outgoing query so it is byte-different from a "clean" request while remaining semantically identical GraphQL — the goal is to slip past naive **regex/signature-based** WAF rules that pattern-match on a fixed query shape, rather than to change what the query does.

| Level | Behavior |
|---|---|
| `0` (default) | Off. Queries are sent exactly as generated. |
| `1` | Whitespace jitter plus insignificant commas (GraphQL treats `,` as whitespace) inserted at existing token boundaries. |
| `2` | Adds level 1, plus randomized `# <token>` end-of-line comments (a different random token per request/line instead of a fixed string). |
| `3` | Adds level 2, plus CRLF line endings and random leading/trailing comment noise. |

> [!NOTE]
> This is a narrow evasion technique. It does **not** help against WAFs or gateways that actually parse GraphQL, or that normalize whitespace/comments/commas before signature matching — those will see the identical query regardless of formatting. It also does not alter the query's meaning, arguments, or payloads in any way; it only changes incidental formatting.

### Case: Reducing request volume
`--batch-probes` groups a batch of safe/low-risk probes (verbose disclosure, unauthenticated-access checks) into fewer HTTP requests:
```bash
introspectre audit http://target.com/graphql --batch-probes --batch-size 10
```

---

## 4. Blind Discovery

A common hardening mistake is to disable **only** the `__schema` root field while leaving `__type` reachable. In that case `scan` and `audit` automatically fall back to a **`__type`-walk**: they discover the root type via `__typename`, then walk `__type(name: ...)` breadth-first across every referenced type to rebuild a typed schema — no flag or wordlist needed. This runs on its own when the normal introspection vectors fail; a note (`reconstructed N types via __type-walk`) is printed and the reconstructed schema feeds the full analysis and visual report. It stops only when both `__schema` and `__type` are blocked, at which point `brute` is the next step.

When introspection is blocked and no schema file is available, `brute` reconstructs what it can. It probes candidate field names and, at the same time, harvests GraphQL's "Did you mean 'user'?" style error suggestions — so it recovers fields even without a direct wordlist hit for each one.

### Case: with a custom wordlist
```bash
introspectre brute http://target.com/graphql -w ./wordlists/graphql-fields.txt
```

### Case: default wordlist + suggestion harvesting
```bash
introspectre brute http://target.com/graphql
```

Both commands accept `--dynamic-throttling` and `-c/--concurrency` to control how aggressively they probe the target.

---

## 5. Smart Data Synthesis

To get past strict input validation, Introspectre needs to know what "good" data looks like for a given field — a generic string sent to a field expecting a UUID will simply get rejected before it reaches anything interesting.

### Case: Traffic ingestion
Import traffic logs exported from Burp Suite or recorded as HAR. Introspectre extracts valid identifiers (UUIDs, user IDs) and variable shapes from them, then substitutes learned values into active probes in place of generic placeholders:
```bash
introspectre scan http://target.com/graphql --seed-traffic ./exported_logs.har
```

**Why this matters:** static schema analysis knows a field's *type* but not a *valid value* for it. A field expecting a real UUID or an existing order ID rejects synthetic input at the validation layer, before a probe ever reaches vulnerable logic. Seeding from real traffic closes that gap — Introspectre reads the `variables` your captured requests actually sent and reuses them.

**Both HAR and Burp XML are accepted**, auto-detected by content:

- **HAR** — export from your browser DevTools (Network tab → *Save all as HAR*), or any proxy that emits HAR.
- **Burp Suite** — in **Proxy → HTTP history**, select the relevant GraphQL requests (Ctrl-click to multi-select, or filter by the endpoint first), right-click → **Save items**, and save as XML. That XML is what you pass to `--seed-traffic`.

```bash
introspectre audit http://target.com/graphql --seed-traffic ./burp-history.xml
```

Variables are harvested from all three places a GraphQL request can carry them: the JSON request body (`{"query":…,"variables":{…}}`), a `GET ?query=…&variables=…` query string, and a `application/x-www-form-urlencoded` body. Only the `variables` map is read — request/response bodies are not otherwise mined. Learned values are stored in the local Seed Vault (`introspectre.db`) and persist across runs.

### Case: Manually supplied seed values
```bash
introspectre audit http://target.com/graphql --seeds ./seeds.json
```
`seeds.json` maps a type or field name to a literal value, e.g. `{ "UserID": "\"user-123\"", "Email": "\"test@example.com\"" }`.

---

## 6. Choosing a Transport

A GraphQL server usually listens on a single endpoint, but not every server accepts requests the same way. The common shape is `POST` with a JSON body, but plenty of real targets also (or only) accept the query in a `GET` query string or a form-encoded body. If Introspectre spoke only one dialect it would simply fail on those endpoints — so `--transport` controls how requests are sent.

| Value | How the query is sent |
| :--- | :--- |
| `auto` (default) | Detects a working transport during the endpoint probe (tries `post-json`, then `get`, then `form`) and reuses it for the rest of the run. |
| `post-json` | `POST` with `Content-Type: application/json` and a `{"query":…,"variables":…}` body. The standard. |
| `get` | `GET` with `?query=…&variables=…`. Query-only — see the note below. |
| `form` | `POST` with `Content-Type: application/x-www-form-urlencoded` and a `query=…&variables=…` body. |
| `graphql` | `POST` with `Content-Type: application/graphql`; the raw body **is** the query (no variables map). |

```bash
# Let Introspectre negotiate (default)
introspectre scan http://target.com/graphql

# Force a specific transport
introspectre audit http://target.com/graphql --transport form
```

> [!NOTE]
> **`get` cannot carry mutations.** Per the GraphQL spec, `GET` is for side-effect-free reads; sending a mutation over `GET` is both non-conformant and a CSRF risk. When a probe needs to send a mutation, Introspectre automatically falls back to `POST` for that single request regardless of `--transport`. Batched probes (`--batch-probes`) always use JSON, since batching is an array body.

---

## 7. Testing Safely & Selecting Probes

Active probing — especially the DoS-class checks — can stress a target. Against a small self-hosted lab, an unbounded DoS probe can take down the very server you are testing (a "self-DoS"). These flags let you scope a run precisely.

`audit` also runs a set of **safe, single-request configuration checks** by default — `introspection-matrix` (which of `__schema`/`__type`/"did you mean?" are open, and at what auth level), `cors` (cross-origin `Access-Control-*` reflection), `apq` (Apollo persisted-query support), and `alias-cap` (per-field alias limit). They generate negligible load; skip any with `--skip <id>`.

| Flag | Effect |
| :--- | :--- |
| `--no-dos` | Skips every DoS-class probe (alias amplification, batching, complexity, nested-list expansion). Use this for functional/coverage runs where you don't want to generate load. |
| `--skip <ids>` | Comma-separated probe ids to skip, e.g. `--skip ssrf,xss`. |
| `--only <ids>` | Run *only* these probe ids, e.g. `--only sql-injection,idor`. |
| `--dry-run` | Prints the probes that *would* run, an estimated request count per probe, and a total wall-clock estimate — and sends **no requests at all**. |
| `--focus <TYPE\|TYPE.field>` | Aim active probing at a subset of root fields — a whole root (`mutation`), a qualified field (`Query.user`), or a name substring (`report`). |
| `--max-targets <N>` | Cap the targets each fan-out probe tests (`0` = unlimited). |
| `--max-requests <N>` | Global cap on the total active requests sent. |

```bash
# Functional run with no load-generating probes
introspectre audit http://lab.local/graphql --no-dos

# Preview the request volume and time cost before firing anything
introspectre audit http://lab.local/graphql --dry-run

# Run a single class in isolation
introspectre audit http://target.com/graphql --only idor
```

### Large schemas

On a big schema (hundreds of mutations, thousands of fields) the fan-out probes (`unauth`, `mutation-privesc`, `sql-injection`, `os-command-injection`, `xss`) would otherwise send *tens of thousands* of requests — hours of traffic, and a self-DoS risk. Introspectre handles this in four ways:

- **Preflight estimate.** `--dry-run` prints, per probe, roughly how many requests it would send and how long that takes at the current `--rate-limit-ms`, so you see the cost before committing.
- **Risk-ranked auto-cap.** Without an explicit `--max-targets`, a large schema auto-caps each fan-out probe to a safe number of targets, **ranked by the severity of any passive finding that already touched them** — so the most interesting fields are probed first. A warning tells you it happened.
- **Scoping.** `--focus User` (or `--focus Query.report`) narrows probing to the part of the schema you care about; `--max-targets N` sets your own per-probe cap (`0` lifts it entirely).
- **Global budget.** `--max-requests N` bounds the whole run; the audit stops cleanly at the budget and reports what it left untested.

```bash
# See the damage before doing it
introspectre audit https://api.big.com/graphql --dry-run

# Probe only user/report surfaces, capped and budgeted
introspectre audit https://api.big.com/graphql --focus user,report --max-targets 50 --max-requests 2000
```

**Building a lab without self-DoS:** run the target in a resource-capped container (e.g. `docker run --cpus 1 --memory 512m …`) so a runaway query can't exhaust the host, use `--no-dos` while you validate the non-DoS coverage, and reach for `--dry-run` to sanity-check a command before firing it. For automated/CI use, prefer a disposable mock GraphQL server over a persistent lab.

---

## 8. Reading the Visual Report

The `--visualize` report renders the schema as an interactive graph. It runs on a **WebGL** engine (Sigma.js + graphology) so it stays responsive on large schemas, and it is a single self-contained file that works offline. A few things about it are worth knowing:

- **Nodes are *types*, not fields.** Each box is a GraphQL type (e.g. `User`, `AddonUser`); the arrows between them are labeled with the field that connects them. A single type appears **once**, even though many fields across the schema return it.
- **Clicking a node expands it progressively.** Because types are shared, expanding a node draws edges to it from *every* currently-visible type that references it — so nodes that aren't directly connected to the one you clicked can appear. To avoid overwhelming you on a large schema, each click reveals a **capped** set of a node's relations (prioritising higher-risk targets); right-click a node for **Expand all** to reveal the rest. Only the newly added nodes are laid out, so the rest of the graph stays put.
- **Hover to highlight.** Hovering a node highlights its immediate neighborhood so you can trace connections without clicking.
- **Isolate Mode.** A click there deliberately shows the full path from a root down to the selected node *and* everything reachable downstream of it — useful for tracing how an attacker reaches a sensitive field, though it surfaces many indirect nodes on purpose.

If a large schema still feels busy, keep **Scalars: HIDDEN** on, use the search box to jump to (and focus) a type, and use **Isolate Mode** to focus a single path.

---

## 9. Flag Reference

### Global flags (all commands)

| Flag | Description |
| :--- | :--- |
| `--config <FILE>` | Path to a TOML config file. |
| `--wordlist <TYPE=PATH>` | Merge extra words into a pattern list (repeatable). |
| `--format text\|json\|markdown` | Output format (default `text`). |
| `--max-affected <N>` | Max affected entries shown per finding (default `30`, `0` = unlimited). |
| `--min-severity low\|medium\|high` | Only show findings at or above this severity. |
| `-t, --token <TOKEN>` | Bearer token for authenticated introspection/requests. |
| `--user-agent <UA>` | Custom User-Agent string. |
| `--stealth` | Use a common browser User-Agent instead of the tool's default. |
| `--transport auto\|post-json\|get\|form\|graphql` | How GraphQL requests are sent (default `auto`; see [Choosing a Transport](#6-choosing-a-transport)). |
| `--no-dos` | Skip all DoS-class probes (alias amplification, batching, complexity, nested-list expansion). |
| `--skip <IDS>` | Comma-separated probe ids to skip. |
| `--only <IDS>` | Run only these comma-separated probe ids. |
| `--dry-run` | Print the probes that would run without sending any requests. |
| `--use-schema <FILE>` | Use a local schema JSON file instead of live introspection. |
| `--visualize [PATH]` | Generate the interactive HTML report (default `introspectre-visual.html`). |
| `--seed-traffic <FILE>` | Learn variable values from a HAR or Burp XML file. |
| `--seeds <FILE>` | Provide known-good values via JSON. |
| `--verbose` | Include extra detail (e.g., PoC blocks) in text output. |

### `scan`-specific flags

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-H, --header <KEY=VALUE>` | — | Extra request header (repeatable). |
| `--timeout <SECS>` | `15` | HTTP request timeout. |
| `--static-only <bool>` | `true` | Passive-only. Set to `false` to also run active probes. |
| `--rate-limit-ms <MS>` | `750` | Delay before each request. |
| `--dynamic-throttling` | `false` | Adjust delay based on observed server latency. |
| `--discover-auth <bool>` | `true` | Probe unauthenticated to map public vs. protected root fields. |
| `--probe-first <bool>` | `true` | Run a lightweight endpoint check before introspection. |
| `--probe-only` | `false` | Only run the endpoint probe; skip introspection and analysis. |

### `audit`-specific flags

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-H, --header <KEY=VALUE>` | — | Extra request header (repeatable). |
| `--timeout <SECS>` | `15` | HTTP request timeout. |
| `--rate-limit-ms <MS>` | `750` | Delay before each request. |
| `--dynamic-throttling` | `false` | Adjust delay based on observed server latency. |
| `--evasion <0-3>` | `0` | Query obfuscation level for WAF-resilience testing. |
| `--batch-probes` | `false` | Batch safe probes into fewer HTTP requests. |
| `--batch-size <N>` | `5` | Max operations per batched request (with `--batch-probes`). |
| `--idor-payloads <IDS>` | — | Custom possibility IDs for IDOR probing (comma-separated or repeatable). |
| `--focus <TYPE\|TYPE.field>` | — | Restrict active probing to matching root fields (repeatable / comma-separated). Matches a whole root (`query`/`mutation`), a qualified `Query.user`, or any field whose name contains the term (`user`). |
| `--max-targets <N>` | auto | Cap the targets each fan-out probe tests. `0` = unlimited. On a large schema the default auto-caps to a safe limit (ranked by passive-finding severity). |
| `--max-requests <N>` | — | Global cap on total active requests. The audit stops probing once reached and reports what it skipped. `0` = unlimited. |

### `brute`-specific flags

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-H, --header <KEY=VALUE>` | — | Extra request header (repeatable). |
| `--timeout <SECS>` | `15` | HTTP request timeout. |
| `-w, --words <FILE>` | — | Custom wordlist of field names (else config wordlists, else a built-in default). |
| `-c, --concurrency <N>` | `10` | Concurrent brute-force probes. |
| `--dynamic-throttling` | `false` | Adjust concurrency based on observed server latency. |
| `--rate-limit-ms <MS>` | `100` | Delay before each request. |

### `file`

Takes a single positional `<path>` to a saved introspection JSON file. No command-specific flags; global flags (e.g. `--visualize`, `--format`) still apply.
