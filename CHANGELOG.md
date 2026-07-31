# Changelog

All notable changes to Introspectre are summarized here at a high level. For the full command/flag surface, see [USAGE.md](./USAGE.md).

## [1.6.0] - 2026-07-31

### Blind schema reconstruction via `__type`-walk
* When a target disables **only** the `__schema` root field but leaves `__type` reachable — a common hardening half-measure — `scan` and `audit` now automatically reconstruct the schema instead of giving up. After the normal `__schema` vectors fail, Introspectre discovers the query root via top-level `__typename`, then walks `__type(name: ...)` breadth-first across every referenced type (field return types, argument types, input-object fields, interfaces, and union members) to rebuild a typed schema that feeds the full analysis pipeline and visual report. Previously this case exited with "introspection disabled — try `brute`", losing all typed analysis (`brute` only recovers untyped root-field names).
* The walk is bounded (max-types cap, visited-set dedup, honours `--rate-limit-ms`) and hardened against servers that cap introspection nesting: each per-type query starts at a modest `ofType` depth and retries once with a shallower selection if the server rejects it. It runs only as a fallback — endpoints with `__schema` enabled are unaffected and incur no extra requests. A note reports how many types were reconstructed; the schema is treated as partial.

## [1.5.0] - 2026-07-27

### New detection coverage
* **Passive analyzers** (schema-only, no requests):
  * `node-idor-surface` — flags a Relay-style global object fetcher (a `Node` interface + a root `node(id:)`/`nodes(ids:)` field) and enumerates the object types it can reach. A single opaque endpoint that returns any object by global id is an enumerable BOLA/IDOR surface when those ids are unsigned/predictable.
  * `rbac-enum-disclosure` — surfaces enums that encode the app's **role/permission model** and lists the disclosed values (the exact privilege taxonomy to target). Distinct from `sensitive-enum-values`; tunable via a `rbac_terms` pattern list in config.
* **Active probes** (safe, O(1); default on, skippable via `--skip`):
  * `introspection-matrix` — reports which of `__schema` / `__type` / field-suggestion ("did you mean?") leakage are reachable, and — when a token is supplied — whether they are open **unauthenticated** vs. only with auth. Unauthenticated schema disclosure on an auth-gated API is called out specifically (disabling only `__schema` is insufficient).
  * `cors-misconfiguration` — sends a hostile `Origin` and inspects the reflected `Access-Control-Allow-Origin` / `-Allow-Credentials`; reflected-origin + credentials is flagged High (cross-origin authenticated-read primitive).
  * `apq-supported` — detects Apollo Automatic Persisted Queries (extra cache/registration surface).
  * `alias-cap-enforced` — characterises the per-selection-set alias cap (an anti-amplification control), reporting the limit when present.

### Audit — large-schema handling
* Active probing is now bounded on large schemas. The fan-out probes (`unauth`, `mutation-privesc`, `sql-injection`, `os-command-injection`, `xss`) previously enumerated their entire target set — on a schema with hundreds of mutations that meant tens of thousands of requests and hours of traffic. New controls:
  * **`--dry-run` now estimates request volume** per probe and total wall-clock time, instead of only listing which probes would run.
  * **Risk-ranked auto-cap**: without an explicit `--max-targets`, a large schema auto-caps each fan-out probe to a safe number of targets, ranked by the severity of any passive finding that already touched them (highest-value fields first). A warning reports it.
  * **`--focus <TYPE|TYPE.field>`** scopes probing to matching root fields; **`--max-targets <N>`** sets a per-probe cap (`0` = unlimited); **`--max-requests <N>`** is a global request budget that stops the run cleanly and reports what it skipped. Defaults can also be set via `max_targets_per_probe` / `max_total_requests` in config.
* Fixed a latent stack overflow: the injection probes' input-object path walk (`find_injectable_paths`) had no cycle guard and recursed infinitely on self-referential input types (e.g. recursive filter inputs). It now uses a visited-type set plus a depth cap.

## [1.4.0] - 2026-07-17

### Visual report — WebGL engine
* The interactive HTML report now renders on a **WebGL** engine (Sigma.js + graphology) instead of the previous canvas renderer, so large schemas stay smooth where they used to lag. The report is still a single self-contained offline file.
* Graph layout is now organic (ForceAtlas2), which de-clutters large schemas compared to the previous rigid hierarchy.
* **Progressive expansion**: clicking a node now reveals a capped set of its relations (with a "show more" path via right-click) instead of dumping every connection at once, and only the newly added nodes are laid out rather than reflowing the whole graph.
* **Hover-to-highlight**: hovering a node now highlights its immediate neighborhood.

### Packaging
* Added crate metadata (description, license, repository, keywords, categories) so Introspectre can be installed with `cargo install`.

## [1.3.0] - 2026-07-16

### Transport
* GraphQL requests are no longer limited to JSON `POST`. A new `--transport` flag supports `post-json`, `get` (`?query=`), `form` (`application/x-www-form-urlencoded`), and `graphql` (raw `application/graphql` body). The default `auto` negotiates a working transport during the endpoint probe and reuses it, so endpoints that only accept a query string or form body are now scannable instead of failing. Mutations that a `GET` cannot legally carry fall back to `POST` automatically.

### Traffic import
* Burp Suite HTTP-history XML (`Save items`) is now a supported `--seed-traffic` format alongside HAR (previously HAR-only; Burp XML was unimplemented). Variables are extracted from JSON bodies, `GET` query strings, and form-encoded bodies.

### Safety & scoping
* Added `--no-dos` (skip all DoS-class probes), `--skip <ids>` / `--only <ids>` (select probes by id), and `--dry-run` (print the probes that would run without sending any request) — useful for testing against fragile self-hosted labs without a self-inflicted DoS.

### Documentation
* Documented the transport model, the Burp export workflow, safe-testing guidance, and why the visual report's type-centric graph reveals indirect nodes on expansion.

## [1.2.0] - 2026-07-12

### Changed
* Finding identifiers are now descriptive slugs (e.g. `os-command-injection`, `idor`, `sensitive-fields`) instead of opaque codes like `AUD-012`/`GQL-013`. This changes the `id` field in JSON/markdown output.
* Requests now send a realistic browser User-Agent (randomized from a built-in list) by default instead of advertising the tool; `--user-agent` still overrides.
* The startup banner now shows the tool version.

### Validated
* Full coverage pass against Damn Vulnerable GraphQL Application (DVGA): SQL injection, OS command injection, IDOR, CSRF, and complexity/depth-limit findings confirmed; no false positives observed for XSS/SSTI/privilege-escalation.

## [1.1.0] - 2026-07-12

### Denial-of-Service Coverage
* Added a query-complexity/depth **enforcement** probe (AUD-DOS-007): sends a deliberately deep introspection query and reports whether the server enforces a limit (rejects it) or accepts it unbounded; also surfaces an exposed complexity limit (e.g. Hygraph `Effective-Complexity-Limit`) when present.

### Evasion
* Improved `--evasion` obfuscation: randomized comment tokens and insignificant-comma/inline-comment insertion (previously a fixed per-line `# abc`), making the reformatting harder for signature-based WAFs to match. Documented the feature in USAGE.md.

### Reliability
* The HTTP client no longer reuses pooled keep-alive connections, fixing "error decoding response body" failures against Flask/werkzeug-style dev servers (e.g. Damn Vulnerable GraphQL Application), which previously made those endpoints unscannable.
* Requests retry once on a transient connection error, and a single failing probe no longer aborts the entire audit — the run continues and reports what it found.

## [1.0.0] - 2026-07-11

First stable release.

### Commands (breaking)
* Merged the former `discover` command into `brute`. Blind reconstruction is now a
  single command: `brute` probes candidate field names (from `-w`/`--words`, your
  config wordlists, or a built-in default) and harvests "Did you mean?" suggestions,
  then runs the normal analysis.

### Reliability & correctness
* Eliminated a class of false positives:
  * XSS is no longer reported for payloads reflected only inside JSON error
    messages — a finding now requires an HTML response context.
  * Passive-finding severities no longer inflate to Critical when a finding
    touches several public fields (severity escalation is capped at one level).
* Implemented previously non-functional flags: `--min-severity` now filters
  findings, and `--probe-only` now runs just the endpoint probe and exits.
* `scan --static-only false` now works, so active probing can be enabled from
  `scan` (the flag previously rejected a value); active findings are shown in the
  `scan` report.
* `--format json`/`markdown` now emit a single valid document (progress output
  moved to stderr; the audit and passive reports no longer concatenate).
* IDOR detection now also flags single-record lookups by unique non-id arguments
  (e.g. `user(username: ...)`), not just `id`/`uuid`-named arguments.
* Recalibrated active-probe confidence: unproven IDOR / privilege-escalation /
  unauthenticated-access results are reported as leads to verify, not as
  confirmed exploits; JWT findings are labeled as local token decoding.
* Hardened the schema cycle detector against large schemas (linear-time,
  de-duplicated) and fixed panics on partial/edge-case introspection responses.
* The tool version is now sourced from the crate version everywhere (including the
  request User-Agent), so it no longer drifts.

### Visual Reporting
* Reworked the interactive HTML report with a refined, high-contrast theme.
* The HTML report is now fully self-contained and works offline — Cytoscape.js and its layout extensions are bundled into the report, with no external CDN dependency at render time.

### Denial-of-Service Coverage
* Expanded DoS-related heuristics and active probes: alias amplification, query batching, and directive overloading, alongside circular-reference and nested-list-inflation checks.

### Licensing & legal
* Released under the MIT License (added `LICENSE`).
* Added a **Legal & Ethical Use** disclaimer to the README covering authorized-use-only, legal responsibility, and the "as-is"/no-warranty terms.

### Documentation
* Consolidated and de-duplicated the documentation set.
* Documented that `scan` defaults to passive-only behavior (`--static-only true`).

## [0.6.0]

* Added `--seed-traffic` ingestion (HAR / Burp XML) to automatically learn realistic variable values for active probes.
* Refined SQLi and XSS injection probing modules for improved accuracy.
* Optimized mutation privilege-escalation logic and authorization-bypass testing.
* General repository cleanup and documentation refresh.
