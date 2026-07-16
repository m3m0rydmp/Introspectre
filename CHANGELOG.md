# Changelog

All notable changes to Introspectre are summarized here at a high level. For the full command/flag surface, see [USAGE.md](./USAGE.md).

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
