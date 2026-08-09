# Changelog

All notable changes to Introspectre are summarized here at a high level. For the full command/flag surface, see [USAGE.md](./USAGE.md).

## [1.15.3] - 2026-08-10

### Fix: `-H "Cookie: …"` now strips the `Cookie:` prefix automatically
* When copying a cookie header from browser dev tools (`Cookie: session=abc; token=xyz`) and passing it
  via `-H`, the `Cookie:` prefix was treated as part of the header **name** (e.g. `Cookie: session`),
  producing an invalid HTTP header that reqwest rejected before any request went out. The
  `--challenge-cookie` flag already had smart prefix-stripping (v1.15.1), but `-H` headers bypassed it.
* **Fix:** `parse_extra_headers` and `parse_header_kv` now detect a leading `Cookie:`/`cookie:` prefix
  in the header name and normalize it to `Cookie`, keeping the value intact. Both `-H "Cookie: a=b"`
  and `-H "Cookie=a=b"` now produce the same correct header. (`src/utils.rs`, `src/audit/utils.rs`)

### UX: `scan --injection` / `scan --chain` now gives a clear error
* `--injection` and `--chain` are `audit`-only flags. Using them with `scan` (or `brute`/`file`)
  previously produced clap's generic `unexpected argument` error with no hint. Now the tool prints a
  friendly message: `--injection is only available with the audit command.` and exits. (`src/main.rs`)

### Guard: injection probes skipped when no schema is available
* When `audit` can't obtain a schema (introspection blocked, type-walk fails, no `--use-schema`), it
  continues with an empty schema so schema-independent probes (CSRF, CORS, APQ, etc.) can still run.
  But injection probes (SQLi, XSS, SSRF, CMDI) were also dispatched — building zero targets and
  silently no-op'ing, with XSS wasting one context request. Now injection probes are explicitly
  skipped with a clear warning: `Injection probes skipped: no schema available …`. (`src/audit/mod.rs`)

## [1.15.2] - 2026-08-10

### Fix: `audit` now negotiates transport when `--transport auto` (matching `scan`)
* When `--transport auto` (the default), `audit` was hardcoded to `POST/JSON` and never probed for
  the actual working transport — unlike `scan --probe-first`, which negotiated PostJson → Get → Form
  via a lightweight `__typename` knock. On endpoints that only answer GET or form-encoded requests,
  every `__type`-walk query in audit silently failed (0 types reconstructed), and audit continued
  with an empty schema reporting "schema-independent probes only." Scan succeeded because the probe
  had already selected the correct transport.
* **Fix:** the `Audit` command now runs the same endpoint probe when `--transport auto`, so
  `resolved_transport` reflects the transport the server actually accepts. The type-walk and all
  active probes then use that negotiated transport. One extra `{ __typename }` request per audit
  run; no new flags or config. (`src/main.rs` audit arm)

## [1.15.1] - 2026-08-10

### Fix: `--challenge-cookie` accepts both raw cookies and `Cookie: …` header values
* `--challenge-cookie` now detects and strips a leading `Cookie:` / `cookie:` prefix, so both
  `--challenge-cookie "id=abc; token=xyz"` and `--challenge-cookie "Cookie: id=abc; token=xyz"`
  (as copied from browser dev tools) work correctly. Previously the `Cookie:` form produced a
  malformed `Cookie=Cookie: …` header and a 403. The `-H` flag remains `Name=Value` format.

## [1.15.0] - 2026-08-10

### CLI: `--cookie` renamed to `--challenge-cookie`
* The bot-wall session-reuse flag is now `--challenge-cookie` — it exists for **WAF/bot-wall challenge
  bypass** (`cf_clearance`, `_px3`, `__cf_bm`, …), where you paste cookies captured from a browser
  session that already passed the challenge. Ordinary session/auth headers remain the job of
  `-H`/`--header` (`Authorization: Bearer ...`, `Cookie: ...`).
* The old `--cookie` spelling is removed (no alias). Update any scripts/aliases.

## [1.14.0] - 2026-08-04

### Blind (error-suppressed) SQL-injection detection
* New **error-differential quote-balance** check confirms SQL injection even when the server hides the
  database error (a generic `500`/empty response). For a string argument whose benign value succeeds, a
  lone `'` that **breaks** the query while a balanced `''` **recovers** it is a definitive injection
  signature (`sql-injection-blind` finding). By construction it stays silent on parameterized backends
  (which error on neither quote), so it does not reintroduce false positives. *(Caught the deliberately
  error-suppressed `dogs(namePrefix)` SQLi in the OWASP poc-graphql lab; silent on Hasura; DVGA's
  error-based SQLi still confirmed.)*

### SSRF: detect host-style sinks (not just URL args)
* The passive SSRF-surface list now includes host/target-style argument names (`host`, `hostname`,
  `domain`, `server`, `target`, `dest`, `proxy`, `fetch`, …), so connectivity/import resolvers are
  flagged — previously only `url`/`webhook`-style names were. The active probe adds **bare host/IP**
  payloads (e.g. `169.254.169.254`, `10.255.255.1`) for host args, **seeds sibling args**
  (`scheme=http`/`port=80`/`path=/`) so multi-arg fetchers actually issue the request, and treats a
  **payload-induced request timeout** (a hung outbound) as an SSRF signal.
* **Out-of-band confirmation (`--oob-url`).** Point the audit at a collaborator domain (Burp
  Collaborator / interactsh / `*.oast.fun`) and the SSRF probe fires payloads carrying a **per-argument
  DNS marker** (`<field>-<arg>.<collaborator>`, in both bare-host and full-URL form). A DNS or HTTP hit in
  your collaborator confirms blind SSRF and pinpoints the exact argument — the reliable path when timing
  is inconclusive (a DNS lookup alone is proof). *(Verified against DVGA `importPaste`: the marker
  `importpaste-host.<collab>` produced a collaborator DNS interaction.)*

### XSS probe: sees nested reflections, reports leads without false positives
* The reflection probe now sends **variable-based** payloads with a **reflective selection set** (all
  no-arg scalar fields of the return type plus one level into nested objects), so a value echoed in a
  wrapper result — e.g. a mutation returning `{ paste { content } }` — is actually observed (the old
  `{ __typename }` selection hid it).
* Reflection in a **JSON** response is now reported as a **Low, "potential stored/DOM XSS — verify HTML
  sink" lead** (`xss-reflected-input`) rather than treated as confirmed XSS — because echoing a script in
  an `application/json` body is not itself exploitable. Only reflection in a response actually **served as
  HTML** is a confirmed High. *(DVGA's `createPaste(content)` echo now surfaces as one lead, zero false
  positives.)*

### OS command injection: structured payloads for parsed inputs
* The time-based OS-command-injection probe now also sends **structured** payloads that survive inputs
  parsed before the shell — `host:port`-prefixed variants (`127.0.0.1:80; sleep 5`, …) and, when a seed
  is known for the argument, `<seed>; sleep 5`. This catches blind command injection in connectivity-style
  sinks (e.g. `host,port = ip.split(':'); os.system(...)`) that a bare `; sleep 5` misses. *(Confirms the
  blind `isSqlUp(ip)` cmdi in graphql-security-labs; DVGA's `systemDebug` cmdi still confirmed.)*

### NoSQL operator-injection detection (JSON/custom-scalar args)
* New detector for MongoDB-style operator injection: probes **custom-scalar arguments** (JSON and other
  non-standard scalars, where operator objects can live — standard `String/Int/…` args can't carry one)
  with `{"$ne":null}` / `{"$gt":""}` / `{"$regex":".*"}` and confirms on a **benign-vs-operator
  differential** (the operator must be accepted, return data differing from a benign literal, and that data
  must be non-empty). Emits `nosql-injection` (Critical). By construction it can't fire on a
  parameterized backend (the operator errors or is treated as a literal). *(Caught a `{"$ne":null}` auth
  bypass in a MongoDB+Apollo lab; silent on Hasura; DVGA SQLi unaffected.)*

### Better injection-sink ranking (true-positive reliability under a budget)
* SQLi target ranking is now **weighted**: filter/search/ordering parameters (`filter`, `search`,
  `where`, `like`, `prefix`, `order`, …) count double a generic identifier field (`id`, `name`, `user`),
  so a real sink is probed **first** and isn't starved when the fair-share `--max-requests` budget is
  tight. *(A full `--max-requests 900` audit of poc-graphql now catches the `dogs(namePrefix)` SQLi it
  previously missed under the same budget.)*

### Fix: SQL-injection false positives on parameterized / Hasura filters
* **Strict database-error matching.** The error-based SQLi confirmation no longer fires on generic
  words (`column`, `table`, `relation`, `database`, `unexpected token`, or bare `$ne/$gt/$in/$regex`)
  that appear in ordinary GraphQL/Hasura/Postgres **validation, type-coercion, and permission** errors.
  It now matches only high-signal database-engine/driver markers (`sqlstate`, `syntax error at or near`,
  `unterminated quoted string`, `unrecognized token`, `operationalerror`, `psycopg2`, `sqlite3.`, …).
* **Baseline differential.** A finding is confirmed only when the payload triggers a database error the
  **dummy baseline did not** — so a field that rejects *any* malformed input (every parameterized filter)
  is no longer mistaken for an injection. A reflection guard also prevents matching our own echoed payload.
* **Hasura-aware.** Parameterized comparison-operator arguments (`where…._eq/_ilike/_similar/…`) are
  skipped by default (with a summary note) — they are parameterized filters, not string-concat sinks.
* **Collapsed findings.** At most one finding per `root.field` instead of one per operator/column.
* *Verified against a local Hasura+Postgres lab (0 false positives; 434 comparison-operator args skipped)
  and DVGA (genuine `Query.pastes(filter)` SQLi still confirmed).*

## [1.13.5] - 2026-08-04

### Docs: quick-start cheat-sheet
* Added a copy-paste **TL;DR command cheat-sheet** to the top of `USAGE.md`, grouped by scenario
  (recon, blind discovery, active audit, WAF/bot-wall session reuse, offline & maintenance) — the most
  useful situational flag combinations in one place, for readers who skip the prose.
* Documented the `--injection` and `--chain` audit flags in the `USAGE.md` flag table (previously only
  in `--help`), and corrected the stale current-version line in `README.md`.

## [1.13.4] - 2026-08-03

### Visualizer performance: level-of-detail + chunked expand-all
* **Level-of-detail labels.** The WebGL graph now drops label rendering entirely when the camera is
  zoomed out past a ratio cutoff (a cluster overview where per-node labels are unreadable anyway),
  and restores them on zoom-in — a large frame-time saving on big schemas. The toggle only fires when
  the state actually flips.
* **Chunked "Expand all children".** Expanding a high-degree node used to insert every reachable node
  and run the full forceAtlas2 relayout in one synchronous pass, freezing the tab. Above ~600 nodes
  the expansion now adds nodes and edges in `requestAnimationFrame`-batched chunks (400/frame) with
  new nodes pre-seeded near the anchor, followed by a single **light** layout pass — the graph visibly
  grows instead of hanging. (Sigma/graphology run on the main thread, so rAF chunking is the practical
  substitute for a worker.)

## [1.13.3] - 2026-08-03

### CLI/UX polish: `--exit-zero` and clearer reconstruction failures
* **`--exit-zero`** (global). Introspectre normally exits non-zero when High/Medium findings are
  present (a CI "findings gate"). `--exit-zero` suppresses that so interactive or chained runs aren't
  treated as failed commands; the report is unchanged.
* **Clearer reconstruction failures.** When every introspection vector *and* the `__type`-walk fallback
  fail, the error now surfaces the **real last `__schema` server error** (e.g. a depth/complexity
  rejection) plus the `__type`-walk failure reason, and adds a targeted hint when the server enforces an
  introspection depth/complexity limit — instead of a generic "failed to parse response".

## [1.13.2] - 2026-08-03

### Streaming traffic parse
* `--seed-traffic` / session extraction now parse HAR and Burp exports through a **buffered reader**
  (`serde_json::from_reader` / `quick_xml::de::from_reader`) instead of reading the whole file into a
  `String` first, cutting peak memory on large captures. Both formats share one loader and the same
  seed output. *(The parsed structure is still materialised; a full zero-DOM event stream remains a
  possible further step.)*

## [1.13.1] - 2026-08-03

### ID-scheme breadth
* The global-ID classifier now distinguishes **time-based UUIDv1** (flagged as *potentially
  predictable — manual review*, distinct from random v4) and recognises **bare hex hashes**
  (MD5/SHA-1/SHA-256 → 128/160/256-bit) as opaque identifiers requiring manual review, rather than
  collapsing everything into "random UUID" or "opaque". Enumerability verdicts are unchanged (only the
  numeric schemes remain enumerable); the new variants are reported as leads, not synthetic guesses.

## [1.13.0] - 2026-08-02

### Auto-chain: SQLi → credential theft → authenticated probing
* New **`--chain`** flag (audit). On a **confirmed SQL injection**, the audit makes a bounded,
  best-effort attempt to **extract credentials** — it discovers the UNION column count, maps a
  readable string column, and brute-forces a short list of common `(table, user_col, pass_col)`
  combinations to dump `username`/`password` rows — then **feeds a recovered pair into the seed map**
  (by argument name) so **later probes can authenticate** and reach otherwise auth-gated sinks. It
  emits a `credential-exposure` finding (passwords masked in the report). Heuristic (targets lax DBs
  like SQLite/MySQL/Postgres with conventional table/column names), bounded (~40 requests), and
  opt-in (`--chain` implies `--injection`). *(DVGA, no `--seeds`: confirms SQLi → recovers
  `admin:changeme` → confirms the admin-gated `systemDiagnostics(cmd)` RCE — the full chain,
  automated.)*

## [1.12.4] - 2026-08-02

### Fair request budget across probes
* The global `--max-requests` budget is now **fair-shared** across the enabled fan-out probes
  (`unauth`, `mutation-privesc`, `sql-injection`, `os-command-injection`, `xss`): each gets an equal
  slice via a per-probe cap, so an early probe can no longer drain the whole budget before later ones
  run. Previously, under a tight `--max-requests`, `sql-injection` could consume everything and
  `os-command-injection` never got a turn. *(DVGA: `--only sql-injection,os-command-injection
  --max-requests 44` now confirms both, where before the command-injection sink was starved.)*

## [1.12.3] - 2026-08-02

### Detect exposed GraphQL IDEs
* The audit now flags an exposed in-browser **GraphQL IDE** (GraphiQL, GraphQL Playground, Altair,
  Voyager) as its own finding. It GETs the endpoint and common sibling paths (`/graphiql`,
  `/playground`, `/altair`, `/voyager`, `/console`) with `Accept: text/html` and matches IDE markers in
  the returned HTML (any `--cookie`/headers you pass are forwarded, so a cookie-gated IDE is still
  detectable). *(DVGA: confirms GraphiQL served at `/graphiql`.)*

## [1.12.2] - 2026-08-02

### IDOR probe works without session config (safe unauthenticated check)
* When no `session.auth_header`/`session.owned_ids` is configured, the `idor` probe no longer just
  reports "skipped". It now runs a **safe, read-only unauthenticated** check on the ID-taking **query**
  fields flagged passively: if a field returns **distinct objects for different IDs with no auth**, it
  reports *Unauthenticated Enumerable Object Access* (a BOLA/IDOR lead) with a PoC. It never touches
  mutations and **skips destructive-named query fields** (e.g. DVGA's `readAndBurn`) so it can't change
  server state. The authenticated cross-tenant test (with session config) is unchanged. *(DVGA: now
  flags `Query.users(id)` — reading arbitrary users by id unauthenticated — instead of skipping.)*

## [1.12.1] - 2026-08-02

### Output polish
* `brute` runs are now labelled **"Blind reconstruction (brute)"** in the report header instead of the
  misleading "Live scan (active probes enabled)".
* The audit's per-probe transient request errors (`! probe error: …`) are now only shown under
  `--verbose` — a single dropped request (common on a single-threaded dev server, already retried once)
  no longer looks like a defect in the default output.

## [1.12.0] - 2026-08-02

### Seed audit arguments by name (supply known credentials / tokens / ids)
* Audit seeds (`--seeds <FILE>` / `[audit.seeds]`) now match **by argument or input-field name** in
  addition to type name, with the **name match winning**. This lets you give distinct known values to
  sibling arguments of the same scalar type — e.g. `{"username":"admin","password":"changeme"}` — so an
  **auth-gated sink can be reached**. Previously seeds keyed only by type, so `username` and `password`
  (both `String`) were indistinguishable. Injection payloads still take precedence over any seed.
  *(DVGA: with the SQLi-recoverable admin creds seeded, `audit --injection` now also confirms the
  auth-gated `systemDiagnostics(cmd)` RCE — not just the unauthenticated `systemDebug(arg)`. Without the
  creds it correctly stays gated.)*

## [1.11.7] - 2026-08-02

### Audit prioritizes likely injection sinks
* Injection probes now rank their targets by **name affinity first**, then passive-finding severity —
  so a field/argument whose name suggests the relevant sink (e.g. `cmd`/`exec`/`debug`/`host` for
  command injection; `filter`/`search`/`id` for SQLi) is probed **before** passively-flagged but
  non-vulnerable fields. Previously, ranking was severity-only, so an obvious sink that no passive
  finding touched (e.g. DVGA's `systemDebug(arg)`) sorted last and could be **starved by the
  `--max-requests` budget** or the large-schema auto-cap. Applies to `sql-injection`,
  `os-command-injection`, and `xss` (SSRF is already driven by its passive finding). *(DVGA: a tight
  `--max-requests 30` now confirms the `systemDebug(arg)` RCE that a capped run previously missed.)*

## [1.11.6] - 2026-08-02

### `brute` now shows what it found
* A default `brute` run previously printed almost nothing (the reconstruction summary was
  `--verbose`-only, and the passive report was never rendered for `brute`), so it looked like it did
  nothing. Now it **always** prints a completion summary with the **list of discovered fields**, and
  it renders the full schema report (overview + findings) on the reconstructed schema, exactly like
  `scan`/`file`. *(Against DVGA it now reports the 9 recovered roots — `pastes`, `search`, `me`,
  `systemUpdate`, `systemDebug`, `systemHealth`, ….)*

## [1.11.5] - 2026-08-02

### `__type`-walk works against depth/complexity-limited servers
* Blind `__type`-walk reconstruction now succeeds on servers that reject deep introspection queries
  (query depth/complexity guards). `fetch_type` progressively falls back — full selection at depth 4,
  then depth 2, then a **stripped minimal query** (a shallow `ofType` chain, no args/enums/interfaces/
  possibleTypes) — and now retries on **transport errors** (some dev servers reset the connection on an
  over-deep query) instead of giving up, only concluding a type is absent on the final, simplest attempt.
  *(Against DVGA "Expert" mode — which has an aggressive depth guard — reconstruction went from a total
  failure with a misleading "Failed to parse JSON" message to recovering 8 types / 33 fields / 12
  queries.)*

## [1.11.4] - 2026-08-02

### Audit no longer gives up when introspection is blocked
* Previously, if a target had introspection disabled (and the `__type`-walk fallback failed), `audit`
  aborted and ran **no** probes at all. Now it continues with an empty schema and still runs the
  **schema-independent** probes (CSRF, introspection method matrix, `__typename`, CORS, APQ), printing a
  note that the schema is unavailable and pointing to `brute` / `--use-schema` for full coverage. The
  schema-dependent fan-out probes simply have no targets. (A hard bot-wall block is still fatal.)
  *(Surfaced by DVGA "Expert" mode — audit went from zero findings to confirming the introspection
  matrix and GraphQL behavior.)*

## [1.11.3] - 2026-08-02

### Audit: injection probes are now discoverable
* The injection-class probes (`sql-injection`, `os-command-injection`, `ssrf`, `xss`) are off by
  default (they send exploit-style payloads), which previously meant a plain `audit` silently skipped
  them. Now: a default `audit` prints a **notice** that they're disabled and how to enable them; the
  `--dry-run` preview **lists** the config-disabled probes instead of omitting them; and a new
  **`--injection`** flag enables them for the run. Naming any injection probe in `--only` (e.g.
  `--only sql-injection`) also enables it automatically. *(Surfaced by DVGA testing — a default audit
  was missing the target's SQLi.)*

## [1.11.2] - 2026-08-02

### Whole-database cache purge
* New global **`--purge-db`** flag wipes the **entire** cache database — every target's cached scan,
  learned seeds, and project records — in one go (the per-target `--purge-cache` only clears one). It
  runs **without a subcommand** and behind a **prominent confirmation**: it prints exactly what will be
  deleted (target/scan/seed counts) and requires you to type `yes`. Non-interactive/piped input that
  isn't `yes` aborts safely, so it can't fire unattended. Running with no subcommand and no `--purge-db`
  now prints a short usage hint.

## [1.11.1] - 2026-08-02

### Fixes
* **Guide overlay scrolls smoothly.** The Guide overlay used a full-screen `backdrop-filter` blur over
  the live WebGL canvas, so scrolling re-composited the blurred backdrop every frame and felt laggy.
  Replaced it with an opaque scrim (and isolated the content's scroll repaint); no visual change beyond
  a slightly darker dim.

## [1.11.0] - 2026-08-02

### In-app GraphQL security guide
* The visualizer gains a **Guide** button (top bar) that opens a self-contained, offline reference:
  what GraphQL is, the query language, the server ecosystem, and the attack vectors — introspection
  exposure, broken authorization / BOLA / IDOR (incl. Relay global-id enumeration), injection→sqlmap,
  DoS (depth/complexity/aliasing/batching), CSRF, and schema hygiene — each mapped to what
  Introspectre detects, plus a working-the-graph walkthrough. **Framework-aware:** when the target's
  server framework is fingerprinted, its section is surfaced first with a tailored note.

## [1.10.0] - 2026-08-02

### Target switcher
* The visualizer can now **switch between targets already cached** in `introspectre.db` from a top-bar
  dropdown — no re-scan and no network. The server lists cached projects (`GET /api/targets`) and
  reconstructs any target's full payload on demand (`GET /api/targets/:id/schema`) by re-running the
  passive analysis over its stored schema (on a blocking thread), replaying the cached fingerprint and
  learned seeds. Switching reloads the graph and panels in place.

## [1.9.2] - 2026-08-02

### Sample-query paths prefer satisfiable arguments
* The per-node **Sample Query** path search is now argument-aware. It became a weighted shortest-path
  (multi-source Dijkstra) that prefers the cheapest reachable entry point — an arg-free or simple-`id`
  field beats one requiring a complex input object, even at equal depth (e.g. `userById(id:)` over
  `search(input: SearchInput!)`). Generated queries also render **only required arguments**, keeping
  them minimal and runnable.

## [1.9.1] - 2026-08-02

### Visualizer fixes
* **Node dragging tracks the cursor.** Dragging previously over-moved and could fling a node
  out of view; it now uses a grab-offset (and suppresses camera panning during the drag) so the
  grab point stays exactly under the pointer at any zoom. Wheel / double-click zoom unchanged.
* **Per-node Sample Query is now a complete, runnable operation.** Instead of a bare selection
  stub, clicking a node shows the full `query { … }` that reaches it via the **shortest path from
  a root operation** — objects get a nested selection, scalars and enums get the leaf field path,
  and arguments along the way are filled from learned seeds or synthesized samples. (Computed with
  a single multi-source BFS over the type graph.) Types unreachable from any root fall back to a
  labeled selection fragment.
* **Copy omits comments.** Copying a query template now yields just the runnable query — the `#`
  hint/annotation lines are stripped from the clipboard while remaining visible on screen. (PoC,
  exploitation-guide, and sqlmap blocks are copied verbatim.)

## [1.9.0] - 2026-08-01

### Interactive visualizer is now a local web app
* `--visualize` no longer writes a static HTML file. It now starts a small local
  **web server** (bound strictly to `127.0.0.1`) that serves an interactive
  attack-surface workspace and exposes the analysis result as JSON at
  `GET /api/schema`; the frontend fetches that on load. The server runs in the
  foreground and stays alive until you press **Ctrl+C**.
* The flag is now a bare switch (`--visualize`, no path argument). Add `--port`
  to pick a port; the default is `7878` and it automatically **falls back** to a
  free port if that one is busy, so concurrent visualizers never clash. The URL is
  printed and your **default browser is opened** automatically (with a WSL/headless
  fallback that just prints the URL to open manually).
* **Rewritten frontend.** The graph is rendered on **WebGL** (Sigma.js + graphology)
  with Sigma's native camera, so wheel-zoom, drag-pan, and node selection are
  independent — clicking a node inspects it instead of hijacking the zoom. It keeps
  the search, scalar toggle, isolate/focus, reset, fit, right-click expansion
  (relations / all children / trace-to-root / hide), findings/seeds/schema panels,
  server-framework badge, and legend, in a dark workspace theme. All assets are
  embedded in the binary, so the server is fully self-contained and offline.
* **Workspace polish:** nodes are now **draggable** (wheel/double-click zoom
  unchanged); the node-detail panel shows a **Sample Query** for each node —
  root-operation fields get a ready-to-run operation template (with seed values
  and auth hints), other object types get a selection stub, and enums list their
  values; the **Schema** tab regains a full collapsible **type → field tree** (with
  enum values and click-to-focus) alongside the stat cards; and the detected
  **GraphQL framework/ecosystem** is always surfaced (shown as *undetected* when
  the fingerprint is inconclusive rather than silently omitted).

## [1.8.0] - 2026-08-01

### Result caching (default)
* `scan` and `brute` now **reuse the last cached schema for a target by default**, so re-running (for example after forgetting `--visualize`) regenerates the report **without another round of requests**. The schema is served from the local `introspectre.db`, findings are recomputed locally, and a notice shows the cache timestamp.
* New `--purge-cache` flag clears a target's cached scan and forces a fresh fetch.
* Live operations always fetch fresh and bypass the cache: `scan --static-only false` and `audit`.

### Blind reconstruction — graphql-ruby
* Fixed `brute`'s field-existence detection, which previously treated any error other than Apollo's `"Cannot query field"`/`"not defined"` as *field exists* — so against graphql-ruby servers (which say `"Field 'x' doesn't exist on type 'Query'"`) it marked essentially every probed word as real. It now recognises the graphql-ruby/other phrasings as *missing*, and treats selection/argument errors as *field exists*.
* `brute` now **captures leaked return types**: graphql-ruby answers an object field with `"field 'user' returns User but has no selections"`, so discovered fields come back **typed** (e.g. `user: User`) with stub type nodes added, instead of all-`String`.
* Introspection failures now surface the server's real GraphQL error on a non-2xx response (e.g. graphql-ruby's HTTP 422 `Field '__schema' doesn't exist on type 'Query'`) instead of a bare "HTTP 422".

### `__type`-walk
* The partial-schema cap warning is now shown **by default** (not only under `--verbose`), and the cap is **configurable** via `audit.max_type_walk_types` in config (default 1000; `0` = unlimited). The message points at the setting so a truncated reconstruction is obvious and adjustable.

### Settings
* New `config` command to view and edit `config.toml` without hand-editing: `config set <key> <value>` (e.g. `config set audit.max_type_walk_types 5000`), `config get <key>`, `config show`, and `config path`. Edits preserve existing comments and formatting.

### Node/Relay IDOR (active)
* New active `node-idor` audit probe that operationalizes the passive `node-idor-surface` flag. It obtains a real global id — from `--seeds`/`--seed-traffic`, else by fetching one of the tester's own accessible objects — base64-decodes it to classify the id **scheme** (`gid://host/Type/<int>`, `Type:<int>` and `Type-<int>` for the graphql-relay-JS and graphql-ruby node-id formats, bare int, UUID, type-tagged UUID, or opaque/signed), and, when the scheme is sequentially enumerable, reports a High-confidence IDOR with a concrete **adjacent-id PoC** (decode → change the counter → re-encode). Opaque/signed or UUID schemes are reported as non-enumerable (no over-fire). It also runs a conservative `node(id){ …on OtherType{…} }` **type-confusion** check for cross-type field leaks. Safe: only ids the tester can already read are used — no cross-tenant access, no mutations.

### Server-framework fingerprinting
* `scan`/`brute`/`audit` now identify the target's **GraphQL server framework** (graphw00f-style) and report it **during the run** (without `--verbose`), in the terminal summary, JSON/markdown (`server_fingerprint`), and the HTML report's header. The result is stored with the cached scan, so cache-served re-runs still show it (no re-probing). Detection combines schema-shape signals (Hasura's auto-generated `_by_pk`/`timestamptz`, Strapi/Prisma naming — free, no requests), response headers (`x-graphql-engine-version`, `apollo-cache-control`, `x-amzn-*`, `Server: Cowboy`, …), and a couple of benign error-probe signatures (graphql-ruby, Apollo/graphql-js, graphql-java/Spring, Hot Chocolate, Graphene, gqlgen, Absinthe, Sangria, and more). It is honest — it reports nothing rather than guess when unsure — and skippable via `--no-fingerprint`.
* Fixed: the `--purge-cache` / "using cached scan" notices were printed to stdout and could corrupt `--format json`/`markdown`; they now go to stderr.

### Exploitation guidance & live audit output
* Confirmed SQL/NoSQL **injection** findings now include a ready-to-run **sqlmap** command tailored to the endpoint and the injectable argument (the value marked with `*`), plus the saved-request (`-r req.txt`) method and an auth note. Shown in the terminal, JSON (`exploit_guide`), markdown, and the interactive HTML report. Introspectre confirms the flaw; sqlmap takes exploitation/extraction further.
* `audit --verbose` now prints a live `✓ FOUND: <title> [<id>]` line the moment a probe confirms a finding, instead of only in the final summary. Progress stays on stderr, so `--format json`/`markdown` stdout is unaffected; noisy per-target "Testing…" lines are now in-place/TTY-only.

### Blind discovery
* Expanded the built-in `brute` wordlist of common GraphQL root-field names, and fixed a bug where it was never actually used: without `-w`, `brute` now probes the **union** of the curated built-in list and your config-derived terms (~240 names, deduped) instead of only the config words.

## [1.7.0] - 2026-08-01

### Bot-management / WAF-aware diagnostics
* Endpoints fronted by a bot-management product (PerimeterX/HUMAN, Cloudflare, Akamai, DataDome, Imperva/Incapsula) are now recognised. When a challenge response (e.g. an HTTP 403/404 HTML "access denied"/captcha page returned *before* GraphQL is reached) is detected, `scan`/`audit` report the real cause and the vendor — instead of the misleading "introspection disabled — try `brute`" (which hits the same wall). Detection inspects the response status, headers, and body (a `px-captcha` page, a Cloudflare `__cf_bm` bot-management response, an Akamai/DataDome/Imperva signature, etc.) and is careful not to flag genuine JSON API auth errors.

### Session reuse for protected endpoints
* New global `--cookie "<raw cookie header>"` flag: pass a bot check in a real browser, then paste the resulting session cookies to reuse that session on every request.
* `--seed-traffic` (HAR / Burp XML) now also extracts and replays the captured request's `Cookie` / `Authorization` / custom `x-*` headers for the target host — not just variable values — so a recorded browser session can be replayed by the tool.
* This enables the legitimate authorized-testing workflow of reusing **your own** session; it does not bypass a bot wall autonomously.

### Requests
* Requests now send a realistic browser header baseline (`Accept`, `Accept-Language`). `--stealth` additionally sends Chromium client hints (`sec-ch-ua`, `sec-fetch-*`) and same-origin `Origin`/`Referer` — previously `--stealth` was a near-no-op.

### Verbose progress
* `--verbose` now shows live, per-request progress during long/looping operations (`__type`-walk reconstruction, `brute`, and each audit probe) instead of going silent. Output is two-tier: a **transient**, in-place status line (overwrites itself) for high-frequency "currently doing X" updates, and **persistent** lines for phase changes, warnings, and summaries you can read later in scrollback. All progress goes to stderr and the in-place updates are shown only on an interactive terminal, so piped output and `--format json`/`markdown` on stdout stay clean.

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
