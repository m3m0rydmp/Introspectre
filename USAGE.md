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

### Case: Manually supplied seed values
```bash
introspectre audit http://target.com/graphql --seeds ./seeds.json
```
`seeds.json` maps a type or field name to a literal value, e.g. `{ "UserID": "\"user-123\"", "Email": "\"test@example.com\"" }`.

---

## 6. Flag Reference

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
