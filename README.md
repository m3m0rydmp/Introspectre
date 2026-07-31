# Introspectre

Introspectre is a GraphQL **offensive security engine** built in Rust. It combines static schema analysis with active probing to surface logical flaws, implementation errors, and protocol-level risks in GraphQL APIs.

_Current version: **1.6.0** — see the [Changelog](./CHANGELOG.md)._

> [!TIP]
> **Documentation**
> * **[Architecture](./ARCHITECTURE.md)** — engine design: graph-centric schema modeling, the passive/active pipeline, and visual reporting.
> * **[Usage Guide](./USAGE.md)** — detailed, case-by-case command and flag reference.
> * **[Changelog](./CHANGELOG.md)** — release history.

Designed for security researchers and penetration testers, Introspectre emphasizes attack-surface visibility through field-centric graph visualization, and uses schema-derived and traffic-learned data to make active probes more likely to reach real backend logic.

> [!WARNING]
> **Authorized use only.** Introspectre sends active offensive payloads in `audit` and `scan --static-only false`. Only run it against systems you own or have explicit written permission to test. See [Legal & Ethical Use](#legal--ethical-use).

---

## Contents
- [Key Features](#key-features)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [Command Reference](#command-reference)
- [Configuration](#configuration)
- [Publishing to crates.io (maintainers)](#publishing-to-cratesio-maintainers)
- [Legal & Ethical Use](#legal--ethical-use)
- [License](#license)

---

## Key Features

### Discovery & Reconnaissance
* **Live introspection**: fetches the schema via fragmented introspection queries (for compatibility with length-limiting WAFs), or analyzes a local `schema.json` file.
* **Clairvoyance engine**: when introspection is disabled, reconstructs the schema by brute-forcing field names from a wordlist and exploiting GraphQL "Did you mean?" suggestions.
* **Auth guard mapping**: identifies which root fields respond as public versus protected, based on unauthenticated probes.
* **Backend fingerprinting**: flags likely backend technology (e.g., Prisma, Hasura, PyMySQL) from error signatures.

### Passive Schema Analysis
* **Circular reference detection**: flags recursive type relationships (e.g., `User -> Post -> User`) that can enable unbounded query depth.
* **Nested list inflation**: flags list-returning fields whose selections fan out into further lists.
* **Recursive mass assignment**: deep-scans `INPUT_OBJECT` structures for sensitive fields (e.g., `role`, `isAdmin`) hidden in nested arguments.
* **Information exposure**: flags sensitive field names, admin/internal-only types, and deprecated fields still returning data.
* **Complexity modeling**: represents the schema as a weighted directed multigraph to estimate which query paths are most resource-intensive.

### Active Auditing
Active probes attempt to *confirm* — not guarantee — the presence of a vulnerability by observing server behavior; results should still be manually verified.
* **Injection probing**: SQLi/NoSQLi (union- and operator-based), XSS, OS command injection, and SSTI.
* **IDOR/BOLA**: identifies identifier-shaped fields/arguments and probes them for unauthorized access.
* **SSRF**: tests URL/hostname-accepting fields.
* **Privilege escalation**: attempts registration/update mutations carrying administrative fields to check for improper trust of client input.
* **Denial-of-service probes**: alias amplification, query batching, and directive overloading, alongside passive circular-reference and unpaginated-list checks.
* **Evasion levels (0-3)**: query obfuscation to gauge WAF resilience.
* **JWT analysis**: flags common token misconfigurations in supplied bearer tokens.

### Data Synthesis (Seed Vault)
* **Scalar intelligence**: regex-based format guessing for common custom scalars (UUID, date, IP, etc.).
* **Traffic ingestion**: extracts realistic variable values and IDs from HAR or Burp XML logs.
* **Custom seeding**: `--seeds` accepts a JSON file of known-good values per type/field.
* **Persistence**: learned values are cached locally (SQLite) so probes stay high-fidelity across sessions.

### Reporting
* **Self-contained HTML report**: the interactive visual report bundles its own WebGL graph engine (Sigma.js and graphology) — it renders fully offline with no external CDN dependency.
* **Field-centric graph**: fields are the primary nodes, edges represent traversals, weights represent estimated cost.
* **Isolate mode & pathfinding**: isolate a single data path, or auto-generate the optimal query path to any field.
* **Embedded proofs**: findings in the visual report include ready-to-reproduce queries with the triggering payload inlined.
* **Structured findings**: text, JSON, and Markdown output, each finding broken into analysis, evidence, and remediation.

---

## Installation

### Prerequisites
Introspectre is built in Rust. Whether you install from crates.io or build from source, you need the Rust toolchain (`cargo`) installed.

#### Linux / macOS
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

#### Windows
Download and run [rustup-init.exe](https://rustup.rs/).

### From crates.io (recommended)
Install the latest published release with Cargo:
```bash
cargo install introspectre
```
This builds `introspectre` and installs it into `~/.cargo/bin` (make sure that directory is on your `PATH`). Verify with `introspectre --help`.

#### Updating
To move to a newer published release, re-run the install:
```bash
cargo install introspectre
```
Recent Cargo upgrades an existing install in place when a newer version is available. If Cargo reports the crate is *already installed*, force a reinstall of the latest version:
```bash
cargo install introspectre --force
```
Pin a specific release with `cargo install introspectre --version X.Y.Z`. To bulk-update every Cargo-installed binary at once, the optional [`cargo-update`](https://crates.io/crates/cargo-update) plugin adds `cargo install-update -a`. If you [built from source](#building-from-source) instead, update with `git pull` followed by `cargo build --release`.

### Building from Source
For the latest unreleased changes, or to hack on Introspectre, build from the repository instead:
1. Clone the repository:
   ```bash
   git clone https://github.com/m3m0rydmp/Introspectre.git
   cd Introspectre
   ```

2. Build with Cargo:
   ```bash
   cargo build --release
   ```

3. The binary is at `./target/release/introspectre`. Run it directly or move it onto your `PATH`:
   ```bash
   ./target/release/introspectre --help
   ```

---

## Quickstart

### Passive scan (default)
`scan` defaults to `--static-only true` — it only performs live introspection and passive schema analysis. No offensive payloads are sent unless you explicitly opt in (`--static-only false`) or run `audit`.
```bash
introspectre scan https://api.target.com/graphql --visualize report.html
```

### Active audit
```bash
introspectre audit https://api.target.com/graphql --visualize audit.html
```

### Traffic-informed scan
```bash
introspectre scan https://api.target.com/graphql --seed-traffic traffic.har
```

See [USAGE.md](./USAGE.md) for a full case-by-case walkthrough, including blind discovery when introspection is disabled.

---

## Command Reference

| Command | Description |
| :--- | :--- |
| `scan <url>` | Live introspection plus passive schema analysis. Passive-only by default; active probes only run if `--static-only false` is passed. |
| `audit <url>` | Active behavioral probing: attempts to confirm vulnerabilities against a live endpoint using schema-derived and seeded data. |
| `brute <url>` | Blind schema reconstruction when introspection is disabled — probes field names (optional `-w` wordlist) and harvests "Did you mean?" suggestions, then analyzes the result. |
| `file <path>` | Analyzes a previously saved introspection JSON file (no network requests). |

> [!NOTE]
> `scan` is **passive by default** — `--static-only` defaults to `true`. To include active probes in a `scan` run, pass `--static-only false`, or use `audit` directly for a dedicated active-probing pass.

### Global Flags
Available on every subcommand (see [USAGE.md](./USAGE.md) for the full per-command flag reference):

| Flag | Description |
| :--- | :--- |
| `--config <FILE>` | Path to a TOML config file. |
| `--wordlist <TYPE=PATH>` | Merge additional words into a pattern list (repeatable). |
| `--format text\|json\|markdown` | Output format (default `text`). |
| `--max-affected <N>` | Max affected entries shown per finding (default `30`, `0` = no limit). |
| `--min-severity <LEVEL>` | Only show findings at or above `low`/`medium`/`high`. |
| `-t, --token <TOKEN>` | Bearer token for authenticated requests. |
| `--user-agent <UA>` | Custom User-Agent string. |
| `--stealth` | Use a common browser User-Agent. |
| `--use-schema <FILE>` | Use a local schema JSON file instead of live introspection. |
| `--visualize [PATH]` | Generate the interactive HTML report (defaults to `introspectre-visual.html`). |
| `--seed-traffic <FILE>` | Learn variable values from a HAR or Burp XML file. |
| `--seeds <FILE>` | Provide known-good values via JSON. |
| `--verbose` | Include extra detail (e.g., PoC blocks) in text output. |

---

## Configuration
Introspectre loads `config.toml` from the current directory. Configurable parameters include:
* **Sensitive patterns**: keywords used to flag information exposure.
* **Audit toggles**: enable/disable specific probes (e.g., `test_injection`, `test_idor`).
* **Custom payloads**: your own offensive vectors.
* **Scope limits**: `max_targets_per_probe` / `max_total_requests` defaults (overridden by `--max-targets` / `--max-requests`).

### Auditing large schemas
On a schema with hundreds of mutations and thousands of fields, active probing can otherwise balloon to tens of thousands of requests. `audit` bounds this: `--dry-run` prints a per-probe request estimate and wall-clock cost; large schemas auto-cap each fan-out probe (ranked by passive-finding severity) unless you set `--max-targets`; and `--focus <Type|Type.field>` plus `--max-requests <N>` let you aim and budget a run. See [USAGE.md](./USAGE.md#large-schemas).

---

## Documentation

| Doc | What's in it |
| :-- | :-- |
| [USAGE.md](./USAGE.md) | Task-oriented CLI guide, safe-testing & large-schema flags, full flag reference. |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Engine internals: analysis graph, passive/active pipeline, visual report. |
| [CHANGELOG.md](./CHANGELOG.md) | Release history. |

Internal design/research/roadmap notes live in [`docs/`](./docs/README.md) (not shipped with the crate).

---

## Publishing to crates.io (maintainers)

Publishing to [crates.io](https://crates.io) is separate from pushing to GitHub, and it is **irreversible**: the crate name is claimed permanently, and a published version can only be *yanked* (hidden from new dependents), never deleted.

**Prerequisites**
- A crates.io account (sign in with GitHub) and a crates.io **API token** (Account Settings → API Tokens). This is a crates.io token — a GitHub token does **not** work for `cargo publish`.
- On Windows, build with the MinGW/GNU toolchain on `PATH` (this repo has no MSVC): `$env:Path = "$env:USERPROFILE\mingw64\bin;$env:Path"`.

**Steps**
1. Bump `version` in `Cargo.toml` (SemVer) and add matching entries to `CHANGELOG.md` and the version line near the top of this README. The CLI banner reads the crate version automatically.
2. Verify the package contents — confirm private files are excluded (`docs/*` and `resources/*` are excluded via `Cargo.toml`; the packaged tree should contain `src/**`, `Cargo.toml`, `README.md`, `LICENSE`, and the public root docs):
   ```bash
   cargo package --list
   ```
3. Dry-run (packages and builds from the packaged tree, uploads nothing):
   ```bash
   cargo publish --dry-run
   ```
4. Authenticate and publish:
   ```bash
   cargo login <your-crates-io-token>
   cargo publish
   ```

If a bad version ships, `cargo yank --version X.Y.Z` stops new projects from depending on it (existing users are unaffected). Prefer not to publish at all? Users can install straight from Git without a crates.io release:
```bash
cargo install --git https://github.com/m3m0rydmp/Introspectre
```

---
## Legal & Ethical Use

Introspectre is intended for **authorized security research, penetration testing, and defensive assessment only**.

- **Only** scan or audit systems you own or have **explicit, written permission** to test. The `audit` command and `scan --static-only false` send active payloads (injection strings, IDOR/BOLA probes, DoS-style requests) that may disrupt or alter target systems.
- Unauthorized access to or testing of computer systems is illegal in most jurisdictions (e.g. the U.S. Computer Fraud and Abuse Act, the U.K. Computer Misuse Act, and equivalents). You are solely responsible for complying with all applicable laws and with any program's rules of engagement / scope (including bug-bounty terms).
- This software is provided "as is", without warranty of any kind; the authors accept no liability for misuse or any damage arising from its use.

By using Introspectre you confirm you have authorization for every target you assess.

---

## License

Introspectre is released under the [MIT License](./LICENSE).

---

See [CHANGELOG.md](./CHANGELOG.md) for release history.
