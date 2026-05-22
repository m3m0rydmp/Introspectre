# Introspectre

<<<<<<< HEAD
Introspectre is a comprehensive security analysis and auditing utility designed for GraphQL schemas. The tool integrates static schema analysis with active probing to detect vulnerabilities such as Insecure Direct Object References (IDOR), Mass Assignment, Sensitive Data Exposure, and various Denial of Service (DoS) attack vectors.

## Installation and Setup

### 1. Requirements
Introspectre is developed in Rust. The Rust toolchain must be installed on the host system:
*   **Unix-based systems (Linux/macOS):** `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
*   **Windows:** Download and execute the [rustup-init.exe](https://rustup.rs/) installer.

### 2. Building from Source
Clone the repository and compile the project using Cargo:
```bash
git clone https://github.com/m3m0rydmp/introspectre.git
cd introspectre
cargo build --release
=======
Introspectre is a professional GraphQL security auditing tool that combines static schema analysis with advanced active probing. It is designed to identify implementation-specific risks, protocol-level vulnerabilities, and complex authorization bypasses.

## Core Features

- **Passive Analysis**: Identifies Circular Refs, Mass Assignment, Sensitive Data Exposure, and 16+ other vulnerability classes.
- **Active Probing**: 
    - **Injection**: Automated SQL Injection (SQLi) and Cross-Site Scripting (XSS) testing.
    - **Authorization**: IDOR/BOLA detection and Mutation Privilege Escalation probes.
    - **DoS**: Directive/Field Overloading and active Recursive Query verification.
    - **Protocol**: CSRF method evasion (GET/URL-encoded) and Engine Fingerprinting (Apollo, Graphene, Hasura, etc.).
- **Smart Recon**: "Clairvoyance" mode for schema reconstruction when introspection is disabled.
- **Actionable Reporting**: Interactive HTML visual reports with graph exploration, "Solo Mode", and copy-pasteable PoCs (curl/GraphQL).

## CLI Usage

```text
Usage: introspectre [OPTIONS] <COMMAND>

Commands:
  scan   Retrieve schema and execute static + behavioral analysis
  audit  Execute intrusive active probes (Injection, IDOR, DoS, CSRF)
  file   Analyze a local introspection JSON file
  help   Display help information
>>>>>>> update-research-refs
```
The compiled binary will be available at `./target/release/introspectre`.

<<<<<<< HEAD
### Platform Dependencies
*   **Linux:** Systems require `pkg-config` and OpenSSL development headers (e.g., `libssl-dev` or `openssl-devel`).
*   **Windows:** Requires Visual Studio Build Tools with the "Desktop development with C++" workload.

## CLI Usage and Commands

```text
Usage: introspectre [OPTIONS] <COMMAND>

Commands:
  scan   Retrieve schema via live introspection and execute static analysis
  audit  Execute active probing based on schema-derived candidates
  file   Analyze a local introspection JSON file
  help   Display help information
```

### Scan Command Parameters
*   `--discover-auth`: Identifies protected and public root fields through unauthenticated probes.
*   `--static-only`: Disables active payload probing; recommended for non-intrusive assessments.
*   `--probe-first`: Validates the GraphQL endpoint state prior to introspection.
*   `--rate-limit-ms <MS>`: Specifies the client-side delay between requests (default: 750ms).

### Audit Command Parameters
*   `--idor-payloads <IDS>`: Configures specific identifier values for IDOR testing.
*   `--rate-limit-ms <MS>`: Adjusts request frequency to mitigate potential rate-limiting or WAF interference.

## Assessment Strategies

### Passive Analysis
Suitable for environments where network traffic or server state changes must be minimized.
```bash
# Analyze a local schema file
introspectre file schema.json

# Perform read-only static analysis on a live endpoint
introspectre scan https://api.example.com/graphql --static-only
```

### Discovery and Behavioral Probing
Evaluates authentication mechanisms and endpoint resilience.
```bash
# Map authentication requirements and validate endpoint behavior
introspectre scan https://api.example.com/graphql --discover-auth --probe-first
```

### Active Auditing
Performs intrusive testing using generated payloads. This mode should be used with caution as it may generate security alerts or impact system performance.
```bash
# Execute active probes for IDOR, SSRF, and complexity-based DoS
introspectre audit https://api.example.com/graphql --rate-limit-ms 1000 --idor-payloads "1,100,2024"
```

## Configuration
Security patterns and wordlists can be customized via a `config.toml` file:
```bash
introspectre --config custom_config.toml scan <URL>
```

Refer to [ARCHITECTURE.md](./ARCHITECTURE.md) for detailed technical specifications.
=======
### Key Flags
*   `--discover-auth`: Map protected vs public root fields.
*   `--visualize <PATH>`: Generate an interactive HTML graph report.
*   `--evasion <LEVEL>`: Apply query obfuscation (1-3) to test WAF/IDS resilience.
*   `--dynamic-throttling`: Adjust request speed based on server latency.
*   `--header <KV>`: Add custom headers (e.g., `-H "Authorization: Bearer ..."`).
*   `--max-affected <N>`: Limit the number of affected items shown per finding.

## Quick Start

```bash
# Full automated audit with visual report
introspectre scan https://api.target.com/graphql --visualize report.html

# Dedicated injection and IDOR testing
introspectre audit https://api.target.com/graphql --idor-payloads "1,2,3"
```

## Configuration
Customize sensitive patterns and probe behavior in `config.toml`.

Refer to [ARCHITECTURE.md](./ARCHITECTURE.md) for deep technical specifications and heuristics.
>>>>>>> update-research-refs
