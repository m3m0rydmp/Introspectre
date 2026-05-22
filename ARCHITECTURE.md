# Introspectre: Technical Architecture

<<<<<<< HEAD
This document provides a technical overview of the internal design, performance optimizations, and security heuristics employed by Introspectre.

## 1. Data Collection and Introspection

Introspectre retrieves the GraphQL schema directly from the target server using the Introspection Engine.

### Introspection Query
The tool utilizes a comprehensive query to extract types, fields, arguments, enums, unions, and directives. To ensure compatibility with legacy or strictly configured servers, a fragmented query structure is implemented:

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind name description
      fields(includeDeprecated: true) {
        name isDeprecated deprecationReason
        type { ...TypeRef }
        args { name type { ...TypeRef } }
      }
      inputFields { name type { ...TypeRef } }
      # Additional schema details
    }
  }
}
```

## 2. Performance Optimizations

Scanning large schemas containing thousands of types requires efficient data structures. Introspectre optimizes this process by constructing an in-memory index immediately after schema retrieval, avoiding inefficient linear searches.

### Indexing Strategy
The tool utilizes hash maps to facilitate constant-time resolution of types during analysis:

```rust
// Implementation example in src/analysis/information_exposure.rs
let type_map: HashMap<&str, &GqlType> = schema.types.iter()
    .filter_map(|t| t.name.as_deref().map(|n| (n, t)))
    .collect();
```

This indexing strategy allows for instantaneous resolution of `INPUT_OBJECT` references during Mass Assignment checks, eliminating the need to re-scan the type list for every mutation.

## 3. Security Heuristics

### Mass Assignment Detection (`GQL-017`)
This heuristic identifies mutations that accept complex objects containing internal fields that match sensitive keywords.

**Detection Methodology:**
1. Enumerate all fields within the `Mutation` root.
2. Resolve the `INPUT_OBJECT` type for each argument.
3. Recursively examine the input type for fields matching sensitive patterns (e.g., `isAdmin`, `role`, or `status`).

```rust
for f in &mutation_fields {
    for arg in args {
        if let Some(input_type) = type_map.get(input_type_name) {
            if let Some(input_fields) = &input_type.input_fields {
                for input_field in input_fields {
                    if matches_pattern(&input_field.name, &patterns.sensitive_fields.names) {
                        // Potential Mass Assignment identified
                    }
                }
            }
        }
    }
}
```

### Denial of Service (DoS) Analysis
Introspectre identifies structural weaknesses that could facilitate query complexity attacks.

*   **Circular References (`GQL-003`)**: Detected by constructing a graph of type relationships and identifying cycles (e.g., `User` -> `Posts` -> `User`).
*   **List Inflation (`GQL-DOS-001`)**: Identifies fields returning lists of objects that themselves contain list-returning fields.

### IDOR / BOLA Discovery (`GQL-013`)
The tool employs an extensive prefix list to identify fields that accept identifiers.

```rust
let idor_arg_matches = |arg_name: &str| {
    let lower = arg_name.to_lowercase();
    matches!(lower.as_str(), "id" | "uuid" | "userid")
        || lower.ends_with("id")
        || lower.ends_with("_id")
};
```

## 4. Active Probing Lifecycle

The `audit` command initiates an active discovery phase:

1.  **Endpoint Verification (Knock Probe)**: Executes a single `__typename` query to confirm endpoint availability and assess basic Web Application Firewall (WAF) behavior.
2.  **Authentication Discovery**: Issues throttled requests for root fields without credentials. The resulting error responses are analyzed for authorization failure patterns.
3.  **Complexity Probing**: Executes multiple aliased queries to determine if the server returns cost-related headers or JSON extensions, revealing internal throttling thresholds.

## 5. Technology Stack
*   **Rust**: Provides memory safety, performance, and high concurrency.
*   **Tokio**: Serving as the asynchronous runtime for parallel network operations.
*   **Reqwest**: Utilized as the HTTP client for its support of custom headers and timeouts.
*   **Clap**: Employed for robust command-line argument parsing.
=======
This document provides a technical overview of the internal design, security heuristics, and advanced auditing logic employed by Introspectre.

## 1. Unified Finding Model

Introspectre implements a lifecycle-based finding system that unifies passive schema analysis with active audit results.

### Finding Lifecycle
1.  **INFERRED**: A theoretical vulnerability identified via static schema heuristics (e.g., a sensitive field name).
2.  **POSSIBLE**: An active probe was executed but yielded inconclusive results (e.g., an IDOR test that returned null data but no error).
3.  **CONFIRMED**: An active probe successfully verified the vulnerability (e.g., an SQL injection that triggered a database error).

### Affected Location Tracking
Instead of string-based labels, the tool uses a structured `AffectedLocation` enum to track vulnerabilities:
*   **Type**: Vulnerability affects an entire GraphQL object (e.g., an Admin type).
*   **Field**: Affects a specific field (e.g., an unpaginated list).
*   **Argument**: Affects a specific operation argument (e.g., an IDOR or SQLi vector).

## 2. Heuristic Scoring Engine

The Scoring Engine (`src/analysis/scoring.rs`) applies cross-vulnerability correlation rules to refine risk assessment.

### Escalation Logic
- **Confirmed Impact**: If an active probe confirms a High severity finding on a path containing keywords like "token" or "credential", it is escalated to **CRITICAL**.
- **Auth Correlation**: Findings on fields that were confirmed as **PUBLIC** during Auth Discovery are automatically escalated.
- **Administrative Context**: Vulnerabilities affecting types with "Admin", "Internal", or "Setup" in their names are assigned a baseline severity of High.

## 3. Active Auditing Probes

### Injection Auditing
- **SQLi (`sqli.rs`)**: Injects UNION-based and boolean payloads into string/ID arguments. Detection is based on an extensive list of database error signatures (MySQL, PG, SQLite, etc.).
- **XSS (`xss.rs`)**: Injects browser-executable payloads and monitors for unsanitized reflection in either the `data` payload or the GraphQL `errors` array.

### Denial of Service (DoS)
- **Directive Overloading**: Monitors server latency when processing queries with 100+ duplicated `@include`/`@skip` directives.
- **Recursive Verification**: Actively follows circular paths found in passive analysis to a depth of 10 levels. If the server processes these without limits, the DoS is marked as Confirmed.

### Protocol Evasion
- **CSRF Check**: Tests if the endpoint accepts state-changing operations via `GET` or `application/x-www-form-urlencoded` POST requests.
- **Evasion Engine**: Applies three levels of query obfuscation (whitespace randomization, comment injection, and line-ending manipulation) to test WAF/IDS resilience.

## 4. Evidence & PoC Factory

The PoC Factory (`src/audit/poc.rs`) centralizes the generation of reproduction steps. It ensures that every finding includes:
- **Actionable Recommendation**: A non-destructive "First Step" for manual verification.
- **Copy-Pasteable Proof**: Either a direct `curl` command or a formatted GraphQL operation.
- **Context-Aware Payload**: Logic automatically adds required sub-selections (e.g., ` { id }`) to generated queries based on the schema.

## 5. Technology Stack
*   **Rust**: Memory-safe performance.
*   **Tokio & Reqwest**: Asynchronous network I/O with custom throttling.
*   **Rusqlite**: Local project state and seed persistence.
*   **Cytoscape.js**: Powering the interactive visual graph report.
>>>>>>> update-research-refs
