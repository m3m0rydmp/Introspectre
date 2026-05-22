# Introspectre Features

Introspectre is a GraphQL security auditing tool that combines static schema analysis with active behavioral probing. Below is a comprehensive list of its current features.

## 1. Schema Discovery and Retrieval
*   **Live Introspection**: Automatically retrieves the full schema from a GraphQL endpoint using optimized, fragmented queries for compatibility.
*   **Local File Analysis**: Supports analyzing local `schema.json` files for offline or pre-deployment assessments.
*   **Clairvoyance Mode**: Programmatically reconstructs the schema even when introspection is disabled by:
    *   Brute-forcing root fields using optimized wordlists.
    *   Leveraging GraphQL's "Did you mean?" suggestions.
    *   Recursive field and type discovery through error signal analysis.

## 2. Static Security Analysis
The tool performs deep analysis of the schema structure to identify potential design flaws:
*   **Information Exposure**:
    *   Detection of sensitive field names (e.g., `password`, `email`, `token`).
    *   Identification of administrative or internal-only types.
    *   Flagging of deprecated fields that may still expose data.
*   **Denial of Service (DoS) Heuristics**:
    *   **Circular References**: Detects recursive type relationships (e.g., `User -> Posts -> User`) that allow deeply nested queries.
    *   **List Inflation**: Identifies fields that return lists of objects containing further list fields, enabling resource exhaustion.
*   **Access Control & Logic**:
    *   **Mass Assignment (GQL-017)**: Deep recursive scan of `INPUT_OBJECT` types to find sensitive fields (e.g., `role`, `isAdmin`) in mutations.
    *   **IDOR/BOLA Discovery (GQL-013)**: Heuristic identification of fields and arguments accepting identifiers (e.g., `uuid`, `userId`) for targeting.
*   **JWT Analysis**: Analyzes provided authentication tokens for common misconfigurations or sensitive data leakage.

## 3. Active Auditing & Probing
Introspectre can execute safe, behavioral probes against a live endpoint to validate vulnerabilities:
*   **Authentication Discovery**: Maps which root fields are public vs. protected by analyzing unauthenticated request failures.
*   **Denial of Service Probes**:
    *   **Alias DoS**: Tests endpoint resilience against queries containing thousands of field aliases.
    *   **Batching**: Checks for support of array-based query batching, which can bypass rate limits.
    *   **Complexity Assessment**: Analyzes response headers and JSON extensions for internal cost-tracking or throttling mechanisms.
*   **Vulnerability Probing**:
    *   **Active IDOR Testing**: Injects user-provided payloads into identified IDOR candidates to check for unauthorized access.
    *   **SSRF Probing**: Tests fields that accept URLs or hostnames for potential Server-Side Request Forgery.
*   **Environment Fingerprinting**:
    *   **Error Disclosure**: Analyzes error responses for stack traces, database information, or verbose debugging data.
    *   **Typename Probe**: Basic endpoint verification and WAF (Web Application Firewall) behavior assessment.

## 4. Advanced Engine Capabilities
*   **Graph-Based Analysis**: Models the schema as a weighted directed graph to find the globally optimal (least-complex) path to sensitive fields using Yen's Algorithm.
*   **High Performance**: Built in Rust with asynchronous I/O (Tokio) and constant-time type indexing for handling massive schemas.
*   **Customizable Heuristics**: Allows tailoring security patterns and sensitive keywords via `config.toml`.
*   **Evasion & Stability**: Includes built-in client-side rate limiting and throttled execution to avoid triggering WAFs or impacting server stability.

## 5. Reporting
*   **Visual HTML Reports**: Generates interactive reports including:
    *   Vulnerability summaries and risk ratings.
    *   Schema multigraph visualizations.
    *   Detailed evidence for each finding.
*   **Detailed Statistics**: Provides metrics on schema size, type distribution, and field deprecation.
