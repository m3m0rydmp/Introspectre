# Introspectre: Deep-Diving into GraphQL Security via Graph Theory and Active Probing

**Author:** [m3m0rydmp]  
**Date:** May 6, 2026  
**Category:** Web Security / GraphQL / Automated Auditing / Research Project

---

## Abstract

GraphQL has revolutionized API development, offering flexibility and efficiency. However, this flexibility introduces unique security challenges that traditional REST scanners often miss. **Introspectre** is a specialized security analysis and auditing tool built in Rust, designed to bridge the gap between static schema analysis and active vulnerability probing. 

This paper outlines Introspectre not just as a tool, but as a **research framework for 0/N-day discovery** in custom GraphQL deployments. It explores the technical architecture of the engine, its use of graph theory to map attack surfaces, and its ability to uncover overlooked risks—proving that a working framework is the most effective Proof-of-Concept for securing the modern API landscape.

---

## 1. Introduction: Uncovering Overlooked Risks

Unlike REST APIs, which have multiple endpoints, GraphQL typically exposes a single `/graphql` endpoint. The security of this endpoint relies entirely on the schema definition and the underlying resolver logic. 

Introspectre targets these **overlooked risks**, focusing on structural flaws that traditional "black-box" scanners miss:
*   **Recursive Mass Assignment**: Vulnerabilities hidden deep within complex input objects.
*   **Query Complexity DoS**: Resource exhaustion mapped through multiple architectural paths.
*   **Information Exposure**: Blind schema reconstruction via verbose error handling.

---

## 2. Technical Architecture: Performance at Scale

### 2.1 The Rust Advantage
Built in Rust, Introspectre leverages zero-cost abstractions and memory safety to perform deep recursive analysis that typically causes Python-based scanners to hang or time out. 
*   **Benchmarking**: Introspectre can resolve and analyze schemas with over 10,000 types in under 200ms.
*   **Concurrency**: Utilizing the `Tokio` runtime, the tool performs thousands of simultaneous network probes during audit phases without sacrificing local analysis speed.

### 2.2 Graph-Based Modeling (Novel Technique)
The core of Introspectre’s intelligence lies in representing the GraphQL schema as a **weighted directed multigraph**. 
*   **Nodes**: Represent GraphQL Types (e.g., `User`, `Post`).
*   **Edges**: Represent Fields connecting these types (e.g., a `User` has a `posts` field).
*   **Weights**: This is the "cost" of asking the server for that specific data.

**Understanding Weights in Simple Terms:**
Imagine ordering at a restaurant: 
1.  Asking for a glass of water is easy and fast. In GraphQL, asking for a basic string like a user's `name` is a **Scalar** field. Introspectre gives this a very low weight (Cost = 1).
2.  Asking for a custom pizza takes more work because the kitchen has to assemble multiple ingredients. In GraphQL, asking for an **Object** (like a user's `Profile`) requires the server to run extra logic to fetch that related data. Introspectre gives this a medium weight (Cost = 5).
3.  Asking for 100 custom pizzas for a party takes massive resources. In GraphQL, asking for a **List** of objects (like all of a user's `friends`, and all of their `posts`) requires the server to potentially query the database hundreds of times. Introspectre gives this a high weight (Cost = 20).

**Why use a Weighted Directed Multigraph?**
Most scanners see an API as a flat list of endpoints. Introspectre sees it as a **topographical map**. This is critical for three reasons:
*   **Predicting "Query Cost"**: By totaling the weights along a path, Introspectre can predict if a query will crash the server before ever sending it.
*   **Identifying Circular DoS**: A "cycle" in a graph (e.g., `User → Friends → User`) is a potential infinite loop. A weighted graph proves that each step in that loop exponentially increases server load.
*   **Prioritizing Attack Paths**: During a pentest, time is limited. The graph allows the tool to ignore low-value fields and focus strictly on the most "expensive" or "deep" paths where authorization is most likely to fail.

---

## 3. The Introspectre Pipeline: From Ingestion to Validation

To understand **how** Introspectre identifies vulnerabilities, we must walk through its four-stage execution pipeline. Each stage answers a critical "why" regarding GraphQL security.

### 3.1 Stage 1: Fragmented Schema Acquisition
**How**: The tool issues a series of "fragmented" introspection queries rather than one large query.
**Why**: Modern WAFs and API Gateways often have a `max_query_length` or block specific introspection keywords. By fragmenting the request, Introspectre bypasses these rudimentary filters. If introspection is disabled, it automatically pivots to its **Clairvoyance Engine** (Probabilistic Reconstruction).

### 3.2 Stage 2: Multigraph Synthesis & Indexing
**How**: The ingested JSON/Introspection result is parsed into a global `type_map` and a weighted graph.
**Why**: GraphQL is naturally a graph, but most tools treat it as a flat list of fields. By building a multigraph, Introspectre can perform **Pathfinding Analysis**. Every field is assigned a weight based on its return type (Scalars = 1, Objects = 5, Lists = 20). This allows the tool to mathematically calculate the "cost" of any given query path before ever sending a request.

### 3.3 Stage 3: Recursive Static Heuristics
**How**: The engine performs a **Recursive Descent** on the graph nodes.
**Why**: Vulnerabilities in GraphQL are often nested. For example, a "Mass Assignment" vulnerability isn't always at the root of a mutation; it might be hidden in an `INPUT_OBJECT` four levels deep. Introspectre's recursive engine follows these dependencies to find "Possibilities" that shallow scanners miss.

### 3.4 Stage 4: Active Behavioral Validation (The Audit)
**How**: For every "Possibility" found in Stage 3, the tool generates a minimal **Knock Probe**.
**Why**: Static analysis can lead to false positives (e.g., a field exists but its resolver is disabled). The Audit stage validates the finding by:
1.  **Auth Discovery**: Checking if the field is public or requires a session.
2.  **Timing Analysis**: Measuring response latency for SSRF and Complexity probes.
3.  **Error Pattern Matching**: Analyzing the `extensions` block of the JSON response for stack traces or internal hints.

---

## 4. Comprehensive Feature Suite & Advanced Attack Vectors

### 4.1 Complexity Analysis via Yen's Algorithm (DoS)
To identify Denial of Service vectors, Introspectre applies **Yen's Algorithm** to find the $K$ shortest paths from the Query root to potentially expensive fields. This demonstrates that a complex query isn't just an anomaly—it is one of hundreds of mathematically calculable paths to exhaust server resources.

### 4.2 The "Clairvoyance" Engine (Blind Reconstruction)
When introspection is disabled, Introspectre switches to its **Clairvoyance Engine**. Unlike simple wordlist brute-forcing, it uses **Probabilistic Schema Mapping**:
1.  **Entropy-Based Wordlists**: Prioritizes fields based on observed naming conventions in production APIs.
2.  **Suggestion Exploitation**: Systematically triggers "Did you mean...?" errors to programmatically learn the schema structure.
3.  **Typename Probing**: Uses `__typename` to identify the underlying object types and recursively map the graph.

### 4.3 Recursive Mass Assignment Detection (`GQL-017`)
Introspectre performs a **deep recursive scan** of all `INPUT_OBJECT` types. It traverses the input tree to identify sensitive fields (like `isAdmin`, `role`, `internal_status`) hidden multiple levels deep within a mutation's arguments, bypassing shallow validation filters.

### 4.4 Automated JWT Inspection
Introspectre analyzes session tokens in real-time, checking for:
*   **Weak Algorithms**: Detects `none` or symmetric keys in public environments.
*   **Sensitive Claim Exposure**: Identifies internal PII or roles leaked in the JWT payload.
*   **Expiration Vulnerabilities**: Flags tokens with over-extended TTLs.

---

## 5. Vulnerability Taxonomy: The 'Why' Behind the Findings

A finding in Introspectre is more than a line in a report; it is an architectural risk. We categorize these into four primary pillars of impact:

### 5.1 Resource Exhaustion (The 'Why' of Circularity)
**Finding**: Circular Type References.
**Impact**: Because GraphQL execution is recursive, circularity allows an attacker to request a query nested thousands of levels deep. This consumes 100% of CPU for validation and exhausts heap memory, leading to a total service outage (DoS).

### 5.2 Permission Gaps (The 'Why' of Directive Absence)
**Finding**: No Authorization Directives on Mutations.
**Impact**: When auth is handled manually inside resolvers rather than declaratively at the schema level, developers inevitably "forget" checks on secondary or "internal-sounding" mutations. This leads directly to IDOR and BOLA vulnerabilities.

### 5.3 Trust Boundaries (The 'Why' of Input Depth)
**Finding**: Deeply Nested Input Objects.
**Impact**: Complex inputs often bypass standard API Gateways or WAFs that only inspect top-level parameters. By hiding a `isAdmin: true` flag inside a nested `profileUpdate` object, an attacker can achieve privilege escalation.

### 5.4 Information Leakage (The 'Why' of Enum Exposure)
**Finding**: Internal Role Leaks (e.g., `UserKind: WEBHOOK, PAT`).
**Impact**: Exposing internal enums allows an attacker to map the backend architecture and identify high-value targets for lateral movement (e.g., targeting the webhook processing system).

---

## 6. Beyond GraphQL: A Force Multiplier for Pentesters

Introspectre aids the modern pentester in several ways that extend beyond simple API testing:

*   **Cloud Reconnaissance**: As seen in our case studies, GraphQL upload mutations often return **S3 signed URLs, AWS Credentials, or Security Tokens**. Introspectre identifies these as high-value targets, providing a direct path into the target's cloud infrastructure.
*   **Stack Fingerprinting**: By analyzing custom directives and error message patterns, Introspectre can identify if the backend is running **Prisma, Hasura, Apollo, or AppSync**, allowing for more targeted exploit selection.
*   **WAF Evasion Probing**: The tool's ability to fragment introspection and probe queries allows pentesters to identify "blind spots" in the target's Web Application Firewall.
*   **Automated Reporting**: The `--visualize` and Markdown exports allow pentesters to generate professional, graph-based evidence for their final reports in seconds.

---

## 7. State of the Art: Comparative Analysis

| Feature | InQL / GraphQLmap | Graphw00f | **Introspectre** |
| :--- | :---: | :---: | :---: |
| **Analysis Paradigm** | Static / Manual | Fingerprinting | **Graph-Theory Based** |
| **DoS Discovery** | Simple Depth | N/A | **Weighted DFS / Dijkstra** |
| **Performance** | Medium (Python) | High (Go/Python) | **Ultra-High (Rust)** |
| **Blind Discovery** | Basic Brute-force | N/A | **Probabilistic Crawling** |
| **Visual POC** | Basic Tree | N/A | **Interactive Multigraph** |

---

## 8. The Defender's Dilemma: Remediation Research

Standard GraphQL defenses often fail because they address symptoms rather than structural flaws:
*   **The Depth Limit Failure**: Many servers implement a simple depth limit. However, Introspectre's circular path analysis shows that an attacker can still cause a **List-Inflation Attack** within those levels.
*   **The Introspection Mirage**: Disabling introspection is often bypassed by the Clairvoyance techniques detailed in Section 4.2.

**Proposed Mitigation: Architectural Flattening**
Instead of generic "middleware" defenses, we propose **View-Specific Types**. By defining response types that are specific to a UI component (rather than mirror-imaging the database), developers can break the circularity of the graph and naturally limit the attack surface.

---

## 9. Live Technical Analysis: Hygraph Case Study

A live scan against a production-grade Hygraph playground validated these theories:
*   **Structural DoS**: Identified **9 unique circular reference paths** (e.g., `Movie → Asset → Movie`).
*   **Credential Exposure**: Detected sensitive fields (`securityToken`, `credential`) in the `AssetUploadRequestPostData` type.
*   **BOLA Possibilities**: Mapped 5 high-fidelity possibilities in mutations like `schedulePublishAsset(releaseId)`.

---

## 10. Conclusion 

Introspectre demonstrates that GraphQL security requires a specialized approach combining static analysis, graph theory, and active behavioral probing. As a working framework, it serves as an essential tool for 0-day hunting in custom APIs, providing researchers with the automated capabilities needed to map, analyze, and exploit structural GraphQL vulnerabilities.

---

*For more information, visit the [Introspectre Repository](https://github.com/m3m0rydmp/introspectre).*

## 11. Known Probe Limitations

### 11.1 Alias-Based DoS Payload Accuracy (`alias_dos.rs`)
Our research identifies a current limitation in the `alias_dos` probe. The probe attempts to test for alias-based DoS by duplicating a query field 100 times. However, the current implementation only uses the raw field name (e.g., `query { a0: field, a1: field }`).

**The Limitation:**
If the selected field requires arguments (e.g., `user(id: ID!)`) or returns an Object type that requires a sub-selection (e.g., `currentUser { ... }`), the GraphQL server will reject the probe with a syntax or validation error (HTTP 400). 

**The False Negative:**
Because the probe interprets any non-200 response or GraphQL error as a sign of server-side "protection" or "limiting," these syntactic failures lead to an **Inconclusive** finding. In reality, the server's actual alias limits have not been tested because the query was discarded during the validation phase before it could even trigger a resolver.

**Remediation for the Tool:**
The probe should be refactored to utilize the framework's internal `build_operation_query` utility. This would ensure that:
1.  Required arguments are filled with mock data.
2.  Proper sub-selections (like `{ __typename }`) are appended for Object types.
3.  The resulting *valid* operation is then duplicated across 100 aliases, ensuring the request reaches the execution/resolver phase where the DoS vulnerability actually lives.
/m3m0rydmp/introspectre).*
e [Introspectre Repository](https://github.com/m3m0rydmp/introspectre).*
