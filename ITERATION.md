# Introspectre: Iteration & Improvement Tracker

This document serves as the central log for the development cycle of Introspectre. It tracks completed milestones, identified failures, architectural debt, and planned improvements.

## 1. Current State & Completed Milestones

### Core Architecture
- **Asynchronous Engine**: Fully migrated to `tokio` and `reqwest` for parallelized auditing.
- **Modular Analysis**: Security logic separated into `src/analysis/` (passive) and `src/audit/probes/` (active).
- **Configuration-Driven**: Patterns, keywords, and payloads externalized to `config.toml`.

### Feature Set
- **Passive Analysis**: Covers 16+ vulnerability classes including Circular Refs, Mass Assignment (deep recursion), and Information Exposure.
- **Active Probing**: Authentication discovery, IDOR, SSRF, and Complexity/Batching detection.
- **Clairvoyance Mode**: Schema reconstruction via field guessing and suggestion parsing.
- **Visual Reporting**: Interactive HTML reports with graph visualization and query templates.

---

## 2. Identified Failures & Technical Debt

### Payload Generation ("Semantic Blindness")
- **Issue**: `src/audit/utils.rs` generates static "blind" data (e.g., `"sample"`, `1`).
- **Status**: Partially addressed via `seed_map` and expanded heuristics. Still needs continuous refinement for rare custom scalars.

### Terminology & UI
- **Refinement**: Transitioned from "Findings" to "Possibilities" in passive analysis to better reflect probabilistic heuristics.

---

## 3. Improvement Roadmap (The Cycle)

### [MEDIUM PRIORITY] Smart GraphQL Value Generation & Operation Design
- [ ] **External Seed Injection**: Support for an external `seeds.json` mapping to allow users to provide valid database IDs or complex objects for specific schema types.
- [ ] **Custom Scalar Intelligence**: Enhance schema analysis to automatically detect and generate valid formats for unknown custom scalars based on their naming or surrounding context.
- [ ] **State-Aware "Next Level" Synthesis**: Implement a data-harvesting engine that can extract valid IDs/data from query responses and automatically "re-seed" them into mutations to test for IDOR and authorization bypasses on real data.

### [MEDIUM PRIORITY] UI/UX & Visualization (Hygraph Inspiration)
- [ ] **Contextual Action Menus**: Add ability to "Expand All Children," "Trace Path to Root," or "Generate Template" directly from the tree/graph interaction.
- [ ] **Dynamic Node UI**: Enhance the visual report to handle massive schemas through smarter clustering and "on-demand" rendering of tree branches.
- [ ] **Solo Mode: Root Node Expansion**: When Solo Mode is active and a Root node (Query/Mutation/Subscription) is selected, automatically expand and show all its top-level operations instead of just the root node.
- [ ] **Graph "Auto-Fit" Viewport**: Refactor graph selection behavior to automatically `fit()` the visible nodes (zoom out/adjust pan) to ensure all active nodes are visible in the viewport, rather than resetting and zooming in on a single point.

### [LOW PRIORITY] Reporting & DX
- [ ] **Unit Test Expansion**: Increase coverage for modular probe logic.
- [ ] **Export Options**: Add CSV export for raw data ingestion into other tools.

---

## 4. Done

### Core Architecture & Refactoring
- [x] **Unified Finding Model**: Refactor `Finding` and `AuditFinding` into a single lifecycle-based model (Inferred -> Possible -> Confirmed). Implement a structured `AffectedLocation` object to replace string-based labels. **Included actionable "First Step" recommendations** for all findings.
- [x] **Heuristic Scoring Engine**: Implement weighted scoring to escalate findings based on correlation (e.g., sensitive field + admin type + unauth access). Introduced **CRITICAL** severity level.
- [x] **PoC Factory**: Centralize query/curl generation into a dedicated engine for consistent, copy-pasteable reproduction steps.
- [x] **Persistent Project State**: Implement a centralized state management system (SQLite or `.introspectre/` directory).
- [x] **Asynchronous Engine**: Fully migrated to `tokio` and `reqwest` for parallelized auditing.
- [x] **Modular Analysis**: Security logic separated into `src/analysis/` and `src/audit/probes/`.

### Auditing & Evasion
- [x] **Expanded DoS Vector Coverage**: Implemented Directive Overloading, Field Duplication, and active **Recursive Query verification** probes.
- [x] **Engine Fingerprinting (graphw00f-style)**: Identify backend technology (Graphene, Apollo, etc.) via malformed queries to tailor payloads.
- [x] **CSRF & Method Evasion**: Probes to test for state-changing operations allowed via `GET` or `application/x-www-form-urlencoded` POST requests.
- [x] **Mutation Privilege Escalation**: Active auditing for sensitive arguments in mutations (role, isAdmin, etc.) to detect mass assignment and auth bypasses.
- [x] **SQL Injection (SQLi) Probe**: Implement UNION-based and error-based SQLi testing for query and mutation arguments (`sqli.rs`).
- [x] **Cross-Site Scripting (XSS) Probe**: Implement automated testing for reflection of XSS payloads in GraphQL error messages and response data (`xss.rs`).
- [x] **Dynamic Throttling**: Automatically adjust delay (Audit) and concurrency (Brute/Discover) based on server response latency.
- [x] **Evasion Testing**: Implemented query obfuscation levels (whitespace, comments, line endings) in `src/audit/utils.rs`.
- [x] **Active Probing**: Authentication discovery, IDOR, SSRF, and Complexity/Batching detection.

### Smart Payload Engine
- [x] **Advanced Data Synthesis**: Heuristics engine matching field names to realistic mock data.
- [x] **Traffic-Driven Value Learning (The Seed Vault)**: HAR/Burp log ingestion for real query/variable extraction.
- [x] **Seeded Payloads**: Support for `seed_map` in `resolve_complex_default` for user-provided valid arguments.
- [x] **Intelligent Query Generation**: Support for deep `INPUT_OBJECT` structures and Operation Definitions with Variables.

### UI/UX & Reporting
- [x] **Graph "Solo Mode" Toggle**: Added a toggle to automatically hide previous selections in the graph, keeping the view focused and uncluttered.
- [x] **Hierarchical Tree Visualization**: Browsable tree structure in visual report.
- [x] **Bidirectional Interaction**: Sync between tree and graph views.
- [x] **Bloodhound-like Graph**: Interactive node expansion and BFS-based path discovery.
- [x] **Interactive Seed Explorer**: Sidebar section for discovered valid data points and hot-swappable templates.
- [x] **JWT Passive Analysis (Phase 2)**: Integrated misconfiguration checking (alg: none, expired, sensitive claims).

### Auditing & Analysis
- [x] **Alias-DoS Refactor**: Transitioned `alias_dos.rs` to use centralized `build_field_call` utility for smarter query generation.
- [x] **Historical Context (Refactored)**: Merged previous improvements to reporting and versioning.
