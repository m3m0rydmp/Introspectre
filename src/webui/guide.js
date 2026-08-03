/* Curated, self-contained GraphQL security reference for the visualizer's Guide overlay.
 * `frameworks` maps a lowercase substring of the detected server fingerprint to a short note
 * that the overlay surfaces first when it matches. Content is static and offline. */
window.INTROSPECTRE_GUIDE = {
    frameworks: {
        "graphql-ruby": "graphql-ruby (Ruby). Often pairs with Rails — watch for `node(id:)`/Relay global IDs (Base64 `Type-<int>`), mass-assignment via input objects, and authorization done in resolvers rather than a policy layer. Errors like \"Field 'x' doesn't exist on type 'Query'\" leak field existence during brute-forcing.",
        "apollo": "Apollo / graphql-js (Node). Check for introspection left on in production, query-depth/complexity limits absent, and CSRF on GET queries. Apollo's error `Did you mean \"...\"?` suggestions accelerate schema recovery.",
        "graphql-js": "graphql-js (Node). Reference implementation — 'Did you mean?' suggestions and permissive introspection are common; look for missing depth/complexity guards.",
        "hasura": "Hasura (Haskell/Postgres). Auto-generated CRUD (`*_by_pk`, `*_aggregate`, `where`/`_eq` filters) exposes the DB shape directly — test row-level permissions, `x-hasura-*` role headers, and unbounded filter/aggregate queries.",
        "graphene": "Graphene (Python). Relay nodes are common; check `node(id:)` global-ID enumeration and Django ORM-backed filters for IDOR.",
        "gqlgen": "gqlgen (Go). Strongly typed; focus on authorization gaps in resolvers and directive-based auth that may not cover every field.",
        "hot chocolate": "Hot Chocolate (.NET). Check for introspection/banana-cake-pop left enabled and missing paging/complexity limits.",
        "absinthe": "Absinthe (Elixir/Phoenix). Look for missing complexity analysis and authorization in resolvers.",
        "sangria": "Sangria (Scala). Check query-complexity/depth limits and field-level auth.",
        "strapi": "Strapi (Node CMS). Public vs authenticated content types are a frequent misconfig — test the default roles/permissions and the REST/GraphQL parity.",
        "prisma": "Prisma-backed API. Filter arguments mirror the DB; probe `where`/relation filters and nested writes for over-permissive access.",
    },
    sections: [
        {
            id: "intro",
            title: "What GraphQL is",
            html: `<p>GraphQL is a query language for APIs served over a <b>single endpoint</b> (usually <code>POST /graphql</code>). The server publishes a strongly-typed <b>schema</b>; clients ask for exactly the fields they want and get back JSON of the same shape.</p>
            <p>For an attacker, the schema is a map of the entire backend surface. Three things make GraphQL distinctive to test:</p>
            <ul>
              <li><b>One endpoint, many operations</b> — traditional per-URL access control doesn't map cleanly; authorization has to happen per field/object.</li>
              <li><b>Client-controlled shape</b> — the client decides depth, breadth, and aliasing of a query, which is the root of most DoS and over-fetch issues.</li>
              <li><b>Introspection</b> — the schema itself is queryable, so recon is often trivial.</li>
            </ul>`,
        },
        {
            id: "language",
            title: "The query language",
            html: `<p>Operations: <code>query</code> (read), <code>mutation</code> (write), <code>subscription</code> (stream).</p>
            <pre class="code">query {
  user(id: "1") {      # a field with an argument
    id
    email
    posts { title }    # nested selection
  }
}</pre>
            <ul>
              <li><b>Arguments</b> parametrize fields (<code>user(id: "1")</code>).</li>
              <li><b>Variables</b> (<code>query($id: ID!){ user(id:$id){…} }</code>) separate data from the query.</li>
              <li><b>Aliases</b> let one request ask the same field many times — <code>a: user(id:"1") b: user(id:"2")</code> — the basis of batching/enumeration.</li>
              <li><b>Fragments</b> reuse selections and, as inline fragments (<code>... on Type</code>), select from interfaces/unions.</li>
              <li><b>Introspection</b> (<code>__schema</code>, <code>__type</code>) returns the full type system. When it's disabled, field names can still be brute-forced via error "Did you mean?" hints.</li>
            </ul>`,
        },
        {
            id: "ecosystem",
            title: "The ecosystem",
            html: `<p>The wire protocol is standard, but each server implementation has its own tells (error phrasing, auto-generated fields, headers) — which is what fingerprinting keys on, and it shapes where the bugs tend to be.</p>
            <table class="kv">
              <tr><td class="k">Apollo / graphql-js</td><td class="v">Node. "Did you mean?" suggestions; introspection often on.</td></tr>
              <tr><td class="k">graphql-ruby</td><td class="v">Ruby/Rails. Relay node IDs; resolver-level auth.</td></tr>
              <tr><td class="k">Hasura</td><td class="v">Auto CRUD over Postgres; <code>_by_pk</code>/<code>_aggregate</code>/<code>where</code>.</td></tr>
              <tr><td class="k">Graphene</td><td class="v">Python/Django; Relay nodes.</td></tr>
              <tr><td class="k">gqlgen</td><td class="v">Go; directive-based auth.</td></tr>
              <tr><td class="k">Hot Chocolate</td><td class="v">.NET.</td></tr>
              <tr><td class="k">Absinthe</td><td class="v">Elixir/Phoenix.</td></tr>
              <tr><td class="k">Strapi / Prisma</td><td class="v">Node; DB-shaped filters &amp; permissions.</td></tr>
            </table>
            <p>Introspectre fingerprints the server (see the <b>Schema</b> tab) and adapts its guidance; the detected framework is highlighted at the top of this guide.</p>`,
        },
        {
            id: "attacks",
            title: "Attack vectors",
            html: `<p>Each maps to something Introspectre flags in the graph and Findings panel.</p>
            <h5>Introspection &amp; information exposure</h5>
            <p>A queryable schema hands over the attack surface. Even with introspection off, verbose errors and "Did you mean?" hints leak it. Introspectre reconstructs the schema (introspection, <code>__type</code>-walk, or brute) and flags sensitive fields (tokens, secrets, emails, PII).</p>
            <h5>Broken authorization — BOLA / IDOR</h5>
            <p>The most common and highest-impact GraphQL bug: a field returns an object by ID without checking ownership. Relay <b>global IDs</b> are just Base64 <code>Type:&lt;int&gt;</code> — decode, change the integer, re-encode, and you may read another tenant's object. Introspectre's <code>node-idor</code> probe decodes the scheme and generates the ±1 PoC; the graph marks ID-accepting fields.</p>
            <h5>Injection</h5>
            <p>Arguments flow into SQL/NoSQL/OS commands server-side. Introspectre probes injectable argument paths and, on a hit, emits a ready <b>sqlmap</b> command (see a finding's Exploitation guide).</p>
            <h5>Denial of service</h5>
            <p>Because the client shapes the query: <b>deep nesting</b> through circular type references, <b>query complexity</b>, <b>alias amplification</b> (same costly field many times), <b>field duplication</b>, and <b>batching</b> (array of operations). Introspectre detects circular references (three-color DFS) and the DoS-class conditions, and estimates blast radius.</p>
            <h5>CSRF</h5>
            <p>If mutations are accepted over <code>GET</code> or <code>application/x-www-form-urlencoded</code> without a CSRF token, they can be triggered cross-site. Introspectre flags GET/form-accepting endpoints.</p>
            <h5>Schema hygiene</h5>
            <p>Deprecated-but-live fields, overly large attack surface, and missing auth directives are reported as lower-severity findings worth reviewing.</p>`,
        },
        {
            id: "workflow",
            title: "Working the graph",
            html: `<p>A practical loop with this visualizer:</p>
            <ol>
              <li><b>Recon</b> — read the <b>Schema</b> tab for size and the detected framework; skim <b>Findings</b> by severity.</li>
              <li><b>Map</b> — start at the <code>Query</code>/<code>Mutation</code> roots, expand toward sensitive types (colored by risk). Drag nodes to arrange; use search to jump.</li>
              <li><b>Reach</b> — click a node for its <b>Sample Query</b> — a complete, runnable operation reaching it from a root (shortest satisfiable path). Copy it (comments are stripped) into your client.</li>
              <li><b>Probe</b> — for a finding, open it for the query template, PoC, and exploitation guide; confirm manually against your own objects/sessions.</li>
              <li><b>Pivot</b> — switch targets from the dropdown to compare cached schemas without re-scanning.</li>
            </ol>
            <p class="guide-note">Only test targets you're authorized to test. Sample queries and PoCs are starting points — validate impact responsibly.</p>`,
        },
    ],
};
