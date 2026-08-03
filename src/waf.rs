//! Bot-management / WAF challenge detection.
//!
//! Some GraphQL endpoints sit behind a bot-management product (PerimeterX/HUMAN,
//! Cloudflare, Akamai, DataDome, Imperva/Incapsula) that returns an HTTP
//! challenge — typically `403`/`503` with a captcha or "access denied" page —
//! *before the request ever reaches GraphQL*. When that happens, introspection,
//! `__type`-walk, and `brute` all fail identically for the same reason, and the
//! usual "introspection disabled" advice is misleading.
//!
//! This module inspects a failed HTTP response (status + headers + body) and,
//! when it recognises a known bot-defense fingerprint, names the vendor so the
//! caller can report the real cause and point the user at the legitimate path:
//! reuse a browser session (cookies) captured after passing the challenge.
//!
//! Detection is a pure function over already-fetched response data — no I/O —
//! so it is fully unit-testable.

use std::collections::HashMap;

/// A recognised bot-management / WAF challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotWall {
    /// Human-readable vendor name, e.g. "PerimeterX / HUMAN".
    pub vendor: &'static str,
    /// Actionable, vendor-specific remediation hint for the operator.
    pub hint: String,
}

/// The session-reuse guidance shared across vendors: pass the challenge in a
/// real browser, then hand the resulting session to the tool.
fn session_hint(cookies: &str) -> String {
    format!(
        "Pass the challenge once in a real browser, then reuse that session: copy the \
         relevant cookies (e.g. {cookies}) into `--cookie \"<paste>\"`, or capture the \
         GraphQL request as a HAR and pass `--seed-traffic <file.har>` (its cookies/auth \
         headers are replayed automatically). This is not something the tool can bypass \
         on its own."
    )
}

/// Inspect a *failed* HTTP response for a known bot-management fingerprint.
///
/// `headers` must have lowercased names; multi-valued headers (notably
/// `set-cookie`) should be joined into a single value. `body` is the raw
/// response text (may be empty or, if compression wasn't decoded, binary — the
/// header/cookie checks still apply). Returns `None` when nothing matches.
pub fn detect_bot_wall(status: u16, headers: &HashMap<String, String>, body: &str) -> Option<BotWall> {
    let get = |k: &str| headers.get(k).map(|s| s.as_str()).unwrap_or("");
    let server = get("server").to_ascii_lowercase();
    let cookies = get("set-cookie").to_ascii_lowercase();
    let content_type = get("content-type").to_ascii_lowercase();
    let body_l = body.to_ascii_lowercase();

    // Challenge responses are almost always these statuses; used to gate the
    // weaker (Cloudflare) signal so a normal 200 behind Cloudflare isn't flagged.
    let challengeish = matches!(status, 401 | 403 | 405 | 406 | 429 | 503);

    // A GraphQL endpoint answers with JSON even for errors. A non-2xx response
    // that is HTML (or otherwise not JSON) means the request did not reach a
    // GraphQL resolver — it was answered by an edge/CDN/bot layer. Used to tell
    // a real API auth error (JSON) apart from an edge block (HTML page).
    let non_json_body = {
        let t = body.trim_start();
        !content_type.contains("json") && !t.starts_with('{') && !t.starts_with('[')
    };

    // PerimeterX / HUMAN Security — strongest, most specific signatures.
    if body_l.contains("px-captcha")
        || body_l.contains("_pxappid")
        || body_l.contains("window._pxuuid")
        || body_l.contains("_pxhosturl")
        || cookies.contains("_px")
    {
        return Some(BotWall {
            vendor: "PerimeterX / HUMAN",
            hint: session_hint("`_px3`, `_pxhd`, `__cf_bm`"),
        });
    }

    // DataDome.
    if cookies.contains("datadome") || body_l.contains("datadome") || !get("x-datadome").is_empty() {
        return Some(BotWall {
            vendor: "DataDome",
            hint: session_hint("`datadome`"),
        });
    }

    // Imperva / Incapsula.
    if cookies.contains("visid_incap")
        || cookies.contains("incap_ses")
        || body_l.contains("_incapsula_resource")
    {
        return Some(BotWall {
            vendor: "Imperva / Incapsula",
            hint: session_hint("`visid_incap_*`, `incap_ses_*`"),
        });
    }

    // Akamai (Bot Manager / Ghost).
    if server.contains("akamaighost")
        || cookies.contains("ak_bmsc")
        || cookies.contains("_abck")
        || (challengeish && body_l.contains("reference #") && body_l.contains("akamai"))
    {
        return Some(BotWall {
            vendor: "Akamai",
            hint: session_hint("`_abck`, `ak_bmsc`, `bm_sz`"),
        });
    }

    // Cloudflare. `__cf_bm` is the Cloudflare Bot Management cookie; combined
    // with a failing, non-JSON (HTML) response it means the request was answered
    // by Cloudflare's edge/bot layer rather than a GraphQL resolver. An explicit
    // challenge marker also qualifies regardless of body. A Cloudflare-fronted
    // API that returns a JSON auth error is deliberately NOT flagged.
    let cf_present =
        server.contains("cloudflare") || !get("cf-ray").is_empty() || cookies.contains("__cf_bm");
    let cf_challenge_marker = !get("cf-mitigated").is_empty()
        || cookies.contains("cf_clearance")
        || body_l.contains("attention required")
        || body_l.contains("challenge-platform")
        || body_l.contains("cf-error-details");
    if cf_present
        && (challengeish || status == 404)
        && (cf_challenge_marker || non_json_body)
    {
        return Some(BotWall {
            vendor: "Cloudflare",
            hint: session_hint("`cf_clearance`, `__cf_bm`"),
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn detects_perimeterx_from_real_priceline_body() {
        // Trimmed from the actual 403 body served by Priceline's endpoint.
        let body = r#"<!DOCTYPE html><html><head>
            <meta name="description" content="px-captcha">
            <title>Access to this page has been denied</title></head>
            <body><script>window._pxUuid = '07fc...';
            window._pxAppId = 'PX9aTjSd0n';
            window._pxHostUrl = '/9aTjSd0n/xhr';</script></body></html>"#;
        let h = hdr(&[("server", "cloudflare"), ("set-cookie", "__cf_bm=abc; Path=/")]);
        let w = detect_bot_wall(403, &h, body).expect("should detect");
        assert_eq!(w.vendor, "PerimeterX / HUMAN");
        assert!(w.hint.contains("--cookie"));
    }

    #[test]
    fn detects_datadome_via_cookie() {
        let h = hdr(&[("set-cookie", "datadome=xyz; Secure")]);
        assert_eq!(detect_bot_wall(403, &h, "").unwrap().vendor, "DataDome");
    }

    #[test]
    fn detects_imperva_via_cookie() {
        let h = hdr(&[("set-cookie", "visid_incap_123=abc")]);
        assert_eq!(detect_bot_wall(403, &h, "").unwrap().vendor, "Imperva / Incapsula");
    }

    #[test]
    fn detects_akamai_via_server_and_cookie() {
        let h = hdr(&[("server", "AkamaiGHost"), ("set-cookie", "ak_bmsc=zzz")]);
        assert_eq!(detect_bot_wall(403, &h, "").unwrap().vendor, "Akamai");
    }

    #[test]
    fn detects_cloudflare_challenge_only_on_challenge_status() {
        let body = "<title>Attention Required! | Cloudflare</title>";
        let h = hdr(&[("server", "cloudflare"), ("cf-ray", "abc123")]);
        // 403 challenge -> detected
        assert_eq!(detect_bot_wall(403, &h, body).unwrap().vendor, "Cloudflare");
        // 200 with the same CF headers but no challenge marker -> not flagged
        assert!(detect_bot_wall(200, &h, "{\"data\":{}}").is_none());
    }

    #[test]
    fn detects_cloudflare_html_404_edge_block() {
        // The real Priceline case: request reaches origin behind Cloudflare and
        // gets an HTML 404 page (not GraphQL JSON), with the CF bot-management
        // cookie set. That's an edge/session gate, not a real endpoint.
        let body = r#"<!DOCTYPE HTML><html><head><title>404 Error - Priceline.com</title></head></html>"#;
        let h = hdr(&[
            ("server", "cloudflare"),
            ("cf-ray", "a23e68aeafea0574-HKG"),
            ("content-type", "text/html; charset=utf-8"),
            ("set-cookie", "__cf_bm=kReGFW...; HttpOnly; Secure"),
        ]);
        assert_eq!(detect_bot_wall(404, &h, body).unwrap().vendor, "Cloudflare");
    }

    #[test]
    fn no_false_positive_on_plain_403() {
        // A genuine GraphQL auth error behind no bot wall must NOT be flagged.
        let h = hdr(&[("content-type", "application/json"), ("server", "nginx")]);
        assert!(detect_bot_wall(403, &h, r#"{"errors":[{"message":"Unauthorized"}]}"#).is_none());
    }

    #[test]
    fn no_false_positive_on_json_auth_error_behind_cloudflare() {
        // A Cloudflare-fronted API that returns a JSON auth error is a real API
        // response, not an edge block — must NOT be flagged.
        let h = hdr(&[
            ("server", "cloudflare"),
            ("cf-ray", "abc"),
            ("content-type", "application/json"),
            ("set-cookie", "__cf_bm=x"),
        ]);
        assert!(detect_bot_wall(403, &h, r#"{"errors":[{"message":"Unauthorized"}]}"#).is_none());
    }

    #[test]
    fn no_false_positive_on_success() {
        let h = hdr(&[("server", "cloudflare"), ("cf-ray", "x")]);
        assert!(detect_bot_wall(200, &h, r#"{"data":{"__typename":"Query"}}"#).is_none());
    }
}
