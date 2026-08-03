use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct HarRoot {
    log: HarLog,
}

#[derive(Debug, Deserialize)]
struct HarLog {
    entries: Vec<HarEntry>,
}

#[derive(Debug, Deserialize)]
struct HarEntry {
    request: HarRequest,
    response: HarResponse,
}

#[derive(Debug, Deserialize)]
struct HarRequest {
    method: Option<String>,
    url: Option<String>,
    #[serde(default)]
    headers: Option<Vec<HarHeader>>,
    #[serde(rename = "postData")]
    post_data: Option<HarPostData>,
}

#[derive(Debug, Deserialize)]
struct HarHeader {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct HarPostData {
    #[serde(rename = "mimeType")]
    mime_type: Option<String>,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HarResponse {
    status: u16,
}

// --- Burp Suite "Save items" XML export ---

#[derive(Debug, Deserialize)]
struct BurpRoot {
    #[serde(rename = "item", default)]
    item: Vec<BurpItem>,
}

#[derive(Debug, Deserialize)]
struct BurpItem {
    url: Option<String>,
    method: Option<String>,
    request: Option<BurpBody>,
    status: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct BurpBody {
    #[serde(rename = "@base64", default)]
    base64: Option<String>,
    #[serde(rename = "$text", default)]
    text: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TrafficSeed {
    pub field_name: String,
    pub type_name: String,
    pub value: String,
    pub source: String,
}

/// A parsed traffic capture (either supported format).
enum TrafficDoc {
    Har(HarRoot),
    Burp(BurpRoot),
}

/// Parse a traffic file **streaming from a buffered reader**, so the whole file is not held as a
/// `String` in addition to the parsed structure — a meaningful peak-memory reduction on large HAR /
/// Burp exports. HAR (JSON) is tried first, then a Burp Suite "Save items" XML export. (The parsed
/// structure is still materialised; a full zero-DOM event stream is a possible further step.)
fn load_traffic(path: &Path) -> Option<TrafficDoc> {
    if let Ok(file) = File::open(path) {
        if let Ok(har) = serde_json::from_reader::<_, HarRoot>(BufReader::new(file)) {
            return Some(TrafficDoc::Har(har));
        }
    }
    if let Ok(file) = File::open(path) {
        if let Ok(burp) = quick_xml::de::from_reader::<_, BurpRoot>(BufReader::new(file)) {
            return Some(TrafficDoc::Burp(burp));
        }
    }
    None
}

pub fn parse_traffic_file(path: &Path) -> Result<Vec<TrafficSeed>, String> {
    match load_traffic(path) {
        Some(TrafficDoc::Har(har)) => Ok(extract_from_har(har)),
        Some(TrafficDoc::Burp(burp)) => Ok(extract_from_burp(burp)),
        None => Err("Unsupported traffic file format. Supported formats: HAR (.har JSON export) and Burp Suite \"Save items\" XML export.".to_string()),
    }
}

/// A request header worth replaying to re-use a captured browser session:
/// cookies, bearer/authorization, and custom `x-*` auth/session headers.
fn wanted_session_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "cookie" || n == "authorization" || n.starts_with("x-")
}

/// Extract the host (`host[:port]`) from a URL without a URL-crate dependency.
fn host_of(url: &str) -> String {
    match url.split_once("://") {
        Some((_, tail)) => tail.split(['/', '?', '#']).next().unwrap_or("").to_ascii_lowercase(),
        None => String::new(),
    }
}

/// Extract session/auth request headers (Cookie, Authorization, `x-*`) from a
/// captured HAR/Burp file, restricted to entries whose host matches the target
/// endpoint. Returned as `key=value` strings ready for the `--header` pipeline.
/// Later entries win on a name conflict, and GraphQL-looking requests are
/// preferred (scanned last). Empty vec if the file can't be parsed or matched.
pub fn extract_session_headers(path: &Path, target_url: &str) -> Vec<String> {
    let Some(doc) = load_traffic(path) else {
        return vec![];
    };
    let target_host = host_of(target_url);
    if target_host.is_empty() {
        return vec![];
    }

    // name(lowercased) -> "Name: preserved" value, so we can dedupe by name but
    // emit the original header name.
    let mut chosen: std::collections::HashMap<String, (String, String)> = std::collections::HashMap::new();
    let mut consider = |name: &str, value: &str| {
        if wanted_session_header(name) && !value.trim().is_empty() {
            chosen.insert(name.to_ascii_lowercase(), (name.to_string(), value.to_string()));
        }
    };

    if let TrafficDoc::Har(har) = &doc {
        // Non-graphql entries first, graphql-looking ones last, so the latter win.
        let mut entries: Vec<&HarEntry> = har.log.entries.iter().collect();
        entries.sort_by_key(|e| {
            let u = e.request.url.clone().unwrap_or_default().to_ascii_lowercase();
            u.contains("graphql") // false(0) sorts before true(1)
        });
        for entry in entries {
            let url = entry.request.url.clone().unwrap_or_default();
            if host_of(&url) != target_host {
                continue;
            }
            if let Some(hs) = &entry.request.headers {
                for h in hs {
                    consider(&h.name, &h.value);
                }
            }
        }
    } else if let TrafficDoc::Burp(burp) = &doc {
        for item in &burp.item {
            let item_url = item.url.clone().unwrap_or_default();
            let Some(request) = &item.request else { continue; };
            let raw_text = request.text.clone().unwrap_or_default();
            let raw = match request.base64.as_deref() {
                Some("true") => String::from_utf8_lossy(&STANDARD.decode(raw_text.trim()).unwrap_or_default()).to_string(),
                _ => raw_text,
            };
            let normalized = raw.replace("\r\n", "\n");
            let head = normalized.splitn(2, "\n\n").next().unwrap_or("");
            let mut lines = head.lines();
            let _request_line = lines.next();
            let mut host = host_of(&item_url);
            let mut pending: Vec<(String, String)> = Vec::new();
            for line in lines {
                if let Some((k, v)) = line.split_once(':') {
                    let (k, v) = (k.trim(), v.trim());
                    if k.eq_ignore_ascii_case("host") && host.is_empty() {
                        host = v.to_ascii_lowercase();
                    }
                    pending.push((k.to_string(), v.to_string()));
                }
            }
            if host != target_host {
                continue;
            }
            for (k, v) in pending {
                consider(&k, &v);
            }
        }
    }

    chosen
        .into_values()
        .map(|(name, value)| format!("{}={}", name, value))
        .collect()
}

fn extract_from_har(har: HarRoot) -> Vec<TrafficSeed> {
    let mut seeds = Vec::new();

    for entry in har.log.entries {
        if entry.response.status != 200 { continue; }

        let method = entry.request.method.clone().unwrap_or_else(|| "POST".to_string());
        let url = entry.request.url.clone().unwrap_or_default();
        let (content_type, body) = match &entry.request.post_data {
            Some(post_data) => (
                post_data.mime_type.clone().unwrap_or_else(|| "application/json".to_string()),
                post_data.text.clone().unwrap_or_default(),
            ),
            None => ("application/json".to_string(), String::new()),
        };

        seeds.extend(extract_seeds_from_request(&method, &url, &content_type, &body, "HAR Traffic"));
    }

    seeds
}

fn extract_from_burp(burp: BurpRoot) -> Vec<TrafficSeed> {
    let mut seeds = Vec::new();

    for item in burp.item {
        // Prefer the explicit top-level <status>200</status> element when present.
        // If it's absent, don't hard-require 200 — just attempt extraction anyway.
        if let Some(status) = item.status {
            if status != 200 { continue; }
        }

        let Some(request) = item.request else { continue; };
        let raw_text = request.text.unwrap_or_default();
        let raw = match request.base64.as_deref() {
            Some("true") => {
                let decoded = STANDARD.decode(raw_text.trim()).unwrap_or_default();
                String::from_utf8_lossy(&decoded).to_string()
            }
            _ => raw_text,
        };

        let Some((method, url_from_line, content_type, body)) = parse_raw_http_request(&raw) else { continue; };

        // Prefer the item's own <url> (a full URL) over the request-line path.
        let url = item.url.clone().unwrap_or(url_from_line);
        let method = item.method.clone().unwrap_or(method);

        seeds.extend(extract_seeds_from_request(&method, &url, &content_type, &body, "Burp Traffic"));
    }

    seeds
}

/// Parse a raw HTTP request (as saved by Burp's base64-encoded `<request>` field)
/// into `(method, url_or_path, content_type, body)`.
fn parse_raw_http_request(raw: &str) -> Option<(String, String, String, String)> {
    // Normalize line endings so the header/body split works regardless of
    // whether Burp used CRLF or LF.
    let normalized = raw.replace("\r\n", "\n");
    let mut parts = normalized.splitn(2, "\n\n");
    let head = parts.next()?;
    let body = parts.next().unwrap_or("").to_string();

    let mut lines = head.lines();
    let request_line = lines.next()?;
    let mut rl_parts = request_line.split_whitespace();
    let method = rl_parts.next()?.to_string();
    let path = rl_parts.next()?.to_string();

    let mut content_type = String::new();
    let mut host = String::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if k.eq_ignore_ascii_case("content-type") {
                content_type = v.to_string();
            } else if k.eq_ignore_ascii_case("host") {
                host = v.to_string();
            }
        }
    }

    // Reconstruct a full URL from Host + path when possible, so the GET
    // query-string carrier below has something to work with.
    let url = if path.starts_with("http://") || path.starts_with("https://") {
        path
    } else if !host.is_empty() {
        format!("https://{}{}", host, path)
    } else {
        path
    };

    Some((method, url, content_type, body))
}

/// Extract GraphQL `variables` values from a single captured request, checking
/// all three carriers a GraphQL request can use: a JSON body, a GET query
/// string, and a form-urlencoded body.
fn extract_seeds_from_request(
    _method: &str,
    url: &str,
    content_type: &str,
    body: &str,
    source: &str,
) -> Vec<TrafficSeed> {
    let mut seeds = Vec::new();

    // 1. JSON body: parse body as JSON, read the "variables" object.
    if let Ok(json) = serde_json::from_str::<Value>(body) {
        if let Some(variables) = json.get("variables").and_then(|v| v.as_object()) {
            push_variable_seeds(&mut seeds, variables, source);
        }
    }

    // 2. GET query string: parse `url`'s query string for a `variables=` param.
    if let Some(query_str) = url.split('?').nth(1) {
        if let Some(vars_json) = extract_query_param(query_str, "variables") {
            if let Ok(parsed) = serde_json::from_str::<Value>(&vars_json) {
                if let Some(variables) = parsed.as_object() {
                    push_variable_seeds(&mut seeds, variables, source);
                }
            }
        }
    }

    // 3. form-urlencoded body: parse `body` for a `variables=` param.
    if content_type.to_lowercase().contains("x-www-form-urlencoded") {
        if let Some(vars_json) = extract_query_param(body, "variables") {
            if let Ok(parsed) = serde_json::from_str::<Value>(&vars_json) {
                if let Some(variables) = parsed.as_object() {
                    push_variable_seeds(&mut seeds, variables, source);
                }
            }
        }
    }

    seeds
}

fn push_variable_seeds(seeds: &mut Vec<TrafficSeed>, variables: &serde_json::Map<String, Value>, source: &str) {
    for (key, val) in variables {
        seeds.push(TrafficSeed {
            field_name: key.clone(),
            type_name: "Unknown".to_string(), // Schema mapping happens later
            value: val.to_string(),
            source: source.to_string(),
        });
    }
}

/// Find `key=value` in a `key=value&key2=value2` style string and return the
/// url-decoded value, if present.
fn extract_query_param(qs: &str, key: &str) -> Option<String> {
    for pair in qs.split('&') {
        let mut parts = pair.splitn(2, '=');
        let k = parts.next().unwrap_or("");
        if k == key {
            let v = parts.next().unwrap_or("");
            return urlencoding::decode(v).ok().map(|c| c.into_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp_har() -> std::path::PathBuf {
        let har = r#"{ "log": { "entries": [
          { "request": { "method": "GET", "url": "https://api.example.com/assets/app.js",
              "headers": [ { "name": "Cookie", "value": "noise=1" } ] },
            "response": { "status": 200 } },
          { "request": { "method": "POST", "url": "https://api.example.com/graphql",
              "headers": [
                { "name": "Cookie", "value": "_px3=sess; __cf_bm=abc" },
                { "name": "Authorization", "value": "Bearer T0KEN" },
                { "name": "x-api-key", "value": "K123" },
                { "name": "Accept", "value": "application/json" } ],
              "postData": { "mimeType": "application/json", "text": "{\"query\":\"{me}\"}" } },
            "response": { "status": 200 } },
          { "request": { "method": "POST", "url": "https://other.example.org/graphql",
              "headers": [ { "name": "Cookie", "value": "SHOULD_NOT=leak" } ] },
            "response": { "status": 200 } }
        ] } }"#;
        let mut p = std::env::temp_dir();
        p.push(format!("introspectre_test_{}.har", std::process::id()));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(har.as_bytes()).unwrap();
        p
    }

    #[test]
    fn session_headers_match_target_host_and_pick_auth_cookies() {
        let p = tmp_har();
        let mut hs = extract_session_headers(&p, "https://api.example.com/graphql");
        hs.sort();
        let _ = std::fs::remove_file(&p);

        // Cookie must be the graphql entry's (last-wins), not the asset entry's.
        assert!(hs.iter().any(|h| h == "Cookie=_px3=sess; __cf_bm=abc"), "got {:?}", hs);
        assert!(hs.iter().any(|h| h == "Authorization=Bearer T0KEN"));
        assert!(hs.iter().any(|h| h == "x-api-key=K123"));
        // Non-session headers dropped; other-host cookies never leak.
        assert!(!hs.iter().any(|h| h.starts_with("Accept=")));
        assert!(!hs.iter().any(|h| h.contains("SHOULD_NOT")));
    }

    #[test]
    fn session_headers_empty_for_unparseable_or_hostless() {
        let p = tmp_har();
        assert!(extract_session_headers(&p, "not-a-url").is_empty());
        let _ = std::fs::remove_file(&p);
    }
}
