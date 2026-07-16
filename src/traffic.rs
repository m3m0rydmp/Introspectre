use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
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
    #[serde(rename = "postData")]
    post_data: Option<HarPostData>,
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

pub fn parse_traffic_file(path: &Path) -> Result<Vec<TrafficSeed>, String> {
    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;

    // Check if it's HAR (JSON) first.
    if let Ok(har) = serde_json::from_str::<HarRoot>(&content) {
        return Ok(extract_from_har(har));
    }

    // Fall back to a Burp Suite "Save items" XML export.
    if let Ok(burp) = quick_xml::de::from_str::<BurpRoot>(&content) {
        return Ok(extract_from_burp(burp));
    }

    Err("Unsupported traffic file format. Supported formats: HAR (.har JSON export) and Burp Suite \"Save items\" XML export.".to_string())
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
