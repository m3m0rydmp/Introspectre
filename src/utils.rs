use crate::types::{GqlSchema, GqlType};

/// Extract field-name suggestions from a GraphQL `Did you mean "x", "y", or "z"?` error
/// message. Returns the identifiers only (empty if the message carries no suggestion).
/// Shared by blind field discovery (`guess.rs`) and the introspection-matrix probe.
pub fn parse_did_you_mean(message: &str) -> Vec<String> {
    let mut out = Vec::new();
    let parts: Vec<&str> = message.split("Did you mean").collect();
    if parts.len() < 2 {
        return out;
    }
    for s in parts[1].split(|c| c == '"' || c == '\'' || c == '`').filter(|s| {
        let t = s.trim();
        !t.is_empty() && t != "," && t != "or" && !t.contains('?')
    }) {
        let cleaned = s.trim().to_string();
        if !cleaned.is_empty() && cleaned.chars().all(|c| c.is_alphanumeric() || c == '_') {
            out.push(cleaned);
        }
    }
    out
}

/// Parse a server's per-selection-set alias cap from an "aliased too many times" error,
/// returning the maximum allowed alias count if the message states one. Used to characterise
/// the endpoint's anti-amplification control.
pub fn parse_alias_cap(message: &str) -> Option<u32> {
    let lower = message.to_lowercase();
    if !(lower.contains("aliased too many times") || lower.contains("too many aliases")) {
        return None;
    }
    // First integer in the message (e.g. "Maximum allowed is 3.").
    let mut num = String::new();
    for c in message.chars() {
        if c.is_ascii_digit() {
            num.push(c);
        } else if !num.is_empty() {
            break;
        }
    }
    num.parse().ok()
}

/// Split an identifier into lowercase word segments, breaking on non-alphanumeric
/// separators and camelCase / acronym boundaries.
/// e.g. "userEmail" -> ["user","email"], "wallet_id" -> ["wallet","id"],
/// "IPAddress" -> ["ip","address"].
pub fn tokenize_identifier(s: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = s.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_alphanumeric() {
            if !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if !cur.is_empty() {
            let prev = chars[i - 1];
            // lower/digit -> Upper starts a new word ("userEmail" -> user|Email)
            let camel = (prev.is_lowercase() || prev.is_ascii_digit()) && c.is_uppercase();
            // ACRONYM -> Word boundary ("IPAddress" -> IP|Address)
            let acronym_end = prev.is_uppercase()
                && c.is_uppercase()
                && chars.get(i + 1).map_or(false, |n| n.is_lowercase());
            if camel || acronym_end {
                tokens.push(std::mem::take(&mut cur));
            }
        }
        cur.push(c.to_ascii_lowercase());
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

/// Returns true if `pattern` (as a token sequence) appears as a contiguous run of
/// whole word-segments inside `name`. This avoids substring false positives such
/// as "key" matching "monkey" or "token" matching "tokenizer", while still
/// matching "email" in "userEmail" and "wallet_id" in "walletId".
pub fn matches_pattern(name: &str, patterns: &[String]) -> bool {
    let name_tokens = tokenize_identifier(name);
    if name_tokens.is_empty() {
        return false;
    }
    patterns.iter().any(|p| {
        let pat_tokens = tokenize_identifier(p.trim());
        if pat_tokens.is_empty() || pat_tokens.len() > name_tokens.len() {
            return false;
        }
        name_tokens
            .windows(pat_tokens.len())
            .any(|w| w == pat_tokens.as_slice())
    })
}

pub fn user_types(schema: &GqlSchema) -> Vec<&GqlType> {
    schema
        .types
        .iter()
        .filter(|t| {
            t.name
                .as_deref()
                .map(|n| !n.starts_with("__"))
                .unwrap_or(false)
        })
        .collect()
}

pub fn parse_extra_headers(extra_headers: &[String]) -> Vec<(String, String)> {
    extra_headers
        .iter()
        .filter_map(|kv| {
            let mut parts = kv.splitn(2, '=');
            let key = parts.next().unwrap_or("").trim();
            let val = parts.next().unwrap_or("").trim();
            if key.is_empty() {
                None
            } else {
                Some((key.to_string(), val.to_string()))
            }
        })
        .collect()
}

pub fn synthesize_value(field_name: &str, type_name: &str) -> String {
    let field_lower = field_name.to_lowercase();
    let type_lower = type_name.to_lowercase();

    // 1. Direct Type Match (Standard & Common Custom Scalars)
    match type_name {
        "String" => return "\"VALUE\"".to_string(),
        "Int" | "Long" | "BigInt" => return "0".to_string(),
        "Float" | "Decimal" => return "0.0".to_string(),
        "Boolean" => return "false".to_string(),
        "ID" => return "\"ID\"".to_string(),
        "Date" => return "\"2024-01-01\"".to_string(),
        "DateTime" | "DateTimeOffset" | "Timestamp" | "ISO8601DateTime" => return "\"2024-01-01T00:00:00Z\"".to_string(),
        "Time" => return "\"00:00:00Z\"".to_string(),
        "UUID" | "GUID" => return "\"00000000-0000-0000-0000-000000000000\"".to_string(),
        "URL" | "URI" => return "\"https://example.com/\"".to_string(),
        "Email" => return "\"admin@example.com\"".to_string(),
        "Phone" | "PhoneNumber" | "Telephone" => return "\"+15555555555\"".to_string(),
        "IP" | "IPv4" | "IpAddress" => return "\"127.0.0.1\"".to_string(),
        "IPv6" => return "\"::1\"".to_string(),
        "JSON" | "JSONObject" | "Json" => return "{}".to_string(),
        "Cents" | "Money" => return "100".to_string(),
        _ => {}
    }

    // 2. Intelligence: Pattern Matching on Type Name (for Custom Scalars)
    if type_lower.contains("uuid") || type_lower.contains("guid") { return "\"00000000-0000-0000-0000-000000000000\"".to_string(); }
    if type_lower.contains("email") { return "\"admin@example.com\"".to_string(); }
    if type_lower.contains("url") || type_lower.contains("uri") || type_lower.contains("link") { return "\"https://example.com/\"".to_string(); }
    if type_lower.contains("date") || type_lower.contains("time") || type_lower.contains("timestamp") { 
        if type_lower.contains("time") && !type_lower.contains("date") { return "\"00:00:00Z\"".to_string(); }
        return "\"2024-01-01T00:00:00Z\"".to_string(); 
    }
    if type_lower.contains("json") || type_lower.contains("object") || type_lower.contains("map") { return "{}".to_string(); }
    if type_lower.contains("ipaddress") || type_lower.contains("ipv4") || type_lower.contains("ipv6") { return "\"127.0.0.1\"".to_string(); }
    if type_lower.contains("html") { return "\"<html><body>Introspectre</body></html>\"".to_string(); }

    // 3. Intelligence: Pattern Matching on Field Name (Heuristics)
    if field_lower.contains("email") { return "\"admin@example.com\"".to_string(); }
    if field_lower.contains("url") || field_lower.contains("uri") || field_lower.contains("website") || field_lower.contains("link") { 
        return "\"https://example.com/\"".to_string(); 
    }
    if field_lower.contains("imdbid") { return "\"tt0111161\"".to_string(); }
    if field_lower.contains("slug") { return "\"sample-slug\"".to_string(); }
    if field_lower.contains("filename") { return "\"sample.jpg\"".to_string(); }
    if field_lower.contains("password") || field_lower.contains("secret") || field_lower.contains("token") || field_lower.contains("apikey") {
        return "\"REDACTED_BY_INTROSPECTRE\"".to_string();
    }
    if field_lower.contains("firstname") || field_lower == "firstname" { return "\"John\"".to_string(); }
    if field_lower.contains("lastname") || field_lower == "lastname" { return "\"Doe\"".to_string(); }
    if field_lower.contains("city") { return "\"San Francisco\"".to_string(); }
    if field_lower.contains("country") { return "\"USA\"".to_string(); }
    if field_lower.contains("postcode") || field_lower.contains("zipcode") { return "\"12345\"".to_string(); }
    if field_lower.contains("phone") || field_lower.contains("tel") { return "\"+15555555555\"".to_string(); }
    if field_lower.contains("amount") || field_lower.contains("price") || field_lower.contains("total") || field_lower.contains("count") || field_lower.contains("limit") { 
        return "100".to_string(); 
    }
    if field_lower.contains("currency") { return "\"USD\"".to_string(); }
    if field_lower == "id" || field_lower.ends_with("id") { return "\"ID\"".to_string(); }

    // 4. Fallback Intelligence: Guessing based on common naming suffixes
    if field_lower.ends_with("at") || field_lower.ends_with("on") || field_lower.contains("date") { return "\"2024-01-01T00:00:00Z\"".to_string(); }
    if field_lower.starts_with("is_") || field_lower.starts_with("has_") || field_lower.starts_with("can_") { return "false".to_string(); }
    
    "null".to_string()
}

#[cfg(test)]
mod tests {
    use super::{parse_alias_cap, parse_did_you_mean};

    #[test]
    fn did_you_mean_parsing() {
        let msg = "Cannot query field \"usr\" on type \"Query\". Did you mean \"user\", \"users\", or \"user_id\"?";
        assert_eq!(parse_did_you_mean(msg), vec!["user", "users", "user_id"]);

        // Single suggestion, backtick style.
        let msg2 = "Did you mean `me`?";
        assert_eq!(parse_did_you_mean(msg2), vec!["me"]);

        // No suggestion at all.
        assert!(parse_did_you_mean("Cannot query field \"x\".").is_empty());
    }

    #[test]
    fn alias_cap_parsing() {
        assert_eq!(
            parse_alias_cap("Field \"__typename\" has been aliased too many times. Maximum allowed is 3."),
            Some(3)
        );
        assert_eq!(parse_alias_cap("too many aliases (limit 10)"), Some(10));
        assert_eq!(parse_alias_cap("Cannot query field \"x\"."), None);
    }
}
