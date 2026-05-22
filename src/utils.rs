use crate::types::{GqlSchema, GqlType};

pub fn matches_pattern(name: &str, patterns: &[String]) -> bool {
    let lower = name.to_lowercase();
    patterns.iter().any(|p| {
        let possibility = p.trim().to_lowercase();
        !possibility.is_empty() && lower.contains(&possibility)
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

    // 1. Heuristics based on Field Name
    if field_lower.contains("email") { return "\"admin@example.com\"".to_string(); }
    if field_lower.contains("url") || field_lower.contains("uri") || field_lower.contains("website") { 
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
    if field_lower.contains("amount") || field_lower.contains("price") || field_lower.contains("total") { return "100".to_string(); }
    if field_lower.contains("currency") { return "\"USD\"".to_string(); }
    if field_lower == "id" || field_lower.ends_with("id") { return "\"ID\"".to_string(); }

    // 2. Heuristics based on Type Name
    match type_name {
        "String" => "\"VALUE\"".to_string(),
        "Int" | "Long" | "BigInt" => "0".to_string(),
        "Float" | "Decimal" => "0.0".to_string(),
        "Boolean" => "false".to_string(),
        "ID" => "\"ID\"".to_string(),
        "Date" => "\"2024-01-01\"".to_string(),
        "DateTime" | "DateTimeOffset" | "Timestamp" => "\"2024-01-01T00:00:00Z\"".to_string(),
        "Time" => "\"00:00:00Z\"".to_string(),
        "UUID" | "GUID" => "\"00000000-0000-0000-0000-000000000000\"".to_string(),
        "URL" | "URI" => "\"https://example.com/\"".to_string(),
        "Email" => "\"admin@example.com\"".to_string(),
        "Phone" | "PhoneNumber" | "Telephone" => "\"+15555555555\"".to_string(),
        "IP" | "IPv4" | "IpAddress" => "\"127.0.0.1\"".to_string(),
        "IPv6" => "\"::1\"".to_string(),
        "JSON" | "JSONObject" | "Json" => "{}".to_string(),
        "Cents" | "Money" => "100".to_string(),
        _ => {
            if type_lower.contains("email") { return "\"admin@example.com\"".to_string(); }
            if type_lower.contains("url") || type_lower.contains("uri") { return "\"https://example.com/\"".to_string(); }
            if type_lower.contains("uuid") || type_lower.contains("guid") { return "\"00000000-0000-0000-0000-000000000000\"".to_string(); }
            if type_lower.contains("phone") { return "\"+15555555555\"".to_string(); }
            if type_lower.contains("ipaddress") || type_lower.contains("ipv4") { return "\"127.0.0.1\"".to_string(); }
            if type_lower.contains("json") { return "{}".to_string(); }
            "null".to_string()
        }
    }
}
