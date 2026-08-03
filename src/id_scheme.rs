//! Global-object ID scheme classification for Relay `node(id:)` IDOR analysis.
//!
//! Relay-style APIs expose a single `node(id: ID!)` fetcher that returns any
//! object by an opaque global id. Whether that is an *enumerable* BOLA/IDOR
//! surface depends entirely on how those ids are encoded: an unsigned,
//! sequential scheme (base64 of `gid://host/Type/123` or `Type:123`, or a plain
//! integer) is directly enumerable — an attacker just decodes one id, changes
//! the number, and re-encodes. A random UUID or a signed/opaque token is not.
//!
//! [`classify_global_id`] decodes a sample id and names the scheme;
//! [`adjacent_id`] produces a neighbouring id for a proof-of-concept. Both are
//! pure and fully unit-testable.

use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;

/// A classified global-id encoding scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdScheme {
    /// base64 of `gid://host/Type/<int>` — enumerable.
    GidNumeric { host: String, type_name: String, id: i64 },
    /// base64 of `Type<sep><int>` (Relay node id) where `sep` is `:` (graphql-relay-JS
    /// default) or `-` (graphql-ruby default) — enumerable.
    TypedNumeric { type_name: String, id: i64, sep: char },
    /// A bare integer id — enumerable.
    PlainNumeric(i64),
    /// base64 of `gid://host/Type/<uuid>` or `Type:<uuid>` — not sequentially
    /// enumerable, but the type is disclosed.
    TypedUuid { type_name: String },
    /// A bare UUID version 4 (or v3/v5) — random / name-based, not enumerable.
    Uuid,
    /// A bare UUID **version 1** — time/node-based. The clock+counter portion is not random, so
    /// ids created close together can be *predictable*; flagged as a manual-review lead (not
    /// auto-enumerated, since reconstructing an adjacent v1 id is non-trivial).
    UuidV1,
    /// A bare hex string the length of a common digest (MD5=128, SHA-1=160, SHA-256=256 bits) —
    /// likely a hashed id; not enumerable, but worth manual review (predictable input? weak salt?).
    Hash { bits: u16 },
    /// Decodes to binary / an unrecognised token — likely signed or random;
    /// treated as not enumerable.
    Opaque,
}

impl IdScheme {
    /// Whether ids in this scheme can be trivially enumerated by
    /// incrementing/decrementing a counter.
    pub fn is_enumerable(&self) -> bool {
        matches!(
            self,
            IdScheme::GidNumeric { .. } | IdScheme::TypedNumeric { .. } | IdScheme::PlainNumeric(_)
        )
    }

    /// A short human-readable label for the scheme.
    pub fn label(&self) -> String {
        match self {
            IdScheme::GidNumeric { host, type_name, id } => {
                format!("sequential Relay global id `gid://{}/{}/{}`", host, type_name, id)
            }
            IdScheme::TypedNumeric { type_name, id, sep } => {
                format!("sequential Relay node id `{}{}{}`", type_name, sep, id)
            }
            IdScheme::PlainNumeric(n) => format!("bare sequential integer id `{}`", n),
            IdScheme::TypedUuid { type_name } => format!("type-tagged UUID (`{}:<uuid>`)", type_name),
            IdScheme::Uuid => "random UUID (v4/v3/v5)".to_string(),
            IdScheme::UuidV1 => "time-based UUIDv1 — potentially predictable, manual review".to_string(),
            IdScheme::Hash { bits } => {
                let algo = match bits {
                    128 => "MD5",
                    160 => "SHA-1",
                    256 => "SHA-256",
                    _ => "hash",
                };
                format!("hash-like id ({}-bit, e.g. {} — requires manual review)", bits, algo)
            }
            IdScheme::Opaque => "opaque / signed token".to_string(),
        }
    }
}

/// Try each common base64 variant; return the decoded bytes on the first hit.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    STANDARD
        .decode(s)
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')))
        .ok()
}

/// Loosely: 8-4-4-4-12 hex with hyphens.
fn is_uuid(s: &str) -> bool {
    let s = s.trim();
    let groups: Vec<&str> = s.split('-').collect();
    groups.len() == 5
        && [8, 4, 4, 4, 12] == groups.iter().map(|g| g.len()).collect::<Vec<_>>()[..]
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// The RFC-4122 version nibble of a UUID (the first hex digit of the third group). `None` if the
/// string is not a UUID or the nibble isn't a hex digit.
fn uuid_version(s: &str) -> Option<u8> {
    if !is_uuid(s) {
        return None;
    }
    s.trim().split('-').nth(2).and_then(|g| g.chars().next()).and_then(|c| c.to_digit(16)).map(|v| v as u8)
}

/// Bit-length if `s` is a bare hex string the size of a common digest (MD5/SHA-1/SHA-256) and
/// contains at least one `a-f` letter (so a same-length run of digits isn't misread as a hash).
fn hex_hash_bits(s: &str) -> Option<u16> {
    let s = s.trim();
    let is_hex = !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit());
    let has_letter = s.chars().any(|c| c.is_ascii_alphabetic());
    if is_hex && has_letter {
        match s.len() {
            32 => return Some(128),
            40 => return Some(160),
            64 => return Some(256),
            _ => {}
        }
    }
    None
}

/// Strip surrounding quotes a seed value may carry (e.g. `"\"abc\""`).
fn unquote(s: &str) -> &str {
    s.trim().trim_matches('"').trim()
}

/// Classify a sample global-id string.
pub fn classify_global_id(raw: &str) -> IdScheme {
    let id = unquote(raw);
    if id.is_empty() {
        return IdScheme::Opaque;
    }
    if let Ok(n) = id.parse::<i64>() {
        return IdScheme::PlainNumeric(n);
    }
    if is_uuid(id) {
        // Distinguish time-based v1 (potentially predictable) from random v4/v3/v5.
        return match uuid_version(id) {
            Some(1) => IdScheme::UuidV1,
            _ => IdScheme::Uuid,
        };
    }
    if let Some(bits) = hex_hash_bits(id) {
        return IdScheme::Hash { bits };
    }

    if let Some(bytes) = b64_decode(id) {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            // gid://host/Type/<id-part>
            if let Some(rest) = s.strip_prefix("gid://") {
                let parts: Vec<&str> = rest.splitn(3, '/').collect();
                if parts.len() == 3 && !parts[1].is_empty() {
                    let (host, type_name, id_part) = (parts[0], parts[1], parts[2]);
                    if let Ok(n) = id_part.parse::<i64>() {
                        return IdScheme::GidNumeric {
                            host: host.to_string(),
                            type_name: type_name.to_string(),
                            id: n,
                        };
                    }
                    if is_uuid(id_part) {
                        return IdScheme::TypedUuid { type_name: type_name.to_string() };
                    }
                }
            }
            // Type<sep><id-part> where sep is `:` (relay-js) or `-` (graphql-ruby).
            for sep in [':', '-'] {
                if let Some((ty, id_part)) = s.split_once(sep) {
                    if !ty.is_empty() && ty.chars().all(|c| c.is_alphanumeric() || c == '_') {
                        if let Ok(n) = id_part.parse::<i64>() {
                            return IdScheme::TypedNumeric { type_name: ty.to_string(), id: n, sep };
                        }
                        if is_uuid(id_part) {
                            return IdScheme::TypedUuid { type_name: ty.to_string() };
                        }
                    }
                }
            }
        }
        // Decoded, but not a recognised printable scheme → opaque/signed.
        return IdScheme::Opaque;
    }

    IdScheme::Opaque
}

/// Produce a neighbouring id in the same encoding, for an IDOR proof-of-concept
/// (`n-1`, or `n+1` when `n <= 1`). Returns `None` for non-enumerable schemes.
pub fn adjacent_id(raw: &str) -> Option<String> {
    let step = |n: i64| if n > 1 { n - 1 } else { n + 1 };
    match classify_global_id(raw) {
        IdScheme::PlainNumeric(n) => Some(step(n).to_string()),
        IdScheme::GidNumeric { host, type_name, id } => {
            Some(STANDARD.encode(format!("gid://{}/{}/{}", host, type_name, step(id))))
        }
        IdScheme::TypedNumeric { type_name, id, sep } => {
            Some(STANDARD.encode(format!("{}{}{}", type_name, sep, step(id))))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &str) -> String {
        STANDARD.encode(s)
    }

    #[test]
    fn classifies_gid_numeric() {
        let id = b64("gid://hackerone/User/12345");
        let scheme = classify_global_id(&id);
        assert_eq!(
            scheme,
            IdScheme::GidNumeric { host: "hackerone".into(), type_name: "User".into(), id: 12345 }
        );
        assert!(scheme.is_enumerable());
    }

    #[test]
    fn classifies_typed_numeric_colon_and_hyphen() {
        // graphql-relay-JS default (colon)
        let s1 = classify_global_id(&b64("UserObject:42"));
        assert_eq!(s1, IdScheme::TypedNumeric { type_name: "UserObject".into(), id: 42, sep: ':' });
        assert!(s1.is_enumerable());
        // graphql-ruby default (hyphen)
        let s2 = classify_global_id(&b64("User-123"));
        assert_eq!(s2, IdScheme::TypedNumeric { type_name: "User".into(), id: 123, sep: '-' });
        assert!(s2.is_enumerable());
    }

    #[test]
    fn classifies_plain_int_and_uuid() {
        assert_eq!(classify_global_id("1001"), IdScheme::PlainNumeric(1001));
        assert!(classify_global_id("1001").is_enumerable());
        assert_eq!(classify_global_id("550e8400-e29b-41d4-a716-446655440000"), IdScheme::Uuid);
        assert!(!classify_global_id("550e8400-e29b-41d4-a716-446655440000").is_enumerable());
    }

    #[test]
    fn distinguishes_uuid_v1_from_v4() {
        // Version nibble '1' (3rd group starts with 1) → time-based v1.
        let v1 = classify_global_id("c232ab00-9414-11ec-b3c8-9e6bdeced846");
        assert_eq!(v1, IdScheme::UuidV1);
        assert!(!v1.is_enumerable());
        assert!(v1.label().contains("v1"));
        // Version nibble '4' → random v4.
        assert_eq!(classify_global_id("550e8400-e29b-41d4-a716-446655440000"), IdScheme::Uuid);
    }

    #[test]
    fn classifies_hash_ids() {
        // MD5 (32 hex, has letters), SHA-1 (40), SHA-256 (64).
        assert_eq!(classify_global_id("5f4dcc3b5aa765d61d8327deb882cf99"), IdScheme::Hash { bits: 128 });
        assert_eq!(
            classify_global_id("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"),
            IdScheme::Hash { bits: 160 }
        );
        assert_eq!(
            classify_global_id("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            IdScheme::Hash { bits: 256 }
        );
        assert!(!classify_global_id("5f4dcc3b5aa765d61d8327deb882cf99").is_enumerable());
        assert!(adjacent_id("5f4dcc3b5aa765d61d8327deb882cf99").is_none());
        // A 32-char run of digits is NOT a hash (no hex letters) → opaque, not enumerable.
        assert_eq!(classify_global_id("12345678901234567890123456789012"), IdScheme::Opaque);
    }

    #[test]
    fn typed_uuid_is_not_enumerable() {
        let scheme = classify_global_id(&b64("User:550e8400-e29b-41d4-a716-446655440000"));
        assert_eq!(scheme, IdScheme::TypedUuid { type_name: "User".into() });
        assert!(!scheme.is_enumerable());
    }

    #[test]
    fn opaque_signed_token_is_not_enumerable() {
        // Random-looking base64 that decodes to binary.
        let scheme = classify_global_id("q1w2e3r4t5y6u7i8o9p0YWJjZGVm");
        assert_eq!(scheme, IdScheme::Opaque);
        assert!(!scheme.is_enumerable());
    }

    #[test]
    fn adjacent_id_decrements_within_scheme() {
        // gid numeric
        let id = b64("gid://h1/Report/500");
        let adj = adjacent_id(&id).unwrap();
        assert_eq!(classify_global_id(&adj), IdScheme::GidNumeric { host: "h1".into(), type_name: "Report".into(), id: 499 });
        // hyphen scheme round-trips with the hyphen preserved
        let hid = b64("User-123");
        let hadj = adjacent_id(&hid).unwrap();
        assert_eq!(String::from_utf8(STANDARD.decode(&hadj).unwrap()).unwrap(), "User-122");
        // plain int, and the n<=1 -> n+1 edge
        assert_eq!(adjacent_id("10").as_deref(), Some("9"));
        assert_eq!(adjacent_id("1").as_deref(), Some("2"));
        // non-enumerable -> None
        assert_eq!(adjacent_id("550e8400-e29b-41d4-a716-446655440000"), None);
    }

    #[test]
    fn unquotes_seed_values() {
        let quoted = format!("\"{}\"", b64("gid://x/Team/7"));
        assert_eq!(
            classify_global_id(&quoted),
            IdScheme::GidNumeric { host: "x".into(), type_name: "Team".into(), id: 7 }
        );
    }
}
