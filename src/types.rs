use serde::{Deserialize, Serialize};

pub const INTROSPECTION_QUERY: &str = r#"
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
        types { ...FullType }
        directives {
            name
            description
            locations
            args { ...InputValue }
        }
    }
}

fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
        name
        description
        args { ...InputValue }
        type { ...TypeRef }
        isDeprecated
        deprecationReason
    }
    inputFields { ...InputValue }
    interfaces { ...TypeRef }
    enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
    }
    possibleTypes { ...TypeRef }
}

fragment InputValue on __InputValue {
    name
    description
    type { ...TypeRef }
    defaultValue
}

fragment TypeRef on __Type {
    kind
    name
    ofType {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
"#;

#[derive(Debug, Deserialize, Serialize)]
pub struct IntrospectionResponse {
    pub data: Option<IntrospectionData>,
    pub errors: Option<Vec<GqlError>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct IntrospectionData {
    #[serde(rename = "__schema")]
    pub schema: GqlSchema,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GqlSchema {
    pub query_type: Option<NamedRef>,
    pub mutation_type: Option<NamedRef>,
    pub subscription_type: Option<NamedRef>,
    pub directives: Option<Vec<GqlDirective>>,
    pub types: Vec<GqlType>,
}

impl GqlSchema {
    pub fn find_type(&self, name: &str) -> Option<&GqlType> {
        self.types.iter().find(|t| t.name.as_deref() == Some(name))
    }

    pub fn fields_for_type(&self, type_name: Option<&str>) -> Vec<&GqlField> {
        let name = match type_name {
            Some(n) => n,
            None => return vec![],
        };
        self.types
            .iter()
            .find(|t| t.name.as_deref() == Some(name))
            .and_then(|t| t.fields.as_ref())
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unwrap_type_name() {
        let tr = GqlTypeRef {
            kind: Some("NON_NULL".to_string()),
            name: None,
            of_type: Some(Box::new(GqlTypeRef {
                kind: Some("LIST".to_string()),
                name: None,
                of_type: Some(Box::new(GqlTypeRef {
                    kind: Some("OBJECT".to_string()),
                    name: Some("User".to_string()),
                    of_type: None,
                })),
            })),
        };
        assert_eq!(tr.unwrap_type_name(), Some("User".to_string()));
    }

    #[test]
    fn test_fields_for_type() {
        let schema = GqlSchema {
            query_type: Some(NamedRef {
                name: "Query".to_string(),
            }),
            mutation_type: None,
            subscription_type: None,
            directives: None,
            types: vec![GqlType {
                kind: Some("OBJECT".to_string()),
                name: Some("Query".to_string()),
                description: None,
                fields: Some(vec![GqlField {
                    name: "me".to_string(),
                    is_deprecated: None,
                    deprecation_reason: None,
                    field_type: None,
                    args: None,
                }]),
                input_fields: None,
                enum_values: None,
                possible_types: None,
            }],
        };
        let fields = schema.fields_for_type(Some("Query"));
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "me");

        let no_fields = schema.fields_for_type(Some("Unknown"));
        assert!(no_fields.is_empty());
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NamedRef {
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GqlDirective {
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GqlType {
    pub kind: Option<String>,
    pub name: Option<String>,
    #[allow(dead_code)]
    pub description: Option<String>,
    pub fields: Option<Vec<GqlField>>,
    pub input_fields: Option<Vec<GqlInputField>>,
    pub enum_values: Option<Vec<GqlEnumValue>>,
    pub possible_types: Option<Vec<GqlTypeRef>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GqlField {
    pub name: String,
    pub is_deprecated: Option<bool>,
    pub deprecation_reason: Option<String>,
    #[serde(rename = "type")]
    pub field_type: Option<GqlTypeRef>,
    pub args: Option<Vec<GqlArg>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GqlArg {
    pub name: String,
    #[serde(rename = "type")]
    pub arg_type: Option<GqlTypeRef>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GqlInputField {
    pub name: String,
    #[serde(rename = "type")]
    #[allow(dead_code)]
    pub field_type: Option<GqlTypeRef>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GqlEnumValue {
    pub name: String,
    #[allow(dead_code)]
    pub is_deprecated: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GqlTypeRef {
    pub kind: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "ofType")]
    pub of_type: Option<Box<GqlTypeRef>>,
}

impl GqlTypeRef {
    pub fn unwrap_type_name(&self) -> Option<String> {
        if let Some(name) = &self.name {
            if !name.is_empty() {
                return Some(name.clone());
            }
        }
        if let Some(inner) = &self.of_type {
            return inner.unwrap_type_name();
        }
        None
    }

    #[allow(dead_code)]
    pub fn unwrap_kind(&self) -> Option<String> {
        if let Some(kind) = &self.kind {
            if kind != "NON_NULL" && kind != "LIST" {
                return Some(kind.clone());
            }
        }
        if let Some(inner) = &self.of_type {
            return inner.unwrap_kind();
        }
        self.kind.clone()
    }

    /// True if this type reference is a list at any wrapper level,
    /// e.g. `[T]`, `[T]!`, or `[T!]!` — but not a plain `String!`.
    pub fn is_list(&self) -> bool {
        if self.kind.as_deref() == Some("LIST") {
            return true;
        }
        match &self.of_type {
            Some(inner) => inner.is_list(),
            None => false,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GqlError {
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "critical")]
    Critical,
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" | "med" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" | "crit" => Ok(Severity::Critical),
            other => Err(format!("Unknown severity: {}", other)),
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum EvidenceLevel {
    #[serde(rename = "executed")]
    Executed,
    #[serde(rename = "inferred")]
    Inferred,
    #[serde(rename = "inconclusive")]
    Inconclusive,
}

impl std::fmt::Display for EvidenceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceLevel::Executed => write!(f, "Executed"),
            EvidenceLevel::Inferred => write!(f, "Inferred"),
            EvidenceLevel::Inconclusive => write!(f, "Inconclusive"),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Confidence {
    #[serde(rename = "theoretical")]
    Theoretical,
    #[serde(rename = "possible")]
    Possible,
    #[serde(rename = "confirmed")]
    Confirmed,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::Theoretical => write!(f, "THEORETICAL"),
            Confidence::Possible => write!(f, "POSSIBLE"),
            Confidence::Confirmed => write!(f, "CONFIRMED"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum AffectedLocation {
    #[serde(rename = "type")]
    Type(String),
    #[serde(rename = "field")]
    Field(String, String), // Type, Field
    #[serde(rename = "argument")]
    Argument(String, String, String), // Type, Field, Arg
}

impl std::fmt::Display for AffectedLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AffectedLocation::Type(t) => write!(f, "{}", t),
            AffectedLocation::Field(t, fi) => write!(f, "{}.{}", t, fi),
            AffectedLocation::Argument(t, fi, a) => write!(f, "{}.{}({})", t, fi, a),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingStatus {
    #[serde(rename = "inferred")]
    Inferred,
    #[serde(rename = "possible")]
    Possible,
    #[serde(rename = "confirmed")]
    Confirmed,
}

impl std::fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingStatus::Inferred => write!(f, "INFERRED"),
            FindingStatus::Possible => write!(f, "POSSIBLE"),
            FindingStatus::Confirmed => write!(f, "CONFIRMED"),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct Finding {
    pub id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub description: String,
    pub affected: Vec<AffectedLocation>,
    pub remediation: &'static str,
    pub first_step: Option<String>,
    pub references: Vec<&'static str>,
    pub status: FindingStatus,
    pub confidence: Confidence,
    pub evidence_level: EvidenceLevel,
    pub poc: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SchemaStats {
    pub total_types: usize,
    pub object_types: usize,
    pub queries: usize,
    pub mutations: usize,
    pub subscriptions: usize,
    pub enums: usize,
    pub interfaces: usize,
    pub unions: usize,
    pub total_fields: usize,
    pub deprecated_fields: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthDiscoveryResult {
    pub protected: Vec<String>,
    pub public: Vec<String>,
    pub inconclusive: Vec<String>,
}

impl AuthDiscoveryResult {
    pub fn new() -> Self {
        Self {
            protected: Vec::new(),
            public: Vec::new(),
            inconclusive: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportMeta {
    pub source: String,
    pub offline: bool,
    pub static_only: bool,
    pub auth_discovery_performed: bool,
    pub auth_discovery: Option<AuthDiscoveryResult>,
}
