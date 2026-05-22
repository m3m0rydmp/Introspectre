pub mod access_control;
pub mod dos;
pub mod information_exposure;
pub mod jwt;
<<<<<<< HEAD
pub mod jwt_tests;
pub mod utils;

use self::utils::user_types;
use crate::config::PatternConfig;
use crate::types::{Finding, GqlSchema, SchemaStats};
=======
pub mod scoring;

use crate::config::PatternConfig;
use crate::types::{Finding, GqlSchema, SchemaStats};
use crate::utils::user_types;
>>>>>>> update-research-refs

pub fn analyze(
    schema: &GqlSchema,
    patterns: &PatternConfig,
    token: Option<&str>,
) -> (Vec<Finding>, SchemaStats) {
    let mut findings: Vec<Finding> = Vec::new();
    let types = user_types(schema);

    let query_name = schema.query_type.as_ref().map(|t| t.name.as_str());
    let mutation_name = schema.mutation_type.as_ref().map(|t| t.name.as_str());
    let subscription_name = schema.subscription_type.as_ref().map(|t| t.name.as_str());

    let total_fields: usize = types
        .iter()
        .map(|t| t.fields.as_ref().map(|f| f.len()).unwrap_or(0))
        .sum();

    let deprecated_fields: usize = types
        .iter()
        .flat_map(|t| t.fields.iter().flat_map(|v| v.iter()))
        .filter(|f| f.is_deprecated.unwrap_or(false))
        .count();

    let stats = SchemaStats {
        total_types: types.len(),
        object_types: types
            .iter()
            .filter(|t| t.kind.as_deref() == Some("OBJECT"))
            .count(),
        queries: schema.fields_for_type(query_name).len(),
        mutations: schema.fields_for_type(mutation_name).len(),
        subscriptions: schema.fields_for_type(subscription_name).len(),
        enums: types
            .iter()
            .filter(|t| t.kind.as_deref() == Some("ENUM"))
            .count(),
        interfaces: types
            .iter()
            .filter(|t| t.kind.as_deref() == Some("INTERFACE"))
            .count(),
        unions: types
            .iter()
            .filter(|t| t.kind.as_deref() == Some("UNION"))
            .count(),
        total_fields,
        deprecated_fields,
    };

    information_exposure::check_information_exposure(schema, patterns, &mut findings);
    dos::check_dos(schema, &mut findings);
    access_control::check_access_control(schema, patterns, &mut findings);
    jwt::check_jwt(token, patterns, &mut findings);

    (findings, stats)
}
