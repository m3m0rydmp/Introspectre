use crate::audit::utils::effective_headers;
use crate::transport::Transport;
use crate::types::{AffectedLocation, Confidence, EvidenceLevel, Finding, FindingStatus, GqlError, Severity};
use reqwest::Client;

/// Characterises the endpoint's per-selection-set **alias cap** — a common anti-amplification
/// control. Aliases one safe field (`__typename`) many times; if the server rejects it with an
/// "aliased too many times" error, reports the cap value (a passing control worth noting). The
/// *absence* of a cap is amplification surface already covered by the `alias-dos` probe.
#[allow(clippy::too_many_arguments)]
pub async fn probe_alias_cap(
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    evasion_level: u8,
    transport: Transport,
    confirmed: &mut Vec<Finding>,
    _unconfirmed: &mut Vec<Finding>,
) -> Result<(), String> {
    const N: usize = 25;
    let aliases: String = (0..N).map(|i| format!("a{}: __typename ", i)).collect();
    let query = format!("{{ {}}}", aliases);

    let headers = effective_headers(extra_headers, None, false);
    let resp = crate::audit::utils::post_graphql_ext(
        client, url, &headers, &query, None, rate_limit_ms, evasion_level, transport, false,
    )
    .await?;

    let errors: Vec<GqlError> = serde_json::from_str(&resp.errors_text).unwrap_or_default();
    let cap = errors
        .iter()
        .find_map(|e| crate::utils::parse_alias_cap(&e.message));

    if let Some(cap) = cap {
        confirmed.push(Finding {
            id: "alias-cap-enforced",
            severity: Severity::Info,
            title: "Per-Field Alias Cap Enforced",
            description: format!(
                "The server rejects a selection set that aliases the same field more than {} time(s) (\"aliased too many times\"). This is an anti-amplification / rate-limit-bypass control: it limits how many times one field can be duplicated via aliases in a single request.",
                cap
            ),
            affected: vec![AffectedLocation::Type("Alias Limit".into())],
            remediation: "No action needed — this is a defensive control. Ensure the cap is low enough to blunt alias-based amplification while not breaking legitimate clients.",
            first_step: Some(format!(
                "Confirm the limit: send a query aliasing `__typename` {} times and observe the \"aliased too many times\" error.",
                N
            )),
            references: vec!["CWE-770: Allocation of Resources Without Limits or Throttling"],
            status: FindingStatus::Confirmed,
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
            poc: Some(format!("query {{ {}}}", (0..cap + 1).map(|i| format!("a{}: __typename ", i)).collect::<String>())),
        });
    }

    Ok(())
}
