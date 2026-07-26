use std::collections::BTreeSet;

use chio_egress_contract::HttpEgressContract;
use url::Url;

pub(crate) fn strict_https_contract(
    endpoint: &Url,
    namespace: &str,
    max_response_bytes: u64,
) -> Result<HttpEgressContract, String> {
    let host = endpoint
        .host_str()
        .ok_or_else(|| "anchor URL must include a host".to_owned())?;
    let normalized_host = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]", host.to_ascii_lowercase())
    } else {
        host.trim_end_matches('.').to_ascii_lowercase()
    };
    let authority = match endpoint.port() {
        Some(port) => format!("{normalized_host}:{port}"),
        None => normalized_host,
    };
    let contract = HttpEgressContract {
        tenant_egress_namespace: namespace.to_owned(),
        allowed_schemes: BTreeSet::from(["https".to_owned()]),
        allowed_authority_set: BTreeSet::from([authority]),
        deny_loopback: true,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 0,
        max_response_bytes,
    };
    contract
        .validate_dispatchable_with_pinned_dns()
        .map_err(|error| error.to_string())?;
    contract
        .enforce_url(endpoint.as_str(), 0)
        .map_err(|error| error.to_string())?;
    Ok(contract)
}
