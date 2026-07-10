use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr};

use chio_egress_contract::HttpEgressContract;
use reqwest::Url;

use crate::AnchorError;

pub fn evm_anchor_devnet_rpc_egress_contract(
    rpc_url: &str,
) -> Result<HttpEgressContract, AnchorError> {
    devnet_rpc_egress_contract_for_url("chio-anchor-evm-devnet-rpc", rpc_url)
}

pub(super) fn validate_rpc_egress_contract(
    rpc_url: &str,
    contract: &HttpEgressContract,
) -> Result<(), AnchorError> {
    contract
        .validate_dispatchable_with_pinned_dns()
        .map_err(|error| {
            AnchorError::Rpc(format!(
                "invalid anchor EVM RPC HttpEgressContract: {error}"
            ))
        })?;
    // Validate scheme/authority and reject IP-literal loopback/link-local hosts
    // here. Hostname address-class is enforced at connect time by the contract's
    // pinned ContractDnsResolver (see client_builder_with_contract), so this does
    // not resolve DNS itself: a config-time lookup would be redundant, fail
    // offline, and be open to TOCTOU drift.
    contract.enforce_url(rpc_url, 0).map_err(|error| {
        AnchorError::Rpc(format!(
            "anchor EVM RPC URL is not allowed by HttpEgressContract: {error}"
        ))
    })?;
    Ok(())
}

fn devnet_rpc_egress_contract_for_url(
    namespace: &str,
    rpc_url: &str,
) -> Result<HttpEgressContract, AnchorError> {
    let url = Url::parse(rpc_url)
        .map_err(|error| AnchorError::Rpc(format!("invalid anchor EVM RPC URL: {error}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| AnchorError::Rpc("anchor EVM RPC URL must include a host".to_string()))?;
    if !rpc_host_is_loopback(host) {
        return Err(AnchorError::InvalidInput(
            "devnet anchor EVM RPC egress contract requires a loopback RPC URL".to_string(),
        ));
    }
    let mut allowed_schemes = BTreeSet::new();
    allowed_schemes.insert(url.scheme().to_ascii_lowercase());
    let mut allowed_authority_set = BTreeSet::new();
    allowed_authority_set.insert(normalized_rpc_authority(&url, host));
    let contract = HttpEgressContract {
        tenant_egress_namespace: namespace.to_string(),
        allowed_schemes,
        allowed_authority_set,
        deny_loopback: false,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 0,
        max_response_bytes: 64 * 1024 * 1024,
    };
    contract
        .validate_dispatchable_with_pinned_dns()
        .map_err(|error| {
            AnchorError::Rpc(format!(
                "invalid anchor EVM RPC HttpEgressContract: {error}"
            ))
        })?;
    contract.enforce_url_with_dns(rpc_url, 0).map_err(|error| {
        AnchorError::Rpc(format!(
            "anchor EVM RPC URL is not allowed by HttpEgressContract: {error}"
        ))
    })?;
    Ok(contract)
}

fn normalized_rpc_authority(url: &Url, host: &str) -> String {
    let host = if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.trim_end_matches('.').to_ascii_lowercase()
    };
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

fn rpc_host_is_loopback(host: &str) -> bool {
    matches!(
        host.trim_end_matches('.').to_ascii_lowercase().as_str(),
        "localhost" | "localhost.localdomain"
    ) || host
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}
