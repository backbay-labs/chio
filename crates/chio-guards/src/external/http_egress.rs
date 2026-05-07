use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::time::Duration;

use chio_egress_contract::{
    client_builder_with_contract, send_with_contract, ContractResponse, HttpEgressContract,
};
use reqwest::{Client, RequestBuilder};
use url::{Host, Url};

use super::ExternalGuardError;

const EXTERNAL_GUARD_REDIRECT_LIMIT: u8 = 4;
const EXTERNAL_GUARD_MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

pub(crate) fn contract_for_url(
    namespace: &'static str,
    target_url: &str,
) -> Result<HttpEgressContract, ExternalGuardError> {
    let url = Url::parse(target_url).map_err(|error| {
        ExternalGuardError::Permanent(format!("invalid external guard endpoint: {error}"))
    })?;
    let host = url.host().ok_or_else(|| {
        ExternalGuardError::Permanent("external guard endpoint missing host".to_string())
    })?;
    let authority = normalized_authority(&url)?;
    let mut allowed_schemes = BTreeSet::new();
    allowed_schemes.insert(url.scheme().to_ascii_lowercase());
    let mut allowed_authority_set = BTreeSet::new();
    allowed_authority_set.insert(authority);
    let contract = HttpEgressContract {
        tenant_egress_namespace: namespace.to_string(),
        allowed_schemes,
        allowed_authority_set,
        deny_loopback: !host_is_loopback(&host),
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: EXTERNAL_GUARD_REDIRECT_LIMIT,
        max_response_bytes: EXTERNAL_GUARD_MAX_RESPONSE_BYTES,
    };
    contract
        .validate_dispatchable_with_pinned_dns()
        .map_err(|error| {
            ExternalGuardError::Permanent(format!(
                "invalid external guard egress contract: {error}"
            ))
        })?;
    Ok(contract)
}

pub(crate) fn client_for_contract(
    contract: &HttpEgressContract,
    timeout: Duration,
) -> Result<Client, ExternalGuardError> {
    client_builder_with_contract(contract)
        .timeout(timeout)
        .build()
        .map_err(|error| ExternalGuardError::Permanent(format!("reqwest build: {error}")))
}

pub(crate) async fn send_request_with_contract(
    contract: &HttpEgressContract,
    client: &Client,
    request: RequestBuilder,
) -> Result<ContractResponse, ExternalGuardError> {
    let request = request.build().map_err(|error| {
        ExternalGuardError::Permanent(format!("reqwest build request: {error}"))
    })?;
    send_with_contract(contract, client, request)
        .await
        .map_err(|error| {
            ExternalGuardError::Permanent(format!(
                "HttpEgressContract rejects external guard dispatch: {error}"
            ))
        })
}

pub(crate) async fn response_text(
    response: ContractResponse,
) -> Result<String, ExternalGuardError> {
    response
        .text()
        .await
        .map_err(|error| ExternalGuardError::Transient(format!("read body: {error}")))
}

fn normalized_authority(url: &Url) -> Result<String, ExternalGuardError> {
    let host = url.host().ok_or_else(|| {
        ExternalGuardError::Permanent("external guard endpoint missing host".to_string())
    })?;
    let host = match host {
        Host::Domain(domain) => domain.trim_end_matches('.').to_ascii_lowercase(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn host_is_loopback(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => matches!(
            domain.trim_end_matches('.').to_ascii_lowercase().as_str(),
            "localhost" | "localhost.localdomain"
        ),
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => {
            address.is_loopback()
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|mapped: Ipv4Addr| mapped.is_loopback())
        }
    }
}
