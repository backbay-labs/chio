//! OpenAPI spec auto-discovery and loading.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use chio_http_core::{client_builder_with_contract, send_with_contract, HttpEgressContract};
use url::{Host, Url};

use crate::error::ProtectError;

const DEFAULT_UPSTREAM_REDIRECT_LIMIT: u8 = 4;
const DEFAULT_UPSTREAM_MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

/// Load an OpenAPI spec from a file path or URL.
pub fn load_spec_from_file(path: &str) -> Result<String, ProtectError> {
    std::fs::read_to_string(path)
        .map_err(|e| ProtectError::SpecLoad(format!("cannot read {path}: {e}")))
}

pub(crate) fn default_upstream_egress_contract(
    upstream: &str,
) -> Result<HttpEgressContract, ProtectError> {
    let url = Url::parse(upstream)
        .map_err(|error| ProtectError::Config(format!("invalid upstream URL: {error}")))?;
    let host = url
        .host()
        .ok_or_else(|| ProtectError::Config("upstream URL must include a host".to_string()))?;
    let mut allowed_schemes = BTreeSet::new();
    allowed_schemes.insert(url.scheme().to_ascii_lowercase());
    let mut allowed_authority_set = BTreeSet::new();
    allowed_authority_set.insert(normalized_authority(&url)?);
    let contract = HttpEgressContract {
        tenant_egress_namespace: "chio-api-protect-upstream".to_string(),
        allowed_schemes,
        allowed_authority_set,
        deny_loopback: !host_is_loopback(&host),
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: DEFAULT_UPSTREAM_REDIRECT_LIMIT,
        max_response_bytes: DEFAULT_UPSTREAM_MAX_RESPONSE_BYTES,
    };
    contract
        .validate_dispatchable_with_pinned_dns()
        .map_err(|error| {
            ProtectError::Config(format!("invalid upstream egress contract: {error}"))
        })?;
    Ok(contract)
}

/// Try to discover the OpenAPI spec from the upstream server.
///
/// Probes well-known paths (`/openapi.json`, `/openapi.yaml`,
/// `/swagger.json`, `/api-docs`) in order, returning the first
/// non-empty successful response.
pub async fn discover_spec(upstream: &str) -> Result<String, ProtectError> {
    let contract = default_upstream_egress_contract(upstream)?;
    let client = client_builder_with_contract(&contract).build()?;
    let well_known_paths = [
        "/openapi.json",
        "/openapi.yaml",
        "/swagger.json",
        "/api-docs",
    ];

    for path in &well_known_paths {
        let url = format!("{}{}", upstream.trim_end_matches('/'), path);
        let request = match client.get(&url).build() {
            Ok(request) => request,
            Err(_) => continue,
        };
        match send_with_contract(&contract, &client, request).await {
            Ok(resp) if resp.status().is_success() => match resp.text().await {
                Ok(body) if !body.is_empty() => return Ok(body),
                _ => continue,
            },
            _ => continue,
        }
    }

    Err(ProtectError::SpecLoad(
        "could not auto-discover OpenAPI spec from upstream; use --spec to provide one".to_string(),
    ))
}

fn normalized_authority(url: &Url) -> Result<String, ProtectError> {
    let host = url
        .host()
        .ok_or_else(|| ProtectError::Config("upstream URL must include a host".to_string()))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn load_spec_from_existing_file() -> Result<(), Box<dyn std::error::Error>> {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let dir = std::env::temp_dir().join(format!("chio-api-protect-test-{suffix}"));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("spec.json");
        std::fs::write(&path, r#"{"openapi":"3.1.0"}"#)?;
        let spec = load_spec_from_file(&path.to_string_lossy())?;
        assert!(spec.contains("3.1.0"));
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn load_spec_from_missing_file_fails() {
        let result = load_spec_from_file("/nonexistent/path/openapi.json");
        assert!(result.is_err());
    }

    #[test]
    fn default_upstream_egress_contract_accepts_production_hostname() {
        let contract = match default_upstream_egress_contract("https://api.example.com") {
            Ok(contract) => contract,
            Err(error) => panic!("production hostname should build an egress contract: {error}"),
        };
        assert!(contract.allowed_authority_set.contains("api.example.com"));
        assert!(contract.deny_loopback);
    }

    #[test]
    fn default_upstream_egress_contract_accepts_loopback_ip_for_tests() {
        let contract = match default_upstream_egress_contract("http://127.0.0.1:8080") {
            Ok(contract) => contract,
            Err(error) => panic!("loopback IP remains available for local proxy tests: {error}"),
        };
        assert!(contract.allowed_authority_set.contains("127.0.0.1:8080"));
    }
}
