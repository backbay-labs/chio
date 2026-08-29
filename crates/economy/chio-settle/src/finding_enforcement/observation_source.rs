//! Strict remote chain and operator observation source.

use std::collections::BTreeSet;
use std::fmt;
use std::io::Read as _;
use std::net::{IpAddr, ToSocketAddrs as _};
use std::sync::Arc;
use std::time::Duration;

use chio_core::{canonical::canonical_json_bytes_from_str, canonical_json_bytes, sha256_hex};
use chio_egress_contract::HttpEgressContract;
use chio_finding::FindingObservedFinality;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use super::{
    FindingBondObservationRecheck, FindingBondObservationSource, FindingFinalityRequirement,
    ReconciledFindingEnforcement, VerifiedFindingEnforcement,
};
use crate::SettlementError;

pub const FINDING_BOND_OBSERVATION_REQUEST_SCHEMA: &str =
    "chio.finding.bond-observation-request.v1";
pub const FINDING_BOND_OBSERVATION_RESPONSE_SCHEMA: &str =
    "chio.finding.bond-observation-response.v1";
pub const FINDING_BOND_OBSERVE_PATH: &str = "/v1/finding-bond-observations/observe";
pub const FINDING_BOND_RECONCILE_PATH: &str =
    "/v1/finding-bond-observations/observe-reconciliation";

const MAX_OBSERVATION_REQUEST_BYTES: usize = 64 * 1024;
const MAX_OBSERVATION_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingBondObservationOperation {
    Observe,
    ObserveReconciliation,
}

impl FindingBondObservationOperation {
    const fn path(self) -> &'static str {
        match self {
            Self::Observe => FINDING_BOND_OBSERVE_PATH,
            Self::ObserveReconciliation => FINDING_BOND_RECONCILE_PATH,
        }
    }
}

/// Minimum verified identity needed to re-read a bond observation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingBondObservationRequest {
    pub schema: String,
    pub operation: FindingBondObservationOperation,
    pub enforcement_envelope_sha256: String,
    pub bond_snapshot_envelope_sha256: String,
    pub enforcement_id: String,
    pub liability_key: String,
    pub chain_id: String,
    pub vault_contract: String,
    pub vault_id: String,
    pub block_number: u64,
    pub block_hash: String,
    pub identity_registry_record: String,
    pub operator_key_hash: String,
    pub operator_key_epoch: u64,
    pub finality_requirement: FindingFinalityRequirement,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingBondObservationResponse {
    pub schema: String,
    pub request_sha256: String,
    pub observation: FindingBondObservationRecheck,
}

#[derive(Debug, Error)]
pub enum FindingBondObservationSourceConfigError {
    #[error("remote bond observation URL is invalid")]
    InvalidUrl,
    #[error("remote bond observation bearer token is invalid")]
    InvalidBearerToken,
    #[error("remote bond observation namespace is invalid")]
    InvalidNamespace,
    #[error("remote bond observation timeout is invalid")]
    InvalidTimeout,
    #[error("remote bond observation egress policy is invalid")]
    InvalidEgressPolicy,
    #[error("remote bond observation DNS resolution failed")]
    DnsResolution,
    #[error("remote bond observation HTTP client could not be built")]
    HttpClient,
}

pub struct RemoteFindingBondObservationSourceConfig {
    base_url: String,
    bearer_token: Zeroizing<String>,
    tenant_egress_namespace: String,
    timeout: Duration,
}

impl fmt::Debug for RemoteFindingBondObservationSourceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteFindingBondObservationSourceConfig")
            .field("base_url", &self.base_url)
            .field("bearer_token", &"[REDACTED]")
            .field("tenant_egress_namespace", &self.tenant_egress_namespace)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl RemoteFindingBondObservationSourceConfig {
    pub fn new(
        base_url: impl Into<String>,
        bearer_token: impl Into<String>,
        tenant_egress_namespace: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, FindingBondObservationSourceConfigError> {
        let config = Self {
            base_url: base_url.into(),
            bearer_token: Zeroizing::new(bearer_token.into()),
            tenant_egress_namespace: tenant_egress_namespace.into(),
            timeout,
        };
        config.endpoint_and_contract()?;
        Ok(config)
    }

    fn endpoint_and_contract(
        &self,
    ) -> Result<(reqwest::Url, HttpEgressContract), FindingBondObservationSourceConfigError> {
        let endpoint = reqwest::Url::parse(&self.base_url)
            .map_err(|_| FindingBondObservationSourceConfigError::InvalidUrl)?;
        if self.base_url.len() > 4096
            || endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.cannot_be_a_base()
        {
            return Err(FindingBondObservationSourceConfigError::InvalidUrl);
        }
        if !valid_bearer_token(&self.bearer_token) || self.bearer_token.len() > 16 * 1024 {
            return Err(FindingBondObservationSourceConfigError::InvalidBearerToken);
        }
        if !valid_namespace(&self.tenant_egress_namespace) {
            return Err(FindingBondObservationSourceConfigError::InvalidNamespace);
        }
        if self.timeout.is_zero() || self.timeout > Duration::from_secs(120) {
            return Err(FindingBondObservationSourceConfigError::InvalidTimeout);
        }
        let host = endpoint
            .host_str()
            .ok_or(FindingBondObservationSourceConfigError::InvalidUrl)?;
        let normalized_host = if host.contains(':') && !host.starts_with('[') {
            format!("[{}]", host.to_ascii_lowercase())
        } else {
            host.trim_end_matches('.').to_ascii_lowercase()
        };
        let authority = endpoint.port().map_or(normalized_host.clone(), |port| {
            format!("{normalized_host}:{port}")
        });
        let contract = HttpEgressContract {
            tenant_egress_namespace: self.tenant_egress_namespace.clone(),
            allowed_schemes: BTreeSet::from(["https".to_owned()]),
            allowed_authority_set: BTreeSet::from([authority]),
            deny_loopback: true,
            deny_link_local: true,
            deny_ipv6_ula: true,
            max_redirect_chain: 0,
            max_response_bytes: MAX_OBSERVATION_RESPONSE_BYTES as u64,
        };
        contract
            .validate_dispatchable_with_pinned_dns()
            .and_then(|()| contract.enforce_url(endpoint.as_str(), 0).map(|_| ()))
            .map_err(|_| FindingBondObservationSourceConfigError::InvalidEgressPolicy)?;
        Ok((endpoint, contract))
    }
}

fn valid_bearer_token(value: &str) -> bool {
    let bytes = value.as_bytes();
    let unpadded_len = bytes
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap_or(bytes.len());
    unpadded_len > 0
        && bytes[..unpadded_len].iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
        && bytes[unpadded_len..].iter().all(|byte| *byte == b'=')
}

fn valid_namespace(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

trait FindingBondObservationTransport: Send + Sync {
    fn post(
        &self,
        operation: FindingBondObservationOperation,
        body: &[u8],
    ) -> Result<Vec<u8>, SettlementError>;
}

struct HttpsFindingBondObservationTransport {
    client: reqwest::blocking::Client,
    base_url: String,
    bearer_token: Zeroizing<String>,
    contract: HttpEgressContract,
}

impl HttpsFindingBondObservationTransport {
    fn new(
        config: RemoteFindingBondObservationSourceConfig,
    ) -> Result<Self, FindingBondObservationSourceConfigError> {
        let (endpoint, contract) = config.endpoint_and_contract()?;
        let host = endpoint
            .host_str()
            .ok_or(FindingBondObservationSourceConfigError::InvalidUrl)?;
        let mut builder = reqwest::blocking::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(config.timeout);
        if host.parse::<IpAddr>().is_err() {
            let port = endpoint
                .port_or_known_default()
                .ok_or(FindingBondObservationSourceConfigError::InvalidUrl)?;
            let addresses = (host, port)
                .to_socket_addrs()
                .map_err(|_| FindingBondObservationSourceConfigError::DnsResolution)?
                .collect::<Vec<_>>();
            if addresses.is_empty() {
                return Err(FindingBondObservationSourceConfigError::DnsResolution);
            }
            for address in &addresses {
                contract
                    .enforce_resolved_ip(host, address.ip())
                    .map_err(|_| FindingBondObservationSourceConfigError::InvalidEgressPolicy)?;
            }
            builder = builder.resolve_to_addrs(host, &addresses);
        }
        let client = builder
            .build()
            .map_err(|_| FindingBondObservationSourceConfigError::HttpClient)?;
        Ok(Self {
            client,
            base_url: config.base_url.trim_end_matches('/').to_owned(),
            bearer_token: config.bearer_token,
            contract,
        })
    }
}

impl FindingBondObservationTransport for HttpsFindingBondObservationTransport {
    fn post(
        &self,
        operation: FindingBondObservationOperation,
        body: &[u8],
    ) -> Result<Vec<u8>, SettlementError> {
        if body.len() > MAX_OBSERVATION_REQUEST_BYTES {
            return Err(SettlementError::InvalidInput(
                "remote bond observation request exceeds its bound".to_owned(),
            ));
        }
        let endpoint = format!("{}{}", self.base_url, operation.path());
        self.contract.enforce_url(&endpoint, 0).map_err(|_| {
            SettlementError::InvalidInput("remote bond observation URL rejected".to_owned())
        })?;
        // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: DNS answers were pinned and
        // checked during construction. Redirects and proxies are disabled.
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(self.bearer_token.as_str())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send()
            .map_err(|error| {
                SettlementError::Rpc(format!(
                    "remote bond observation unavailable: {}",
                    transport_error_class(&error)
                ))
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(SettlementError::Rpc(format!(
                "remote bond observation returned HTTP {status}"
            )));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if content_type != Some("application/json") {
            return Err(SettlementError::Verification(
                "remote bond observation media type is invalid".to_owned(),
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_OBSERVATION_RESPONSE_BYTES as u64)
        {
            return Err(SettlementError::Verification(
                "remote bond observation response exceeds its bound".to_owned(),
            ));
        }
        let mut response_body = Vec::new();
        response
            .take(MAX_OBSERVATION_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut response_body)
            .map_err(|_| {
                SettlementError::Rpc(
                    "remote bond observation response could not be read".to_owned(),
                )
            })?;
        self.contract
            .enforce_response_bytes(response_body.len() as u64)
            .map_err(|_| {
                SettlementError::Verification(
                    "remote bond observation response exceeds its bound".to_owned(),
                )
            })?;
        Ok(response_body)
    }
}

fn transport_error_class(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else {
        "transport"
    }
}

pub struct RemoteFindingBondObservationSource {
    transport: Arc<dyn FindingBondObservationTransport>,
}

impl fmt::Debug for RemoteFindingBondObservationSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteFindingBondObservationSource")
            .finish_non_exhaustive()
    }
}

impl RemoteFindingBondObservationSource {
    pub fn new(
        config: RemoteFindingBondObservationSourceConfig,
    ) -> Result<Self, FindingBondObservationSourceConfigError> {
        Ok(Self {
            transport: Arc::new(HttpsFindingBondObservationTransport::new(config)?),
        })
    }

    fn execute(
        &self,
        operation: FindingBondObservationOperation,
        verified: &VerifiedFindingEnforcement,
    ) -> Result<FindingBondObservationRecheck, SettlementError> {
        let request = request_for(operation, verified);
        let request_bytes = canonical_json_bytes(&request).map_err(|_| {
            SettlementError::Serialization(
                "remote bond observation request canonicalization failed".to_owned(),
            )
        })?;
        if request_bytes.len() > MAX_OBSERVATION_REQUEST_BYTES {
            return Err(SettlementError::InvalidInput(
                "remote bond observation request exceeds its bound".to_owned(),
            ));
        }
        let request_sha256 = sha256_hex(&request_bytes);
        let response = self.transport.post(operation, &request_bytes)?;
        decode_response(&request_sha256, &response)
    }
}

impl FindingBondObservationSource for RemoteFindingBondObservationSource {
    fn observe(
        &self,
        verified: &VerifiedFindingEnforcement,
    ) -> Result<FindingBondObservationRecheck, SettlementError> {
        self.execute(FindingBondObservationOperation::Observe, verified)
    }

    fn observe_reconciliation(
        &self,
        reconciled: &ReconciledFindingEnforcement,
    ) -> Result<FindingBondObservationRecheck, SettlementError> {
        self.execute(
            FindingBondObservationOperation::ObserveReconciliation,
            reconciled.verified(),
        )
    }
}

fn request_for(
    operation: FindingBondObservationOperation,
    verified: &VerifiedFindingEnforcement,
) -> FindingBondObservationRequest {
    let enforcement = verified.enforcement();
    let snapshot = verified.snapshot();
    FindingBondObservationRequest {
        schema: FINDING_BOND_OBSERVATION_REQUEST_SCHEMA.to_owned(),
        operation,
        enforcement_envelope_sha256: verified.enforcement_envelope_sha256().to_owned(),
        bond_snapshot_envelope_sha256: verified.bond_snapshot_envelope_sha256().to_owned(),
        enforcement_id: enforcement.enforcement_id.clone(),
        liability_key: enforcement.liability_key.clone(),
        chain_id: snapshot.chain_id.clone(),
        vault_contract: snapshot.vault_contract.clone(),
        vault_id: snapshot.vault_id.clone(),
        block_number: snapshot.block_number,
        block_hash: snapshot.block_hash.clone(),
        identity_registry_record: snapshot.identity_registry_record.clone(),
        operator_key_hash: snapshot.operator_key_hash.clone(),
        operator_key_epoch: snapshot.operator_key_epoch,
        finality_requirement: verified.finality_requirement(),
    }
}

fn decode_response(
    request_sha256: &str,
    bytes: &[u8],
) -> Result<FindingBondObservationRecheck, SettlementError> {
    if bytes.is_empty() || bytes.len() > MAX_OBSERVATION_RESPONSE_BYTES {
        return Err(SettlementError::Verification(
            "remote bond observation response exceeds its bound".to_owned(),
        ));
    }
    let raw = std::str::from_utf8(bytes).map_err(|_| {
        SettlementError::Verification("remote bond observation response is not UTF-8".to_owned())
    })?;
    let canonical = canonical_json_bytes_from_str(raw).map_err(|_| {
        SettlementError::Verification(
            "remote bond observation response is not strict canonical JSON".to_owned(),
        )
    })?;
    if canonical != bytes {
        return Err(SettlementError::Verification(
            "remote bond observation response is not canonical".to_owned(),
        ));
    }
    let response: FindingBondObservationResponse = serde_json::from_slice(bytes).map_err(|_| {
        SettlementError::Verification("remote bond observation response is invalid".to_owned())
    })?;
    if response.schema != FINDING_BOND_OBSERVATION_RESPONSE_SCHEMA
        || response.request_sha256 != request_sha256
        || !valid_observation(&response.observation)
    {
        return Err(SettlementError::Verification(
            "remote bond observation response binding is invalid".to_owned(),
        ));
    }
    Ok(response.observation)
}

fn valid_observation(observation: &FindingBondObservationRecheck) -> bool {
    observation
        .block_hash
        .as_deref()
        .is_none_or(valid_chain_hash)
        && valid_text(&observation.identity_registry_record)
        && valid_chain_hash(&observation.operator_key_hash)
        && observation.operator_key_epoch > 0
        && !matches!(
            observation.observed_finality,
            FindingObservedFinality::Confirmations { depth: 0 }
        )
}

fn valid_chain_hash(value: &str) -> bool {
    let value = value.strip_prefix("0x").unwrap_or(value);
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation() -> FindingBondObservationRecheck {
        FindingBondObservationRecheck {
            block_hash: Some("a".repeat(64)),
            observed_finality: FindingObservedFinality::Confirmations { depth: 12 },
            identity_registry_record: "registry:operator-1".to_owned(),
            operator_key_hash: "b".repeat(64),
            operator_key_epoch: 7,
            operator_active: true,
        }
    }

    #[test]
    fn response_is_canonical_and_request_bound() {
        let response = FindingBondObservationResponse {
            schema: FINDING_BOND_OBSERVATION_RESPONSE_SCHEMA.to_owned(),
            request_sha256: "c".repeat(64),
            observation: observation(),
        };
        let bytes = canonical_json_bytes(&response).unwrap_or_default();
        assert!(decode_response(&"c".repeat(64), &bytes).is_ok());
        assert!(decode_response(&"d".repeat(64), &bytes).is_err());

        let noncanonical = serde_json::to_string_pretty(&response).unwrap_or_default();
        assert!(decode_response(&"c".repeat(64), noncanonical.as_bytes()).is_err());
    }

    #[test]
    fn response_rejects_malformed_chain_state() {
        let mut invalid = observation();
        invalid.operator_key_epoch = 0;
        assert!(!valid_observation(&invalid));
        invalid.operator_key_epoch = 1;
        invalid.operator_key_hash = "0xABC".to_owned();
        assert!(!valid_observation(&invalid));
    }

    #[test]
    fn configuration_rejects_cleartext_credentials_and_invalid_secrets() {
        assert!(RemoteFindingBondObservationSourceConfig::new(
            "http://observer.example",
            "secret",
            "tenant:one",
            Duration::from_secs(5),
        )
        .is_err());
        assert!(RemoteFindingBondObservationSourceConfig::new(
            "https://user@observer.example",
            "secret",
            "tenant:one",
            Duration::from_secs(5),
        )
        .is_err());
        assert!(RemoteFindingBondObservationSourceConfig::new(
            "https://observer.example",
            "bad token",
            "tenant:one",
            Duration::from_secs(5),
        )
        .is_err());
    }

    #[test]
    fn remote_wire_values_conform_to_registered_schemas() -> Result<(), String> {
        let request = FindingBondObservationRequest {
            schema: FINDING_BOND_OBSERVATION_REQUEST_SCHEMA.to_owned(),
            operation: FindingBondObservationOperation::Observe,
            enforcement_envelope_sha256: "1".repeat(64),
            bond_snapshot_envelope_sha256: "2".repeat(64),
            enforcement_id: "3".repeat(64),
            liability_key: "4".repeat(64),
            chain_id: "eip155:1".to_owned(),
            vault_contract: "0x1000000000000000000000000000000000000001".to_owned(),
            vault_id: "5".repeat(64),
            block_number: 100,
            block_hash: "6".repeat(64),
            identity_registry_record: "registry:operator-1".to_owned(),
            operator_key_hash: "7".repeat(64),
            operator_key_epoch: 2,
            finality_requirement: FindingFinalityRequirement::Confirmations { min_depth: 12 },
        };
        validate_schema(
            "bond-observation-request.schema.json",
            &serde_json::to_value(request).map_err(|error| error.to_string())?,
        )?;

        let response = FindingBondObservationResponse {
            schema: FINDING_BOND_OBSERVATION_RESPONSE_SCHEMA.to_owned(),
            request_sha256: "8".repeat(64),
            observation: observation(),
        };
        let response_value = serde_json::to_value(response).map_err(|error| error.to_string())?;
        validate_schema("bond-observation-response.schema.json", &response_value)?;
        let mut unknown = response_value;
        unknown["unknown"] = serde_json::json!(true);
        assert!(validate_schema("bond-observation-response.schema.json", &unknown).is_err());
        Ok(())
    }

    fn validate_schema(name: &str, value: &serde_json::Value) -> Result<(), String> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../spec/schemas/chio-finding/v1")
            .join(name);
        let schema = chio_spec_validate::load_json(&path).map_err(|error| error.to_string())?;
        chio_spec_validate::validate_value(&path, &schema, &path, value)
            .map_err(|error| error.to_string())
    }
}
