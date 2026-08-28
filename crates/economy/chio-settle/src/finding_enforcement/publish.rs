//! Durable local and remote broadcast seams for a fenced impairment intent.

use std::collections::BTreeSet;
use std::fmt;
use std::io::Read as _;
use std::net::{IpAddr, ToSocketAddrs as _};
use std::sync::Arc;
use std::time::Duration;

use chio_core::{canonical::canonical_json_bytes_from_str, canonical_json_bytes, sha256_hex};
use chio_egress_contract::HttpEgressContract;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use super::plan::{
    FindingImpairmentIntent, PlannedFindingImpairment, PlannedFindingImpairmentReconciliation,
};
use super::reconcile::{
    reconcile_finding_impairment, FindingImpairmentAttempt, FindingImpairmentOutcome,
};
use crate::PreparedEvmCall;

/// Wire schema for a digest-bound remote impairment request.
pub const FINDING_IMPAIRMENT_PUBLISHER_REQUEST_SCHEMA: &str =
    "chio.finding.impairment-publisher-request.v1";
/// Wire schema for a digest-bound remote impairment response.
pub const FINDING_IMPAIRMENT_PUBLISHER_RESPONSE_SCHEMA: &str =
    "chio.finding.impairment-publisher-response.v1";
/// Remote path that may fence and broadcast an exact impairment.
pub const FINDING_IMPAIRMENT_DISPATCH_PATH: &str = "/v1/finding-impairments/dispatch";
/// Remote path that may only observe an already fenced impairment.
pub const FINDING_IMPAIRMENT_OBSERVE_PATH: &str = "/v1/finding-impairments/observe";

const MAX_PUBLISHER_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_PUBLISHER_RESPONSE_BYTES: usize = 1024 * 1024;

/// Closed operation vocabulary understood by the remote publisher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingImpairmentPublisherOperation {
    /// Fence and broadcast the supplied call, or replay its durable result.
    Dispatch,
    /// Re-observe a stored transaction without broadcasting.
    Observe,
}

impl FindingImpairmentPublisherOperation {
    const fn path(self) -> &'static str {
        match self {
            Self::Dispatch => FINDING_IMPAIRMENT_DISPATCH_PATH,
            Self::Observe => FINDING_IMPAIRMENT_OBSERVE_PATH,
        }
    }
}

/// Exact canonical request accepted by a remote durable publisher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingImpairmentPublisherRequest {
    pub schema: String,
    pub operation: FindingImpairmentPublisherOperation,
    pub intent: FindingImpairmentIntent,
    pub call: PreparedEvmCall,
}

/// Exact canonical response returned by a remote durable publisher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingImpairmentPublisherResponse {
    pub schema: String,
    /// SHA-256 of the canonical request bytes this response answers.
    pub request_sha256: String,
    pub attempt: FindingImpairmentAttempt,
}

/// Configuration failure for the production HTTPS publisher adapter.
#[derive(Debug, Error)]
pub enum FindingImpairmentPublisherConfigError {
    #[error("remote impairment publisher URL is invalid")]
    InvalidUrl,
    #[error("remote impairment publisher bearer token is invalid")]
    InvalidBearerToken,
    #[error("remote impairment publisher namespace is invalid")]
    InvalidNamespace,
    #[error("remote impairment publisher timeout is invalid")]
    InvalidTimeout,
    #[error("remote impairment publisher egress policy is invalid")]
    InvalidEgressPolicy,
    #[error("remote impairment publisher DNS resolution failed")]
    DnsResolution,
    #[error("remote impairment publisher HTTP client could not be built")]
    HttpClient,
}

/// Immutable production transport configuration.
pub struct RemoteFindingImpairmentPublisherConfig {
    base_url: String,
    bearer_token: Zeroizing<String>,
    tenant_egress_namespace: String,
    timeout: Duration,
}

impl fmt::Debug for RemoteFindingImpairmentPublisherConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteFindingImpairmentPublisherConfig")
            .field("base_url", &self.base_url)
            .field("bearer_token", &"[REDACTED]")
            .field("tenant_egress_namespace", &self.tenant_egress_namespace)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl RemoteFindingImpairmentPublisherConfig {
    /// Construct and validate a strict HTTPS publisher configuration.
    pub fn new(
        base_url: impl Into<String>,
        bearer_token: impl Into<String>,
        tenant_egress_namespace: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, FindingImpairmentPublisherConfigError> {
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
    ) -> Result<(reqwest::Url, HttpEgressContract), FindingImpairmentPublisherConfigError> {
        let endpoint = reqwest::Url::parse(&self.base_url)
            .map_err(|_| FindingImpairmentPublisherConfigError::InvalidUrl)?;
        if self.base_url.len() > 4096
            || endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.cannot_be_a_base()
        {
            return Err(FindingImpairmentPublisherConfigError::InvalidUrl);
        }
        if self.bearer_token.len() > 16 * 1024 || !valid_bearer_token(&self.bearer_token) {
            return Err(FindingImpairmentPublisherConfigError::InvalidBearerToken);
        }
        if self.tenant_egress_namespace.is_empty()
            || self.tenant_egress_namespace.len() > 256
            || self.tenant_egress_namespace.trim() != self.tenant_egress_namespace
            || !self.tenant_egress_namespace.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
            })
        {
            return Err(FindingImpairmentPublisherConfigError::InvalidNamespace);
        }
        if self.timeout.is_zero() || self.timeout > Duration::from_secs(120) {
            return Err(FindingImpairmentPublisherConfigError::InvalidTimeout);
        }
        let host = endpoint
            .host_str()
            .ok_or(FindingImpairmentPublisherConfigError::InvalidUrl)?;
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
            max_response_bytes: MAX_PUBLISHER_RESPONSE_BYTES as u64,
        };
        contract
            .validate_dispatchable_with_pinned_dns()
            .and_then(|()| contract.enforce_url(endpoint.as_str(), 0).map(|_| ()))
            .map_err(|_| FindingImpairmentPublisherConfigError::InvalidEgressPolicy)?;
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

trait FindingImpairmentTransport: Send + Sync {
    fn post(
        &self,
        operation: FindingImpairmentPublisherOperation,
        body: &[u8],
    ) -> Result<Vec<u8>, FindingImpairmentPublishError>;
}

struct HttpsFindingImpairmentTransport {
    client: reqwest::blocking::Client,
    base_url: String,
    bearer_token: Zeroizing<String>,
    contract: HttpEgressContract,
}

impl HttpsFindingImpairmentTransport {
    fn new(
        config: RemoteFindingImpairmentPublisherConfig,
    ) -> Result<Self, FindingImpairmentPublisherConfigError> {
        let (endpoint, contract) = config.endpoint_and_contract()?;
        let host = endpoint
            .host_str()
            .ok_or(FindingImpairmentPublisherConfigError::InvalidUrl)?;
        let mut builder = reqwest::blocking::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(config.timeout);
        if host.parse::<IpAddr>().is_err() {
            let port = endpoint
                .port_or_known_default()
                .ok_or(FindingImpairmentPublisherConfigError::InvalidUrl)?;
            let addresses = (host, port)
                .to_socket_addrs()
                .map_err(|_| FindingImpairmentPublisherConfigError::DnsResolution)?
                .collect::<Vec<_>>();
            if addresses.is_empty() {
                return Err(FindingImpairmentPublisherConfigError::DnsResolution);
            }
            for address in &addresses {
                contract
                    .enforce_resolved_ip(host, address.ip())
                    .map_err(|_| FindingImpairmentPublisherConfigError::InvalidEgressPolicy)?;
            }
            builder = builder.resolve_to_addrs(host, &addresses);
        }
        let client = builder
            .build()
            .map_err(|_| FindingImpairmentPublisherConfigError::HttpClient)?;
        Ok(Self {
            client,
            base_url: config.base_url.trim_end_matches('/').to_owned(),
            bearer_token: config.bearer_token,
            contract,
        })
    }
}

impl FindingImpairmentTransport for HttpsFindingImpairmentTransport {
    fn post(
        &self,
        operation: FindingImpairmentPublisherOperation,
        body: &[u8],
    ) -> Result<Vec<u8>, FindingImpairmentPublishError> {
        if body.len() > MAX_PUBLISHER_REQUEST_BYTES {
            return Err(FindingImpairmentPublishError::Permanent(
                "remote impairment request exceeds its bound".to_owned(),
            ));
        }
        let endpoint = format!("{}{}", self.base_url, operation.path());
        self.contract
            .enforce_url(&endpoint, 0)
            .map_err(|error| FindingImpairmentPublishError::Permanent(error.to_string()))?;
        // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: construction pins every DNS
        // answer after enforcing the stored contract, and this exact request
        // is checked above. Redirects and proxies are disabled on the client.
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(self.bearer_token.as_str())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send()
            .map_err(|error| {
                FindingImpairmentPublishError::Transient(format!(
                    "remote impairment publisher unavailable: {}",
                    transport_error_class(&error)
                ))
            })?;
        let status = response.status();
        if !status.is_success() {
            let message = format!("remote impairment publisher returned HTTP {status}");
            return if status.is_server_error()
                || status == reqwest::StatusCode::REQUEST_TIMEOUT
                || status == reqwest::StatusCode::TOO_MANY_REQUESTS
            {
                Err(FindingImpairmentPublishError::Transient(message))
            } else {
                Err(FindingImpairmentPublishError::Permanent(message))
            };
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if content_type != Some("application/json") {
            return Err(FindingImpairmentPublishError::Permanent(
                "remote impairment publisher response media type is invalid".to_owned(),
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_PUBLISHER_RESPONSE_BYTES as u64)
        {
            return Err(FindingImpairmentPublishError::Permanent(
                "remote impairment publisher response exceeds its bound".to_owned(),
            ));
        }
        let mut response_body = Vec::new();
        response
            .take(MAX_PUBLISHER_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut response_body)
            .map_err(|_| {
                FindingImpairmentPublishError::Transient(
                    "remote impairment publisher response could not be read".to_owned(),
                )
            })?;
        self.contract
            .enforce_response_bytes(response_body.len() as u64)
            .map_err(|error| FindingImpairmentPublishError::Permanent(error.to_string()))?;
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

/// Production remote publisher for a service that durably fences each intent.
pub struct RemoteFindingImpairmentPublisher {
    transport: Arc<dyn FindingImpairmentTransport>,
}

impl fmt::Debug for RemoteFindingImpairmentPublisher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteFindingImpairmentPublisher")
            .finish_non_exhaustive()
    }
}

impl RemoteFindingImpairmentPublisher {
    pub fn new(
        config: RemoteFindingImpairmentPublisherConfig,
    ) -> Result<Self, FindingImpairmentPublisherConfigError> {
        Ok(Self {
            transport: Arc::new(HttpsFindingImpairmentTransport::new(config)?),
        })
    }

    #[cfg(test)]
    fn with_transport(transport: Arc<dyn FindingImpairmentTransport>) -> Self {
        Self { transport }
    }

    fn execute(
        &self,
        operation: FindingImpairmentPublisherOperation,
        intent: &FindingImpairmentIntent,
        call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        let request = FindingImpairmentPublisherRequest {
            schema: FINDING_IMPAIRMENT_PUBLISHER_REQUEST_SCHEMA.to_owned(),
            operation,
            intent: intent.clone(),
            call: call.clone(),
        };
        let request_bytes = canonical_json_bytes(&request).map_err(|_| {
            FindingImpairmentPublishError::Permanent(
                "remote impairment request canonicalization failed".to_owned(),
            )
        })?;
        if request_bytes.len() > MAX_PUBLISHER_REQUEST_BYTES {
            return Err(FindingImpairmentPublishError::Permanent(
                "remote impairment request exceeds its bound".to_owned(),
            ));
        }
        let request_sha256 = sha256_hex(&request_bytes);
        let response_bytes = self.transport.post(operation, &request_bytes)?;
        let response_text = std::str::from_utf8(&response_bytes).map_err(|_| {
            FindingImpairmentPublishError::Permanent(
                "remote impairment publisher response is not UTF-8".to_owned(),
            )
        })?;
        let canonical = canonical_json_bytes_from_str(response_text).map_err(|_| {
            FindingImpairmentPublishError::Permanent(
                "remote impairment publisher response is not canonical JSON".to_owned(),
            )
        })?;
        if canonical != response_bytes {
            return Err(FindingImpairmentPublishError::Permanent(
                "remote impairment publisher response is not canonical JSON".to_owned(),
            ));
        }
        let response: FindingImpairmentPublisherResponse = serde_json::from_slice(&response_bytes)
            .map_err(|_| {
                FindingImpairmentPublishError::Permanent(
                    "remote impairment publisher response schema is invalid".to_owned(),
                )
            })?;
        if response.schema != FINDING_IMPAIRMENT_PUBLISHER_RESPONSE_SCHEMA
            || response.request_sha256 != request_sha256
        {
            return Err(FindingImpairmentPublishError::Permanent(
                "remote impairment publisher response binding is invalid".to_owned(),
            ));
        }
        Ok(response.attempt)
    }
}

/// Failure surfaced by a [`FindingImpairmentPublisher`].
///
/// These are transport dispositions, not settlement outcomes. A publisher
/// that cannot say what happened returns an error and leaves the liability
/// where it was; it never manufactures an attempt.
#[derive(Debug, Error)]
pub enum FindingImpairmentPublishError {
    /// The intent was not durably fenced before dispatch was attempted.
    #[error("impairment intent is not durably fenced: {0}")]
    IntentNotFenced(String),
    /// The publisher could not reach the chain and may succeed on replay.
    #[error("transient impairment publisher failure: {0}")]
    Transient(String),
    /// The publisher rejected the dispatch and replay cannot succeed.
    #[error("permanent impairment publisher failure: {0}")]
    Permanent(String),
}

/// Durable publisher for one frozen impairment intent.
///
/// The trait is dyn-compatible so a coordinator can hold an
/// `Arc<dyn FindingImpairmentPublisher>`. Implementations MUST:
///
/// - refuse any intent whose id they have not already fenced durably, so
///   nothing external is dispatched before its semantic intent is persisted;
/// - be idempotent by `intent.intent_id` across process restarts and lease
///   recovery, since dispatch is at-least-once;
/// - broadcast the supplied call verbatim, never a re-derived one, and store
///   the raw transaction they broadcast before it can land;
/// - return what they actually observed. An implementation that cannot
///   determine which transaction consumed the evidence reports the stored
///   transaction it has, including the absence of an input, rather than
///   asserting a match.
///
pub trait FindingImpairmentPublisher: Send + Sync {
    /// Broadcast the prepared call for a fenced intent and report the result.
    fn publish(
        &self,
        intent: &FindingImpairmentIntent,
        call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError>;

    /// Re-observe the stored transaction for an already broadcast intent.
    ///
    /// This method MUST NOT broadcast. It re-reads the transaction receipt,
    /// canonical block identity, and configured finality depth immediately
    /// before the coordinator commits confirmation or settlement. `call` is
    /// supplied only so the returned raw transaction can be checked against
    /// the same frozen bytes as the original publication.
    fn observe(
        &self,
        intent: &FindingImpairmentIntent,
        call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError>;
}

impl FindingImpairmentPublisher for RemoteFindingImpairmentPublisher {
    fn publish(
        &self,
        intent: &FindingImpairmentIntent,
        call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        self.execute(FindingImpairmentPublisherOperation::Dispatch, intent, call)
    }

    fn observe(
        &self,
        intent: &FindingImpairmentIntent,
        call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        self.execute(FindingImpairmentPublisherOperation::Observe, intent, call)
    }
}

/// Dispatch a planned impairment through a publisher and reconcile the
/// result against the frozen intent.
///
/// The publisher's report is never trusted as an outcome on its own: whatever
/// it returns goes through [`reconcile_finding_impairment`], so a publisher
/// cannot confirm an impairment the frozen intent does not match.
pub fn dispatch_finding_impairment(
    planned: &PlannedFindingImpairment,
    publisher: &dyn FindingImpairmentPublisher,
) -> Result<FindingImpairmentOutcome, FindingImpairmentPublishError> {
    let attempt = publisher.publish(planned.intent(), planned.call())?;
    Ok(reconcile_finding_impairment(planned.intent(), &attempt))
}

/// Re-observe and reconcile an already broadcast impairment without
/// dispatching it again.
pub fn reobserve_finding_impairment(
    planned: &PlannedFindingImpairment,
    publisher: &dyn FindingImpairmentPublisher,
) -> Result<FindingImpairmentOutcome, FindingImpairmentPublishError> {
    let attempt = publisher.observe(planned.intent(), planned.call())?;
    Ok(reconcile_finding_impairment(planned.intent(), &attempt))
}

/// Re-observe a reconciliation-only plan without making it dispatchable.
pub fn reobserve_finding_impairment_for_reconciliation(
    planned: &PlannedFindingImpairmentReconciliation,
    publisher: &dyn FindingImpairmentPublisher,
) -> Result<FindingImpairmentOutcome, FindingImpairmentPublishError> {
    let planned = planned.planned();
    let attempt = publisher.observe(planned.intent(), planned.call())?;
    Ok(reconcile_finding_impairment(planned.intent(), &attempt))
}

#[cfg(test)]
mod remote_tests {
    use super::*;
    use crate::{FindingImpairmentDestination, FindingVaultRejection, StoredImpairmentTransaction};
    use chio_core::capability::scope::MonetaryAmount;

    struct ResponseTransport {
        corrupt_binding: bool,
        append_newline: bool,
    }

    impl FindingImpairmentTransport for ResponseTransport {
        fn post(
            &self,
            operation: FindingImpairmentPublisherOperation,
            body: &[u8],
        ) -> Result<Vec<u8>, FindingImpairmentPublishError> {
            let request: FindingImpairmentPublisherRequest = serde_json::from_slice(body)
                .map_err(|_| FindingImpairmentPublishError::Permanent("request".to_owned()))?;
            if request.schema != FINDING_IMPAIRMENT_PUBLISHER_REQUEST_SCHEMA
                || request.operation != operation
            {
                return Err(FindingImpairmentPublishError::Permanent(
                    "request binding".to_owned(),
                ));
            }
            let request_sha256 = if self.corrupt_binding {
                "0".repeat(64)
            } else {
                sha256_hex(body)
            };
            let response = FindingImpairmentPublisherResponse {
                schema: FINDING_IMPAIRMENT_PUBLISHER_RESPONSE_SCHEMA.to_owned(),
                request_sha256,
                attempt: FindingImpairmentAttempt::Rejected {
                    rejection: FindingVaultRejection::BondNotLive,
                    stored: None,
                },
            };
            let mut bytes = canonical_json_bytes(&response)
                .map_err(|_| FindingImpairmentPublishError::Permanent("response".to_owned()))?;
            if self.append_newline {
                bytes.push(b'\n');
            }
            Ok(bytes)
        }
    }

    fn intent() -> FindingImpairmentIntent {
        FindingImpairmentIntent {
            intent_id: "intent-1".to_owned(),
            enforcement_id: "enforcement-1".to_owned(),
            liability_key: "liability-1".to_owned(),
            bond_snapshot_envelope_sha256: "1".repeat(64),
            chain_id: "eip155:1".to_owned(),
            target_contract: "0x1000000000000000000000000000000000000001".to_owned(),
            vault_id: format!("0x{}", "2".repeat(64)),
            evidence_hash: format!("0x{}", "3".repeat(64)),
            merkle_root: format!("0x{}", "4".repeat(64)),
            amount: MonetaryAmount {
                units: 10,
                currency: "USD".to_owned(),
            },
            slash_amount_minor_units: 10,
            destinations: vec![FindingImpairmentDestination {
                destination: "0x1000000000000000000000000000000000000002".to_owned(),
                amount: MonetaryAmount {
                    units: 10,
                    currency: "USD".to_owned(),
                },
                share_minor_units: 10,
            }],
        }
    }

    fn call() -> PreparedEvmCall {
        PreparedEvmCall {
            from_address: "0x1000000000000000000000000000000000000003".to_owned(),
            to_address: "0x1000000000000000000000000000000000000001".to_owned(),
            data: "0x1234".to_owned(),
            gas_limit: Some(100_000),
        }
    }

    #[test]
    fn remote_response_is_bound_to_exact_canonical_request() {
        let publisher =
            RemoteFindingImpairmentPublisher::with_transport(Arc::new(ResponseTransport {
                corrupt_binding: false,
                append_newline: false,
            }));

        let attempt = publisher.publish(&intent(), &call());

        assert_eq!(
            attempt.ok(),
            Some(FindingImpairmentAttempt::Rejected {
                rejection: FindingVaultRejection::BondNotLive,
                stored: None,
            })
        );
    }

    #[test]
    fn remote_response_with_another_request_digest_fails_closed() {
        let publisher =
            RemoteFindingImpairmentPublisher::with_transport(Arc::new(ResponseTransport {
                corrupt_binding: true,
                append_newline: false,
            }));

        let error = publisher.publish(&intent(), &call());

        assert!(matches!(
            error,
            Err(FindingImpairmentPublishError::Permanent(message))
                if message.contains("binding")
        ));
    }

    #[test]
    fn noncanonical_remote_response_fails_closed() {
        let publisher =
            RemoteFindingImpairmentPublisher::with_transport(Arc::new(ResponseTransport {
                corrupt_binding: false,
                append_newline: true,
            }));

        let error = publisher.observe(&intent(), &call());

        assert!(matches!(
            error,
            Err(FindingImpairmentPublishError::Permanent(message))
                if message.contains("canonical JSON")
        ));
    }

    #[test]
    fn publisher_configuration_rejects_unsafe_network_boundaries() {
        for endpoint in [
            "http://publisher.example",
            "https://user@publisher.example",
            "https://publisher.example?token=secret",
            "https://127.0.0.1",
            "https://[::1]",
        ] {
            assert!(RemoteFindingImpairmentPublisherConfig::new(
                endpoint,
                "token",
                "tenant:one",
                Duration::from_secs(5),
            )
            .is_err());
        }
        assert!(RemoteFindingImpairmentPublisherConfig::new(
            "https://publisher.example/api",
            "token",
            "tenant:one",
            Duration::from_secs(5),
        )
        .is_ok());
    }

    #[test]
    fn publisher_debug_output_redacts_credentials() {
        let config = RemoteFindingImpairmentPublisherConfig::new(
            "https://publisher.example",
            "super-secret-token",
            "tenant:one",
            Duration::from_secs(5),
        );
        let Some(config) = config.ok() else {
            panic!("safe publisher configuration was rejected");
        };

        let debug = format!("{config:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret-token"));
    }

    #[test]
    fn remote_wire_values_conform_to_registered_schemas() -> Result<(), String> {
        let request = FindingImpairmentPublisherRequest {
            schema: FINDING_IMPAIRMENT_PUBLISHER_REQUEST_SCHEMA.to_owned(),
            operation: FindingImpairmentPublisherOperation::Dispatch,
            intent: intent(),
            call: call(),
        };
        let request_value = serde_json::to_value(request).map_err(|error| error.to_string())?;
        validate_schema("impairment-publisher-request.schema.json", &request_value)?;

        let response = FindingImpairmentPublisherResponse {
            schema: FINDING_IMPAIRMENT_PUBLISHER_RESPONSE_SCHEMA.to_owned(),
            request_sha256: "5".repeat(64),
            attempt: FindingImpairmentAttempt::Rejected {
                rejection: FindingVaultRejection::BondNotLive,
                stored: None,
            },
        };
        let response_value = serde_json::to_value(response).map_err(|error| error.to_string())?;
        validate_schema("impairment-publisher-response.schema.json", &response_value)?;

        let observed = FindingImpairmentPublisherResponse {
            schema: FINDING_IMPAIRMENT_PUBLISHER_RESPONSE_SCHEMA.to_owned(),
            request_sha256: "6".repeat(64),
            attempt: FindingImpairmentAttempt::Observed {
                stored: StoredImpairmentTransaction {
                    chain_id: "eip155:1".to_owned(),
                    tx_hash: format!("0x{}", "7".repeat(64)),
                    to_address: "0x1000000000000000000000000000000000000001".to_owned(),
                    input_data: Some("0x1234".to_owned()),
                    receipt: Some(crate::EvmTransactionReceipt {
                        tx_hash: format!("0x{}", "7".repeat(64)),
                        block_number: 10,
                        block_hash: format!("0x{}", "8".repeat(64)),
                        status: true,
                        from_address: "0x1000000000000000000000000000000000000003".to_owned(),
                        to_address: "0x1000000000000000000000000000000000000001".to_owned(),
                        gas_used: 21_000,
                        observed_at: 100,
                        logs: Vec::new(),
                    }),
                    finality: Some(crate::SettlementFinalityStatus::Finalized),
                },
            },
        };
        validate_schema(
            "impairment-publisher-response.schema.json",
            &serde_json::to_value(observed).map_err(|error| error.to_string())?,
        )?;

        let mut unknown = response_value;
        unknown["unknown"] = serde_json::json!(true);
        assert!(validate_schema("impairment-publisher-response.schema.json", &unknown).is_err());
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
