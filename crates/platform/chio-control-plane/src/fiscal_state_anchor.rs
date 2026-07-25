use std::fmt;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use chio_core::canonical::canonical_json_bytes;
use chio_egress_contract::HttpEgressContract;
use chio_fiscal::{
    FiscalCharterRegistry, FiscalGenesisPolicy, FiscalStateAnchor, FiscalStateAnchorError,
    SignedFiscalContinuityCheckpoint, VerifiedFiscalContinuityAdvance,
    VerifiedFiscalContinuityCheckpoint,
};
use serde::Serialize;

pub const FISCAL_STATE_READ_PATH: &str = "/v1/fiscal-state/read";
pub const FISCAL_STATE_CAS_PATH: &str = "/v1/fiscal-state/compare-and-swap";
const FISCAL_STATE_TRANSPORT_LIMIT: usize = 4 * 1024 * 1024;

#[derive(Clone)]
pub struct RemoteFiscalStateAnchorConfig {
    pub base_url: String,
    pub bearer_token: String,
    pub timeout: Duration,
    pub policy: FiscalGenesisPolicy,
    pub charters: FiscalCharterRegistry,
}

impl fmt::Debug for RemoteFiscalStateAnchorConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteFiscalStateAnchorConfig")
            .field("base_url", &self.base_url)
            .field("bearer_token", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("policy_id", &self.policy.policy_id)
            .field("anchor_id", &self.policy.anchor_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FiscalStateAnchorConfigError {
    #[error("invalid fiscal anchor URL: {0}")]
    InvalidUrl(String),
    #[error("fiscal anchor bearer token is invalid")]
    InvalidBearerToken,
    #[error("fiscal anchor timeout must be greater than zero")]
    InvalidTimeout,
    #[error("fiscal anchor policy or charter registry is invalid: {0}")]
    InvalidPins(String),
    #[error("failed to build fiscal anchor HTTP client: {0}")]
    HttpClient(String),
    #[error("invalid fiscal anchor HTTP egress contract: {0}")]
    InvalidEgressContract(String),
}

impl RemoteFiscalStateAnchorConfig {
    pub fn validate(&self) -> Result<(), FiscalStateAnchorConfigError> {
        let endpoint = url::Url::parse(&self.base_url)
            .map_err(|error| FiscalStateAnchorConfigError::InvalidUrl(error.to_string()))?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.cannot_be_a_base()
        {
            return Err(FiscalStateAnchorConfigError::InvalidUrl(
                "URL must be an HTTPS base URL without credentials, query, or fragment".to_owned(),
            ));
        }
        if !valid_bearer_token(&self.bearer_token) {
            return Err(FiscalStateAnchorConfigError::InvalidBearerToken);
        }
        if self.timeout.is_zero() {
            return Err(FiscalStateAnchorConfigError::InvalidTimeout);
        }
        crate::anchor_egress::strict_https_contract(
            &endpoint,
            "control-plane.fiscal-state-anchor",
            FISCAL_STATE_TRANSPORT_LIMIT as u64,
        )
        .map_err(FiscalStateAnchorConfigError::InvalidEgressContract)?;
        let genesis = self
            .charters
            .resolve(
                &self.policy.genesis_charter_id,
                &self.policy.genesis_charter_digest,
            )
            .map_err(|error| FiscalStateAnchorConfigError::InvalidPins(error.to_string()))?;
        self.policy
            .validate(&genesis)
            .map_err(|error| FiscalStateAnchorConfigError::InvalidPins(error.to_string()))
    }
}

trait FiscalStateAnchorTransport: Send + Sync {
    fn post(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, FiscalStateAnchorError>;
}

struct HttpsFiscalStateAnchorTransport {
    client: reqwest::blocking::Client,
    base_url: String,
    bearer_token: Arc<str>,
    egress_contract: HttpEgressContract,
}

impl HttpsFiscalStateAnchorTransport {
    fn new(config: &RemoteFiscalStateAnchorConfig) -> Result<Self, FiscalStateAnchorConfigError> {
        let endpoint = url::Url::parse(&config.base_url)
            .map_err(|error| FiscalStateAnchorConfigError::InvalidUrl(error.to_string()))?;
        let egress_contract = crate::anchor_egress::strict_https_contract(
            &endpoint,
            "control-plane.fiscal-state-anchor",
            FISCAL_STATE_TRANSPORT_LIMIT as u64,
        )
        .map_err(FiscalStateAnchorConfigError::InvalidEgressContract)?;
        // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: this blocking anchor client
        // denies redirects and proxies, and each request is contract-preflighted.
        let client = reqwest::blocking::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(config.timeout)
            .build()
            .map_err(|error| FiscalStateAnchorConfigError::HttpClient(error.to_string()))?;
        Ok(Self {
            client,
            base_url: config.base_url.trim_end_matches('/').to_owned(),
            bearer_token: Arc::from(config.bearer_token.as_str()),
            egress_contract,
        })
    }
}

impl FiscalStateAnchorTransport for HttpsFiscalStateAnchorTransport {
    fn post(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, FiscalStateAnchorError> {
        if body.len() > FISCAL_STATE_TRANSPORT_LIMIT {
            return Err(FiscalStateAnchorError::Unavailable);
        }
        let endpoint = format!("{}{path}", self.base_url);
        self.egress_contract
            .enforce_url_with_dns(&endpoint, 0)
            .map_err(|_| FiscalStateAnchorError::Unavailable)?;
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(self.bearer_token.as_ref())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: the stored contract was
            // enforced immediately above for this exact URL.
            .send()
            .map_err(|_| FiscalStateAnchorError::Unavailable)?;
        if !response.status().is_success() {
            return Err(FiscalStateAnchorError::Unavailable);
        }
        if let Some(length) = response.content_length() {
            self.egress_contract
                .enforce_response_bytes(length)
                .map_err(|_| FiscalStateAnchorError::Unavailable)?;
        }
        let mut body = Vec::new();
        response
            .take(FISCAL_STATE_TRANSPORT_LIMIT as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|_| FiscalStateAnchorError::Unavailable)?;
        self.egress_contract
            .enforce_response_bytes(body.len() as u64)
            .map_err(|_| FiscalStateAnchorError::Unavailable)?;
        Ok(body)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FiscalStateReadRequest<'a> {
    anchor_id: &'a str,
    anchor_namespace: &'a str,
    governing_operator_id: &'a str,
    genesis_policy_id: &'a str,
    genesis_policy_digest: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FiscalStateCasRequest<'a> {
    expected_checkpoint_digest: &'a str,
    advance_proof: serde_json::Value,
}

pub struct RemoteFiscalStateAnchor {
    policy: FiscalGenesisPolicy,
    charters: FiscalCharterRegistry,
    transport: Arc<dyn FiscalStateAnchorTransport>,
}

impl fmt::Debug for RemoteFiscalStateAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteFiscalStateAnchor")
            .field("policy_id", &self.policy.policy_id)
            .field("anchor_id", &self.policy.anchor_id)
            .finish_non_exhaustive()
    }
}

impl RemoteFiscalStateAnchor {
    pub fn new(
        config: RemoteFiscalStateAnchorConfig,
    ) -> Result<Self, FiscalStateAnchorConfigError> {
        config.validate()?;
        let transport = Arc::new(HttpsFiscalStateAnchorTransport::new(&config)?);
        Ok(Self {
            policy: config.policy,
            charters: config.charters,
            transport,
        })
    }

    #[cfg(test)]
    fn with_fixture_transport(
        config: RemoteFiscalStateAnchorConfig,
        transport: Arc<dyn FiscalStateAnchorTransport>,
    ) -> Result<Self, FiscalStateAnchorConfigError> {
        config.validate()?;
        Ok(Self {
            policy: config.policy,
            charters: config.charters,
            transport,
        })
    }

    fn post(
        &self,
        path: &str,
        request: &impl Serialize,
    ) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
        let request =
            canonical_json_bytes(request).map_err(|_| FiscalStateAnchorError::Divergence)?;
        let response = self.transport.post(path, &request)?;
        if response.is_empty() || response.len() > FISCAL_STATE_TRANSPORT_LIMIT {
            return Err(FiscalStateAnchorError::Divergence);
        }
        serde_json::from_slice(&response).map_err(|_| FiscalStateAnchorError::Divergence)
    }

    fn verify_response(
        &self,
        signed: SignedFiscalContinuityCheckpoint,
    ) -> Result<VerifiedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
        VerifiedFiscalContinuityCheckpoint::verify(signed, &self.policy, &self.charters)
            .map_err(|_| FiscalStateAnchorError::Divergence)
    }
}

impl FiscalStateAnchor for RemoteFiscalStateAnchor {
    fn read(&self) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
        let request = FiscalStateReadRequest {
            anchor_id: &self.policy.anchor_id,
            anchor_namespace: &self.policy.anchor_namespace,
            governing_operator_id: &self.policy.governing_operator_id,
            genesis_policy_id: &self.policy.policy_id,
            genesis_policy_digest: self
                .policy
                .digest()
                .map_err(|_| FiscalStateAnchorError::Divergence)?,
        };
        let verified = self.verify_response(self.post(FISCAL_STATE_READ_PATH, &request)?)?;
        Ok(verified.signed().clone())
    }

    fn compare_and_swap(
        &self,
        expected_checkpoint_digest: &str,
        advance: &VerifiedFiscalContinuityAdvance,
    ) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
        advance
            .reverify(&self.policy, &self.charters)
            .map_err(|_| FiscalStateAnchorError::Divergence)?;
        if expected_checkpoint_digest != advance.current().digest() {
            return Err(FiscalStateAnchorError::Conflict);
        }
        let advance_proof = serde_json::from_slice(advance.canonical_proof_bytes())
            .map_err(|_| FiscalStateAnchorError::Divergence)?;
        let request = FiscalStateCasRequest {
            expected_checkpoint_digest,
            advance_proof,
        };
        let verified = self.verify_response(self.post(FISCAL_STATE_CAS_PATH, &request)?)?;
        if verified.signed() != advance.next().signed() {
            return Err(FiscalStateAnchorError::Divergence);
        }
        Ok(verified.signed().clone())
    }
}

pub fn compose_fiscal_state_anchor(
    config: RemoteFiscalStateAnchorConfig,
) -> Result<Arc<dyn FiscalStateAnchor>, FiscalStateAnchorConfigError> {
    Ok(Arc::new(RemoteFiscalStateAnchor::new(config)?))
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

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use chio_fiscal::{FiscalGenesisPolicy, SignedFiscalCharter};

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct FixtureTransport {
        response: Vec<u8>,
        request: Mutex<Option<(String, Vec<u8>)>>,
    }

    impl FiscalStateAnchorTransport for FixtureTransport {
        fn post(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, FiscalStateAnchorError> {
            *self
                .request
                .lock()
                .map_err(|_| FiscalStateAnchorError::Unavailable)? =
                Some((path.to_owned(), body.to_vec()));
            Ok(self.response.clone())
        }
    }

    fn fixture_bytes(name: &str) -> TestResult<Vec<u8>> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../../spec/schemas/chio-fiscal/v1/fixtures/{name}.positive.json"
        ));
        Ok(std::fs::read(path)?)
    }

    fn config() -> TestResult<RemoteFiscalStateAnchorConfig> {
        let policy: FiscalGenesisPolicy =
            serde_json::from_slice(&fixture_bytes("genesis-policy")?)?;
        let charter: SignedFiscalCharter = serde_json::from_slice(&fixture_bytes("charter")?)?;
        Ok(RemoteFiscalStateAnchorConfig {
            base_url: "https://fiscal-anchor.example".to_owned(),
            bearer_token: "fixture-token".to_owned(),
            timeout: Duration::from_secs(1),
            policy,
            charters: FiscalCharterRegistry::new(vec![charter])?,
        })
    }

    #[test]
    fn config_requires_https_and_redacts_bearer_token() -> TestResult {
        let mut config = config()?;
        assert!(!format!("{config:?}").contains("fixture-token"));
        config.base_url = "http://fiscal-anchor.example".to_owned();
        assert!(matches!(
            config.validate(),
            Err(FiscalStateAnchorConfigError::InvalidUrl(_))
        ));
        Ok(())
    }

    #[test]
    fn read_reverifies_the_remote_checkpoint_and_binds_the_request() -> TestResult {
        let transport = Arc::new(FixtureTransport {
            response: fixture_bytes("continuity-checkpoint")?,
            request: Mutex::new(None),
        });
        let anchor = RemoteFiscalStateAnchor::with_fixture_transport(config()?, transport.clone())?;
        let signed = anchor.read()?;
        assert_eq!(signed.body.continuity_sequence, 0);
        let request = transport
            .request
            .lock()
            .map_err(|_| "fixture request lock poisoned")?
            .clone()
            .ok_or("fixture request was not captured")?;
        assert_eq!(request.0, FISCAL_STATE_READ_PATH);
        let body: serde_json::Value = serde_json::from_slice(&request.1)?;
        assert_eq!(body["anchorId"], "fiscal-anchor");
        assert_eq!(body["genesisPolicyId"], anchor.policy.policy_id);
        Ok(())
    }

    #[test]
    fn read_rejects_a_validly_encoded_but_divergent_checkpoint() -> TestResult {
        let mut checkpoint: serde_json::Value =
            serde_json::from_slice(&fixture_bytes("continuity-checkpoint")?)?;
        checkpoint["body"]["anchorNamespace"] = "other".into();
        let transport = Arc::new(FixtureTransport {
            response: serde_json::to_vec(&checkpoint)?,
            request: Mutex::new(None),
        });
        let anchor = RemoteFiscalStateAnchor::with_fixture_transport(config()?, transport)?;
        assert_eq!(anchor.read(), Err(FiscalStateAnchorError::Divergence));
        Ok(())
    }
}
