use std::io::Read;
use std::time::Duration;

use chio_egress_contract::HttpEgressContract;
use chio_federation::frost::{
    FrostAnchorError, FrostAnchoredAuthorizationSlot, FrostAuthorizationSlotAnchor,
    FrostAuthorizationSlotAnchorWriter, FrostEpochAnchor, FrostEpochAnchorWriter,
    FrostEpochCheckpointV1, VerifiedFrostAuthorizationSlotBind, VerifiedFrostAuthorizationSlotBurn,
    VerifiedFrostAuthorizationSlotCompletion, VerifiedFrostEpochAdvance,
};
use reqwest::blocking::{Client, Response};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::Serialize;
use url::Url;

#[path = "frost/coordinator.rs"]
mod coordinator;

pub use coordinator::*;

const MAX_ANCHOR_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct RemoteFrostAnchorConfig {
    pub base_url: String,
    pub bearer_token: String,
    pub timeout: Duration,
}

impl std::fmt::Debug for RemoteFrostAnchorConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteFrostAnchorConfig")
            .field("base_url", &self.base_url)
            .field("bearer_token", &"<redacted>")
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RemoteFrostAnchorConfigError {
    #[error("invalid FROST anchor URL: {0}")]
    Url(String),
    #[error("FROST anchor URL must use HTTPS")]
    InsecureTransport,
    #[error("FROST anchor URL must not contain credentials, query, or fragment")]
    AmbiguousUrl,
    #[error("FROST anchor bearer token is invalid")]
    InvalidToken,
    #[error("FROST anchor timeout must be non-zero")]
    InvalidTimeout,
    #[error("failed to construct FROST anchor HTTP client: {0}")]
    Client(String),
    #[error("invalid FROST anchor HTTP egress contract: {0}")]
    InvalidEgressContract(String),
}

#[derive(Clone)]
pub struct RemoteFrostAnchorClient {
    client: Client,
    base_url: Url,
    bearer_token: String,
    egress_contract: HttpEgressContract,
}

impl std::fmt::Debug for RemoteFrostAnchorClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteFrostAnchorClient")
            .field("base_url", &self.base_url)
            .field("bearer_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl RemoteFrostAnchorClient {
    pub fn new(config: RemoteFrostAnchorConfig) -> Result<Self, RemoteFrostAnchorConfigError> {
        let base_url = Url::parse(&config.base_url)
            .map_err(|error| RemoteFrostAnchorConfigError::Url(error.to_string()))?;
        if base_url.scheme() != "https" {
            return Err(RemoteFrostAnchorConfigError::InsecureTransport);
        }
        if base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(RemoteFrostAnchorConfigError::AmbiguousUrl);
        }
        if config.bearer_token.is_empty()
            || config.bearer_token.trim() != config.bearer_token
            || config
                .bearer_token
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(RemoteFrostAnchorConfigError::InvalidToken);
        }
        if config.timeout.is_zero() {
            return Err(RemoteFrostAnchorConfigError::InvalidTimeout);
        }
        let egress_contract = crate::anchor_egress::strict_https_contract(
            &base_url,
            "control-plane.frost-anchor",
            MAX_ANCHOR_RESPONSE_BYTES,
        )
        .map_err(RemoteFrostAnchorConfigError::InvalidEgressContract)?;
        // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: this blocking anchor client
        // denies redirects and proxies, and each request is contract-preflighted.
        let client = Client::builder()
            .timeout(config.timeout)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|error| RemoteFrostAnchorConfigError::Client(error.to_string()))?;
        Ok(Self {
            client,
            base_url,
            bearer_token: config.bearer_token,
            egress_contract,
        })
    }

    fn endpoint(&self, segments: &[&str]) -> Result<Url, FrostAnchorError> {
        let mut url = self.base_url.clone();
        let mut path = url.path_segments_mut().map_err(|()| {
            FrostAnchorError::InvalidResponse("anchor URL cannot carry path segments".to_string())
        })?;
        path.pop_if_empty();
        path.extend(segments.iter().copied());
        drop(path);
        Ok(url)
    }

    fn get_json<T: DeserializeOwned>(&self, url: Url) -> Result<T, FrostAnchorError> {
        self.egress_contract
            .enforce_url_with_dns(url.as_str(), 0)
            .map_err(unavailable)?;
        let response = self
            .client
            .request(Method::GET, url)
            .bearer_auth(&self.bearer_token)
            // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: the stored contract was
            // enforced immediately above for this exact URL.
            .send()
            .map_err(unavailable)?;
        decode_response(&self.egress_contract, response)
    }

    fn post_json<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        url: Url,
        body: &B,
    ) -> Result<T, FrostAnchorError> {
        self.egress_contract
            .enforce_url_with_dns(url.as_str(), 0)
            .map_err(unavailable)?;
        let response = self
            .client
            .request(Method::POST, url)
            .bearer_auth(&self.bearer_token)
            .json(body)
            // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: the stored contract was
            // enforced immediately above for this exact URL.
            .send()
            .map_err(unavailable)?;
        decode_response(&self.egress_contract, response)
    }
}

impl FrostEpochAnchor for RemoteFrostAnchorClient {
    fn resolve_epoch_checkpoint(
        &self,
        scope_id: &str,
    ) -> Result<FrostEpochCheckpointV1, FrostAnchorError> {
        self.get_json(self.endpoint(&["v1", "frost", "epochs", scope_id])?)
    }
}

impl FrostEpochAnchorWriter for RemoteFrostAnchorClient {
    fn compare_and_swap_epoch(
        &self,
        expected_checkpoint_digest: &str,
        advance: &VerifiedFrostEpochAdvance,
    ) -> Result<FrostEpochCheckpointV1, FrostAnchorError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Request<'a> {
            namespace: &'static str,
            expected_checkpoint_digest: &'a str,
            predecessor: &'a FrostEpochCheckpointV1,
            target_roster: &'a chio_federation::frost::FrostRosterV1,
            rotation_authorization_digest: &'a str,
            burn_summary: &'a chio_federation::frost::FrostSessionBurnSummaryV1,
            activation_fence: u64,
            clock_high_water: u64,
        }

        self.post_json(
            self.endpoint(&[
                "v1",
                "frost",
                "epochs",
                &advance.target_roster().scope_id,
                "compare-and-swap",
            ])?,
            &Request {
                namespace: "epoch",
                expected_checkpoint_digest,
                predecessor: advance.predecessor(),
                target_roster: advance.target_roster(),
                rotation_authorization_digest: advance.rotation_authorization_digest(),
                burn_summary: advance.burn_summary(),
                activation_fence: advance.activation_fence(),
                clock_high_water: advance.clock_high_water(),
            },
        )
    }
}

impl FrostAuthorizationSlotAnchor for RemoteFrostAnchorClient {
    fn resolve_authorization_slot(
        &self,
        scope_id: &str,
        slot_id: &str,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError> {
        self.get_json(self.endpoint(&["v1", "frost", "authorization-slots", scope_id, slot_id])?)
    }
}

impl FrostAuthorizationSlotAnchorWriter for RemoteFrostAnchorClient {
    fn compare_and_swap_bind(
        &self,
        bind: &VerifiedFrostAuthorizationSlotBind,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError> {
        self.post_json(
            self.endpoint(&[
                "v1",
                "frost",
                "authorization-slots",
                bind.request().scope_id(),
                bind.request().slot_id(),
                "bind",
            ])?,
            bind.request(),
        )
    }

    fn compare_and_swap_complete(
        &self,
        completion: &VerifiedFrostAuthorizationSlotCompletion,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError> {
        self.post_json(
            self.endpoint(&[
                "v1",
                "frost",
                "authorization-slot-transitions",
                completion.request().expected_bound_checkpoint_digest(),
                "complete",
            ])?,
            completion.request(),
        )
    }

    fn compare_and_swap_burn(
        &self,
        burn: &VerifiedFrostAuthorizationSlotBurn,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError> {
        self.post_json(
            self.endpoint(&[
                "v1",
                "frost",
                "authorization-slot-transitions",
                burn.request().expected_bound_checkpoint_digest(),
                "burn",
            ])?,
            burn.request(),
        )
    }
}

fn decode_response<T: DeserializeOwned>(
    egress_contract: &HttpEgressContract,
    mut response: Response,
) -> Result<T, FrostAnchorError> {
    let status = response.status();
    if !status.is_success() {
        return Err(FrostAnchorError::Unavailable(format!(
            "anchor returned HTTP {status}"
        )));
    }
    if let Some(length) = response.content_length() {
        egress_contract
            .enforce_response_bytes(length)
            .map_err(|error| FrostAnchorError::InvalidResponse(error.to_string()))?;
    }
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(MAX_ANCHOR_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(unavailable)?;
    egress_contract
        .enforce_response_bytes(bytes.len() as u64)
        .map_err(|error| FrostAnchorError::InvalidResponse(error.to_string()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| FrostAnchorError::InvalidResponse(error.to_string()))
}

fn unavailable(error: impl std::fmt::Display) -> FrostAnchorError {
    FrostAnchorError::Unavailable(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_client_requires_https_auth_and_timeout() {
        for config in [
            RemoteFrostAnchorConfig {
                base_url: "http://anchor.example".to_string(),
                bearer_token: "token".to_string(),
                timeout: Duration::from_secs(1),
            },
            RemoteFrostAnchorConfig {
                base_url: "https://anchor.example".to_string(),
                bearer_token: String::new(),
                timeout: Duration::from_secs(1),
            },
            RemoteFrostAnchorConfig {
                base_url: "https://anchor.example".to_string(),
                bearer_token: "token".to_string(),
                timeout: Duration::ZERO,
            },
        ] {
            assert!(RemoteFrostAnchorClient::new(config).is_err());
        }
        assert!(RemoteFrostAnchorClient::new(RemoteFrostAnchorConfig {
            base_url: "https://anchor.example/api".to_string(),
            bearer_token: "token".to_string(),
            timeout: Duration::from_secs(1),
        })
        .is_ok());
    }
}
