use std::fmt;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use chio_core::economic_continuity::{
    assess_economic_state_readiness, reverify_economic_effect_cancellation_advance,
    reverify_economic_effect_dispatch_advance, reverify_economic_state_batch_advance,
    verify_economic_admission_batch, verify_economic_effect_cancellation_commit,
    verify_economic_effect_dispatch_commit, verify_economic_state_batch_commit,
    verify_economic_state_view, EconomicAdmissionHandoffVerifier, EconomicCheckpointReadQuery,
    EconomicEffectCancellationProofVerifier, EconomicEffectDispatchCommitV1, EconomicStateAnchor,
    EconomicStateAnchorError, EconomicStateAnchorPins, EconomicStateAnchorViewV1,
    EconomicStateReadQuery, EconomicStateReadiness, EconomicStateReadinessExpectation,
    EconomicTransitionProofVerifier, QualifiedEconomicEffectUnknownAdvance,
    QualifiedGenericEconomicStateBatchAdvance, VerifiedEconomicEffectCancellationAdvance,
    VerifiedEconomicEffectDispatch, VerifiedEconomicEffectDispatchAdvance,
    VerifiedEconomicEffectNotDispatched, VerifiedEconomicStateBatchAdvance,
    VerifiedEconomicStateView, MAX_ECONOMIC_BATCH_BYTES, MAX_ECONOMIC_INLINE_CONTENT_BYTES,
    MAX_ECONOMIC_TERMINAL_CONTENT_BYTES, MAX_ECONOMIC_TRANSITIONS,
};
use chio_egress_contract::HttpEgressContract;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const ECONOMIC_STATE_READ_PATH: &str = "/v1/economic-state/read";
pub const ECONOMIC_STATE_CHECKPOINT_READ_PATH: &str = "/v1/economic-state/checkpoints/read";
pub const ECONOMIC_STATE_CAS_PATH: &str = "/v1/economic-state/compare-and-swap";
pub const ECONOMIC_EFFECT_DISPATCH_PATH: &str = "/v1/economic-state/effects/dispatch";
pub const ECONOMIC_EFFECT_CANCELLATION_PATH: &str = "/v1/economic-state/effects/cancel";
const ECONOMIC_STATE_REQUEST_LIMIT: usize = MAX_ECONOMIC_BATCH_BYTES;
const ECONOMIC_STATE_RESPONSE_LIMIT: usize = MAX_ECONOMIC_TRANSITIONS
    * (MAX_ECONOMIC_INLINE_CONTENT_BYTES + MAX_ECONOMIC_TERMINAL_CONTENT_BYTES)
    + 4 * 1024 * 1024;

pub use crate::economic_effect_coordinator::SequencedEconomicEffectCoordinator as SequencedEconomicEffectDispatcher;

#[derive(Clone)]
pub struct RemoteEconomicStateAnchorConfig {
    pub base_url: String,
    pub bearer_token: String,
    pub timeout: Duration,
    pub pins: EconomicStateAnchorPins,
}

impl fmt::Debug for RemoteEconomicStateAnchorConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteEconomicStateAnchorConfig")
            .field("base_url", &self.base_url)
            .field("bearer_token", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("pins", &self.pins)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EconomicStateAnchorConfigError {
    #[error("invalid economic anchor URL: {0}")]
    InvalidUrl(String),
    #[error("economic anchor bearer token is invalid")]
    InvalidBearerToken,
    #[error("economic anchor timeout must be greater than zero")]
    InvalidTimeout,
    #[error("failed to build economic anchor HTTP client: {0}")]
    HttpClient(String),
    #[error("invalid economic anchor HTTP egress contract: {0}")]
    InvalidEgressContract(String),
    #[error("invalid economic anchor pins: {0}")]
    InvalidPins(#[from] EconomicStateAnchorError),
}

impl RemoteEconomicStateAnchorConfig {
    pub fn validate(&self) -> Result<(), EconomicStateAnchorConfigError> {
        let endpoint = url::Url::parse(&self.base_url)
            .map_err(|error| EconomicStateAnchorConfigError::InvalidUrl(error.to_string()))?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.cannot_be_a_base()
        {
            return Err(EconomicStateAnchorConfigError::InvalidUrl(
                "URL must be an HTTPS base URL without credentials, query, or fragment".to_owned(),
            ));
        }
        if !valid_bearer_token(&self.bearer_token) {
            return Err(EconomicStateAnchorConfigError::InvalidBearerToken);
        }
        if self.timeout.is_zero() {
            return Err(EconomicStateAnchorConfigError::InvalidTimeout);
        }
        crate::anchor_egress::strict_https_contract(
            &endpoint,
            "control-plane.economic-state-anchor",
            ECONOMIC_STATE_RESPONSE_LIMIT as u64,
        )
        .map_err(EconomicStateAnchorConfigError::InvalidEgressContract)?;
        self.pins.validate()?;
        Ok(())
    }
}

trait EconomicStateAnchorTransport: Send + Sync {
    fn post(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, EconomicStateAnchorError>;
}

struct HttpsEconomicStateAnchorTransport {
    client: reqwest::blocking::Client,
    base_url: String,
    bearer_token: Arc<str>,
    egress_contract: HttpEgressContract,
}

impl fmt::Debug for HttpsEconomicStateAnchorTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpsEconomicStateAnchorTransport")
            .field("base_url", &self.base_url)
            .field("bearer_token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl HttpsEconomicStateAnchorTransport {
    fn new(
        config: &RemoteEconomicStateAnchorConfig,
    ) -> Result<Self, EconomicStateAnchorConfigError> {
        let endpoint = url::Url::parse(&config.base_url)
            .map_err(|error| EconomicStateAnchorConfigError::InvalidUrl(error.to_string()))?;
        let egress_contract = crate::anchor_egress::strict_https_contract(
            &endpoint,
            "control-plane.economic-state-anchor",
            ECONOMIC_STATE_RESPONSE_LIMIT as u64,
        )
        .map_err(EconomicStateAnchorConfigError::InvalidEgressContract)?;
        // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: this blocking anchor client
        // denies redirects and proxies, and each request is contract-preflighted.
        let client = reqwest::blocking::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(config.timeout)
            .build()
            .map_err(|error| EconomicStateAnchorConfigError::HttpClient(error.to_string()))?;
        Ok(Self {
            client,
            base_url: config.base_url.trim_end_matches('/').to_owned(),
            bearer_token: Arc::from(config.bearer_token.as_str()),
            egress_contract,
        })
    }
}

impl EconomicStateAnchorTransport for HttpsEconomicStateAnchorTransport {
    fn post(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, EconomicStateAnchorError> {
        if body.len() > ECONOMIC_STATE_REQUEST_LIMIT {
            return Err(EconomicStateAnchorError::Unavailable(
                "economic anchor request exceeds the transport bound".to_owned(),
            ));
        }
        let endpoint = format!("{}{path}", self.base_url);
        self.egress_contract
            .enforce_url_with_dns(&endpoint, 0)
            .map_err(|error| EconomicStateAnchorError::Unavailable(error.to_string()))?;
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(self.bearer_token.as_ref())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: the stored contract was
            // enforced immediately above for this exact URL.
            .send()
            .map_err(|error| EconomicStateAnchorError::Unavailable(error.to_string()))?;
        if !response.status().is_success() {
            return Err(EconomicStateAnchorError::Unavailable(format!(
                "economic anchor returned HTTP {}",
                response.status()
            )));
        }
        if let Some(length) = response.content_length() {
            self.egress_contract
                .enforce_response_bytes(length)
                .map_err(|error| EconomicStateAnchorError::Unavailable(error.to_string()))?;
        }
        let mut body = Vec::new();
        response
            .take(ECONOMIC_STATE_RESPONSE_LIMIT as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|error| EconomicStateAnchorError::Unavailable(error.to_string()))?;
        self.egress_contract
            .enforce_response_bytes(body.len() as u64)
            .map_err(|error| EconomicStateAnchorError::Unavailable(error.to_string()))?;
        ensure_bounded_response(&body)?;
        Ok(body)
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

pub struct RemoteEconomicStateAnchor {
    pins: EconomicStateAnchorPins,
    transition_verifier: Arc<dyn EconomicTransitionProofVerifier>,
    admission_verifier: Arc<dyn EconomicAdmissionHandoffVerifier>,
    cancellation_verifier: Arc<dyn EconomicEffectCancellationProofVerifier>,
    transport: Arc<dyn EconomicStateAnchorTransport>,
}

impl fmt::Debug for RemoteEconomicStateAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteEconomicStateAnchor")
            .field("pins", &self.pins)
            .finish_non_exhaustive()
    }
}

impl RemoteEconomicStateAnchor {
    pub fn new(
        config: RemoteEconomicStateAnchorConfig,
        transition_verifier: Arc<dyn EconomicTransitionProofVerifier>,
        admission_verifier: Arc<dyn EconomicAdmissionHandoffVerifier>,
        cancellation_verifier: Arc<dyn EconomicEffectCancellationProofVerifier>,
    ) -> Result<Self, EconomicStateAnchorConfigError> {
        config.validate()?;
        let transport = Arc::new(HttpsEconomicStateAnchorTransport::new(&config)?);
        Ok(Self {
            pins: config.pins,
            transition_verifier,
            admission_verifier,
            cancellation_verifier,
            transport,
        })
    }

    #[cfg(test)]
    fn with_fixture_transport(
        config: RemoteEconomicStateAnchorConfig,
        transition_verifier: Arc<dyn EconomicTransitionProofVerifier>,
        admission_verifier: Arc<dyn EconomicAdmissionHandoffVerifier>,
        cancellation_verifier: Arc<dyn EconomicEffectCancellationProofVerifier>,
        transport: Arc<dyn EconomicStateAnchorTransport>,
    ) -> Result<Self, EconomicStateAnchorConfigError> {
        config.validate()?;
        Ok(Self {
            pins: config.pins,
            transition_verifier,
            admission_verifier,
            cancellation_verifier,
            transport,
        })
    }

    fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        request: &impl Serialize,
    ) -> Result<T, EconomicStateAnchorError> {
        let request = serde_json::to_vec(request)
            .map_err(|error| EconomicStateAnchorError::Canonicalization(error.to_string()))?;
        let response = self.transport.post(path, &request)?;
        ensure_bounded_response(&response)?;
        serde_json::from_slice(&response)
            .map_err(|error| EconomicStateAnchorError::Canonicalization(error.to_string()))
    }

    fn compare_and_swap_verified_batch(
        &self,
        advance: &VerifiedEconomicStateBatchAdvance,
    ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
        reverify_economic_state_batch_advance(
            advance,
            &self.pins,
            self.transition_verifier.as_ref(),
        )?;
        verify_economic_admission_batch(advance, self.admission_verifier.as_ref())?;
        let committed = verify_economic_state_view(
            self.post(ECONOMIC_STATE_CAS_PATH, advance.batch())?,
            &self.pins,
        )?;
        verify_economic_state_batch_commit(advance, &committed, &self.pins)?;
        Ok(committed)
    }

    pub fn readiness(
        &self,
        query: &EconomicStateReadQuery,
        expectation: &EconomicStateReadinessExpectation,
    ) -> EconomicStateReadiness {
        match self.read_state(query) {
            Ok(current) => assess_economic_state_readiness(&current, expectation)
                .unwrap_or(EconomicStateReadiness::Divergent),
            Err(error) => readiness_for_error(&error),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EconomicEffectDispatchResponse {
    view: EconomicStateAnchorViewV1,
    commit: EconomicEffectDispatchCommitV1,
}

impl EconomicStateAnchor for RemoteEconomicStateAnchor {
    fn read_state(
        &self,
        query: &EconomicStateReadQuery,
    ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
        query.validate()?;
        let view =
            verify_economic_state_view(self.post(ECONOMIC_STATE_READ_PATH, query)?, &self.pins)?;
        verify_query_coverage(query, &view)?;
        Ok(view)
    }

    fn read_checkpoint_state(
        &self,
        query: &EconomicCheckpointReadQuery,
    ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
        query.validate()?;
        let view = verify_economic_state_view(
            self.post(ECONOMIC_STATE_CHECKPOINT_READ_PATH, query)?,
            &self.pins,
        )?;
        if view.view().checkpoint_sequence != query.checkpoint_sequence
            || view.view().checkpoint_digest != query.checkpoint_digest
        {
            return Err(EconomicStateAnchorError::InvalidView(
                "retained checkpoint does not match the requested identity",
            ));
        }
        verify_query_coverage(&query.query, &view)?;
        Ok(view)
    }

    fn compare_and_swap_batch(
        &self,
        advance: QualifiedGenericEconomicStateBatchAdvance<'_>,
    ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
        self.compare_and_swap_verified_batch(advance.advance())
    }

    fn compare_and_swap_effect_dispatch(
        &self,
        advance: VerifiedEconomicEffectDispatchAdvance,
    ) -> Result<VerifiedEconomicEffectDispatch, EconomicStateAnchorError> {
        reverify_economic_effect_dispatch_advance(
            &advance,
            &self.pins,
            self.transition_verifier.as_ref(),
            self.admission_verifier.as_ref(),
        )?;
        let response: EconomicEffectDispatchResponse =
            self.post(ECONOMIC_EFFECT_DISPATCH_PATH, advance.batch())?;
        let committed = verify_economic_state_view(response.view, &self.pins)?;
        verify_economic_effect_dispatch_commit(advance, &committed, response.commit, &self.pins)
    }

    fn compare_and_swap_effect_unknown(
        &self,
        advance: QualifiedEconomicEffectUnknownAdvance<'_>,
    ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
        self.compare_and_swap_verified_batch(advance.advance())
    }

    fn compare_and_swap_effect_cancellation(
        &self,
        advance: VerifiedEconomicEffectCancellationAdvance,
    ) -> Result<VerifiedEconomicEffectNotDispatched, EconomicStateAnchorError> {
        cancellation::compare_and_swap(self, advance)
    }
}

pub fn compose_economic_state_anchor(
    config: RemoteEconomicStateAnchorConfig,
    transition_verifier: Arc<dyn EconomicTransitionProofVerifier>,
    admission_verifier: Arc<dyn EconomicAdmissionHandoffVerifier>,
    cancellation_verifier: Arc<dyn EconomicEffectCancellationProofVerifier>,
) -> Result<Arc<dyn EconomicStateAnchor>, EconomicStateAnchorConfigError> {
    Ok(Arc::new(RemoteEconomicStateAnchor::new(
        config,
        transition_verifier,
        admission_verifier,
        cancellation_verifier,
    )?))
}

fn ensure_bounded_response(body: &[u8]) -> Result<(), EconomicStateAnchorError> {
    if body.len() > ECONOMIC_STATE_RESPONSE_LIMIT {
        Err(EconomicStateAnchorError::Unavailable(
            "economic anchor response exceeds the transport bound".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn verify_query_coverage(
    query: &EconomicStateReadQuery,
    current: &VerifiedEconomicStateView,
) -> Result<(), EconomicStateAnchorError> {
    for key in &query.resource_keys {
        if current.view().head(key).is_none() && !current.view().proves_resource_absent(key) {
            return Err(EconomicStateAnchorError::CurrentHeadMissing(key.clone()));
        }
    }
    for key in &query.request_keys {
        if current.view().request_replay(key).is_none()
            && !current.view().proves_request_absent(key)
        {
            return Err(EconomicStateAnchorError::CurrentRequestMissing(key.clone()));
        }
    }
    Ok(())
}

fn readiness_for_error(error: &EconomicStateAnchorError) -> EconomicStateReadiness {
    match error {
        EconomicStateAnchorError::Missing
        | EconomicStateAnchorError::CurrentHeadMissing(_)
        | EconomicStateAnchorError::CurrentAbsenceMissing(_)
        | EconomicStateAnchorError::CurrentRequestMissing(_) => EconomicStateReadiness::Missing,
        EconomicStateAnchorError::Unavailable(_) => EconomicStateReadiness::Unavailable,
        EconomicStateAnchorError::InvalidSignature | EconomicStateAnchorError::PinMismatch(_) => {
            EconomicStateReadiness::Untrusted
        }
        _ => EconomicStateReadiness::Divergent,
    }
}

mod cancellation;

#[cfg(test)]
#[path = "economic_state_anchor/cancellation_tests.rs"]
mod cancellation_tests;

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::sync::MutexGuard;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use chio_core::crypto::{sha256_hex, Keypair};
    use chio_core::economic_continuity::{
        qualify_generic_economic_state_batch_advance, EconomicAdmissionHandoffStateV1,
        EconomicAdmissionHandoffV1, EconomicContentV1, EconomicEffectSlotV1, EconomicEffectStateV1,
        EconomicEffectTargetV1, EconomicExpectedHead, EconomicRequestBindingV1,
        EconomicRequestKeyV1, EconomicResourceHeadV1, EconomicResourceKeyV1, EconomicStateAnchor,
        EconomicStateAnchorPins, EconomicStateAnchorViewV1, EconomicStateBatchV1,
        EconomicStateReadQuery, EconomicStateReadinessExpectation, EconomicStateTransitionV1,
        EconomicTransitionAuthorizationV1, EconomicTransitionProofVerifier,
        VerifiedEconomicEffectDispatchAdvance, CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA,
        CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA, CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA,
        CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
    };
    use chio_kernel::admission_operation::AdmissionMutationSequencer;
    use serde_json::json;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        match mutex.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn pins() -> EconomicStateAnchorPins {
        EconomicStateAnchorPins {
            anchor_id: "anchor-1".to_owned(),
            namespace: "economy-prod".to_owned(),
            signer_key_id: "anchor-key-1".to_owned(),
            signer_key_epoch: 1,
            signer_public_key: Keypair::from_seed(&[0x41; 32]).public_key(),
        }
    }

    fn digest(label: &str) -> String {
        sha256_hex(label.as_bytes())
    }

    fn resource_key(resource_id: &str) -> EconomicResourceKeyV1 {
        EconomicResourceKeyV1 {
            resource_family: "clearing_round".to_owned(),
            scope_id: "tenant-1".to_owned(),
            resource_id: resource_id.to_owned(),
        }
    }

    fn resource_head(key: EconomicResourceKeyV1) -> TestResult<EconomicResourceHeadV1> {
        let state = EconomicContentV1::Inline {
            value: json!({"roundId": key.resource_id}),
        };
        Ok(EconomicResourceHeadV1 {
            schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
            anchor_id: "anchor-1".to_owned(),
            namespace: "economy-prod".to_owned(),
            resource_key: key,
            head_version: 1,
            resource_version: 1,
            lifecycle_fence: 1,
            lifecycle_state: "open".to_owned(),
            state_digest: state.digest()?,
            state,
            operation_id: None,
            effect_idempotency_key: None,
            frost: None,
            terminal_result: None,
            trusted_clock_high_water: 100,
            predecessor_digest: None,
        })
    }

    fn signed_view(
        heads: Vec<EconomicResourceHeadV1>,
        absent_resource_keys: Vec<EconomicResourceKeyV1>,
    ) -> TestResult<EconomicStateAnchorViewV1> {
        signed_view_at(1, digest("checkpoint-1"), heads, absent_resource_keys)
    }

    fn signed_view_at(
        checkpoint_sequence: u64,
        checkpoint_digest: String,
        heads: Vec<EconomicResourceHeadV1>,
        absent_resource_keys: Vec<EconomicResourceKeyV1>,
    ) -> TestResult<EconomicStateAnchorViewV1> {
        let mut view = EconomicStateAnchorViewV1 {
            schema: CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA.to_owned(),
            anchor_id: "anchor-1".to_owned(),
            namespace: "economy-prod".to_owned(),
            checkpoint_sequence,
            checkpoint_digest,
            heads_root: String::new(),
            heads,
            absent_resource_keys,
            request_replays_root: String::new(),
            request_replays: Vec::new(),
            absent_request_keys: Vec::new(),
            observed_at: 100,
            signer_key_id: "anchor-key-1".to_owned(),
            signer_key_epoch: 1,
            anchor_signature: String::new(),
        };
        view.seal(&Keypair::from_seed(&[0x41; 32]))?;
        Ok(view)
    }

    #[derive(Debug)]
    struct DirectTransitionVerifier;

    impl EconomicTransitionProofVerifier for DirectTransitionVerifier {
        fn verify_transition(
            &self,
            _current: Option<&EconomicResourceHeadV1>,
            _transition: &chio_core::economic_continuity::EconomicStateTransitionV1,
        ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
            Ok(EconomicTransitionAuthorizationV1::Direct)
        }
    }

    #[derive(Debug, Default)]
    struct CountingTransitionVerifier {
        calls: AtomicUsize,
    }

    impl EconomicTransitionProofVerifier for CountingTransitionVerifier {
        fn verify_transition(
            &self,
            _current: Option<&EconomicResourceHeadV1>,
            _transition: &EconomicStateTransitionV1,
        ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(EconomicTransitionAuthorizationV1::Direct)
        }
    }

    #[derive(Debug)]
    struct AdmissionVerifier;

    impl chio_core::economic_continuity::EconomicAdmissionHandoffVerifier for AdmissionVerifier {
        fn verify_operation_active(
            &self,
            _operation_id: &str,
        ) -> Result<(), EconomicStateAnchorError> {
            Ok(())
        }

        fn verify_prepared_effect(
            &self,
            _slot: &EconomicEffectSlotV1,
        ) -> Result<(), EconomicStateAnchorError> {
            Ok(())
        }

        fn verify_handoff(
            &self,
            _operation_id: &str,
            _handoff: &EconomicAdmissionHandoffV1,
        ) -> Result<(), EconomicStateAnchorError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct RejectingActiveAdmissionVerifier;

    impl chio_core::economic_continuity::EconomicAdmissionHandoffVerifier
        for RejectingActiveAdmissionVerifier
    {
        fn verify_operation_active(
            &self,
            _operation_id: &str,
        ) -> Result<(), EconomicStateAnchorError> {
            Err(EconomicStateAnchorError::AdmissionHandoffRejected)
        }

        fn verify_handoff(
            &self,
            _operation_id: &str,
            _handoff: &EconomicAdmissionHandoffV1,
        ) -> Result<(), EconomicStateAnchorError> {
            Err(EconomicStateAnchorError::AdmissionHandoffRejected)
        }
    }

    #[derive(Debug)]
    struct RejectingCancellationVerifier;

    impl EconomicEffectCancellationProofVerifier for RejectingCancellationVerifier {
        fn verify_cancellation(
            &self,
            _current: &EconomicEffectSlotV1,
            _next: &EconomicEffectSlotV1,
        ) -> Result<chio_core::economic_continuity::EconomicNoEffectKindV1, EconomicStateAnchorError>
        {
            Err(EconomicStateAnchorError::EffectCancellationRejected(
                "fixture does not authorize cancellation",
            ))
        }
    }

    #[derive(Debug, Default)]
    struct CountingAdmissionVerifier {
        calls: AtomicUsize,
    }

    impl chio_core::economic_continuity::EconomicAdmissionHandoffVerifier
        for CountingAdmissionVerifier
    {
        fn verify_operation_active(
            &self,
            _operation_id: &str,
        ) -> Result<(), EconomicStateAnchorError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn verify_prepared_effect(
            &self,
            _slot: &EconomicEffectSlotV1,
        ) -> Result<(), EconomicStateAnchorError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn verify_handoff(
            &self,
            _operation_id: &str,
            _handoff: &EconomicAdmissionHandoffV1,
        ) -> Result<(), EconomicStateAnchorError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn ready_effect_slot() -> TestResult<EconomicEffectSlotV1> {
        let mut slot = EconomicEffectSlotV1 {
            schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
            slot_id: String::new(),
            anchor_id: "anchor-1".to_owned(),
            namespace: "economy-prod".to_owned(),
            resource_key: resource_key("round-1"),
            operation_id: digest("operation-1"),
            effect_kind: "settlement_dispatch".to_owned(),
            request: EconomicRequestBindingV1 {
                request_namespace_digest: digest("request-namespace"),
                request_id: "request-1".to_owned(),
                request_binding_digest: digest("request-binding"),
            },
            admission_handoff: EconomicAdmissionHandoffV1 {
                state: EconomicAdmissionHandoffStateV1::MutationSubmitted,
                operation_version: 4,
                lifecycle_fence: 9,
                store_fence: chio_kernel::admission_operation::StoreMutationFence {
                    store_uuid: "store-1".to_owned(),
                    lease_id: "lease-1".to_owned(),
                    owner_epoch: 3,
                },
            },
            target: EconomicEffectTargetV1 {
                target_id: "settlement-rail".to_owned(),
                target_key_epoch: 2,
                qualification_digest: digest("target-qualification"),
            },
            action_digest: digest("action"),
            parameters_digest: digest("parameters"),
            resource_head_digest: digest("resource-head"),
            frost: None,
            idempotency_key: digest("idempotency-key"),
            state: EconomicEffectStateV1::Ready,
            terminal: None,
        };
        slot.resource_head_digest = resource_head(slot.resource_key.clone())?.digest()?;
        slot.slot_id = slot.recompute_slot_id()?;
        Ok(slot)
    }

    fn effect_head(
        slot: &EconomicEffectSlotV1,
        head_version: u64,
        predecessor_digest: Option<String>,
    ) -> TestResult<EconomicResourceHeadV1> {
        let state = EconomicContentV1::Inline {
            value: serde_json::to_value(slot)?,
        };
        Ok(EconomicResourceHeadV1 {
            schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
            anchor_id: slot.anchor_id.clone(),
            namespace: slot.namespace.clone(),
            resource_key: slot.resource_head_key(),
            head_version,
            resource_version: head_version,
            lifecycle_fence: head_version,
            lifecycle_state: match slot.state {
                EconomicEffectStateV1::Ready => "ready",
                EconomicEffectStateV1::DispatchCommitted => "dispatch_committed",
                EconomicEffectStateV1::NoEffect => "no_effect",
                _ => "terminal",
            }
            .to_owned(),
            state_digest: state.digest()?,
            state,
            operation_id: Some(slot.operation_id.clone()),
            effect_idempotency_key: Some(slot.idempotency_key.clone()),
            frost: slot.frost.clone(),
            terminal_result: None,
            trusted_clock_high_water: 100 + head_version,
            predecessor_digest,
        })
    }

    fn dispatch_advance(
        transition_verifier: &dyn EconomicTransitionProofVerifier,
        admission_verifier: &dyn chio_core::economic_continuity::EconomicAdmissionHandoffVerifier,
    ) -> TestResult<(
        VerifiedEconomicEffectDispatchAdvance,
        chio_core::economic_continuity::VerifiedEconomicStateView,
    )> {
        let ready = ready_effect_slot()?;
        let target_head = resource_head(ready.resource_key.clone())?;
        let ready_head = effect_head(&ready, 1, None)?;
        let ready_head_digest = ready_head.digest()?;
        let current = chio_core::economic_continuity::verify_economic_state_view(
            signed_view(vec![target_head.clone(), ready_head], Vec::new())?,
            &pins(),
        )?;
        let mut dispatched = ready;
        dispatched.state = EconomicEffectStateV1::DispatchCommitted;
        let dispatched_head = effect_head(&dispatched, 2, Some(ready_head_digest.clone()))?;
        let mut batch = EconomicStateBatchV1 {
            schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
            batch_id: String::new(),
            checkpoint_digest: String::new(),
            anchor_id: "anchor-1".to_owned(),
            namespace: "economy-prod".to_owned(),
            checkpoint_sequence: 2,
            previous_checkpoint_digest: Some(current.view().checkpoint_digest.clone()),
            expected_heads_root: String::new(),
            next_heads_root: String::new(),
            transitions: vec![EconomicStateTransitionV1 {
                resource_key: dispatched_head.resource_key.clone(),
                expected_head_digest: Some(ready_head_digest),
                next_head: dispatched_head.clone(),
                transition_proof_digest: digest("transition-proof"),
                prepared_effect: None,
            }],
            effect_slots: Vec::new(),
            request_replays: Vec::new(),
            operation_id: Some(dispatched.operation_id.clone()),
            issued_at: 102,
            signer_key_id: "anchor-key-1".to_owned(),
            signer_key_epoch: 1,
            anchor_signature: String::new(),
        };
        batch.seal(&Keypair::from_seed(&[0x41; 32]))?;
        let advance = chio_core::economic_continuity::verify_economic_state_batch_advance(
            &current,
            batch,
            &pins(),
            transition_verifier,
        )?;
        let advance = chio_core::economic_continuity::verify_economic_effect_dispatch_advance(
            advance,
            admission_verifier,
        )?;
        let committed = chio_core::economic_continuity::verify_economic_state_view(
            signed_view_at(
                2,
                advance.batch().checkpoint_digest.clone(),
                vec![target_head, dispatched_head],
                Vec::new(),
            )?,
            &pins(),
        )?;
        Ok((advance, committed))
    }

    #[derive(Debug, Default)]
    struct FixtureTransport {
        responses: Mutex<VecDeque<Result<Vec<u8>, EconomicStateAnchorError>>>,
        requests: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl FixtureTransport {
        fn respond_with(&self, value: &impl serde::Serialize) -> Result<(), serde_json::Error> {
            let body = serde_json::to_vec(value)?;
            lock_unpoisoned(&self.responses).push_back(Ok(body));
            Ok(())
        }

        fn respond_with_error(&self, error: EconomicStateAnchorError) {
            lock_unpoisoned(&self.responses).push_back(Err(error));
        }
    }

    impl EconomicStateAnchorTransport for FixtureTransport {
        fn post(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, EconomicStateAnchorError> {
            lock_unpoisoned(&self.requests).push((path.to_owned(), body.to_vec()));
            lock_unpoisoned(&self.responses)
                .pop_front()
                .ok_or_else(|| {
                    EconomicStateAnchorError::Unavailable("fixture response is missing".to_owned())
                })?
        }
    }

    fn config(
        base_url: &str,
        bearer_token: &str,
        timeout: Duration,
    ) -> RemoteEconomicStateAnchorConfig {
        RemoteEconomicStateAnchorConfig {
            base_url: base_url.to_owned(),
            bearer_token: bearer_token.to_owned(),
            timeout,
            pins: pins(),
        }
    }

    #[test]
    fn production_config_requires_unambiguous_https_auth_and_pins() {
        assert!(config(
            "https://anchor.example/v1",
            "anchor-token",
            Duration::from_secs(5)
        )
        .validate()
        .is_ok());
        for invalid in [
            "http://anchor.example/v1",
            "https://user@anchor.example/v1",
            "https://anchor.example/v1?tenant=prod",
            "https://anchor.example/v1#fragment",
        ] {
            assert!(config(invalid, "anchor-token", Duration::from_secs(5))
                .validate()
                .is_err());
        }
        assert!(config("https://anchor.example", "", Duration::from_secs(5))
            .validate()
            .is_err());
        assert!(config(
            "https://anchor.example",
            "token with space",
            Duration::from_secs(5)
        )
        .validate()
        .is_err());
        assert!(
            config("https://anchor.example", "anchor-token", Duration::ZERO)
                .validate()
                .is_err()
        );
        let mut invalid_pins = config(
            "https://anchor.example",
            "anchor-token",
            Duration::from_secs(5),
        );
        invalid_pins.pins.signer_key_epoch = 0;
        assert!(invalid_pins.validate().is_err());
    }

    #[test]
    fn remote_read_requires_signed_value_or_absence_for_every_query_key() -> TestResult {
        let present = resource_key("round-1");
        let absent = resource_key("round-2");
        let query = EconomicStateReadQuery {
            resource_keys: vec![present.clone(), absent.clone()],
            request_keys: Vec::<EconomicRequestKeyV1>::new(),
        };
        let transport = Arc::new(FixtureTransport::default());
        transport.respond_with(&signed_view(
            vec![resource_head(present.clone())?],
            vec![absent.clone()],
        )?)?;
        transport.respond_with(&signed_view(vec![resource_head(present)?], Vec::new())?)?;
        let anchor = RemoteEconomicStateAnchor::with_fixture_transport(
            config(
                "https://anchor.example",
                "anchor-token",
                Duration::from_secs(5),
            ),
            Arc::new(DirectTransitionVerifier),
            Arc::new(AdmissionVerifier),
            Arc::new(RejectingCancellationVerifier),
            transport.clone(),
        )?;

        let verified = anchor.read_state(&query)?;
        assert!(verified.view().head(&absent).is_none());
        assert!(anchor.read_state(&query).is_err());
        let requests = lock_unpoisoned(&transport.requests);
        assert_eq!(requests[0].0, ECONOMIC_STATE_READ_PATH);
        assert_eq!(
            serde_json::from_slice::<EconomicStateReadQuery>(&requests[0].1)?,
            query
        );
        Ok(())
    }

    #[test]
    fn remote_checkpoint_read_requires_the_exact_retained_checkpoint() -> TestResult {
        let key = resource_key("round-1");
        let checkpoint_digest = digest("checkpoint-7");
        let query = chio_core::economic_continuity::EconomicCheckpointReadQuery {
            checkpoint_sequence: 7,
            checkpoint_digest: checkpoint_digest.clone(),
            query: EconomicStateReadQuery {
                resource_keys: vec![key.clone()],
                request_keys: Vec::new(),
            },
        };
        let transport = Arc::new(FixtureTransport::default());
        transport.respond_with(&signed_view_at(
            7,
            checkpoint_digest,
            vec![resource_head(key.clone())?],
            Vec::new(),
        )?)?;
        transport.respond_with(&signed_view_at(
            8,
            digest("checkpoint-8"),
            vec![resource_head(key)?],
            Vec::new(),
        )?)?;
        let anchor = RemoteEconomicStateAnchor::with_fixture_transport(
            config(
                "https://anchor.example",
                "anchor-token",
                Duration::from_secs(5),
            ),
            Arc::new(DirectTransitionVerifier),
            Arc::new(AdmissionVerifier),
            Arc::new(RejectingCancellationVerifier),
            transport.clone(),
        )?;

        anchor.read_checkpoint_state(&query)?;
        assert!(anchor.read_checkpoint_state(&query).is_err());
        let requests = lock_unpoisoned(&transport.requests);
        assert_eq!(requests[0].0, ECONOMIC_STATE_CHECKPOINT_READ_PATH);
        assert_eq!(
            serde_json::from_slice::<chio_core::economic_continuity::EconomicCheckpointReadQuery>(
                &requests[0].1
            )?,
            query
        );
        Ok(())
    }

    #[test]
    fn remote_cas_reverifies_consumer_proof_and_exact_committed_checkpoint() -> TestResult {
        let key = resource_key("round-1");
        let current_head = resource_head(key.clone())?;
        let current_digest = current_head.digest()?;
        let mut next_head = resource_head(key.clone())?;
        next_head.head_version = 2;
        next_head.resource_version = 2;
        next_head.lifecycle_fence = 2;
        next_head.trusted_clock_high_water = 101;
        next_head.predecessor_digest = Some(current_digest.clone());
        let next_state = EconomicContentV1::Inline {
            value: json!({"roundId": key.resource_id, "version": 2}),
        };
        next_head.state_digest = next_state.digest()?;
        next_head.state = next_state;
        let current = chio_core::economic_continuity::verify_economic_state_view(
            signed_view(vec![current_head], Vec::new())?,
            &pins(),
        )?;
        let mut batch = EconomicStateBatchV1 {
            schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
            batch_id: String::new(),
            checkpoint_digest: String::new(),
            anchor_id: "anchor-1".to_owned(),
            namespace: "economy-prod".to_owned(),
            checkpoint_sequence: 2,
            previous_checkpoint_digest: Some(current.view().checkpoint_digest.clone()),
            expected_heads_root: String::new(),
            next_heads_root: String::new(),
            transitions: vec![EconomicStateTransitionV1 {
                resource_key: key,
                expected_head_digest: Some(current_digest),
                next_head: next_head.clone(),
                transition_proof_digest: digest("transition-proof"),
                prepared_effect: None,
            }],
            effect_slots: Vec::new(),
            request_replays: Vec::new(),
            operation_id: Some(digest("operation-1")),
            issued_at: 101,
            signer_key_id: "anchor-key-1".to_owned(),
            signer_key_epoch: 1,
            anchor_signature: String::new(),
        };
        batch.seal(&Keypair::from_seed(&[0x41; 32]))?;
        let verifier = Arc::new(CountingTransitionVerifier::default());
        let advance = chio_core::economic_continuity::verify_economic_state_batch_advance(
            &current,
            batch,
            &pins(),
            verifier.as_ref(),
        )?;
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);

        let transport = Arc::new(FixtureTransport::default());
        transport.respond_with(&signed_view_at(
            2,
            advance.batch().checkpoint_digest.clone(),
            vec![next_head.clone()],
            Vec::new(),
        )?)?;
        transport.respond_with(&signed_view_at(
            2,
            digest("unrelated-checkpoint"),
            vec![next_head],
            Vec::new(),
        )?)?;
        let anchor = RemoteEconomicStateAnchor::with_fixture_transport(
            config(
                "https://anchor.example",
                "anchor-token",
                Duration::from_secs(5),
            ),
            verifier.clone(),
            Arc::new(AdmissionVerifier),
            Arc::new(RejectingCancellationVerifier),
            transport.clone(),
        )?;

        anchor.compare_and_swap_batch(qualify_generic_economic_state_batch_advance(&advance)?)?;
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 2);
        assert!(anchor
            .compare_and_swap_batch(qualify_generic_economic_state_batch_advance(&advance)?)
            .is_err());
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 3);
        let requests = lock_unpoisoned(&transport.requests);
        assert_eq!(requests[0].0, ECONOMIC_STATE_CAS_PATH);
        assert_eq!(
            serde_json::from_slice::<EconomicStateBatchV1>(&requests[0].1)?,
            *advance.batch()
        );
        drop(requests);

        let rejected_transport = Arc::new(FixtureTransport::default());
        let rejecting_anchor = RemoteEconomicStateAnchor::with_fixture_transport(
            config(
                "https://anchor.example",
                "anchor-token",
                Duration::from_secs(5),
            ),
            verifier,
            Arc::new(RejectingActiveAdmissionVerifier),
            Arc::new(RejectingCancellationVerifier),
            rejected_transport.clone(),
        )?;
        assert!(rejecting_anchor
            .compare_and_swap_batch(qualify_generic_economic_state_batch_advance(&advance)?)
            .is_err());
        assert!(lock_unpoisoned(&rejected_transport.requests).is_empty());
        Ok(())
    }

    #[test]
    fn remote_effect_dispatch_requires_signed_cas_receipt_and_rechecks_handoff() -> TestResult {
        let transition_verifier = Arc::new(CountingTransitionVerifier::default());
        let admission_verifier = Arc::new(CountingAdmissionVerifier::default());
        let (advance, committed) =
            dispatch_advance(transition_verifier.as_ref(), admission_verifier.as_ref())?;
        let commit = EconomicEffectDispatchCommitV1::sign(
            &advance,
            &committed,
            digest("cas-nonce"),
            103,
            "anchor-key-1",
            1,
            &Keypair::from_seed(&[0x41; 32]),
        )?;
        let expected_commit_id = commit.commit_id.clone();
        let transport = Arc::new(FixtureTransport::default());
        transport.respond_with(&EconomicEffectDispatchResponse {
            view: committed.view().clone(),
            commit,
        })?;
        let anchor = RemoteEconomicStateAnchor::with_fixture_transport(
            config(
                "https://anchor.example",
                "anchor-token",
                Duration::from_secs(5),
            ),
            transition_verifier.clone(),
            admission_verifier.clone(),
            Arc::new(RejectingCancellationVerifier),
            transport.clone(),
        )?;

        let dispatch = anchor.compare_and_swap_effect_dispatch(advance)?;
        assert_eq!(dispatch.commit_id(), expected_commit_id);
        assert_eq!(transition_verifier.calls.load(Ordering::SeqCst), 2);
        assert_eq!(admission_verifier.calls.load(Ordering::SeqCst), 2);
        let requests = lock_unpoisoned(&transport.requests);
        assert_eq!(requests[0].0, ECONOMIC_EFFECT_DISPATCH_PATH);
        Ok(())
    }

    struct BlockingEffectAnchor {
        entered: Mutex<Option<mpsc::Sender<()>>>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl EconomicStateAnchor for BlockingEffectAnchor {
        fn read_state(
            &self,
            _query: &EconomicStateReadQuery,
        ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
            Err(EconomicStateAnchorError::Missing)
        }

        fn read_checkpoint_state(
            &self,
            _query: &EconomicCheckpointReadQuery,
        ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
            Err(EconomicStateAnchorError::Missing)
        }

        fn compare_and_swap_batch(
            &self,
            _advance: QualifiedGenericEconomicStateBatchAdvance<'_>,
        ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
            Err(EconomicStateAnchorError::Missing)
        }

        fn compare_and_swap_effect_dispatch(
            &self,
            _advance: VerifiedEconomicEffectDispatchAdvance,
        ) -> Result<VerifiedEconomicEffectDispatch, EconomicStateAnchorError> {
            if let Some(sender) = lock_unpoisoned(&self.entered).take() {
                sender
                    .send(())
                    .map_err(|error| EconomicStateAnchorError::Unavailable(error.to_string()))?;
            }
            lock_unpoisoned(&self.release)
                .recv()
                .map_err(|error| EconomicStateAnchorError::Unavailable(error.to_string()))?;
            Err(EconomicStateAnchorError::Unavailable(
                "blocked dispatch fixture released".to_owned(),
            ))
        }
    }

    #[test]
    fn effect_dispatch_shares_the_admission_mutation_sequence() -> TestResult {
        let transition_verifier = CountingTransitionVerifier::default();
        let admission_verifier = CountingAdmissionVerifier::default();
        let (advance, _) = dispatch_advance(&transition_verifier, &admission_verifier)?;
        let fence = advance.slot().admission_handoff.store_fence.clone();
        let (entered_sender, entered_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let dispatcher = Arc::new(SequencedEconomicEffectDispatcher::new(
            Arc::new(BlockingEffectAnchor {
                entered: Mutex::new(Some(entered_sender)),
                release: Mutex::new(release_receiver),
            }),
            &fence,
        )?);
        let dispatch_thread = std::thread::spawn(move || dispatcher.dispatch(advance));
        entered_receiver.recv_timeout(Duration::from_secs(1))?;

        let competing = AdmissionMutationSequencer::for_fence(&fence)?;
        let (acquired_sender, acquired_receiver) = mpsc::channel();
        let competing_thread = std::thread::spawn(move || {
            let _guard = competing.lock().map_err(|error| error.to_string())?;
            acquired_sender.send(()).map_err(|error| error.to_string())
        });
        assert!(acquired_receiver
            .recv_timeout(Duration::from_millis(25))
            .is_err());
        release_sender.send(())?;
        assert!(dispatch_thread
            .join()
            .map_err(|_| "dispatch thread panicked")?
            .is_err());
        acquired_receiver.recv_timeout(Duration::from_secs(1))?;
        competing_thread
            .join()
            .map_err(|_| "competing thread panicked")??;
        Ok(())
    }

    #[test]
    fn readiness_is_false_for_unavailable_untrusted_and_missing_anchor_state() -> TestResult {
        let key = resource_key("round-1");
        let head = resource_head(key.clone())?;
        let head_digest = head.digest()?;
        let query = EconomicStateReadQuery {
            resource_keys: vec![key.clone()],
            request_keys: Vec::new(),
        };
        let expectation = EconomicStateReadinessExpectation {
            checkpoint_sequence: 1,
            checkpoint_digest: digest("checkpoint-1"),
            heads: vec![EconomicExpectedHead {
                resource_key: key,
                head_digest,
            }],
        };
        let transport = Arc::new(FixtureTransport::default());
        transport.respond_with(&signed_view(vec![head.clone()], Vec::new())?)?;
        transport.respond_with_error(EconomicStateAnchorError::Unavailable(
            "fixture unavailable".to_owned(),
        ));
        let mut wrong_key = signed_view(vec![head], Vec::new())?;
        wrong_key.seal(&Keypair::from_seed(&[0x77; 32]))?;
        transport.respond_with(&wrong_key)?;
        transport.respond_with(&signed_view(Vec::new(), Vec::new())?)?;
        let anchor = RemoteEconomicStateAnchor::with_fixture_transport(
            config(
                "https://anchor.example",
                "anchor-token",
                Duration::from_secs(5),
            ),
            Arc::new(DirectTransitionVerifier),
            Arc::new(AdmissionVerifier),
            Arc::new(RejectingCancellationVerifier),
            transport,
        )?;

        assert!(anchor.readiness(&query, &expectation).is_ready());
        assert_eq!(
            anchor.readiness(&query, &expectation),
            EconomicStateReadiness::Unavailable
        );
        assert_eq!(
            anchor.readiness(&query, &expectation),
            EconomicStateReadiness::Untrusted
        );
        assert_eq!(
            anchor.readiness(&query, &expectation),
            EconomicStateReadiness::Missing
        );
        Ok(())
    }
}
