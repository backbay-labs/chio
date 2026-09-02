//! Durable control-plane boundary for the cognition-market finding status
//! feed. Public reads return the exact signed epoch and portable proof bytes
//! that the trusted verifier persisted. The only HTTP mutation is an
//! operator-signed voluntary retraction intent. Epoch advancement has no HTTP
//! request shape, so an untrusted caller can never propose a "latest" root.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_finding::verify_pinned_envelope;
use chio_store_sqlite::{
    FindingRetractionIntentCommitLiveness, FindingRetractionIntentInput,
    FindingRetractionIntentRecord, FindingRetractionIntentSource, FindingStatusEpochRecord,
    FindingStatusProofKind, FindingStatusProofRecord, FindingStatusStoreError,
    FindingStatusWriteOutcome, FindingStickyStatus, SqliteFindingStatusStore,
};

use super::report_validation::validate_service_auth;
use super::*;

/// Status intent requests remain far below the service-wide body cap. Keeping
/// the exact signed request bounded also bounds the durable outbox record.
pub(crate) const FINDING_STATUS_INTENT_MAX_BODY_BYTES: usize = 256 * 1024;

const FINDING_STATUS_INTENT_SCHEMA: &str = "chio.finding.status-intent-submission.v1";
const FINDING_STATUS_INTENT_ID_DOMAIN: &str = "chio.finding.status-intent-id.v1";
const FINDING_VOLUNTARY_RETRACTION_RECEIPT_SCHEMA: &str =
    "chio.finding.voluntary-retraction-receipt.v1";

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FindingStatusIntentSource {
    Voluntary,
    Enforcement,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct FindingVoluntaryRetractionReceipt {
    schema: String,
    feed_id: String,
    key_domain_nonce: u64,
    finding_id: String,
    source_authority_id: String,
    issued_at: u64,
}

impl FindingStatusIntentSource {
    const fn store_source(self) -> FindingRetractionIntentSource {
        match self {
            Self::Voluntary => FindingRetractionIntentSource::Voluntary,
            Self::Enforcement => FindingRetractionIntentSource::Enforcement,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Voluntary => "voluntary",
            Self::Enforcement => "enforcement",
        }
    }
}

/// Operator countersignature over one authenticated source receipt. For a
/// voluntary request the source receipt is the seller's signed retraction
/// intent. Enforced intents are created only by the challenge finality
/// coordinator and
/// are deliberately refused at this HTTP boundary.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct FindingStatusIntentSubmission {
    schema: String,
    intent_id: String,
    feed_id: String,
    key_domain_nonce: u64,
    finding_id: String,
    source: FindingStatusIntentSource,
    source_authority_id: String,
    source_receipt_sha256: String,
    source_receipt: SignedExportEnvelope<FindingVoluntaryRetractionReceipt>,
    operator_id: String,
    operator_key_epoch: u64,
    issued_at: u64,
    inclusion_deadline: u64,
}

type SignedFindingStatusIntentSubmission = SignedExportEnvelope<FindingStatusIntentSubmission>;

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct FindingStatusRootResponse {
    feed_id: String,
    key_domain_nonce: u64,
    map_epoch: u64,
    epoch_id: String,
    root_hash: String,
    signed_epoch_sha256: String,
    signed_epoch_b64: String,
    valid_until: u64,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct FindingStatusProofResponse {
    feed_id: String,
    key_domain_nonce: u64,
    map_epoch: u64,
    epoch_id: String,
    root_hash: String,
    finding_id: String,
    proof_kind: &'static str,
    proof_sha256: String,
    proof_input_b64: String,
    signed_epoch_sha256: String,
    signed_epoch_b64: String,
    service_bond_evidence_sha256: String,
    checked_at: u64,
    valid_until: u64,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct FindingStatusIntentResponse {
    intent_id: String,
    feed_id: String,
    finding_id: String,
    intent_sha256: String,
    status: &'static str,
    exact_replay: bool,
    inclusion_deadline: u64,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct FindingStatusIntentIdPreimage<'a> {
    domain: &'static str,
    feed_id: &'a str,
    key_domain_nonce: u64,
    finding_id: &'a str,
    source: &'a str,
    source_authority_id: &'a str,
    source_receipt_sha256: &'a str,
    operator_id: &'a str,
    operator_key_epoch: u64,
    issued_at: u64,
    inclusion_deadline: u64,
}

fn compute_intent_id(body: &FindingStatusIntentSubmission) -> Result<String, Response> {
    let preimage = FindingStatusIntentIdPreimage {
        domain: FINDING_STATUS_INTENT_ID_DOMAIN,
        feed_id: &body.feed_id,
        key_domain_nonce: body.key_domain_nonce,
        finding_id: &body.finding_id,
        source: body.source.name(),
        source_authority_id: &body.source_authority_id,
        source_receipt_sha256: &body.source_receipt_sha256,
        operator_id: &body.operator_id,
        operator_key_epoch: body.operator_key_epoch,
        issued_at: body.issued_at,
        inclusion_deadline: body.inclusion_deadline,
    };
    let bytes = canonical_json_bytes(&preimage).map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent id preimage is not canonical",
        )
    })?;
    Ok(sha256_hex(&bytes))
}

/// Build the exact seller-signed, operator-countersigned voluntary retraction
/// submitted to the status outbox. The caller still has to send it through
/// the authenticated route, which reloads the retained Finding and proves the
/// seller key is its issuer.
pub fn build_operator_voluntary_retraction(
    market: &FindingMarketConfig,
    seller: &chio_core::crypto::Keypair,
    status_operator: &chio_core::crypto::Keypair,
    finding_id: &str,
    issued_at: u64,
) -> Result<Vec<u8>, String> {
    market.validate().map_err(|error| error.to_string())?;
    require_hex64(finding_id, "finding_id").map_err(|_| "finding_id is invalid".to_owned())?;
    let expected_operator = market
        .status_feed_operator
        .authority
        .key()
        .map_err(|error| error.to_string())?;
    if status_operator.public_key() != expected_operator {
        return Err("status operator key does not match the configured pin".to_owned());
    }
    let source_authority_id = seller.public_key().to_hex();
    let source_receipt = SignedExportEnvelope::sign(
        FindingVoluntaryRetractionReceipt {
            schema: FINDING_VOLUNTARY_RETRACTION_RECEIPT_SCHEMA.to_owned(),
            feed_id: market.status_feed_operator.feed_id.clone(),
            key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
            finding_id: finding_id.to_owned(),
            source_authority_id: source_authority_id.clone(),
            issued_at,
        },
        seller,
    )
    .map_err(|error| error.to_string())?;
    let source_receipt_sha256 =
        chio_finding::signed_envelope_sha256(&source_receipt).map_err(|error| error.to_string())?;
    let inclusion_deadline = issued_at
        .checked_add(market.status_feed_service_bond.inclusion_sla_secs)
        .ok_or_else(|| "status intent inclusion deadline overflowed".to_owned())?;
    let mut body = FindingStatusIntentSubmission {
        schema: FINDING_STATUS_INTENT_SCHEMA.to_owned(),
        intent_id: String::new(),
        feed_id: market.status_feed_operator.feed_id.clone(),
        key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
        finding_id: finding_id.to_owned(),
        source: FindingStatusIntentSource::Voluntary,
        source_authority_id,
        source_receipt_sha256,
        source_receipt,
        operator_id: market.status_feed_operator.authority.authority_id.clone(),
        operator_key_epoch: market.status_feed_operator.authority.key_epoch,
        issued_at,
        inclusion_deadline,
    };
    body.intent_id = compute_intent_id(&body)
        .map_err(|_| "status intent identity cannot be derived".to_owned())?;
    let signed =
        SignedExportEnvelope::sign(body, status_operator).map_err(|error| error.to_string())?;
    canonical_json_bytes(&signed).map_err(|error| error.to_string())
}

fn require_hex64(value: &str, label: &'static str) -> Result<(), Response> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            &format!("{label} must be lowercase hex with length 64"),
        ));
    }
    Ok(())
}

fn strict_intent_ingress(raw: &str) -> Result<SignedFindingStatusIntentSubmission, Response> {
    if raw.len() > FINDING_STATUS_INTENT_MAX_BODY_BYTES {
        return Err(plain_http_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "status intent exceeds the ingress size bound",
        ));
    }
    let canonical = chio_core::canonical::canonical_json_bytes_from_str(raw).map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent is not strict canonical I-JSON",
        )
    })?;
    if canonical.as_slice() != raw.as_bytes() {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent bytes are not the canonical serialization",
        ));
    }
    let signed: SignedFindingStatusIntentSubmission = serde_json::from_str(raw).map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent failed typed deserialization",
        )
    })?;
    let typed = canonical_json_bytes(&signed).map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent failed canonicalization",
        )
    })?;
    if typed != canonical {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent typed bytes drift from the accepted bytes",
        ));
    }
    Ok(signed)
}

fn status_context(
    state: &TrustServiceState,
    feed_id: &str,
    now: u64,
) -> Result<(FindingMarketConfig, SqliteFindingStatusStore), Response> {
    let config = live_status_config(state, feed_id, now)?;
    let store = status_store(state)?;
    Ok((config, store))
}

fn live_status_config(
    state: &TrustServiceState,
    feed_id: &str,
    now: u64,
) -> Result<FindingMarketConfig, Response> {
    let Some(config) = state.config.finding_market.clone() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "finding market is not configured on this control plane",
        ));
    };
    config
        .require_live_status_feed(feed_id, now)
        .map_err(|error| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()))?;
    Ok(config)
}

fn status_store(state: &TrustServiceState) -> Result<SqliteFindingStatusStore, Response> {
    let Some(store) = state
        .joint_authority_store
        .as_ref()
        .map(|authority| authority.finding_status_store())
    else {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "finding status feed requires the durable joint authority store",
        ));
    };
    Ok(store)
}

fn require_current_epoch(
    operator: &FindingStatusOperatorPin,
    service_bond: &FindingStatusServiceBond,
    max_epoch_age_secs: u64,
    epoch: &FindingStatusEpochRecord,
    now: u64,
) -> Result<(), Response> {
    super::finding_status_verifier::verify_epoch_record(
        operator,
        service_bond,
        max_epoch_age_secs,
        epoch,
        now,
    )
    .map_err(|error| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()))
}

fn require_current_proof_material(
    operator: &FindingStatusOperatorPin,
    service_bond: &FindingStatusServiceBond,
    max_epoch_age_secs: u64,
    epoch: &FindingStatusEpochRecord,
    proof: &FindingStatusProofRecord,
    now: u64,
) -> Result<(), Response> {
    super::finding_status_verifier::verify_proof_record(
        operator,
        service_bond,
        max_epoch_age_secs,
        proof,
        now,
    )
    .map_err(|error| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()))?;
    if proof.feed_id != epoch.feed_id
        || proof.operator_id != epoch.operator_id
        || proof.key_domain_nonce != FINDING_STATUS_KEY_DOMAIN_NONCE
        || proof.map_epoch != epoch.map_epoch
        || proof.epoch_id != epoch.epoch_id
        || proof.root_hash != epoch.root_hash
        || proof.signed_epoch_sha256 != epoch.signed_epoch_sha256
        || proof.signed_epoch_bytes != epoch.signed_epoch_bytes
        || proof.proof_sha256 != sha256_hex(&proof.proof_bytes)
        || proof.checked_at > now
        || now >= proof.valid_until
    {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "finding status proof is not current at the durable feed floor",
        ));
    }

    Ok(())
}

fn require_proof_sticky_state(
    store: &SqliteFindingStatusStore,
    proof: &FindingStatusProofRecord,
) -> Result<(), Response> {
    let sticky = store
        .get_finding_status(&proof.feed_id, &proof.finding_id)
        .map_err(status_read_error)?;
    match (proof.kind, sticky.as_ref().map(|status| status.state)) {
        (FindingStatusProofKind::NonInclusion, None) => Ok(()),
        (FindingStatusProofKind::Inclusion, Some(FindingStickyStatus::Retracted)) => Ok(()),
        (FindingStatusProofKind::NonInclusion, Some(_)) => Err(plain_http_error(
            StatusCode::CONFLICT,
            "non-inclusion contradicts sticky pending or retracted status",
        )),
        (FindingStatusProofKind::Inclusion, _) => Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "inclusion proof is missing sticky retracted state",
        )),
    }
}

fn observe_status_route_time(
    store: &SqliteFindingStatusStore,
    feed_id: &str,
    read_now: impl FnOnce() -> u64,
) -> Result<u64, Response> {
    store
        .observe_trusted_time_with_clock(feed_id, read_now)
        .map(|(_, observed_at)| observed_at)
        .map_err(status_read_error)
}

fn validate_intent_submission(
    signed: &SignedFindingStatusIntentSubmission,
    operator: &FindingStatusOperatorPin,
    service_bond: &FindingStatusServiceBond,
    feed_id: &str,
    now: u64,
) -> Result<(), Response> {
    let body = &signed.body;
    if body.schema != FINDING_STATUS_INTENT_SCHEMA
        || body.feed_id != feed_id
        || body.key_domain_nonce != FINDING_STATUS_KEY_DOMAIN_NONCE
        || body.operator_id != operator.authority.authority_id
        || body.operator_key_epoch != operator.authority.key_epoch
    {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent does not match the configured feed domain or operator",
        ));
    }
    if body.source != FindingStatusIntentSource::Voluntary {
        return Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "enforced status intents require the appeal-final coordinator",
        ));
    }
    require_hex64(&body.finding_id, "finding_id")?;
    require_hex64(&body.source_receipt_sha256, "source_receipt_sha256")?;
    if body.source_authority_id.trim().is_empty()
        || body.source_authority_id.trim() != body.source_authority_id
    {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent source authority id is invalid",
        ));
    }
    let deadline = body
        .issued_at
        .checked_add(service_bond.inclusion_sla_secs)
        .ok_or_else(|| {
            plain_http_error(StatusCode::BAD_REQUEST, "status intent deadline overflowed")
        })?;
    if body.issued_at == 0
        || body.issued_at > now
        || body.inclusion_deadline != deadline
        || now >= body.inclusion_deadline
    {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent is stale or has the wrong inclusion deadline",
        ));
    }
    if body.intent_id != compute_intent_id(body)? {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent id does not match its canonical preimage",
        ));
    }
    let pinned_key = require_status_feed_through(
        operator,
        service_bond,
        feed_id,
        now,
        body.inclusion_deadline,
    )
    .map_err(|error| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()))?;
    verify_pinned_envelope(signed, &pinned_key, "status intent operator").map_err(|_| {
        plain_http_error(
            StatusCode::UNAUTHORIZED,
            "status intent operator signature is invalid",
        )
    })?;
    let source = &body.source_receipt;
    if source.body.schema != FINDING_VOLUNTARY_RETRACTION_RECEIPT_SCHEMA
        || source.body.feed_id != body.feed_id
        || source.body.key_domain_nonce != body.key_domain_nonce
        || source.body.finding_id != body.finding_id
        || source.body.source_authority_id != body.source_authority_id
        || source.body.issued_at != body.issued_at
        || source.signer_key.to_hex() != body.source_authority_id
    {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "voluntary retraction source receipt bindings are invalid",
        ));
    }
    if !matches!(source.verify_signature(), Ok(true)) {
        return Err(plain_http_error(
            StatusCode::UNAUTHORIZED,
            "voluntary retraction source receipt signature is invalid",
        ));
    }
    let source_digest = chio_finding::signed_envelope_sha256(source).map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "voluntary retraction source receipt is not canonical",
        )
    })?;
    if source_digest != body.source_receipt_sha256 {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "voluntary retraction source receipt digest differs",
        ));
    }
    Ok(())
}

fn intent_persistence_time(
    signed: &SignedFindingStatusIntentSubmission,
    operator: &FindingStatusOperatorPin,
    service_bond: &FindingStatusServiceBond,
    feed_id: &str,
    read_now: impl FnOnce() -> u64,
) -> Result<u64, Response> {
    let persistence_now = read_now();
    validate_intent_submission(signed, operator, service_bond, feed_id, persistence_now)?;
    Ok(persistence_now)
}

fn intent_response(record: FindingRetractionIntentRecord, exact_replay: bool) -> Response {
    let status = match record.state {
        chio_store_sqlite::FindingRetractionIntentState::WaitingFinality => "waiting_finality",
        chio_store_sqlite::FindingRetractionIntentState::DispatchEligible => "dispatch_eligible",
        chio_store_sqlite::FindingRetractionIntentState::Published => "published",
    };
    Json(FindingStatusIntentResponse {
        intent_id: record.intent_id,
        feed_id: record.feed_id,
        finding_id: record.finding_id,
        intent_sha256: record.intent_sha256,
        status,
        exact_replay,
        inclusion_deadline: record.inclusion_deadline,
    })
    .into_response()
}

fn recover_exact_intent_replay(
    store: &SqliteFindingStatusStore,
    intent_id: &str,
    raw: &[u8],
) -> Result<Option<Response>, Response> {
    match store.get_retraction_intent(intent_id) {
        Ok(Some(record)) if record.intent_bytes == raw => Ok(Some(intent_response(record, true))),
        Ok(_) => Ok(None),
        Err(error) => Err(status_read_error(error)),
    }
}

fn require_authorized_voluntary_source(
    state: &TrustServiceState,
    signed: &SignedFindingStatusIntentSubmission,
) -> Result<(), Response> {
    let Some(authority) = state.joint_authority_store.as_ref() else {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "voluntary retraction authorization requires the durable finding market",
        ));
    };
    let raw = authority
        .finding_market_store()
        .get_finding_bytes(&signed.body.finding_id)
        .map_err(|error| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()))?
        .ok_or_else(|| {
            plain_http_error(
                StatusCode::FORBIDDEN,
                "voluntary retraction source is not authorized for the retained finding",
            )
        })?;
    let finding: chio_finding::Finding = serde_json::from_str(&raw).map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "retained finding cannot be authenticated for voluntary retraction",
        )
    })?;
    chio_finding::verify_finding(&finding).map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "retained finding cannot be authenticated for voluntary retraction",
        )
    })?;
    if finding.finding_id != signed.body.finding_id
        || finding.status_feed_ref != signed.body.feed_id
        || finding.issuer.to_hex() != signed.body.source_authority_id
        || signed.body.source_receipt.signer_key != finding.issuer
    {
        return Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "voluntary retraction source is not authorized for the retained finding",
        ));
    }
    Ok(())
}

fn status_read_error(error: FindingStatusStoreError) -> Response {
    plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string())
}

fn status_write_error(error: FindingStatusStoreError) -> Response {
    let status = match error {
        FindingStatusStoreError::Conflict(_)
        | FindingStatusStoreError::Rollback { .. }
        | FindingStatusStoreError::Equivocation { .. }
        | FindingStatusStoreError::ContradictoryNonInclusion { .. } => StatusCode::CONFLICT,
        FindingStatusStoreError::Fenced => StatusCode::FORBIDDEN,
        FindingStatusStoreError::Unavailable(_)
        | FindingStatusStoreError::Invariant(_)
        | FindingStatusStoreError::OutcomeUnknown(_)
        | FindingStatusStoreError::MissingFloor { .. }
        | FindingStatusStoreError::MissingState { .. }
        | FindingStatusStoreError::ClockRollback { .. }
        | FindingStatusStoreError::StaleProof { .. } => StatusCode::SERVICE_UNAVAILABLE,
    };
    plain_http_error(status, &error.to_string())
}

/// GET /v1/findings/status/{feed}/root.
pub(crate) async fn handle_get_finding_status_root(
    State(state): State<TrustServiceState>,
    AxumPath(feed_id): AxumPath<String>,
) -> Response {
    let request_started_at = unix_timestamp_now();
    let (_, store) = match status_context(&state, &feed_id, request_started_at) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let epoch = match store.get_current_epoch(&feed_id) {
        Ok(epoch) => epoch,
        Err(error) => return status_read_error(error),
    };
    let verification_now = match observe_status_route_time(&store, &feed_id, unix_timestamp_now) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let config = match live_status_config(&state, &feed_id, verification_now) {
        Ok(config) => config,
        Err(response) => return response,
    };
    if let Err(response) = require_current_epoch(
        &config.status_feed_operator,
        &config.status_feed_service_bond,
        config.status_max_epoch_age_secs,
        &epoch,
        verification_now,
    ) {
        return response;
    }
    Json(FindingStatusRootResponse {
        feed_id: epoch.feed_id,
        key_domain_nonce: epoch.key_domain_nonce,
        map_epoch: epoch.map_epoch,
        epoch_id: epoch.epoch_id,
        root_hash: epoch.root_hash,
        signed_epoch_sha256: epoch.signed_epoch_sha256,
        signed_epoch_b64: STANDARD.encode(epoch.signed_epoch_bytes),
        valid_until: epoch.valid_until,
    })
    .into_response()
}

/// GET /v1/findings/status/{feed}/proof/{finding_id}.
pub(crate) async fn handle_get_finding_status_proof(
    State(state): State<TrustServiceState>,
    AxumPath((feed_id, finding_id)): AxumPath<(String, String)>,
) -> Response {
    let request_started_at = unix_timestamp_now();
    let (_, store) = match status_context(&state, &feed_id, request_started_at) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let epoch = match store.get_current_epoch(&feed_id) {
        Ok(epoch) => epoch,
        Err(error) => return status_read_error(error),
    };
    let proof = match store.get_latest_proof(&feed_id, &finding_id) {
        Ok(Some(proof)) => proof,
        Ok(None) => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "current portable finding status proof is unavailable",
            )
        }
        Err(error) => return status_read_error(error),
    };
    let verification_now = match observe_status_route_time(&store, &feed_id, unix_timestamp_now) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let config = match live_status_config(&state, &feed_id, verification_now) {
        Ok(config) => config,
        Err(response) => return response,
    };
    if let Err(response) = require_current_epoch(
        &config.status_feed_operator,
        &config.status_feed_service_bond,
        config.status_max_epoch_age_secs,
        &epoch,
        verification_now,
    ) {
        return response;
    }
    if let Err(response) = require_current_proof_material(
        &config.status_feed_operator,
        &config.status_feed_service_bond,
        config.status_max_epoch_age_secs,
        &epoch,
        &proof,
        verification_now,
    ) {
        return response;
    }
    if let Err(response) = require_proof_sticky_state(&store, &proof) {
        return response;
    }
    let final_now = match observe_status_route_time(&store, &feed_id, unix_timestamp_now) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let config = match live_status_config(&state, &feed_id, final_now) {
        Ok(config) => config,
        Err(response) => return response,
    };
    if let Err(response) = require_current_epoch(
        &config.status_feed_operator,
        &config.status_feed_service_bond,
        config.status_max_epoch_age_secs,
        &epoch,
        final_now,
    ) {
        return response;
    }
    if let Err(response) = require_current_proof_material(
        &config.status_feed_operator,
        &config.status_feed_service_bond,
        config.status_max_epoch_age_secs,
        &epoch,
        &proof,
        final_now,
    ) {
        return response;
    }
    if let Err(response) = require_proof_sticky_state(&store, &proof) {
        return response;
    }
    let proof_kind = match proof.kind {
        FindingStatusProofKind::Inclusion => "inclusion",
        FindingStatusProofKind::NonInclusion => "non_inclusion",
    };
    Json(FindingStatusProofResponse {
        feed_id: proof.feed_id,
        key_domain_nonce: proof.key_domain_nonce,
        map_epoch: proof.map_epoch,
        epoch_id: proof.epoch_id,
        root_hash: proof.root_hash,
        finding_id: proof.finding_id,
        proof_kind,
        proof_sha256: proof.proof_sha256,
        proof_input_b64: STANDARD.encode(proof.proof_bytes),
        signed_epoch_sha256: proof.signed_epoch_sha256,
        signed_epoch_b64: STANDARD.encode(proof.signed_epoch_bytes),
        service_bond_evidence_sha256: config.status_feed_service_bond.evidence_sha256,
        checked_at: proof.checked_at,
        valid_until: proof.valid_until,
    })
    .into_response()
}

/// POST /v1/findings/status/{feed}/intents. This accepts voluntary intent
/// receipts only. The exact canonical signed request is retained in the
/// durable outbox and immediately makes the finding sticky pending.
pub(crate) async fn handle_submit_finding_status_intent(
    State(state): State<TrustServiceState>,
    AxumPath(feed_id): AxumPath<String>,
    headers: HeaderMap,
    raw: String,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let signed = match strict_intent_ingress(&raw) {
        Ok(signed) => signed,
        Err(response) => return response,
    };
    let body = &signed.body;
    if let Err(response) = require_hex64(&body.intent_id, "intent_id") {
        return response;
    }
    if body.feed_id != feed_id {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent does not match the route feed",
        );
    }
    let store = match status_store(&state) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match recover_exact_intent_replay(&store, &body.intent_id, raw.as_bytes()) {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let now = unix_timestamp_now();
    let config = match live_status_config(&state, &feed_id, now) {
        Ok(config) => config,
        Err(response) => return response,
    };
    if let Err(response) = validate_intent_submission(
        &signed,
        &config.status_feed_operator,
        &config.status_feed_service_bond,
        &feed_id,
        now,
    ) {
        return response;
    }
    if let Err(response) = require_authorized_voluntary_source(&state, &signed) {
        return response;
    }
    let persistence_now = match intent_persistence_time(
        &signed,
        &config.status_feed_operator,
        &config.status_feed_service_bond,
        &feed_id,
        unix_timestamp_now,
    ) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let operator_valid_until = config
        .status_feed_operator
        .revoked_from
        .unwrap_or(config.status_feed_operator.authority.valid_until)
        .min(config.status_feed_operator.authority.valid_until);
    let commit_liveness = FindingRetractionIntentCommitLiveness {
        valid_from: config
            .status_feed_operator
            .authority
            .valid_from
            .max(config.status_feed_service_bond.valid_from),
        valid_until: operator_valid_until.min(config.status_feed_service_bond.valid_until),
    };
    let outcome = match store.issue_retraction_intent_with_commit_clock(
        &FindingRetractionIntentInput {
            intent_id: &body.intent_id,
            feed_id: &body.feed_id,
            operator_id: &body.operator_id,
            finding_id: &body.finding_id,
            source: body.source.store_source(),
            intent_bytes: raw.as_bytes(),
            issued_at: body.issued_at,
            inclusion_deadline: body.inclusion_deadline,
            created_at: persistence_now,
        },
        commit_liveness,
        unix_timestamp_now,
    ) {
        Ok(outcome) => outcome,
        Err(error) => return status_write_error(error),
    };
    let record = match store.get_retraction_intent(&body.intent_id) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "persisted status intent cannot be recovered",
            )
        }
        Err(error) => return status_read_error(error),
    };
    intent_response(record, outcome == FindingStatusWriteOutcome::ExactReplay)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use chio_core::crypto::Keypair;
    use chio_kernel::finding_purchase::{
        FindingStatusProofContextView, FindingStatusProofVerifier,
    };
    use chio_store_sqlite::SqliteAuthorityStore;
    use chio_test_support::prelude::*;
    use chio_transaction_passport::{
        CognitionMarketStatusObservation, CognitionMarketStatusTrustStore,
    };

    const FEED_ID: &str = "status-feed/test";
    const NOW: u64 = 1_800_000_000;

    fn operator_key() -> Keypair {
        Keypair::from_seed(&[81; 32])
    }

    fn authority_pin(seed: u8, authority_id: &str, now: u64) -> FindingAuthorityPin {
        FindingAuthorityPin {
            authority_id: authority_id.to_string(),
            key_hex: Keypair::from_seed(&[seed; 32]).public_key().to_hex(),
            key_epoch: 1,
            valid_from: now.saturating_sub(100),
            valid_until: now.saturating_add(10_000),
            revocation_status_ref: format!("revocations/{authority_id}"),
        }
    }

    fn config() -> (FindingStatusOperatorPin, FindingStatusServiceBond) {
        let operator = FindingStatusOperatorPin {
            feed_id: FEED_ID.to_string(),
            role: FINDING_STATUS_OPERATOR_ROLE.to_string(),
            authority: FindingAuthorityPin {
                authority_id: "status-operator".to_string(),
                key_hex: operator_key().public_key().to_hex(),
                key_epoch: 4,
                valid_from: NOW - 100,
                valid_until: NOW + 10_000,
                revocation_status_ref: "revocations/status".to_string(),
            },
            rotation_policy_ref: "rotation/status-v1".to_string(),
            authorization_sha256: sha256_hex(b"status-authorization"),
            revoked_from: None,
        };
        let bond = FindingStatusServiceBond {
            bond_id: "status-bond".to_string(),
            feed_id: FEED_ID.to_string(),
            operator_id: "status-operator".to_string(),
            locked_units: 1_000,
            currency: "USD".to_string(),
            valid_from: NOW - 100,
            valid_until: NOW + 10_000,
            inclusion_sla_secs: 600,
            missed_inclusion_slash_units: 100,
            equivocation_slash_units: 1_000,
            evidence_sha256: sha256_hex(b"bond"),
        };
        (operator, bond)
    }

    fn submission() -> FindingStatusIntentSubmission {
        let (operator, bond) = config();
        let seller = Keypair::from_seed(&[83; 32]);
        let source_authority_id = seller.public_key().to_hex();
        let finding_id = sha256_hex(b"finding");
        let source_receipt = SignedExportEnvelope::sign(
            FindingVoluntaryRetractionReceipt {
                schema: FINDING_VOLUNTARY_RETRACTION_RECEIPT_SCHEMA.to_string(),
                feed_id: FEED_ID.to_string(),
                key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
                finding_id: finding_id.clone(),
                source_authority_id: source_authority_id.clone(),
                issued_at: NOW,
            },
            &seller,
        )
        .test_expect("seller-signed retraction receipt");
        let source_receipt_sha256 = chio_finding::signed_envelope_sha256(&source_receipt)
            .test_expect("source receipt digest");
        let mut body = FindingStatusIntentSubmission {
            schema: FINDING_STATUS_INTENT_SCHEMA.to_string(),
            intent_id: String::new(),
            feed_id: FEED_ID.to_string(),
            key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
            finding_id,
            source: FindingStatusIntentSource::Voluntary,
            source_authority_id,
            source_receipt_sha256,
            source_receipt,
            operator_id: operator.authority.authority_id,
            operator_key_epoch: operator.authority.key_epoch,
            issued_at: NOW,
            inclusion_deadline: NOW + bond.inclusion_sla_secs,
        };
        body.intent_id = compute_intent_id(&body).test_expect("canonical status intent id");
        body
    }

    fn live_market_config(now: u64) -> FindingMarketConfig {
        let status_operator = FindingStatusOperatorPin {
            feed_id: FEED_ID.to_string(),
            role: FINDING_STATUS_OPERATOR_ROLE.to_string(),
            authority: FindingAuthorityPin {
                authority_id: "status-operator".to_string(),
                key_hex: operator_key().public_key().to_hex(),
                key_epoch: 4,
                valid_from: now.saturating_sub(100),
                valid_until: now.saturating_add(10_000),
                revocation_status_ref: "revocations/status".to_string(),
            },
            rotation_policy_ref: "rotation/status-v1".to_string(),
            authorization_sha256: sha256_hex(b"status-authorization"),
            revoked_from: None,
        };
        FindingMarketConfig {
            venue_id: "status-test-venue".to_string(),
            venue: authority_pin(1, "venue", now),
            listing: authority_pin(12, "listing", now),
            governance_root: authority_pin(2, "governance", now),
            authority_status: authority_pin(13, "authority-status", now),
            verifier_report: authority_pin(3, "verifier", now),
            collateral: authority_pin(4, "collateral", now),
            purchase: authority_pin(5, "purchase", now),
            failed_delivery: authority_pin(6, "failed-delivery", now),
            challenge_evaluator: authority_pin(7, "challenge-evaluator", now),
            venue_finalization: authority_pin(8, "venue-finalization", now),
            market_penalty: authority_pin(9, "market-penalty", now),
            settlement_observer: authority_pin(10, "settlement-observer", now),
            anchor_publisher: authority_pin(15, "anchor-publisher", now),
            max_snapshot_age_secs: 3_600,
            settlement_finality_requirement:
                chio_settle::FindingFinalityRequirement::Confirmations { min_depth: 64 },
            audit_authority: authority_pin(11, "audit-authority", now),
            audit_randomness_witness: authority_pin(14, "audit-randomness-witness", now),
            audit_pool: FindingPoolPin {
                principal_id: "pool:audit".to_string(),
                rail_destination: "rail:test:audit".to_string(),
                currency: "USD".to_string(),
                authority_epoch: 1,
            },
            challenge_administration_pool: FindingPoolPin {
                principal_id: "pool:challenge".to_string(),
                rail_destination: "rail:test:challenge".to_string(),
                currency: "USD".to_string(),
                authority_epoch: 1,
            },
            community_fund_destination: "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
            status_feed_operator_ref: FEED_ID.to_string(),
            status_feed_operator: status_operator,
            status_feed_service_bond: FindingStatusServiceBond {
                bond_id: "status-bond".to_string(),
                feed_id: FEED_ID.to_string(),
                operator_id: "status-operator".to_string(),
                locked_units: 1_000,
                currency: "USD".to_string(),
                valid_from: now.saturating_sub(100),
                valid_until: now.saturating_add(10_000),
                inclusion_sla_secs: 600,
                missed_inclusion_slash_units: 100,
                equivocation_slash_units: 1_000,
                evidence_sha256: sha256_hex(b"status-bond"),
            },
            status_max_epoch_age_secs: 300,
            fee_schedule_operator_keys: vec![Keypair::from_seed(&[90; 32]).public_key().to_hex()],
        }
    }

    fn service_state(
        authority: Arc<SqliteAuthorityStore>,
        market: FindingMarketConfig,
    ) -> TrustServiceState {
        TrustServiceState {
            config: TrustServiceConfig {
                listen: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
                service_token: "service-secret".to_string(),
                tenant_read_tokens: BTreeMap::new(),
                receipt_db_path: None,
                revocation_db_path: None,
                authority_seed_path: None,
                authority_db_path: None,
                budget_db_path: None,
                joint_authority_db_path: None,
                fiscal_runtime: None,
                enterprise_providers_file: None,
                federation_policies_file: None,
                scim_lifecycle_file: None,
                verifier_policies_file: None,
                verifier_challenge_db_path: None,
                passport_statuses_file: None,
                passport_issuance_offers_file: None,
                certification_registry_file: None,
                certification_discovery_file: None,
                issuance_policy: None,
                runtime_assurance_policy: None,
                advertise_url: None,
                allow_local_peer_urls: true,
                certification_public_metadata_ttl_seconds: 300,
                peer_urls: Vec::new(),
                cluster_sync_interval: Duration::from_millis(25),
                roster_policy: None,
                memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
                finding_market: Some(market),
            },
            joint_authority_store: Some(authority),
            fiscal_runtime: None,
            budget_store: None,
            revocation_store: None,
            enterprise_provider_registry: None,
            verifier_policy_registry: None,
            federation_admission_rate_limiter: Arc::new(Mutex::new(
                FederationAdmissionRateLimiter::default(),
            )),
            cluster: None,
            cluster_progress: None,
            finding_rail: None,
            finding_purchase_executor: None,
            finding_purchase_execution_lane: Arc::new(tokio::sync::Semaphore::new(1)),
            finding_proof_egress_lane: Arc::new(tokio::sync::Semaphore::new(1)),
            finding_seller_submission_executor: None,
            finding_seller_submission_lane: Arc::new(tokio::sync::Semaphore::new(1)),
            finding_challenge_submission_lane: Arc::new(tokio::sync::Semaphore::new(1)),
            finding_authority_status_resolver: None,
            finding_challenge_executor: None,
        }
    }

    fn provision_authority(
    ) -> Result<(tempfile::TempDir, Arc<SqliteAuthorityStore>), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))?;
        }
        let database = temp.path().join("authority.sqlite3");
        let lock_root = temp.path().join("locks");
        fs::create_dir(&lock_root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o700))?;
        }
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        let authority = Arc::new(SqliteAuthorityStore::open_serving(&database, &lock_root)?);
        Ok((temp, authority))
    }

    #[test]
    fn status_intent_id_binds_the_fixed_domain_and_source_receipt() {
        let body = submission();
        let id = compute_intent_id(&body).test_expect("status intent id");
        let mut substituted = body;
        substituted.source_receipt_sha256 = sha256_hex(b"other-source-receipt");
        let other = compute_intent_id(&substituted).test_expect("substituted intent id");
        assert_ne!(id, other);
    }

    #[test]
    fn strict_ingress_rejects_noncanonical_signed_bytes() {
        let signed = SignedExportEnvelope::sign(submission(), &operator_key())
            .test_expect("signed status intent");
        let pretty = serde_json::to_string_pretty(&signed).test_expect("pretty status intent");
        assert!(strict_intent_ingress(&pretty).is_err());

        let canonical = canonical_json_bytes(&signed).test_expect("canonical status intent");
        let raw = String::from_utf8(canonical).test_expect("UTF-8 status intent");
        assert!(strict_intent_ingress(&raw).is_ok());
    }

    #[test]
    fn intent_validation_rejects_unsigned_and_operator_substitution() {
        let (operator, bond) = config();
        let mut signed = SignedExportEnvelope::sign(submission(), &operator_key())
            .test_expect("signed status intent");
        signed.body.source_authority_id = "substituted-seller".to_string();
        signed.body.intent_id =
            compute_intent_id(&signed.body).test_expect("substituted status intent id");
        let response = validate_intent_submission(&signed, &operator, &bond, FEED_ID, NOW)
            .test_expect_err("mutated unsigned body must reject");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let substitute = Keypair::from_seed(&[82; 32]);
        let signed = SignedExportEnvelope::sign(submission(), &substitute)
            .test_expect("substitute-signed status intent");
        let response = validate_intent_submission(&signed, &operator, &bond, FEED_ID, NOW)
            .test_expect_err("operator substitution must reject");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn intent_validation_rejects_a_countersigned_forged_source_receipt() {
        let (operator, bond) = config();
        let mut body = submission();
        body.source_receipt.signature = Keypair::from_seed(&[84; 32]).sign(b"forged source");
        body.source_receipt_sha256 = chio_finding::signed_envelope_sha256(&body.source_receipt)
            .test_expect("forged source receipt digest");
        body.intent_id = compute_intent_id(&body).test_expect("forged status intent id");
        let signed = SignedExportEnvelope::sign(body, &operator_key())
            .test_expect("operator-countersigned forged source receipt");

        let response = validate_intent_submission(&signed, &operator, &bond, FEED_ID, NOW)
            .test_expect_err("operator countersignature cannot replace source authentication");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn intent_validation_rejects_stale_intent_and_expired_bond() {
        let (operator, mut bond) = config();
        let mut stale = submission();
        stale.issued_at = NOW - bond.inclusion_sla_secs;
        stale.inclusion_deadline = NOW;
        stale.intent_id = compute_intent_id(&stale).test_expect("stale status intent id");
        let stale = SignedExportEnvelope::sign(stale, &operator_key())
            .test_expect("stale signed status intent");
        let response = validate_intent_submission(&stale, &operator, &bond, FEED_ID, NOW)
            .test_expect_err("stale status intent must reject");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        bond.valid_until = NOW;
        let signed = SignedExportEnvelope::sign(submission(), &operator_key())
            .test_expect("signed status intent");
        let response = validate_intent_submission(&signed, &operator, &bond, FEED_ID, NOW)
            .test_expect_err("expired status bond must reject");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let (mut operator, mut bond) = config();
        operator.authority.valid_until = NOW + bond.inclusion_sla_secs;
        bond.valid_until = NOW + bond.inclusion_sla_secs;
        let signed = SignedExportEnvelope::sign(submission(), &operator_key())
            .test_expect("signed status intent at expiring SLA boundary");
        let response = validate_intent_submission(&signed, &operator, &bond, FEED_ID, NOW)
            .test_expect_err("operator and bond must cover the full inclusion SLA");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn new_intent_refreshes_liveness_at_persistence() {
        let (operator, bond) = config();
        let signed = SignedExportEnvelope::sign(submission(), &operator_key())
            .test_expect("signed status intent");
        let response = intent_persistence_time(&signed, &operator, &bond, FEED_ID, || {
            signed.body.inclusion_deadline
        })
        .test_expect_err("intent expiring during validation must not be persisted");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn retained_exact_replay_recovers_without_current_liveness() {
        let (_temp, authority) = provision_authority().test_expect("durable authority store");
        let store = authority.finding_status_store();
        let signed = SignedExportEnvelope::sign(submission(), &operator_key())
            .test_expect("signed status intent");
        let raw = canonical_json_bytes(&signed).test_expect("canonical signed intent");
        store
            .issue_retraction_intent(&FindingRetractionIntentInput {
                intent_id: &signed.body.intent_id,
                feed_id: &signed.body.feed_id,
                operator_id: &signed.body.operator_id,
                finding_id: &signed.body.finding_id,
                source: FindingRetractionIntentSource::Voluntary,
                intent_bytes: &raw,
                issued_at: signed.body.issued_at,
                inclusion_deadline: signed.body.inclusion_deadline,
                created_at: signed.body.issued_at,
            })
            .test_expect("persist exact status intent");

        let response = recover_exact_intent_replay(&store, &signed.body.intent_id, &raw)
            .test_expect("read retained intent")
            .test_expect("exact replay returns its retained decision");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn retained_finding_rejects_a_self_authorized_voluntary_source(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_temp, authority) = provision_authority()?;
        let raw = include_str!(
            "../../../../../fixtures/proof-room/finding/verified-fix-basic/finding.json"
        );
        let finding: chio_finding::Finding = serde_json::from_str(raw)?;
        chio_finding::verify_finding(&finding)?;
        authority.finding_market_store().put_finding(
            &chio_store_sqlite::FindingRecordInput {
                finding_id: &finding.finding_id,
                artifact_json: raw,
                topic: &finding.descriptor.topic,
                context_sha256: &finding.descriptor.context_sha256,
                issued_at: finding.issued_at,
                expires_at: finding.expires_at,
            },
            NOW,
        )?;

        let seller = Keypair::from_seed(&[83; 32]);
        let mut body = submission();
        body.finding_id.clone_from(&finding.finding_id);
        body.feed_id.clone_from(&finding.status_feed_ref);
        body.source_receipt = SignedExportEnvelope::sign(
            FindingVoluntaryRetractionReceipt {
                schema: FINDING_VOLUNTARY_RETRACTION_RECEIPT_SCHEMA.to_string(),
                feed_id: body.feed_id.clone(),
                key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
                finding_id: body.finding_id.clone(),
                source_authority_id: seller.public_key().to_hex(),
                issued_at: NOW,
            },
            &seller,
        )?;
        body.source_authority_id = seller.public_key().to_hex();
        body.source_receipt_sha256 = chio_finding::signed_envelope_sha256(&body.source_receipt)?;
        body.intent_id = compute_intent_id(&body).test_expect("self-authorized intent id");
        let signed = SignedExportEnvelope::sign(body, &operator_key())?;
        let state = service_state(authority, live_market_config(NOW));

        let response = require_authorized_voluntary_source(&state, &signed)
            .test_expect_err("an arbitrary source key must not authorize its own retraction");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[test]
    fn verifier_and_publisher_reject_malformed_service_bond(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (operator, mut bond) = config();
        let (_temp, authority) = provision_authority()?;
        bond.locked_units = 0;

        assert!(
            super::super::finding_status_verifier::MarketFindingStatusVerifier::new(
                operator.clone(),
                bond.clone(),
                300,
                authority.finding_status_store(),
            )
            .is_err()
        );
        assert!(
            super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
                authority.finding_status_store(),
                operator,
                bond,
                operator_key(),
                300,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn imported_point_proof_cannot_advance_the_publisher_floor(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (operator, bond) = config();
        let (_local_temp, local_authority) = provision_authority()?;
        let local_store = local_authority.finding_status_store();
        let local_publisher =
            super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
                local_store.clone(),
                operator.clone(),
                bond.clone(),
                operator_key(),
                300,
            )?;
        let finding_id = sha256_hex(b"local-live-finding");
        let local = local_publisher.publish_non_inclusion(&finding_id, &[], NOW)?;
        assert_eq!(local.map_epoch, 1);

        let (_remote_temp, remote_authority) = provision_authority()?;
        let remote_store = remote_authority.finding_status_store();
        let remote_publisher =
            super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
                remote_store.clone(),
                operator.clone(),
                bond.clone(),
                operator_key(),
                300,
            )?;
        remote_publisher.publish_non_inclusion(&finding_id, &[], NOW)?;
        let retracted_id = sha256_hex(b"remote-retracted-finding");
        let intent_id = sha256_hex(b"remote-retraction-intent");
        let intent_bytes = canonical_json_bytes(&serde_json::json!({
            "finding_id": retracted_id,
            "schema": "chio.finding.test-retraction.v1",
        }))?;
        remote_store.issue_retraction_intent(&FindingRetractionIntentInput {
            intent_id: &intent_id,
            feed_id: FEED_ID,
            operator_id: &operator.authority.authority_id,
            finding_id: &retracted_id,
            source: FindingRetractionIntentSource::Voluntary,
            intent_bytes: &intent_bytes,
            issued_at: NOW,
            inclusion_deadline: NOW + bond.inclusion_sla_secs,
            created_at: NOW,
        })?;
        let retracted = remote_publisher.publish_retraction(&intent_id, &[], NOW + 1)?;
        let retracted_epoch =
            chio_finding::parse_signed_status_epoch(&retracted.signed_epoch_bytes)?;
        let retracted_proof = chio_finding::parse_status_proof_input(&retracted.proof_bytes)?;
        let retracted_error = remote_store
            .admit_verified_status(&CognitionMarketStatusObservation {
                signed_epoch: &retracted_epoch,
                signed_epoch_bytes: &retracted.signed_epoch_bytes,
                proof: &retracted_proof,
                proof_bytes: &retracted.proof_bytes,
                operator_authorization_sha256: &operator.authorization_sha256,
                max_epoch_age_secs: 300,
                recorded_at: NOW + 1,
            })
            .test_expect_err("an imported inclusion must preserve the raw v1 leaf encoding");
        assert_eq!(retracted_error, "finding is retracted");
        assert_eq!(
            remote_store
                .get_leaf(FEED_ID, &retracted_id)?
                .ok_or_else(|| std::io::Error::other("retracted leaf"))?
                .status_value_bytes,
            b"retracted"
        );
        let imported = remote_publisher.publish_non_inclusion(&finding_id, &[], NOW + 1)?;
        assert_eq!(imported.map_epoch, 2);

        let imported_epoch = chio_finding::parse_signed_status_epoch(&imported.signed_epoch_bytes)?;
        let imported_proof = chio_finding::parse_status_proof_input(&imported.proof_bytes)?;
        let import_error = local_store
            .admit_verified_status(&CognitionMarketStatusObservation {
                signed_epoch: &imported_epoch,
                signed_epoch_bytes: &imported.signed_epoch_bytes,
                proof: &imported_proof,
                proof_bytes: &imported.proof_bytes,
                operator_authorization_sha256: &operator.authorization_sha256,
                max_epoch_age_secs: 300,
                recorded_at: NOW + 1,
            })
            .test_expect_err("one imported point proof must not advance the durable feed floor");
        assert!(import_error.contains("exact durable feed floor"));
        assert_eq!(local_store.get_feed_floor(FEED_ID)?.map_epoch, 1);

        let verifier = super::super::finding_status_verifier::MarketFindingStatusVerifier::new(
            operator,
            bond,
            300,
            local_store.clone(),
        )?;
        let imported_b64 = STANDARD.encode(&imported.proof_bytes);
        let view = FindingStatusProofContextView {
            proof_b64: &imported_b64,
            expected_finding_id: &finding_id,
            expected_feed_id: FEED_ID,
        };
        let verified = verifier.verify_status_proof(&view)?;
        let error = verifier
            .verify_status_admission(&view, &verified, NOW + 1)
            .test_expect_err("an imported future point proof must not advance publisher state");
        assert!(error.detail().contains("authoritative publisher floor"));
        assert_eq!(local_store.get_feed_floor(FEED_ID)?.map_epoch, 1);
        assert_eq!(
            local_publisher
                .publish_non_inclusion(&sha256_hex(b"another-local-live-finding"), &[], NOW + 1)?
                .map_epoch,
            1
        );
        Ok(())
    }

    #[test]
    fn portable_proof_is_bound_to_the_authenticated_finding_feed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (operator, bond) = config();
        let (_temp, authority) = provision_authority()?;
        let store = authority.finding_status_store();
        let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
            store.clone(),
            operator.clone(),
            bond.clone(),
            operator_key(),
            300,
        )?;
        let finding_id = sha256_hex(b"feed-bound-finding");
        let published = publisher.publish_non_inclusion(&finding_id, &[], NOW)?;
        let verifier = super::super::finding_status_verifier::MarketFindingStatusVerifier::new(
            operator, bond, 300, store,
        )?;
        let proof_b64 = STANDARD.encode(&published.proof_bytes);
        let error = verifier
            .verify_status_proof(&FindingStatusProofContextView {
                proof_b64: &proof_b64,
                expected_finding_id: &finding_id,
                expected_feed_id: "status-feed/other",
            })
            .test_expect_err("a proof from another feed must not establish live status");
        assert_eq!(
            error.detail(),
            "finding status proof binds a different feed"
        );
        Ok(())
    }

    #[test]
    fn portable_proof_survives_a_valid_replacement_bond_window(
    ) -> Result<(), Box<dyn std::error::Error>> {
        struct FixedAdmissionClock(u64);

        impl super::super::finding_status_verifier::FindingStatusAdmissionClock for FixedAdmissionClock {
            fn now_unix_secs(&self) -> Result<u64, String> {
                Ok(self.0)
            }
        }

        let (operator, bond) = config();
        let (_temp, authority) = provision_authority()?;
        let store = authority.finding_status_store();
        let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
            store.clone(),
            operator.clone(),
            bond.clone(),
            operator_key(),
            300,
        )?;
        let finding_id = sha256_hex(b"replacement-bond-finding");
        let published = publisher.publish_non_inclusion(&finding_id, &[], NOW)?;
        let mut replacement_bond = bond;
        replacement_bond.valid_from = NOW + 1;
        replacement_bond.evidence_sha256 = sha256_hex(b"replacement-status-bond");
        let verifier =
            super::super::finding_status_verifier::MarketFindingStatusVerifier::new_with_clock(
                operator,
                replacement_bond,
                300,
                store,
                Arc::new(FixedAdmissionClock(NOW + 1)),
            )?;
        let proof_b64 = STANDARD.encode(&published.proof_bytes);
        let view = FindingStatusProofContextView {
            proof_b64: &proof_b64,
            expected_finding_id: &finding_id,
            expected_feed_id: FEED_ID,
        };

        let verified = verifier.verify_status_proof(&view)?;
        verifier.verify_status_admission(&view, &verified, NOW + 1)?;
        Ok(())
    }

    #[test]
    fn root_projection_rejects_stale_or_substituted_epoch_authority(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (operator, bond) = config();
        let (_temp, authority) = provision_authority()?;
        let store = authority.finding_status_store();
        let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
            store.clone(),
            operator.clone(),
            bond.clone(),
            operator_key(),
            300,
        )?;
        publisher.publish_non_inclusion(&sha256_hex(b"root-test-finding"), &[], NOW)?;
        let mut epoch = store.get_current_epoch(FEED_ID)?;
        require_current_epoch(&operator, &bond, 300, &epoch, NOW)
            .test_expect("authorized current epoch");

        epoch.operator_key = Keypair::from_seed(&[83; 32]).public_key().to_hex();
        let response = require_current_epoch(&operator, &bond, 300, &epoch, NOW)
            .test_expect_err("substitute epoch operator must reject");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        epoch.operator_key = operator.authority.key_hex.clone();
        epoch.valid_until = NOW;
        let response = require_current_epoch(&operator, &bond, 300, &epoch, NOW)
            .test_expect_err("stale epoch must reject");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        Ok(())
    }

    #[tokio::test]
    async fn root_and_proof_handlers_return_the_exact_verified_bytes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_temp, authority) = provision_authority()?;
        let now = unix_timestamp_now();
        let market = live_market_config(now);
        market.validate()?;
        let store = authority.finding_status_store();
        let finding_id = sha256_hex(b"proof-finding");
        let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
            store,
            market.status_feed_operator.clone(),
            market.status_feed_service_bond.clone(),
            operator_key(),
            market.status_max_epoch_age_secs,
        )?;
        let published = publisher.publish_non_inclusion(&finding_id, &[], now)?;
        let epoch_bytes = published.signed_epoch_bytes.clone();
        let proof_bytes = published.proof_bytes.clone();
        let state = service_state(authority, market);

        let root =
            handle_get_finding_status_root(State(state.clone()), AxumPath(FEED_ID.to_string()))
                .await;
        assert_eq!(root.status(), StatusCode::OK);
        let root_body = axum::body::to_bytes(root.into_body(), usize::MAX).await?;
        let root_json: serde_json::Value = serde_json::from_slice(&root_body)?;
        assert_eq!(
            root_json["signed_epoch_b64"],
            serde_json::Value::String(STANDARD.encode(&epoch_bytes))
        );

        let proof = handle_get_finding_status_proof(
            State(state),
            AxumPath((FEED_ID.to_string(), finding_id)),
        )
        .await;
        assert_eq!(proof.status(), StatusCode::OK);
        let proof_body = axum::body::to_bytes(proof.into_body(), usize::MAX).await?;
        let proof_json: serde_json::Value = serde_json::from_slice(&proof_body)?;
        assert_eq!(
            proof_json["signed_epoch_b64"],
            serde_json::Value::String(STANDARD.encode(&epoch_bytes))
        );
        assert_eq!(
            proof_json["proof_input_b64"],
            serde_json::Value::String(STANDARD.encode(&proof_bytes))
        );
        Ok(())
    }

    #[test]
    fn status_routes_reject_a_clock_below_the_durable_feed_floor(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_temp, authority) = provision_authority()?;
        let market = live_market_config(NOW);
        let store = authority.finding_status_store();
        let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
            store.clone(),
            market.status_feed_operator,
            market.status_feed_service_bond,
            operator_key(),
            market.status_max_epoch_age_secs,
        )?;
        publisher.publish_non_inclusion(&sha256_hex(b"clock-fenced-route"), &[], NOW)?;
        store.observe_trusted_time(FEED_ID, NOW + 100)?;

        let response = observe_status_route_time(&store, FEED_ID, || NOW + 50)
            .test_expect_err("route time below the durable floor must reject");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        Ok(())
    }

    #[test]
    fn changed_anchor_references_advance_an_unchanged_status_root(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_temp, authority) = provision_authority()?;
        let (operator, bond) = config();
        let store = authority.finding_status_store();
        let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
            store.clone(),
            operator,
            bond,
            operator_key(),
            300,
        )?;
        let first = publisher.publish_non_inclusion(&sha256_hex(b"first"), &[], NOW)?;
        let anchors = vec!["anchor/status-feed/1".to_string()];
        let second = publisher.publish_non_inclusion(&sha256_hex(b"second"), &anchors, NOW + 1)?;
        assert_eq!(second.map_epoch, first.map_epoch + 1);
        let current = store.get_current_epoch(FEED_ID)?;
        let signed = chio_finding::parse_signed_status_epoch(&current.signed_epoch_bytes)?;
        assert_eq!(signed.body.anchor_refs, anchors);
        Ok(())
    }

    #[test]
    fn reordered_or_duplicate_anchor_references_reuse_the_current_status_root(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_temp, authority) = provision_authority()?;
        let (operator, bond) = config();
        let store = authority.finding_status_store();
        let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
            store.clone(),
            operator,
            bond,
            operator_key(),
            300,
        )?;
        let first_anchors = vec![
            "anchor/status-feed/2".to_string(),
            "anchor/status-feed/1".to_string(),
            "anchor/status-feed/2".to_string(),
        ];
        let first = publisher.publish_non_inclusion(
            &sha256_hex(b"first-canonical-anchor-finding"),
            &first_anchors,
            NOW,
        )?;
        let reordered = vec![
            "anchor/status-feed/1".to_string(),
            "anchor/status-feed/2".to_string(),
        ];
        let second = publisher.publish_non_inclusion(
            &sha256_hex(b"second-canonical-anchor-finding"),
            &reordered,
            NOW + 1,
        )?;
        assert_eq!(second.map_epoch, first.map_epoch);
        let current = store.get_current_epoch(FEED_ID)?;
        let signed = chio_finding::parse_signed_status_epoch(&current.signed_epoch_bytes)?;
        assert_eq!(signed.body.anchor_refs, reordered);
        Ok(())
    }

    #[test]
    fn changed_operator_authorization_advances_an_unchanged_status_root(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_temp, authority) = provision_authority()?;
        let (operator, bond) = config();
        let store = authority.finding_status_store();
        let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
            store.clone(),
            operator.clone(),
            bond.clone(),
            operator_key(),
            300,
        )?;
        let first = publisher.publish_non_inclusion(&sha256_hex(b"first"), &[], NOW)?;

        let mut refreshed_operator = operator;
        let rotated_key = Keypair::from_seed(&[82; 32]);
        refreshed_operator.authority.key_hex = rotated_key.public_key().to_hex();
        refreshed_operator.authority.key_epoch += 1;
        refreshed_operator.revoked_from = Some(NOW + 1_000);
        refreshed_operator.authorization_sha256 = sha256_hex(b"refreshed-status-authorization");
        let refreshed = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
            store.clone(),
            refreshed_operator.clone(),
            bond,
            rotated_key,
            300,
        )?;
        let second = refreshed.publish_non_inclusion(&sha256_hex(b"second"), &[], NOW + 1)?;

        assert_eq!(second.map_epoch, first.map_epoch + 1);
        assert_eq!(
            store
                .get_current_epoch(FEED_ID)?
                .operator_authorization_sha256,
            refreshed_operator.authorization_sha256
        );
        Ok(())
    }

    #[test]
    fn publisher_rejects_epoch_reuse_after_operator_revocation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_temp, authority) = provision_authority()?;
        let (operator, bond) = config();
        let store = authority.finding_status_store();
        let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
            store.clone(),
            operator.clone(),
            bond.clone(),
            operator_key(),
            1_000,
        )?;
        let finding_id = sha256_hex(b"pre-revocation-finding");
        publisher.publish_non_inclusion(&finding_id, &[], NOW)?;

        let mut revoked_operator = operator;
        revoked_operator.revoked_from = Some(NOW + 700);
        let revoked_publisher =
            super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
                store,
                revoked_operator,
                bond,
                operator_key(),
                1_000,
            )?;
        let error = revoked_publisher
            .publish_non_inclusion(&finding_id, &[], NOW + 701)
            .test_expect_err("revoked operator must not reuse a prior signed epoch");
        assert!(
            error.contains("outside its validity window"),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[test]
    fn publisher_rejects_epoch_reuse_after_service_bond_expiry(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_temp, authority) = provision_authority()?;
        let (operator, bond) = config();
        let store = authority.finding_status_store();
        let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
            store.clone(),
            operator.clone(),
            bond,
            operator_key(),
            1_000,
        )?;
        publisher.publish_non_inclusion(&sha256_hex(b"bonded-finding"), &[], NOW)?;

        let mut replacement_operator = operator;
        replacement_operator.authority.valid_from = NOW - 2_000;
        let mut expired_bond = config().1;
        expired_bond.valid_from = NOW - 1_000;
        expired_bond.valid_until = NOW - 200;
        let expired_publisher =
            super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
                store,
                replacement_operator,
                expired_bond,
                operator_key(),
                1_000,
            )?;
        let error = expired_publisher
            .publish_non_inclusion(&sha256_hex(b"another-bonded-finding"), &[], NOW + 1)
            .test_expect_err("expired service bond must not reuse a prior signed epoch");
        assert_eq!(error, "finding status publisher service bond is expired");
        Ok(())
    }

    #[tokio::test]
    async fn status_handlers_fail_closed_without_live_bond_or_authentication(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_temp, authority) = provision_authority()?;
        let now = unix_timestamp_now();
        let mut market = live_market_config(now);
        market.status_feed_service_bond.valid_until = now;
        let state = service_state(Arc::clone(&authority), market);
        let response =
            handle_get_finding_status_root(State(state), AxumPath(FEED_ID.to_string())).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let market = live_market_config(now);
        let state = service_state(authority, market);
        let signed = SignedExportEnvelope::sign(submission(), &operator_key())?;
        let raw = String::from_utf8(canonical_json_bytes(&signed)?)?;
        let response = handle_submit_finding_status_intent(
            State(state),
            AxumPath(FEED_ID.to_string()),
            HeaderMap::new(),
            raw,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn exact_status_intent_replay_recovers_after_deadline_but_new_stale_intent_rejects(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_temp, authority) = provision_authority()?;
        let now = unix_timestamp_now();
        let market = live_market_config(now);
        let seller = Keypair::from_seed(&[83; 32]);
        let issued_at = now.saturating_sub(
            market
                .status_feed_service_bond
                .inclusion_sla_secs
                .saturating_add(1),
        );
        let mut body = submission();
        body.issued_at = issued_at;
        body.inclusion_deadline = issued_at
            .checked_add(market.status_feed_service_bond.inclusion_sla_secs)
            .ok_or("test status deadline overflowed")?;
        body.source_receipt = SignedExportEnvelope::sign(
            FindingVoluntaryRetractionReceipt {
                schema: FINDING_VOLUNTARY_RETRACTION_RECEIPT_SCHEMA.to_string(),
                feed_id: body.feed_id.clone(),
                key_domain_nonce: body.key_domain_nonce,
                finding_id: body.finding_id.clone(),
                source_authority_id: seller.public_key().to_hex(),
                issued_at,
            },
            &seller,
        )?;
        body.source_authority_id = seller.public_key().to_hex();
        body.source_receipt_sha256 = chio_finding::signed_envelope_sha256(&body.source_receipt)?;
        body.intent_id = compute_intent_id(&body).test_expect("expired status intent id");
        let signed = SignedExportEnvelope::sign(body, &operator_key())?;
        let raw = String::from_utf8(canonical_json_bytes(&signed)?)?;
        let store = authority.finding_status_store();
        assert_eq!(
            store.issue_retraction_intent(&FindingRetractionIntentInput {
                intent_id: &signed.body.intent_id,
                feed_id: &signed.body.feed_id,
                operator_id: &signed.body.operator_id,
                finding_id: &signed.body.finding_id,
                source: FindingRetractionIntentSource::Voluntary,
                intent_bytes: raw.as_bytes(),
                issued_at: signed.body.issued_at,
                inclusion_deadline: signed.body.inclusion_deadline,
                created_at: issued_at,
            })?,
            FindingStatusWriteOutcome::Inserted
        );
        let live_state = service_state(Arc::clone(&authority), market.clone());
        let mut expired_market = market;
        expired_market.status_feed_operator.authority.valid_until = now;
        expired_market.status_feed_service_bond.valid_until = now;
        let expired_state = service_state(Arc::clone(&authority), expired_market);
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Bearer service-secret"),
        );

        let response = handle_submit_finding_status_intent(
            State(expired_state),
            AxumPath(FEED_ID.to_string()),
            headers.clone(),
            raw.clone(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let response_json: serde_json::Value = serde_json::from_slice(&response_body)?;
        assert_eq!(response_json["exact_replay"], true);
        assert_eq!(response_json["status"], "dispatch_eligible");

        let other_feed = "status-feed/other-venue";
        let mut other_market = live_market_config(now);
        other_market.status_feed_operator_ref = other_feed.to_string();
        other_market.status_feed_operator.feed_id = other_feed.to_string();
        other_market.status_feed_service_bond.feed_id = other_feed.to_string();
        let other_state = service_state(Arc::clone(&authority), other_market);
        let response = handle_submit_finding_status_intent(
            State(other_state),
            AxumPath(other_feed.to_string()),
            headers.clone(),
            raw,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut stale_new = signed.body;
        stale_new.finding_id = sha256_hex(b"another stale finding");
        stale_new.source_receipt.body.finding_id = stale_new.finding_id.clone();
        stale_new.source_receipt =
            SignedExportEnvelope::sign(stale_new.source_receipt.body, &seller)?;
        stale_new.source_receipt_sha256 =
            chio_finding::signed_envelope_sha256(&stale_new.source_receipt)?;
        stale_new.intent_id = compute_intent_id(&stale_new).test_expect("new stale intent id");
        let stale_new = SignedExportEnvelope::sign(stale_new, &operator_key())?;
        let stale_raw = String::from_utf8(canonical_json_bytes(&stale_new)?)?;
        let response = handle_submit_finding_status_intent(
            State(live_state),
            AxumPath(FEED_ID.to_string()),
            headers,
            stale_raw,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }
}
