//! HTTP surface for the cognition-market finding market: strict
//! canonical publish ingress, immutable by-id resolution, the bounded
//! paginated descriptor index, digest-addressed dependency retention,
//! governance-profile registration, collateral registration, the durable
//! idempotent activation transaction, participation-epoch renewal, and
//! admission serving.
//!
//! Ingress discipline (the reusable Finding-ingress invariant): the raw
//! request body is size-limited at the route layer, strict-canonicalized
//! from the raw text (rejecting duplicate keys and non-I-JSON numbers),
//! required byte-equal to its canonical serialization, schema-validated
//! as a parsed value from the same accepted input, typed-deserialized,
//! required to reserialize to the same strict bytes, domain-verified, and
//! only then persisted. Composite authenticated venue requests (activate,
//! participation) carry already-signed envelopes whose digests are
//! recomputed and cross-bound here; the raw-first invariant applies to
//! the standalone artifact surfaces (publish, recipes, profiles).

use chio_finding::{
    required_finding_facets, verify_signed_authority_status, verify_signed_bond_backing,
    verify_signed_profile, verify_signed_seller_authorization, verify_signed_verifier_report,
    Finding, FindingAuthorityKeyPolicy, FindingFacetKind, FindingFacetOutcome, FindingFeeEvent,
    FindingGuaranteeClass, FindingPayee, FindingReplayRecipeInput, SignedFindingAdmission,
    SignedFindingAuthorityStatus, SignedFindingBondBacking, SignedFindingChallengeVerifierProfile,
    SignedFindingMarketTerms, SignedFindingSellerAuthorization, SignedFindingVerifierReport,
    FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1,
};
use chio_open_market::fee_schedule::SignedOpenMarketFeeSchedule;
use chio_open_market::finding_admission::{
    verify_finding_admission_for_activation, FindingAdmissionContext, FindingAdmissionPenaltyGate,
    FindingAllocationSnapshot as AdmissionAllocationSnapshot, FindingAllocationStatus,
    FindingConstituentExpiryBounds, FindingFeeScheduleGate,
};
use chio_open_market::fiscal_adapter::signed_fee_schedule_digest;
use chio_open_market::listing::{
    ensure_generic_listing_signed_by_namespace_owner, normalize_namespace, GenericListingStatus,
    SignedGenericListing,
};
use chio_store_sqlite::finding_market_store::{
    finding_fee_idempotency_key, FindingActivationAttemptState,
    FindingActivationPreparationOutcome, FindingAdmissionSnapshot, FindingAllocationState,
    FindingFeeIntent, FindingFeeIntentOutcome, FindingRecordInput, SqliteFindingMarketStore,
};

use super::report_validation::validate_service_auth;
use super::*;

/// Publish body cap: strict canonical findings are small; anything larger
/// is hostile or malformed. Enforced at the route layer and re-checked
/// here so direct handler tests share the bound.
pub(crate) const FINDING_PUBLISH_MAX_BODY_BYTES: usize = 256 * 1024;
/// Dependency uploads (recipes, input bundles, profiles) may carry larger
/// canonical payloads; still bounded well below the service cap.
pub(crate) const FINDING_DEPENDENCY_MAX_BODY_BYTES: usize = 1024 * 1024;
/// A status reading older than this cannot establish current authority
/// standing at a finding-market trust boundary.
pub(crate) const FINDING_AUTHORITY_STATUS_MAX_AGE_SECS: u64 = 3_600;

const FINDING_SCHEMA_JSON: &str =
    include_str!("../../../../../spec/schemas/chio-finding/v1/finding.schema.json");
const RECIPE_SCHEMA_JSON: &str =
    include_str!("../../../../../spec/schemas/chio-finding/v1/replay-recipe-input.schema.json");
const PROFILE_SCHEMA_JSON: &str = include_str!(
    "../../../../../spec/schemas/chio-finding/v1/challenge-verifier-profile.schema.json"
);

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FindingProfileRegistrationRequest {
    profile: SignedFindingChallengeVerifierProfile,
    governance_authority_status: SignedFindingAuthorityStatus,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FindingCollateralRegistrationRequest {
    backing: SignedFindingBondBacking,
    collateral_authority_status: SignedFindingAuthorityStatus,
}

/// Deterministic instruction the venue-ledger rail settles. Its canonical
/// digest is the instruction commitment the admission's fee terminal
/// binds.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FindingRailInstruction {
    pub idempotency_key: String,
    /// Principal debited by the instruction. For a bond return this is
    /// the challenge-administration pool rather than the original buyer.
    pub payer: String,
    pub amount_units: u64,
    pub currency: String,
    /// Governed pool participating in the movement. It is the destination
    /// for a collection and the source for a return.
    pub pool_principal_id: String,
    /// Credited rail destination. A bond return names the durable lock
    /// owner here.
    pub rail_destination: String,
}

/// Rail acknowledgement bound to the exact instruction. Its canonical
/// digest is the observation commitment the admission binds; reconciling
/// a fee event requires it to match exactly.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FindingRailObservation {
    pub instruction_sha256: String,
    pub amount_units: u64,
    pub currency: String,
    pub rail_destination: String,
    pub rail: String,
}

struct PreparedFindingFeeCharge {
    idempotency_key: String,
    instruction: FindingRailInstruction,
    instruction_sha256: String,
}

/// The evidenced rail seam: the deterministic venue-ledger observer is
/// the rail implementation; tests inject failing observers to prove a
/// failed charge cannot admit. Implementations must treat the
/// instruction idempotency key as the replay key: retrying the same
/// instruction may recover its observation but must not move money twice.
pub trait FindingRailObserver: Send + Sync {
    fn dispatch(
        &self,
        instruction: &FindingRailInstruction,
    ) -> Result<FindingRailObservation, String>;
}

/// Deterministic venue-ledger rail: the venue's own evidenced ledger
/// acknowledges the exact instruction. Observation digests are therefore
/// computable when the venue signs the admission, before activation runs.
pub struct VenueLedgerRailObserver;

impl FindingRailObserver for VenueLedgerRailObserver {
    fn dispatch(
        &self,
        instruction: &FindingRailInstruction,
    ) -> Result<FindingRailObservation, String> {
        let digest = canonical_digest_of(instruction)?;
        Ok(FindingRailObservation {
            instruction_sha256: digest,
            amount_units: instruction.amount_units,
            currency: instruction.currency.clone(),
            rail_destination: instruction.rail_destination.clone(),
            rail: "venue-ledger".to_string(),
        })
    }
}

fn canonical_digest_of<T: serde::Serialize>(value: &T) -> Result<String, String> {
    let bytes = chio_core::canonical_json_bytes(value).map_err(|error| error.to_string())?;
    Ok(chio_core::sha256_hex(&bytes))
}

pub(super) fn finding_market_context(
    state: &TrustServiceState,
) -> Result<(FindingMarketConfig, SqliteFindingMarketStore), Response> {
    let Some(config) = state.config.finding_market.clone() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "finding market is not configured on this control plane",
        ));
    };
    let Some(store) = state
        .joint_authority_store
        .as_ref()
        .map(|authority| authority.finding_market_store())
    else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "finding market requires the joint authority store",
        ));
    };
    Ok((config, store))
}

/// The strict raw-first ingress pipeline for one registered artifact.
pub(super) fn strict_artifact_ingress<T: serde::de::DeserializeOwned + serde::Serialize>(
    raw: &str,
    max_bytes: usize,
    schema_json: &str,
    schema_label: &str,
) -> Result<(Vec<u8>, T), Response> {
    if raw.len() > max_bytes {
        return Err(plain_http_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "artifact exceeds the ingress size bound",
        ));
    }
    let strict_bytes = chio_core::canonical::canonical_json_bytes_from_str(raw).map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "artifact is not strict canonical I-JSON",
        )
    })?;
    // Canonical-only ingress: canonicalization normalizes rather than
    // rejects, so byte equality is the actual rejection of noncanonical
    // spellings.
    if strict_bytes.as_slice() != raw.as_bytes() {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "artifact bytes are not the canonical serialization",
        ));
    }
    let schema: serde_json::Value = serde_json::from_str(schema_json).map_err(|_| {
        plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, "embedded schema invalid")
    })?;
    let parsed: serde_json::Value = serde_json::from_str(raw)
        .map_err(|_| plain_http_error(StatusCode::BAD_REQUEST, "artifact is not a JSON object"))?;
    let schema_path = std::path::Path::new(schema_label);
    let doc_path = std::path::Path::new("request-body");
    if chio_spec_validate::validate_value(schema_path, &schema, doc_path, &parsed).is_err() {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "artifact rejected by the registered schema",
        ));
    }
    let typed: T = serde_json::from_str(raw).map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "artifact failed typed deserialization",
        )
    })?;
    let typed_bytes = chio_core::canonical_json_bytes(&typed).map_err(|_| {
        plain_http_error(StatusCode::BAD_REQUEST, "artifact failed canonicalization")
    })?;
    if typed_bytes != strict_bytes {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "typed canonical bytes drift from the accepted raw bytes",
        ));
    }
    Ok((strict_bytes, typed))
}

fn strict_profile_registration_ingress(
    raw: &str,
) -> Result<(Vec<u8>, FindingProfileRegistrationRequest), Response> {
    if raw.len() > FINDING_DEPENDENCY_MAX_BODY_BYTES {
        return Err(plain_http_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "profile registration exceeds the ingress size bound",
        ));
    }
    let strict_request_bytes =
        chio_core::canonical::canonical_json_bytes_from_str(raw).map_err(|_| {
            plain_http_error(
                StatusCode::BAD_REQUEST,
                "profile registration is not strict canonical I-JSON",
            )
        })?;
    if strict_request_bytes.as_slice() != raw.as_bytes() {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "profile registration bytes are not the canonical serialization",
        ));
    }
    let request: FindingProfileRegistrationRequest = serde_json::from_str(raw).map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "profile registration failed typed deserialization",
        )
    })?;
    let typed_bytes = chio_core::canonical_json_bytes(&request).map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "profile registration failed canonicalization",
        )
    })?;
    if typed_bytes != strict_request_bytes {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "typed profile registration drifts from the accepted bytes",
        ));
    }
    let profile_bytes = chio_core::canonical_json_bytes(&request.profile).map_err(|_| {
        plain_http_error(StatusCode::BAD_REQUEST, "profile failed canonicalization")
    })?;
    let profile_raw = std::str::from_utf8(&profile_bytes).map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "profile canonical bytes are not UTF-8",
        )
    })?;
    let (profile_bytes, _) = strict_artifact_ingress::<SignedFindingChallengeVerifierProfile>(
        profile_raw,
        FINDING_DEPENDENCY_MAX_BODY_BYTES,
        PROFILE_SCHEMA_JSON,
        "chio-finding/v1/challenge-verifier-profile.schema.json",
    )?;
    Ok((profile_bytes, request))
}

fn verify_profile_registration_authority(
    request: &FindingProfileRegistrationRequest,
    config: &FindingMarketConfig,
    now: u64,
) -> Result<(), String> {
    if !config.governance_root.covers(now) {
        return Err("profile governance authority is not live at registration".to_owned());
    }
    let governance_key = config
        .governance_root
        .key()
        .map_err(|error| error.to_string())?;
    verify_signed_profile(&request.profile, &governance_key).map_err(|error| error.to_string())?;
    if !config
        .governance_root
        .covers(request.profile.body.issued_at)
    {
        return Err("profile was issued outside the governance key validity window".to_owned());
    }
    if now < request.profile.body.issued_at || now >= request.profile.body.expires_at {
        return Err("verifier profile is not live at registration".to_owned());
    }

    let status_key = config
        .authority_status
        .key()
        .map_err(|error| error.to_string())?;
    verify_signed_authority_status(&request.governance_authority_status, &status_key)
        .map_err(|error| error.to_string())?;
    let status = &request.governance_authority_status.body;
    if !config.authority_status.covers(status.observed_at) || !config.authority_status.covers(now) {
        return Err("authority-status signer is not live at profile registration".to_owned());
    }
    if status.status_ref != config.governance_root.revocation_status_ref
        || status.authority_id != config.governance_root.authority_id
        || status.key != governance_key
        || status.key_epoch != config.governance_root.key_epoch
    {
        return Err("governance authority status does not bind the deployment pin".to_owned());
    }
    if status.observed_at < request.profile.body.issued_at {
        return Err("governance authority status predates profile issuance".to_owned());
    }
    if status.observed_at > now
        || now.saturating_sub(status.observed_at) > FINDING_AUTHORITY_STATUS_MAX_AGE_SECS
    {
        return Err("governance authority status is not a fresh current reading".to_owned());
    }
    if status.revoked_from.is_some() {
        return Err("profile governance authority is revoked at registration".to_owned());
    }
    Ok(())
}

/// Re-load the exact recipe committed by a deterministic-replay Finding
/// and require every opaque dependency that the v1 recipe says must be
/// venue-retained. The profile has its own signed registration path;
/// this closure covers both phase input bundles, the canonical parameter
/// bundle, and the cycle-free pre-run template. These blobs cannot vanish
/// after this check because the store rejects recipe-blob deletion.
fn verify_retained_recipe_closure(
    store: &SqliteFindingMarketStore,
    recipe_sha256: &str,
) -> Result<(), Response> {
    let recipe_bytes = match store.get_recipe_blob(recipe_sha256) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return Err(plain_http_error(
                StatusCode::BAD_REQUEST,
                "replay recipe preimage is not retained; upload it before publishing",
            ))
        }
        Err(error) => {
            return Err(plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &error.to_string(),
            ))
        }
    };
    let raw = std::str::from_utf8(&recipe_bytes).map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "retained replay recipe is not UTF-8",
        )
    })?;
    let (_, recipe) = strict_artifact_ingress::<FindingReplayRecipeInput>(
        raw,
        FINDING_DEPENDENCY_MAX_BODY_BYTES,
        RECIPE_SCHEMA_JSON,
        "chio-finding/v1/replay-recipe-input.schema.json",
    )?;
    recipe
        .validate()
        .map_err(|error| plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()))?;

    let mut dependencies = Vec::with_capacity(recipe.phases.len() + 4);
    dependencies.push((
        "runner manifest".to_string(),
        recipe.runner_manifest_sha256.as_str(),
    ));
    for (index, phase) in recipe.phases.iter().enumerate() {
        dependencies.push((
            format!("phase input bundle {index}"),
            phase.input_bundle_sha256.as_str(),
        ));
    }
    dependencies.push((
        "parameter bundle".to_string(),
        recipe.parameters_sha256.as_str(),
    ));
    dependencies.push((
        "runtime image".to_string(),
        recipe.environment.runtime_image_sha256.as_str(),
    ));
    dependencies.push((
        "pre-run template".to_string(),
        recipe.pre_run_template_sha256.as_str(),
    ));
    for (kind, digest) in dependencies {
        match store.get_recipe_blob(digest) {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(plain_http_error(
                    StatusCode::BAD_REQUEST,
                    &format!("replay recipe {kind} is not retained: {digest}"),
                ))
            }
            Err(error) => {
                return Err(plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &error.to_string(),
                ))
            }
        }
    }
    Ok(())
}

/// POST /v1/findings/publish (authenticated): the strict canonical
/// Finding ingress. Publication indexes the finding; admission is the
/// separate activation transaction.
pub(crate) async fn handle_publish_finding(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    raw: String,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (_, store) = match finding_market_context(&state) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let (strict_bytes, finding) = match strict_artifact_ingress::<Finding>(
        &raw,
        FINDING_PUBLISH_MAX_BODY_BYTES,
        FINDING_SCHEMA_JSON,
        "chio-finding/v1/finding.schema.json",
    ) {
        Ok(accepted) => accepted,
        Err(response) => return response,
    };
    if let Err(error) = chio_finding::verify_finding(&finding) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    // Both bounds enforce liveness: a correctly signed
    // but future-issued or expired finding must not become indexable.
    let now = unix_timestamp_now();
    if finding.issued_at > now {
        return plain_http_error(StatusCode::BAD_REQUEST, "finding is future-issued");
    }
    if finding.expires_at <= now {
        return plain_http_error(StatusCode::BAD_REQUEST, "finding has expired");
    }
    // The finding-scoped pricing hint signs `finding:<finding_id>`;
    // hashing the hint into the finding would be a cycle, so this
    // projection requires the reference absent.
    if finding.price_hint_ref.is_some() {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "price_hint_ref must be absent for the finding-scoped projection",
        );
    }
    // A deterministic-replay claim publishes only with its recipe
    // preimage already retained; seller availability cannot control
    // later adjudication.
    if finding.guarantee_class == FindingGuaranteeClass::DeterministicReplay {
        let Some(recipe_sha256) = finding.replay_recipe_sha256.as_deref() else {
            return plain_http_error(StatusCode::BAD_REQUEST, "replay recipe digest missing");
        };
        if let Err(response) = verify_retained_recipe_closure(&store, recipe_sha256) {
            return response;
        }
    }
    let artifact_json = match std::str::from_utf8(&strict_bytes) {
        Ok(text) => text,
        Err(_) => {
            return plain_http_error(StatusCode::BAD_REQUEST, "artifact is not UTF-8");
        }
    };
    let record = FindingRecordInput {
        finding_id: &finding.finding_id,
        artifact_json,
        topic: &finding.descriptor.topic,
        context_sha256: &finding.descriptor.context_sha256,
        issued_at: finding.issued_at,
        expires_at: finding.expires_at,
    };
    match store.put_finding(&record, now) {
        Ok(_) => Json(serde_json::json!({
            "findingId": finding.finding_id,
            "artifactSha256": chio_core::sha256_hex(&strict_bytes),
        }))
        .into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

/// GET /v1/findings/{finding_id} (public): immutable content-addressed
/// resolution serving the EXACT accepted bytes verbatim.
pub(crate) async fn handle_get_finding(
    State(state): State<TrustServiceState>,
    AxumPath(finding_id): AxumPath<String>,
) -> Response {
    let (_, store) = match finding_market_context(&state) {
        Ok(context) => context,
        Err(response) => return response,
    };
    match store.get_finding_bytes(&finding_id) {
        Ok(Some(bytes)) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            bytes,
        )
            .into_response(),
        Ok(None) => plain_http_error(StatusCode::NOT_FOUND, "unknown finding"),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

/// Search query DTO shared by the GET and POST variants.
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FindingSearchQuery {
    #[serde(default)]
    pub topic_prefix: Option<String>,
    #[serde(default)]
    pub context_sha256: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingSearchAdmissionView {
    admission_id: String,
    envelope_sha256: String,
    expires_at: u64,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingSearchRowView {
    finding_id: String,
    artifact_sha256: String,
    topic: String,
    context_sha256: String,
    issued_at: u64,
    expires_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    admission: Option<FindingSearchAdmissionView>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingSearchResponse {
    results: Vec<FindingSearchRowView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
    count: usize,
}

/// A stored admission is CURRENT only while its envelope is unexpired,
/// its allocation remains consumed by the active admission, and
/// participation fees are paid through the present audit epoch (computed
/// from the retained terms envelope the admission binds by digest).
/// Presence of this block in a search row IS the qualified
/// cognition-market profile marker.
fn current_admission_view(
    store: &SqliteFindingMarketStore,
    finding_id: &str,
    now: u64,
) -> Option<FindingSearchAdmissionView> {
    let snapshot = store.get_current_admission(finding_id).ok().flatten()?;
    let admission: SignedFindingAdmission = serde_json::from_str(&snapshot.envelope_json).ok()?;
    let current_epoch = live_admission_epoch(store, &snapshot, &admission, now)?;
    let paid_through = store
        .paid_through_epoch(
            finding_id,
            &snapshot.listing_id,
            &admission.body.fee_schedule_envelope_sha256,
        )
        .ok()
        .flatten()?;
    if paid_through < current_epoch {
        return None;
    }
    Some(FindingSearchAdmissionView {
        admission_id: snapshot.admission_id,
        envelope_sha256: snapshot.envelope_sha256,
        expires_at: snapshot.expires_at,
    })
}

/// Return the current payable audit epoch only while the stored admission
/// still owns its backing and remains inside its signed lifetime. Payment
/// status is intentionally checked by the caller: discovery requires the
/// epoch already paid, while renewal requires the next unpaid epoch to be due.
fn live_admission_epoch(
    store: &SqliteFindingMarketStore,
    snapshot: &FindingAdmissionSnapshot,
    admission: &SignedFindingAdmission,
    now: u64,
) -> Option<u64> {
    if now >= snapshot.expires_at {
        return None;
    }
    // Activation dedicates the allocation in the same transaction that
    // indexes the admission, so the healthy state for an ACTIVE admission
    // is `Consumed` (encumbered by exactly this admission). `Expired` and
    // `Released` mean the backing is gone; `Live` with an active
    // admission cannot happen through the store transaction.
    if snapshot.allocation_state != FindingAllocationState::Consumed {
        return None;
    }
    let terms_bytes = store
        .get_recipe_blob(&admission.body.terms_envelope_sha256)
        .ok()
        .flatten()?;
    let terms: SignedFindingMarketTerms = serde_json::from_slice(&terms_bytes).ok()?;
    let epoch_length = terms.body.audit_epoch_length_secs.max(1);
    Some(now.saturating_sub(snapshot.activated_at) / epoch_length)
}

fn run_finding_search(state: &TrustServiceState, query: &FindingSearchQuery) -> Response {
    let (_, store) = match finding_market_context(state) {
        Ok(context) => context,
        Err(response) => return response,
    };
    if query.topic_prefix.is_none() && query.context_sha256.is_none() {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "search requires a topic prefix or a context digest",
        );
    }
    let limit = query
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);
    let now = unix_timestamp_now();
    let rows = match store.search_findings(
        query.topic_prefix.as_deref(),
        query.context_sha256.as_deref(),
        query.cursor.as_deref(),
        limit,
        now,
    ) {
        Ok(rows) => rows,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let next_cursor = if rows.len() == limit {
        rows.last().map(|row| row.finding_id.clone())
    } else {
        None
    };
    let results: Vec<FindingSearchRowView> = rows
        .into_iter()
        .map(|row| {
            let admission = current_admission_view(&store, &row.finding_id, now);
            FindingSearchRowView {
                finding_id: row.finding_id,
                artifact_sha256: row.artifact_sha256,
                topic: row.topic,
                context_sha256: row.context_sha256,
                issued_at: row.issued_at,
                expires_at: row.expires_at,
                admission,
            }
        })
        .collect();
    let count = results.len();
    Json(FindingSearchResponse {
        results,
        next_cursor,
        count,
    })
    .into_response()
}

/// GET /v1/findings/search (public).
pub(crate) async fn handle_search_findings_get(
    State(state): State<TrustServiceState>,
    Query(query): Query<FindingSearchQuery>,
) -> Response {
    run_finding_search(&state, &query)
}

/// POST /v1/findings/search (public).
pub(crate) async fn handle_search_findings_post(
    State(state): State<TrustServiceState>,
    Json(query): Json<FindingSearchQuery>,
) -> Response {
    run_finding_search(&state, &query)
}

/// POST /v1/findings/recipes (authenticated): digest-addressed retention
/// for replay recipes and their dependencies. A body that is a
/// `chio.finding.replay-recipe-input.v1` artifact passes the full strict
/// pipeline; any other body is an opaque digest-addressed dependency
/// (input bundles, parameter bundles) retained by its byte digest.
pub(crate) async fn handle_upload_finding_dependency(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (_, store) = match finding_market_context(&state) {
        Ok(context) => context,
        Err(response) => return response,
    };
    if body.len() > FINDING_DEPENDENCY_MAX_BODY_BYTES {
        return plain_http_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "dependency exceeds the ingress size bound",
        );
    }
    let is_recipe = std::str::from_utf8(&body).ok().and_then(|text| {
        serde_json::from_str::<serde_json::Value>(text)
            .ok()
            .map(|value| {
                value.get("schema").and_then(serde_json::Value::as_str)
                    == Some(FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1)
            })
    });
    if is_recipe == Some(true) {
        let raw = match std::str::from_utf8(&body) {
            Ok(text) => text,
            Err(_) => {
                return plain_http_error(StatusCode::BAD_REQUEST, "recipe is not UTF-8");
            }
        };
        let (strict_bytes, recipe) = match strict_artifact_ingress::<FindingReplayRecipeInput>(
            raw,
            FINDING_DEPENDENCY_MAX_BODY_BYTES,
            RECIPE_SCHEMA_JSON,
            "chio-finding/v1/replay-recipe-input.schema.json",
        ) {
            Ok(accepted) => accepted,
            Err(response) => return response,
        };
        if let Err(error) = recipe.validate() {
            return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
        }
        let digest = chio_core::sha256_hex(&strict_bytes);
        return match store.put_recipe_blob(&digest, &strict_bytes, unix_timestamp_now()) {
            Ok(_) => Json(serde_json::json!({ "canonicalSha256": digest })).into_response(),
            Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
        };
    }
    let digest = chio_core::sha256_hex(&body);
    match store.put_recipe_blob(&digest, &body, unix_timestamp_now()) {
        Ok(_) => Json(serde_json::json!({ "canonicalSha256": digest })).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

/// POST /v1/findings/profiles (authenticated): register a
/// governance-signed reusable verifier profile. The envelope must verify
/// under the pinned governance root; the exact envelope bytes are then
/// retained digest-addressed so terms and recipes can bind them.
pub(crate) async fn handle_register_finding_profile(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    raw: String,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (config, store) = match finding_market_context(&state) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let (profile_bytes, request) = match strict_profile_registration_ingress(&raw) {
        Ok(accepted) => accepted,
        Err(response) => return response,
    };
    let now = unix_timestamp_now();
    if let Err(error) = verify_profile_registration_authority(&request, &config, now) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    if let Err(error) =
        chio_finding_verifier::validate_supported_finding_verifier_profile(&request.profile.body)
    {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    let digest = chio_core::sha256_hex(&profile_bytes);
    match store.put_recipe_blob(&digest, &profile_bytes, now) {
        Ok(_) => Json(serde_json::json!({
            "profileId": request.profile.body.profile_id,
            "envelopeSha256": digest,
        }))
        .into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

/// POST /v1/findings/collateral (authenticated): register a live
/// exclusive collateral allocation from a bond-backing envelope signed by
/// the pinned collateral authority.
pub(crate) async fn handle_register_finding_collateral(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<FindingCollateralRegistrationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (config, store) = match finding_market_context(&state) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let backing = &request.backing;
    let now = unix_timestamp_now();
    if !config.collateral.covers(backing.body.issued_at) || !config.collateral.covers(now) {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "finding collateral authority is not live at registration",
        );
    }
    let collateral_key = match config.collateral.key() {
        Ok(key) => key,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    if let Err(error) = verify_signed_bond_backing(backing, &collateral_key) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    let status_key = match config.authority_status.key() {
        Ok(key) => key,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    if let Err(error) =
        verify_signed_authority_status(&request.collateral_authority_status, &status_key)
    {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    let status = &request.collateral_authority_status.body;
    if !config.authority_status.covers(status.observed_at) || !config.authority_status.covers(now) {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "authority-status signer is not live at collateral registration",
        );
    }
    if status.status_ref != config.collateral.revocation_status_ref
        || status.authority_id != config.collateral.authority_id
        || status.key != collateral_key
        || status.key_epoch != config.collateral.key_epoch
    {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "collateral authority status does not bind the deployment pin",
        );
    }
    if status.observed_at < backing.body.issued_at {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "collateral authority status predates backing issuance",
        );
    }
    if status.observed_at > now
        || now.saturating_sub(status.observed_at) > FINDING_AUTHORITY_STATUS_MAX_AGE_SECS
    {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "collateral authority status is not a fresh current reading",
        );
    }
    if status.revoked_from.is_some() {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "collateral authority is revoked at registration",
        );
    }
    // The allocation backs a finding this venue actually serves.
    match store.get_finding_bytes(&backing.body.finding_id) {
        Ok(Some(_)) => {}
        Ok(None) => return plain_http_error(StatusCode::BAD_REQUEST, "unknown finding"),
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
    let envelope_json = match chio_core::canonical_json_bytes(&backing)
        .map_err(|_| ())
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| ()))
    {
        Ok(json) => json,
        Err(()) => {
            return plain_http_error(StatusCode::BAD_REQUEST, "backing failed canonicalization")
        }
    };
    match store.register_allocation(&envelope_json, &backing.body, now) {
        Ok(()) => Json(serde_json::json!({
            "allocationId": backing.body.allocation_id,
        }))
        .into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

/// Composite activation request: every envelope the admission binds by
/// digest travels with it so the venue verifies exact bindings before the
/// durable transaction runs.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FindingActivateRequest {
    pub admission: SignedFindingAdmission,
    pub venue_authority_status: SignedFindingAuthorityStatus,
    pub seller_authorization: SignedFindingSellerAuthorization,
    pub terms: SignedFindingMarketTerms,
    pub backing: SignedFindingBondBacking,
    pub fee_schedule: SignedOpenMarketFeeSchedule,
    pub verifier_report: SignedFindingVerifierReport,
    pub verifier_authority_status: SignedFindingAuthorityStatus,
    pub listing: SignedGenericListing,
    pub pricing_hint: chio_open_market::listing::SignedListingPricingHint,
}

pub(crate) fn verify_venue_authority_lifecycle(
    admission: &SignedFindingAdmission,
    authority_status: &SignedFindingAuthorityStatus,
    config: &FindingMarketConfig,
    now: u64,
) -> Result<(), String> {
    let venue_key = config.venue.key().map_err(|error| error.to_string())?;
    let status_key = config
        .authority_status
        .key()
        .map_err(|error| error.to_string())?;
    verify_signed_authority_status(authority_status, &status_key)
        .map_err(|error| error.to_string())?;
    let status = &authority_status.body;
    if !config.authority_status.covers(status.observed_at) || !config.authority_status.covers(now) {
        return Err("authority-status signer is not live at activation".into());
    }
    if status.status_ref != config.venue.revocation_status_ref
        || status.authority_id != config.venue.authority_id
        || status.key != venue_key
        || status.key_epoch != config.venue.key_epoch
    {
        return Err("venue authority status does not bind the deployment pin".into());
    }
    if status.observed_at < admission.body.issued_at {
        return Err("venue authority status predates the admission".into());
    }
    if status.observed_at > now
        || now.saturating_sub(status.observed_at) > FINDING_AUTHORITY_STATUS_MAX_AGE_SECS
    {
        return Err("venue authority status is not a fresh current reading".into());
    }
    if status.revoked_from.is_some() {
        return Err("venue authority is revoked at activation".into());
    }
    Ok(())
}

pub(crate) fn verify_profile_for_activation(
    profile: &SignedFindingChallengeVerifierProfile,
    expected_envelope_sha256: &str,
    config: &FindingMarketConfig,
    now: u64,
) -> Result<(), String> {
    profile.body.validate().map_err(|error| error.to_string())?;
    chio_finding_verifier::validate_supported_finding_verifier_profile(&profile.body)
        .map_err(|error| error.to_string())?;
    let digest = canonical_digest_of(profile)?;
    if digest != expected_envelope_sha256 {
        return Err("retained profile digest does not match the admission".to_string());
    }
    let governance_key = config
        .governance_root
        .key()
        .map_err(|error| error.to_string())?;
    verify_signed_profile(profile, &governance_key).map_err(|error| error.to_string())?;
    if !config.governance_root.covers(profile.body.issued_at) {
        return Err("profile was issued outside the governance key validity window".to_string());
    }
    if now < profile.body.issued_at || now >= profile.body.expires_at {
        return Err("verifier profile is not live at activation".to_string());
    }
    Ok(())
}

fn verify_authority_policy_matches_deployment(
    label: &str,
    policy: &FindingAuthorityKeyPolicy,
    pin: &FindingAuthorityPin,
) -> Result<(), String> {
    let key = pin.key().map_err(|error| error.to_string())?;
    if policy.authority_id != pin.authority_id
        || policy.key != key
        || policy.key_epoch != pin.key_epoch
        || policy.valid_from != pin.valid_from
        || policy.valid_until != pin.valid_until
        || policy.revocation_status_ref != pin.revocation_status_ref
    {
        return Err(format!(
            "profile {label} authority does not match the deployment pin"
        ));
    }
    Ok(())
}

pub(crate) fn verify_profile_settlement_authorities(
    profile: &SignedFindingChallengeVerifierProfile,
    admission: &SignedFindingAdmission,
    config: &FindingMarketConfig,
) -> Result<(), String> {
    for (label, profile_policy, admission_policy, deployment_pin) in [
        (
            "purchase",
            &profile.body.purchase_authority,
            &admission.body.purchase_authority,
            &config.purchase,
        ),
        (
            "failed-delivery",
            &profile.body.failed_delivery_authority,
            &admission.body.failed_delivery_authority,
            &config.failed_delivery,
        ),
    ] {
        if profile_policy != admission_policy {
            return Err(format!(
                "profile {label} authority does not match the admission policy"
            ));
        }
        verify_authority_policy_matches_deployment(label, profile_policy, deployment_pin)?;
    }
    Ok(())
}

pub(crate) fn verify_report_authority_lifecycle(
    report: &SignedFindingVerifierReport,
    authority_status: &SignedFindingAuthorityStatus,
    profile: &SignedFindingChallengeVerifierProfile,
    finding: &Finding,
    config: &FindingMarketConfig,
    now: u64,
) -> Result<(), String> {
    let instant = report.body.evaluation_time;
    let verifier_key = config
        .verifier_report
        .key()
        .map_err(|error| error.to_string())?;
    verify_signed_verifier_report(report, &verifier_key).map_err(|error| error.to_string())?;
    if !config.verifier_report.covers(instant) {
        return Err("verifier report evaluation is outside the pinned key validity window".into());
    }
    if !config.verifier_report.covers(now) {
        return Err("verifier report authority is not live at activation".into());
    }
    if instant < profile.body.issued_at || instant >= profile.body.expires_at {
        return Err("verifier report evaluation is outside the profile lifecycle".into());
    }
    if instant < finding.issued_at || instant >= finding.expires_at {
        return Err("verifier report evaluation is outside the Finding lifecycle".into());
    }
    if report.body.verifier_key_epoch != config.verifier_report.key_epoch {
        return Err("verifier report key epoch does not match the deployment pin".into());
    }
    let policy = &profile.body.verifier_report_signer;
    if policy.authority_id != config.verifier_report.authority_id
        || policy.key != verifier_key
        || policy.key_epoch != config.verifier_report.key_epoch
        || policy.revocation_status_ref != config.verifier_report.revocation_status_ref
    {
        return Err("profile verifier-report authority does not match the deployment pin".into());
    }
    if instant < policy.valid_from || instant >= policy.valid_until {
        return Err("verifier report evaluation is outside the profile signer policy".into());
    }
    if now < policy.valid_from || now >= policy.valid_until {
        return Err("profile verifier-report authority is not live at activation".into());
    }

    let status_key = config
        .authority_status
        .key()
        .map_err(|error| error.to_string())?;
    verify_signed_authority_status(authority_status, &status_key)
        .map_err(|error| error.to_string())?;
    let status = &authority_status.body;
    if !config.authority_status.covers(status.observed_at) || !config.authority_status.covers(now) {
        return Err("authority-status signer is not live at activation".into());
    }
    if status.status_ref != config.verifier_report.revocation_status_ref
        || status.authority_id != config.verifier_report.authority_id
        || status.key != verifier_key
        || status.key_epoch != config.verifier_report.key_epoch
    {
        return Err("verifier authority status does not bind the deployment pin".into());
    }
    if status.observed_at < instant {
        return Err("verifier authority status predates the report evaluation".into());
    }
    if status.observed_at > now
        || now.saturating_sub(status.observed_at) > FINDING_AUTHORITY_STATUS_MAX_AGE_SECS
    {
        return Err("verifier authority status is not a fresh current reading".into());
    }
    if status.revoked_from.is_some() {
        return Err("verifier report authority is revoked at activation".into());
    }
    Ok(())
}

/// POST /v1/findings/{finding_id}/activate (authenticated): the durable
/// idempotent activation transaction. A durable prepare first claims the
/// allocation for the exact admission. Fee collection then runs on the
/// evidenced rail, and finalization atomically asserts the reconciled
/// terminals and indexes the admission. A crash after settlement resumes
/// from the prepare record without charging again.
pub(crate) async fn handle_activate_finding(
    State(state): State<TrustServiceState>,
    AxumPath(finding_id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<FindingActivateRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (config, store) = match finding_market_context(&state) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let admission = &request.admission.body;
    if admission.finding_id != finding_id {
        return plain_http_error(StatusCode::BAD_REQUEST, "admission names another finding");
    }
    let now = unix_timestamp_now();
    if !config.venue.covers(admission.issued_at) || !config.venue.covers(now) {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "finding venue authority is not live for admission activation",
        );
    }
    if let Err(error) = verify_venue_authority_lifecycle(
        &request.admission,
        &request.venue_authority_status,
        &config,
        now,
    ) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error);
    }
    let admission_json = match chio_core::canonical_json_bytes(&request.admission)
        .map_err(|_| ())
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| ()))
    {
        Ok(json) => json,
        Err(()) => {
            return plain_http_error(StatusCode::BAD_REQUEST, "admission failed canonicalization")
        }
    };

    // A prepared retry owns the consumed allocation named by these exact
    // bytes. An activated retry is already complete, including when a
    // later admission superseded it.
    let activation_attempt_state = match store.get_activation_attempt(&admission.admission_id) {
        Ok(Some(attempt)) => {
            if attempt.envelope_json != admission_json {
                return plain_http_error(
                    StatusCode::BAD_REQUEST,
                    "admission id is already bound to different activation bytes",
                );
            }
            Some(attempt.state)
        }
        Ok(None) => None,
        Err(error) => {
            return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
        }
    };
    let prepared_replay = activation_attempt_state == Some(FindingActivationAttemptState::Prepared);
    let mut completed_replay =
        activation_attempt_state == Some(FindingActivationAttemptState::Activated);

    // Exact-replay short circuit: a retry of an already committed
    // activation must return the stored outcome instead of re-verifying
    // against the post-commit allocation state. Byte equality on the
    // canonical envelope is the replay test. Listing pin, signature, and
    // status checks still run below before the success is returned.
    match store.get_current_admission(&finding_id) {
        Ok(Some(snapshot)) if snapshot.admission_id == admission.admission_id => {
            if admission_json != snapshot.envelope_json {
                return plain_http_error(
                    StatusCode::BAD_REQUEST,
                    "admission id is already bound to different bytes",
                );
            }
            completed_replay = true;
        }
        Ok(_) => {}
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }

    let purchase_store = match state.joint_authority_store.as_ref() {
        Some(authority) => authority.finding_purchase_store(),
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "finding market requires the joint authority store",
            )
        }
    };
    match purchase_store.sales_blocked(&admission.listing_id) {
        Ok(true) => {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "listing admission is blocked by an enforced penalty",
            )
        }
        Ok(false) => {}
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }

    // The published finding is the root of every binding.
    let artifact_json = match store.get_finding_bytes(&finding_id) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return plain_http_error(StatusCode::NOT_FOUND, "unknown finding"),
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let finding: Finding = match serde_json::from_str(&artifact_json) {
        Ok(finding) => finding,
        Err(_) => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "stored finding failed deserialization",
            )
        }
    };
    if finding.guarantee_class == FindingGuaranteeClass::DeterministicReplay {
        let Some(recipe_sha256) = finding.replay_recipe_sha256.as_deref() else {
            return plain_http_error(StatusCode::BAD_REQUEST, "replay recipe digest missing");
        };
        if let Err(response) = verify_retained_recipe_closure(&store, recipe_sha256) {
            return response;
        }
    }
    let artifact_sha256 = chio_core::sha256_hex(artifact_json.as_bytes());
    if admission.finding_artifact_sha256 != artifact_sha256 {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "admission binds a different finding artifact",
        );
    }

    // Listing and pricing-hint exact bindings: a mismatched hint or
    // metadata binding is rejected.
    let listing_digest = match canonical_digest_of(&request.listing) {
        Ok(digest) => digest,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error),
    };
    if listing_digest != admission.listing_envelope_sha256 {
        return plain_http_error(StatusCode::BAD_REQUEST, "listing envelope digest mismatch");
    }
    if let Err(error) =
        ensure_generic_listing_signed_by_namespace_owner(&request.listing, "finding listing")
    {
        return plain_http_error(StatusCode::BAD_REQUEST, &error);
    }
    let listing_authority = match config.listing.key() {
        Ok(key) => key,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    if request.listing.signer_key != listing_authority
        || request.listing.body.namespace_ownership.owner_id != config.listing.authority_id
    {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "finding listing signer does not match the configured listing authority",
        );
    }
    if request.listing.body.published_at > now {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "finding listing was published after the activation clock",
        );
    }
    if !config.listing.covers(request.listing.body.published_at) {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "finding listing was published outside the configured listing authority window",
        );
    }
    if !config.listing.covers(now) {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "finding listing authority is not live at activation",
        );
    }
    if request.listing.body.status != GenericListingStatus::Active {
        return plain_http_error(StatusCode::BAD_REQUEST, "finding listing is not active");
    }
    if completed_replay {
        if let Err(error) = purchase_store.register_community_fund_destination(
            &admission.backing_allocation_id,
            &admission.community_fund_destination,
            now,
        ) {
            return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
        }
        return Json(serde_json::json!({
            "admissionId": admission.admission_id,
            "outcome": "ExactReplay",
        }))
        .into_response();
    }
    let hint_digest = match canonical_digest_of(&request.pricing_hint) {
        Ok(digest) => digest,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error),
    };
    if hint_digest != admission.pricing_hint_envelope_sha256 {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "pricing hint envelope digest mismatch",
        );
    }
    if let Err(error) = request.pricing_hint.body.validate() {
        return plain_http_error(StatusCode::BAD_REQUEST, &error);
    }
    if !matches!(request.pricing_hint.verify_signature(), Ok(true)) {
        return plain_http_error(StatusCode::BAD_REQUEST, "pricing hint signature is invalid");
    }
    if !request.pricing_hint.body.is_live_at(now) {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "pricing hint is not live at activation",
        );
    }
    if request.pricing_hint.signer_key != listing_authority
        || request.pricing_hint.body.listing_id != request.listing.body.listing_id
        || normalize_namespace(&request.pricing_hint.body.namespace)
            != normalize_namespace(&request.listing.body.namespace)
        || request.pricing_hint.body.provider_operator_id != admission.publisher_operator_id
        || request.pricing_hint.body.provider_operator_id
            != request.listing.body.namespace_ownership.owner_id
        || request.listing.body.subject.actor_id != admission.server_id
    {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "pricing hint identity does not match the admitted listing",
        );
    }
    if request.pricing_hint.body.capability_scope != admission.capability_scope {
        return plain_http_error(StatusCode::BAD_REQUEST, "pricing hint scope mismatch");
    }
    if request.pricing_hint.body.expires_at < admission.expires_at {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "admission outlives the pricing hint",
        );
    }
    let listing_metadata_url = request
        .listing
        .body
        .subject
        .metadata_url
        .as_deref()
        .unwrap_or_default();
    if listing_metadata_url != admission.metadata_url {
        return plain_http_error(StatusCode::BAD_REQUEST, "listing metadata url mismatch");
    }
    if request.listing.body.listing_id != admission.listing_id {
        return plain_http_error(StatusCode::BAD_REQUEST, "listing id mismatch");
    }

    // Seller authorization: the issuer-signed grant that lets this
    // seller list this exact finding. Required even when issuer and
    // seller are the same key.
    let authorization_digest = match canonical_digest_of(&request.seller_authorization) {
        Ok(digest) => digest,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error),
    };
    if authorization_digest != admission.seller_authorization_envelope_sha256 {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "seller authorization envelope digest mismatch",
        );
    }
    if let Err(error) = verify_signed_seller_authorization(&request.seller_authorization) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    let authorization = &request.seller_authorization.body;
    if authorization.issuer != finding.issuer {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "seller authorization issuer is not the finding issuer",
        );
    }
    if authorization.seller != request.terms.body.seller {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "seller authorization names a different seller than the terms",
        );
    }
    if authorization.finding_id != finding_id
        || authorization.finding_artifact_sha256 != artifact_sha256
    {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "seller authorization binds a different finding",
        );
    }
    if authorization.listing_id != admission.listing_id {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "seller authorization names a different listing",
        );
    }
    if authorization.issued_at > now || authorization.expires_at <= now {
        return plain_http_error(StatusCode::BAD_REQUEST, "seller authorization is not live");
    }
    if let FindingPayee::Beneficiary { destination, .. } = &authorization.payee {
        if destination != &admission.payee_destination {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "seller authorization payee does not match the admission",
            );
        }
    }

    // Collateral snapshot for the named allocation.
    let allocation = match store.get_allocation(&admission.backing_allocation_id) {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => {
            return plain_http_error(StatusCode::BAD_REQUEST, "unknown collateral allocation")
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };

    // The retained profile remains an authority-bearing dependency at
    // activation. Digest-addressed storage proves only byte identity, so
    // re-run its body validation, governance signature, and liveness
    // checks before any profile field influences admission.
    let profile_bytes = match store.get_recipe_blob(&admission.profile_envelope_sha256) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "verifier profile is not registered with this venue",
            )
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let profile: SignedFindingChallengeVerifierProfile =
        match serde_json::from_slice(&profile_bytes) {
            Ok(profile) => profile,
            Err(_) => {
                return plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "retained profile failed deserialization",
                )
            }
        };
    if let Err(error) =
        verify_profile_for_activation(&profile, &admission.profile_envelope_sha256, &config, now)
    {
        return plain_http_error(StatusCode::BAD_REQUEST, &error);
    }
    if let Err(error) = verify_profile_settlement_authorities(&profile, &request.admission, &config)
    {
        return plain_http_error(StatusCode::BAD_REQUEST, &error);
    }

    // Pinned keys.
    let (venue_key, collateral_key) = match (config.venue.key(), config.collateral.key()) {
        (Ok(venue), Ok(collateral)) => (venue, collateral),
        _ => return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, "pinned keys invalid"),
    };

    // The full admission verification: venue pin, liveness, terms and
    // backing bindings, fiscal gate, sizing inequality, expiry bound.
    let trusted_signers = match config.fee_schedule_operators() {
        Ok(signers) => signers,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    let gate = match state.fiscal_runtime.as_ref() {
        Some(_) => {
            // Fiscal-governed venues verify schedules through the
            // resolver-driven surface; no resolver is wired into finding
            // activation yet, so fiscal-governed venues are rejected here.
            return plain_http_error(
                StatusCode::CONFLICT,
                "fiscal-governed finding activation is unavailable: no fee-schedule resolver is wired for this venue",
            );
        }
        None => FindingFeeScheduleGate::Legacy,
    };
    if let Err(error) = verify_report_authority_lifecycle(
        &request.verifier_report,
        &request.verifier_authority_status,
        &profile,
        &finding,
        &config,
        now,
    ) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error);
    }
    // The report's affirmative bond claim, if any, feeds the admission
    // seam's report-before-backing ordering check.
    let report = &request.verifier_report.body;
    let bond_backing_observed_at = (report.facet_outcome(FindingFacetKind::BondBacking)
        == Some(FindingFacetOutcome::Verified))
    .then_some(report.evaluation_time);
    let admission_context = FindingAdmissionContext {
        venue_authority: &venue_key,
        venue_id: &config.venue_id,
        now,
        fee_schedule: &request.fee_schedule,
        fee_schedule_gate: gate,
        trusted_local_operator_signers: &trusted_signers,
        terms: &request.terms,
        backing: &request.backing,
        allocation_snapshot: AdmissionAllocationSnapshot {
            allocation_id: allocation.backing.allocation_id.clone(),
            backing_envelope_sha256: allocation.backing_envelope_sha256.clone(),
            expires_at: allocation.backing.expires_at,
            status: match allocation.state {
                FindingAllocationState::Live => FindingAllocationStatus::Available,
                FindingAllocationState::Consumed => FindingAllocationStatus::Consumed,
                FindingAllocationState::Expired => FindingAllocationStatus::Expired,
                FindingAllocationState::Released => FindingAllocationStatus::Released,
            },
            active_admission_id: allocation.active_admission_id.clone(),
            prepared_admission_id: prepared_replay.then(|| admission.admission_id.clone()),
            accepted_at: allocation.accepted_at,
        },
        bond_backing_observed_at,
        // The HTTP surface gates on the durable sales block above. It
        // never accepts a caller-supplied penalty evaluation.
        penalty_gate: FindingAdmissionPenaltyGate::Ungoverned,
        collateral_authority: &collateral_key,
        constituent_expiry_bounds: FindingConstituentExpiryBounds {
            finding: finding.expires_at,
            listing: request.listing.body.expires_at.unwrap_or(u64::MAX),
            pricing_hint: request.pricing_hint.body.expires_at,
            seller_authorization: authorization.expires_at,
            profile: profile.body.expires_at,
        },
    };
    if let Err(error) =
        verify_finding_admission_for_activation(&request.admission, &admission_context)
    {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }

    // The verifier signer and its current authenticated status were checked
    // above before the report influenced admission sizing. Continue with its
    // exact bindings and required-facet policy against the retained profile.
    let report = &request.verifier_report.body;
    let report_digest = match canonical_digest_of(&request.verifier_report) {
        Ok(digest) => digest,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error),
    };
    if report_digest != admission.verifier_report_envelope_sha256
        || report.report_id != admission.verifier_report_id
    {
        return plain_http_error(StatusCode::BAD_REQUEST, "verifier report binding mismatch");
    }
    if report.finding_id != finding_id || report.finding_artifact_sha256 != artifact_sha256 {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "verifier report binds a different finding",
        );
    }
    if report.verifier_profile_envelope_sha256 != admission.profile_envelope_sha256 {
        return plain_http_error(StatusCode::BAD_REQUEST, "verifier profile binding mismatch");
    }
    if report.verifier_profile_id != profile.body.profile_id {
        return plain_http_error(StatusCode::BAD_REQUEST, "verifier profile id mismatch");
    }
    if report.facet_outcome(FindingFacetKind::BondBacking) == Some(FindingFacetOutcome::Verified) {
        if report.backing_allocation_id.as_deref() != Some(admission.backing_allocation_id.as_str())
        {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "report bond verdict names another allocation",
            );
        }
        // Mechanical report-before-backing: the allocation must have been
        // accepted before the report's evaluation time.
        if allocation.accepted_at >= report.evaluation_time {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "report claims bond backing before the allocation existed",
            );
        }
    }
    if report
        .facets
        .iter()
        .any(|facet| facet.outcome == FindingFacetOutcome::Failed)
    {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "verifier report contains a failed facet; admission denied",
        );
    }
    for facet in required_finding_facets(&finding, &profile.body) {
        if report.facet_outcome(facet) != Some(FindingFacetOutcome::Verified) {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "a required facet is not verified; admission denied",
            );
        }
    }

    // Terms binding for later epoch computation: retain the exact terms
    // envelope digest-addressed, since the admission binds it.
    let terms_json = match chio_core::canonical_json_bytes(&request.terms) {
        Ok(bytes) => bytes,
        Err(_) => {
            return plain_http_error(StatusCode::BAD_REQUEST, "terms failed canonicalization")
        }
    };
    let terms_digest = chio_core::sha256_hex(&terms_json);
    if store
        .put_recipe_blob(&terms_digest, &terms_json, now)
        .is_err()
    {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, "terms retention failed");
    }

    // Validate every fee terminal and install every idempotency fence
    // before the allocation is prepared. No rail dispatch occurs until
    // all local fee inputs are known to be internally consistent.
    let Some(rail) = state.finding_rail.as_ref() else {
        return plain_http_error(
            StatusCode::CONFLICT,
            "no evidenced rail observer is configured",
        );
    };
    let schedule_digest = match signed_fee_schedule_digest(&request.fee_schedule) {
        Ok(digest) => digest,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let mut charges = Vec::with_capacity(admission.fee_terminals.len());
    for terminal in &admission.fee_terminals {
        if terminal.fee_schedule_envelope_sha256 != schedule_digest {
            return plain_http_error(StatusCode::BAD_REQUEST, "fee terminal schedule mismatch");
        }
        // Both fee event kinds restrict to the governance-pinned audit pool.
        if terminal.pool_principal_id != config.audit_pool.principal_id
            || terminal.rail_destination != config.audit_pool.rail_destination
            || terminal.amount.currency != config.audit_pool.currency
        {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "fee terminal does not name the pinned audit pool",
            );
        }
        let expected_amount = match &terminal.event {
            FindingFeeEvent::Publication => &request.fee_schedule.body.publication_fee,
            FindingFeeEvent::ParticipationEpoch { .. } => {
                &request.fee_schedule.body.market_participation_fee
            }
        };
        if terminal.amount != *expected_amount {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "fee terminal amount does not match the schedule",
            );
        }
        let idempotency_key = finding_fee_idempotency_key(
            &schedule_digest,
            &terminal.event,
            &finding_id,
            &admission.listing_id,
        );
        let instruction = FindingRailInstruction {
            idempotency_key: idempotency_key.clone(),
            payer: terminal.payer.clone(),
            amount_units: terminal.amount.units,
            currency: terminal.amount.currency.clone(),
            pool_principal_id: terminal.pool_principal_id.clone(),
            rail_destination: terminal.rail_destination.clone(),
        };
        let instruction_sha256 = match canonical_digest_of(&instruction) {
            Ok(digest) => digest,
            Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error),
        };
        if instruction_sha256 != terminal.instruction_sha256 {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "fee terminal instruction commitment mismatch",
            );
        }
        charges.push(PreparedFindingFeeCharge {
            idempotency_key,
            instruction,
            instruction_sha256,
        });
    }
    let mut fee_outcomes = Vec::with_capacity(charges.len());
    for (terminal, charge) in admission.fee_terminals.iter().zip(&charges) {
        let intent = FindingFeeIntent {
            fee_schedule_envelope_sha256: &schedule_digest,
            event: &terminal.event,
            finding_id: &finding_id,
            listing_id: &admission.listing_id,
            payer: &terminal.payer,
            amount: &terminal.amount,
            pool_principal_id: &terminal.pool_principal_id,
            rail_destination: &terminal.rail_destination,
            instruction_sha256: &charge.instruction_sha256,
        };
        match store.begin_fee_intent(&intent) {
            Ok(fenced) => fee_outcomes.push(fenced.outcome),
            Err(error) => {
                return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
            }
        }
    }

    // Claim the allocation and retain the exact admission before money
    // can move. A crash from here onward leaves a replayable prepare
    // record, so a reconciled charge cannot lose its activation owner to
    // a concurrent allocation consumer.
    match store.prepare_listing_activation(&admission_json, admission, now) {
        Ok(FindingActivationPreparationOutcome::Prepared)
        | Ok(FindingActivationPreparationOutcome::PendingReplay) => {}
        Ok(FindingActivationPreparationOutcome::AlreadyActivated) => {
            return Json(serde_json::json!({
                "admissionId": admission.admission_id,
                "outcome": "ExactReplay",
            }))
            .into_response();
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }

    // Dispatch and reconcile each unsettled terminal. Reconciled intents
    // from an earlier attempt are never dispatched twice.
    for ((terminal, charge), outcome) in admission
        .fee_terminals
        .iter()
        .zip(&charges)
        .zip(fee_outcomes)
    {
        if outcome == FindingFeeIntentOutcome::AlreadyReconciled {
            continue;
        }
        let observation = match rail.dispatch(&charge.instruction) {
            Ok(observation) => observation,
            Err(reason) => {
                // The intent and prepare record stay durable. No admission
                // becomes active, and an identical retry can resume.
                let _ = store.mark_fee_failed(&charge.idempotency_key);
                return plain_http_error(
                    StatusCode::BAD_GATEWAY,
                    &format!("rail dispatch failed: {reason}"),
                );
            }
        };
        if !super::finding_challenge_coordinator::rail_observation_matches(
            &charge.instruction,
            &charge.instruction_sha256,
            &observation,
        ) {
            let _ = store.mark_fee_failed(&charge.idempotency_key);
            return plain_http_error(
                StatusCode::BAD_GATEWAY,
                "rail observation does not reconcile to the dispatched instruction",
            );
        }
        let observation_sha256 = match canonical_digest_of(&observation) {
            Ok(digest) => digest,
            Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error),
        };
        if observation_sha256 != terminal.observation_sha256 {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "fee terminal observation commitment mismatch",
            );
        }
        if let Err(error) = store.mark_fee_reconciled(
            &charge.idempotency_key,
            &observation_sha256,
            &terminal.amount,
            &terminal.rail_destination,
        ) {
            return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
        }
    }

    // Finalization atomically checks every reconciled terminal, inserts
    // the active admission, supersedes the prior active row, and marks
    // the durable prepare complete.
    match store.activate_listing(&admission_json, admission, now) {
        Ok(outcome) => {
            if let Err(error) = purchase_store.register_community_fund_destination(
                &admission.backing_allocation_id,
                &admission.community_fund_destination,
                now,
            ) {
                return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
            }
            Json(serde_json::json!({
                "admissionId": admission.admission_id,
                "outcome": format!("{outcome:?}"),
            }))
            .into_response()
        }
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

/// Participation renewal request: the exact signed fee schedule the
/// admission bound at activation.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FindingParticipationRequest {
    pub fee_schedule: SignedOpenMarketFeeSchedule,
}

/// POST /v1/findings/{finding_id}/participation (authenticated): collect
/// the next unpaid audit epoch. Later unpaid epochs make the
/// listing non-admitted at read time; this is the renewal path.
pub(crate) async fn handle_finding_participation(
    State(state): State<TrustServiceState>,
    AxumPath(finding_id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<FindingParticipationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (config, store) = match finding_market_context(&state) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let snapshot = match store.get_current_admission(&finding_id) {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => return plain_http_error(StatusCode::NOT_FOUND, "no active admission"),
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let admission: SignedFindingAdmission = match serde_json::from_str(&snapshot.envelope_json) {
        Ok(admission) => admission,
        Err(_) => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "stored admission failed deserialization",
            )
        }
    };
    let now = unix_timestamp_now();
    let current_epoch = match live_admission_epoch(&store, &snapshot, &admission, now) {
        Some(epoch) => epoch,
        None => {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "admission is not live for participation renewal",
            )
        }
    };
    let schedule_digest = match signed_fee_schedule_digest(&request.fee_schedule) {
        Ok(digest) => digest,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if schedule_digest != admission.body.fee_schedule_envelope_sha256 {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "fee schedule does not match the admitted binding",
        );
    }
    let paid_through = match store.paid_through_epoch(
        &finding_id,
        &snapshot.listing_id,
        &admission.body.fee_schedule_envelope_sha256,
    ) {
        Ok(Some(epoch)) => epoch,
        Ok(None) => {
            return plain_http_error(StatusCode::BAD_REQUEST, "no reconciled participation epoch")
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let next_epoch = match paid_through.checked_add(1) {
        Some(epoch) => epoch,
        None => return plain_http_error(StatusCode::BAD_REQUEST, "epoch index overflow"),
    };
    if next_epoch > current_epoch {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "participation is already paid through the current audit epoch",
        );
    }
    let Some(rail) = state.finding_rail.as_ref() else {
        return plain_http_error(
            StatusCode::CONFLICT,
            "no evidenced rail observer is configured",
        );
    };
    let event = FindingFeeEvent::ParticipationEpoch {
        epoch_index: next_epoch,
    };
    let amount = request.fee_schedule.body.market_participation_fee.clone();
    if amount.currency != config.audit_pool.currency {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "participation fee currency does not match the audit pool",
        );
    }
    let idempotency_key =
        finding_fee_idempotency_key(&schedule_digest, &event, &finding_id, &snapshot.listing_id);
    let instruction = FindingRailInstruction {
        idempotency_key: idempotency_key.clone(),
        payer: admission.body.publisher_operator_id.clone(),
        amount_units: amount.units,
        currency: amount.currency.clone(),
        pool_principal_id: config.audit_pool.principal_id.clone(),
        rail_destination: config.audit_pool.rail_destination.clone(),
    };
    let instruction_sha256 = match canonical_digest_of(&instruction) {
        Ok(digest) => digest,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error),
    };
    let intent = FindingFeeIntent {
        fee_schedule_envelope_sha256: &schedule_digest,
        event: &event,
        finding_id: &finding_id,
        listing_id: &snapshot.listing_id,
        payer: &admission.body.publisher_operator_id,
        amount: &amount,
        pool_principal_id: &config.audit_pool.principal_id,
        rail_destination: &config.audit_pool.rail_destination,
        instruction_sha256: &instruction_sha256,
    };
    match store.begin_fee_intent(&intent) {
        Ok(fenced) if fenced.outcome == FindingFeeIntentOutcome::AlreadyReconciled => {
            return Json(serde_json::json!({
                "findingId": finding_id,
                "paidThroughEpoch": next_epoch,
            }))
            .into_response();
        }
        Ok(_) => {}
        Err(error) => {
            return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
        }
    }
    let observation = match rail.dispatch(&instruction) {
        Ok(observation) => observation,
        Err(reason) => {
            let _ = store.mark_fee_failed(&idempotency_key);
            return plain_http_error(
                StatusCode::BAD_GATEWAY,
                &format!("rail dispatch failed: {reason}"),
            );
        }
    };
    if !super::finding_challenge_coordinator::rail_observation_matches(
        &instruction,
        &instruction_sha256,
        &observation,
    ) {
        let _ = store.mark_fee_failed(&idempotency_key);
        return plain_http_error(
            StatusCode::BAD_GATEWAY,
            "rail observation does not reconcile to the dispatched instruction",
        );
    }
    let observation_sha256 = match canonical_digest_of(&observation) {
        Ok(digest) => digest,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error),
    };
    match store.mark_fee_reconciled(
        &idempotency_key,
        &observation_sha256,
        &amount,
        &config.audit_pool.rail_destination,
    ) {
        Ok(()) => Json(serde_json::json!({
            "findingId": finding_id,
            "paidThroughEpoch": next_epoch,
        }))
        .into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

/// GET /v1/findings/{finding_id}/admission (public): serve the CURRENT
/// venue-signed admission envelope verbatim, or 404 when none is
/// current.
pub(crate) async fn handle_get_finding_admission(
    State(state): State<TrustServiceState>,
    AxumPath(finding_id): AxumPath<String>,
) -> Response {
    let (_, store) = match finding_market_context(&state) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let now = unix_timestamp_now();
    if current_admission_view(&store, &finding_id, now).is_none() {
        return plain_http_error(StatusCode::NOT_FOUND, "no current admission");
    }
    match store.get_current_admission(&finding_id) {
        Ok(Some(snapshot)) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            snapshot.envelope_json,
        )
            .into_response(),
        Ok(None) => plain_http_error(StatusCode::NOT_FOUND, "no current admission"),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}
