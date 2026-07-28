//! HTTP surface for the cognition-market finding market (M2): strict
//! canonical publish ingress, immutable by-id resolution, the bounded
//! paginated descriptor index, digest-addressed dependency retention,
//! governance-profile registration, collateral registration, the durable
//! idempotent activation transaction, participation-epoch renewal, and
//! admission serving. Compiled only under `cognition-market-experimental`.
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
    verify_pinned_envelope, verify_signed_bond_backing, verify_signed_verifier_report, Finding,
    FindingChallengeVerifierProfile, FindingEvidenceClass, FindingFacetKind, FindingFacetOutcome,
    FindingFeeEvent, FindingGuaranteeClass, FindingReplayRecipeInput, SignedFindingAdmission,
    SignedFindingBondBacking, SignedFindingChallengeVerifierProfile, SignedFindingMarketTerms,
    SignedFindingVerifierReport, FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1,
};
use chio_open_market::fee_schedule::SignedOpenMarketFeeSchedule;
use chio_open_market::finding_admission::{
    verify_finding_admission, FindingAdmissionContext,
    FindingAllocationSnapshot as AdmissionAllocationSnapshot, FindingFeeScheduleGate,
};
use chio_open_market::fiscal_adapter::signed_fee_schedule_digest;
use chio_open_market::listing::SignedGenericListing;
use chio_store_sqlite::finding_market_store::{
    finding_fee_idempotency_key, FindingAllocationState, FindingFeeIntent, FindingRecordInput,
    SqliteFindingMarketStore,
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

const FINDING_SCHEMA_JSON: &str =
    include_str!("../../../../../spec/schemas/chio-finding/v1/finding.schema.json");
const RECIPE_SCHEMA_JSON: &str =
    include_str!("../../../../../spec/schemas/chio-finding/v1/replay-recipe-input.schema.json");
const PROFILE_SCHEMA_JSON: &str = include_str!(
    "../../../../../spec/schemas/chio-finding/v1/challenge-verifier-profile.schema.json"
);

/// Deterministic instruction the venue-ledger rail settles. Its canonical
/// digest is the instruction commitment the admission's fee terminal
/// binds.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct FindingRailInstruction {
    pub idempotency_key: String,
    pub payer: String,
    pub amount_units: u64,
    pub currency: String,
    pub pool_principal_id: String,
    pub rail_destination: String,
}

/// Rail acknowledgement bound to the exact instruction. Its canonical
/// digest is the observation commitment the admission binds; reconciling
/// a fee event requires it to match exactly.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct FindingRailObservation {
    pub instruction_sha256: String,
    pub amount_units: u64,
    pub currency: String,
    pub rail_destination: String,
    pub rail: String,
}

/// The evidenced rail seam (plan D9). The wedge ships the deterministic
/// venue-ledger observer; tests inject failing observers to prove a
/// failed charge cannot admit.
pub(crate) trait FindingRailObserver: Send + Sync {
    fn dispatch(
        &self,
        instruction: &FindingRailInstruction,
    ) -> Result<FindingRailObservation, String>;
}

/// Deterministic venue-ledger rail: the venue's own evidenced ledger
/// acknowledges the exact instruction. Observation digests are therefore
/// computable when the venue signs the admission, before activation runs.
pub(crate) struct VenueLedgerRailObserver;

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

fn finding_market_context(
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
fn strict_artifact_ingress<T: serde::de::DeserializeOwned + serde::Serialize>(
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
    // Liveness is a surface obligation, both bounds: a correctly signed
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
    // projection requires the reference absent (plan invariant 4).
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
        match store.get_recipe_blob(recipe_sha256) {
            Ok(Some(_)) => {}
            Ok(None) => {
                return plain_http_error(
                    StatusCode::BAD_REQUEST,
                    "replay recipe preimage is not retained; upload it before publishing",
                )
            }
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            }
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

/// Search query DTO shared by the GET and POST variants (plan D1/D2).
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
/// its allocation is live, and participation fees are paid through the
/// present audit epoch (computed from the retained terms envelope the
/// admission binds by digest). Presence of this block in a search row IS
/// the qualified cognition-market profile marker.
fn current_admission_view(
    store: &SqliteFindingMarketStore,
    finding_id: &str,
    now: u64,
) -> Option<FindingSearchAdmissionView> {
    let snapshot = store.get_current_admission(finding_id).ok().flatten()?;
    if now >= snapshot.expires_at {
        return None;
    }
    if snapshot.allocation_state != FindingAllocationState::Live {
        return None;
    }
    let admission: SignedFindingAdmission = serde_json::from_str(&snapshot.envelope_json).ok()?;
    let terms_bytes = store
        .get_recipe_blob(&admission.body.terms_envelope_sha256)
        .ok()
        .flatten()?;
    let terms: SignedFindingMarketTerms = serde_json::from_slice(&terms_bytes).ok()?;
    let epoch_length = terms.body.audit_epoch_length_secs.max(1);
    let current_epoch = now.saturating_sub(snapshot.activated_at) / epoch_length;
    let paid_through = store
        .paid_through_epoch(finding_id, &snapshot.listing_id)
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
/// for replay recipes and their dependencies (plan D4). A body that is a
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
    let (strict_bytes, profile) =
        match strict_artifact_ingress::<SignedFindingChallengeVerifierProfile>(
            &raw,
            FINDING_DEPENDENCY_MAX_BODY_BYTES,
            PROFILE_SCHEMA_JSON,
            "chio-finding/v1/challenge-verifier-profile.schema.json",
        ) {
            Ok(accepted) => accepted,
            Err(response) => return response,
        };
    let governance_key = match config.governance_root.key() {
        Ok(key) => key,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    if let Err(error) = profile.body.validate() {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    if let Err(error) = verify_pinned_envelope(&profile, &governance_key, "profile") {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    let digest = chio_core::sha256_hex(&strict_bytes);
    match store.put_recipe_blob(&digest, &strict_bytes, unix_timestamp_now()) {
        Ok(_) => Json(serde_json::json!({
            "profileId": profile.body.profile_id,
            "envelopeSha256": digest,
        }))
        .into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

/// POST /v1/findings/collateral (authenticated): register a live
/// exclusive collateral allocation from a bond-backing envelope signed by
/// the pinned collateral authority (plan D10).
pub(crate) async fn handle_register_finding_collateral(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(backing): Json<SignedFindingBondBacking>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (config, store) = match finding_market_context(&state) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let collateral_key = match config.collateral.key() {
        Ok(key) => key,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    if let Err(error) = verify_signed_bond_backing(&backing, &collateral_key) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
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
    match store.register_allocation(&envelope_json, &backing.body, unix_timestamp_now()) {
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
    pub terms: SignedFindingMarketTerms,
    pub backing: SignedFindingBondBacking,
    pub fee_schedule: SignedOpenMarketFeeSchedule,
    pub verifier_report: SignedFindingVerifierReport,
    pub listing: SignedGenericListing,
    pub pricing_hint: chio_open_market::listing::SignedListingPricingHint,
}

/// The facets a finding REQUIRES exactly `verified` before admission: the
/// profile's floor plus every claim the artifact itself makes. Mirrors
/// the verifier-side derivation; nothing here waives a profile-listed
/// facet.
fn required_facets(
    finding: &Finding,
    profile: &FindingChallengeVerifierProfile,
) -> Vec<FindingFacetKind> {
    let mut required: std::collections::BTreeSet<FindingFacetKind> =
        profile.required_facets.iter().copied().collect();
    required.insert(FindingFacetKind::ArtifactIntegrity);
    if finding.guarantee_class == FindingGuaranteeClass::DeterministicReplay {
        required.insert(FindingFacetKind::RecipeBinding);
    }
    if finding.evidence_class == FindingEvidenceClass::Verified {
        required.insert(FindingFacetKind::ReceiptAuthenticity);
        required.insert(FindingFacetKind::CheckpointMembership);
    }
    if finding.runtime_assurance_tier.is_some() {
        required.insert(FindingFacetKind::RuntimeAssuranceBacking);
    }
    required.into_iter().collect()
}

/// POST /v1/findings/{finding_id}/activate (authenticated): the durable
/// idempotent activation transaction (plan Task 4). Fee collection runs
/// on the evidenced rail first; the store transaction then atomically
/// asserts the reconciled terminals, consumes the allocation, and indexes
/// the admission. A failed charge cannot publish for free and crash or
/// retry replays idempotently.
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
    let artifact_sha256 = chio_core::sha256_hex(artifact_json.as_bytes());
    if admission.finding_artifact_sha256 != artifact_sha256 {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "admission binds a different finding artifact",
        );
    }

    // Listing and pricing-hint exact bindings (wrong hint or metadata
    // binding is an M2 exit rejection).
    let listing_digest = match canonical_digest_of(&request.listing) {
        Ok(digest) => digest,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error),
    };
    if listing_digest != admission.listing_envelope_sha256 {
        return plain_http_error(StatusCode::BAD_REQUEST, "listing envelope digest mismatch");
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

    // Collateral snapshot for the named allocation.
    let allocation = match store.get_allocation(&admission.backing_allocation_id) {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => {
            return plain_http_error(StatusCode::BAD_REQUEST, "unknown collateral allocation")
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };

    // Pinned keys.
    let (venue_key, collateral_key, verifier_key) = match (
        config.venue.key(),
        config.collateral.key(),
        config.verifier_report.key(),
    ) {
        (Ok(venue), Ok(collateral), Ok(verifier)) => (venue, collateral, verifier),
        _ => return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, "pinned keys invalid"),
    };

    // The full admission verification: venue pin, liveness, terms and
    // backing bindings, fiscal gate, sizing inequality, expiry bound.
    let earliest_constituent_expiry = finding.expires_at.min(request.pricing_hint.body.expires_at);
    let trusted_signers = [request.fee_schedule.signer_key.clone()];
    let gate = match state.fiscal_runtime.as_ref() {
        Some(_) => {
            // Fiscal-governed venues verify schedules through the
            // resolver-driven surface; the wedge exposes the legacy gate
            // and the governed path lands with its consuming deployment.
            return plain_http_error(
                StatusCode::CONFLICT,
                "fiscal-governed finding activation is not wired in the M2 wedge",
            );
        }
        None => FindingFeeScheduleGate::Legacy,
    };
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
            live: allocation.state == FindingAllocationState::Live,
            accepted_at: allocation.accepted_at,
        },
        collateral_authority: &collateral_key,
        earliest_constituent_expiry,
    };
    if let Err(error) = verify_finding_admission(&request.admission, &admission_context) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }

    // Verifier report: pinned signer, exact bindings, report-before-
    // backing (plan D14), and the required-facet policy against the
    // retained profile.
    if let Err(error) = verify_signed_verifier_report(&request.verifier_report, &verifier_key) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
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
    for facet in required_facets(&finding, &profile.body) {
        if report.facet_outcome(facet) != Some(FindingFacetOutcome::Verified) {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "a required facet is not verified; admission denied",
            );
        }
    }

    // Terms binding for later epoch computation: retain the exact terms
    // envelope digest-addressed (the admission binds it, D8).
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

    // Fee collection on the evidenced rail, one terminal at a time:
    // intent (durable idempotency fence) -> rail dispatch -> exact
    // reconciliation. The admission's bound digests must equal the
    // locally computed instruction/observation commitments.
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
    for terminal in &admission.fee_terminals {
        if terminal.fee_schedule_envelope_sha256 != schedule_digest {
            return plain_http_error(StatusCode::BAD_REQUEST, "fee terminal schedule mismatch");
        }
        // Both M2 events restrict to the governance-pinned audit pool.
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
        let intent = FindingFeeIntent {
            fee_schedule_envelope_sha256: &schedule_digest,
            event: &terminal.event,
            finding_id: &finding_id,
            listing_id: &admission.listing_id,
            payer: &terminal.payer,
            amount: &terminal.amount,
            pool_principal_id: &terminal.pool_principal_id,
            rail_destination: &terminal.rail_destination,
            instruction_sha256: &instruction_sha256,
        };
        if let Err(error) = store.begin_fee_intent(&intent) {
            return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
        }
        let observation = match rail.dispatch(&instruction) {
            Ok(observation) => observation,
            Err(reason) => {
                // The intent stays durable and unreconciled; activation
                // below cannot complete, so a failed charge cannot admit.
                let _ = store.mark_fee_failed(&idempotency_key);
                return plain_http_error(
                    StatusCode::BAD_GATEWAY,
                    &format!("rail dispatch failed: {reason}"),
                );
            }
        };
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
            &idempotency_key,
            &observation_sha256,
            &terminal.amount,
            &terminal.rail_destination,
        ) {
            return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
        }
    }

    // The atomic activation: reconciled terminals asserted, allocation
    // consumed, admission indexed, prior admission superseded; any
    // failure rolls the whole transaction back.
    let admission_json = match chio_core::canonical_json_bytes(&request.admission)
        .map_err(|_| ())
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| ()))
    {
        Ok(json) => json,
        Err(()) => {
            return plain_http_error(StatusCode::BAD_REQUEST, "admission failed canonicalization")
        }
    };
    match store.activate_listing(&admission_json, admission, now) {
        Ok(outcome) => Json(serde_json::json!({
            "admissionId": admission.admission_id,
            "outcome": format!("{outcome:?}"),
        }))
        .into_response(),
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
/// the next unpaid audit epoch (plan D8). Later unpaid epochs make the
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
    let paid_through = match store.paid_through_epoch(&finding_id, &snapshot.listing_id) {
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
    if let Err(error) = store.begin_fee_intent(&intent) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
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
/// venue-signed admission envelope verbatim, or 404 when none is current
/// (plan D5).
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
