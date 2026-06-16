use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::http::StatusCode;
use chio_core_types::{PublicKey, Signature};
use sha2::{Digest, Sha256};

mod crypto_context;
mod receipt_coverage;
mod server;

pub use crypto_context::crypto_context_rejection_report_bytes;
use crypto_context::crypto_context_verified_report_bytes;
pub use server::{
    build_proof_room_fixture_catalog_json, build_proof_room_fixture_catalog_json_with_fixture_root,
    is_proof_room_bundle_namespace, parse_listen_addr, proof_room_content_type,
    proof_room_fixture_asset_response, proof_room_router, proof_room_router_with_fixture_root,
    proof_room_router_with_optional_ui_root, proof_room_served_bundle_paths,
    resolve_proof_room_served_asset_path, serve_proof_room, ProofRoomServeConfig,
};

const PROOF_ROOM_BUNDLE_SCHEMA: &str = "chio.proof-room.bundle.v1";
const PROOF_ROOM_VERIFIER_REPORT_SCHEMA: &str = "chio.proof-room.verifier-report.v1";
const PROOF_ROOM_DOCKER_QUICKSTART_EVIDENCE_SCHEMA: &str =
    "chio.proof.docker-quickstart-evidence.v1";
const PROOF_ROOM_RELEASE_TRUTH_SCHEMA: &str = "chio.proof.release-truth.v1";
const PROOF_ROOM_FIRST_RUN_CAPABILITY_PROOF_SCHEMA: &str =
    "chio.proof.first-run.capability-proof.v1";
const PROOF_ROOM_FIRST_RUN_GUARD_REPORT_SCHEMA: &str = "chio.proof.first-run.guard-report.v1";
const PROOF_ROOM_FIRST_RUN_TRUST_ROOTS_SCHEMA: &str = "chio.proof.first-run.trust-roots.v1";
const PROOF_ROOM_FIRST_RUN_COMMAND_LOG_SCHEMA: &str = "chio.proof.first-run.command-log.v1";
const PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA: &str = "chio.proof-room.receipt-evidence.v1";
const TRANSACTION_REQUEST_DIGEST_SCHEMA: &str = "chio.request.digest.v1";
const TRANSACTION_RESPONSE_DIGEST_SCHEMA: &str = "chio.response.digest.v1";
const RUNTIME_TERMINAL_RECEIPT_SCHEMA: &str = "chio.runtime.terminal-receipt.v1";
const PROOF_ROOM_SIGNATURE_KIND: &str = "detached-dsse";
const PROOF_ROOM_DSSE_PAYLOAD_TYPE: &str = "application/vnd.chio.proof-room.bundle.v1+json";
const PROOF_ROOM_BUNDLE_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-proof-room/v1/bundle.schema.json"
));
const PROOF_ROOM_VERIFIER_REPORT_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-proof-room/v1/verifier-report.schema.json"
));
const PROOF_ROOM_DOCKER_QUICKSTART_EVIDENCE_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-proof-room/v1/docker-quickstart-evidence.schema.json"
));
const PROOF_ROOM_RELEASE_TRUTH_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-proof-room/v1/release-truth.schema.json"
));
const PROOF_ROOM_FIRST_RUN_CAPABILITY_PROOF_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-proof-room/v1/first-run-capability-proof.schema.json"
));
const PROOF_ROOM_FIRST_RUN_GUARD_REPORT_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-proof-room/v1/first-run-guard-report.schema.json"
));
const PROOF_ROOM_FIRST_RUN_TRUST_ROOTS_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-proof-room/v1/first-run-trust-roots.schema.json"
));
const PROOF_ROOM_FIRST_RUN_COMMAND_LOG_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-proof-room/v1/first-run-command-log.schema.json"
));
const PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-proof-room/v1/receipt-evidence.schema.json"
));
const TRANSACTION_REQUEST_DIGEST_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-transaction/v1/request-digest.schema.json"
));
const TRANSACTION_RESPONSE_DIGEST_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-transaction/v1/response-digest.schema.json"
));
const RUNTIME_TERMINAL_RECEIPT_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-runtime/v1/terminal-receipt.schema.json"
));
const PROOF_FIXTURE_CATALOG_SCHEMA: &str = "chio.proof-room.fixture-root-catalog.v1";
const PROOF_FIXTURE_CATALOG_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../fixtures/proof-room/catalog.json"
));
const CLAIM_TRANSACTION_PASSPORT_ROOT_VERIFIED: &str = "claim.transaction.passport_root_verified";
const CLAIM_PROOF_ROOM_VERIFIER_REPORT_BOUND: &str = "claim.proof_room.verifier_report_bound";
const CLAIM_PROOF_ROOM_ALLOW_AND_DENY_VISIBLE: &str = "claim.proof_room.allow_and_deny_visible";
const CLAIM_PROOF_ROOM_RECEIPT_COVERAGE_MATRIX_BOUND: &str =
    "claim.proof_room.receipt_coverage_matrix_bound";
const CLAIM_PROOF_ROOM_AUTHORITY_EVIDENCE_BOUND: &str = "claim.proof_room.authority_evidence_bound";
const CLAIM_RISK_COMPTROLLER_REPORT_BOUND: &str = "claim.risk.comptroller_report_bound";
const CLAIM_PREFIX_RUNTIME: &str = "claim.runtime.";
const CLAIM_PREFIX_RISK: &str = "claim.risk.";
const CLAIM_PREFIX_ENTERPRISE: &str = "claim.enterprise.";
const CLAIM_PREFIX_AGENT_WEB: &str = "claim.agent_web.";
const CLAIM_PREFIX_TRUST_MARKET: &str = "claim.trust_market.";
const CLAIM_PREFIX_PUBLIC_SETTLEMENT: &str = "claim.public_settlement.";
const CLAIM_PREFIX_SWARM: &str = "claim.swarm.";
const CLAIM_PREFIX_DISCLOSURE: &str = "claim.disclosure.";
const CLAIM_PREFIX_COMMERCE: &str = "claim.commerce.";
const SOURCE_VERIFIER_CLAIM_PREFIXES: [&str; 9] = [
    CLAIM_PREFIX_RUNTIME,
    CLAIM_PREFIX_RISK,
    CLAIM_PREFIX_ENTERPRISE,
    CLAIM_PREFIX_AGENT_WEB,
    CLAIM_PREFIX_TRUST_MARKET,
    CLAIM_PREFIX_PUBLIC_SETTLEMENT,
    CLAIM_PREFIX_SWARM,
    CLAIM_PREFIX_DISCLOSURE,
    CLAIM_PREFIX_COMMERCE,
];
const ENTERPRISE_APPROVAL_CASE_SCHEMA: &str = "chio.enterprise.approval-case.v1";
const ENTERPRISE_CONTROL_EVIDENCE_MAP_SCHEMA: &str = "chio.enterprise.control-evidence-map.v1";
const ENTERPRISE_DATA_GOVERNANCE_REPORT_SCHEMA: &str = "chio.enterprise.data-governance-report.v1";
const ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_SCHEMA: &str = "chio.enterprise.evidence-export-bundle.v1";
const ENTERPRISE_TELEMETRY_PROJECTION_SCHEMA: &str = "chio.enterprise.telemetry-projection.v1";
const RISK_ADJUDICATION_JURISDICTION_RECEIPT_SCHEMA: &str =
    "chio.risk.adjudication-jurisdiction-receipt.v1";
const RISK_GUARANTEE_DECISION_SCHEMA: &str = "chio.risk.guarantee-decision.v1";
const COMMERCE_PROVIDER_SELECTION_REPORT_SCHEMA: &str =
    "chio.commerce.provider-selection-report.v1";
const CHIO_RECEIPT_SCHEMA: &str = "chio.receipt.v1";
const WEB3_SETTLEMENT_EXECUTION_RECEIPT_SCHEMA: &str = "chio.web3-settlement-execution-receipt.v1";
const WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA: &str = "chio.web3-settlement-proof-bundle.v1";

const REQUIRED_AUTHORITY_ARTIFACTS: &[(&str, &str)] = &[
    (
        "artifacts/authority/capability-proof.json",
        PROOF_ROOM_FIRST_RUN_CAPABILITY_PROOF_SCHEMA,
    ),
    (
        "artifacts/authority/guard-report.json",
        PROOF_ROOM_FIRST_RUN_GUARD_REPORT_SCHEMA,
    ),
    (
        "artifacts/authority/trust-roots.json",
        PROOF_ROOM_FIRST_RUN_TRUST_ROOTS_SCHEMA,
    ),
];
const REQUIRED_RECEIPT_ARTIFACTS: &[&str] = &[
    "artifacts/receipts/allow-receipt.json",
    "artifacts/receipts/denial-receipt.json",
];

const ALLOWED_BUNDLE_CLAIMS: &[&str] = &[
    CLAIM_TRANSACTION_PASSPORT_ROOT_VERIFIED,
    CLAIM_PROOF_ROOM_VERIFIER_REPORT_BOUND,
    CLAIM_PROOF_ROOM_ALLOW_AND_DENY_VISIBLE,
    CLAIM_PROOF_ROOM_RECEIPT_COVERAGE_MATRIX_BOUND,
    CLAIM_PROOF_ROOM_AUTHORITY_EVIDENCE_BOUND,
];
const REQUIRED_FIRST_RUN_PROOF_ROOM_CLAIMS: &[&str] = &[
    CLAIM_PROOF_ROOM_ALLOW_AND_DENY_VISIBLE,
    CLAIM_PROOF_ROOM_RECEIPT_COVERAGE_MATRIX_BOUND,
    CLAIM_PROOF_ROOM_AUTHORITY_EVIDENCE_BOUND,
];
const REQUIRED_RECEIPT_COVERAGE_CATEGORIES: &[&str] = &[
    "runtime_terminal_allow",
    "runtime_terminal_denial",
    "runtime_terminal_failure",
];

struct EmbeddedProofFixtureFile {
    path: &'static str,
    contents: &'static [u8],
}

include!(concat!(env!("OUT_DIR"), "/proof_fixture_files.rs"));

#[derive(Debug, thiserror::Error)]
pub enum ProofRoomError {
    #[error("{0}")]
    Validation(String),
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("{context}: {source}")]
    Json {
        context: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("proof-room.listen.invalid: {0}")]
    ListenAddress(std::net::AddrParseError),
    #[error("proof-room.serve: {0}")]
    Serve(std::io::Error),
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomBundleManifest {
    schema: String,
    bundle_id: String,
    fixture_id: String,
    hash_algorithm: String,
    transaction_passport_ref: ProofRoomArtifactRef,
    evidence_graph_ref: ProofRoomArtifactRef,
    verifier_report_ref: ProofRoomArtifactRef,
    #[serde(default)]
    proof_room_verifier_report_ref: Option<ProofRoomArtifactRef>,
    #[serde(default)]
    artifacts: Vec<ProofRoomArtifactRef>,
    claims: Vec<ProofRoomClaim>,
    receipt_coverage: Vec<ProofRoomReceiptCoverage>,
    negative_cases: Vec<ProofRoomNegativeCase>,
    #[serde(default)]
    signature: Option<ProofRoomBundleSignature>,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomBundleSignature {
    kind: String,
    signature_ref: String,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomDetachedDsse {
    #[serde(rename = "payloadType")]
    payload_type: String,
    #[serde(rename = "payloadRef")]
    payload_ref: ProofRoomArtifactRef,
    signatures: Vec<ProofRoomDsseSignature>,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomDsseSignature {
    keyid: String,
    sig: String,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomTrustRoots {
    roots: Vec<ProofRoomTrustedRoot>,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomTrustedRoot {
    key_id: String,
    key_digest: String,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomClaim {
    claim_id: String,
    #[serde(default)]
    required_artifacts: Vec<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ProofRoomReceiptCoverage {
    category: String,
    status: String,
    #[serde(default)]
    artifact_path: Option<String>,
    #[serde(default)]
    terminal_status: Option<String>,
    #[serde(default)]
    exclusion_reason: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ProofRoomNegativeCase {
    id: String,
    path: String,
    expected_failure_code: String,
    #[serde(default)]
    observed_failure_code: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ProofRoomArtifactRef {
    path: String,
    sha256: String,
    schema: String,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomNegativeDescriptor {
    #[serde(default)]
    schema: String,
    id: String,
    #[serde(default = "default_base_manifest")]
    base_manifest: String,
    mutation: serde_json::Value,
    expected_failure_code: String,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomVerifierReport {
    schema: String,
    verdict: String,
    bundle_id: String,
    fixture_id: String,
    source_verifier_report_ref: ProofRoomArtifactRef,
    ui_verdict_source: String,
    rendered_claims: Vec<ProofRoomRenderedClaim>,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomRenderedClaim {
    claim_id: String,
    source: String,
    verdict: String,
}

#[derive(Debug, serde::Serialize)]
struct ProofRoomDoctorReport<'a> {
    schema: &'a str,
    verdict: &'a str,
    bundle: &'a str,
    bundle_id: &'a str,
    fixture_id: &'a str,
    verifier_report_ref: &'a ProofRoomArtifactRef,
    receipt_coverage: &'a [ProofRoomReceiptCoverage],
    negative_cases: &'a [ProofRoomNegativeCase],
}

#[derive(Debug, serde::Serialize)]
struct ProofRoomFixtureCatalog {
    schema: &'static str,
    fixtures: Vec<ProofRoomFixtureCatalogEntry>,
    available_fixtures: Vec<ProofRoomAvailableFixture>,
}

#[derive(Debug, serde::Serialize)]
struct ProofRoomFixtureCatalogEntry {
    fixture_id: String,
    bundle_id: String,
    verdict: String,
    manifest_path: &'static str,
    load_report_path: String,
    negative_cases: Vec<ProofRoomFixtureCatalogNegativeCase>,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomAvailableFixtureCatalog {
    schema: String,
    fixtures: Vec<ProofRoomAvailableFixture>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ProofRoomAvailableFixture {
    id: String,
    kind: String,
    path: String,
    description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    negative_cases: Vec<ProofRoomFixtureCatalogNegativeCase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verifier_report: Option<ProofRoomAvailableFixtureReport>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ProofRoomAvailableFixtureReport {
    path: String,
    status: u16,
    verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct ProofRoomFixtureCatalogNegativeCase {
    id: String,
    path: String,
    expected_failure_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_failure_code: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomAvailableFixtureNegativeDescriptor {
    #[serde(default)]
    base_fixture: Option<String>,
    expected_failure_code: String,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomCatalogLoadReport {
    verdict: String,
}

pub fn verify_proof_room_bundle(manifest_path: &Path) -> Result<(), ProofRoomError> {
    verify_proof_room_bundle_inner(manifest_path).map_err(ProofRoomError::Validation)
}

pub fn verify_proof_room_quickstart(
    bundle: &Path,
    doctor_report: Option<&Path>,
) -> Result<(), ProofRoomError> {
    let manifest_path = bundle.join("manifest.json");
    verify_proof_room_bundle(&manifest_path)?;
    if let Some(report_path) = doctor_report {
        write_doctor_report(report_path, bundle)?;
    }
    Ok(())
}

pub fn proof_room_fixture_failure_code(error: &str) -> &str {
    match error.split(':').next() {
        Some(code) => code,
        None => error,
    }
}

fn proof_room_fixture_verifier_failure_message(
    fixture_id: &str,
    error: impl std::fmt::Display,
) -> String {
    format!("proof-room.fixture.verify-failed: {fixture_id}: {error}")
}

fn proof_room_failed_verifier_report(
    fixture_id: &str,
    passport: &chio_transaction_passport::TransactionPassport,
    error: &str,
) -> Result<(Vec<u8>, &'static str), (StatusCode, String)> {
    let report = serde_json::json!({
        "schema": "chio.transaction.verifier-report.v1",
        "id": format!("verifier-report-{}", passport.id),
        "issued_at": passport.issued_at,
        "verdict": "failed",
        "passport_id": passport.id,
        "passport_path": "transaction-passport.json",
        "evidence_graph_sha256": passport.evidence_graph_sha256,
        "evidence_graph_path": passport.evidence_graph_path,
        "verifier_policy_sha256": passport.verifier_policy_sha256,
        "verifier_policy_path": passport.verifier_policy_path,
        "failure_code": proof_room_fixture_failure_code(error),
        "error": error,
    });
    let contents = serde_json::to_vec(&report).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("proof-room.fixture.failed-report-encode: {fixture_id}: {error}"),
        )
    })?;
    Ok((contents, "application/json"))
}

fn proof_room_fixture_verified_report_bytes<T, E>(
    fixture_id: &str,
    passport: &chio_transaction_passport::TransactionPassport,
    result: Result<T, E>,
) -> Result<Vec<u8>, (StatusCode, String)>
where
    T: serde::Serialize,
    E: std::fmt::Display,
{
    let report = match result {
        Ok(report) => report,
        Err(error) => {
            return proof_room_failed_verifier_report(
                fixture_id,
                passport,
                &proof_room_fixture_verifier_failure_message(fixture_id, error),
            )
            .map(|(contents, _)| contents);
        }
    };
    proof_room_fixture_report_bytes(fixture_id, &report)
}

fn proof_room_fixture_report_bytes<T: serde::Serialize>(
    fixture_id: &str,
    report: &T,
) -> Result<Vec<u8>, (StatusCode, String)> {
    serde_json::to_vec(report).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("proof-room.fixture.report-encode: {fixture_id}: {error}"),
        )
    })
}

fn proof_room_fixture_claim_requirements(
    fixture_id: &str,
    verifier_policy_bytes: &[u8],
) -> Result<SourceVerifierClaimRequirements, (StatusCode, String)> {
    source_verifier_claim_requirements(verifier_policy_bytes).map_err(|error| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "proof-room.fixture.policy-invalid: {fixture_id}: {}",
                proof_room_fixture_policy_error_message(&error)
            ),
        )
    })
}

fn proof_room_fixture_policy_error_message(error: &str) -> String {
    if let Some(error) = error.strip_prefix("proof-room.verifier-policy.invalid-json: ") {
        return format!("verifier policy is not valid JSON: {error}");
    }
    if error == "proof-room.verifier-policy.required-claim-invalid" {
        return "required claim must be a string".to_string();
    }
    error.to_string()
}

#[derive(Clone, Copy)]
enum ProofRoomFixtureReportRoute {
    Commerce,
    DisclosureLineage,
    Swarm,
    PublicSettlement,
    StandaloneRisk,
    TrustMarket,
    Enterprise,
    AgentWeb,
    Runtime,
    MinimalPassport,
}

struct ProofRoomFixtureClaimRoute {
    prefix: &'static str,
    route: ProofRoomFixtureReportRoute,
}

const PRIMARY_PROOF_ROOM_FIXTURE_ROUTES: &[ProofRoomFixtureClaimRoute] = &[
    ProofRoomFixtureClaimRoute {
        prefix: CLAIM_PREFIX_COMMERCE,
        route: ProofRoomFixtureReportRoute::Commerce,
    },
    ProofRoomFixtureClaimRoute {
        prefix: CLAIM_PREFIX_DISCLOSURE,
        route: ProofRoomFixtureReportRoute::DisclosureLineage,
    },
    ProofRoomFixtureClaimRoute {
        prefix: CLAIM_PREFIX_SWARM,
        route: ProofRoomFixtureReportRoute::Swarm,
    },
    ProofRoomFixtureClaimRoute {
        prefix: CLAIM_PREFIX_PUBLIC_SETTLEMENT,
        route: ProofRoomFixtureReportRoute::PublicSettlement,
    },
];

const SECONDARY_PROOF_ROOM_FIXTURE_ROUTES: &[ProofRoomFixtureClaimRoute] = &[
    ProofRoomFixtureClaimRoute {
        prefix: CLAIM_PREFIX_AGENT_WEB,
        route: ProofRoomFixtureReportRoute::AgentWeb,
    },
    ProofRoomFixtureClaimRoute {
        prefix: CLAIM_PREFIX_RUNTIME,
        route: ProofRoomFixtureReportRoute::Runtime,
    },
];

fn proof_room_fixture_asset(
    fixture_id: &str,
    asset_path: &str,
) -> Result<(Vec<u8>, &'static str), (StatusCode, String)> {
    proof_room_fixture_asset_with_root(fixture_id, asset_path, None)
}

pub fn proof_room_fixture_asset_bytes(
    fixture_id: &str,
    asset_path: &str,
    installed_fixture_root: Option<&Path>,
) -> Result<(Vec<u8>, &'static str), (StatusCode, String)> {
    proof_room_fixture_asset_with_root(fixture_id, asset_path, installed_fixture_root)
}

fn proof_room_fixture_asset_with_root(
    fixture_id: &str,
    asset_path: &str,
    installed_fixture_root: Option<&Path>,
) -> Result<(Vec<u8>, &'static str), (StatusCode, String)> {
    let fixture = available_fixture_descriptor(fixture_id, installed_fixture_root)?;
    let asset_path = validate_fixture_asset_path(asset_path)?;
    let source = ProofRoomFixtureSource::new(&fixture, installed_fixture_root)?;
    if asset_path == "verifier-report.json" && fixture.kind == "proof-room" {
        let contents = source.file(asset_path, fixture_id)?;
        return Ok((contents, fixture_asset_content_type(asset_path)));
    }
    if asset_path == "verifier-report.json" && fixture.kind == "disclosure-crypto-context" {
        let context_bytes = source.file("verification-context.json", fixture_id)?;
        let report_bytes = source.file("crypto-context-report.json", fixture_id)?;
        let contents =
            crypto_context_verified_report_bytes(&context_bytes, &report_bytes, fixture_id)
                .map_err(|error| (StatusCode::UNPROCESSABLE_ENTITY, error))?;
        return Ok((contents, fixture_asset_content_type(asset_path)));
    }
    if asset_path == "verifier-report.json" && fixture.kind == "negative-disclosure-crypto-context"
    {
        return proof_room_crypto_context_rejection_report(fixture_id, &source);
    }
    if asset_path == "verifier-report.json" && fixture.kind == "workflow-preflight" {
        return proof_room_workflow_preflight_report(fixture_id, &source);
    }
    if asset_path == "verifier-report.json" {
        return proof_room_fixture_verifier_report(fixture_id, &source);
    }
    ensure_fixture_asset_advertised(&fixture, &source, fixture_id, asset_path)?;
    let contents = source.file(asset_path, fixture_id)?;

    Ok((contents, fixture_asset_content_type(asset_path)))
}

fn ensure_fixture_asset_advertised(
    fixture: &ProofRoomAvailableFixture,
    source: &ProofRoomFixtureSource,
    fixture_id: &str,
    asset_path: &str,
) -> Result<(), (StatusCode, String)> {
    let allowed = allowed_fixture_asset_paths(fixture, source, fixture_id)?;
    if allowed.contains(asset_path) {
        return Ok(());
    }
    Err((
        StatusCode::NOT_FOUND,
        format!("proof-room.fixture.asset-not-found: {fixture_id}/{asset_path}"),
    ))
}

fn allowed_fixture_asset_paths(
    fixture: &ProofRoomAvailableFixture,
    source: &ProofRoomFixtureSource,
    fixture_id: &str,
) -> Result<BTreeSet<String>, (StatusCode, String)> {
    let mut allowed = BTreeSet::new();
    insert_allowed_fixture_asset(&mut allowed, "verifier-report.json", fixture_id)?;

    match fixture.kind.as_str() {
        "proof-room" => {
            insert_proof_room_fixture_bundle_assets(&mut allowed, source, fixture_id)?;
        }
        "workflow-preflight" => {
            insert_allowed_fixture_asset(&mut allowed, "preflight-plan.json", fixture_id)?;
        }
        "disclosure-crypto-context" => {
            insert_allowed_fixture_assets(
                &mut allowed,
                fixture_id,
                &[
                    "verification-context.json",
                    "crypto-context-report.json",
                    "key-state.json",
                    "revocation-snapshot.json",
                    "transparency-inclusion-proof.json",
                    "verifier-privacy-profile.json",
                ],
            )?;
        }
        "negative-disclosure-crypto-context" => {
            insert_allowed_fixture_asset(&mut allowed, "verification-context.json", fixture_id)?;
        }
        "transaction-passport" | "negative-transaction-passport" => {
            insert_transaction_fixture_assets(&mut allowed, source, fixture_id)?;
        }
        _ => {}
    }

    Ok(allowed)
}

fn insert_transaction_fixture_assets(
    allowed: &mut BTreeSet<String>,
    source: &ProofRoomFixtureSource,
    fixture_id: &str,
) -> Result<(), (StatusCode, String)> {
    insert_allowed_fixture_assets(
        allowed,
        fixture_id,
        &[
            "transaction-passport.json",
            "evidence-graph.json",
            "verifier-policy.json",
        ],
    )?;

    let Ok(passport_bytes) = source.file("transaction-passport.json", fixture_id) else {
        return Ok(());
    };
    let Ok(passport) =
        serde_json::from_slice::<chio_transaction_passport::TransactionPassport>(&passport_bytes)
    else {
        return Ok(());
    };
    insert_allowed_fixture_asset(allowed, &passport.evidence_graph_path, fixture_id)?;
    insert_allowed_fixture_asset(allowed, &passport.verifier_policy_path, fixture_id)?;

    let Ok(evidence_graph_bytes) = source.file(&passport.evidence_graph_path, fixture_id) else {
        return Ok(());
    };
    let graph = parse_embedded_evidence_graph(&evidence_graph_bytes, "fixture evidence graph")
        .map_err(|error| (StatusCode::UNPROCESSABLE_ENTITY, error))?;
    for node in graph.nodes {
        insert_allowed_fixture_asset(allowed, &node.path, fixture_id)?;
    }
    Ok(())
}

fn insert_proof_room_fixture_bundle_assets(
    allowed: &mut BTreeSet<String>,
    source: &ProofRoomFixtureSource,
    fixture_id: &str,
) -> Result<(), (StatusCode, String)> {
    const BUNDLE_ROOT: &str = "proof-room-bundle";
    insert_allowed_fixture_asset(allowed, BUNDLE_ROOT, fixture_id)?;
    insert_allowed_fixture_asset(allowed, "proof-room-bundle/README.md", fixture_id)?;
    insert_allowed_fixture_asset(allowed, "proof-room-bundle/manifest.json", fixture_id)?;

    let Ok(manifest_bytes) = source.file("proof-room-bundle/manifest.json", fixture_id) else {
        return Ok(());
    };
    let manifest: ProofRoomBundleManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|error| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("proof-room.fixture.manifest-invalid: {fixture_id}: {error}"),
            )
        })?;

    insert_allowed_bundle_ref(
        allowed,
        BUNDLE_ROOT,
        &manifest.transaction_passport_ref.path,
        fixture_id,
    )?;
    insert_allowed_bundle_ref(
        allowed,
        BUNDLE_ROOT,
        &manifest.evidence_graph_ref.path,
        fixture_id,
    )?;
    insert_allowed_bundle_ref(
        allowed,
        BUNDLE_ROOT,
        &manifest.verifier_report_ref.path,
        fixture_id,
    )?;
    if let Some(report_ref) = manifest.proof_room_verifier_report_ref.as_ref() {
        insert_allowed_bundle_ref(allowed, BUNDLE_ROOT, &report_ref.path, fixture_id)?;
    }
    for artifact in &manifest.artifacts {
        insert_allowed_bundle_ref(allowed, BUNDLE_ROOT, &artifact.path, fixture_id)?;
    }
    for negative_case in &manifest.negative_cases {
        insert_allowed_bundle_ref(allowed, BUNDLE_ROOT, &negative_case.path, fixture_id)?;
        insert_proof_room_negative_case_asset_refs(
            allowed,
            source,
            fixture_id,
            BUNDLE_ROOT,
            &negative_case.path,
        )?;
    }
    for coverage in &manifest.receipt_coverage {
        if let Some(artifact_path) = coverage.artifact_path.as_deref() {
            insert_allowed_bundle_ref(allowed, BUNDLE_ROOT, artifact_path, fixture_id)?;
        }
    }
    if let Some(signature) = manifest.signature.as_ref() {
        insert_allowed_bundle_ref(allowed, BUNDLE_ROOT, &signature.signature_ref, fixture_id)?;
    }
    Ok(())
}

fn insert_proof_room_negative_case_asset_refs(
    allowed: &mut BTreeSet<String>,
    source: &ProofRoomFixtureSource,
    fixture_id: &str,
    bundle_root: &str,
    negative_case_path: &str,
) -> Result<(), (StatusCode, String)> {
    if !negative_case_path.ends_with("/transaction-passport.json") {
        return Ok(());
    }
    let Some((negative_dir, _passport_file)) = negative_case_path.rsplit_once('/') else {
        return Ok(());
    };
    let passport_asset_path = format!("{bundle_root}/{negative_case_path}");
    let passport_bytes = source.file(&passport_asset_path, fixture_id)?;
    let passport: chio_transaction_passport::TransactionPassport =
        serde_json::from_slice(&passport_bytes).map_err(|error| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!(
                    "proof-room.fixture.negative-passport-invalid: {fixture_id}: {negative_case_path}: {error}"
                ),
            )
        })?;

    let evidence_graph_path =
        negative_case_bundle_member_path(negative_dir, &passport.evidence_graph_path, fixture_id)?;
    let verifier_policy_path =
        negative_case_bundle_member_path(negative_dir, &passport.verifier_policy_path, fixture_id)?;
    insert_allowed_bundle_ref(allowed, bundle_root, &evidence_graph_path, fixture_id)?;
    insert_allowed_bundle_ref(allowed, bundle_root, &verifier_policy_path, fixture_id)?;

    let evidence_graph_asset_path = format!("{bundle_root}/{evidence_graph_path}");
    let evidence_graph_bytes = source.file(&evidence_graph_asset_path, fixture_id)?;
    let graph = parse_embedded_evidence_graph(
        &evidence_graph_bytes,
        "proof room fixture negative evidence graph",
    )
    .map_err(|error| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "proof-room.fixture.negative-evidence-graph-invalid: {fixture_id}: {evidence_graph_path}: {error}"
            ),
        )
    })?;
    for node in graph.nodes {
        let artifact_path = negative_case_bundle_member_path(negative_dir, &node.path, fixture_id)?;
        insert_allowed_bundle_ref(allowed, bundle_root, &artifact_path, fixture_id)?;
    }
    Ok(())
}

fn negative_case_bundle_member_path(
    negative_dir: &str,
    member_path: &str,
    fixture_id: &str,
) -> Result<String, (StatusCode, String)> {
    validate_fixture_asset_path(member_path).map_err(|(_status, error)| {
        (
            StatusCode::BAD_REQUEST,
            format!("proof-room.fixture.asset-path-invalid: {fixture_id}/{member_path}: {error}"),
        )
    })?;
    let path = format!("{negative_dir}/{member_path}");
    validate_fixture_asset_path(&path).map_err(|(_status, error)| {
        (
            StatusCode::BAD_REQUEST,
            format!("proof-room.fixture.asset-path-invalid: {fixture_id}/{path}: {error}"),
        )
    })?;
    Ok(path)
}

fn insert_allowed_bundle_ref(
    allowed: &mut BTreeSet<String>,
    bundle_root: &str,
    path: &str,
    fixture_id: &str,
) -> Result<(), (StatusCode, String)> {
    validate_fixture_asset_path(path)?;
    let asset_path = format!("{bundle_root}/{path}");
    insert_allowed_fixture_asset(allowed, &asset_path, fixture_id)
}

fn insert_allowed_fixture_assets(
    allowed: &mut BTreeSet<String>,
    fixture_id: &str,
    asset_paths: &[&str],
) -> Result<(), (StatusCode, String)> {
    for asset_path in asset_paths {
        insert_allowed_fixture_asset(allowed, asset_path, fixture_id)?;
    }
    Ok(())
}

fn insert_allowed_fixture_asset(
    allowed: &mut BTreeSet<String>,
    asset_path: &str,
    fixture_id: &str,
) -> Result<(), (StatusCode, String)> {
    validate_fixture_asset_path(asset_path).map_err(|(_status, error)| {
        (
            StatusCode::BAD_REQUEST,
            format!("proof-room.fixture.asset-path-invalid: {fixture_id}/{asset_path}: {error}"),
        )
    })?;
    allowed.insert(asset_path.to_string());
    Ok(())
}

enum ProofRoomFixtureSource {
    Embedded { fixture_root: String },
    Installed { root: PathBuf, fixture_root: String },
}

impl ProofRoomFixtureSource {
    fn new(
        fixture: &ProofRoomAvailableFixture,
        installed_fixture_root: Option<&Path>,
    ) -> Result<Self, (StatusCode, String)> {
        let fixture_root = available_fixture_embedded_root(fixture)?;
        match installed_fixture_root {
            Some(root) => Ok(Self::Installed {
                root: installed_fixture_root_path(root, &fixture.id)?,
                fixture_root,
            }),
            None => Ok(Self::Embedded { fixture_root }),
        }
    }

    fn file(&self, asset_path: &str, fixture_id: &str) -> Result<Vec<u8>, (StatusCode, String)> {
        match self {
            Self::Embedded { fixture_root } => {
                embedded_fixture_file(fixture_root, asset_path, fixture_id)
                    .map(|bytes| bytes.to_vec())
            }
            Self::Installed { root, fixture_root } => {
                installed_fixture_file(root, fixture_root, asset_path, fixture_id)
            }
        }
    }

    fn artifact_map(
        &self,
        fixture_id: &str,
    ) -> Result<BTreeMap<String, Vec<u8>>, (StatusCode, String)> {
        match self {
            Self::Embedded { fixture_root } => Ok(embedded_fixture_artifact_map(fixture_root)),
            Self::Installed { root, fixture_root } => {
                installed_fixture_artifact_map(root, fixture_root, fixture_id)
            }
        }
    }

    fn installed_file_path(
        &self,
        asset_path: &str,
        fixture_id: &str,
    ) -> Result<Option<PathBuf>, (StatusCode, String)> {
        match self {
            Self::Embedded { .. } => Ok(None),
            Self::Installed { root, fixture_root } => {
                let fixture_dir = installed_fixture_directory(root, fixture_root, fixture_id)?;
                resolve_installed_fixture_asset(root, &fixture_dir, asset_path, fixture_id)
                    .map(Some)
            }
        }
    }
}

fn installed_fixture_root_path(
    installed_fixture_root: &Path,
    fixture_id: &str,
) -> Result<PathBuf, (StatusCode, String)> {
    fs::canonicalize(installed_fixture_root).map_err(|error| {
        (
            StatusCode::NOT_FOUND,
            format!("proof-room.fixture.root-unreadable: {fixture_id}: {error}"),
        )
    })
}

fn installed_fixture_directory(
    installed_fixture_root: &Path,
    fixture_root: &str,
    fixture_id: &str,
) -> Result<PathBuf, (StatusCode, String)> {
    let path = installed_fixture_root.join(fixture_root);
    let path = fs::canonicalize(&path).map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            format!("proof-room.fixture.root-not-found: {fixture_id}"),
        )
    })?;
    if !path.starts_with(installed_fixture_root) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("proof-room.fixture.root-path-escape: {fixture_id}"),
        ));
    }
    if !path.is_dir() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("proof-room.fixture.root-not-found: {fixture_id}"),
        ));
    }
    Ok(path)
}

fn installed_fixture_file(
    installed_fixture_root: &Path,
    fixture_root: &str,
    asset_path: &str,
    fixture_id: &str,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let fixture_dir =
        installed_fixture_directory(installed_fixture_root, fixture_root, fixture_id)?;
    let path = resolve_installed_fixture_asset(
        installed_fixture_root,
        &fixture_dir,
        asset_path,
        fixture_id,
    )?;
    let metadata = fs::metadata(&path).map_err(|error| {
        (
            StatusCode::NOT_FOUND,
            format!("proof-room.fixture.asset-not-found: {fixture_id}/{asset_path}: {error}"),
        )
    })?;
    if !metadata.is_file() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("proof-room.fixture.asset-not-found: {fixture_id}/{asset_path}"),
        ));
    }
    fs::read(&path).map_err(|error| {
        (
            StatusCode::NOT_FOUND,
            format!("proof-room.fixture.asset-not-found: {fixture_id}/{asset_path}: {error}"),
        )
    })
}

fn resolve_installed_fixture_asset(
    installed_fixture_root: &Path,
    fixture_dir: &Path,
    asset_path: &str,
    fixture_id: &str,
) -> Result<PathBuf, (StatusCode, String)> {
    validate_fixture_asset_path(asset_path)?;
    let path = fs::canonicalize(fixture_dir.join(asset_path)).map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            format!("proof-room.fixture.asset-not-found: {fixture_id}/{asset_path}"),
        )
    })?;
    if !path.starts_with(installed_fixture_root) || !path.starts_with(fixture_dir) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("proof-room.fixture.asset-path-escape: {fixture_id}/{asset_path}"),
        ));
    }
    Ok(path)
}

fn installed_fixture_artifact_map(
    installed_fixture_root: &Path,
    fixture_root: &str,
    fixture_id: &str,
) -> Result<BTreeMap<String, Vec<u8>>, (StatusCode, String)> {
    let fixture_dir =
        installed_fixture_directory(installed_fixture_root, fixture_root, fixture_id)?;
    let mut artifacts = BTreeMap::new();
    collect_installed_fixture_artifacts(
        installed_fixture_root,
        &fixture_dir,
        &fixture_dir,
        fixture_id,
        &mut artifacts,
    )?;
    Ok(artifacts)
}

fn collect_installed_fixture_artifacts(
    installed_fixture_root: &Path,
    fixture_dir: &Path,
    directory: &Path,
    fixture_id: &str,
    artifacts: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), (StatusCode, String)> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| {
            (
                StatusCode::NOT_FOUND,
                format!("proof-room.fixture.root-unreadable: {fixture_id}: {error}"),
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            (
                StatusCode::NOT_FOUND,
                format!("proof-room.fixture.root-unreadable: {fixture_id}: {error}"),
            )
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            (
                StatusCode::NOT_FOUND,
                format!("proof-room.fixture.asset-unreadable: {fixture_id}: {error}"),
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("proof-room.fixture.asset-symlink-unsupported: {fixture_id}"),
            ));
        }
        let canonical_path = fs::canonicalize(&path).map_err(|error| {
            (
                StatusCode::NOT_FOUND,
                format!("proof-room.fixture.asset-unreadable: {fixture_id}: {error}"),
            )
        })?;
        if !canonical_path.starts_with(installed_fixture_root)
            || !canonical_path.starts_with(fixture_dir)
        {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("proof-room.fixture.asset-path-escape: {fixture_id}"),
            ));
        }
        if metadata.is_dir() {
            collect_installed_fixture_artifacts(
                installed_fixture_root,
                fixture_dir,
                &canonical_path,
                fixture_id,
                artifacts,
            )?;
        } else if metadata.is_file() {
            let relative_path =
                installed_fixture_relative_path(fixture_dir, &canonical_path, fixture_id)?;
            let contents = fs::read(&canonical_path).map_err(|error| {
                (
                    StatusCode::NOT_FOUND,
                    format!(
                        "proof-room.fixture.asset-unreadable: {fixture_id}/{relative_path}: {error}"
                    ),
                )
            })?;
            artifacts.insert(relative_path, contents);
        } else {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("proof-room.fixture.asset-kind-unsupported: {fixture_id}"),
            ));
        }
    }
    Ok(())
}

fn installed_fixture_relative_path(
    fixture_dir: &Path,
    path: &Path,
    fixture_id: &str,
) -> Result<String, (StatusCode, String)> {
    let relative_path = path.strip_prefix(fixture_dir).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("proof-room.fixture.asset-path-escape: {fixture_id}"),
        )
    })?;
    let relative_path = relative_path.to_string_lossy().replace('\\', "/");
    validate_fixture_asset_path(&relative_path)?;
    Ok(relative_path)
}

fn proof_room_fixture_verifier_report(
    fixture_id: &str,
    source: &ProofRoomFixtureSource,
) -> Result<(Vec<u8>, &'static str), (StatusCode, String)> {
    let passport_bytes = source.file("transaction-passport.json", fixture_id)?;
    let passport: chio_transaction_passport::TransactionPassport =
        serde_json::from_slice(&passport_bytes).map_err(|error| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("proof-room.fixture.passport-invalid: {fixture_id}: {error}"),
            )
        })?;
    let evidence_graph_bytes = source.file(&passport.evidence_graph_path, fixture_id)?;
    let verifier_policy_bytes = source.file(&passport.verifier_policy_path, fixture_id)?;
    let requirements = proof_room_fixture_claim_requirements(fixture_id, &verifier_policy_bytes)?;
    let artifacts = source.artifact_map(fixture_id)?;
    let route = proof_room_fixture_report_route(fixture_id, &requirements, &evidence_graph_bytes)?;
    let contents = proof_room_fixture_route_report_bytes(
        route,
        fixture_id,
        &passport,
        &evidence_graph_bytes,
        &verifier_policy_bytes,
        &artifacts,
    )?;

    Ok((contents, "application/json"))
}

fn proof_room_fixture_report_route(
    fixture_id: &str,
    requirements: &SourceVerifierClaimRequirements,
    evidence_graph_bytes: &[u8],
) -> Result<ProofRoomFixtureReportRoute, (StatusCode, String)> {
    let requires_risk = requirements.requires(CLAIM_PREFIX_RISK);
    let route_risk_through_trust_market = requires_risk
        && embedded_evidence_graph_has_role(
            evidence_graph_bytes,
            is_trust_market_risk_context_role,
        )
        .map_err(|error| proof_room_fixture_invalid(fixture_id, "evidence-graph", error))?;
    let route_risk_through_enterprise = requires_risk
        && embedded_evidence_graph_has_role(evidence_graph_bytes, is_enterprise_risk_context_role)
            .map_err(|error| proof_room_fixture_invalid(fixture_id, "evidence-graph", error))?;

    if let Some(route) =
        first_required_fixture_claim_route(requirements, PRIMARY_PROOF_ROOM_FIXTURE_ROUTES)
    {
        return Ok(route);
    }

    if requires_risk && !route_risk_through_enterprise && !route_risk_through_trust_market {
        return Ok(ProofRoomFixtureReportRoute::StandaloneRisk);
    }
    if requirements.requires(CLAIM_PREFIX_TRUST_MARKET) || route_risk_through_trust_market {
        return Ok(ProofRoomFixtureReportRoute::TrustMarket);
    }
    if requirements.requires(CLAIM_PREFIX_ENTERPRISE) || route_risk_through_enterprise {
        return Ok(ProofRoomFixtureReportRoute::Enterprise);
    }
    if let Some(route) =
        first_required_fixture_claim_route(requirements, SECONDARY_PROOF_ROOM_FIXTURE_ROUTES)
    {
        return Ok(route);
    }

    Ok(ProofRoomFixtureReportRoute::MinimalPassport)
}

fn first_required_fixture_claim_route(
    requirements: &SourceVerifierClaimRequirements,
    routes: &[ProofRoomFixtureClaimRoute],
) -> Option<ProofRoomFixtureReportRoute> {
    routes
        .iter()
        .find(|route| requirements.requires(route.prefix))
        .map(|route| route.route)
}

fn proof_room_fixture_route_report_bytes(
    route: ProofRoomFixtureReportRoute,
    fixture_id: &str,
    passport: &chio_transaction_passport::TransactionPassport,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>, (StatusCode, String)> {
    match route {
        ProofRoomFixtureReportRoute::Commerce => {
            let commerce_bundle =
                embedded_commerce_order_bundle(evidence_graph_bytes, artifacts)
                    .map_err(|error| proof_room_fixture_invalid(fixture_id, "commerce", error))?;
            proof_room_fixture_verified_report_bytes(
                fixture_id,
                passport,
                chio_commerce_order::verify_commerce_order(&commerce_bundle),
            )
        }
        ProofRoomFixtureReportRoute::DisclosureLineage => {
            let disclosure_bundle =
                embedded_disclosure_lineage_bundle(evidence_graph_bytes, artifacts).map_err(
                    |error| proof_room_fixture_invalid(fixture_id, "disclosure-lineage", error),
                )?;
            proof_room_fixture_verified_report_bytes(
                fixture_id,
                passport,
                chio_disclosure_lineage::verify_disclosure_lineage_bundle(&disclosure_bundle),
            )
        }
        ProofRoomFixtureReportRoute::Swarm => {
            let swarm_bundle = embedded_swarm_authority_bundle(evidence_graph_bytes, artifacts)
                .map_err(|error| proof_room_fixture_invalid(fixture_id, "swarm", error))?;
            proof_room_fixture_verified_report_bytes(
                fixture_id,
                passport,
                chio_swarm_authority::verify_swarm_authority_bundle(&swarm_bundle),
            )
        }
        ProofRoomFixtureReportRoute::PublicSettlement => {
            let proof_bundle =
                embedded_public_settlement_proof_bundle(evidence_graph_bytes, artifacts).map_err(
                    |error| proof_room_fixture_invalid(fixture_id, "public-settlement", error),
                )?;
            if proof_bundle.transaction_passport_id != passport.id {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!(
                        "proof-room.fixture.public-settlement-invalid: {fixture_id}: passport mismatch: expected {}, got {}",
                        passport.id, proof_bundle.transaction_passport_id
                    ),
                ));
            }
            proof_room_fixture_verified_report_bytes(
                fixture_id,
                passport,
                chio_web3::settlement_proof::verify_public_settlement_proof(&proof_bundle),
            )
        }
        ProofRoomFixtureReportRoute::StandaloneRisk => proof_room_fixture_standalone_risk_report(
            fixture_id,
            passport,
            evidence_graph_bytes,
            artifacts,
        ),
        ProofRoomFixtureReportRoute::TrustMarket => proof_room_fixture_verified_report_bytes(
            fixture_id,
            passport,
            chio_trust_market_context::verify_trust_market_context(
                &chio_trust_market_context::TrustMarketBundle {
                    passport: passport.clone(),
                    evidence_graph_bytes: evidence_graph_bytes.to_vec(),
                    verifier_policy_bytes: verifier_policy_bytes.to_vec(),
                    artifacts: artifacts.clone(),
                },
            ),
        ),
        ProofRoomFixtureReportRoute::Enterprise => proof_room_fixture_verified_report_bytes(
            fixture_id,
            passport,
            chio_enterprise_export::verify_enterprise_export(
                &chio_enterprise_export::EnterpriseExportBundle {
                    passport: passport.clone(),
                    evidence_graph_bytes: evidence_graph_bytes.to_vec(),
                    verifier_policy_bytes: verifier_policy_bytes.to_vec(),
                    artifacts: artifacts.clone(),
                },
            ),
        ),
        ProofRoomFixtureReportRoute::AgentWeb => proof_room_fixture_verified_report_bytes(
            fixture_id,
            passport,
            chio_agent_web_interop::verify_agent_web_interop(
                &chio_agent_web_interop::AgentWebInteropBundle {
                    passport: passport.clone(),
                    evidence_graph_bytes: evidence_graph_bytes.to_vec(),
                    verifier_policy_bytes: verifier_policy_bytes.to_vec(),
                    artifacts: artifacts.clone(),
                },
            ),
        ),
        ProofRoomFixtureReportRoute::Runtime => {
            let runtime_artifacts = embedded_runtime_artifacts(evidence_graph_bytes, artifacts)
                .map_err(|error| proof_room_fixture_invalid(fixture_id, "runtime", error))?;
            proof_room_fixture_verified_report_bytes(
                fixture_id,
                passport,
                chio_transaction_passport::verify_runtime_security_claims(
                    &chio_transaction_passport::RuntimeSecurityBundle {
                        passport: passport.clone(),
                        evidence_graph_bytes: evidence_graph_bytes.to_vec(),
                        verifier_policy_bytes: verifier_policy_bytes.to_vec(),
                        artifacts: runtime_artifacts,
                    },
                ),
            )
        }
        ProofRoomFixtureReportRoute::MinimalPassport => proof_room_fixture_verified_report_bytes(
            fixture_id,
            passport,
            chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
                passport,
                "transaction-passport.json".to_string(),
                evidence_graph_bytes,
                verifier_policy_bytes,
                artifacts,
            ),
        ),
    }
}

fn proof_room_fixture_standalone_risk_report(
    fixture_id: &str,
    passport: &chio_transaction_passport::TransactionPassport,
    evidence_graph_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let risk_report = embedded_risk_comptroller_report(evidence_graph_bytes, artifacts)
        .map_err(|error| proof_room_fixture_invalid(fixture_id, "risk", error))?;
    if let Err(error) = chio_risk_comptroller::validate_risk_report(passport, &risk_report) {
        return proof_room_failed_verifier_report(
            fixture_id,
            passport,
            &proof_room_fixture_verifier_failure_message(fixture_id, error),
        )
        .map(|(contents, _)| contents);
    }
    let risk_evidence_ref_schemas = embedded_evidence_graph_ref_schemas(evidence_graph_bytes)
        .map_err(|error| proof_room_fixture_invalid(fixture_id, "evidence-graph", error))?;
    match chio_risk_comptroller::validate_risk_evidence_refs(&risk_report, |evidence_ref, kind| {
        risk_evidence_ref_schemas
            .get(evidence_ref)
            .is_some_and(|schema| risk_evidence_schema_matches_kind(schema, kind))
    }) {
        Ok(()) => {}
        Err(error) => {
            return proof_room_failed_verifier_report(
                fixture_id,
                passport,
                &proof_room_fixture_verifier_failure_message(fixture_id, error),
            )
            .map(|(contents, _)| contents);
        }
    }
    proof_room_fixture_report_bytes(
        fixture_id,
        &serde_json::json!({
            "schema": "chio.transaction.verifier-report.v1",
            "id": format!("verifier-report-{}", passport.id),
            "issued_at": passport.issued_at,
            "verdict": "verified",
            "passport_id": passport.id,
            "passport_path": "transaction-passport.json",
            "evidence_graph_sha256": passport.evidence_graph_sha256,
            "evidence_graph_path": passport.evidence_graph_path,
            "verifier_policy_sha256": passport.verifier_policy_sha256,
            "verifier_policy_path": passport.verifier_policy_path,
            "risk_comptroller_report_ref": risk_report.id,
            "order_id": risk_report.order_id,
            "subject": risk_report.subject,
            "verified_claims": [CLAIM_RISK_COMPTROLLER_REPORT_BOUND],
        }),
    )
}

fn proof_room_fixture_invalid(
    fixture_id: &str,
    label: &str,
    error: impl std::fmt::Display,
) -> (StatusCode, String) {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        format!("proof-room.fixture.{label}-invalid: {fixture_id}: {error}"),
    )
}

fn proof_room_crypto_context_rejection_report(
    fixture_id: &str,
    source: &ProofRoomFixtureSource,
) -> Result<(Vec<u8>, &'static str), (StatusCode, String)> {
    let context_bytes = source.file("verification-context.json", fixture_id)?;
    crypto_context_rejection_report_bytes(&context_bytes, fixture_id)
        .map(|contents| (contents, "application/json"))
        .map_err(|error| (StatusCode::UNPROCESSABLE_ENTITY, error))
}

fn proof_room_workflow_preflight_report(
    fixture_id: &str,
    source: &ProofRoomFixtureSource,
) -> Result<(Vec<u8>, &'static str), (StatusCode, String)> {
    let plan_bytes = source.file("preflight-plan.json", fixture_id)?;
    let plan: chio_workflow_preflight::WorkflowPreflightPlan = serde_json::from_slice(&plan_bytes)
        .map_err(|error| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("proof-room.fixture.workflow-preflight-invalid: {fixture_id}: {error}"),
            )
        })?;
    let report = chio_workflow_preflight::evaluate_workflow_preflight(&plan).map_err(|error| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("proof-room.fixture.workflow-preflight-invalid: {fixture_id}: {error}"),
        )
    })?;
    let contents = serde_json::to_vec(&report).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("proof-room.fixture.workflow-preflight-report: {fixture_id}: {error}"),
        )
    })?;
    Ok((contents, "application/json"))
}

#[derive(serde::Deserialize)]
struct ProofRoomEmbeddedEvidenceGraph {
    nodes: Vec<ProofRoomEmbeddedEvidenceNode>,
}

#[derive(serde::Deserialize)]
struct ProofRoomEmbeddedEvidenceNode {
    id: String,
    role: String,
    schema: String,
    path: String,
    sha256: String,
}

fn parse_embedded_evidence_graph(
    evidence_graph_bytes: &[u8],
    error_prefix: &str,
) -> Result<ProofRoomEmbeddedEvidenceGraph, String> {
    serde_json::from_slice(evidence_graph_bytes)
        .map_err(|error| format!("{error_prefix} is not valid JSON: {error}"))
}

fn embedded_evidence_graph_has_role(
    evidence_graph_bytes: &[u8],
    predicate: fn(&str) -> bool,
) -> Result<bool, String> {
    let graph = parse_embedded_evidence_graph(evidence_graph_bytes, "evidence graph")?;
    Ok(graph.nodes.iter().any(|node| predicate(&node.role)))
}

fn embedded_evidence_graph_ref_schemas(
    evidence_graph_bytes: &[u8],
) -> Result<BTreeMap<String, String>, String> {
    let graph = parse_embedded_evidence_graph(evidence_graph_bytes, "evidence graph")?;
    Ok(graph
        .nodes
        .into_iter()
        .map(|node| (node.id, node.schema))
        .collect())
}

fn risk_evidence_schema_matches_kind(
    schema: &str,
    kind: chio_risk_comptroller::RiskEvidenceRefKind,
) -> bool {
    use chio_risk_comptroller::RiskEvidenceRefKind;

    match kind {
        RiskEvidenceRefKind::AuthorityReceipt => matches!(
            schema,
            ENTERPRISE_APPROVAL_CASE_SCHEMA | RISK_GUARANTEE_DECISION_SCHEMA | CHIO_RECEIPT_SCHEMA
        ),
        RiskEvidenceRefKind::SupportingEvidence => matches!(
            schema,
            ENTERPRISE_DATA_GOVERNANCE_REPORT_SCHEMA
                | ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_SCHEMA
                | ENTERPRISE_TELEMETRY_PROJECTION_SCHEMA
                | ENTERPRISE_CONTROL_EVIDENCE_MAP_SCHEMA
                | COMMERCE_PROVIDER_SELECTION_REPORT_SCHEMA
        ),
        RiskEvidenceRefKind::ReserveLedgerReceipt => matches!(
            schema,
            ENTERPRISE_APPROVAL_CASE_SCHEMA | RISK_GUARANTEE_DECISION_SCHEMA | CHIO_RECEIPT_SCHEMA
        ),
        RiskEvidenceRefKind::Settlement => matches!(
            schema,
            ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_SCHEMA
                | WEB3_SETTLEMENT_EXECUTION_RECEIPT_SCHEMA
                | WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA
                | CHIO_RECEIPT_SCHEMA
        ),
        RiskEvidenceRefKind::Jurisdiction => matches!(
            schema,
            RISK_ADJUDICATION_JURISDICTION_RECEIPT_SCHEMA
                | ENTERPRISE_APPROVAL_CASE_SCHEMA
                | CHIO_RECEIPT_SCHEMA
        ),
    }
}

fn is_enterprise_risk_context_role(role: &str) -> bool {
    matches!(
        role,
        "data-governance-report"
            | "evidence-export-bundle"
            | "telemetry-projection"
            | "approval-case"
            | "control-evidence-map"
    )
}

fn is_trust_market_risk_context_role(role: &str) -> bool {
    matches!(
        role,
        "provider-discovery-snapshot"
            | "provider-selection-report"
            | "trust-scorecard-snapshot"
            | "reputation-import-report"
            | "sla-commitment"
            | "sla-performance-report"
            | "collateral-position-report"
            | "guarantee-decision"
            | "adjudication-jurisdiction-receipt"
    )
}

fn embedded_risk_comptroller_report(
    evidence_graph_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<chio_risk_comptroller::RiskComptrollerReport, String> {
    let graph = parse_embedded_evidence_graph(evidence_graph_bytes, "risk evidence graph")?;
    let bytes = embedded_single_role_artifact_bytes(
        &graph.nodes,
        artifacts,
        "risk-comptroller-report",
        "chio.risk.comptroller-report.v1",
        "risk comptroller",
    )?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("risk comptroller report JSON invalid: {error}"))
}

fn embedded_single_role_artifact_bytes(
    nodes: &[ProofRoomEmbeddedEvidenceNode],
    artifacts: &BTreeMap<String, Vec<u8>>,
    role: &str,
    expected_schema: &str,
    label: &str,
) -> Result<Vec<u8>, String> {
    let node = select_single_embedded_artifact_node(nodes, role, label)?;
    embedded_artifact_node_bytes(node, artifacts, expected_schema, label)
}

fn select_single_embedded_artifact_node<'a>(
    nodes: &'a [ProofRoomEmbeddedEvidenceNode],
    role: &str,
    label: &str,
) -> Result<&'a ProofRoomEmbeddedEvidenceNode, String> {
    let matches = embedded_artifact_nodes_by_role(nodes, role);
    match matches.as_slice() {
        [node] => Ok(node),
        [] => Err(format!("missing {label} artifact role: {role}")),
        _ => Err(format!("multiple {label} artifact roles: {role}")),
    }
}

fn embedded_artifact_nodes_by_role<'a>(
    nodes: &'a [ProofRoomEmbeddedEvidenceNode],
    role: &str,
) -> Vec<&'a ProofRoomEmbeddedEvidenceNode> {
    nodes.iter().filter(|node| node.role == role).collect()
}

fn embedded_artifact_node_bytes(
    node: &ProofRoomEmbeddedEvidenceNode,
    artifacts: &BTreeMap<String, Vec<u8>>,
    expected_schema: &str,
    label: &str,
) -> Result<Vec<u8>, String> {
    if node.schema != expected_schema {
        return Err(format!(
            "unsupported {label} artifact schema for {}: {}",
            node.path, node.schema,
        ));
    }
    let bytes = artifacts
        .get(&node.path)
        .ok_or_else(|| format!("missing {label} artifact: {}", node.path))?;
    let actual_digest = sha256_hex(bytes);
    if actual_digest != node.sha256 {
        return Err(format!(
            "{label} artifact digest mismatch for {}: expected {}, got {}",
            node.path, node.sha256, actual_digest,
        ));
    }
    Ok(bytes.clone())
}

fn embedded_required_json_artifact<T: for<'de> serde::Deserialize<'de>>(
    nodes: &[ProofRoomEmbeddedEvidenceNode],
    artifacts: &BTreeMap<String, Vec<u8>>,
    role: &str,
    expected_schema: &str,
    label: &str,
) -> Result<T, String> {
    let node = select_single_embedded_artifact_node(nodes, role, label)?;
    embedded_json_artifact(node, artifacts, expected_schema, label)
}

fn embedded_optional_json_artifact<T: for<'de> serde::Deserialize<'de>>(
    nodes: &[ProofRoomEmbeddedEvidenceNode],
    artifacts: &BTreeMap<String, Vec<u8>>,
    role: &str,
    expected_schema: &str,
    label: &str,
) -> Result<Option<T>, String> {
    let matches = embedded_artifact_nodes_by_role(nodes, role);
    match matches.as_slice() {
        [node] => embedded_json_artifact(node, artifacts, expected_schema, label).map(Some),
        [] => Ok(None),
        _ => Err(format!("multiple {label} artifact roles: {role}")),
    }
}

fn embedded_json_artifacts<T: for<'de> serde::Deserialize<'de>>(
    nodes: &[ProofRoomEmbeddedEvidenceNode],
    artifacts: &BTreeMap<String, Vec<u8>>,
    role: &str,
    expected_schema: &str,
    label: &str,
) -> Result<Vec<T>, String> {
    let mut decoded = Vec::new();
    for node in embedded_artifact_nodes_by_role(nodes, role) {
        decoded.push(embedded_json_artifact(
            node,
            artifacts,
            expected_schema,
            label,
        )?);
    }
    if decoded.is_empty() {
        return Err(format!("missing {label} artifact role: {role}"));
    }
    Ok(decoded)
}

fn embedded_json_artifact<T: for<'de> serde::Deserialize<'de>>(
    node: &ProofRoomEmbeddedEvidenceNode,
    artifacts: &BTreeMap<String, Vec<u8>>,
    expected_schema: &str,
    label: &str,
) -> Result<T, String> {
    let bytes = embedded_artifact_node_bytes(node, artifacts, expected_schema, label)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("{label} artifact JSON invalid for {}: {error}", node.path))
}

fn embedded_commerce_order_bundle(
    evidence_graph_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<chio_commerce_order::CommerceOrderVerificationBundle, String> {
    let graph = parse_embedded_evidence_graph(evidence_graph_bytes, "commerce evidence graph")?;
    let order_context: chio_commerce_order::CommerceOrderContext = embedded_commerce_json_artifact(
        &graph.nodes,
        artifacts,
        "commerce-order-context",
        chio_commerce_order::COMMERCE_ORDER_CONTEXT_SCHEMA_ID,
    )?;
    let event_log_bytes = embedded_single_role_artifact_bytes(
        &graph.nodes,
        artifacts,
        "commerce-event-log",
        chio_commerce_order::COMMERCE_EVENT_LOG_SCHEMA_ID,
        "commerce",
    )?;
    let payment_lifecycle_bytes = embedded_single_role_artifact_bytes(
        &graph.nodes,
        artifacts,
        "commerce-payment-lifecycle",
        chio_commerce_order::COMMERCE_PAYMENT_LIFECYCLE_SCHEMA_ID,
        "commerce",
    )?;
    let mandate_ledger_bytes = embedded_single_role_artifact_bytes(
        &graph.nodes,
        artifacts,
        "commerce-mandate-allowance-ledger",
        chio_commerce_order::COMMERCE_MANDATE_ALLOWANCE_LEDGER_SCHEMA_ID,
        "commerce",
    )?;

    Ok(chio_commerce_order::CommerceOrderVerificationBundle {
        order_context,
        event_log_bytes,
        payment_lifecycle_bytes,
        mandate_ledger_bytes,
    })
}

fn embedded_commerce_json_artifact<T: for<'de> serde::Deserialize<'de>>(
    nodes: &[ProofRoomEmbeddedEvidenceNode],
    artifacts: &BTreeMap<String, Vec<u8>>,
    role: &str,
    expected_schema: &str,
) -> Result<T, String> {
    let bytes =
        embedded_single_role_artifact_bytes(nodes, artifacts, role, expected_schema, "commerce")?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("commerce artifact JSON invalid for {role}: {error}"))
}

fn embedded_disclosure_lineage_bundle(
    evidence_graph_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<chio_disclosure_lineage::DisclosureLineageBundle, String> {
    let graph =
        parse_embedded_evidence_graph(evidence_graph_bytes, "disclosure lineage evidence graph")?;
    let capsule: chio_disclosure_lineage::DisclosureCapsule = embedded_required_json_artifact(
        &graph.nodes,
        artifacts,
        "disclosure-capsule",
        chio_disclosure_lineage::DISCLOSURE_CAPSULE_SCHEMA_V1,
        "disclosure lineage",
    )?;
    let lineage: chio_disclosure_lineage::SignedLineageSubgraph = embedded_required_json_artifact(
        &graph.nodes,
        artifacts,
        "signed-lineage-subgraph",
        chio_disclosure_lineage::LINEAGE_SIGNED_SUBGRAPH_SCHEMA_V1,
        "disclosure lineage",
    )?;
    let leakage_ledger: chio_disclosure_lineage::DisclosureLeakageLedger =
        embedded_required_json_artifact(
            &graph.nodes,
            artifacts,
            "disclosure-leakage-ledger",
            chio_disclosure_lineage::DISCLOSURE_LEAKAGE_LEDGER_SCHEMA_V1,
            "disclosure lineage",
        )?;
    let crypto_context_report: Option<chio_disclosure_lineage::DisclosureCryptoContextReport> =
        embedded_optional_json_artifact(
            &graph.nodes,
            artifacts,
            "disclosure-crypto-context-report",
            chio_disclosure_lineage::DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1,
            "disclosure lineage",
        )?;

    Ok(chio_disclosure_lineage::DisclosureLineageBundle {
        capsule,
        lineage,
        leakage_ledger,
        crypto_context_report,
    })
}

fn embedded_runtime_artifacts(
    evidence_graph_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let graph = parse_embedded_evidence_graph(evidence_graph_bytes, "runtime evidence graph")?;
    let mut runtime_artifacts = BTreeMap::new();
    for node in graph
        .nodes
        .iter()
        .filter(|node| is_runtime_artifact_role(&node.role))
    {
        let bytes = artifacts
            .get(&node.path)
            .ok_or_else(|| format!("missing runtime artifact: {}", node.path))?;
        runtime_artifacts.insert(node.path.clone(), bytes.clone());
    }
    if runtime_artifacts.is_empty() {
        return Err("missing runtime evidence artifacts".to_string());
    }
    Ok(runtime_artifacts)
}

fn is_runtime_artifact_role(role: &str) -> bool {
    matches!(
        role,
        "receipt"
            | "execution-lease"
            | "tool-server-ack"
            | "revocation-freshness-proof"
            | "sandbox-attestation"
    )
}

fn embedded_swarm_authority_bundle(
    evidence_graph_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<chio_swarm_authority::SwarmAuthorityBundle, String> {
    let graph = parse_embedded_evidence_graph(evidence_graph_bytes, "swarm evidence graph")?;
    let task_graph: chio_swarm_authority::SwarmTaskGraph = embedded_required_json_artifact(
        &graph.nodes,
        artifacts,
        "swarm-task-graph",
        chio_swarm_authority::CHIO_SWARM_TASK_GRAPH_SCHEMA,
        "swarm",
    )?;
    let budget_pool: chio_swarm_authority::SwarmBudgetPool = embedded_required_json_artifact(
        &graph.nodes,
        artifacts,
        "swarm-budget-pool",
        chio_swarm_authority::CHIO_SWARM_BUDGET_POOL_SCHEMA,
        "swarm",
    )?;
    let revocation_epoch: chio_swarm_authority::SwarmRevocationEpoch =
        embedded_required_json_artifact(
            &graph.nodes,
            artifacts,
            "swarm-revocation-epoch",
            chio_swarm_authority::CHIO_SWARM_REVOCATION_EPOCH_SCHEMA,
            "swarm",
        )?;
    let continuation_tokens: Vec<chio_swarm_authority::SwarmContinuationToken> =
        embedded_json_artifacts(
            &graph.nodes,
            artifacts,
            "swarm-continuation-token",
            chio_swarm_authority::CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA,
            "swarm",
        )?;
    let witness_chains: Vec<chio_swarm_authority::SwarmDelegationWitnessChain> =
        embedded_json_artifacts(
            &graph.nodes,
            artifacts,
            "swarm-delegation-witness-chain",
            chio_swarm_authority::CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA,
            "swarm",
        )?;
    let join_receipts: Vec<chio_swarm_authority::SwarmJoinReceipt> = embedded_json_artifacts(
        &graph.nodes,
        artifacts,
        "swarm-join-receipt",
        chio_swarm_authority::CHIO_SWARM_JOIN_RECEIPT_SCHEMA,
        "swarm",
    )?;
    let route_plan_receipts: Vec<chio_swarm_authority::SwarmRoutePlanReceipt> =
        embedded_json_artifacts(
            &graph.nodes,
            artifacts,
            "swarm-route-plan-receipt",
            chio_swarm_authority::CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA,
            "swarm",
        )?;

    Ok(chio_swarm_authority::SwarmAuthorityBundle {
        now_unix_ms: task_graph.created_at_unix_ms.saturating_add(1_000),
        task_graph,
        continuation_tokens,
        witness_chains,
        join_receipts,
        route_plan_receipts,
        budget_pool,
        revocation_epoch,
    })
}

fn embedded_public_settlement_proof_bundle(
    evidence_graph_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<chio_web3::settlement_proof::PublicSettlementProofBundle, String> {
    let graph =
        parse_embedded_evidence_graph(evidence_graph_bytes, "public settlement evidence graph")?;
    let bytes = embedded_single_role_artifact_bytes(
        &graph.nodes,
        artifacts,
        "public-settlement-proof-bundle",
        chio_web3::settlement_proof::CHIO_WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA,
        "public settlement",
    )?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("public settlement proof bundle JSON invalid: {error}"))
}

fn embedded_fixture_file(
    fixture_root: &str,
    asset_path: &str,
    fixture_id: &str,
) -> Result<&'static [u8], (StatusCode, String)> {
    validate_fixture_asset_path(asset_path)?;
    let embedded_path = format!("{fixture_root}/{asset_path}");
    EMBEDDED_PROOF_FIXTURE_FILES
        .iter()
        .find(|file| file.path == embedded_path)
        .map(|file| file.contents)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("proof-room.fixture.asset-not-found: {fixture_id}/{asset_path}"),
            )
        })
}

fn embedded_fixture_artifact_map(fixture_root: &str) -> BTreeMap<String, Vec<u8>> {
    let prefix = format!("{fixture_root}/");
    EMBEDDED_PROOF_FIXTURE_FILES
        .iter()
        .filter_map(|file| {
            let relative_path = file.path.strip_prefix(&prefix)?;
            Some((relative_path.to_string(), file.contents.to_vec()))
        })
        .collect()
}

fn embedded_fixture_has_files(fixture_root: &str) -> bool {
    let prefix = format!("{fixture_root}/");
    EMBEDDED_PROOF_FIXTURE_FILES
        .iter()
        .any(|file| file.path.starts_with(&prefix))
}

fn available_fixture_descriptor(
    fixture_id: &str,
    installed_fixture_root: Option<&Path>,
) -> Result<ProofRoomAvailableFixture, (StatusCode, String)> {
    validate_fixture_id(fixture_id)?;
    parse_available_proof_fixtures_with_root(installed_fixture_root)
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?
        .into_iter()
        .find(|fixture| fixture.id == fixture_id)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("proof-room.fixture.unknown: {fixture_id}"),
            )
        })
}

fn available_fixture_embedded_root(
    fixture: &ProofRoomAvailableFixture,
) -> Result<String, (StatusCode, String)> {
    fixture
        .path
        .strip_prefix("fixtures/proof-room/")
        .filter(|relative_path| validate_fixture_asset_path(relative_path).is_ok())
        .map(str::to_string)
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("proof-room.fixture.catalog-path-invalid: {}", fixture.path),
            )
        })
}

fn validate_fixture_id(fixture_id: &str) -> Result<(), (StatusCode, String)> {
    if fixture_id.is_empty()
        || fixture_id.contains('/')
        || fixture_id.contains('\\')
        || fixture_id == "."
        || fixture_id == ".."
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("proof-room.fixture.id-invalid: {fixture_id}"),
        ));
    }
    Ok(())
}

fn validate_fixture_asset_path(asset_path: &str) -> Result<&str, (StatusCode, String)> {
    if asset_path.is_empty() || asset_path.starts_with('/') || asset_path.contains('\\') {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("proof-room.fixture.asset-path-invalid: {asset_path}"),
        ));
    }
    if asset_path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("proof-room.fixture.asset-path-invalid: {asset_path}"),
        ));
    }
    Ok(asset_path)
}

fn fixture_asset_content_type(asset_path: &str) -> &'static str {
    if asset_path.ends_with(".json") {
        "application/json"
    } else if asset_path.ends_with(".md") {
        "text/markdown; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

fn build_proof_room_fixture_catalog(
    bundle: &Path,
    installed_fixture_root: Option<&Path>,
) -> Result<ProofRoomFixtureCatalog, String> {
    let manifest_path = bundle.join("manifest.json");
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|error| format!("proof-room.catalog.manifest: {error}"))?;
    let manifest: ProofRoomBundleManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("proof-room.catalog.manifest-json: {error}"))?;
    let load_report_path = manifest
        .proof_room_verifier_report_ref
        .as_ref()
        .map(|reference| reference.path.clone())
        .unwrap_or_else(|| "ui/proof-room-static/load-report.json".to_string());
    let resolved_load_report_path = resolve_proof_room_bundle_path(bundle, &load_report_path)?;
    let load_report_bytes = fs::read(&resolved_load_report_path)
        .map_err(|error| format!("proof-room.catalog.load-report: {error}"))?;
    let load_report: ProofRoomCatalogLoadReport = serde_json::from_slice(&load_report_bytes)
        .map_err(|error| format!("proof-room.catalog.load-report-json: {error}"))?;
    let negative_cases = manifest
        .negative_cases
        .into_iter()
        .map(|negative_case| ProofRoomFixtureCatalogNegativeCase {
            id: negative_case.id,
            path: negative_case.path,
            expected_failure_code: negative_case.expected_failure_code,
            observed_failure_code: negative_case.observed_failure_code,
        })
        .collect();

    Ok(ProofRoomFixtureCatalog {
        schema: "chio.proof-room.fixture-catalog.v1",
        fixtures: vec![ProofRoomFixtureCatalogEntry {
            fixture_id: manifest.fixture_id,
            bundle_id: manifest.bundle_id,
            verdict: load_report.verdict,
            manifest_path: "manifest.json",
            load_report_path,
            negative_cases,
        }],
        available_fixtures: available_proof_fixtures_with_reports(installed_fixture_root)?,
    })
}

fn available_proof_fixtures_with_reports(
    installed_fixture_root: Option<&Path>,
) -> Result<Vec<ProofRoomAvailableFixture>, String> {
    let fixtures = parse_available_proof_fixtures_with_root(installed_fixture_root)?
        .into_iter()
        .filter(|fixture| {
            installed_fixture_root.is_some() || available_fixture_embedded_assets_exist(fixture)
        })
        .collect::<Vec<_>>();
    let mut negative_cases =
        available_fixture_negative_cases_by_fixture(&fixtures, installed_fixture_root)?;
    fixtures
        .into_iter()
        .map(|mut fixture| {
            if fixture.kind == "transaction-passport" {
                fixture.negative_cases = negative_cases.remove(&fixture.id).unwrap_or_default();
            } else if fixture.kind == "proof-room" {
                fixture.negative_cases =
                    available_proof_room_fixture_negative_cases(&fixture, installed_fixture_root)?;
            }
            fixture.verifier_report = Some(proof_room_available_fixture_report_for_fixture(
                &fixture,
                installed_fixture_root,
            ));
            Ok(fixture)
        })
        .collect()
}

fn available_proof_room_fixture_negative_cases(
    fixture: &ProofRoomAvailableFixture,
    installed_fixture_root: Option<&Path>,
) -> Result<Vec<ProofRoomFixtureCatalogNegativeCase>, String> {
    let source = ProofRoomFixtureSource::new(fixture, installed_fixture_root)
        .map_err(|(_status, error)| error)?;
    let manifest_bytes = match source.file("proof-room-bundle/manifest.json", &fixture.id) {
        Ok(bytes) => bytes,
        Err((StatusCode::NOT_FOUND, _error)) => return Ok(Vec::new()),
        Err((_status, error)) => return Err(error),
    };
    let manifest: ProofRoomBundleManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|error| {
            format!(
                "proof-room.fixture.manifest-invalid: {}: {error}",
                fixture.id
            )
        })?;

    manifest
        .negative_cases
        .into_iter()
        .map(|negative_case| {
            let path = format!("proof-room-bundle/{}", negative_case.path);
            validate_fixture_asset_path(&path).map_err(|(_status, error)| error)?;
            Ok(ProofRoomFixtureCatalogNegativeCase {
                id: negative_case.id,
                path,
                expected_failure_code: negative_case.expected_failure_code,
                observed_failure_code: negative_case.observed_failure_code,
            })
        })
        .collect()
}

fn available_fixture_embedded_assets_exist(fixture: &ProofRoomAvailableFixture) -> bool {
    available_fixture_embedded_root(fixture)
        .map(|fixture_root| embedded_fixture_has_files(&fixture_root))
        .unwrap_or(false)
}

fn available_fixture_negative_cases_by_fixture(
    fixtures: &[ProofRoomAvailableFixture],
    installed_fixture_root: Option<&Path>,
) -> Result<BTreeMap<String, Vec<ProofRoomFixtureCatalogNegativeCase>>, String> {
    let positives = fixtures
        .iter()
        .filter(|fixture| fixture.kind == "transaction-passport")
        .collect::<Vec<_>>();
    let mut negative_cases = BTreeMap::new();

    for negative_fixture in fixtures
        .iter()
        .filter(|fixture| fixture.kind == "negative-transaction-passport")
    {
        let Some(descriptor) =
            available_fixture_negative_descriptor(negative_fixture, installed_fixture_root)?
        else {
            continue;
        };
        let Some(base_fixture_path) = descriptor.base_fixture.as_deref() else {
            continue;
        };
        let Some(base_fixture) = positives
            .iter()
            .find(|fixture| descriptor_base_matches_fixture(base_fixture_path, fixture))
        else {
            continue;
        };
        negative_cases
            .entry(base_fixture.id.clone())
            .or_insert_with(Vec::new)
            .push(available_fixture_catalog_negative_case(
                negative_fixture,
                &descriptor,
                installed_fixture_root,
            ));
    }

    Ok(negative_cases)
}

fn descriptor_base_matches_fixture(
    descriptor_base_fixture: &str,
    fixture: &ProofRoomAvailableFixture,
) -> bool {
    descriptor_base_fixture
        .strip_prefix(&fixture.path)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

fn available_fixture_negative_descriptor(
    fixture: &ProofRoomAvailableFixture,
    installed_fixture_root: Option<&Path>,
) -> Result<Option<ProofRoomAvailableFixtureNegativeDescriptor>, String> {
    let descriptor_path = available_fixture_negative_descriptor_path(fixture)?;
    let descriptor_bytes = match installed_fixture_root {
        Some(root) => {
            installed_available_fixture_descriptor_bytes(root, fixture, &descriptor_path)?
        }
        None => match embedded_fixture_file_bytes(&descriptor_path) {
            Some(bytes) => bytes.to_vec(),
            None => return Ok(None),
        },
    };
    serde_json::from_slice(&descriptor_bytes)
        .map(Some)
        .map_err(|error| {
            format!(
                "proof-room.fixture.negative-descriptor-invalid: {}: {}: {error}",
                fixture.id, descriptor_path
            )
        })
}

fn installed_available_fixture_descriptor_bytes(
    installed_fixture_root: &Path,
    fixture: &ProofRoomAvailableFixture,
    descriptor_path: &str,
) -> Result<Vec<u8>, String> {
    let root = fs::canonicalize(installed_fixture_root).map_err(|error| {
        format!(
            "proof-room.fixture.root-unreadable: {}: {error}",
            fixture.id
        )
    })?;
    validate_fixture_asset_path(descriptor_path).map_err(|(_status, error)| error)?;
    let path = fs::canonicalize(root.join(descriptor_path)).map_err(|error| {
        format!(
            "proof-room.fixture.negative-descriptor-missing: {}: {}: {error}",
            fixture.id, descriptor_path
        )
    })?;
    if !path.starts_with(&root) {
        return Err(format!(
            "proof-room.fixture.negative-descriptor-path-escape: {}: {}",
            fixture.id, descriptor_path
        ));
    }
    let metadata = fs::metadata(&path).map_err(|error| {
        format!(
            "proof-room.fixture.negative-descriptor-missing: {}: {}: {error}",
            fixture.id, descriptor_path
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "proof-room.fixture.negative-descriptor-missing: {}: {}",
            fixture.id, descriptor_path
        ));
    }
    fs::read(&path).map_err(|error| {
        format!(
            "proof-room.fixture.negative-descriptor-missing: {}: {}: {error}",
            fixture.id, descriptor_path
        )
    })
}

fn available_fixture_negative_descriptor_path(
    fixture: &ProofRoomAvailableFixture,
) -> Result<String, String> {
    let relative_path = fixture
        .path
        .strip_prefix("fixtures/proof-room/")
        .ok_or_else(|| format!("proof-room.fixture.catalog-path-invalid: {}", fixture.path))?;
    let (fixture_family, fixture_leaf) = relative_path.rsplit_once('/').ok_or_else(|| {
        format!(
            "proof-room.fixture.catalog-path-missing-family: {}",
            fixture.path
        )
    })?;
    let descriptor_path = format!("{fixture_family}/negatives/{fixture_leaf}.json");
    let descriptor_path = validate_fixture_asset_path(&descriptor_path)
        .map_err(|(_status, error)| error)?
        .to_string();
    Ok(descriptor_path)
}

fn embedded_fixture_file_bytes(path: &str) -> Option<&'static [u8]> {
    EMBEDDED_PROOF_FIXTURE_FILES
        .iter()
        .find(|file| file.path == path)
        .map(|file| file.contents)
}

fn available_fixture_catalog_negative_case(
    fixture: &ProofRoomAvailableFixture,
    descriptor: &ProofRoomAvailableFixtureNegativeDescriptor,
    installed_fixture_root: Option<&Path>,
) -> ProofRoomFixtureCatalogNegativeCase {
    let report = proof_room_available_fixture_report(&fixture.id, installed_fixture_root);
    let observed_failure_code = available_fixture_observed_failure_code(&fixture.id, &report);
    ProofRoomFixtureCatalogNegativeCase {
        id: fixture.id.clone(),
        path: "transaction-passport.json".to_string(),
        expected_failure_code: descriptor.expected_failure_code.clone(),
        observed_failure_code,
    }
}

fn available_fixture_observed_failure_code(
    fixture_id: &str,
    report: &ProofRoomAvailableFixtureReport,
) -> Option<String> {
    report
        .error
        .as_deref()
        .map(|error| fixture_verifier_domain_error(fixture_id, error).to_string())
        .or_else(|| report.failure_code.clone())
}

fn fixture_verifier_domain_error<'a>(fixture_id: &str, error: &'a str) -> &'a str {
    let prefix = format!("proof-room.fixture.verify-failed: {fixture_id}: ");
    error.strip_prefix(&prefix).unwrap_or(error)
}

fn proof_room_available_fixture_report(
    fixture_id: &str,
    installed_fixture_root: Option<&Path>,
) -> ProofRoomAvailableFixtureReport {
    let path = format!("/proof-room-fixtures/{fixture_id}/verifier-report.json");
    match proof_room_fixture_asset_with_root(
        fixture_id,
        "verifier-report.json",
        installed_fixture_root,
    ) {
        Ok((contents, _content_type)) => {
            proof_room_available_fixture_report_from_contents(path, &contents)
        }
        Err((status, error)) => ProofRoomAvailableFixtureReport {
            path,
            status: status.as_u16(),
            verdict: "failed".to_string(),
            failure_code: Some(proof_room_fixture_failure_code(&error).to_string()),
            error: Some(error),
        },
    }
}

fn proof_room_available_fixture_report_for_fixture(
    fixture: &ProofRoomAvailableFixture,
    installed_fixture_root: Option<&Path>,
) -> ProofRoomAvailableFixtureReport {
    let report = proof_room_available_fixture_report(&fixture.id, installed_fixture_root);
    if fixture.kind != "proof-room" || report.verdict != "verified" {
        return report;
    }
    match verify_available_proof_room_fixture_bundle(fixture, installed_fixture_root) {
        Ok(()) => report,
        Err(error) => {
            let error = format!("proof-room.fixture.verify-failed: {}: {error}", fixture.id);
            ProofRoomAvailableFixtureReport {
                path: report.path,
                status: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                verdict: "failed".to_string(),
                failure_code: Some(proof_room_fixture_failure_code(&error).to_string()),
                error: Some(error),
            }
        }
    }
}

fn verify_available_proof_room_fixture_bundle(
    fixture: &ProofRoomAvailableFixture,
    installed_fixture_root: Option<&Path>,
) -> Result<(), String> {
    let source = ProofRoomFixtureSource::new(fixture, installed_fixture_root)
        .map_err(|(_status, error)| error)?;
    let Some(manifest_path) = source
        .installed_file_path("proof-room-bundle/manifest.json", &fixture.id)
        .map_err(|(_status, error)| error)?
    else {
        return Ok(());
    };
    verify_proof_room_bundle_inner_with_options(&manifest_path, false, true)
}

fn proof_room_available_fixture_report_from_contents(
    path: String,
    contents: &[u8],
) -> ProofRoomAvailableFixtureReport {
    let report = match serde_json::from_slice::<serde_json::Value>(contents) {
        Ok(report) => report,
        Err(error) => {
            return ProofRoomAvailableFixtureReport {
                path,
                status: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                verdict: "failed".to_string(),
                failure_code: Some("proof-room.fixture.report-invalid".to_string()),
                error: Some(format!("proof-room.fixture.report-invalid: {error}")),
            };
        }
    };

    let Some(verdict) = proof_room_fixture_report_string(&report, "verdict") else {
        return ProofRoomAvailableFixtureReport {
            path,
            status: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
            verdict: "failed".to_string(),
            failure_code: Some("proof-room.fixture.report-verdict-missing".to_string()),
            error: Some("proof-room.fixture.report-verdict-missing".to_string()),
        };
    };

    ProofRoomAvailableFixtureReport {
        path,
        status: proof_room_fixture_status_for_verdict(&verdict).as_u16(),
        verdict,
        failure_code: proof_room_fixture_report_string(&report, "failure_code"),
        error: proof_room_fixture_report_string(&report, "error"),
    }
}

pub fn proof_room_fixture_report_status(contents: &[u8]) -> StatusCode {
    let Ok(report) = serde_json::from_slice::<serde_json::Value>(contents) else {
        return StatusCode::UNPROCESSABLE_ENTITY;
    };
    let Some(verdict) = proof_room_fixture_report_string(&report, "verdict") else {
        return StatusCode::UNPROCESSABLE_ENTITY;
    };
    proof_room_fixture_status_for_verdict(&verdict)
}

fn proof_room_fixture_status_for_verdict(verdict: &str) -> StatusCode {
    if verdict == "failed" {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    }
}

fn proof_room_fixture_report_string(report: &serde_json::Value, field: &str) -> Option<String> {
    report
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn parse_available_proof_fixtures() -> Result<Vec<ProofRoomAvailableFixture>, String> {
    let catalog: ProofRoomAvailableFixtureCatalog =
        serde_json::from_str(PROOF_FIXTURE_CATALOG_JSON)
            .map_err(|error| format!("proof-room.catalog.available-fixtures-json: {error}"))?;
    parse_available_fixture_catalog(catalog)
}

fn parse_available_proof_fixtures_with_root(
    installed_fixture_root: Option<&Path>,
) -> Result<Vec<ProofRoomAvailableFixture>, String> {
    if let Some(root) = installed_fixture_root {
        if let Some(fixtures) = parse_installed_available_proof_fixtures(root)? {
            return Ok(fixtures);
        }
    }
    parse_available_proof_fixtures()
}

fn parse_installed_available_proof_fixtures(
    installed_fixture_root: &Path,
) -> Result<Option<Vec<ProofRoomAvailableFixture>>, String> {
    let catalog_path = installed_fixture_root.join("catalog.json");
    let catalog_bytes = match fs::read(&catalog_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "proof-room.catalog.available-fixtures-file: {}: {error}",
                catalog_path.display()
            ));
        }
    };
    let catalog: ProofRoomAvailableFixtureCatalog = serde_json::from_slice(&catalog_bytes)
        .map_err(|error| {
            format!(
                "proof-room.catalog.available-fixtures-json: {}: {error}",
                catalog_path.display()
            )
        })?;
    parse_available_fixture_catalog(catalog).map(Some)
}

fn parse_available_fixture_catalog(
    catalog: ProofRoomAvailableFixtureCatalog,
) -> Result<Vec<ProofRoomAvailableFixture>, String> {
    if catalog.schema != PROOF_FIXTURE_CATALOG_SCHEMA {
        return Err(format!(
            "proof-room.catalog.available-fixtures-schema: {}",
            catalog.schema
        ));
    }
    for fixture in &catalog.fixtures {
        validate_fixture_id(&fixture.id).map_err(|(_status, error)| error)?;
        available_fixture_embedded_root(fixture).map_err(|(_status, error)| error)?;
    }
    Ok(catalog.fixtures)
}

fn verify_proof_room_bundle_inner(manifest_path: &Path) -> Result<(), String> {
    verify_proof_room_bundle_inner_with_options(manifest_path, true, true)
}

fn verify_proof_room_bundle_inner_with_options(
    manifest_path: &Path,
    verify_manifest_negative_cases: bool,
    verify_manifest_signature: bool,
) -> Result<(), String> {
    let bundle_root = manifest_path
        .parent()
        .ok_or_else(|| "proof-room.bundle.path-invalid: manifest has no parent".to_string())?;
    validate_bundle_tree_file_types(bundle_root)?;

    let manifest_bytes =
        fs::read(manifest_path).map_err(|error| format!("missing or unreadable: {error}"))?;
    let manifest_value: serde_json::Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("invalid Proof Room manifest JSON: {error}"))?;
    validate_proof_room_schema(&manifest_value, PROOF_ROOM_BUNDLE_SCHEMA_JSON, "manifest")?;
    let manifest: ProofRoomBundleManifest = serde_json::from_value(manifest_value)
        .map_err(|error| format!("invalid Proof Room manifest JSON: {error}"))?;
    if manifest.schema != PROOF_ROOM_BUNDLE_SCHEMA {
        return Err(format!(
            "proof-room.bundle.schema-mismatch: expected {PROOF_ROOM_BUNDLE_SCHEMA}"
        ));
    }
    if manifest.hash_algorithm != "sha256" {
        return Err("proof-room.hash.unsupported: expected sha256".to_string());
    }
    let requires_first_run_claims = manifest.fixture_id == "single-call-authority";

    if verify_manifest_signature {
        verify_bundle_signature(bundle_root, &manifest, &manifest_bytes)?;
    }
    let transaction_passport = verify_manifest_ref(
        bundle_root,
        &manifest.transaction_passport_ref,
        "transaction_passport_ref",
        Some("chio.transaction-passport.v1"),
    )?;
    let evidence_graph = verify_manifest_ref(
        bundle_root,
        &manifest.evidence_graph_ref,
        "evidence_graph_ref",
        Some("chio.transaction.evidence-graph.v1"),
    )?;
    let has_authority_claim =
        has_claim(&manifest.claims, CLAIM_PROOF_ROOM_AUTHORITY_EVIDENCE_BOUND);
    let requires_authority_evidence = requires_first_run_claims || has_authority_claim;
    if requires_authority_evidence {
        verify_first_run_authority_evidence(bundle_root, &manifest.claims, &manifest.artifacts)?;
        verify_first_run_evidence_graph_binding(&evidence_graph.bytes, &manifest.artifacts)?;
    }
    let verifier_report = verify_manifest_ref(
        bundle_root,
        &manifest.verifier_report_ref,
        "verifier_report_ref",
        Some("chio.transaction.verifier-report.v1"),
    )?;
    let verifier_report_value: serde_json::Value =
        serde_json::from_slice(&verifier_report.bytes)
            .map_err(|error| format!("proof-room.report.invalid-json: {error}"))?;
    verify_source_verifier_report(bundle_root, &transaction_passport, &verifier_report_value)?;
    verify_manifest_claims(
        &manifest.claims,
        &manifest.artifacts,
        &manifest.verifier_report_ref,
        manifest.proof_room_verifier_report_ref.as_ref(),
        &verifier_report_value,
        requires_first_run_claims,
    )?;
    let has_receipt_matrix_claim = has_claim(
        &manifest.claims,
        CLAIM_PROOF_ROOM_RECEIPT_COVERAGE_MATRIX_BOUND,
    );
    receipt_coverage::verify(
        bundle_root,
        &manifest.receipt_coverage,
        &manifest.artifacts,
        requires_first_run_claims || has_receipt_matrix_claim,
    )?;
    if verify_manifest_negative_cases {
        verify_negative_cases(
            bundle_root,
            &manifest.negative_cases,
            requires_first_run_claims,
        )?;
    }
    let source_verifier_verdict = verifier_report_value
        .get("verdict")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "proof-room.report.verdict-missing".to_string())?;
    let proof_room_report_path = manifest
        .proof_room_verifier_report_ref
        .as_ref()
        .map(|reference| reference.path.as_str());
    for artifact in &manifest.artifacts {
        let label = if proof_room_report_path == Some(artifact.path.as_str())
            && artifact.schema == PROOF_ROOM_VERIFIER_REPORT_SCHEMA
        {
            "ui-report"
        } else {
            "artifact"
        };
        verify_manifest_ref(bundle_root, artifact, label, None)?;
    }
    if let Some(proof_room_report_ref) = &manifest.proof_room_verifier_report_ref {
        let proof_room_report = verify_manifest_ref(
            bundle_root,
            proof_room_report_ref,
            "proof_room_verifier_report_ref",
            Some(PROOF_ROOM_VERIFIER_REPORT_SCHEMA),
        )?;
        verify_proof_room_report(
            &proof_room_report.bytes,
            &manifest.bundle_id,
            &manifest.fixture_id,
            &manifest.verifier_report_ref,
            source_verifier_verdict,
            &manifest.claims,
        )?;
    }

    Ok(())
}

fn write_doctor_report(path: &Path, bundle: &Path) -> Result<(), ProofRoomError> {
    let manifest_path = bundle.join("manifest.json");
    let manifest_bytes = fs::read(&manifest_path).map_err(|source| ProofRoomError::Io {
        context: "proof-room.doctor-report.manifest-read",
        source,
    })?;
    let manifest: ProofRoomBundleManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|source| ProofRoomError::Json {
            context: "proof-room.doctor-report.manifest-json",
            source,
        })?;
    let report = ProofRoomDoctorReport {
        schema: "chio.proof-room.quickstart-doctor-report.v1",
        verdict: "verified",
        bundle: &bundle.to_string_lossy(),
        bundle_id: &manifest.bundle_id,
        fixture_id: &manifest.fixture_id,
        verifier_report_ref: &manifest.verifier_report_ref,
        receipt_coverage: &manifest.receipt_coverage,
        negative_cases: &manifest.negative_cases,
    };
    let bytes = serde_json::to_vec_pretty(&report).map_err(|source| ProofRoomError::Json {
        context: "proof-room.doctor-report.encode",
        source,
    })?;
    fs::write(path, bytes).map_err(|source| ProofRoomError::Io {
        context: "proof-room.doctor-report.write",
        source,
    })
}

fn verify_negative_cases(
    bundle_root: &Path,
    negative_cases: &[ProofRoomNegativeCase],
    require_cases: bool,
) -> Result<(), String> {
    if negative_cases.is_empty() {
        return if require_cases {
            Err("proof-room.negative-case.missing".to_string())
        } else {
            Ok(())
        };
    }
    let mut ids = BTreeSet::new();
    for negative_case in negative_cases {
        if negative_case.id.is_empty() {
            return Err("proof-room.negative-case.id-missing".to_string());
        }
        if !ids.insert(negative_case.id.as_str()) {
            return Err(format!(
                "proof-room.negative-case.duplicate: {}",
                negative_case.id
            ));
        }
        if negative_case.path.is_empty() {
            return Err(format!(
                "proof-room.negative-case.path-missing: {}",
                negative_case.id
            ));
        }
        if negative_case.expected_failure_code.is_empty() {
            return Err(format!(
                "proof-room.negative-case.expected-failure-missing: {}",
                negative_case.id
            ));
        }
        let negative_path = resolve_proof_room_bundle_path(bundle_root, &negative_case.path)?;
        let error = match verify_negative_case_path(bundle_root, &negative_path, negative_case) {
            Ok(()) => {
                return Err(format!(
                    "proof-room.negative-case.unexpected-success: {}",
                    negative_case.id
                ));
            }
            Err(error) => error,
        };
        if !negative_failure_code_matches(&error, &negative_case.expected_failure_code) {
            return Err(format!(
                "proof-room.negative-case.failure-mismatch: {} expected {} got {error}",
                negative_case.id, negative_case.expected_failure_code
            ));
        }
        if let Some(observed_failure_code) = negative_case.observed_failure_code.as_deref() {
            if observed_failure_code.is_empty() {
                return Err(format!(
                    "proof-room.negative-case.observed-failure-missing: {}",
                    negative_case.id
                ));
            }
            if !negative_failure_code_matches(&error, observed_failure_code) {
                return Err(format!(
                    "proof-room.negative-case.observed-failure-mismatch: {} expected {} got {error}",
                    negative_case.id, observed_failure_code
                ));
            }
        }
    }
    Ok(())
}

fn negative_failure_code_matches(error: &str, expected_code: &str) -> bool {
    error.match_indices(expected_code).any(|(index, _)| {
        let before = error[..index].chars().next_back();
        let after = error[index + expected_code.len()..].chars().next();
        negative_failure_code_start_boundary(before) && negative_failure_code_end_boundary(after)
    })
}

fn negative_failure_code_start_boundary(boundary: Option<char>) -> bool {
    boundary.is_none_or(|character| character == ':' || character.is_ascii_whitespace())
}

fn negative_failure_code_end_boundary(boundary: Option<char>) -> bool {
    boundary.is_none_or(|character| character == ':')
}

fn verify_negative_case_path(
    bundle_root: &Path,
    negative_path: &Path,
    negative_case: &ProofRoomNegativeCase,
) -> Result<(), String> {
    let bytes = fs::read(negative_path)
        .map_err(|error| format!("proof-room.negative-case.unreadable: {error}"))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("proof-room.negative-case.invalid-json: {error}"))?;
    if value.get("mutation").is_some() {
        let descriptor: ProofRoomNegativeDescriptor = serde_json::from_value(value)
            .map_err(|error| format!("proof-room.negative-case.descriptor-invalid: {error}"))?;
        verify_proof_room_negative_descriptor(bundle_root, &descriptor, negative_case)
    } else {
        verify_negative_transaction_passport(negative_path).map(|_| ())
    }
}

fn verify_proof_room_negative_descriptor(
    bundle_root: &Path,
    descriptor: &ProofRoomNegativeDescriptor,
    negative_case: &ProofRoomNegativeCase,
) -> Result<(), String> {
    if !descriptor.schema.is_empty() && descriptor.schema != "chio.proof-room.negative-fixture.v1" {
        return Err(format!(
            "proof-room.negative-case.descriptor-schema-unsupported: {}",
            descriptor.schema
        ));
    }
    if descriptor.id != negative_case.id {
        return Err(format!(
            "proof-room.negative-case.descriptor-id-mismatch: {}",
            negative_case.id
        ));
    }
    if descriptor.expected_failure_code != negative_case.expected_failure_code {
        return Err(format!(
            "proof-room.negative-case.descriptor-expected-failure-mismatch: {}",
            negative_case.id
        ));
    }

    let work = create_negative_case_work_dir(&negative_case.id)?;
    let result = (|| {
        copy_dir_all(bundle_root, &work)?;
        apply_proof_room_negative_descriptor(&work, descriptor)?;
        let manifest_path = resolve_proof_room_bundle_path(&work, &descriptor.base_manifest)?;
        verify_proof_room_bundle_inner_with_options(&manifest_path, false, false)
    })();
    let _ = fs::remove_dir_all(&work);
    result
}

fn verify_negative_transaction_passport(path: &Path) -> Result<(), String> {
    let bundle_root = path
        .parent()
        .ok_or_else(|| "proof-room.negative-case.path-invalid".to_string())?;
    verify_transaction_passport_family_report(bundle_root, path).map(|_| ())
}

fn verify_manifest_claims(
    claims: &[ProofRoomClaim],
    artifacts: &[ProofRoomArtifactRef],
    verifier_report_ref: &ProofRoomArtifactRef,
    proof_room_report_ref: Option<&ProofRoomArtifactRef>,
    source_report: &serde_json::Value,
    require_first_run_claims: bool,
) -> Result<(), String> {
    if claims.is_empty() {
        return Err("proof-room.claim.missing: manifest has no claims".to_string());
    }
    let artifact_paths = artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect::<BTreeSet<_>>();
    for claim in claims {
        if !ALLOWED_BUNDLE_CLAIMS.contains(&claim.claim_id.as_str())
            && !source_report_verifies_claim(source_report, &claim.claim_id)
        {
            return Err(format!("proof-room.claim.unregistered: {}", claim.claim_id));
        }
        if claim.required_artifacts.is_empty() {
            return Err(format!(
                "proof-room.claim.required-artifacts-missing: {}",
                claim.claim_id
            ));
        }
        for artifact_path in &claim.required_artifacts {
            if !artifact_paths.contains(artifact_path.as_str()) {
                return Err(format!(
                    "proof-room.claim.required-artifact-missing: {} -> {}",
                    claim.claim_id, artifact_path
                ));
            }
        }
        match claim.claim_id.as_str() {
            CLAIM_PROOF_ROOM_VERIFIER_REPORT_BOUND => {
                require_claim_artifact(
                    claim,
                    &verifier_report_ref.path,
                    "proof-room.report.claim-source-missing",
                )?;
                if let Some(proof_room_report_ref) = proof_room_report_ref {
                    require_claim_artifact(
                        claim,
                        &proof_room_report_ref.path,
                        "proof-room.ui-report.claim-source-missing",
                    )?;
                }
            }
            CLAIM_PROOF_ROOM_ALLOW_AND_DENY_VISIBLE => {
                require_claim_artifact(
                    claim,
                    "artifacts/receipts/allow-receipt.json",
                    "proof-room.first-run.allow-missing",
                )?;
                require_claim_artifact(
                    claim,
                    "artifacts/receipts/denial-receipt.json",
                    "proof-room.first-run.denial-missing",
                )?;
            }
            _ => {}
        }
    }
    if !has_claim(claims, CLAIM_PROOF_ROOM_VERIFIER_REPORT_BOUND) {
        return Err(format!(
            "proof-room.claim.missing: {CLAIM_PROOF_ROOM_VERIFIER_REPORT_BOUND}"
        ));
    }
    if require_first_run_claims {
        for required_claim in REQUIRED_FIRST_RUN_PROOF_ROOM_CLAIMS {
            if !has_claim(claims, required_claim) {
                if *required_claim == CLAIM_PROOF_ROOM_AUTHORITY_EVIDENCE_BOUND {
                    return Err("proof-room.first-run.authority-evidence-missing".to_string());
                }
                return Err(format!("proof-room.claim.missing: {required_claim}"));
            }
        }
    }
    Ok(())
}

fn has_claim(claims: &[ProofRoomClaim], claim_id: &str) -> bool {
    claims.iter().any(|claim| claim.claim_id == claim_id)
}

fn source_report_verifies_claim(source_report: &serde_json::Value, claim_id: &str) -> bool {
    if source_report
        .get("verdict")
        .and_then(serde_json::Value::as_str)
        != Some("verified")
    {
        return false;
    }
    if claim_id == CLAIM_TRANSACTION_PASSPORT_ROOT_VERIFIED {
        return source_report
            .get("schema")
            .and_then(serde_json::Value::as_str)
            == Some("chio.transaction.verifier-report.v1");
    }
    source_report
        .get("verified_claims")
        .or_else(|| source_report.get("verifiedClaims"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|claims| claims.iter().any(|claim| claim.as_str() == Some(claim_id)))
}

fn verify_first_run_authority_evidence(
    bundle_root: &Path,
    claims: &[ProofRoomClaim],
    artifacts: &[ProofRoomArtifactRef],
) -> Result<(), String> {
    let Some(authority_claim) = claims
        .iter()
        .find(|claim| claim.claim_id == CLAIM_PROOF_ROOM_AUTHORITY_EVIDENCE_BOUND)
    else {
        return Err("proof-room.first-run.authority-evidence-missing".to_string());
    };

    for (artifact_path, schema) in REQUIRED_AUTHORITY_ARTIFACTS {
        require_claim_artifact(
            authority_claim,
            artifact_path,
            "proof-room.first-run.authority-evidence-missing",
        )?;
        let artifact = artifacts
            .iter()
            .find(|artifact| artifact.path == *artifact_path)
            .ok_or_else(|| "proof-room.first-run.authority-evidence-missing".to_string())?;
        let verified = verify_manifest_ref_defer_json_schema(
            bundle_root,
            artifact,
            "authority_evidence",
            Some(schema),
        )?;
        validate_authority_artifact(artifact_path, &verified.bytes)?;
        validate_json_artifact_schema(&verified.bytes, schema, "authority_evidence")?;
    }
    verify_first_run_guard_receipt_refs(bundle_root, artifacts)?;
    Ok(())
}

fn verify_first_run_guard_receipt_refs(
    bundle_root: &Path,
    artifacts: &[ProofRoomArtifactRef],
) -> Result<(), String> {
    let guard_artifact = artifact_ref(
        artifacts,
        "artifacts/authority/guard-report.json",
        "proof-room.first-run.authority-evidence-missing",
    )?;
    let guard_report = verify_manifest_ref(
        bundle_root,
        guard_artifact,
        "authority_evidence",
        Some(PROOF_ROOM_FIRST_RUN_GUARD_REPORT_SCHEMA),
    )?;
    let guard: serde_json::Value = serde_json::from_slice(&guard_report.bytes)
        .map_err(|error| format!("proof-room.first-run.guard-report-invalid: {error}"))?;
    let allow_receipt_ref = required_json_string(
        &guard,
        "allow_receipt_ref",
        "proof-room.first-run.guard-allow-receipt-ref-missing",
    )?;
    let denial_receipt_ref = required_json_string(
        &guard,
        "denial_receipt_ref",
        "proof-room.first-run.guard-denial-receipt-ref-missing",
    )?;
    let allow_receipt_id = first_run_receipt_id(
        bundle_root,
        artifacts,
        "artifacts/receipts/allow-receipt.json",
        "proof-room.first-run.allow-missing",
    )?;
    let denial_receipt_id = first_run_receipt_id(
        bundle_root,
        artifacts,
        "artifacts/receipts/denial-receipt.json",
        "proof-room.first-run.denial-missing",
    )?;
    if allow_receipt_ref != allow_receipt_id {
        return Err("proof-room.first-run.guard-allow-receipt-mismatch".to_string());
    }
    if denial_receipt_ref != denial_receipt_id {
        return Err("proof-room.first-run.guard-denial-receipt-mismatch".to_string());
    }
    Ok(())
}

fn first_run_receipt_id(
    bundle_root: &Path,
    artifacts: &[ProofRoomArtifactRef],
    artifact_path: &str,
    missing_code: &str,
) -> Result<String, String> {
    let receipt_artifact = artifact_ref(artifacts, artifact_path, missing_code)?;
    let receipt = verify_manifest_ref(
        bundle_root,
        receipt_artifact,
        "first_run_receipt",
        Some(PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA),
    )?;
    let value: serde_json::Value = serde_json::from_slice(&receipt.bytes).map_err(|error| {
        format!("proof-room.first-run.receipt-invalid: {artifact_path}: {error}")
    })?;
    required_json_string(
        &value,
        "receipt_id",
        "proof-room.first-run.receipt-id-missing",
    )
    .map(str::to_string)
}

fn artifact_ref<'a>(
    artifacts: &'a [ProofRoomArtifactRef],
    artifact_path: &str,
    missing_code: &str,
) -> Result<&'a ProofRoomArtifactRef, String> {
    artifacts
        .iter()
        .find(|artifact| artifact.path == artifact_path)
        .ok_or_else(|| format!("{missing_code}: {artifact_path}"))
}

fn required_json_string<'a>(
    value: &'a serde_json::Value,
    field: &str,
    missing_code: &str,
) -> Result<&'a str, String> {
    let Some(field_value) = value.get(field).and_then(serde_json::Value::as_str) else {
        return Err(missing_code.to_string());
    };
    if field_value.is_empty() {
        return Err(missing_code.to_string());
    }
    Ok(field_value)
}

fn verify_first_run_evidence_graph_binding(
    evidence_graph_bytes: &[u8],
    artifacts: &[ProofRoomArtifactRef],
) -> Result<(), String> {
    let graph: serde_json::Value = serde_json::from_slice(evidence_graph_bytes)
        .map_err(|error| format!("proof-room.evidence-graph.invalid-json: {error}"))?;
    let nodes = graph
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "proof-room.evidence-graph.nodes-missing".to_string())?;
    for (artifact_path, _schema) in REQUIRED_AUTHORITY_ARTIFACTS {
        require_graph_bound_artifact(
            nodes,
            artifacts,
            artifact_path,
            "proof-room.evidence-graph.authority-node-missing",
        )?;
    }
    for artifact_path in REQUIRED_RECEIPT_ARTIFACTS {
        require_graph_bound_artifact(
            nodes,
            artifacts,
            artifact_path,
            "proof-room.evidence-graph.receipt-node-missing",
        )?;
    }
    Ok(())
}

fn require_graph_bound_artifact(
    nodes: &[serde_json::Value],
    artifacts: &[ProofRoomArtifactRef],
    artifact_path: &str,
    missing_code: &str,
) -> Result<(), String> {
    let artifact = artifacts
        .iter()
        .find(|artifact| artifact.path == artifact_path)
        .ok_or_else(|| format!("{missing_code}: {artifact_path}"))?;
    let node = nodes
        .iter()
        .find(|node| node.get("path").and_then(serde_json::Value::as_str) == Some(artifact_path))
        .ok_or_else(|| format!("{missing_code}: {artifact_path}"))?;
    let node_schema = node
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("proof-room.evidence-graph.node-schema-missing: {artifact_path}"))?;
    if node_schema != artifact.schema {
        return Err(format!(
            "proof-room.evidence-graph.node-schema-mismatch: {artifact_path}"
        ));
    }
    let node_sha256 = node
        .get("sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("proof-room.evidence-graph.node-hash-missing: {artifact_path}"))?;
    if node_sha256 != artifact.sha256 {
        return Err(format!(
            "proof-room.evidence-graph.node-hash-mismatch: {artifact_path}"
        ));
    }
    Ok(())
}

fn validate_authority_artifact(path: &str, bytes: &[u8]) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("proof-room.authority-evidence.invalid-json: {path}: {error}"))?;
    match path {
        "artifacts/authority/capability-proof.json" => require_json_fields(
            path,
            &value,
            &[
                "capability_id",
                "issuer",
                "subject",
                "scope",
                "policy_digest",
                "not_before",
                "expires_at",
                "signature",
            ],
        ),
        "artifacts/authority/guard-report.json" => require_json_fields(
            path,
            &value,
            &[
                "capability_id",
                "guard_id",
                "decision",
                "policy_digest",
                "allow_receipt_ref",
                "denial_receipt_ref",
                "request_digest",
                "response_digest",
                "signature",
            ],
        ),
        "artifacts/authority/trust-roots.json" => {
            require_json_fields(path, &value, &["trust_domain", "signature"])?;
            let roots = value
                .get("roots")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    format!("proof-room.authority-evidence.field-missing: {path} roots")
                })?;
            if roots.is_empty() {
                Err(format!(
                    "proof-room.authority-evidence.field-missing: {path} roots"
                ))
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}

fn require_json_fields(
    path: &str,
    value: &serde_json::Value,
    fields: &[&str],
) -> Result<(), String> {
    for field in fields {
        let Some(value) = value.get(*field).and_then(serde_json::Value::as_str) else {
            return Err(format!(
                "proof-room.authority-evidence.field-missing: {path} {field}"
            ));
        };
        if value.is_empty() {
            return Err(format!(
                "proof-room.authority-evidence.field-missing: {path} {field}"
            ));
        }
    }
    Ok(())
}

fn require_claim_artifact(
    claim: &ProofRoomClaim,
    artifact_path: &str,
    error_code: &str,
) -> Result<(), String> {
    if claim
        .required_artifacts
        .iter()
        .any(|required| required == artifact_path)
    {
        return Ok(());
    }
    Err(error_code.to_string())
}

fn verify_bundle_signature(
    bundle_root: &Path,
    manifest: &ProofRoomBundleManifest,
    manifest_bytes: &[u8],
) -> Result<(), String> {
    let signature = manifest
        .signature
        .as_ref()
        .ok_or_else(|| "proof-room.signature.missing".to_string())?;
    if signature.kind != PROOF_ROOM_SIGNATURE_KIND {
        return Err(format!(
            "proof-room.signature.kind-unsupported: {}",
            signature.kind
        ));
    }
    if signature.signature_ref.is_empty() {
        return Err("proof-room.signature.path-missing".to_string());
    }

    let signature_path = resolve_proof_room_bundle_path(bundle_root, &signature.signature_ref)?;
    let signature_bytes = fs::read(&signature_path)
        .map_err(|error| format!("proof-room.signature.unreadable: {error}"))?;
    let detached: ProofRoomDetachedDsse = serde_json::from_slice(&signature_bytes)
        .map_err(|error| format!("proof-room.signature.invalid-json: {error}"))?;

    if detached.payload_type != PROOF_ROOM_DSSE_PAYLOAD_TYPE {
        return Err("proof-room.signature.payload-type-mismatch".to_string());
    }
    if detached.payload_ref.path != "manifest.json" {
        return Err("proof-room.signature.payload-path-mismatch".to_string());
    }
    if detached.payload_ref.schema != PROOF_ROOM_BUNDLE_SCHEMA {
        return Err("proof-room.signature.payload-schema-mismatch".to_string());
    }
    let actual_manifest_sha256 = sha256_hex(manifest_bytes);
    if detached.payload_ref.sha256 != actual_manifest_sha256 {
        return Err("proof-room.signature.payload-hash-mismatch".to_string());
    }
    if detached.signatures.is_empty() {
        return Err("proof-room.signature.signatures-missing".to_string());
    }
    let trusted_signer_keys = trusted_bundle_signer_keys(bundle_root, manifest)?;
    let signing_payload = dsse_pre_auth_encoding(&detached.payload_type, manifest_bytes);
    for entry in &detached.signatures {
        if entry.keyid.is_empty() || entry.sig.is_empty() {
            return Err("proof-room.signature.field-missing".to_string());
        }
        if !trusted_signer_keys.contains(&entry.keyid) {
            return Err("proof-room.signature.signer-untrusted".to_string());
        }
        let public_key = PublicKey::from_hex(&entry.keyid)
            .map_err(|error| format!("proof-room.signature.key-invalid: {error}"))?;
        let signature = Signature::from_hex(&entry.sig)
            .map_err(|error| format!("proof-room.signature.signature-invalid: {error}"))?;
        if !public_key.verify(&signing_payload, &signature) {
            return Err("proof-room.signature.verification-failed".to_string());
        }
    }

    Ok(())
}

fn trusted_bundle_signer_keys(
    bundle_root: &Path,
    manifest: &ProofRoomBundleManifest,
) -> Result<BTreeSet<String>, String> {
    let Some(reference) = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.path == "artifacts/authority/trust-roots.json")
    else {
        return Err("proof-room.signature.trust-roots-missing".to_string());
    };
    let artifact = verify_manifest_ref(
        bundle_root,
        reference,
        "signature_trust_roots_ref",
        Some(PROOF_ROOM_FIRST_RUN_TRUST_ROOTS_SCHEMA),
    )?;
    let trust_roots: ProofRoomTrustRoots = serde_json::from_slice(&artifact.bytes)
        .map_err(|error| format!("proof-room.signature.trust-roots-invalid: {error}"))?;
    if trust_roots.roots.is_empty() {
        return Err("proof-room.signature.trust-roots-missing".to_string());
    }
    let mut trusted = BTreeSet::new();
    for root in trust_roots.roots {
        if root.key_id.is_empty() || root.key_digest.is_empty() {
            return Err("proof-room.signature.trust-root-field-missing".to_string());
        }
        if root.key_digest != sha256_hex(root.key_id.as_bytes()) {
            return Err("proof-room.signature.trust-root-digest-mismatch".to_string());
        }
        trusted.insert(root.key_id);
    }
    Ok(trusted)
}

fn dsse_pre_auth_encoding(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let payload_type = payload_type.as_bytes();
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"DSSEv1 ");
    encoded.extend_from_slice(payload_type.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload_type);
    encoded.push(b' ');
    encoded.extend_from_slice(payload.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload);
    encoded
}

struct VerifiedManifestArtifact {
    bytes: Vec<u8>,
    path: PathBuf,
}

fn verify_manifest_ref(
    bundle_root: &Path,
    reference: &ProofRoomArtifactRef,
    label: &str,
    expected_schema: Option<&str>,
) -> Result<VerifiedManifestArtifact, String> {
    verify_manifest_ref_with_json_schema(bundle_root, reference, label, expected_schema, true)
}

fn verify_manifest_ref_defer_json_schema(
    bundle_root: &Path,
    reference: &ProofRoomArtifactRef,
    label: &str,
    expected_schema: Option<&str>,
) -> Result<VerifiedManifestArtifact, String> {
    verify_manifest_ref_with_json_schema(bundle_root, reference, label, expected_schema, false)
}

fn verify_manifest_ref_with_json_schema(
    bundle_root: &Path,
    reference: &ProofRoomArtifactRef,
    label: &str,
    expected_schema: Option<&str>,
    validate_json_schema: bool,
) -> Result<VerifiedManifestArtifact, String> {
    if let Some(expected_schema) = expected_schema {
        if reference.schema != expected_schema {
            return Err(format!(
                "proof-room.schema-mismatch: {label} expected {expected_schema}"
            ));
        }
    }
    let artifact_path = resolve_proof_room_bundle_path(bundle_root, &reference.path)?;
    let bytes = fs::read(&artifact_path).map_err(|error| {
        format!(
            "proof-room.artifact.unreadable: {}: {error}",
            reference.path
        )
    })?;
    let actual_sha256 = sha256_hex(&bytes);
    if actual_sha256 != reference.sha256 {
        let code = if label == "verifier_report_ref" {
            "proof-room.report.hash-mismatch"
        } else {
            "proof-room.artifact.hash-mismatch"
        };
        return Err(format!(
            "{code}: {label} expected {} got {actual_sha256}",
            reference.sha256
        ));
    }
    if validate_json_schema {
        validate_json_artifact_schema(&bytes, &reference.schema, label)?;
    }
    Ok(VerifiedManifestArtifact {
        bytes,
        path: artifact_path,
    })
}

fn verify_source_verifier_report(
    bundle_root: &Path,
    transaction_passport_artifact: &VerifiedManifestArtifact,
    actual_report: &serde_json::Value,
) -> Result<(), String> {
    if source_report_has_family_reports(actual_report) {
        verify_family_source_verifier_report(
            bundle_root,
            transaction_passport_artifact,
            actual_report,
        )?;
        return Ok(());
    }
    match verify_transaction_passport_file(bundle_root, &transaction_passport_artifact.path) {
        Ok(expected_report) => {
            if actual_report != &expected_report {
                return Err(
                    "proof-room.report.mismatch: verifier report does not match transaction passport"
                        .to_string(),
                );
            }
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

fn source_report_has_family_reports(report: &serde_json::Value) -> bool {
    report
        .get("family_reports")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|reports| !reports.is_empty())
}

fn verify_family_source_verifier_report(
    bundle_root: &Path,
    transaction_passport_artifact: &VerifiedManifestArtifact,
    actual_report: &serde_json::Value,
) -> Result<(), String> {
    let expected_report = verify_transaction_passport_family_report(
        bundle_root,
        &transaction_passport_artifact.path,
    )?;
    if actual_report != &expected_report {
        return Err(
            "proof-room.report.mismatch: verifier report does not match transaction passport"
                .to_string(),
        );
    }
    Ok(())
}

struct SourceVerifierContext {
    passport: chio_transaction_passport::TransactionPassport,
    passport_report_path: String,
    evidence_graph_bytes: Vec<u8>,
    verifier_policy_bytes: Vec<u8>,
    artifacts: BTreeMap<String, Vec<u8>>,
}

#[derive(Default)]
struct SourceVerifierClaimRequirements {
    required_claims: Vec<String>,
    prefixes: BTreeSet<&'static str>,
}

impl SourceVerifierClaimRequirements {
    fn requires(&self, prefix: &'static str) -> bool {
        self.prefixes.contains(prefix)
    }
}

#[derive(Default)]
struct SourceRiskRoute {
    through_enterprise: bool,
    through_trust_market: bool,
    standalone: bool,
}

#[derive(Clone, Copy)]
struct SourceLocalFamilyRoute {
    prefix: &'static str,
    route: ProofRoomFixtureReportRoute,
    label: &'static str,
}

const SOURCE_LOCAL_FAMILY_ROUTES: &[SourceLocalFamilyRoute] = &[
    SourceLocalFamilyRoute {
        prefix: CLAIM_PREFIX_COMMERCE,
        route: ProofRoomFixtureReportRoute::Commerce,
        label: "commerce",
    },
    SourceLocalFamilyRoute {
        prefix: CLAIM_PREFIX_DISCLOSURE,
        route: ProofRoomFixtureReportRoute::DisclosureLineage,
        label: "disclosure",
    },
    SourceLocalFamilyRoute {
        prefix: CLAIM_PREFIX_SWARM,
        route: ProofRoomFixtureReportRoute::Swarm,
        label: "swarm",
    },
    SourceLocalFamilyRoute {
        prefix: CLAIM_PREFIX_PUBLIC_SETTLEMENT,
        route: ProofRoomFixtureReportRoute::PublicSettlement,
        label: "public settlement",
    },
];

fn verify_transaction_passport_family_report(
    bundle_root: &Path,
    path: &Path,
) -> Result<serde_json::Value, String> {
    let context = source_verifier_context(bundle_root, path)?;
    verify_source_passport_artifact_digests(&context)?;
    let requirements = source_verifier_claim_requirements(&context.verifier_policy_bytes)?;
    let risk_route = source_risk_route(
        &context.evidence_graph_bytes,
        requirements.requires(CLAIM_PREFIX_RISK),
    )?;
    let mut family_reports = Vec::new();

    for route in SOURCE_LOCAL_FAMILY_ROUTES {
        if requirements.requires(route.prefix) {
            push_source_local_family_report(
                &mut family_reports,
                &context,
                &requirements.required_claims,
                route,
            )?;
        }
    }
    if risk_route.standalone {
        family_reports.push(verify_source_standalone_risk_report(
            &context,
            &requirements.required_claims,
        )?);
    }
    if requirements.requires(CLAIM_PREFIX_TRUST_MARKET) || risk_route.through_trust_market {
        let report = chio_trust_market_context::verify_trust_market_context(
            &chio_trust_market_context::TrustMarketBundle {
                passport: context.passport.clone(),
                evidence_graph_bytes: context.evidence_graph_bytes.clone(),
                verifier_policy_bytes: context.verifier_policy_bytes.clone(),
                artifacts: context.artifacts.clone(),
            },
        )
        .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
        push_source_family_report(&mut family_reports, report)?;
    }
    if requirements.requires(CLAIM_PREFIX_AGENT_WEB) {
        let report = chio_agent_web_interop::verify_agent_web_interop(
            &chio_agent_web_interop::AgentWebInteropBundle {
                passport: context.passport.clone(),
                evidence_graph_bytes: context.evidence_graph_bytes.clone(),
                verifier_policy_bytes: context.verifier_policy_bytes.clone(),
                artifacts: context.artifacts.clone(),
            },
        )
        .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
        push_source_family_report(&mut family_reports, report)?;
    }
    if requirements.requires(CLAIM_PREFIX_ENTERPRISE) || risk_route.through_enterprise {
        let report = chio_enterprise_export::verify_enterprise_export(
            &chio_enterprise_export::EnterpriseExportBundle {
                passport: context.passport.clone(),
                evidence_graph_bytes: context.evidence_graph_bytes.clone(),
                verifier_policy_bytes: context.verifier_policy_bytes.clone(),
                artifacts: context.artifacts.clone(),
            },
        )
        .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
        push_source_family_report(&mut family_reports, report)?;
    }
    if requirements.requires(CLAIM_PREFIX_RUNTIME) {
        let artifacts =
            embedded_runtime_artifacts(&context.evidence_graph_bytes, &context.artifacts)
                .map_err(|error| format!("proof-room.runtime-invalid: {error}"))?;
        let report = chio_transaction_passport::verify_runtime_security_claims(
            &chio_transaction_passport::RuntimeSecurityBundle {
                passport: context.passport.clone(),
                evidence_graph_bytes: context.evidence_graph_bytes.clone(),
                verifier_policy_bytes: context.verifier_policy_bytes.clone(),
                artifacts,
            },
        )
        .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
        push_source_family_report(&mut family_reports, report)?;
    }

    if family_reports.len() == 1 {
        attach_source_runtime_proof_parity_report(&context, &mut family_reports[0])?;
    }

    let mut report = if family_reports.is_empty() {
        verify_transaction_passport_file(bundle_root, path)?
    } else {
        merge_source_family_verifier_reports(&context, family_reports)
    };
    attach_source_runtime_proof_parity_report(&context, &mut report)?;
    Ok(report)
}

fn push_source_local_family_report(
    family_reports: &mut Vec<serde_json::Value>,
    context: &SourceVerifierContext,
    required_claims: &[String],
    route: &SourceLocalFamilyRoute,
) -> Result<(), String> {
    match route.route {
        ProofRoomFixtureReportRoute::Commerce => {
            let bundle =
                embedded_commerce_order_bundle(&context.evidence_graph_bytes, &context.artifacts)
                    .map_err(|error| format!("proof-room.commerce-invalid: {error}"))?;
            push_source_local_family_result(
                family_reports,
                required_claims,
                route,
                chio_commerce_order::verify_commerce_order(&bundle),
            )
        }
        ProofRoomFixtureReportRoute::DisclosureLineage => {
            let bundle = embedded_disclosure_lineage_bundle(
                &context.evidence_graph_bytes,
                &context.artifacts,
            )
            .map_err(|error| format!("proof-room.disclosure-lineage-invalid: {error}"))?;
            push_source_local_family_result(
                family_reports,
                required_claims,
                route,
                chio_disclosure_lineage::verify_disclosure_lineage_bundle(&bundle),
            )
        }
        ProofRoomFixtureReportRoute::Swarm => {
            let bundle =
                embedded_swarm_authority_bundle(&context.evidence_graph_bytes, &context.artifacts)
                    .map_err(|error| format!("proof-room.swarm-invalid: {error}"))?;
            push_source_local_family_result(
                family_reports,
                required_claims,
                route,
                chio_swarm_authority::verify_swarm_authority_bundle(&bundle),
            )
        }
        ProofRoomFixtureReportRoute::PublicSettlement => {
            let proof_bundle = embedded_public_settlement_proof_bundle(
                &context.evidence_graph_bytes,
                &context.artifacts,
            )
            .map_err(|error| format!("proof-room.public-settlement-invalid: {error}"))?;
            if proof_bundle.transaction_passport_id != context.passport.id {
                return Err(format!(
                    "proof-room.public-settlement-invalid: passport mismatch: expected {}, got {}",
                    context.passport.id, proof_bundle.transaction_passport_id
                ));
            }
            push_source_local_family_result(
                family_reports,
                required_claims,
                route,
                chio_web3::settlement_proof::verify_public_settlement_proof(&proof_bundle),
            )
        }
        ProofRoomFixtureReportRoute::StandaloneRisk
        | ProofRoomFixtureReportRoute::TrustMarket
        | ProofRoomFixtureReportRoute::Enterprise
        | ProofRoomFixtureReportRoute::AgentWeb
        | ProofRoomFixtureReportRoute::Runtime
        | ProofRoomFixtureReportRoute::MinimalPassport => {
            Err("proof-room.source-verifier.route-invalid".to_string())
        }
    }
}

fn push_source_local_family_result<T, E>(
    family_reports: &mut Vec<serde_json::Value>,
    required_claims: &[String],
    route: &SourceLocalFamilyRoute,
    result: Result<T, E>,
) -> Result<(), String>
where
    T: serde::Serialize,
    E: std::fmt::Display,
{
    let report = result.map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
    push_verified_source_family_report(family_reports, required_claims, route, report)
}

fn push_verified_source_family_report<T: serde::Serialize>(
    family_reports: &mut Vec<serde_json::Value>,
    required_claims: &[String],
    route: &SourceLocalFamilyRoute,
    report: T,
) -> Result<(), String> {
    let report = source_verifier_report_value(report)?;
    ensure_source_required_claims_verified(required_claims, &report, route.prefix, route.label)?;
    family_reports.push(report);
    Ok(())
}

fn push_source_family_report<T: serde::Serialize>(
    family_reports: &mut Vec<serde_json::Value>,
    report: T,
) -> Result<(), String> {
    let report = source_verifier_report_value(report)?;
    family_reports.push(report);
    Ok(())
}

fn source_verifier_report_value<T: serde::Serialize>(
    report: T,
) -> Result<serde_json::Value, String> {
    serde_json::to_value(report)
        .map_err(|error| format!("proof-room.source-verifier.report-encode: {error}"))
}

fn source_verifier_context(
    bundle_root: &Path,
    path: &Path,
) -> Result<SourceVerifierContext, String> {
    let passport_bytes =
        fs::read(path).map_err(|error| format!("proof-room.passport.unreadable: {error}"))?;
    let passport: chio_transaction_passport::TransactionPassport =
        serde_json::from_slice(&passport_bytes)
            .map_err(|error| format!("proof-room.passport.invalid-json: {error}"))?;
    chio_transaction_passport::verify_minimal_passport_schema(&passport)
        .map_err(|error| format!("proof-room.passport.invalid: {error}"))?;
    let passport_dir = path
        .parent()
        .ok_or_else(|| "proof-room.passport.path-invalid".to_string())?;
    let evidence_graph_path =
        resolve_nested_bundle_path(bundle_root, passport_dir, &passport.evidence_graph_path)?;
    let verifier_policy_path =
        resolve_nested_bundle_path(bundle_root, passport_dir, &passport.verifier_policy_path)?;
    let evidence_graph_bytes = fs::read(&evidence_graph_path)
        .map_err(|error| format!("proof-room.evidence-graph.unreadable: {error}"))?;
    let verifier_policy_bytes = fs::read(&verifier_policy_path)
        .map_err(|error| format!("proof-room.verifier-policy.unreadable: {error}"))?;
    chio_transaction_passport::validate_verifier_policy_artifact(&verifier_policy_bytes)
        .map_err(|error| format!("proof-room.verifier-policy.invalid: {error}"))?;
    let artifacts =
        load_standalone_evidence_graph_artifacts(bundle_root, passport_dir, &evidence_graph_bytes)?;
    let passport_report_path = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());
    Ok(SourceVerifierContext {
        passport,
        passport_report_path,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
    })
}

fn verify_source_passport_artifact_digests(context: &SourceVerifierContext) -> Result<(), String> {
    let evidence_graph_sha256 = sha256_hex(&context.evidence_graph_bytes);
    if evidence_graph_sha256 != context.passport.evidence_graph_sha256 {
        return Err(format!(
            "proof-room.source-verifier.failed: evidence graph digest mismatch: expected {}, got {}",
            context.passport.evidence_graph_sha256, evidence_graph_sha256
        ));
    }
    let verifier_policy_sha256 = sha256_hex(&context.verifier_policy_bytes);
    if verifier_policy_sha256 != context.passport.verifier_policy_sha256 {
        return Err(format!(
            "proof-room.source-verifier.failed: verifier policy digest mismatch: expected {}, got {}",
            context.passport.verifier_policy_sha256, verifier_policy_sha256
        ));
    }
    Ok(())
}

fn source_verifier_claim_requirements(
    policy_bytes: &[u8],
) -> Result<SourceVerifierClaimRequirements, String> {
    let policy: serde_json::Value = serde_json::from_slice(policy_bytes)
        .map_err(|error| format!("proof-room.verifier-policy.invalid-json: {error}"))?;
    let mut requirements = SourceVerifierClaimRequirements::default();
    if let Some(claims) = policy
        .get("required_claims")
        .and_then(serde_json::Value::as_array)
    {
        for claim in claims {
            let Some(claim) = claim.as_str() else {
                return Err("proof-room.verifier-policy.required-claim-invalid".to_string());
            };
            requirements.required_claims.push(claim.to_string());
            for prefix in SOURCE_VERIFIER_CLAIM_PREFIXES {
                if claim.starts_with(prefix) {
                    requirements.prefixes.insert(prefix);
                }
            }
        }
    }
    Ok(requirements)
}

fn source_risk_route(
    evidence_graph_bytes: &[u8],
    requires_risk: bool,
) -> Result<SourceRiskRoute, String> {
    if !requires_risk {
        return Ok(SourceRiskRoute::default());
    }
    let through_enterprise =
        embedded_evidence_graph_has_role(evidence_graph_bytes, is_enterprise_risk_context_role)?;
    let through_trust_market =
        embedded_evidence_graph_has_role(evidence_graph_bytes, is_trust_market_risk_context_role)?;
    Ok(SourceRiskRoute {
        through_enterprise,
        through_trust_market,
        standalone: !through_enterprise && !through_trust_market,
    })
}

fn verify_source_standalone_risk_report(
    context: &SourceVerifierContext,
    required_claims: &[String],
) -> Result<serde_json::Value, String> {
    let risk_report =
        embedded_risk_comptroller_report(&context.evidence_graph_bytes, &context.artifacts)
            .map_err(|error| format!("proof-room.risk-invalid: {error}"))?;
    chio_risk_comptroller::validate_risk_report(&context.passport, &risk_report)
        .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
    let risk_evidence_ref_schemas =
        embedded_evidence_graph_ref_schemas(&context.evidence_graph_bytes)
            .map_err(|error| format!("proof-room.evidence-graph-invalid: {error}"))?;
    chio_risk_comptroller::validate_risk_evidence_refs(&risk_report, |evidence_ref, kind| {
        risk_evidence_ref_schemas
            .get(evidence_ref)
            .is_some_and(|schema| risk_evidence_schema_matches_kind(schema, kind))
    })
    .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
    let verified_claims = vec![CLAIM_RISK_COMPTROLLER_REPORT_BOUND.to_string()];
    let report = serde_json::json!({
        "schema": "chio.transaction.verifier-report.v1",
        "id": format!("verifier-report-{}", context.passport.id),
        "issued_at": context.passport.issued_at.clone(),
        "verdict": "verified",
        "passport_id": context.passport.id.clone(),
        "passport_path": context.passport_report_path,
        "evidence_graph_sha256": context.passport.evidence_graph_sha256.clone(),
        "evidence_graph_path": context.passport.evidence_graph_path.clone(),
        "verifier_policy_sha256": context.passport.verifier_policy_sha256.clone(),
        "verifier_policy_path": context.passport.verifier_policy_path.clone(),
        "risk_comptroller_report_ref": risk_report.id,
        "order_id": risk_report.order_id,
        "subject": risk_report.subject,
        "verified_claims": verified_claims,
    });
    ensure_source_required_claims_verified(required_claims, &report, CLAIM_PREFIX_RISK, "risk")?;
    Ok(report)
}

fn merge_source_family_verifier_reports(
    context: &SourceVerifierContext,
    family_reports: Vec<serde_json::Value>,
) -> serde_json::Value {
    let mut seen_claims = BTreeSet::new();
    let mut verified_claims = Vec::new();
    for report in &family_reports {
        for claim in source_report_verified_claims(report) {
            if seen_claims.insert(claim.clone()) && family_reports.len() > 1 {
                verified_claims.push(serde_json::Value::String(claim));
            }
        }
    }
    if family_reports.len() == 1 {
        verified_claims = seen_claims
            .into_iter()
            .map(serde_json::Value::String)
            .collect();
    }

    serde_json::json!({
        "schema": "chio.transaction.verifier-report.v1",
        "id": format!("verifier-report-{}", context.passport.id),
        "issued_at": context.passport.issued_at.clone(),
        "verdict": "verified",
        "passport_id": context.passport.id.clone(),
        "passport_path": context.passport_report_path,
        "evidence_graph_sha256": context.passport.evidence_graph_sha256.clone(),
        "evidence_graph_path": context.passport.evidence_graph_path.clone(),
        "verifier_policy_sha256": context.passport.verifier_policy_sha256.clone(),
        "verifier_policy_path": context.passport.verifier_policy_path.clone(),
        "verified_claims": verified_claims,
        "family_reports": family_reports,
        "checker_provenance": source_claim_checker_provenance(&verified_claims),
    })
}

fn source_claim_checker_provenance(
    verified_claims: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    verified_claims
        .iter()
        .filter_map(serde_json::Value::as_str)
        .map(|claim_id| {
            serde_json::json!({
                "claim_id": claim_id,
                "checker": source_checker_for_claim(claim_id)
            })
        })
        .collect()
}

fn source_checker_for_claim(claim_id: &str) -> &'static str {
    if claim_id.starts_with("claim.agent_web.") {
        "chio proof verify --require external-envelope"
    } else if claim_id.starts_with("claim.commerce.") {
        "chio proof verify --require commerce"
    } else if claim_id.starts_with("claim.disclosure.") {
        "chio proof verify --require disclosure"
    } else if claim_id.starts_with("claim.enterprise.") {
        "chio proof verify --require enterprise"
    } else if claim_id.starts_with("claim.public_settlement.") {
        "chio proof verify --require settlement"
    } else if claim_id.starts_with("claim.risk.") {
        "chio proof verify --require risk"
    } else if claim_id.starts_with("claim.runtime.") {
        "chio proof verify --require runtime"
    } else if claim_id.starts_with("claim.swarm.") {
        "chio proof verify --require delegation"
    } else if claim_id.starts_with("claim.trust_market.") {
        "chio proof verify --require trust-market"
    } else {
        "chio proof verify"
    }
}

fn ensure_source_required_claims_verified(
    required_claims: &[String],
    report: &serde_json::Value,
    claim_prefix: &str,
    label: &str,
) -> Result<(), String> {
    let verified_claims = source_report_verified_claims(report);
    for required_claim in required_claims {
        if required_claim.starts_with(claim_prefix)
            && !verified_claims.iter().any(|claim| claim == required_claim)
        {
            return Err(format!(
                "proof-room.source-verifier.failed: required {label} claim not verified: {required_claim}"
            ));
        }
    }
    Ok(())
}

fn source_report_verified_claims(report: &serde_json::Value) -> Vec<String> {
    report
        .get("verified_claims")
        .or_else(|| report.get("verifiedClaims"))
        .and_then(serde_json::Value::as_array)
        .map(|claims| {
            claims
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn verify_transaction_passport_file(
    bundle_root: &Path,
    path: &Path,
) -> Result<serde_json::Value, String> {
    let passport_bytes =
        fs::read(path).map_err(|error| format!("proof-room.passport.unreadable: {error}"))?;
    let passport: chio_transaction_passport::TransactionPassport =
        serde_json::from_slice(&passport_bytes)
            .map_err(|error| format!("proof-room.passport.invalid-json: {error}"))?;
    let passport_dir = path
        .parent()
        .ok_or_else(|| "proof-room.passport.path-invalid".to_string())?;
    let evidence_graph_path =
        resolve_nested_bundle_path(bundle_root, passport_dir, &passport.evidence_graph_path)?;
    let verifier_policy_path =
        resolve_nested_bundle_path(bundle_root, passport_dir, &passport.verifier_policy_path)?;
    let evidence_graph_bytes = fs::read(&evidence_graph_path)
        .map_err(|error| format!("proof-room.evidence-graph.unreadable: {error}"))?;
    let verifier_policy_bytes = fs::read(&verifier_policy_path)
        .map_err(|error| format!("proof-room.verifier-policy.unreadable: {error}"))?;
    let artifacts =
        load_standalone_evidence_graph_artifacts(bundle_root, passport_dir, &evidence_graph_bytes)?;
    let passport_report_path = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());
    let report = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        passport_report_path,
        &evidence_graph_bytes,
        &verifier_policy_bytes,
        &artifacts,
    )
    .map_err(|error| format!("proof-room.source-verifier.failed: {error}"))?;
    let mut report = serde_json::to_value(report)
        .map_err(|error| format!("proof-room.source-verifier.report-encode: {error}"))?;
    let context = SourceVerifierContext {
        passport,
        passport_report_path: String::new(),
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
    };
    attach_source_runtime_proof_parity_report(&context, &mut report)?;
    Ok(report)
}

#[derive(serde::Deserialize)]
struct StandaloneEvidenceGraphArtifactIndex {
    nodes: Vec<StandaloneEvidenceGraphArtifactNode>,
}

#[derive(serde::Deserialize)]
struct StandaloneEvidenceGraphArtifactNode {
    path: String,
}

#[derive(serde::Deserialize)]
struct SourceRuntimeParityEvidenceGraph {
    nodes: Vec<SourceRuntimeParityEvidenceNode>,
}

#[derive(serde::Deserialize)]
struct SourceRuntimeParityEvidenceNode {
    path: String,
    schema: String,
    sha256: String,
    #[serde(default)]
    role: String,
}

fn attach_source_runtime_proof_parity_report(
    context: &SourceVerifierContext,
    report: &mut serde_json::Value,
) -> Result<(), String> {
    let Some(parity_report) = source_runtime_proof_parity_report(context)? else {
        return Ok(());
    };
    validate_source_runtime_proof_regeneration_artifacts(context)?;
    let report_object = report
        .as_object_mut()
        .ok_or_else(|| "proof-room.source-verifier.report-not-object".to_string())?;
    report_object.insert("runtime_proof_parity_report".to_string(), parity_report);
    Ok(())
}

fn source_runtime_proof_parity_report(
    context: &SourceVerifierContext,
) -> Result<Option<serde_json::Value>, String> {
    let graph: SourceRuntimeParityEvidenceGraph =
        serde_json::from_slice(&context.evidence_graph_bytes)
            .map_err(|error| format!("proof-room.evidence-graph.invalid-json: {error}"))?;
    let parity_nodes = graph
        .nodes
        .into_iter()
        .filter(|node| {
            node.role == "runtime-proof-parity-report"
                || node.schema == chio_runtime_proof_parity::CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA
        })
        .collect::<Vec<_>>();
    let node = match parity_nodes.as_slice() {
        [] => return Ok(None),
        [node] => node,
        _ => return Err("proof-room.runtime-parity.multiple-reports".to_string()),
    };
    if node.schema != chio_runtime_proof_parity::CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA {
        return Err(format!(
            "proof-room.runtime-parity.schema-unsupported: {}",
            node.schema
        ));
    }
    let bytes = context
        .artifacts
        .get(&node.path)
        .ok_or_else(|| format!("proof-room.runtime-parity.artifact-missing: {}", node.path))?;
    let actual_sha256 = sha256_hex(bytes);
    if actual_sha256 != node.sha256 {
        return Err(format!(
            "proof-room.runtime-parity.hash-mismatch: expected {}, got {}",
            node.sha256, actual_sha256
        ));
    }
    let report: chio_runtime_proof_parity::RuntimeProofParityReport = serde_json::from_slice(bytes)
        .map_err(|error| format!("proof-room.runtime-parity.invalid-json: {error}"))?;
    chio_runtime_proof_parity::validate_runtime_proof_parity_report(&report)
        .map_err(|error| format!("proof-room.runtime-parity.invalid: {error}"))?;
    serde_json::to_value(report)
        .map(Some)
        .map_err(|error| format!("proof-room.runtime-parity.report-encode: {error}"))
}

fn validate_source_runtime_proof_regeneration_artifacts(
    context: &SourceVerifierContext,
) -> Result<(), String> {
    let graph: SourceRuntimeParityEvidenceGraph =
        serde_json::from_slice(&context.evidence_graph_bytes)
            .map_err(|error| format!("proof-room.evidence-graph.invalid-json: {error}"))?;
    if !graph
        .nodes
        .iter()
        .any(source_runtime_proof_regeneration_node_is_present)
    {
        return Ok(());
    }
    let proof_regeneration_report = source_runtime_graph_artifact_bytes(
        context,
        &graph.nodes,
        "runtime-proof-regeneration-report",
        Some(chio_runtime_proof_parity::CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA),
    )?;
    let proof_regeneration_input = source_runtime_graph_artifact_bytes(
        context,
        &graph.nodes,
        "runtime-proof-regeneration-input",
        Some(chio_runtime_proof_parity::CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA),
    )?;
    let evidence_manifest = source_runtime_graph_artifact_bytes(
        context,
        &graph.nodes,
        "runtime-evidence-manifest",
        Some(chio_runtime_proof_parity::CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA),
    )?;
    let workflow_run_report = source_runtime_graph_artifact_bytes(
        context,
        &graph.nodes,
        "runtime-workflow-run-report",
        Some(chio_runtime_proof_parity::CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA),
    )?;
    let proof_package =
        source_runtime_graph_artifact_bytes(context, &graph.nodes, "runtime-proof-package", None)?;
    let verifier_report = source_runtime_graph_artifact_bytes(
        context,
        &graph.nodes,
        "runtime-verifier-report",
        None,
    )?;
    let workflow_receipt = source_runtime_graph_artifact_bytes(
        context,
        &graph.nodes,
        "runtime-workflow-receipt",
        None,
    )?;

    chio_runtime_proof_parity::validate_runtime_proof_regeneration_artifacts(
        chio_runtime_proof_parity::RuntimeProofRegenerationArtifacts {
            proof_regeneration_report,
            proof_regeneration_input,
            evidence_manifest,
            workflow_run_report,
            proof_package,
            verifier_report,
            workflow_receipt,
        },
    )
    .map_err(|error| format!("proof-room.runtime-regeneration.invalid: {error}"))
}

fn source_runtime_proof_regeneration_node_is_present(
    node: &SourceRuntimeParityEvidenceNode,
) -> bool {
    matches!(
        node.role.as_str(),
        "runtime-proof-regeneration-report"
            | "runtime-proof-regeneration-input"
            | "runtime-evidence-manifest"
            | "runtime-workflow-run-report"
    ) || matches!(
        node.schema.as_str(),
        chio_runtime_proof_parity::CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA
            | chio_runtime_proof_parity::CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA
            | chio_runtime_proof_parity::CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA
            | chio_runtime_proof_parity::CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA
    )
}

fn source_runtime_graph_artifact_bytes<'a>(
    context: &'a SourceVerifierContext,
    nodes: &[SourceRuntimeParityEvidenceNode],
    role: &str,
    schema: Option<&str>,
) -> Result<&'a [u8], String> {
    let matching_nodes = nodes
        .iter()
        .filter(|node| {
            node.role == role
                || schema.is_some_and(|expected_schema| node.schema.as_str() == expected_schema)
        })
        .collect::<Vec<_>>();
    let node = match matching_nodes.as_slice() {
        [node] => *node,
        [] => {
            return Err(format!(
                "proof-room.runtime-regeneration.artifact-missing: {role}"
            ));
        }
        _ => {
            return Err(format!(
                "proof-room.runtime-regeneration.artifact-duplicate: {role}"
            ));
        }
    };
    if let Some(expected_schema) = schema {
        if node.schema != expected_schema {
            return Err(format!(
                "proof-room.runtime-regeneration.schema-unsupported: {role}: {}",
                node.schema
            ));
        }
    }
    let bytes = context.artifacts.get(&node.path).ok_or_else(|| {
        format!(
            "proof-room.runtime-regeneration.artifact-missing: {}",
            node.path
        )
    })?;
    let actual_sha256 = sha256_hex(bytes);
    if actual_sha256 != node.sha256 {
        return Err(format!(
            "proof-room.runtime-regeneration.hash-mismatch: {role}: expected {}, got {}",
            node.sha256, actual_sha256
        ));
    }
    Ok(bytes)
}

fn load_standalone_evidence_graph_artifacts(
    bundle_root: &Path,
    passport_dir: &Path,
    evidence_graph_bytes: &[u8],
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let graph: StandaloneEvidenceGraphArtifactIndex = serde_json::from_slice(evidence_graph_bytes)
        .map_err(|error| format!("proof-room.evidence-graph.invalid-json: {error}"))?;
    let mut artifacts = BTreeMap::new();
    for node in graph.nodes {
        validate_bundle_relative_path(&node.path)?;
        let artifact_path = if bundle_root.join(&node.path).exists() {
            resolve_nested_bundle_path(bundle_root, bundle_root, &node.path)?
        } else if passport_dir.join(&node.path).exists() {
            resolve_nested_bundle_path(bundle_root, passport_dir, &node.path)?
        } else {
            continue;
        };
        let bytes = fs::read(&artifact_path)
            .map_err(|error| format!("proof-room.artifact.unreadable: {}: {error}", node.path))?;
        artifacts.insert(node.path, bytes);
    }
    load_enterprise_export_sidecar_artifacts(bundle_root, passport_dir, &mut artifacts)?;
    Ok(artifacts)
}

fn load_enterprise_export_sidecar_artifacts(
    bundle_root: &Path,
    passport_dir: &Path,
    artifacts: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    let export_bundle_paths = artifacts
        .iter()
        .filter_map(|(path, bytes)| {
            let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
            (value.get("schema").and_then(serde_json::Value::as_str)
                == Some(ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_SCHEMA))
            .then(|| path.clone())
        })
        .collect::<Vec<_>>();

    for export_bundle_path in export_bundle_paths {
        let export_bundle_bytes = artifacts
            .get(&export_bundle_path)
            .ok_or_else(|| format!("proof-room.enterprise-export.missing: {export_bundle_path}"))?;
        let sidecar_paths = enterprise_export_sidecar_paths(export_bundle_bytes)?;
        for sidecar_path in sidecar_paths {
            if artifacts.contains_key(&sidecar_path) {
                continue;
            }
            validate_bundle_relative_path(&sidecar_path)?;
            let artifact_path = if bundle_root.join(&sidecar_path).exists() {
                resolve_nested_bundle_path(bundle_root, bundle_root, &sidecar_path)?
            } else {
                resolve_nested_bundle_path(bundle_root, passport_dir, &sidecar_path)?
            };
            let bytes = fs::read(&artifact_path).map_err(|error| {
                format!("proof-room.artifact.unreadable: {sidecar_path}: {error}")
            })?;
            artifacts.insert(sidecar_path, bytes);
        }
    }
    Ok(())
}

fn enterprise_export_sidecar_paths(export_bundle_bytes: &[u8]) -> Result<Vec<String>, String> {
    #[derive(serde::Deserialize)]
    struct ExportBundlePaths {
        artifacts: Vec<ExportArtifactPath>,
    }

    #[derive(serde::Deserialize)]
    struct ExportArtifactPath {
        path: String,
    }

    let export_bundle: ExportBundlePaths = serde_json::from_slice(export_bundle_bytes)
        .map_err(|error| format!("proof-room.enterprise-export.invalid-json: {error}"))?;
    Ok(export_bundle
        .artifacts
        .into_iter()
        .map(|artifact| artifact.path)
        .collect())
}

fn verify_proof_room_report(
    bytes: &[u8],
    bundle_id: &str,
    fixture_id: &str,
    verifier_report_ref: &ProofRoomArtifactRef,
    source_verifier_verdict: &str,
    manifest_claims: &[ProofRoomClaim],
) -> Result<(), String> {
    let report_value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("proof-room.ui-report.invalid-json: {error}"))?;
    validate_proof_room_schema(
        &report_value,
        PROOF_ROOM_VERIFIER_REPORT_SCHEMA_JSON,
        "ui-report",
    )?;
    let report: ProofRoomVerifierReport = serde_json::from_value(report_value)
        .map_err(|error| format!("proof-room.ui-report.invalid-json: {error}"))?;
    if report.schema != PROOF_ROOM_VERIFIER_REPORT_SCHEMA {
        return Err(format!(
            "proof-room.ui-report.schema-mismatch: expected {PROOF_ROOM_VERIFIER_REPORT_SCHEMA}"
        ));
    }
    if report.bundle_id != bundle_id {
        return Err("proof-room.ui-report.bundle-mismatch".to_string());
    }
    if report.fixture_id != fixture_id {
        return Err("proof-room.ui-report.fixture-mismatch".to_string());
    }
    if report.verdict != "verified" && report.verdict != "failed" {
        return Err("proof-room.ui-report.verdict-not-verified".to_string());
    }
    if report.verdict != source_verifier_verdict {
        return Err("proof-room.ui-report.verdict-mismatch".to_string());
    }
    if report.ui_verdict_source != "verifier_report_ref" {
        return Err("proof-room.ui.verdict-unauthenticated".to_string());
    }
    if report.source_verifier_report_ref.path != verifier_report_ref.path
        || report.source_verifier_report_ref.sha256 != verifier_report_ref.sha256
        || report.source_verifier_report_ref.schema != verifier_report_ref.schema
    {
        return Err("proof-room.report.hash-mismatch: UI report source ref drifted".to_string());
    }
    verify_rendered_claims(
        &report.rendered_claims,
        verifier_report_ref,
        manifest_claims,
    )?;
    Ok(())
}

fn verify_rendered_claims(
    rendered_claims: &[ProofRoomRenderedClaim],
    verifier_report_ref: &ProofRoomArtifactRef,
    manifest_claims: &[ProofRoomClaim],
) -> Result<(), String> {
    if rendered_claims.is_empty() {
        return Err("proof-room.ui-report.rendered-claims-missing".to_string());
    }
    let mut rendered_claim_ids = BTreeSet::new();
    for rendered_claim in rendered_claims {
        if !rendered_claim_ids.insert(rendered_claim.claim_id.as_str()) {
            return Err(format!(
                "proof-room.ui-report.rendered-claim-duplicate: {}",
                rendered_claim.claim_id
            ));
        }
        let Some(manifest_claim) = manifest_claims
            .iter()
            .find(|claim| claim.claim_id == rendered_claim.claim_id)
        else {
            return Err(format!(
                "proof-room.ui-report.rendered-claim-unbacked: {}",
                rendered_claim.claim_id
            ));
        };
        if rendered_claim.source != verifier_report_ref.path
            && !manifest_claim
                .required_artifacts
                .iter()
                .any(|artifact| artifact == &rendered_claim.source)
        {
            return Err(format!(
                "proof-room.ui-report.rendered-claim-source-unbacked: {} -> {}",
                rendered_claim.claim_id, rendered_claim.source
            ));
        }
        if !matches!(
            rendered_claim.verdict.as_str(),
            "verified" | "failed" | "unsupported"
        ) {
            return Err(format!(
                "proof-room.ui-report.rendered-claim-verdict-invalid: {}",
                rendered_claim.claim_id
            ));
        }
        if rendered_claim.verdict == "verified"
            && !manifest_claim
                .required_artifacts
                .iter()
                .any(|artifact| artifact == &rendered_claim.source)
        {
            return Err(format!(
                "proof-room.ui-report.rendered-claim-source-unbacked: {} -> {}",
                rendered_claim.claim_id, rendered_claim.source
            ));
        }
    }
    for manifest_claim in manifest_claims {
        if !rendered_claim_ids.contains(manifest_claim.claim_id.as_str()) {
            return Err(format!(
                "proof-room.ui-report.rendered-claim-missing: {}",
                manifest_claim.claim_id
            ));
        }
    }
    Ok(())
}

fn validate_json_artifact_schema(
    bytes: &[u8],
    expected_schema: &str,
    label: &str,
) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("proof-room.artifact.invalid-json: {label}: {error}"))?;
    match value.get("schema").and_then(serde_json::Value::as_str) {
        Some(actual_schema) if actual_schema == expected_schema => Ok(()),
        Some(actual_schema) => Err(format!(
            "proof-room.schema-mismatch: {label} expected {expected_schema} got {actual_schema}"
        )),
        None => Err(format!(
            "proof-room.schema-missing: {label} missing schema field"
        )),
    }?;
    if let Some(schema_json) = proof_room_artifact_schema_json(expected_schema) {
        validate_proof_room_schema(&value, schema_json, label)?;
    }
    Ok(())
}

fn proof_room_artifact_schema_json(schema: &str) -> Option<&'static str> {
    match schema {
        PROOF_ROOM_VERIFIER_REPORT_SCHEMA => Some(PROOF_ROOM_VERIFIER_REPORT_SCHEMA_JSON),
        PROOF_ROOM_DOCKER_QUICKSTART_EVIDENCE_SCHEMA => {
            Some(PROOF_ROOM_DOCKER_QUICKSTART_EVIDENCE_SCHEMA_JSON)
        }
        PROOF_ROOM_RELEASE_TRUTH_SCHEMA => Some(PROOF_ROOM_RELEASE_TRUTH_SCHEMA_JSON),
        PROOF_ROOM_FIRST_RUN_CAPABILITY_PROOF_SCHEMA => {
            Some(PROOF_ROOM_FIRST_RUN_CAPABILITY_PROOF_SCHEMA_JSON)
        }
        PROOF_ROOM_FIRST_RUN_GUARD_REPORT_SCHEMA => {
            Some(PROOF_ROOM_FIRST_RUN_GUARD_REPORT_SCHEMA_JSON)
        }
        PROOF_ROOM_FIRST_RUN_TRUST_ROOTS_SCHEMA => {
            Some(PROOF_ROOM_FIRST_RUN_TRUST_ROOTS_SCHEMA_JSON)
        }
        PROOF_ROOM_FIRST_RUN_COMMAND_LOG_SCHEMA => {
            Some(PROOF_ROOM_FIRST_RUN_COMMAND_LOG_SCHEMA_JSON)
        }
        PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA => Some(PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA_JSON),
        TRANSACTION_REQUEST_DIGEST_SCHEMA => Some(TRANSACTION_REQUEST_DIGEST_SCHEMA_JSON),
        TRANSACTION_RESPONSE_DIGEST_SCHEMA => Some(TRANSACTION_RESPONSE_DIGEST_SCHEMA_JSON),
        RUNTIME_TERMINAL_RECEIPT_SCHEMA => Some(RUNTIME_TERMINAL_RECEIPT_SCHEMA_JSON),
        _ => None,
    }
}

fn validate_proof_room_schema(
    value: &serde_json::Value,
    schema_json: &str,
    label: &str,
) -> Result<(), String> {
    let schema: serde_json::Value = serde_json::from_str(schema_json)
        .map_err(|error| format!("proof-room.schema-invalid: {label}: {error}"))?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|error| format!("proof-room.schema-invalid: {label}: {error}"))?;
    if validator.is_valid(value) {
        return Ok(());
    }
    let errors = validator
        .iter_errors(value)
        .map(|error| error.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    Err(format!("proof-room.schema-violation: {label}: {errors}"))
}

fn resolve_proof_room_bundle_path(
    bundle_root: &Path,
    relative_path: &str,
) -> Result<PathBuf, String> {
    validate_bundle_relative_path(relative_path)?;
    let bundle_root = fs::canonicalize(bundle_root)
        .map_err(|error| format!("proof-room.bundle.unreadable: {error}"))?;
    let joined_path = bundle_root.join(relative_path);
    let resolved_path = fs::canonicalize(&joined_path)
        .map_err(|error| format!("proof-room.artifact.unreadable: {relative_path}: {error}"))?;
    if resolved_path.starts_with(&bundle_root) {
        Ok(resolved_path)
    } else {
        Err(format!(
            "proof-room.artifact.escape: artifact path escapes bundle: {relative_path}"
        ))
    }
}

fn resolve_nested_bundle_path(
    bundle_root: &Path,
    base_dir: &Path,
    relative_path: &str,
) -> Result<PathBuf, String> {
    validate_bundle_relative_path(relative_path)?;
    let bundle_root = fs::canonicalize(bundle_root)
        .map_err(|error| format!("proof-room.bundle.unreadable: {error}"))?;
    let joined_path = base_dir.join(relative_path);
    let resolved_path = fs::canonicalize(&joined_path)
        .map_err(|error| format!("proof-room.artifact.unreadable: {relative_path}: {error}"))?;
    if resolved_path.starts_with(&bundle_root) {
        Ok(resolved_path)
    } else {
        Err(format!(
            "proof-room.artifact.escape: artifact path escapes bundle: {relative_path}"
        ))
    }
}

fn validate_bundle_relative_path(relative_path: &str) -> Result<(), String> {
    if relative_path.is_empty()
        || relative_path.starts_with('/')
        || relative_path.contains('\\')
        || relative_path.contains(':')
        || relative_path.contains("//")
        || relative_path
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(unsafe_bundle_path_error(relative_path));
    }
    for segment in relative_path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(unsafe_bundle_path_error(relative_path));
        }
        let decoded = percent_decode_path_segment(segment, relative_path)?;
        if decoded.is_empty()
            || decoded == "."
            || decoded == ".."
            || decoded.contains('/')
            || decoded.contains('\\')
            || decoded
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(unsafe_bundle_path_error(relative_path));
        }
    }
    Ok(())
}

fn percent_decode_path_segment(segment: &str, full_path: &str) -> Result<String, String> {
    let bytes = segment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(unsafe_bundle_path_error(full_path));
            }
            let high =
                hex_value(bytes[index + 1]).ok_or_else(|| unsafe_bundle_path_error(full_path))?;
            let low =
                hex_value(bytes[index + 2]).ok_or_else(|| unsafe_bundle_path_error(full_path))?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| unsafe_bundle_path_error(full_path))
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn unsafe_bundle_path_error(relative_path: &str) -> String {
    format!("proof-room.artifact.unsafe-path: {relative_path}")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn default_base_manifest() -> String {
    "manifest.json".to_string()
}

fn create_negative_case_work_dir(case_id: &str) -> Result<PathBuf, String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("proof-room.negative-case.clock: {error}"))?
        .as_nanos();
    let mut path = env::temp_dir();
    path.push(format!(
        "chio-proof-room-negative-{}-{timestamp}-{}",
        process::id(),
        sanitize_temp_path_component(case_id)
    ));
    fs::create_dir(&path).map_err(|error| {
        format!(
            "proof-room.negative-case.tempdir: {}: {error}",
            path.display()
        )
    })?;
    Ok(path)
}

fn sanitize_temp_path_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn validate_bundle_tree_file_types(root: &Path) -> Result<(), String> {
    let file_type = fs::symlink_metadata(root)
        .map_err(|error| format!("proof-room.bundle.walk: {}: {error}", root.display()))?
        .file_type();
    if !file_type.is_dir() {
        return Err(format!(
            "unsupported proof bundle file type: {}",
            root.display()
        ));
    }
    validate_bundle_tree_file_types_from(root)
}

fn validate_bundle_tree_file_types_from(current: &Path) -> Result<(), String> {
    for entry in fs::read_dir(current)
        .map_err(|error| format!("proof-room.bundle.walk: {}: {error}", current.display()))?
    {
        let entry = entry
            .map_err(|error| format!("proof-room.bundle.walk: {}: {error}", current.display()))?;
        let path = entry.path();
        let file_type = fs::symlink_metadata(&path)
            .map_err(|error| format!("proof-room.bundle.walk: {}: {error}", path.display()))?
            .file_type();
        if file_type.is_dir() {
            validate_bundle_tree_file_types_from(&path)?;
        } else if !file_type.is_file() {
            return Err(format!(
                "unsupported proof bundle file type: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn copy_dir_all(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(|error| {
        format!(
            "proof-room.negative-case.copy: {}: {error}",
            destination.display()
        )
    })?;
    for entry in fs::read_dir(source).map_err(|error| {
        format!(
            "proof-room.negative-case.copy: {}: {error}",
            source.display()
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "proof-room.negative-case.copy: {}: {error}",
                source.display()
            )
        })?;
        let file_type = entry.file_type().map_err(|error| {
            format!(
                "proof-room.negative-case.copy: {}: {error}",
                entry.path().display()
            )
        })?;
        let destination_path = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), &destination_path).map_err(|error| {
                format!(
                    "proof-room.negative-case.copy: {}: {error}",
                    destination_path.display()
                )
            })?;
        } else {
            return Err(format!(
                "proof-room.negative-case.copy: unsupported file type: {}",
                entry.path().display()
            ));
        }
    }
    Ok(())
}

fn apply_proof_room_negative_descriptor(
    bundle: &Path,
    descriptor: &ProofRoomNegativeDescriptor,
) -> Result<(), String> {
    let manifest_path = resolve_proof_room_bundle_path(bundle, &descriptor.base_manifest)?;
    let mut manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(&manifest_path)
            .map_err(|error| format!("proof-room.negative-case.manifest: {error}"))?,
    )
    .map_err(|error| format!("proof-room.negative-case.manifest-json: {error}"))?;
    let mutation = &descriptor.mutation;

    if let Some(path) = mutation.get("path").and_then(serde_json::Value::as_array) {
        let value = mutation
            .get("value")
            .ok_or_else(|| "proof-room.negative-case.mutation-value-missing".to_string())?;
        set_json_path(&mut manifest, path, value.clone())?;
    } else if let Some(category) = mutation.get("category").and_then(serde_json::Value::as_str) {
        let terminal_status = mutation
            .get("terminal_status")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "proof-room.negative-case.terminal-status-missing".to_string())?;
        let coverage =
            find_array_object_mut(&mut manifest, "receipt_coverage", "category", category)?;
        coverage["terminal_status"] = serde_json::Value::String(terminal_status.to_string());
    } else if let Some(artifact_path) = mutation
        .get("artifact_path")
        .and_then(serde_json::Value::as_str)
    {
        if mutation.get("json_path").is_some() {
            mutate_json_artifact_and_rehash(bundle, &mut manifest, artifact_path, mutation)?;
        } else {
            remove_graph_node_and_rehash(bundle, &mut manifest, artifact_path)?;
        }
    } else if let Some(claim_id) = mutation.get("claim_id").and_then(serde_json::Value::as_str) {
        if let Some(required_artifacts) = mutation.get("required_artifacts") {
            let claim = find_array_object_mut(&mut manifest, "claims", "claim_id", claim_id)?;
            claim["required_artifacts"] = required_artifacts.clone();
        } else if let Some(artifact_paths) = mutation
            .get("artifact_paths")
            .and_then(serde_json::Value::as_array)
        {
            if let Some(claims) = manifest
                .get_mut("claims")
                .and_then(serde_json::Value::as_array_mut)
            {
                claims.retain(|claim| {
                    claim.get("claim_id").and_then(serde_json::Value::as_str) != Some(claim_id)
                });
            }
            let artifact_paths = artifact_paths
                .iter()
                .map(|path| {
                    path.as_str()
                        .ok_or_else(|| "proof-room.negative-case.artifact-path-invalid".to_string())
                        .map(str::to_string)
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            if let Some(artifacts) = manifest
                .get_mut("artifacts")
                .and_then(serde_json::Value::as_array_mut)
            {
                artifacts.retain(|artifact| {
                    artifact
                        .get("path")
                        .and_then(serde_json::Value::as_str)
                        .is_none_or(|path| !artifact_paths.contains(path))
                });
            }
            for artifact_path in artifact_paths {
                let resolved = resolve_proof_room_bundle_path(bundle, &artifact_path)?;
                fs::remove_file(&resolved).map_err(|error| {
                    format!("proof-room.negative-case.remove-artifact: {artifact_path}: {error}")
                })?;
            }
        } else {
            return Err("proof-room.negative-case.claim-mutation-unsupported".to_string());
        }
    } else {
        return Err("proof-room.negative-case.mutation-unsupported".to_string());
    }

    write_json_file(&manifest_path, &manifest)?;
    refresh_bundle_signature(bundle)?;
    Ok(())
}

fn mutate_json_artifact_and_rehash(
    bundle: &Path,
    manifest: &mut serde_json::Value,
    artifact_path: &str,
    mutation: &serde_json::Value,
) -> Result<(), String> {
    let json_path = mutation
        .get("json_path")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "proof-room.negative-case.json-path-missing".to_string())?;
    let value = mutation
        .get("value")
        .ok_or_else(|| "proof-room.negative-case.mutation-value-missing".to_string())?;
    let resolved = resolve_proof_room_bundle_path(bundle, artifact_path)?;
    let mut artifact: serde_json::Value =
        serde_json::from_slice(&fs::read(&resolved).map_err(|error| {
            format!("proof-room.negative-case.artifact: {artifact_path}: {error}")
        })?)
        .map_err(|error| {
            format!("proof-room.negative-case.artifact-json: {artifact_path}: {error}")
        })?;
    set_json_path(&mut artifact, json_path, value.clone())?;
    write_json_file(&resolved, &artifact)?;
    let artifact_sha256 = sha256_file(&resolved)?;

    update_graph_node_hash_and_rehash(bundle, manifest, artifact_path, &artifact_sha256)
}

fn find_array_object_mut<'a>(
    value: &'a mut serde_json::Value,
    array_field: &str,
    key: &str,
    expected: &str,
) -> Result<&'a mut serde_json::Value, String> {
    let array = value
        .get_mut(array_field)
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| format!("proof-room.negative-case.array-missing: {array_field}"))?;
    array
        .iter_mut()
        .find(|entry| entry.get(key).and_then(serde_json::Value::as_str) == Some(expected))
        .ok_or_else(|| {
            format!("proof-room.negative-case.array-entry-missing: {array_field}.{key}={expected}")
        })
}

fn set_json_path(
    value: &mut serde_json::Value,
    path: &[serde_json::Value],
    replacement: serde_json::Value,
) -> Result<(), String> {
    let mut cursor = value;
    let Some((last, parents)) = path.split_last() else {
        return Err("proof-room.negative-case.path-empty".to_string());
    };
    for segment in parents {
        let key = segment
            .as_str()
            .ok_or_else(|| "proof-room.negative-case.path-segment-invalid".to_string())?;
        cursor = cursor
            .get_mut(key)
            .ok_or_else(|| format!("proof-room.negative-case.path-missing: {key}"))?;
    }
    let key = last
        .as_str()
        .ok_or_else(|| "proof-room.negative-case.path-segment-invalid".to_string())?;
    let object = cursor
        .as_object_mut()
        .ok_or_else(|| "proof-room.negative-case.path-parent-invalid".to_string())?;
    if !object.contains_key(key) {
        return Err(format!("proof-room.negative-case.path-missing: {key}"));
    }
    object.insert(key.to_string(), replacement);
    Ok(())
}

fn remove_graph_node_and_rehash(
    bundle: &Path,
    manifest: &mut serde_json::Value,
    artifact_path: &str,
) -> Result<(), String> {
    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &fs::read(&evidence_graph_path)
            .map_err(|error| format!("proof-room.negative-case.evidence-graph: {error}"))?,
    )
    .map_err(|error| format!("proof-room.negative-case.evidence-graph-json: {error}"))?;
    evidence_graph["nodes"]
        .as_array_mut()
        .ok_or_else(|| "proof-room.negative-case.evidence-graph-nodes-missing".to_string())?
        .retain(|node| node.get("path").and_then(serde_json::Value::as_str) != Some(artifact_path));
    write_json_file(&evidence_graph_path, &evidence_graph)?;
    refresh_roots_and_manifest_after_evidence_graph_change(bundle, manifest)
}

fn update_graph_node_hash_and_rehash(
    bundle: &Path,
    manifest: &mut serde_json::Value,
    artifact_path: &str,
    artifact_sha256: &str,
) -> Result<(), String> {
    set_manifest_artifact_hash(manifest, artifact_path, artifact_sha256)?;
    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &fs::read(&evidence_graph_path)
            .map_err(|error| format!("proof-room.negative-case.evidence-graph: {error}"))?,
    )
    .map_err(|error| format!("proof-room.negative-case.evidence-graph-json: {error}"))?;
    let node = evidence_graph["nodes"]
        .as_array_mut()
        .ok_or_else(|| "proof-room.negative-case.evidence-graph-nodes-missing".to_string())?
        .iter_mut()
        .find(|node| node.get("path").and_then(serde_json::Value::as_str) == Some(artifact_path))
        .ok_or_else(|| {
            format!("proof-room.negative-case.evidence-graph-node-missing: {artifact_path}")
        })?;
    node["sha256"] = serde_json::Value::String(artifact_sha256.to_string());
    write_json_file(&evidence_graph_path, &evidence_graph)?;
    refresh_roots_and_manifest_after_evidence_graph_change(bundle, manifest)
}

fn refresh_roots_and_manifest_after_evidence_graph_change(
    bundle: &Path,
    manifest: &mut serde_json::Value,
) -> Result<(), String> {
    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let passport_path = bundle.join("roots/transaction-passport.json");
    let mut passport: serde_json::Value = serde_json::from_slice(
        &fs::read(&passport_path)
            .map_err(|error| format!("proof-room.negative-case.passport: {error}"))?,
    )
    .map_err(|error| format!("proof-room.negative-case.passport-json: {error}"))?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
    write_json_file(&passport_path, &passport)?;
    let passport_sha256 = sha256_file(&passport_path)?;

    let verifier_report_path = bundle.join("verifier/report.json");
    let mut verifier_report: serde_json::Value = serde_json::from_slice(
        &fs::read(&verifier_report_path)
            .map_err(|error| format!("proof-room.negative-case.verifier-report: {error}"))?,
    )
    .map_err(|error| format!("proof-room.negative-case.verifier-report-json: {error}"))?;
    verifier_report["evidence_graph_sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    write_json_file(&verifier_report_path, &verifier_report)?;
    let verifier_report_sha256 = sha256_file(&verifier_report_path)?;

    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    let mut ui_report: serde_json::Value = serde_json::from_slice(
        &fs::read(&ui_report_path)
            .map_err(|error| format!("proof-room.negative-case.ui-report: {error}"))?,
    )
    .map_err(|error| format!("proof-room.negative-case.ui-report-json: {error}"))?;
    ui_report["source_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    write_json_file(&ui_report_path, &ui_report)?;
    let ui_report_sha256 = sha256_file(&ui_report_path)?;

    set_manifest_hash(manifest, "transaction_passport_ref", &passport_sha256)?;
    set_manifest_hash(manifest, "evidence_graph_ref", &evidence_graph_sha256)?;
    set_manifest_hash(manifest, "verifier_report_ref", &verifier_report_sha256)?;
    set_manifest_hash(
        manifest,
        "proof_room_verifier_report_ref",
        &ui_report_sha256,
    )?;
    set_manifest_artifact_hash(
        manifest,
        "roots/transaction-passport.json",
        &passport_sha256,
    )?;
    set_manifest_artifact_hash(
        manifest,
        "roots/evidence-graph.json",
        &evidence_graph_sha256,
    )?;
    set_manifest_artifact_hash(manifest, "verifier/report.json", &verifier_report_sha256)?;
    set_manifest_artifact_hash(
        manifest,
        "ui/proof-room-static/load-report.json",
        &ui_report_sha256,
    )?;
    Ok(())
}

fn set_manifest_hash(
    manifest: &mut serde_json::Value,
    field: &str,
    sha256: &str,
) -> Result<(), String> {
    let reference = manifest
        .get_mut(field)
        .ok_or_else(|| format!("proof-room.negative-case.manifest-ref-missing: {field}"))?;
    reference["sha256"] = serde_json::Value::String(sha256.to_string());
    Ok(())
}

fn set_manifest_artifact_hash(
    manifest: &mut serde_json::Value,
    path: &str,
    sha256: &str,
) -> Result<(), String> {
    let artifact = find_array_object_mut(manifest, "artifacts", "path", path)?;
    artifact["sha256"] = serde_json::Value::String(sha256.to_string());
    Ok(())
}

fn refresh_bundle_signature(bundle: &Path) -> Result<(), String> {
    let manifest_path = bundle.join("manifest.json");
    let signature_path = bundle.join("bundle-signature.dsse.json");
    let mut signature: serde_json::Value = serde_json::from_slice(
        &fs::read(&signature_path)
            .map_err(|error| format!("proof-room.signature.unreadable: {error}"))?,
    )
    .map_err(|error| format!("proof-room.signature.invalid-json: {error}"))?;
    signature["payloadRef"]["sha256"] = serde_json::Value::String(sha256_file(&manifest_path)?);
    write_json_file(&signature_path, &signature)
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "proof-room.artifact.unreadable: {}: {error}",
            path.display()
        )
    })?;
    Ok(sha256_hex(&bytes))
}

fn write_json_file(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("proof-room.json.encode: {}: {error}", path.display()))?;
    bytes.push(b'\n');
    fs::write(path, bytes)
        .map_err(|error| format!("proof-room.json.write: {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, error::Error, fs, path::Path};

    use axum::{
        body::{to_bytes, Body},
        http::{header::CONTENT_TYPE, Request, StatusCode},
    };
    use chio_core_types::Keypair;
    use tower::ServiceExt;

    use super::{
        crypto_context_verified_report_bytes, proof_room_router as build_proof_room_router,
        proof_room_router_with_fixture_root as build_proof_room_router_with_fixture_root,
        verify_proof_room_bundle,
    };

    const TEST_SIGNATURE_SEED: [u8; 32] = [7; 32];
    const TEST_RECEIPT_SEED: [u8; 32] = [23; 32];

    fn proof_room_router(bundle: std::path::PathBuf, ui_dir: std::path::PathBuf) -> axum::Router {
        match build_proof_room_router(bundle, ui_dir) {
            Ok(router) => router,
            Err(error) => panic!("proof room router builds: {error}"),
        }
    }

    fn proof_room_router_with_fixture_root(
        bundle: std::path::PathBuf,
        ui_dir: std::path::PathBuf,
        fixture_root: std::path::PathBuf,
    ) -> axum::Router {
        match build_proof_room_router_with_fixture_root(bundle, ui_dir, Some(fixture_root)) {
            Ok(router) => router,
            Err(error) => panic!("proof room router builds: {error}"),
        }
    }

    fn proof_room_router_with_repo_fixture_root(
        bundle: std::path::PathBuf,
        ui_dir: std::path::PathBuf,
    ) -> Result<axum::Router, Box<dyn Error>> {
        Ok(proof_room_router_with_fixture_root(
            bundle,
            ui_dir,
            repo_root()?.join("fixtures/proof-room"),
        ))
    }

    #[test]
    fn source_runtime_parity_rejects_tampered_proof_regeneration_report(
    ) -> Result<(), Box<dyn Error>> {
        let context = runtime_regeneration_context(true)?;
        let mut report = serde_json::json!({});

        let error = super::attach_source_runtime_proof_parity_report(&context, &mut report)
            .err()
            .ok_or("tampered runtime proof regeneration report unexpectedly verified")?;

        assert!(
            error.contains("runtime proof regeneration report hash mismatch"),
            "{error}"
        );
        Ok(())
    }

    fn runtime_regeneration_context(
        tamper_report: bool,
    ) -> Result<super::SourceVerifierContext, Box<dyn Error>> {
        let passport_bytes = fs::read(
            repo_root()?
                .join("fixtures/proof-room/minimal-passport/valid/transaction-passport.json"),
        )?;
        let passport: chio_transaction_passport::TransactionPassport =
            serde_json::from_slice(&passport_bytes)?;
        let proof_package = serde_json::json!({
            "schema": "test.runtime-proof-package.v1",
            "packageId": "runtime-proof-package-1"
        });
        let verifier_report = serde_json::json!({
            "schema": "test.runtime-verifier-report.v1",
            "verdict": "verified"
        });
        let workflow_receipt = serde_json::json!({
            "schema": "test.runtime-workflow-receipt.v1",
            "receiptId": "runtime-workflow-receipt-1"
        });
        let proof_package_bytes = json_bytes(&proof_package)?;
        let verifier_report_bytes = json_bytes(&verifier_report)?;
        let workflow_receipt_bytes = json_bytes(&workflow_receipt)?;
        let proof_package_sha256 = canonical_json_sha256(&proof_package)?;
        let verifier_report_sha256 = canonical_json_sha256(&verifier_report)?;
        let workflow_receipt_sha256 = canonical_json_sha256(&workflow_receipt)?;
        let source_record = serde_json::json!({
            "stepIndex": 0,
            "admissionReportSha256": "a".repeat(64),
            "toolReceiptSha256": "b".repeat(64),
            "bilateralDsseSha256": "c".repeat(64),
            "workflowStepSha256": "d".repeat(64)
        });
        let proof_report = serde_json::json!({
            "schema": "chio.runtime.proof-regeneration-report.v1",
            "runId": "runtime-loopback-1",
            "accepted": true,
            "generatedAtUnixMs": 1_800_000_000_000u64,
            "proofPackageSha256": proof_package_sha256,
            "verifierReportSha256": verifier_report_sha256,
            "workflowReceiptSha256": workflow_receipt_sha256,
            "sourceRecords": [source_record.clone()],
            "checks": ["runtime_regeneration.source_records_bound"]
        });
        let proof_report_sha256 = canonical_json_sha256(&proof_report)?;
        let workflow_report = serde_json::json!({
            "schema": "chio.runtime.workflow-run-report.v1",
            "runId": "runtime-loopback-1",
            "accepted": true,
            "generatedAtUnixMs": 1_800_000_000_000u64,
            "admissionReportSha256": "a".repeat(64),
            "evidencePaths": ["proof-regeneration-report.json"],
            "stepEvidence": [{
                "schema": "chio.runtime.step-evidence.v1",
                "stepIndex": 0,
                "admissionId": "admission-1",
                "admissionReportSha256": "a".repeat(64),
                "toolReceiptId": "tool-receipt-1",
                "toolReceiptSha256": "b".repeat(64),
                "outputSha256": "e".repeat(64),
                "bilateralDsseSha256": "c".repeat(64),
                "workflowStepSha256": "d".repeat(64),
                "consistencyAnchor": "anchor-1",
                "destructive": false
            }],
            "proofRegenerationReportSha256": proof_report_sha256
        });
        let workflow_report_bytes = json_bytes(&workflow_report)?;
        let workflow_report_sha256 = canonical_json_sha256(&workflow_report)?;
        let manifest = serde_json::json!({
            "schema": "chio.runtime.evidence-manifest.v1",
            "runId": "runtime-loopback-1",
            "generatedAtUnixMs": 1_800_000_000_000u64,
            "workflowRunReportSha256": workflow_report_sha256,
            "proofRegenerationReportSha256": proof_report_sha256,
            "entries": [
                runtime_manifest_entry("proof_package", "runtime-proof-package.json", &proof_package_bytes),
                runtime_manifest_entry("verifier_report", "runtime-verifier-report.json", &verifier_report_bytes),
                runtime_manifest_entry("workflow_receipt", "runtime-workflow-receipt.json", &workflow_receipt_bytes),
                runtime_manifest_entry("proof_regeneration_report", "proof-regeneration-report.json", &json_bytes(&proof_report)?),
                runtime_manifest_entry("runtime_run_report", "runtime-workflow-run-report.json", &workflow_report_bytes)
            ]
        });
        let manifest_bytes = json_bytes(&manifest)?;
        let manifest_sha256 = canonical_json_sha256(&manifest)?;
        let proof_input = serde_json::json!({
            "schema": "chio.runtime.proof-regeneration-input.v1",
            "runId": "runtime-loopback-1",
            "evidenceManifestSha256": manifest_sha256,
            "workflowRunReportSha256": workflow_report_sha256,
            "admissionReportSha256": "a".repeat(64),
            "trustBundleSha256": "f".repeat(64),
            "verificationContextSha256": "1".repeat(64),
            "sourceRecords": [source_record]
        });
        let mut proof_report_for_artifact = proof_report;
        if tamper_report {
            proof_report_for_artifact["checks"]
                .as_array_mut()
                .ok_or("proof report checks missing")?
                .push(serde_json::Value::String(
                    "runtime_regeneration.tampered".to_string(),
                ));
        }
        let proof_report_bytes = json_bytes(&proof_report_for_artifact)?;
        let proof_input_bytes = json_bytes(&proof_input)?;
        let parity_report = serde_json::json!({
            "schema": chio_runtime_proof_parity::CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA,
            "runId": "runtime-loopback-1",
            "accepted": true,
            "generatedAtUnixMs": 1_800_000_000_000u64,
            "staticProofPackageSha256": "2".repeat(64),
            "runtimeProofPackageSha256": "2".repeat(64),
            "staticVerifierReportSha256": "3".repeat(64),
            "runtimeVerifierReportSha256": "3".repeat(64),
            "comparedFields": ["verified_claims"],
            "mismatches": []
        });
        let parity_report_bytes = json_bytes(&parity_report)?;

        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "runtime-proof-parity-report.json".to_string(),
            parity_report_bytes.clone(),
        );
        artifacts.insert(
            "proof-regeneration-report.json".to_string(),
            proof_report_bytes.clone(),
        );
        artifacts.insert(
            "proof-regeneration-input.json".to_string(),
            proof_input_bytes.clone(),
        );
        artifacts.insert(
            "runtime-evidence-manifest.json".to_string(),
            manifest_bytes.clone(),
        );
        artifacts.insert(
            "runtime-workflow-run-report.json".to_string(),
            workflow_report_bytes.clone(),
        );
        artifacts.insert(
            "runtime-proof-package.json".to_string(),
            proof_package_bytes,
        );
        artifacts.insert(
            "runtime-verifier-report.json".to_string(),
            verifier_report_bytes,
        );
        artifacts.insert(
            "runtime-workflow-receipt.json".to_string(),
            workflow_receipt_bytes,
        );

        let evidence_graph = serde_json::json!({
            "nodes": [
                runtime_graph_node("runtime-proof-parity-report", chio_runtime_proof_parity::CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA, "runtime-proof-parity-report.json", &parity_report_bytes),
                runtime_graph_node("runtime-proof-regeneration-report", "chio.runtime.proof-regeneration-report.v1", "proof-regeneration-report.json", &proof_report_bytes),
                runtime_graph_node("runtime-proof-regeneration-input", "chio.runtime.proof-regeneration-input.v1", "proof-regeneration-input.json", &proof_input_bytes),
                runtime_graph_node("runtime-evidence-manifest", "chio.runtime.evidence-manifest.v1", "runtime-evidence-manifest.json", &manifest_bytes),
                runtime_graph_node("runtime-workflow-run-report", "chio.runtime.workflow-run-report.v1", "runtime-workflow-run-report.json", &workflow_report_bytes),
                runtime_graph_node("runtime-proof-package", "test.runtime-proof-package.v1", "runtime-proof-package.json", artifacts.get("runtime-proof-package.json").ok_or("proof package missing")?),
                runtime_graph_node("runtime-verifier-report", "test.runtime-verifier-report.v1", "runtime-verifier-report.json", artifacts.get("runtime-verifier-report.json").ok_or("verifier report missing")?),
                runtime_graph_node("runtime-workflow-receipt", "test.runtime-workflow-receipt.v1", "runtime-workflow-receipt.json", artifacts.get("runtime-workflow-receipt.json").ok_or("workflow receipt missing")?)
            ]
        });

        Ok(super::SourceVerifierContext {
            passport,
            passport_report_path: String::new(),
            evidence_graph_bytes: json_bytes(&evidence_graph)?,
            verifier_policy_bytes: Vec::new(),
            artifacts,
        })
    }

    fn runtime_manifest_entry(role: &str, path: &str, bytes: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "role": role,
            "path": path,
            "sha256": super::sha256_hex(bytes),
            "byteCount": bytes.len()
        })
    }

    fn runtime_graph_node(role: &str, schema: &str, path: &str, bytes: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "role": role,
            "schema": schema,
            "path": path,
            "sha256": super::sha256_hex(bytes)
        })
    }

    fn canonical_json_sha256(value: &serde_json::Value) -> Result<String, Box<dyn Error>> {
        let bytes = chio_core_types::crypto::canonical_json_bytes(value)?;
        Ok(super::sha256_hex(&bytes))
    }

    #[test]
    fn verifies_single_call_authority_bundle() -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?.join(
            "fixtures/proof-room/first-run/single-call-authority/proof-room-bundle/manifest.json",
        );

        verify_proof_room_bundle(&bundle)?;

        Ok(())
    }

    #[test]
    fn verifies_single_call_authority_bundle_runs_bad_receipt_signature_negative(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?.join(
            "fixtures/proof-room/first-run/single-call-authority/proof-room-bundle/manifest.json",
        );
        let manifest: serde_json::Value = serde_json::from_slice(&fs::read(&bundle)?)?;
        let has_bad_receipt_signature_negative = manifest
            .get("negative_cases")
            .and_then(serde_json::Value::as_array)
            .ok_or("manifest negative cases missing")?
            .iter()
            .any(|negative_case| {
                negative_case.get("id").and_then(serde_json::Value::as_str)
                    == Some("bad-receipt-signature")
            });

        assert!(has_bad_receipt_signature_negative);
        verify_proof_room_bundle(&bundle)?;

        Ok(())
    }

    #[test]
    fn verifies_single_call_authority_bundle_runs_stale_capability_negative(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?.join(
            "fixtures/proof-room/first-run/single-call-authority/proof-room-bundle/manifest.json",
        );
        let manifest: serde_json::Value = serde_json::from_slice(&fs::read(&bundle)?)?;
        let has_stale_capability_negative = manifest
            .get("negative_cases")
            .and_then(serde_json::Value::as_array)
            .ok_or("manifest negative cases missing")?
            .iter()
            .any(|negative_case| {
                negative_case.get("id").and_then(serde_json::Value::as_str)
                    == Some("stale-capability")
            });

        assert!(has_stale_capability_negative);
        verify_proof_room_bundle(&bundle)?;

        Ok(())
    }

    #[test]
    fn verifies_single_call_authority_bundle_runs_guard_deny_negative() -> Result<(), Box<dyn Error>>
    {
        let bundle = repo_root()?.join(
            "fixtures/proof-room/first-run/single-call-authority/proof-room-bundle/manifest.json",
        );
        let manifest: serde_json::Value = serde_json::from_slice(&fs::read(&bundle)?)?;
        let has_guard_deny_negative = manifest
            .get("negative_cases")
            .and_then(serde_json::Value::as_array)
            .ok_or("manifest negative cases missing")?
            .iter()
            .any(|negative_case| {
                negative_case.get("id").and_then(serde_json::Value::as_str) == Some("guard-deny")
            });

        assert!(has_guard_deny_negative);
        verify_proof_room_bundle(&bundle)?;

        Ok(())
    }

    #[test]
    fn rejects_source_family_verifier_policy_missing_schema_field() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source = root.join(
            "fixtures/proof-room/public-stages/commerce-transaction-passport/proof-room-bundle",
        );
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;
        remove_verifier_policy_field_and_rehash(work.path(), "omitted_claims")?;
        let manifest_path = work.path().join("manifest.json");

        let error = verify_proof_room_bundle(&manifest_path).err().ok_or(
            "proof room bundle with malformed source verifier policy unexpectedly verified",
        )?;

        assert!(
            error
                .to_string()
                .contains("proof-room.verifier-policy.invalid"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_receipt_coverage_status_mismatch() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;
        let manifest_path = work.path().join("manifest.json");
        let manifest = fs::read_to_string(&manifest_path)?;
        let mutated = manifest.replace(
            "\"terminal_status\": \"denied_guard_request\"",
            "\"terminal_status\": \"allowed_executed\"",
        );
        fs::write(&manifest_path, mutated)?;
        refresh_bundle_signature(work.path())?;

        let error = verify_proof_room_bundle(&manifest_path)
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.receipt-coverage.status-mismatch"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_excluded_receipt_coverage_without_reason_at_schema() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let manifest_path = work.path().join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        let coverage = manifest
            .get_mut("receipt_coverage")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or("manifest receipt coverage missing")?
            .iter_mut()
            .find(|entry| {
                entry.get("category").and_then(serde_json::Value::as_str)
                    == Some("runtime_terminal_failure")
            })
            .ok_or("runtime failure coverage missing")?;
        coverage
            .as_object_mut()
            .ok_or("runtime failure coverage is not an object")?
            .remove("exclusion_reason");
        fs::write(&manifest_path, json_bytes(&manifest)?)?;
        refresh_bundle_signature(work.path())?;

        let error = verify_proof_room_bundle(&manifest_path)
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.schema-violation: manifest"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_first_run_receipt_signature_mismatch() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let receipt_path = work.path().join("artifacts/receipts/allow-receipt.json");
        let mut receipt: serde_json::Value = serde_json::from_slice(&fs::read(&receipt_path)?)?;
        receipt["signature"] = serde_json::Value::String("0".repeat(128));
        fs::write(&receipt_path, json_bytes(&receipt)?)?;
        let receipt_sha256 = sha256_file(&receipt_path)?;

        let evidence_graph_path = work.path().join("roots/evidence-graph.json");
        let mut evidence_graph: serde_json::Value =
            serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
        for node in evidence_graph["nodes"]
            .as_array_mut()
            .ok_or("evidence graph nodes missing")?
        {
            if node.get("path").and_then(serde_json::Value::as_str)
                == Some("artifacts/receipts/allow-receipt.json")
            {
                node["sha256"] = serde_json::Value::String(receipt_sha256.clone());
            }
        }
        fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
        refresh_source_roots_and_manifest(
            work.path(),
            Some(("artifacts/receipts/allow-receipt.json", receipt_sha256)),
        )?;

        let manifest_path = work.path().join("manifest.json");
        let error = verify_proof_room_bundle(&manifest_path)
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.receipt-coverage.signature-invalid: runtime_terminal_allow"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_first_run_receipt_body_forgery_with_rehashed_artifact() -> Result<(), Box<dyn Error>>
    {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let receipt_path = work.path().join("artifacts/receipts/allow-receipt.json");
        let mut receipt: serde_json::Value = serde_json::from_slice(&fs::read(&receipt_path)?)?;
        receipt["execution_lease_ref"] =
            serde_json::Value::String("first-run-forged-lease".to_string());
        fs::write(&receipt_path, json_bytes(&receipt)?)?;
        let receipt_sha256 = sha256_file(&receipt_path)?;

        let evidence_graph_path = work.path().join("roots/evidence-graph.json");
        let mut evidence_graph: serde_json::Value =
            serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
        for node in evidence_graph["nodes"]
            .as_array_mut()
            .ok_or("evidence graph nodes missing")?
        {
            if node.get("path").and_then(serde_json::Value::as_str)
                == Some("artifacts/receipts/allow-receipt.json")
            {
                node["sha256"] = serde_json::Value::String(receipt_sha256.clone());
            }
        }
        fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
        refresh_source_roots_and_manifest(
            work.path(),
            Some(("artifacts/receipts/allow-receipt.json", receipt_sha256)),
        )?;

        let manifest_path = work.path().join("manifest.json");
        let error = verify_proof_room_bundle(&manifest_path)
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.receipt-coverage.signature-invalid: runtime_terminal_allow"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_first_run_receipt_projection_with_unexpected_field() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let receipt_path = work.path().join("artifacts/receipts/allow-receipt.json");
        let mut receipt: serde_json::Value = serde_json::from_slice(&fs::read(&receipt_path)?)?;
        receipt["ambient_authority"] = serde_json::Value::Bool(true);
        sign_first_run_receipt_projection(&mut receipt)?;
        fs::write(&receipt_path, json_bytes(&receipt)?)?;
        let receipt_sha256 = sha256_file(&receipt_path)?;
        update_evidence_graph_node_hash(
            work.path(),
            "artifacts/receipts/allow-receipt.json",
            &receipt_sha256,
        )?;
        refresh_source_roots_and_manifest(
            work.path(),
            Some(("artifacts/receipts/allow-receipt.json", receipt_sha256)),
        )?;

        let manifest_path = work.path().join("manifest.json");
        let error = verify_proof_room_bundle(&manifest_path)
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.schema-violation: first_run_receipt"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_first_run_guard_denial_receipt_mismatch() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let guard_report_path = work.path().join("artifacts/authority/guard-report.json");
        let mut guard_report: serde_json::Value =
            serde_json::from_slice(&fs::read(&guard_report_path)?)?;
        guard_report["denial_receipt_ref"] =
            serde_json::Value::String("first-run-single-call-allow".to_string());
        fs::write(&guard_report_path, json_bytes(&guard_report)?)?;
        let guard_report_sha256 = sha256_file(&guard_report_path)?;

        let evidence_graph_path = work.path().join("roots/evidence-graph.json");
        let mut evidence_graph: serde_json::Value =
            serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
        for node in evidence_graph["nodes"]
            .as_array_mut()
            .ok_or("evidence graph nodes missing")?
        {
            if node.get("path").and_then(serde_json::Value::as_str)
                == Some("artifacts/authority/guard-report.json")
            {
                node["sha256"] = serde_json::Value::String(guard_report_sha256.clone());
            }
        }
        fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
        refresh_source_roots_and_manifest(
            work.path(),
            Some(("artifacts/authority/guard-report.json", guard_report_sha256)),
        )?;

        let manifest_path = work.path().join("manifest.json");
        let error = verify_proof_room_bundle(&manifest_path)
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.first-run.guard-denial-receipt-mismatch"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_manifest_schema_drift() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;
        let manifest_path = work.path().join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        manifest["unshipped_public_field"] = serde_json::Value::String("accepted".to_string());
        fs::write(&manifest_path, json_bytes(&manifest)?)?;

        let error = verify_proof_room_bundle(&manifest_path)
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.schema-violation: manifest"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_manifest_without_signature_at_schema() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let manifest_path = work.path().join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        manifest
            .as_object_mut()
            .ok_or("manifest is not an object")?
            .remove("signature");
        fs::write(&manifest_path, json_bytes(&manifest)?)?;

        let error = verify_proof_room_bundle(&manifest_path)
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.schema-violation: manifest"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_manifest_with_unsupported_signature_kind_at_schema() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let manifest_path = work.path().join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        manifest["signature"]["kind"] = serde_json::Value::String("unsigned".to_string());
        fs::write(&manifest_path, json_bytes(&manifest)?)?;

        let error = verify_proof_room_bundle(&manifest_path)
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.schema-violation: manifest"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_excluded_artifact_with_unsafe_path_at_schema() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let manifest_path = work.path().join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        manifest["excluded_artifacts"] = serde_json::json!([
            {
                "path": "../outside.json",
                "reason": "outside bundle"
            }
        ]);
        fs::write(&manifest_path, json_bytes(&manifest)?)?;
        refresh_bundle_signature(work.path())?;

        let error = verify_proof_room_bundle(&manifest_path)
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.schema-violation: manifest"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_manifest_artifact_ref_with_dot_segment_at_schema() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let manifest_path = work.path().join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        manifest["verifier_report_ref"]["path"] =
            serde_json::Value::String("verifier/./report.json".to_string());
        fs::write(&manifest_path, json_bytes(&manifest)?)?;
        refresh_bundle_signature(work.path())?;

        let error = verify_proof_room_bundle(&manifest_path)
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.schema-violation: manifest"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_manifest_artifact_ref_with_encoded_parent_segment_at_schema(
    ) -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let manifest_path = work.path().join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        manifest["verifier_report_ref"]["path"] =
            serde_json::Value::String("verifier/%2e%2e/report.json".to_string());
        fs::write(&manifest_path, json_bytes(&manifest)?)?;
        refresh_bundle_signature(work.path())?;

        let error = verify_proof_room_bundle(&manifest_path)
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.schema-violation: manifest"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_manifest_artifact_ref_with_encoded_separator_before_filesystem(
    ) -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let manifest_path = work.path().join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        manifest["verifier_report_ref"]["path"] =
            serde_json::Value::String("verifier%2freport.json".to_string());
        fs::write(&manifest_path, json_bytes(&manifest)?)?;
        refresh_bundle_signature(work.path())?;

        let error = verify_proof_room_bundle(&manifest_path)
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.schema-violation: manifest"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_manifested_artifact_schema_drift() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let artifact_relative_path = "artifacts/release/docker-quickstart-evidence.json";
        let artifact_path = work.path().join(artifact_relative_path);
        let mut artifact: serde_json::Value = serde_json::from_slice(&fs::read(&artifact_path)?)?;
        artifact["endpoints"] = serde_json::Value::Array(Vec::new());
        let artifact_bytes = json_bytes(&artifact)?;
        fs::write(&artifact_path, &artifact_bytes)?;
        let artifact_sha256 = super::sha256_hex(&artifact_bytes);

        let manifest_path = work.path().join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        for entry in manifest["artifacts"]
            .as_array_mut()
            .ok_or("manifest artifacts missing")?
        {
            if entry.get("path").and_then(serde_json::Value::as_str) == Some(artifact_relative_path)
            {
                entry["sha256"] = serde_json::Value::String(artifact_sha256.clone());
            }
        }
        fs::write(&manifest_path, json_bytes(&manifest)?)?;
        refresh_bundle_signature(work.path())?;

        let error = verify_proof_room_bundle(&manifest_path)
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.schema-violation: artifact"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_release_truth_schema_drift() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let artifact_relative_path = "artifacts/release/release-truth.json";
        let artifact_path = work.path().join(artifact_relative_path);
        let mut artifact: serde_json::Value = serde_json::from_slice(&fs::read(&artifact_path)?)?;
        artifact["truth"]
            .as_object_mut()
            .ok_or("release truth object missing")?
            .remove("hosted_demo");
        fs::write(&artifact_path, json_bytes(&artifact)?)?;
        let artifact_sha256 = sha256_file(&artifact_path)?;

        let manifest_path = work.path().join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        for entry in manifest["artifacts"]
            .as_array_mut()
            .ok_or("manifest artifacts missing")?
        {
            if entry.get("path").and_then(serde_json::Value::as_str) == Some(artifact_relative_path)
            {
                entry["sha256"] = serde_json::Value::String(artifact_sha256.clone());
            }
        }
        fs::write(&manifest_path, json_bytes(&manifest)?)?;
        refresh_bundle_signature(work.path())?;

        let error = verify_proof_room_bundle(&manifest_path)
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.schema-violation: artifact"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_detached_signature_payload_hash_mismatch() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let signature_path = work.path().join("bundle-signature.dsse.json");
        let mut signature: serde_json::Value = serde_json::from_slice(&fs::read(&signature_path)?)?;
        signature["payloadRef"]["sha256"] = serde_json::Value::String("0".repeat(64));
        fs::write(&signature_path, json_bytes(&signature)?)?;

        let error = verify_proof_room_bundle(&work.path().join("manifest.json"))
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.signature.payload-hash-mismatch"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_detached_signature_forgery() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let signature_path = work.path().join("bundle-signature.dsse.json");
        let mut signature: serde_json::Value = serde_json::from_slice(&fs::read(&signature_path)?)?;
        signature["signatures"][0]["sig"] = serde_json::Value::String("0".repeat(128));
        fs::write(&signature_path, json_bytes(&signature)?)?;

        let error = verify_proof_room_bundle(&work.path().join("manifest.json"))
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.signature.verification-failed"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_detached_signature_from_untrusted_key() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let untrusted_keypair = Keypair::from_seed(&[8; 32]);
        sign_bundle_signature_with_key(work.path(), &untrusted_keypair)?;

        let error = verify_proof_room_bundle(&work.path().join("manifest.json"))
            .err()
            .ok_or("untrusted proof room bundle signature unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.signature.signer-untrusted"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_detached_signature_without_trust_roots() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let manifest_path = work.path().join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        manifest["artifacts"]
            .as_array_mut()
            .ok_or("manifest artifacts missing")?
            .retain(|artifact| {
                artifact.get("path").and_then(serde_json::Value::as_str)
                    != Some("artifacts/authority/trust-roots.json")
            });
        fs::write(&manifest_path, json_bytes(&manifest)?)?;
        let untrusted_keypair = Keypair::from_seed(&[8; 32]);
        sign_bundle_signature_with_key(work.path(), &untrusted_keypair)?;

        let manifest_bytes = fs::read(&manifest_path)?;
        let manifest: super::ProofRoomBundleManifest = serde_json::from_slice(&manifest_bytes)?;
        let error = super::verify_bundle_signature(work.path(), &manifest, &manifest_bytes)
            .err()
            .ok_or("proof room bundle signature without trust roots unexpectedly verified")?;

        assert!(
            error.contains("proof-room.signature.trust-roots-missing"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_ui_report_schema_drift() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let ui_report_path = work.path().join("ui/proof-room-static/load-report.json");
        let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
        ui_report["unshipped_public_field"] = serde_json::Value::String("accepted".to_string());
        let ui_report_bytes = json_bytes(&ui_report)?;
        fs::write(&ui_report_path, &ui_report_bytes)?;
        let ui_report_sha256 = super::sha256_hex(&ui_report_bytes);

        let manifest_path = work.path().join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        manifest["proof_room_verifier_report_ref"]["sha256"] =
            serde_json::Value::String(ui_report_sha256.clone());
        for artifact in manifest["artifacts"]
            .as_array_mut()
            .ok_or("manifest artifacts missing")?
        {
            if artifact.get("path").and_then(serde_json::Value::as_str)
                == Some("ui/proof-room-static/load-report.json")
            {
                artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
            }
        }
        fs::write(&manifest_path, json_bytes(&manifest)?)?;
        refresh_bundle_signature(work.path())?;

        let error = verify_proof_room_bundle(&manifest_path)
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.schema-violation: ui-report"),
            "{error}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_referenced_bundle_assets() -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router(bundle, ui.path().to_path_buf());

        let cases = [
            (
                "/verifier/report.json",
                "chio.transaction.verifier-report.v1",
            ),
            (
                "/roots/transaction-passport.json",
                "chio.transaction-passport.v1",
            ),
            ("/artifacts/receipts/allow-receipt.json", "allowed_executed"),
            (
                "/negatives/missing-denial-receipt.json",
                "expected_failure_code",
            ),
        ];

        for (path, expected) in cases {
            let response = router
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty())?)
                .await?;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let body = to_bytes(response.into_body(), 1024 * 1024).await?;
            let body = String::from_utf8(body.to_vec())?;
            assert!(body.contains(expected), "{path} did not contain {expected}");
        }

        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_does_not_host_unmanifested_bundle_files(
    ) -> Result<(), Box<dyn Error>> {
        let source = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;
        let internal_dir = work.path().join("artifacts/internal");
        fs::create_dir_all(&internal_dir)?;
        fs::write(
            internal_dir.join("debug-notes.json"),
            br#"{"schema":"debug-notes.v1","note":"not manifest evidence"}"#,
        )?;
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router(work.path().to_path_buf(), ui.path().to_path_buf());

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/artifacts/internal/debug-notes.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let body = String::from_utf8(body.to_vec())?;
        assert!(!body.contains("debug-notes.v1"));
        Ok(())
    }

    #[test]
    fn proof_room_router_reports_invalid_manifest_serving_paths() -> Result<(), Box<dyn Error>> {
        let bundle = tempfile::tempdir()?;
        fs::write(
            bundle.path().join("manifest.json"),
            br#"{"schema":"chio.proof-room.bundle.v1","artifacts":[{"path":"../secret.json"}]}"#,
        )?;
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;

        let error = build_proof_room_router(bundle.path().to_path_buf(), ui.path().to_path_buf())
            .err()
            .ok_or("invalid manifest serving path unexpectedly built a router")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.serve member path ../secret.json is unsafe"),
            "{error}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn proof_room_router_root_opens_proof_room_view() -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router(bundle, ui.path().to_path_buf());

        let response = router
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = response
            .headers()
            .get("location")
            .ok_or("redirect location missing")?;
        assert_eq!(location, "/proof-room?view=proof-room");

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room?view=proof-room")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let body = String::from_utf8(body.to_vec())?;
        assert!(body.contains("Proof Room"));
        Ok(())
    }

    #[tokio::test]
    async fn proof_room_router_serves_dashboard_assets_referenced_by_index(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = tempfile::tempdir()?;
        let ui = tempfile::tempdir()?;
        let assets = ui.path().join("assets");
        fs::create_dir(&assets)?;
        fs::write(
            ui.path().join("index.html"),
            r#"<!doctype html><script type="module" src="/assets/proof-room.js"></script>"#,
        )?;
        fs::write(
            assets.join("proof-room.js"),
            "window.__proofRoomAssetLoaded = true;",
        )?;
        let router = proof_room_router(bundle.path().to_path_buf(), ui.path().to_path_buf());

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/proof-room?view=proof-room")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let body = String::from_utf8(body.to_vec())?;
        assert!(body.contains("/assets/proof-room.js"));

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/assets/proof-room.js")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let body = String::from_utf8(body.to_vec())?;
        assert!(body.contains("window.__proofRoomAssetLoaded = true;"));
        Ok(())
    }

    #[tokio::test]
    async fn proof_room_router_uses_ui_fallback_for_unmanifested_root_paths(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = tempfile::tempdir()?;
        fs::write(
            bundle.path().join("kernel-receipt.json"),
            r#"{"schema":"chio.receipt.v1"}"#,
        )?;
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room shell</main>",
        )?;
        let router = proof_room_router(bundle.path().to_path_buf(), ui.path().to_path_buf());

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/kernel-receipt.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let body = String::from_utf8(body.to_vec())?;
        assert!(body.contains("Proof Room shell"));
        assert!(!body.contains("\"schema\":\"chio.receipt.v1\""));
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_fixture_catalog() -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixture-catalog.json")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let catalog: serde_json::Value = serde_json::from_slice(&body)?;

        assert_eq!(catalog["schema"], "chio.proof-room.fixture-catalog.v1");
        super::validate_proof_room_schema(
            &catalog,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../spec/schemas/chio-proof-room/v1/fixture-catalog.schema.json"
            )),
            "proof-room fixture catalog",
        )
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        assert_eq!(
            catalog["fixtures"][0]["fixture_id"],
            "single-call-authority"
        );
        assert_eq!(
            catalog["fixtures"][0]["bundle_id"],
            "proof-room-single-call-authority"
        );
        assert_eq!(
            catalog["fixtures"][0]["negative_cases"][0]["observed_failure_code"],
            "verifier policy digest mismatch"
        );
        let negative_case_ids = catalog["fixtures"][0]["negative_cases"]
            .as_array()
            .ok_or("negative cases missing")?
            .iter()
            .filter_map(|negative_case| negative_case.get("id").and_then(serde_json::Value::as_str))
            .collect::<Vec<_>>();
        assert!(negative_case_ids.contains(&"missing-denial-receipt"));
        assert!(negative_case_ids.contains(&"missing-receipt-graph-node"));
        let available_fixtures = catalog["available_fixtures"]
            .as_array()
            .ok_or("available fixtures missing")?;
        let available_fixture_ids = available_fixtures
            .iter()
            .filter_map(|fixture| fixture.get("id").and_then(serde_json::Value::as_str))
            .collect::<Vec<_>>();
        for public_stage_id in [
            "single-call-authority",
            "commerce-transaction-passport",
            "recursive-runtime-swarm",
            "disclosure-and-agent-web-envelope",
        ] {
            assert!(
                available_fixture_ids
                    .iter()
                    .any(|id| id == &public_stage_id),
                "served fixture catalog missing public stage fixture: {public_stage_id}"
            );
        }
        let commerce_stage = available_fixtures
            .iter()
            .find(|fixture| fixture["id"] == "commerce-transaction-passport")
            .ok_or("commerce public stage fixture missing")?;
        let commerce_stage_negative_cases = commerce_stage["negative_cases"]
            .as_array()
            .ok_or("commerce public stage negative cases missing")?;
        assert!(
            commerce_stage_negative_cases.iter().any(|negative_case| {
                negative_case["id"] == "commerce-payment-wrong-merchant"
                    && negative_case["path"]
                        == "proof-room-bundle/negatives/catalog/commerce-payment-wrong-merchant/transaction-passport.json"
            }),
            "commerce public stage should expose manifest negative cases"
        );
        for fixture in available_fixtures {
            assert!(
                fixture.get("verifier_report").is_some(),
                "available fixture should expose an inspectable verifier report: {}",
                fixture["id"]
            );
        }
        let minimal_fixture = available_fixtures
            .iter()
            .find(|fixture| fixture["id"] == "minimal-passport-valid")
            .ok_or("minimal passport fixture missing")?;
        assert_eq!(minimal_fixture["verifier_report"]["status"], 200);
        assert_eq!(minimal_fixture["verifier_report"]["verdict"], "verified");
        let commerce_fixture = available_fixtures
            .iter()
            .find(|fixture| fixture["id"] == "commerce-offline-psp")
            .ok_or("commerce fixture missing")?;
        let commerce_negative_cases = commerce_fixture["negative_cases"]
            .as_array()
            .ok_or("commerce negative cases missing")?;
        let commerce_wrong_merchant = commerce_negative_cases
            .iter()
            .find(|negative_case| negative_case["id"] == "commerce-payment-wrong-merchant")
            .ok_or("commerce wrong merchant negative case missing")?;
        assert_eq!(commerce_wrong_merchant["path"], "transaction-passport.json");
        let commerce_wrong_merchant_asset = router
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/proof-room-fixtures/{}/{}",
                        commerce_wrong_merchant["id"]
                            .as_str()
                            .ok_or("commerce wrong merchant id missing")?,
                        commerce_wrong_merchant["path"]
                            .as_str()
                            .ok_or("commerce wrong merchant path missing")?
                    ))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(commerce_wrong_merchant_asset.status(), StatusCode::OK);
        assert!(commerce_wrong_merchant["observed_failure_code"]
            .as_str()
            .ok_or("commerce wrong merchant observed failure missing")?
            .contains("payment merchant mismatch"));
        let agent_web_negative = available_fixtures
            .iter()
            .find(|fixture| fixture["id"] == "agent-web-external-digest-mismatch")
            .ok_or("agent web negative fixture missing")?;
        assert_eq!(
            agent_web_negative["verifier_report"]["status"],
            StatusCode::UNPROCESSABLE_ENTITY.as_u16()
        );
        assert_eq!(agent_web_negative["verifier_report"]["verdict"], "failed");
        assert_eq!(
            agent_web_negative["verifier_report"]["failure_code"],
            "proof-room.fixture.verify-failed"
        );
        assert!(agent_web_negative["verifier_report"]["error"]
            .as_str()
            .ok_or("agent web negative error missing")?
            .contains("external subject digest mismatch"));
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_without_fixture_root_lists_only_embedded_fixture_assets(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router(bundle, ui.path().to_path_buf());

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixture-catalog.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let catalog: serde_json::Value = serde_json::from_slice(&body)?;
        let available_fixture_ids = catalog["available_fixtures"]
            .as_array()
            .ok_or("available_fixtures missing")?
            .iter()
            .filter_map(|fixture| fixture.get("id").and_then(serde_json::Value::as_str))
            .collect::<Vec<_>>();

        assert!(available_fixture_ids.contains(&"single-call-authority"));
        assert!(!available_fixture_ids.contains(&"minimal-passport-valid"));
        Ok(())
    }

    #[test]
    fn fixture_catalog_rejects_load_report_path_escape() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        let bundle = work.path().join("bundle");
        copy_dir_all(&source, &bundle)?;
        fs::write(
            work.path().join("outside-load-report.json"),
            br#"{"verdict":"forged"}"#,
        )?;

        let manifest_path = bundle.join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        manifest["proof_room_verifier_report_ref"]["path"] =
            serde_json::Value::String("../outside-load-report.json".to_string());
        fs::write(&manifest_path, json_bytes(&manifest)?)?;

        let error = super::build_proof_room_fixture_catalog(&bundle, None)
            .err()
            .ok_or("catalog unexpectedly read outside load report")?;

        assert!(error.contains("proof-room.artifact.unsafe-path"), "{error}");
        Ok(())
    }

    #[test]
    fn available_fixture_catalog_marks_malformed_verifier_report_failed() {
        let report: super::ProofRoomAvailableFixtureReport =
            super::proof_room_available_fixture_report_from_contents(
                "/proof-room-fixtures/minimal-passport-valid/verifier-report.json".to_string(),
                b"{not valid json",
            );

        assert_eq!(report.status, StatusCode::UNPROCESSABLE_ENTITY.as_u16());
        assert_eq!(report.verdict, "failed");
        assert_eq!(
            report.failure_code.as_deref(),
            Some("proof-room.fixture.report-invalid")
        );
        assert!(report
            .error
            .as_deref()
            .is_some_and(|error: &str| error.contains("proof-room.fixture.report-invalid")));
    }

    #[test]
    fn available_fixture_catalog_marks_missing_verdict_report_failed() {
        let report: super::ProofRoomAvailableFixtureReport =
            super::proof_room_available_fixture_report_from_contents(
                "/proof-room-fixtures/minimal-passport-valid/verifier-report.json".to_string(),
                br#"{"schema":"chio.transaction.verifier-report.v1"}"#,
            );

        assert_eq!(report.status, StatusCode::UNPROCESSABLE_ENTITY.as_u16());
        assert_eq!(report.verdict, "failed");
        assert_eq!(
            report.failure_code.as_deref(),
            Some("proof-room.fixture.report-verdict-missing")
        );
        assert_eq!(
            report.error.as_deref(),
            Some("proof-room.fixture.report-verdict-missing")
        );
    }

    #[test]
    fn fixture_catalog_schema_rejects_uninspectable_available_fixture() {
        let catalog = serde_json::json!({
            "schema": "chio.proof-room.fixture-catalog.v1",
            "fixtures": [],
            "available_fixtures": [
                {
                    "id": "commerce-transaction-passport",
                    "kind": "generated-proof-room",
                    "path": "generated/commerce-transaction-passport",
                    "description": "Generated Proof Room stage"
                }
            ]
        });

        let error = super::validate_proof_room_schema(
            &catalog,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../spec/schemas/chio-proof-room/v1/fixture-catalog.schema.json"
            )),
            "proof-room fixture catalog",
        )
        .err()
        .expect("available fixture without report should be rejected");

        assert!(error.contains("verifier_report"), "{error}");
    }

    #[tokio::test]
    async fn quickstart_router_serves_available_fixture_asset() -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/minimal-passport-valid/transaction-passport.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let passport: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(passport["schema"], "chio.transaction-passport.v1");
        assert_eq!(passport["id"], "passport-minimal-valid");
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_public_stage_bundle_readme() -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

        let response = router
            .oneshot(
                Request::builder()
                    .uri(
                        "/proof-room-fixtures/commerce-transaction-passport/proof-room-bundle/README.md",
                    )
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let body = String::from_utf8(body.to_vec())?;
        assert!(body.contains("commerce-transaction-passport"));
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_public_stage_negative_sibling_assets(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

        let response = router
            .oneshot(
                Request::builder()
                    .uri(
                        "/proof-room-fixtures/commerce-transaction-passport/proof-room-bundle/negatives/catalog/commerce-payment-wrong-merchant/evidence-graph.json",
                    )
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let graph: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(graph["schema"], "chio.transaction.evidence-graph.v1");
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_available_fixture_asset_from_configured_fixture_root(
    ) -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source = root.join("fixtures/proof-room/minimal-passport/valid");
        let installed = tempfile::tempdir()?;
        let installed_fixture = installed.path().join("minimal-passport/valid");
        copy_dir_all(&source, &installed_fixture)?;
        let passport_path = installed_fixture.join("transaction-passport.json");
        let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
        passport["id"] = serde_json::Value::String("passport-installed-root".to_string());
        fs::write(&passport_path, json_bytes(&passport)?)?;
        let bundle =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_fixture_root(
            bundle,
            ui.path().to_path_buf(),
            installed.path().to_path_buf(),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/minimal-passport-valid/transaction-passport.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let passport: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(passport["id"], "passport-installed-root");
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_uses_configured_fixture_root_catalog() -> Result<(), Box<dyn Error>>
    {
        let root = repo_root()?;
        let source = root.join("fixtures/proof-room/minimal-passport/valid");
        let installed = tempfile::tempdir()?;
        let installed_fixture = installed.path().join("minimal-passport/valid");
        copy_dir_all(&source, &installed_fixture)?;
        fs::write(
            installed.path().join("catalog.json"),
            br#"{
  "schema": "chio.proof-room.fixture-root-catalog.v1",
  "fixtures": [
    {
      "id": "installed-only-minimal",
      "kind": "transaction-passport",
      "path": "fixtures/proof-room/minimal-passport/valid",
      "description": "Installed fixture root catalog entry"
    }
  ]
}"#,
        )?;
        let bundle =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_fixture_root(
            bundle,
            ui.path().to_path_buf(),
            installed.path().to_path_buf(),
        );

        let catalog_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixture-catalog.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(catalog_response.status(), StatusCode::OK);
        let catalog_body = to_bytes(catalog_response.into_body(), 1024 * 1024).await?;
        let catalog: serde_json::Value = serde_json::from_slice(&catalog_body)?;
        let available_fixture_ids = catalog["available_fixtures"]
            .as_array()
            .ok_or("available_fixtures missing")?
            .iter()
            .filter_map(|fixture| fixture.get("id").and_then(serde_json::Value::as_str))
            .collect::<Vec<_>>();
        assert_eq!(available_fixture_ids, vec!["installed-only-minimal"]);

        let fixture_response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/installed-only-minimal/transaction-passport.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(fixture_response.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_rejects_unadvertised_installed_fixture_asset(
    ) -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source = root.join("fixtures/proof-room/minimal-passport/valid");
        let installed = tempfile::tempdir()?;
        let installed_fixture = installed.path().join("minimal-passport/valid");
        copy_dir_all(&source, &installed_fixture)?;
        fs::write(
            installed_fixture.join("debug-notes.json"),
            br#"{"debug":"not part of the proof fixture"}"#,
        )?;
        let bundle =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_fixture_root(
            bundle,
            ui.path().to_path_buf(),
            installed.path().to_path_buf(),
        );

        let passport_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/minimal-passport-valid/transaction-passport.json")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(passport_response.status(), StatusCode::OK);

        let verifier_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/minimal-passport-valid/verifier-report.json")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(verifier_response.status(), StatusCode::OK);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/minimal-passport-valid/debug-notes.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let error = String::from_utf8(body.to_vec())?;
        assert!(error.contains("proof-room.fixture.asset-not-found"));
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_requires_fixture_root_for_non_shipped_catalog_assets(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router(bundle, ui.path().to_path_buf());

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/minimal-passport-valid/transaction-passport.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let error = String::from_utf8(body.to_vec())?;
        assert!(error.contains("proof-room.fixture.asset-not-found"));
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_generates_verifier_report_from_configured_fixture_root(
    ) -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source = root.join("fixtures/proof-room/workflow-preflight/valid-child-scope");
        let installed = tempfile::tempdir()?;
        let installed_fixture = installed
            .path()
            .join("workflow-preflight/valid-child-scope");
        copy_dir_all(&source, &installed_fixture)?;
        let plan_path = installed_fixture.join("preflight-plan.json");
        let mut plan: serde_json::Value = serde_json::from_slice(&fs::read(&plan_path)?)?;
        plan["id"] = serde_json::Value::String("workflow-preflight-installed-root".to_string());
        fs::write(&plan_path, json_bytes(&plan)?)?;
        let bundle =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_fixture_root(
            bundle,
            ui.path().to_path_buf(),
            installed.path().to_path_buf(),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/workflow-preflight-valid/verifier-report.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let report: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(report["schema"], "chio.workflow.preflight-report.v1");
        assert_eq!(report["verdict"], "accepted");
        assert_eq!(report["plan_id"], "workflow-preflight-installed-root");
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_catalog_summarizes_configured_fixture_root_reports(
    ) -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source = root.join("fixtures/proof-room");
        let broader_plan = root
            .join("fixtures/proof-room/workflow-preflight/broader-child-scope/preflight-plan.json");
        let installed = tempfile::tempdir()?;
        let installed_fixture = installed
            .path()
            .join("workflow-preflight/valid-child-scope");
        copy_dir_all(&source, installed.path())?;
        fs::copy(broader_plan, installed_fixture.join("preflight-plan.json"))?;
        let bundle =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_fixture_root(
            bundle,
            ui.path().to_path_buf(),
            installed.path().to_path_buf(),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixture-catalog.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let catalog: serde_json::Value = serde_json::from_slice(&body)?;
        let fixture = catalog["available_fixtures"]
            .as_array()
            .ok_or("available_fixtures missing")?
            .iter()
            .find(|fixture| fixture["id"] == "workflow-preflight-valid")
            .ok_or("workflow-preflight-valid fixture missing")?;
        assert_eq!(fixture["verifier_report"]["verdict"], "rejected");
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_catalog_fails_public_stage_with_corrupt_nested_bundle(
    ) -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source = root.join("fixtures/proof-room/public-stages/commerce-transaction-passport");
        let installed = tempfile::tempdir()?;
        let installed_fixture = installed
            .path()
            .join("public-stages/commerce-transaction-passport");
        copy_dir_all(&source, &installed_fixture)?;
        fs::write(
            installed.path().join("catalog.json"),
            br#"{
  "schema": "chio.proof-room.fixture-root-catalog.v1",
  "fixtures": [
    {
      "id": "commerce-transaction-passport",
      "kind": "proof-room",
      "path": "fixtures/proof-room/public-stages/commerce-transaction-passport",
      "description": "Installed public stage"
    }
  ]
}"#,
        )?;
        let passport_path =
            installed_fixture.join("proof-room-bundle/roots/transaction-passport.json");
        let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
        passport["id"] = serde_json::Value::String("passport-corrupt-nested-bundle".to_string());
        fs::write(&passport_path, json_bytes(&passport)?)?;
        let bundle =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_fixture_root(
            bundle,
            ui.path().to_path_buf(),
            installed.path().to_path_buf(),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixture-catalog.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let catalog: serde_json::Value = serde_json::from_slice(&body)?;
        let fixture = catalog["available_fixtures"]
            .as_array()
            .ok_or("available_fixtures missing")?
            .iter()
            .find(|fixture| fixture["id"] == "commerce-transaction-passport")
            .ok_or("commerce-transaction-passport fixture missing")?;
        assert_eq!(fixture["verifier_report"]["verdict"], "failed");
        assert_eq!(
            fixture["verifier_report"]["failure_code"],
            "proof-room.fixture.verify-failed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_available_fixture_verifier_report(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/minimal-passport-valid/verifier-report.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let report: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
        assert_eq!(report["verdict"], "verified");
        assert_eq!(report["passport_id"], "passport-minimal-valid");
        assert_eq!(report["evidence_graph_path"], "evidence-graph.json");
        assert_eq!(report["verifier_policy_path"], "verifier-policy.json");
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_workflow_preflight_fixture_report(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/workflow-preflight-valid/verifier-report.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let report: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(report["schema"], "chio.workflow.preflight-report.v1");
        assert_eq!(report["verdict"], "accepted");
        assert_eq!(report["evidence_class"], "planning");
        assert!(report["verified_claims"]
            .as_array()
            .ok_or("verified_claims missing")?
            .iter()
            .any(|claim| claim == "claim.workflow.preflight_child_scope_bounded"));
        assert!(report["live_authority_claims"]
            .as_array()
            .ok_or("live_authority_claims missing")?
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_first_run_fixture_verifier_report(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router(bundle, ui.path().to_path_buf());

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/single-call-authority/verifier-report.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let report: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
        assert_eq!(report["verdict"], "verified");
        assert_eq!(report["passport_id"], "passport-minimal-valid");
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_domain_fixture_verifier_report() -> Result<(), Box<dyn Error>>
    {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/commerce-offline-psp/verifier-report.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let report: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(report["schema"], "chio.commerce.order-passport.v1");
        assert_eq!(report["verdict"], "verified");
        assert_eq!(report["order_id"], "order-commerce-001");
        assert_eq!(report["current_state"], "completed");
        assert!(report["verified_claims"]
            .as_array()
            .ok_or("verified_claims missing")?
            .iter()
            .any(|claim| claim == "claim.commerce.order_replay_consistent"));
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_swarm_fixture_verifier_report() -> Result<(), Box<dyn Error>>
    {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/recursive-runtime-swarm/verifier-report.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let report: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
        assert_eq!(report["verdict"], "verified");
        assert_eq!(report["passport_id"], "passport-swarm-valid");
        assert!(report["verified_claims"]
            .as_array()
            .ok_or("verified_claims missing")?
            .iter()
            .any(|claim| claim == "claim.swarm.task_graph_bound"));
        assert_eq!(
            report["runtime_proof_parity_report"]["schema"],
            "chio.runtime.proof-parity-report.v1"
        );
        assert_eq!(
            report["runtime_proof_parity_report"]["runId"],
            "runtime-loopback-1"
        );
        let family_report = report["family_reports"]
            .as_array()
            .ok_or("family_reports missing")?
            .iter()
            .find(|family_report| {
                family_report["schema"] == "chio.swarm.authority-verifier-report.v1"
            })
            .ok_or("swarm family report missing")?;
        assert_eq!(family_report["graphId"], "swarm-graph-proof-valid");
        assert_eq!(family_report["taskCount"], 3);
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_public_settlement_fixture_verifier_report(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

        let response = router
            .oneshot(
                Request::builder()
                    .uri(
                        "/proof-room-fixtures/public-settlement-offline-finality/verifier-report.json",
                    )
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let report: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(
            report["schema"],
            "chio.public-settlement-verifier-report.v1"
        );
        assert_eq!(report["verdict"], "verified");
        assert_eq!(report["bundle_id"], "web3-settlement-proof-public-valid");
        assert_eq!(report["commerce_order_id"], "order-public-settlement-valid");
        assert_eq!(report["finality_decision"]["status"], "final");
        assert!(report["verified_claims"]
            .as_array()
            .ok_or("verified_claims missing")?
            .iter()
            .any(|claim| claim == "claim.public_settlement.finality_verified"));
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_runtime_fixture_verifier_report() -> Result<(), Box<dyn Error>>
    {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/runtime-side-effecting-call/verifier-report.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let report: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(
            report["schema"],
            "chio.transaction.runtime-security-report.v1"
        );
        assert_eq!(report["verdict"], "verified");
        assert_eq!(report["passport_id"], "runtime-passport-valid");
        assert!(report["verified_claims"]
            .as_array()
            .ok_or("verified_claims missing")?
            .iter()
            .any(|claim| claim == "claim.runtime.execution_lease_valid"));
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_disclosure_lineage_fixture_verifier_report(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/disclosure-lineage-ledger/verifier-report.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let report: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(
            report["schema"],
            "chio.disclosure.lineage-verifier-report.v1"
        );
        assert_eq!(report["verdict"], "verified");
        assert_eq!(report["capsule_id"], "disclosure-capsule-valid");
        assert_eq!(report["lineage_subgraph_ref"], "lineage-subgraph-valid");
        assert_eq!(report["leakage_ledger_ref"], "leakage-ledger-valid");
        assert!(report["verified_claims"]
            .as_array()
            .ok_or("verified_claims missing")?
            .iter()
            .any(|claim| claim == "claim.disclosure.lineage_subgraph_bound"));
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_crypto_context_fixture_verifier_report(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/crypto-context-valid-bbs/verifier-report.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let report: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(report["schema"], "chio.disclosure.crypto-context-report.v1");
        assert_eq!(report["verdict"], "verified");
        assert_eq!(report["context_id"], "crypto-context-buyer-auditor");
        assert!(report["verified_claims"]
            .as_array()
            .ok_or("verified_claims missing")?
            .iter()
            .any(|claim| claim == "claim.disclosure.crypto_context_bound"));
        Ok(())
    }

    #[test]
    fn crypto_context_verified_report_rejects_context_report_drift() -> Result<(), Box<dyn Error>> {
        let fixture = repo_root()?.join("fixtures/proof-room/crypto-context/valid-bbs-context");
        let report_bytes = fs::read(fixture.join("crypto-context-report.json"))?;
        let context_bytes = fs::read(fixture.join("verification-context.json"))?;
        let mut context: serde_json::Value = serde_json::from_slice(&context_bytes)?;
        context["audience"] =
            serde_json::Value::String("https://attacker.example/chio".to_string());
        let context_bytes = serde_json::to_vec(&context)?;

        let error = crypto_context_verified_report_bytes(
            &context_bytes,
            &report_bytes,
            "crypto-context-valid-bbs",
        )
        .err()
        .ok_or("drifted crypto context report unexpectedly verified")?;

        assert!(error.contains("disclosure_context_audience_mismatch"));
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_crypto_context_negative_fixture_report(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/crypto-context-wrong-audience/verifier-report.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let report: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(report["schema"], "chio.disclosure.crypto-context-report.v1");
        assert_eq!(report["verdict"], "rejected");
        assert_eq!(report["context_id"], "crypto-context-wrong-audience");
        assert!(report["rejected_checks"]
            .as_array()
            .ok_or("rejected_checks missing")?
            .iter()
            .any(|check| check["code"] == "disclosure_context_audience_mismatch"));
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_trust_market_fixture_verifier_report(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/trust-market-context/verifier-report.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let report: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
        assert_eq!(report["verdict"], "verified");
        assert_eq!(report["passport_id"], "passport-trust-market-valid");
        assert_eq!(
            report["trust_market_sections"]["risk_comptroller_report_ref"],
            "risk-comptroller-market-valid"
        );
        assert_eq!(
            report["trust_market_sections"]["selected_provider_subject"],
            "did:chio:provider-alpha"
        );
        assert!(report["verified_claims"]
            .as_array()
            .ok_or("verified_claims missing")?
            .iter()
            .any(|claim| claim == "claim.trust_market.provider_selection_bound"));
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_enterprise_fixture_verifier_report(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/enterprise-autonomous-commerce/verifier-report.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let report: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
        assert_eq!(report["verdict"], "verified");
        assert_eq!(report["passport_id"], "passport-enterprise-valid");
        assert_eq!(
            report["risk_comptroller_report_ref"],
            "risk-comptroller-enterprise-valid"
        );
        assert_eq!(
            report["enterprise_sections"]["data_governance_report_ref"],
            "data-governance-enterprise-valid"
        );
        assert_eq!(
            report["enterprise_sections"]["control_evidence_map_ref"],
            "control-map-enterprise-valid"
        );
        assert!(report["verified_claims"]
            .as_array()
            .ok_or("verified_claims missing")?
            .iter()
            .any(|claim| claim == "claim.enterprise.control_map_bound"));
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_enterprise_risk_only_fixture_verifier_report(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

        let response = router
            .oneshot(
                Request::builder()
                    .uri(
                        "/proof-room-fixtures/enterprise-risk-only-comptroller/verifier-report.json",
                    )
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let report: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
        assert_eq!(report["verdict"], "verified");
        assert_eq!(report["passport_id"], "passport-enterprise-valid");
        assert_eq!(
            report["risk_comptroller_report_ref"],
            "risk-comptroller-enterprise-valid"
        );
        assert!(report["verified_claims"]
            .as_array()
            .ok_or("verified_claims missing")?
            .iter()
            .any(|claim| claim == "claim.risk.comptroller_report_bound"));
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_standalone_risk_fixture_verifier_report(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/risk-standalone-comptroller/verifier-report.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let report: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
        assert_eq!(report["verdict"], "verified");
        assert_eq!(report["passport_id"], "passport-enterprise-valid");
        assert_eq!(
            report["risk_comptroller_report_ref"],
            "risk-comptroller-enterprise-valid"
        );
        assert!(report["verified_claims"]
            .as_array()
            .ok_or("verified_claims missing")?
            .iter()
            .any(|claim| claim == "claim.risk.comptroller_report_bound"));
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_serves_agent_web_fixture_verifier_report(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/proof-room-fixtures/agent-web-interop/verifier-report.json")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let report: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(
            report["schema"],
            "chio.agent-web.interop-verifier-report.v1"
        );
        assert_eq!(report["verdict"], "verified");
        assert_eq!(report["passport_id"], "passport-agent-web-valid");
        assert!(report["verified_claims"]
            .as_array()
            .ok_or("verified_claims missing")?
            .iter()
            .any(|claim| claim == "claim.agent_web.sidecar_not_native_authority"));
        assert!(report["projections"]
            .as_array()
            .ok_or("projections missing")?
            .iter()
            .any(|projection| projection["source_protocol"] == "mcp"));
        assert!(report["unsupported_claims"]
            .as_array()
            .ok_or("unsupported_claims missing")?
            .iter()
            .any(|claim| claim == "claim.external.mcp_tool_call_is_chio_authority"));
        Ok(())
    }

    #[tokio::test]
    async fn quickstart_router_explains_negative_fixture_verifier_failure(
    ) -> Result<(), Box<dyn Error>> {
        let bundle = repo_root()?
            .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let ui = tempfile::tempdir()?;
        fs::write(
            ui.path().join("index.html"),
            "<!doctype html><main>Proof Room</main>",
        )?;
        let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

        let response = router
            .oneshot(
                Request::builder()
                    .uri(
                        "/proof-room-fixtures/agent-web-external-digest-mismatch/verifier-report.json",
                    )
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(response.into_body(), 1024 * 1024).await?;
        let report: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
        assert_eq!(report["verdict"], "failed");
        assert_eq!(report["passport_id"], "passport-agent-web-valid");
        assert_eq!(report["failure_code"], "proof-room.fixture.verify-failed");
        assert!(report["error"]
            .as_str()
            .ok_or("error missing")?
            .contains("external subject digest mismatch"));
        Ok(())
    }

    #[test]
    fn rejects_negative_case_expected_failure_mismatch() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;
        let manifest_path = work.path().join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        manifest["negative_cases"][0]["expected_failure_code"] =
            serde_json::Value::String("expected failure that does not occur".to_string());
        fs::write(
            &manifest_path,
            [serde_json::to_vec_pretty(&manifest)?.as_slice(), b"\n"].concat(),
        )?;
        refresh_bundle_signature(work.path())?;

        let error = verify_proof_room_bundle(&manifest_path)
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.negative-case.failure-mismatch"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_verifier_report_that_does_not_match_passport() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let verifier_report_path = work.path().join("verifier/report.json");
        let mut verifier_report: serde_json::Value =
            serde_json::from_slice(&fs::read(&verifier_report_path)?)?;
        verifier_report["passport_id"] =
            serde_json::Value::String("passport-minimal-drifted".to_string());
        let verifier_report_bytes = json_bytes(&verifier_report)?;
        fs::write(&verifier_report_path, &verifier_report_bytes)?;
        let verifier_report_sha256 = super::sha256_hex(&verifier_report_bytes);

        let ui_report_path = work.path().join("ui/proof-room-static/load-report.json");
        let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
        ui_report["source_verifier_report_ref"]["sha256"] =
            serde_json::Value::String(verifier_report_sha256.clone());
        let ui_report_bytes = json_bytes(&ui_report)?;
        fs::write(&ui_report_path, &ui_report_bytes)?;
        let ui_report_sha256 = super::sha256_hex(&ui_report_bytes);

        let manifest_path = work.path().join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        manifest["verifier_report_ref"]["sha256"] =
            serde_json::Value::String(verifier_report_sha256.clone());
        manifest["proof_room_verifier_report_ref"]["sha256"] =
            serde_json::Value::String(ui_report_sha256.clone());
        for artifact in manifest["artifacts"]
            .as_array_mut()
            .ok_or("manifest artifacts missing")?
        {
            match artifact.get("path").and_then(serde_json::Value::as_str) {
                Some("verifier/report.json") => {
                    artifact["sha256"] = serde_json::Value::String(verifier_report_sha256.clone());
                }
                Some("ui/proof-room-static/load-report.json") => {
                    artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
                }
                _ => {}
            }
        }
        fs::write(&manifest_path, json_bytes(&manifest)?)?;
        refresh_bundle_signature(work.path())?;

        let error = verify_proof_room_bundle(&manifest_path)
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error.to_string().contains("proof-room.report.mismatch"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_source_report_for_non_transaction_required_claim() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        add_required_claim_to_verifier_policy(work.path(), "claim.runtime.execution_lease_valid")?;

        let error = verify_proof_room_bundle(&work.path().join("manifest.json"))
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("standalone transaction verifier cannot satisfy required claim"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_evidence_graph_that_transaction_verifier_rejects() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let evidence_graph_path = work.path().join("roots/evidence-graph.json");
        let mut evidence_graph: serde_json::Value =
            serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
        evidence_graph["edges"]
            .as_array_mut()
            .ok_or("evidence graph edges missing")?
            .push(serde_json::json!({
                "from": "allow-receipt",
                "to": "missing-evidence-node",
                "predicate": "binds",
                "evidence_class": "digest-bound-reference"
            }));
        let evidence_graph_bytes = json_bytes(&evidence_graph)?;
        fs::write(&evidence_graph_path, &evidence_graph_bytes)?;
        let evidence_graph_sha256 = super::sha256_hex(&evidence_graph_bytes);

        let passport_path = work.path().join("roots/transaction-passport.json");
        let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
        passport["evidence_graph_sha256"] =
            serde_json::Value::String(evidence_graph_sha256.clone());
        let passport_bytes = json_bytes(&passport)?;
        fs::write(&passport_path, &passport_bytes)?;
        let passport_sha256 = super::sha256_hex(&passport_bytes);

        let verifier_report_path = work.path().join("verifier/report.json");
        let mut verifier_report: serde_json::Value =
            serde_json::from_slice(&fs::read(&verifier_report_path)?)?;
        verifier_report["evidence_graph_sha256"] =
            serde_json::Value::String(evidence_graph_sha256.clone());
        let verifier_report_bytes = json_bytes(&verifier_report)?;
        fs::write(&verifier_report_path, &verifier_report_bytes)?;
        let verifier_report_sha256 = super::sha256_hex(&verifier_report_bytes);

        let ui_report_path = work.path().join("ui/proof-room-static/load-report.json");
        let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
        ui_report["source_verifier_report_ref"]["sha256"] =
            serde_json::Value::String(verifier_report_sha256.clone());
        let ui_report_bytes = json_bytes(&ui_report)?;
        fs::write(&ui_report_path, &ui_report_bytes)?;
        let ui_report_sha256 = super::sha256_hex(&ui_report_bytes);

        let manifest_path = work.path().join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        manifest["transaction_passport_ref"]["sha256"] =
            serde_json::Value::String(passport_sha256.clone());
        manifest["evidence_graph_ref"]["sha256"] =
            serde_json::Value::String(evidence_graph_sha256.clone());
        manifest["verifier_report_ref"]["sha256"] =
            serde_json::Value::String(verifier_report_sha256.clone());
        manifest["proof_room_verifier_report_ref"]["sha256"] =
            serde_json::Value::String(ui_report_sha256.clone());
        for artifact in manifest["artifacts"]
            .as_array_mut()
            .ok_or("manifest artifacts missing")?
        {
            match artifact.get("path").and_then(serde_json::Value::as_str) {
                Some("roots/transaction-passport.json") => {
                    artifact["sha256"] = serde_json::Value::String(passport_sha256.clone());
                }
                Some("roots/evidence-graph.json") => {
                    artifact["sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
                }
                Some("verifier/report.json") => {
                    artifact["sha256"] = serde_json::Value::String(verifier_report_sha256.clone());
                }
                Some("ui/proof-room-static/load-report.json") => {
                    artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
                }
                _ => {}
            }
        }
        fs::write(&manifest_path, json_bytes(&manifest)?)?;
        refresh_bundle_signature(work.path())?;

        let error = verify_proof_room_bundle(&manifest_path)
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error.to_string().contains("proof-room.report.mismatch")
                || error
                    .to_string()
                    .contains("unknown evidence graph edge target"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_authority_evidence_missing_from_graph() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;
        remove_graph_node_and_rehash(work.path(), "artifacts/authority/capability-proof.json")?;

        let error = verify_proof_room_bundle(&work.path().join("manifest.json"))
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.evidence-graph.authority-node-missing"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_authority_guard_report_without_capability_binding() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;
        remove_guard_report_capability_binding_and_rehash(work.path())?;

        let error = verify_proof_room_bundle(&work.path().join("manifest.json"))
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error.to_string().contains(
                "proof-room.authority-evidence.field-missing: artifacts/authority/guard-report.json capability_id"
            ),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_authority_guard_report_with_unexpected_field() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;

        let guard_report_path = work.path().join("artifacts/authority/guard-report.json");
        let mut guard_report: serde_json::Value =
            serde_json::from_slice(&fs::read(&guard_report_path)?)?;
        guard_report["ambient_authority"] = serde_json::Value::Bool(true);
        fs::write(&guard_report_path, json_bytes(&guard_report)?)?;
        let guard_report_sha256 = sha256_file(&guard_report_path)?;

        let evidence_graph_path = work.path().join("roots/evidence-graph.json");
        let mut evidence_graph: serde_json::Value =
            serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
        for node in evidence_graph["nodes"]
            .as_array_mut()
            .ok_or("evidence graph nodes missing")?
        {
            if node.get("path").and_then(serde_json::Value::as_str)
                == Some("artifacts/authority/guard-report.json")
            {
                node["sha256"] = serde_json::Value::String(guard_report_sha256.clone());
            }
        }
        fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
        refresh_source_roots_and_manifest(
            work.path(),
            Some(("artifacts/authority/guard-report.json", guard_report_sha256)),
        )?;

        let error = verify_proof_room_bundle(&work.path().join("manifest.json"))
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error
                .to_string()
                .contains("proof-room.schema-violation: authority_evidence"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_first_run_public_artifacts_with_unexpected_fields() -> Result<(), Box<dyn Error>> {
        let root = repo_root()?;
        let source =
            root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");

        for artifact_path in [
            "artifacts/release/command-log.json",
            "roots/request-digest.json",
            "roots/response-digest.json",
        ] {
            let work = tempfile::tempdir()?;
            copy_dir_all(&source, work.path())?;
            add_unexpected_field_to_bundle_artifact_and_rehash(work.path(), artifact_path)?;

            let error = verify_proof_room_bundle(&work.path().join("manifest.json"))
                .err()
                .ok_or("mutated proof room bundle unexpectedly verified")?;

            assert!(
                error
                    .to_string()
                    .contains("proof-room.schema-violation: artifact"),
                "{artifact_path}: {error}"
            );
        }
        Ok(())
    }

    fn repo_root() -> Result<std::path::PathBuf, Box<dyn Error>> {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for _ in 0..3 {
            path = path
                .parent()
                .ok_or("crate manifest directory has no repo parent")?
                .to_path_buf();
        }
        Ok(path)
    }

    fn copy_dir_all(source: &Path, destination: &Path) -> Result<(), Box<dyn Error>> {
        fs::create_dir_all(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let destination_path = destination.join(entry.file_name());
            if file_type.is_dir() {
                copy_dir_all(&entry.path(), &destination_path)?;
            } else if file_type.is_file() {
                fs::copy(entry.path(), destination_path)?;
            }
        }
        Ok(())
    }

    fn json_bytes(value: &serde_json::Value) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok([serde_json::to_vec_pretty(value)?.as_slice(), b"\n"].concat())
    }

    fn refresh_bundle_signature(bundle: &Path) -> Result<(), Box<dyn Error>> {
        let keypair = Keypair::from_seed(&TEST_SIGNATURE_SEED);
        sign_bundle_signature_with_key(bundle, &keypair)
    }

    fn sign_bundle_signature_with_key(
        bundle: &Path,
        keypair: &Keypair,
    ) -> Result<(), Box<dyn Error>> {
        let manifest_path = bundle.join("manifest.json");
        let signature_path = bundle.join("bundle-signature.dsse.json");
        let manifest_bytes = fs::read(&manifest_path)?;
        let mut signature: serde_json::Value = serde_json::from_slice(&fs::read(&signature_path)?)?;
        let signed_payload =
            super::dsse_pre_auth_encoding(super::PROOF_ROOM_DSSE_PAYLOAD_TYPE, &manifest_bytes);
        signature["payloadRef"]["sha256"] =
            serde_json::Value::String(super::sha256_hex(&manifest_bytes));
        signature["signatures"][0]["keyid"] =
            serde_json::Value::String(keypair.public_key().to_hex());
        signature["signatures"][0]["sig"] =
            serde_json::Value::String(keypair.sign(&signed_payload).to_hex());
        fs::write(&signature_path, json_bytes(&signature)?)?;
        Ok(())
    }

    fn remove_graph_node_and_rehash(
        bundle: &Path,
        artifact_path: &str,
    ) -> Result<(), Box<dyn Error>> {
        let evidence_graph_path = bundle.join("roots/evidence-graph.json");
        let mut evidence_graph: serde_json::Value =
            serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
        evidence_graph["nodes"]
            .as_array_mut()
            .ok_or("evidence graph nodes missing")?
            .retain(|node| {
                node.get("path").and_then(serde_json::Value::as_str) != Some(artifact_path)
            });
        fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
        let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

        let passport_path = bundle.join("roots/transaction-passport.json");
        let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
        passport["evidence_graph_sha256"] =
            serde_json::Value::String(evidence_graph_sha256.clone());
        fs::write(&passport_path, json_bytes(&passport)?)?;
        let passport_sha256 = sha256_file(&passport_path)?;

        let verifier_report_path = bundle.join("verifier/report.json");
        let mut verifier_report: serde_json::Value =
            serde_json::from_slice(&fs::read(&verifier_report_path)?)?;
        verifier_report["evidence_graph_sha256"] =
            serde_json::Value::String(evidence_graph_sha256.clone());
        fs::write(&verifier_report_path, json_bytes(&verifier_report)?)?;
        let verifier_report_sha256 = sha256_file(&verifier_report_path)?;

        let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
        let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
        ui_report["source_verifier_report_ref"]["sha256"] =
            serde_json::Value::String(verifier_report_sha256.clone());
        fs::write(&ui_report_path, json_bytes(&ui_report)?)?;
        let ui_report_sha256 = sha256_file(&ui_report_path)?;

        let manifest_path = bundle.join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        manifest["transaction_passport_ref"]["sha256"] =
            serde_json::Value::String(passport_sha256.clone());
        manifest["evidence_graph_ref"]["sha256"] =
            serde_json::Value::String(evidence_graph_sha256.clone());
        manifest["verifier_report_ref"]["sha256"] =
            serde_json::Value::String(verifier_report_sha256.clone());
        manifest["proof_room_verifier_report_ref"]["sha256"] =
            serde_json::Value::String(ui_report_sha256.clone());
        for artifact in manifest["artifacts"]
            .as_array_mut()
            .ok_or("manifest artifacts missing")?
        {
            match artifact.get("path").and_then(serde_json::Value::as_str) {
                Some("roots/transaction-passport.json") => {
                    artifact["sha256"] = serde_json::Value::String(passport_sha256.clone());
                }
                Some("roots/evidence-graph.json") => {
                    artifact["sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
                }
                Some("verifier/report.json") => {
                    artifact["sha256"] = serde_json::Value::String(verifier_report_sha256.clone());
                }
                Some("ui/proof-room-static/load-report.json") => {
                    artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
                }
                _ => {}
            }
        }
        fs::write(&manifest_path, json_bytes(&manifest)?)?;
        refresh_bundle_signature(bundle)?;
        Ok(())
    }

    fn remove_guard_report_capability_binding_and_rehash(
        bundle: &Path,
    ) -> Result<(), Box<dyn Error>> {
        let guard_report_path = bundle.join("artifacts/authority/guard-report.json");
        let mut guard_report: serde_json::Value =
            serde_json::from_slice(&fs::read(&guard_report_path)?)?;
        guard_report
            .as_object_mut()
            .ok_or("guard report object missing")?
            .remove("capability_id");
        fs::write(&guard_report_path, json_bytes(&guard_report)?)?;
        let guard_report_sha256 = sha256_file(&guard_report_path)?;

        let evidence_graph_path = bundle.join("roots/evidence-graph.json");
        let mut evidence_graph: serde_json::Value =
            serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
        for node in evidence_graph["nodes"]
            .as_array_mut()
            .ok_or("evidence graph nodes missing")?
        {
            if node.get("path").and_then(serde_json::Value::as_str)
                == Some("artifacts/authority/guard-report.json")
            {
                node["sha256"] = serde_json::Value::String(guard_report_sha256.clone());
            }
        }
        fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
        refresh_source_roots_and_manifest(
            bundle,
            Some(("artifacts/authority/guard-report.json", guard_report_sha256)),
        )?;
        Ok(())
    }

    fn add_unexpected_field_to_bundle_artifact_and_rehash(
        bundle: &Path,
        artifact_relative_path: &str,
    ) -> Result<(), Box<dyn Error>> {
        let artifact_path = bundle.join(artifact_relative_path);
        let mut artifact: serde_json::Value = serde_json::from_slice(&fs::read(&artifact_path)?)?;
        artifact["ambient_authority"] = serde_json::Value::Bool(true);
        fs::write(&artifact_path, json_bytes(&artifact)?)?;
        let artifact_sha256 = sha256_file(&artifact_path)?;

        let evidence_graph_path = bundle.join("roots/evidence-graph.json");
        let mut evidence_graph: serde_json::Value =
            serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
        if let Some(nodes) = evidence_graph["nodes"].as_array_mut() {
            for node in nodes {
                if node.get("path").and_then(serde_json::Value::as_str)
                    == Some(artifact_relative_path)
                {
                    node["sha256"] = serde_json::Value::String(artifact_sha256.clone());
                }
            }
            fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
        }

        refresh_source_roots_and_manifest(bundle, Some((artifact_relative_path, artifact_sha256)))?;
        Ok(())
    }

    fn sign_first_run_receipt_projection(
        receipt: &mut serde_json::Value,
    ) -> Result<(), Box<dyn Error>> {
        let keypair = Keypair::from_seed(&TEST_RECEIPT_SEED);
        receipt["kernel_key"] = serde_json::Value::String(keypair.public_key().to_hex());
        let mut signed_body = receipt.clone();
        signed_body
            .as_object_mut()
            .ok_or("receipt projection object missing")?
            .remove("signature");
        let (signature, _canonical) = keypair.sign_canonical(&signed_body)?;
        receipt["signature"] = serde_json::Value::String(signature.to_hex());
        Ok(())
    }

    fn update_evidence_graph_node_hash(
        bundle: &Path,
        artifact_relative_path: &str,
        artifact_sha256: &str,
    ) -> Result<(), Box<dyn Error>> {
        let evidence_graph_path = bundle.join("roots/evidence-graph.json");
        let mut evidence_graph: serde_json::Value =
            serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
        let node = evidence_graph["nodes"]
            .as_array_mut()
            .ok_or("evidence graph nodes missing")?
            .iter_mut()
            .find(|node| {
                node.get("path").and_then(serde_json::Value::as_str) == Some(artifact_relative_path)
            })
            .ok_or("evidence graph node missing")?;
        node["sha256"] = serde_json::Value::String(artifact_sha256.to_string());
        fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
        Ok(())
    }

    fn refresh_source_roots_and_manifest(
        bundle: &Path,
        extra_artifact_hash: Option<(&str, String)>,
    ) -> Result<(), Box<dyn Error>> {
        let evidence_graph_path = bundle.join("roots/evidence-graph.json");
        let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

        let passport_path = bundle.join("roots/transaction-passport.json");
        let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
        passport["evidence_graph_sha256"] =
            serde_json::Value::String(evidence_graph_sha256.clone());
        fs::write(&passport_path, json_bytes(&passport)?)?;
        let passport_sha256 = sha256_file(&passport_path)?;

        let verifier_report_path = bundle.join("verifier/report.json");
        let mut verifier_report: serde_json::Value =
            serde_json::from_slice(&fs::read(&verifier_report_path)?)?;
        verifier_report["evidence_graph_sha256"] =
            serde_json::Value::String(evidence_graph_sha256.clone());
        fs::write(&verifier_report_path, json_bytes(&verifier_report)?)?;
        let verifier_report_sha256 = sha256_file(&verifier_report_path)?;

        let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
        let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
        ui_report["source_verifier_report_ref"]["sha256"] =
            serde_json::Value::String(verifier_report_sha256.clone());
        fs::write(&ui_report_path, json_bytes(&ui_report)?)?;
        let ui_report_sha256 = sha256_file(&ui_report_path)?;

        let manifest_path = bundle.join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        manifest["transaction_passport_ref"]["sha256"] =
            serde_json::Value::String(passport_sha256.clone());
        manifest["evidence_graph_ref"]["sha256"] =
            serde_json::Value::String(evidence_graph_sha256.clone());
        manifest["verifier_report_ref"]["sha256"] =
            serde_json::Value::String(verifier_report_sha256.clone());
        manifest["proof_room_verifier_report_ref"]["sha256"] =
            serde_json::Value::String(ui_report_sha256.clone());
        for artifact in manifest["artifacts"]
            .as_array_mut()
            .ok_or("manifest artifacts missing")?
        {
            match artifact.get("path").and_then(serde_json::Value::as_str) {
                Some("roots/transaction-passport.json") => {
                    artifact["sha256"] = serde_json::Value::String(passport_sha256.clone());
                }
                Some("roots/evidence-graph.json") => {
                    artifact["sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
                }
                Some("verifier/report.json") => {
                    artifact["sha256"] = serde_json::Value::String(verifier_report_sha256.clone());
                }
                Some("ui/proof-room-static/load-report.json") => {
                    artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
                }
                Some(path) => {
                    if let Some((extra_path, extra_hash)) = extra_artifact_hash.as_ref() {
                        if path == *extra_path {
                            artifact["sha256"] = serde_json::Value::String(extra_hash.to_string());
                        }
                    }
                }
                None => {}
            }
        }
        fs::write(&manifest_path, json_bytes(&manifest)?)?;
        refresh_bundle_signature(bundle)?;
        Ok(())
    }

    fn add_required_claim_to_verifier_policy(
        bundle: &Path,
        claim: &str,
    ) -> Result<(), Box<dyn Error>> {
        let verifier_policy_path = bundle.join("roots/verifier-policy.json");
        let mut verifier_policy: serde_json::Value =
            serde_json::from_slice(&fs::read(&verifier_policy_path)?)?;
        verifier_policy["required_claims"]
            .as_array_mut()
            .ok_or("verifier policy required_claims missing")?
            .push(serde_json::Value::String(claim.to_string()));
        fs::write(&verifier_policy_path, json_bytes(&verifier_policy)?)?;
        let verifier_policy_sha256 = sha256_file(&verifier_policy_path)?;

        let evidence_graph_path = bundle.join("roots/evidence-graph.json");
        let mut evidence_graph: serde_json::Value =
            serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
        for node in evidence_graph["nodes"]
            .as_array_mut()
            .ok_or("evidence graph nodes missing")?
        {
            if node.get("path").and_then(serde_json::Value::as_str) == Some("verifier-policy.json")
            {
                node["sha256"] = serde_json::Value::String(verifier_policy_sha256.clone());
            }
        }
        fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
        let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

        let passport_path = bundle.join("roots/transaction-passport.json");
        let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
        passport["evidence_graph_sha256"] =
            serde_json::Value::String(evidence_graph_sha256.clone());
        passport["verifier_policy_sha256"] =
            serde_json::Value::String(verifier_policy_sha256.clone());
        fs::write(&passport_path, json_bytes(&passport)?)?;
        let passport_sha256 = sha256_file(&passport_path)?;

        let verifier_report_path = bundle.join("verifier/report.json");
        let mut verifier_report: serde_json::Value =
            serde_json::from_slice(&fs::read(&verifier_report_path)?)?;
        verifier_report["evidence_graph_sha256"] =
            serde_json::Value::String(evidence_graph_sha256.clone());
        verifier_report["verifier_policy_sha256"] =
            serde_json::Value::String(verifier_policy_sha256.clone());
        fs::write(&verifier_report_path, json_bytes(&verifier_report)?)?;
        let verifier_report_sha256 = sha256_file(&verifier_report_path)?;

        let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
        let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
        ui_report["source_verifier_report_ref"]["sha256"] =
            serde_json::Value::String(verifier_report_sha256.clone());
        fs::write(&ui_report_path, json_bytes(&ui_report)?)?;
        let ui_report_sha256 = sha256_file(&ui_report_path)?;

        let manifest_path = bundle.join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        manifest["transaction_passport_ref"]["sha256"] =
            serde_json::Value::String(passport_sha256.clone());
        manifest["evidence_graph_ref"]["sha256"] =
            serde_json::Value::String(evidence_graph_sha256.clone());
        manifest["verifier_report_ref"]["sha256"] =
            serde_json::Value::String(verifier_report_sha256.clone());
        manifest["proof_room_verifier_report_ref"]["sha256"] =
            serde_json::Value::String(ui_report_sha256.clone());
        for artifact in manifest["artifacts"]
            .as_array_mut()
            .ok_or("manifest artifacts missing")?
        {
            match artifact.get("path").and_then(serde_json::Value::as_str) {
                Some("roots/transaction-passport.json") => {
                    artifact["sha256"] = serde_json::Value::String(passport_sha256.clone());
                }
                Some("roots/evidence-graph.json") => {
                    artifact["sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
                }
                Some("roots/verifier-policy.json") => {
                    artifact["sha256"] = serde_json::Value::String(verifier_policy_sha256.clone());
                }
                Some("verifier/report.json") => {
                    artifact["sha256"] = serde_json::Value::String(verifier_report_sha256.clone());
                }
                Some("ui/proof-room-static/load-report.json") => {
                    artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
                }
                _ => {}
            }
        }
        fs::write(&manifest_path, json_bytes(&manifest)?)?;
        refresh_bundle_signature(bundle)?;
        Ok(())
    }

    fn remove_verifier_policy_field_and_rehash(
        bundle: &Path,
        field: &str,
    ) -> Result<(), Box<dyn Error>> {
        let verifier_policy_path = bundle.join("roots/verifier-policy.json");
        let mut verifier_policy: serde_json::Value =
            serde_json::from_slice(&fs::read(&verifier_policy_path)?)?;
        verifier_policy
            .as_object_mut()
            .ok_or("verifier policy object missing")?
            .remove(field);
        fs::write(&verifier_policy_path, json_bytes(&verifier_policy)?)?;
        let verifier_policy_sha256 = sha256_file(&verifier_policy_path)?;

        let evidence_graph_path = bundle.join("roots/evidence-graph.json");
        let mut evidence_graph: serde_json::Value =
            serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
        for node in evidence_graph["nodes"]
            .as_array_mut()
            .ok_or("evidence graph nodes missing")?
        {
            if node.get("path").and_then(serde_json::Value::as_str) == Some("verifier-policy.json")
            {
                node["sha256"] = serde_json::Value::String(verifier_policy_sha256.clone());
            }
        }
        fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
        let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

        let passport_path = bundle.join("roots/transaction-passport.json");
        let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
        passport["evidence_graph_sha256"] =
            serde_json::Value::String(evidence_graph_sha256.clone());
        passport["verifier_policy_sha256"] =
            serde_json::Value::String(verifier_policy_sha256.clone());
        fs::write(&passport_path, json_bytes(&passport)?)?;
        let passport_sha256 = sha256_file(&passport_path)?;

        let verifier_report_path = bundle.join("verifier/report.json");
        let mut verifier_report: serde_json::Value =
            serde_json::from_slice(&fs::read(&verifier_report_path)?)?;
        verifier_report["evidence_graph_sha256"] =
            serde_json::Value::String(evidence_graph_sha256.clone());
        verifier_report["verifier_policy_sha256"] =
            serde_json::Value::String(verifier_policy_sha256.clone());
        fs::write(&verifier_report_path, json_bytes(&verifier_report)?)?;
        let verifier_report_sha256 = sha256_file(&verifier_report_path)?;

        let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
        let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
        ui_report["source_verifier_report_ref"]["sha256"] =
            serde_json::Value::String(verifier_report_sha256.clone());
        fs::write(&ui_report_path, json_bytes(&ui_report)?)?;
        let ui_report_sha256 = sha256_file(&ui_report_path)?;

        let test_key_id = Keypair::from_seed(&TEST_SIGNATURE_SEED)
            .public_key()
            .to_hex();
        let trust_roots_path = bundle.join("artifacts/authority/trust-roots.json");
        let mut trust_roots: serde_json::Value =
            serde_json::from_slice(&fs::read(&trust_roots_path)?)?;
        let root = trust_roots["roots"]
            .as_array_mut()
            .and_then(|roots| roots.first_mut())
            .ok_or("trust roots missing")?;
        root["key_id"] = serde_json::Value::String(test_key_id.clone());
        root["key_digest"] = serde_json::Value::String(super::sha256_hex(test_key_id.as_bytes()));
        fs::write(&trust_roots_path, json_bytes(&trust_roots)?)?;
        let trust_roots_sha256 = sha256_file(&trust_roots_path)?;

        let manifest_path = bundle.join("manifest.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        manifest["transaction_passport_ref"]["sha256"] =
            serde_json::Value::String(passport_sha256.clone());
        manifest["evidence_graph_ref"]["sha256"] =
            serde_json::Value::String(evidence_graph_sha256.clone());
        manifest["verifier_report_ref"]["sha256"] =
            serde_json::Value::String(verifier_report_sha256.clone());
        manifest["proof_room_verifier_report_ref"]["sha256"] =
            serde_json::Value::String(ui_report_sha256.clone());
        for artifact in manifest["artifacts"]
            .as_array_mut()
            .ok_or("manifest artifacts missing")?
        {
            match artifact.get("path").and_then(serde_json::Value::as_str) {
                Some("roots/transaction-passport.json") => {
                    artifact["sha256"] = serde_json::Value::String(passport_sha256.clone());
                }
                Some("roots/evidence-graph.json") => {
                    artifact["sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
                }
                Some("roots/verifier-policy.json") => {
                    artifact["sha256"] = serde_json::Value::String(verifier_policy_sha256.clone());
                }
                Some("verifier/report.json") => {
                    artifact["sha256"] = serde_json::Value::String(verifier_report_sha256.clone());
                }
                Some("ui/proof-room-static/load-report.json") => {
                    artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
                }
                Some("artifacts/authority/trust-roots.json") => {
                    artifact["sha256"] = serde_json::Value::String(trust_roots_sha256.clone());
                }
                _ => {}
            }
        }
        fs::write(&manifest_path, json_bytes(&manifest)?)?;
        refresh_bundle_signature(bundle)?;
        Ok(())
    }

    fn sha256_file(path: &Path) -> Result<String, Box<dyn Error>> {
        Ok(super::sha256_hex(&fs::read(path)?))
    }
}
