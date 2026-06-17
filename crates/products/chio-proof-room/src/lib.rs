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

mod bundle_a;
mod bundle_b;
mod crypto_context;
mod fixture_a;
mod fixture_b;
mod receipt_coverage;
mod server;
mod source_verifier;
#[cfg(test)]
mod tests;

pub(crate) use bundle_a::*;
pub(crate) use bundle_b::*;
pub(crate) use fixture_a::*;
pub(crate) use fixture_b::*;
pub(crate) use source_verifier::*;

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
const CLAIM_PREFIX_TRANSACTION: &str = "claim.transaction.";
const CLAIM_PREFIX_MARKET: &str = "claim.market.";
const AGENT_WEB_STANDARD_WEBHOOKS_SECRET_ENV: &str = "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_SECRET";
const AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV: &str = "CHIO_AGENT_WEB_TRUSTED_KERNEL_KEYS";
const SOURCE_VERIFIER_CLAIM_PREFIXES: [&str; 11] = [
    CLAIM_PREFIX_RUNTIME,
    CLAIM_PREFIX_RISK,
    CLAIM_PREFIX_ENTERPRISE,
    CLAIM_PREFIX_AGENT_WEB,
    CLAIM_PREFIX_TRUST_MARKET,
    CLAIM_PREFIX_PUBLIC_SETTLEMENT,
    CLAIM_PREFIX_SWARM,
    CLAIM_PREFIX_DISCLOSURE,
    CLAIM_PREFIX_COMMERCE,
    CLAIM_PREFIX_TRANSACTION,
    CLAIM_PREFIX_MARKET,
];

pub(crate) fn agent_web_verifier_trust_from_env(
) -> Result<chio_agent_web_interop::AgentWebVerifierTrust, String> {
    let mut trust = match env::var(AGENT_WEB_STANDARD_WEBHOOKS_SECRET_ENV) {
        Ok(secret) => chio_agent_web_interop::AgentWebVerifierTrust::new()
            .with_standard_webhooks_secret(secret.into_bytes()),
        Err(env::VarError::NotPresent) => chio_agent_web_interop::AgentWebVerifierTrust::new(),
        Err(env::VarError::NotUnicode(_)) => {
            return Err(format!(
                "{AGENT_WEB_STANDARD_WEBHOOKS_SECRET_ENV} must be valid UTF-8"
            ))
        }
    };
    match env::var(AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV) {
        Ok(keys) => {
            trust =
                trust.with_trusted_receipt_kernel_keys(parse_agent_web_trusted_kernel_keys(&keys)?);
        }
        Err(env::VarError::NotPresent) => {}
        Err(env::VarError::NotUnicode(_)) => {
            return Err(format!(
                "{AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV} must be valid UTF-8"
            ))
        }
    }
    Ok(trust)
}

fn parse_agent_web_trusted_kernel_keys(
    keys: &str,
) -> Result<Vec<chio_core_types::PublicKey>, String> {
    if keys.trim().is_empty() {
        return Err(format!(
            "{AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV} must contain comma-separated public keys"
        ));
    }

    keys.split(',')
        .map(|key| {
            let key = key.trim();
            if key.is_empty() {
                return Err(format!(
                    "{AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV} must not contain empty public keys"
                ));
            }
            chio_core_types::PublicKey::from_hex(key).map_err(|error| {
                format!("{AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV} contains invalid public key: {error}")
            })
        })
        .collect()
}
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
    result: String,
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
