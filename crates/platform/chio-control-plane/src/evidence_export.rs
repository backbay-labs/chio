use std::cmp::{max, min};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use chio_core::receipt::{
    body::ChioReceipt, crypto_floor::ReceiptCryptoFloor, kinds::BoundaryClass, kinds::ReceiptKind,
};
use chio_core::{
    canonical_json_bytes, receipt::body::chio_receipt_id, sha256_hex, PublicKey, Signature,
};
use chio_kernel::checkpoint::{
    checkpoint_body_sha256, validate_checkpoint_transparency, CheckpointConsistencyProof,
    CheckpointEquivocation, CheckpointPublication, CheckpointTransparencySummary,
    CheckpointWitness,
};
use chio_kernel::evidence_export::{
    build_evidence_transparency_claims, EvidenceTransparencyClaims,
};
use chio_kernel::{
    is_supported_checkpoint_schema, verify_checkpoint_signature, CapabilitySnapshot,
    EvidenceChildReceiptRecord, EvidenceChildReceiptScope, EvidenceExportBundle,
    EvidenceExportQuery, EvidenceRetentionMetadata, EvidenceToolReceiptRecord,
    EvidenceUncheckpointedReceipt, KernelCheckpoint, ReceiptInclusionProof, ReceiptReadBoundary,
};
use chio_store_sqlite::SqliteReceiptStore;

use crate::policy::load_policy;
use crate::{load_or_create_authority_keypair, CliError};

mod verification;

pub use verification::load_verified_evidence_package_summary;
pub(crate) use verification::{build_federated_share_import, validate_import_package_data};
use verification::{
    evidence_receipt_semantic_summary, load_verified_evidence_package,
    validate_checkpoint_transparency_summary, verify_checkpoint_transparency_records,
};

const EVIDENCE_EXPORT_MANIFEST_SCHEMA: &str = "chio.evidence_export_manifest.v1";
const FEDERATION_POLICY_SCHEMA: &str = "chio.federation-policy.v1";
const FEDERATED_EVIDENCE_SHARE_SCHEMA: &str = "chio.federated-evidence-share.v1";

fn is_supported_evidence_export_manifest_schema(schema: &str) -> bool {
    schema == EVIDENCE_EXPORT_MANIFEST_SCHEMA
}

fn is_supported_federation_policy_schema(schema: &str) -> bool {
    schema == FEDERATION_POLICY_SCHEMA
}

fn federated_evidence_share_schema_for_manifest(_schema: &str) -> &'static str {
    FEDERATED_EVIDENCE_SHARE_SCHEMA
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct EvidenceExportCounts {
    tool_receipts: u64,
    child_receipts: u64,
    checkpoints: u64,
    capability_lineage: u64,
    inclusion_proofs: u64,
    uncheckpointed_receipts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct EvidenceProofCoverage {
    checkpointed_receipts: u64,
    uncheckpointed_receipts: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct EvidenceReceiptSemanticSummary {
    mediated_decisions: u64,
    trace_observations: u64,
    advisory_evaluations: u64,
    prevent: u64,
    detect_only: u64,
    advisory_only: u64,
    cannot_see: u64,
    authorized: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct EvidenceExportFileHash {
    path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct PolicyAttachmentMetadata {
    format: String,
    source_hash: String,
    runtime_hash: String,
    source_path: String,
    source_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct FederationPolicyAttachmentMetadata {
    issuer: String,
    partner: String,
    signer_public_key: PublicKey,
    created_at: u64,
    expires_at: u64,
    require_proofs: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FederationPolicyBody {
    schema: String,
    issuer: String,
    partner: String,
    signer_public_key: PublicKey,
    created_at: u64,
    expires_at: u64,
    query: EvidenceExportQuery,
    require_proofs: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FederationPolicyDocument {
    body: FederationPolicyBody,
    signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct RemoteEvidenceExportRequest {
    #[serde(default)]
    pub query: EvidenceExportQuery,
    #[serde(default)]
    pub require_proofs: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_policy: Option<FederationPolicyDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteEvidenceExportResponse {
    pub bundle: EvidenceExportBundle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency: Option<CheckpointTransparencySummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_policy: Option<FederationPolicyDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceImportPackage {
    manifest: EvidenceExportManifest,
    bundle: EvidenceExportBundle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transparency: Option<CheckpointTransparencySummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    federation_policy: Option<FederationPolicyDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteEvidenceImportRequest {
    pub package: EvidenceImportPackage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteEvidenceImportResponse {
    pub share: chio_kernel::FederatedEvidenceShareSummary,
}

#[derive(Debug, Clone)]
pub struct VerifiedEvidencePackage {
    pub bundle: EvidenceExportBundle,
    pub transparency: Option<CheckpointTransparencySummary>,
    pub manifest_schema: String,
    pub exported_at: u64,
    pub manifest_hash: String,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedEvidenceExport {
    pub query: EvidenceExportQuery,
    pub require_proofs: bool,
    pub federation_policy: Option<FederationPolicyDocument>,
}

/// Documented metadata disclosure attached to tenant-scoped exports.
///
/// Tenant-scoped evidence exports inherit kernel-signed checkpoint bodies and
/// their inclusion proofs. Those signed artifacts cover the full per-batch
/// Merkle tree, which is shared across tenants by design. This notice lists
/// which cross-tenant fields the exported checkpoint set inherently reveals,
/// so receiving parties can audit the disclosure boundary without parsing
/// every signed body manually. Admin-all exports do not carry the notice
/// because the operator already requested a cross-tenant view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct EvidenceDisclosureNotice {
    /// Stable identifier for the notice format so downstream parsers can
    /// branch deterministically when the disclosure list changes.
    schema: String,
    /// Concise summary describing why this disclosure is unavoidable in the
    /// current protocol version.
    summary: String,
    /// Names of fields on each exported `KernelCheckpointBody` (in
    /// `checkpoints.ndjson`) that describe the full per-batch Merkle tree and
    /// therefore reveal cross-tenant aggregate information.
    disclosed_checkpoint_body_fields: Vec<String>,
    /// Names of derived publication / witness fields (in
    /// `checkpoint-*.ndjson`) that mirror the signed body and are therefore
    /// equivalent disclosures.
    disclosed_publication_fields: Vec<String>,
    /// Specific metadata that is intentionally narrowed for tenant-scoped
    /// exports compared to admin-all exports.
    narrowed_metadata: Vec<String>,
    /// Stable reference to the docs section describing why the disclosure
    /// cannot be eliminated without protocol-level changes.
    protocol_reference: String,
}

const EVIDENCE_DISCLOSURE_NOTICE_SCHEMA: &str = "chio.evidence_export_disclosure_notice.v1";

fn tenant_scoped_disclosure_notice() -> EvidenceDisclosureNotice {
    EvidenceDisclosureNotice {
        schema: EVIDENCE_DISCLOSURE_NOTICE_SCHEMA.to_string(),
        summary: "Kernel-signed checkpoint bodies and their derived publication records cover the full per-batch Merkle tree shared across tenants. Tenant-scoped exports therefore reveal aggregate batch metadata for receipts they do not contain. This disclosure is unavoidable without protocol-level per-tenant subtree proofs.".to_string(),
        disclosed_checkpoint_body_fields: vec![
            "batch_start_seq".to_string(),
            "batch_end_seq".to_string(),
            "tree_size".to_string(),
            "merkle_root".to_string(),
            "checkpoint_seq".to_string(),
            "issued_at".to_string(),
            "previous_checkpoint_sha256".to_string(),
        ],
        disclosed_publication_fields: vec![
            "entry_start_seq".to_string(),
            "entry_end_seq".to_string(),
            "log_tree_size".to_string(),
        ],
        narrowed_metadata: vec![
            "retention.liveDbSizeBytes is omitted (admin-all only)".to_string(),
            "retention.oldestLiveReceiptTimestamp is restricted to the requesting tenant"
                .to_string(),
        ],
        protocol_reference:
            "docs/release/COMPLIANCE_EVIDENCE_EXPORT_PLAN.md#tenant-scoped-disclosure".to_string(),
    }
}

#[must_use]
fn maybe_build_disclosure_notice(query: &EvidenceExportQuery) -> Option<EvidenceDisclosureNotice> {
    match &query.read_boundary {
        Some(ReceiptReadBoundary::TenantScoped { .. }) => Some(tenant_scoped_disclosure_notice()),
        Some(ReceiptReadBoundary::AdminAll) | None => None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct EvidenceExportManifest {
    schema: String,
    exported_at: u64,
    query: EvidenceExportQuery,
    counts: EvidenceExportCounts,
    proof_coverage: EvidenceProofCoverage,
    #[serde(default)]
    receipt_semantics: EvidenceReceiptSemanticSummary,
    child_receipt_scope: EvidenceChildReceiptScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    claim_boundary: Option<EvidenceTransparencyClaims>,
    files: Vec<EvidenceExportFileHash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy: Option<PolicyAttachmentMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    federation_policy: Option<FederationPolicyAttachmentMetadata>,
    /// Per-tenant disclosure notice attached when the export is tenant-scoped.
    /// Documents which signed-checkpoint fields inherently reveal aggregate
    /// cross-tenant metadata so the disclosure boundary stays auditable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    disclosure_notice: Option<EvidenceDisclosureNotice>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceVerificationResult {
    schema: String,
    verified_at: u64,
    tool_receipts: u64,
    child_receipts: u64,
    checkpoints: u64,
    checkpoint_publications: u64,
    checkpoint_witnesses: u64,
    checkpoint_consistency_proofs: u64,
    checkpoint_equivocations: u64,
    capability_lineage: u64,
    inclusion_proofs: u64,
    uncheckpointed_receipts: u64,
    receipt_semantics: EvidenceReceiptSemanticSummary,
    verified_files: u64,
    child_receipt_scope: EvidenceChildReceiptScope,
    claim_boundary: EvidenceTransparencyClaims,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    disclosure_notice: Option<EvidenceDisclosureNotice>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn ensure_clean_output_dir(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        if !path.is_dir() {
            return Err(CliError::cli_other_error(format!(
                "evidence export output path must be a directory: {}",
                path.display()
            )));
        }
        let mut entries = fs::read_dir(path).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to inspect evidence export output directory {}: {error}",
                path.display()
            ))
        })?;
        match entries.next() {
            Some(Ok(_)) => {
                return Err(CliError::cli_other_error(format!(
                    "evidence export output directory must be empty: {}",
                    path.display()
                )));
            }
            Some(Err(error)) => {
                return Err(CliError::cli_io_error(format!(
                    "failed to inspect evidence export output directory {}: {error}",
                    path.display()
                )));
            }
            None => {}
        }
    } else {
        fs::create_dir_all(path).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to create evidence export output directory {}: {error}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

fn ensure_existing_dir(path: &Path, label: &str) -> Result<(), CliError> {
    if !path.exists() {
        return Err(CliError::attest_error(format!(
            "{label} directory does not exist: {}",
            path.display()
        )));
    }
    if !path.is_dir() {
        return Err(CliError::attest_error(format!(
            "{label} path must be a directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn write_bytes_file(
    output_dir: &Path,
    relative_path: &str,
    bytes: &[u8],
    file_hashes: &mut Vec<EvidenceExportFileHash>,
) -> Result<(), CliError> {
    let path = output_dir.join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, bytes)?;
    file_hashes.push(EvidenceExportFileHash {
        path: relative_path.to_string(),
        sha256: sha256_hex(bytes),
        bytes: bytes.len() as u64,
    });
    Ok(())
}

fn write_json_file<T: Serialize>(
    output_dir: &Path,
    relative_path: &str,
    value: &T,
    file_hashes: &mut Vec<EvidenceExportFileHash>,
) -> Result<(), CliError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_bytes_file(output_dir, relative_path, &bytes, file_hashes)
}

fn write_ndjson_file<T: Serialize>(
    output_dir: &Path,
    relative_path: &str,
    records: &[T],
    file_hashes: &mut Vec<EvidenceExportFileHash>,
) -> Result<(), CliError> {
    let mut bytes = Vec::new();
    for record in records {
        bytes.extend_from_slice(serde_json::to_string(record)?.as_bytes());
        bytes.push(b'\n');
    }
    write_bytes_file(output_dir, relative_path, &bytes, file_hashes)
}

fn read_json_file<T: for<'de> Deserialize<'de>>(
    input_dir: &Path,
    relative_path: &str,
) -> Result<T, CliError> {
    let path = input_dir.join(relative_path);
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn read_ndjson_file<T: for<'de> Deserialize<'de>>(
    input_dir: &Path,
    relative_path: &str,
) -> Result<Vec<T>, CliError> {
    let path = input_dir.join(relative_path);
    let bytes = fs::read(path)?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    String::from_utf8(bytes)
        .map_err(|error| {
            CliError::attest_error(format!("{} is not valid UTF-8: {error}", relative_path))
        })?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line).map_err(|error| {
                CliError::attest_error(format!(
                    "{relative_path} line {} does not parse as the current record schema \
                     (records written by an older schema version must be re-exported): {error}",
                    index + 1
                ))
            })
        })
        .collect()
}

fn read_optional_ndjson_file<T: for<'de> Deserialize<'de>>(
    input_dir: &Path,
    relative_path: &str,
) -> Result<Vec<T>, CliError> {
    let path = input_dir.join(relative_path);
    if !path.exists() {
        return Ok(Vec::new());
    }
    read_ndjson_file(input_dir, relative_path)
}

fn render_readme(
    bundle: &EvidenceExportBundle,
    transparency: &CheckpointTransparencySummary,
    claim_boundary: &EvidenceTransparencyClaims,
    disclosure_notice: Option<&EvidenceDisclosureNotice>,
) -> String {
    let trust_anchor = claim_boundary.trust_anchor.as_deref().unwrap_or("none");
    let child_scope = match bundle.child_receipt_scope {
        EvidenceChildReceiptScope::FullQueryWindow => {
            "Child receipts include the full export query window."
        }
        EvidenceChildReceiptScope::TimeWindowContextOnly => {
            "Child receipts are included only as time-window context; capability and agent filters do not apply to them yet."
        }
        EvidenceChildReceiptScope::OmittedNoJoinPath => {
            "Child receipts are omitted because the export was capability/agent scoped without a truthful child-receipt join path."
        }
    };
    let disclosure_block = match disclosure_notice {
        Some(notice) => format!(
            "\nCross-tenant disclosure notice\n{}\nDisclosed checkpoint body fields: {}\nDisclosed publication record fields: {}\nNarrowed metadata: {}\nProtocol reference: {}\n",
            notice.summary,
            notice.disclosed_checkpoint_body_fields.join(", "),
            notice.disclosed_publication_fields.join(", "),
            notice.narrowed_metadata.join("; "),
            notice.protocol_reference,
        ),
        None => String::new(),
    };

    format!(
        "\
Chio evidence export

This directory is a local SQLite export assembled by `chio evidence export`.
It contains signed receipts, checkpoints, inclusion proofs, capability lineage,
and retention metadata for offline review.

Audit claims in this package are limited to local receipt verification,
signed checkpoint continuity, and inclusion-proof coverage.
Publication state: {}
Trust anchor: {}
Transparency log identity and append-only growth remain preview-only unless
the package itself carries verifiable trust-anchor publication material.

Tool receipts: {}
Child receipts: {}
Checkpoints: {}
Inclusion proofs: {}
Uncheckpointed receipts: {}
Checkpoint publications: {}
Checkpoint witnesses: {}
Checkpoint consistency proofs: {}
Checkpoint equivocations: {}
Transparency preview logs: {}

{}
{}",
        claim_boundary.publication_state.as_str(),
        trust_anchor,
        bundle.tool_receipts.len(),
        bundle.child_receipts.len(),
        bundle.checkpoints.len(),
        bundle.inclusion_proofs.len(),
        bundle.uncheckpointed_receipts.len(),
        transparency.publications.len(),
        transparency.witnesses.len(),
        transparency.consistency_proofs.len(),
        transparency.equivocations.len(),
        claim_boundary.transparency_preview.len(),
        child_scope,
        disclosure_block,
    )
}

fn policy_source_relative_path(policy_file: &Path) -> String {
    let extension = policy_file
        .extension()
        .and_then(|extension| extension.to_str())
        .filter(|extension| !extension.is_empty())
        .unwrap_or("txt");
    format!("policy/source.{extension}")
}

fn federation_policy_relative_path() -> &'static str {
    "federation-policy.json"
}

fn policy_metadata(
    policy_file: &Path,
    source_path: &str,
    source_bytes: u64,
) -> Result<PolicyAttachmentMetadata, CliError> {
    let loaded = load_policy(policy_file)?;
    Ok(PolicyAttachmentMetadata {
        format: loaded.format_name().to_string(),
        source_hash: loaded.identity.source_hash,
        runtime_hash: loaded.identity.runtime_hash,
        source_path: source_path.to_string(),
        source_bytes,
    })
}

fn read_federation_policy(path: &Path) -> Result<FederationPolicyDocument, CliError> {
    let policy: FederationPolicyDocument = serde_json::from_slice(&fs::read(path)?)?;
    verify_federation_policy(&policy)?;
    Ok(policy)
}

pub(crate) fn render_missing_proofs_error(records: &[EvidenceUncheckpointedReceipt]) -> CliError {
    let sample = records
        .iter()
        .take(5)
        .map(|record| format!("{}@{}", record.receipt_id, record.seq))
        .collect::<Vec<_>>()
        .join(", ");
    CliError::attest_error(format!(
        "evidence export requires checkpoint coverage, but {} receipt(s) are uncheckpointed: {}",
        records.len(),
        sample
    ))
}

pub(crate) fn verify_federation_policy(policy: &FederationPolicyDocument) -> Result<(), CliError> {
    if !is_supported_federation_policy_schema(&policy.body.schema) {
        return Err(CliError::attest_error(format!(
            "unsupported federation policy schema: expected {}, got {}",
            FEDERATION_POLICY_SCHEMA, policy.body.schema
        )));
    }
    if policy.body.created_at > policy.body.expires_at {
        return Err(CliError::attest_error(
            "federation policy created_at must be less than or equal to expires_at".to_string(),
        ));
    }
    if !policy
        .body
        .signer_public_key
        .verify_canonical(&policy.body, &policy.signature)?
    {
        return Err(CliError::attest_error(
            "federation policy signature verification failed".to_string(),
        ));
    }
    match &policy.body.query.read_boundary {
        Some(ReceiptReadBoundary::TenantScoped { tenant }) => {
            if tenant.trim().is_empty() {
                return Err(CliError::attest_error(
                    "federation policy tenant read boundary requires a non-empty tenant"
                        .to_string(),
                ));
            }
            if policy
                .body
                .query
                .tenant
                .as_deref()
                .is_some_and(|query_tenant| query_tenant != tenant)
            {
                return Err(CliError::attest_error(
                    "federation policy tenant scope must match its read boundary".to_string(),
                ));
            }
        }
        Some(ReceiptReadBoundary::AdminAll) => {
            if policy
                .body
                .query
                .tenant
                .as_deref()
                .is_some_and(|tenant| !tenant.trim().is_empty())
            {
                return Err(CliError::attest_error(
                    "federation policy admin-all read boundary must not include tenant scope"
                        .to_string(),
                ));
            }
        }
        None => {
            return Err(CliError::attest_error(
                "federation policy must bind an explicit receipt read boundary".to_string(),
            ));
        }
    }
    Ok(())
}

fn federation_policy_metadata(
    policy: &FederationPolicyDocument,
) -> FederationPolicyAttachmentMetadata {
    FederationPolicyAttachmentMetadata {
        issuer: policy.body.issuer.clone(),
        partner: policy.body.partner.clone(),
        signer_public_key: policy.body.signer_public_key.clone(),
        created_at: policy.body.created_at,
        expires_at: policy.body.expires_at,
        require_proofs: policy.body.require_proofs,
    }
}

pub(crate) fn merge_export_query(
    policy_query: &EvidenceExportQuery,
    cli_query: &EvidenceExportQuery,
) -> Result<EvidenceExportQuery, CliError> {
    let capability_id = merge_exact_scope(
        policy_query.capability_id.as_deref(),
        cli_query.capability_id.as_deref(),
        "capability_id",
    )?;
    let agent_subject = merge_exact_scope(
        policy_query.agent_subject.as_deref(),
        cli_query.agent_subject.as_deref(),
        "agent_subject",
    )?;
    let tenant = merge_exact_scope(
        policy_query.tenant.as_deref(),
        cli_query.tenant.as_deref(),
        "tenant",
    )?;
    let read_boundary = merge_read_boundary(
        policy_query.read_boundary.as_ref(),
        cli_query.read_boundary.as_ref(),
    )?;
    let since = match (policy_query.since, cli_query.since) {
        (Some(policy), Some(cli)) => Some(max(policy, cli)),
        (Some(policy), None) => Some(policy),
        (None, Some(cli)) => Some(cli),
        (None, None) => None,
    };
    let until = match (policy_query.until, cli_query.until) {
        (Some(policy), Some(cli)) => Some(min(policy, cli)),
        (Some(policy), None) => Some(policy),
        (None, Some(cli)) => Some(cli),
        (None, None) => None,
    };
    if let (Some(since), Some(until)) = (since, until) {
        if since > until {
            return Err(CliError::attest_error(
                "federation policy scope and requested export window do not overlap".to_string(),
            ));
        }
    }
    let mut merged = EvidenceExportQuery {
        capability_id,
        agent_subject,
        since,
        until,
        tenant,
        read_boundary,
    };
    if let Some(ReceiptReadBoundary::TenantScoped { tenant }) = &merged.read_boundary {
        if merged
            .tenant
            .as_deref()
            .is_some_and(|query_tenant| query_tenant != tenant)
        {
            return Err(CliError::attest_error(
                "evidence package read boundary tenant conflicts with query tenant".to_string(),
            ));
        }
        merged.tenant = Some(tenant.clone());
    }
    Ok(merged)
}

fn merge_exact_scope(
    policy_value: Option<&str>,
    cli_value: Option<&str>,
    field: &str,
) -> Result<Option<String>, CliError> {
    match (policy_value, cli_value) {
        (Some(policy), Some(cli)) if policy != cli => Err(CliError::attest_error(format!(
            "requested export {field} falls outside the signed federation policy"
        ))),
        (Some(policy), _) => Ok(Some(policy.to_string())),
        (None, Some(cli)) => Ok(Some(cli.to_string())),
        (None, None) => Ok(None),
    }
}

fn merge_read_boundary(
    policy_value: Option<&ReceiptReadBoundary>,
    cli_value: Option<&ReceiptReadBoundary>,
) -> Result<Option<ReceiptReadBoundary>, CliError> {
    match (policy_value, cli_value) {
        (
            Some(ReceiptReadBoundary::TenantScoped { tenant: policy }),
            Some(ReceiptReadBoundary::TenantScoped { tenant: cli }),
        ) if policy != cli => Err(CliError::attest_error(format!(
            "requested export tenant scope '{cli}' falls outside the signed federation policy \
             tenant scope '{policy}'"
        ))),
        (Some(ReceiptReadBoundary::TenantScoped { .. }), Some(ReceiptReadBoundary::AdminAll)) => {
            Err(CliError::attest_error(
                "requested admin-all export exceeds tenant-scoped federation policy".to_string(),
            ))
        }
        (Some(boundary), _) => Ok(Some(boundary.clone())),
        (None, Some(_)) | (None, None) => Err(CliError::attest_error(
            "signed federation policy must bind an explicit receipt read boundary".to_string(),
        )),
    }
}

pub(crate) fn ensure_query_within_federation_policy(
    policy_query: &EvidenceExportQuery,
    export_query: &EvidenceExportQuery,
) -> Result<(), CliError> {
    let merged_boundary = merge_read_boundary(
        policy_query.read_boundary.as_ref(),
        export_query.read_boundary.as_ref(),
    )?;
    if merged_boundary != export_query.read_boundary {
        return Err(CliError::attest_error(
            "evidence package read boundary exceeds federation policy scope".to_string(),
        ));
    }
    if let Some(ReceiptReadBoundary::TenantScoped { tenant }) = &export_query.read_boundary {
        if export_query
            .tenant
            .as_deref()
            .is_some_and(|query_tenant| query_tenant != tenant)
        {
            return Err(CliError::attest_error(
                "evidence package read boundary tenant conflicts with query tenant".to_string(),
            ));
        }
    }
    if policy_query.capability_id.is_some()
        && policy_query.capability_id != export_query.capability_id
    {
        return Err(CliError::attest_error(
            "evidence package query exceeds federation policy capability scope".to_string(),
        ));
    }
    if policy_query.agent_subject.is_some()
        && policy_query.agent_subject != export_query.agent_subject
    {
        return Err(CliError::attest_error(
            "evidence package query exceeds federation policy agent scope".to_string(),
        ));
    }
    if policy_query.tenant.is_some() && policy_query.tenant != export_query.tenant {
        return Err(CliError::attest_error(
            "evidence package query exceeds federation policy tenant scope".to_string(),
        ));
    }
    if let Some(policy_since) = policy_query.since {
        if export_query.since.unwrap_or(0) < policy_since {
            return Err(CliError::attest_error(
                "evidence package query starts before the federation policy window".to_string(),
            ));
        }
    }
    if let Some(policy_until) = policy_query.until {
        if export_query.until.unwrap_or(u64::MAX) > policy_until {
            return Err(CliError::attest_error(
                "evidence package query ends after the federation policy window".to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn prepare_evidence_export(
    query: EvidenceExportQuery,
    require_proofs: bool,
    federation_policy: Option<FederationPolicyDocument>,
) -> Result<PreparedEvidenceExport, CliError> {
    if let Some(policy) = &federation_policy {
        verify_federation_policy(policy)?;
    }
    let query = if let Some(policy) = &federation_policy {
        merge_export_query(&policy.body.query, &query)?
    } else {
        query
    };
    query
        .validate_read_boundary()
        .map_err(|error| CliError::attest_error(error.to_string()))?;
    let require_proofs = require_proofs
        || federation_policy
            .as_ref()
            .is_some_and(|policy| policy.body.require_proofs);
    Ok(PreparedEvidenceExport {
        query,
        require_proofs,
        federation_policy,
    })
}

pub(crate) fn validate_evidence_bundle_requirements(
    bundle: &EvidenceExportBundle,
    require_proofs: bool,
) -> Result<(), CliError> {
    if require_proofs && !bundle.uncheckpointed_receipts.is_empty() {
        return Err(render_missing_proofs_error(&bundle.uncheckpointed_receipts));
    }
    Ok(())
}

fn safe_relative_path(relative_path: &str) -> Result<PathBuf, CliError> {
    let path = Path::new(relative_path);
    if path.is_absolute() {
        return Err(CliError::attest_error(format!(
            "evidence package manifest path must be relative: {relative_path}"
        )));
    }
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(CliError::attest_error(format!(
                    "evidence package manifest path escapes the package root: {relative_path}"
                )));
            }
        }
    }
    Ok(path.to_path_buf())
}

fn write_evidence_package(
    output: &Path,
    bundle: EvidenceExportBundle,
    transparency: Option<CheckpointTransparencySummary>,
    policy_file: Option<&Path>,
    federation_policy: Option<&FederationPolicyDocument>,
) -> Result<(), CliError> {
    ensure_clean_output_dir(output)?;
    let transparency = match transparency {
        Some(summary) => {
            verify_checkpoint_transparency_records(
                &bundle.checkpoints,
                &summary.publications,
                &summary.witnesses,
                &summary.consistency_proofs,
                &summary.equivocations,
            )?;
            summary
        }
        None => validate_checkpoint_transparency_summary(&bundle.checkpoints)?,
    };
    let claim_boundary = build_evidence_transparency_claims(&bundle, &transparency, None);
    let disclosure_notice = maybe_build_disclosure_notice(&bundle.query);

    let mut file_hashes = Vec::new();
    write_json_file(output, "query.json", &bundle.query, &mut file_hashes)?;
    write_ndjson_file(
        output,
        "receipts.ndjson",
        &bundle.tool_receipts,
        &mut file_hashes,
    )?;
    write_ndjson_file(
        output,
        "child-receipts.ndjson",
        &bundle.child_receipts,
        &mut file_hashes,
    )?;
    write_ndjson_file(
        output,
        "checkpoints.ndjson",
        &bundle.checkpoints,
        &mut file_hashes,
    )?;
    write_ndjson_file(
        output,
        "checkpoint-publications.ndjson",
        &transparency.publications,
        &mut file_hashes,
    )?;
    write_ndjson_file(
        output,
        "checkpoint-witnesses.ndjson",
        &transparency.witnesses,
        &mut file_hashes,
    )?;
    write_ndjson_file(
        output,
        "checkpoint-consistency-proofs.ndjson",
        &transparency.consistency_proofs,
        &mut file_hashes,
    )?;
    write_ndjson_file(
        output,
        "checkpoint-equivocations.ndjson",
        &transparency.equivocations,
        &mut file_hashes,
    )?;
    write_ndjson_file(
        output,
        "capability-lineage.ndjson",
        &bundle.capability_lineage,
        &mut file_hashes,
    )?;
    write_ndjson_file(
        output,
        "inclusion-proofs.ndjson",
        &bundle.inclusion_proofs,
        &mut file_hashes,
    )?;
    write_json_file(
        output,
        "retention.json",
        &bundle.retention,
        &mut file_hashes,
    )?;
    write_bytes_file(
        output,
        "README.txt",
        render_readme(
            &bundle,
            &transparency,
            &claim_boundary,
            disclosure_notice.as_ref(),
        )
        .as_bytes(),
        &mut file_hashes,
    )?;

    let policy = if let Some(policy_file) = policy_file {
        let source_bytes = fs::read(policy_file)?;
        let source_path = policy_source_relative_path(policy_file);
        write_bytes_file(output, &source_path, &source_bytes, &mut file_hashes)?;
        let metadata = policy_metadata(policy_file, &source_path, source_bytes.len() as u64)?;
        write_json_file(output, "policy/metadata.json", &metadata, &mut file_hashes)?;
        Some(metadata)
    } else {
        None
    };

    let federation_policy = if let Some(policy) = federation_policy {
        write_json_file(
            output,
            federation_policy_relative_path(),
            policy,
            &mut file_hashes,
        )?;
        Some(federation_policy_metadata(policy))
    } else {
        None
    };

    let counts = EvidenceExportCounts {
        tool_receipts: bundle.tool_receipts.len() as u64,
        child_receipts: bundle.child_receipts.len() as u64,
        checkpoints: bundle.checkpoints.len() as u64,
        capability_lineage: bundle.capability_lineage.len() as u64,
        inclusion_proofs: bundle.inclusion_proofs.len() as u64,
        uncheckpointed_receipts: bundle.uncheckpointed_receipts.len() as u64,
    };
    let proof_coverage = EvidenceProofCoverage {
        checkpointed_receipts: counts
            .tool_receipts
            .saturating_sub(counts.uncheckpointed_receipts),
        uncheckpointed_receipts: counts.uncheckpointed_receipts,
    };
    let receipt_semantics = evidence_receipt_semantic_summary(&bundle.tool_receipts);
    let manifest = EvidenceExportManifest {
        schema: EVIDENCE_EXPORT_MANIFEST_SCHEMA.to_string(),
        exported_at: unix_now(),
        query: bundle.query,
        counts,
        proof_coverage,
        receipt_semantics,
        child_receipt_scope: bundle.child_receipt_scope,
        claim_boundary: Some(claim_boundary),
        files: file_hashes,
        policy,
        federation_policy,
        disclosure_notice,
    };
    let manifest_path = output.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    Ok(())
}

pub struct EvidenceFederationPolicyCreateArgs<'a> {
    pub output: &'a Path,
    pub signing_seed_file: &'a Path,
    pub issuer: &'a str,
    pub partner: &'a str,
    pub capability_id: Option<&'a str>,
    pub agent_subject: Option<&'a str>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub tenant: Option<&'a str>,
    pub admin_all: bool,
    pub expires_at: u64,
    pub require_proofs: bool,
    pub purpose: Option<&'a str>,
    pub json_output: bool,
}

pub fn cmd_evidence_federation_policy_create(
    args: EvidenceFederationPolicyCreateArgs<'_>,
) -> Result<(), CliError> {
    let keypair = load_or_create_authority_keypair(args.signing_seed_file)?;
    let created_at = unix_now();
    if created_at > args.expires_at {
        return Err(CliError::attest_error(
            "--expires-at must be greater than or equal to the current Unix timestamp".to_string(),
        ));
    }
    if let (Some(since), Some(until)) = (args.since, args.until) {
        if since > until {
            return Err(CliError::attest_error(
                "federation policy since must be less than or equal to until".to_string(),
            ));
        }
    }
    if args.admin_all && args.tenant.is_some() {
        return Err(CliError::attest_error(
            "use either --tenant or --admin-all for a federation policy, not both".to_string(),
        ));
    }
    let read_boundary = if args.admin_all {
        Some(ReceiptReadBoundary::AdminAll)
    } else if let Some(tenant) = args.tenant {
        Some(ReceiptReadBoundary::tenant_scoped(tenant))
    } else {
        return Err(CliError::attest_error(
            "federation policy requires either --tenant or --admin-all".to_string(),
        ));
    };

    let body = FederationPolicyBody {
        schema: FEDERATION_POLICY_SCHEMA.to_string(),
        issuer: args.issuer.to_string(),
        partner: args.partner.to_string(),
        signer_public_key: keypair.public_key(),
        created_at,
        expires_at: args.expires_at,
        query: EvidenceExportQuery {
            capability_id: args.capability_id.map(ToOwned::to_owned),
            agent_subject: args.agent_subject.map(ToOwned::to_owned),
            since: args.since,
            until: args.until,
            tenant: args.tenant.map(ToOwned::to_owned),
            read_boundary,
        },
        require_proofs: args.require_proofs,
        purpose: args.purpose.map(ToOwned::to_owned),
    };
    let (signature, _) = keypair.sign_canonical(&body)?;
    let policy = FederationPolicyDocument { body, signature };
    verify_federation_policy(&policy)?;
    fs::write(args.output, serde_json::to_vec_pretty(&policy)?)?;

    if args.json_output {
        println!("{}", serde_json::to_string_pretty(&policy)?);
    } else {
        println!("federation policy created");
        println!("output:              {}", args.output.display());
        println!("issuer:              {}", policy.body.issuer);
        println!("partner:             {}", policy.body.partner);
        println!(
            "signer_public_key:   {}",
            policy.body.signer_public_key.to_hex()
        );
        println!("require_proofs:      {}", policy.body.require_proofs);
    }

    Ok(())
}

pub fn cmd_evidence_export(
    output: &Path,
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    tenant: Option<&str>,
    admin_all: bool,
    policy_file: Option<&Path>,
    federation_policy_file: Option<&Path>,
    require_proofs: bool,
    receipt_db: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    if admin_all && tenant.is_some() {
        return Err(CliError::attest_error(
            "use either --tenant or --admin-all for evidence export, not both".to_string(),
        ));
    }
    let read_boundary = if admin_all {
        Some(ReceiptReadBoundary::AdminAll)
    } else {
        tenant.map(ReceiptReadBoundary::tenant_scoped)
    };
    let prepared = prepare_evidence_export(
        EvidenceExportQuery {
            capability_id: capability_id.map(ToOwned::to_owned),
            agent_subject: agent_subject.map(ToOwned::to_owned),
            since,
            until,
            tenant: tenant.map(ToOwned::to_owned),
            read_boundary,
        },
        require_proofs,
        federation_policy_file
            .map(read_federation_policy)
            .transpose()?,
    )?;

    let response = match (receipt_db, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::attest_error(
                "use either --receipt-db or --control-url for evidence export, not both"
                    .to_string(),
            ));
        }
        (Some(receipt_db), None) => {
            let store = SqliteReceiptStore::open(receipt_db)?;
            let (bundle, transparency) =
                store.build_evidence_export_bundle_with_transparency(&prepared.query)?;
            validate_evidence_bundle_requirements(&bundle, prepared.require_proofs)?;
            RemoteEvidenceExportResponse {
                bundle,
                transparency: Some(transparency),
                federation_policy: prepared.federation_policy,
            }
        }
        (None, Some(control_url)) => {
            let token = super::require_control_token(control_token)?;
            let client =
                crate::trust_control::service_runtime::client::build_client(control_url, token)?;
            client.export_evidence(&RemoteEvidenceExportRequest {
                query: prepared.query,
                require_proofs: prepared.require_proofs,
                federation_policy: prepared.federation_policy,
            })?
        }
        (None, None) => {
            return Err(CliError::attest_error(
                "evidence export requires either --receipt-db <path> or --control-url <url>"
                    .to_string(),
            ));
        }
    };

    write_evidence_package(
        output,
        response.bundle,
        response.transparency,
        policy_file,
        response.federation_policy.as_ref(),
    )
}

pub fn cmd_evidence_import(
    input: &Path,
    receipt_db: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    json_output: bool,
) -> Result<(), CliError> {
    let package = load_verified_evidence_package(input)?;
    let share_import = build_federated_share_import(&package)?;

    let share = match (receipt_db, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::attest_error(
                "use either --receipt-db or --control-url for evidence import, not both"
                    .to_string(),
            ));
        }
        (Some(receipt_db), None) => {
            let mut store = SqliteReceiptStore::open(receipt_db)?;
            store.import_federated_evidence_share(&share_import)?
        }
        (None, Some(control_url)) => {
            let token = super::require_control_token(control_token)?;
            let client =
                crate::trust_control::service_runtime::client::build_client(control_url, token)?;
            client
                .import_evidence(&RemoteEvidenceImportRequest { package })?
                .share
        }
        (None, None) => {
            return Err(CliError::attest_error(
                "evidence import requires either --receipt-db <path> or --control-url <url>"
                    .to_string(),
            ));
        }
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&share)?);
    } else {
        println!("federated evidence share imported");
        println!("share_id:            {}", share.share_id);
        println!("issuer:              {}", share.issuer);
        println!("partner:             {}", share.partner);
        println!("signer_public_key:   {}", share.signer_public_key);
        println!("tool_receipts:       {}", share.tool_receipts);
        println!("capability_lineage:  {}", share.capability_lineage);
    }

    Ok(())
}

pub fn cmd_evidence_verify(input: &Path, json_output: bool) -> Result<(), CliError> {
    let package = load_verified_evidence_package(input)?;
    let manifest = package.manifest;
    let transparency = match package.transparency.as_ref() {
        Some(summary) => chio_kernel::checkpoint::verify_checkpoint_transparency_records(
            &package.bundle.checkpoints,
            summary,
        )
        .map_err(|error| {
            CliError::attest_error(format!(
                "checkpoint transparency verification failed: {error}"
            ))
        })?,
        None => validate_checkpoint_transparency_summary(&package.bundle.checkpoints)?,
    };
    let claim_boundary = build_evidence_transparency_claims(&package.bundle, &transparency, None);

    let result = EvidenceVerificationResult {
        schema: manifest.schema,
        verified_at: unix_now(),
        tool_receipts: manifest.counts.tool_receipts,
        child_receipts: manifest.counts.child_receipts,
        checkpoints: manifest.counts.checkpoints,
        checkpoint_publications: transparency.publications.len() as u64,
        checkpoint_witnesses: transparency.witnesses.len() as u64,
        checkpoint_consistency_proofs: transparency.consistency_proofs.len() as u64,
        checkpoint_equivocations: transparency.equivocations.len() as u64,
        capability_lineage: manifest.counts.capability_lineage,
        inclusion_proofs: manifest.counts.inclusion_proofs,
        uncheckpointed_receipts: manifest.counts.uncheckpointed_receipts,
        receipt_semantics: manifest.receipt_semantics,
        verified_files: manifest.files.len() as u64,
        child_receipt_scope: manifest.child_receipt_scope,
        claim_boundary,
        disclosure_notice: manifest.disclosure_notice,
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("evidence package verified");
        println!("tool_receipts:          {}", result.tool_receipts);
        println!("child_receipts:         {}", result.child_receipts);
        println!("checkpoints:            {}", result.checkpoints);
        println!(
            "checkpoint_publications: {}",
            result.checkpoint_publications
        );
        println!("checkpoint_witnesses:   {}", result.checkpoint_witnesses);
        println!(
            "checkpoint_consistency_proofs: {}",
            result.checkpoint_consistency_proofs
        );
        println!(
            "checkpoint_equivocations: {}",
            result.checkpoint_equivocations
        );
        println!("capability_lineage:     {}", result.capability_lineage);
        println!("inclusion_proofs:       {}", result.inclusion_proofs);
        println!(
            "uncheckpointed_receipts: {}",
            result.uncheckpointed_receipts
        );
        println!(
            "authorized_receipts:     {}",
            result.receipt_semantics.authorized
        );
        println!(
            "trace_observations:      {}",
            result.receipt_semantics.trace_observations
        );
        println!(
            "advisory_evaluations:    {}",
            result.receipt_semantics.advisory_evaluations
        );
        println!("verified_files:         {}", result.verified_files);
        println!("child_receipt_scope:    {:?}", result.child_receipt_scope);
        println!(
            "transparency_preview_logs: {}",
            result.claim_boundary.transparency_preview.len()
        );
        println!(
            "publication_state:      {}",
            result.claim_boundary.publication_state.as_str()
        );
        if let Some(trust_anchor) = result.claim_boundary.trust_anchor.as_deref() {
            println!("trust_anchor:          {}", trust_anchor);
        }
        if let Some(notice) = result.disclosure_notice.as_ref() {
            println!(
                "disclosure_notice:      tenant-scoped export discloses {} signed-checkpoint and {} derived-publication aggregate fields (see README.txt and {})",
                notice.disclosed_checkpoint_body_fields.len(),
                notice.disclosed_publication_fields.len(),
                notice.protocol_reference,
            );
        }
    }

    Ok(())
}

#[cfg(test)]
#[path = "evidence_export/tests.rs"]
mod tests;
