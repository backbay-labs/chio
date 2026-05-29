use std::cmp::{max, min};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use chio_core::receipt::{BoundaryClass, ChioReceipt, ReceiptKind};
use chio_core::{canonical_json_bytes, chio_receipt_id, sha256_hex, PublicKey, Signature};
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
        .map(|line| serde_json::from_str(line).map_err(CliError::from))
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

fn verify_manifest_file_hashes(
    input_dir: &Path,
    manifest: &EvidenceExportManifest,
) -> Result<(), CliError> {
    let mut seen = BTreeSet::new();
    for file in &manifest.files {
        if !seen.insert(file.path.as_str()) {
            return Err(CliError::attest_error(format!(
                "duplicate file entry in evidence manifest: {}",
                file.path
            )));
        }
        let relative = safe_relative_path(&file.path)?;
        let bytes = fs::read(input_dir.join(relative))?;
        let actual_hash = sha256_hex(&bytes);
        let actual_bytes = bytes.len() as u64;
        if actual_hash != file.sha256 {
            return Err(CliError::attest_error(format!(
                "evidence package file hash mismatch for {}",
                file.path
            )));
        }
        if actual_bytes != file.bytes {
            return Err(CliError::attest_error(format!(
                "evidence package byte length mismatch for {}",
                file.path
            )));
        }
    }
    Ok(())
}

fn verify_query_scope(
    query: &EvidenceExportQuery,
    tool_receipts: &[EvidenceToolReceiptRecord],
    child_receipts: &[EvidenceChildReceiptRecord],
    child_receipt_scope: EvidenceChildReceiptScope,
    lineage_by_capability: &BTreeMap<String, &CapabilitySnapshot>,
) -> Result<(), CliError> {
    let expected_child_scope = query.child_receipt_scope();
    if child_receipt_scope != expected_child_scope {
        return Err(CliError::attest_error(format!(
            "child receipt scope mismatch: manifest says {:?}, query implies {:?}",
            child_receipt_scope, expected_child_scope
        )));
    }
    if matches!(
        child_receipt_scope,
        EvidenceChildReceiptScope::OmittedNoJoinPath
    ) && !child_receipts.is_empty()
    {
        return Err(CliError::attest_error(
            "child receipts were exported despite an omitted child-receipt scope".to_string(),
        ));
    }

    let tenant_scope = match &query.read_boundary {
        Some(ReceiptReadBoundary::TenantScoped { tenant }) => Some(tenant.as_str()),
        Some(ReceiptReadBoundary::AdminAll) | None => query
            .tenant
            .as_deref()
            .map(str::trim)
            .filter(|tenant| !tenant.is_empty()),
    };

    for record in tool_receipts {
        if let Some(tenant) = tenant_scope {
            if record.receipt.tenant_id.as_deref() != Some(tenant) {
                return Err(CliError::attest_error(format!(
                    "tool receipt {} is outside tenant scope {}",
                    record.receipt.id, tenant
                )));
            }
        }
        if let Some(capability_id) = &query.capability_id {
            if &record.receipt.capability_id != capability_id {
                return Err(CliError::attest_error(format!(
                    "tool receipt {} is outside capability filter {}",
                    record.receipt.id, capability_id
                )));
            }
        }
        if let Some(since) = query.since {
            if record.receipt.timestamp < since {
                return Err(CliError::attest_error(format!(
                    "tool receipt {} predates query lower bound {}",
                    record.receipt.id, since
                )));
            }
        }
        if let Some(until) = query.until {
            if record.receipt.timestamp > until {
                return Err(CliError::attest_error(format!(
                    "tool receipt {} exceeds query upper bound {}",
                    record.receipt.id, until
                )));
            }
        }
        if let Some(agent_subject) = &query.agent_subject {
            let snapshot = lineage_by_capability
                .get(record.receipt.capability_id.as_str())
                .ok_or_else(|| {
                    CliError::attest_error(format!(
                        "missing capability lineage for receipt capability {}",
                        record.receipt.capability_id
                    ))
                })?;
            if &snapshot.subject_key != agent_subject {
                return Err(CliError::attest_error(format!(
                    "tool receipt {} lineage subject {} does not match agent filter {}",
                    record.receipt.id, snapshot.subject_key, agent_subject
                )));
            }
        }
    }

    for record in child_receipts {
        if let Some(since) = query.since {
            if record.receipt.timestamp < since {
                return Err(CliError::attest_error(format!(
                    "child receipt {} predates query lower bound {}",
                    record.receipt.id, since
                )));
            }
        }
        if let Some(until) = query.until {
            if record.receipt.timestamp > until {
                return Err(CliError::attest_error(format!(
                    "child receipt {} exceeds query upper bound {}",
                    record.receipt.id, until
                )));
            }
        }
    }

    Ok(())
}

fn verify_tool_receipts(
    tool_receipts: &[EvidenceToolReceiptRecord],
) -> Result<BTreeMap<u64, &ChioReceipt>, CliError> {
    let mut by_seq = BTreeMap::new();
    for record in tool_receipts {
        if by_seq.insert(record.seq, &record.receipt).is_some() {
            return Err(CliError::attest_error(format!(
                "duplicate tool receipt seq in evidence package: {}",
                record.seq
            )));
        }
        if !record.receipt.verify_signature()? {
            return Err(CliError::attest_error(format!(
                "tool receipt signature verification failed: {}",
                record.receipt.id
            )));
        }
        if !record.receipt.action.verify_hash()? {
            return Err(CliError::attest_error(format!(
                "tool receipt action hash verification failed: {}",
                record.receipt.id
            )));
        }
    }
    Ok(by_seq)
}

fn verify_child_receipts(child_receipts: &[EvidenceChildReceiptRecord]) -> Result<(), CliError> {
    let mut seen = BTreeSet::new();
    for record in child_receipts {
        if !seen.insert(record.seq) {
            return Err(CliError::attest_error(format!(
                "duplicate child receipt seq in evidence package: {}",
                record.seq
            )));
        }
        if !record.receipt.verify_signature()? {
            return Err(CliError::attest_error(format!(
                "child receipt signature verification failed: {}",
                record.receipt.id
            )));
        }
    }
    Ok(())
}

fn verify_checkpoints(
    checkpoints: &[KernelCheckpoint],
) -> Result<BTreeMap<u64, &KernelCheckpoint>, CliError> {
    let mut by_seq = BTreeMap::<u64, &KernelCheckpoint>::new();
    for checkpoint in checkpoints {
        if !is_supported_checkpoint_schema(&checkpoint.body.schema) {
            return Err(CliError::attest_error(format!(
                "unsupported checkpoint schema in evidence package: {}",
                checkpoint.body.schema
            )));
        }
        if !verify_checkpoint_signature(checkpoint)? {
            return Err(CliError::attest_error(format!(
                "checkpoint signature verification failed: {}",
                checkpoint.body.checkpoint_seq
            )));
        }
        if let Some(existing) = by_seq.get(&checkpoint.body.checkpoint_seq) {
            let existing_sha256 = checkpoint_body_sha256(&existing.body).map_err(|error| {
                CliError::attest_error(format!("checkpoint digest computation failed: {error}"))
            })?;
            let checkpoint_sha256 = checkpoint_body_sha256(&checkpoint.body).map_err(|error| {
                CliError::attest_error(format!("checkpoint digest computation failed: {error}"))
            })?;
            if existing_sha256 != checkpoint_sha256 {
                return Err(CliError::attest_error(format!(
                    "checkpoint transparency equivocation detected: checkpoint_seq {} has conflicting digests {} and {}",
                    checkpoint.body.checkpoint_seq, existing_sha256, checkpoint_sha256
                )));
            }
            return Err(CliError::attest_error(format!(
                "duplicate checkpoint_seq in evidence package: {}",
                checkpoint.body.checkpoint_seq
            )));
        }
        by_seq.insert(checkpoint.body.checkpoint_seq, checkpoint);
    }
    Ok(by_seq)
}

fn verify_lineage(
    capability_lineage: &[CapabilitySnapshot],
) -> Result<BTreeMap<String, &CapabilitySnapshot>, CliError> {
    let mut by_capability = BTreeMap::new();
    for snapshot in capability_lineage {
        if by_capability
            .insert(snapshot.capability_id.clone(), snapshot)
            .is_some()
        {
            return Err(CliError::attest_error(format!(
                "duplicate capability lineage snapshot in evidence package: {}",
                snapshot.capability_id
            )));
        }
    }
    Ok(by_capability)
}

fn validate_checkpoint_transparency_summary(
    checkpoints: &[KernelCheckpoint],
) -> Result<CheckpointTransparencySummary, CliError> {
    validate_checkpoint_transparency(checkpoints).map_err(|error| {
        CliError::attest_error(format!(
            "checkpoint transparency verification failed: {error}"
        ))
    })
}

fn verify_checkpoint_transparency_records(
    checkpoints: &[KernelCheckpoint],
    publications: &[CheckpointPublication],
    witnesses: &[CheckpointWitness],
    consistency_proofs: &[CheckpointConsistencyProof],
    equivocations: &[CheckpointEquivocation],
) -> Result<CheckpointTransparencySummary, CliError> {
    chio_kernel::checkpoint::verify_checkpoint_transparency_records(
        checkpoints,
        &CheckpointTransparencySummary {
            publications: publications.to_vec(),
            witnesses: witnesses.to_vec(),
            consistency_proofs: consistency_proofs.to_vec(),
            equivocations: equivocations.to_vec(),
        },
    )
    .map_err(|error| {
        CliError::attest_error(format!(
            "checkpoint transparency verification failed: {error}"
        ))
    })
}

fn verify_transparency_claim_boundary(
    expected: Option<&EvidenceTransparencyClaims>,
    bundle: &EvidenceExportBundle,
    transparency: &CheckpointTransparencySummary,
) -> Result<(), CliError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    expected.validate().map_err(CliError::attest_error)?;
    let actual =
        build_evidence_transparency_claims(bundle, transparency, expected.trust_anchor.as_deref());
    if expected != &actual {
        return Err(CliError::attest_error(
            "evidence package transparency claim boundary does not match the exported data"
                .to_string(),
        ));
    }
    Ok(())
}

fn verify_inclusion_proofs(
    tool_receipts_by_seq: &BTreeMap<u64, &ChioReceipt>,
    checkpoints_by_seq: &BTreeMap<u64, &KernelCheckpoint>,
    inclusion_proofs: &[ReceiptInclusionProof],
    expected_uncheckpointed_receipts: u64,
) -> Result<(), CliError> {
    let mut proved_receipt_seqs = BTreeSet::new();
    for proof in inclusion_proofs {
        let checkpoint = checkpoints_by_seq
            .get(&proof.checkpoint_seq)
            .ok_or_else(|| {
                CliError::attest_error(format!(
                    "inclusion proof references missing checkpoint {}",
                    proof.checkpoint_seq
                ))
            })?;
        let receipt = tool_receipts_by_seq
            .get(&proof.receipt_seq)
            .ok_or_else(|| {
                CliError::attest_error(format!(
                    "inclusion proof references missing receipt seq {}",
                    proof.receipt_seq
                ))
            })?;
        if proof.merkle_root != checkpoint.body.merkle_root {
            return Err(CliError::attest_error(format!(
                "inclusion proof root mismatch for receipt seq {}",
                proof.receipt_seq
            )));
        }
        if proof.leaf_index >= checkpoint.body.tree_size {
            return Err(CliError::attest_error(format!(
                "inclusion proof leaf index {} exceeds checkpoint tree size {}",
                proof.leaf_index, checkpoint.body.tree_size
            )));
        }
        if proof.receipt_seq < checkpoint.body.batch_start_seq
            || proof.receipt_seq > checkpoint.body.batch_end_seq
        {
            return Err(CliError::attest_error(format!(
                "inclusion proof receipt seq {} falls outside checkpoint batch {}-{}",
                proof.receipt_seq, checkpoint.body.batch_start_seq, checkpoint.body.batch_end_seq
            )));
        }
        if !proved_receipt_seqs.insert(proof.receipt_seq) {
            return Err(CliError::attest_error(format!(
                "duplicate inclusion proof for receipt seq {}",
                proof.receipt_seq
            )));
        }
        let canonical = canonical_json_bytes(*receipt)?;
        if !proof.verify(&canonical, &checkpoint.body.merkle_root) {
            return Err(CliError::attest_error(format!(
                "inclusion proof verification failed for receipt seq {}",
                proof.receipt_seq
            )));
        }
    }

    let derived_uncheckpointed = tool_receipts_by_seq
        .len()
        .saturating_sub(proved_receipt_seqs.len()) as u64;
    if derived_uncheckpointed != expected_uncheckpointed_receipts {
        return Err(CliError::attest_error(format!(
            "uncheckpointed receipt count mismatch: manifest says {}, derived {}",
            expected_uncheckpointed_receipts, derived_uncheckpointed
        )));
    }

    Ok(())
}

fn evidence_receipt_semantic_summary(
    tool_receipts: &[EvidenceToolReceiptRecord],
) -> EvidenceReceiptSemanticSummary {
    let mut summary = EvidenceReceiptSemanticSummary::default();
    for record in tool_receipts {
        let semantics = record.receipt.semantic_fields();
        match semantics.receipt_kind {
            ReceiptKind::MediatedDecision => summary.mediated_decisions += 1,
            ReceiptKind::TraceObservation => summary.trace_observations += 1,
            ReceiptKind::AdvisoryEvaluation => summary.advisory_evaluations += 1,
        }
        match semantics.boundary_class {
            BoundaryClass::Prevent => summary.prevent += 1,
            BoundaryClass::DetectOnly => summary.detect_only += 1,
            BoundaryClass::AdvisoryOnly => summary.advisory_only += 1,
            BoundaryClass::CannotSee => summary.cannot_see += 1,
        }
        if chio_receipt_id(&record.receipt.body())
            .map(|id| id == record.receipt.id)
            .unwrap_or(false)
            && record.receipt.is_allowed()
            && record.receipt.verify_signature().unwrap_or(false)
            && record.receipt.action.verify_hash().unwrap_or(false)
        {
            summary.authorized += 1;
        }
    }
    summary
}

fn verify_manifest_counts(
    manifest: &EvidenceExportManifest,
    tool_receipts: &[EvidenceToolReceiptRecord],
    child_receipts: &[EvidenceChildReceiptRecord],
    checkpoints: &[KernelCheckpoint],
    capability_lineage: &[CapabilitySnapshot],
    inclusion_proofs: &[ReceiptInclusionProof],
) -> Result<(), CliError> {
    let counts = &manifest.counts;
    if counts.tool_receipts != tool_receipts.len() as u64
        || counts.child_receipts != child_receipts.len() as u64
        || counts.checkpoints != checkpoints.len() as u64
        || counts.capability_lineage != capability_lineage.len() as u64
        || counts.inclusion_proofs != inclusion_proofs.len() as u64
    {
        return Err(CliError::attest_error(
            "evidence package manifest counts do not match exported data".to_string(),
        ));
    }
    let checkpointed_receipts = counts
        .tool_receipts
        .saturating_sub(counts.uncheckpointed_receipts);
    if manifest.proof_coverage.checkpointed_receipts != checkpointed_receipts
        || manifest.proof_coverage.uncheckpointed_receipts != counts.uncheckpointed_receipts
    {
        return Err(CliError::attest_error(
            "evidence package proof coverage summary does not match receipt counts".to_string(),
        ));
    }
    let derived_semantics = evidence_receipt_semantic_summary(tool_receipts);
    if manifest.receipt_semantics != derived_semantics {
        return Err(CliError::attest_error(
            "evidence package receipt semantic summary does not match exported data".to_string(),
        ));
    }
    Ok(())
}

fn verify_policy_attachment(
    input_dir: &Path,
    manifest: &EvidenceExportManifest,
) -> Result<(), CliError> {
    let Some(expected_policy) = &manifest.policy else {
        return Ok(());
    };
    let metadata: PolicyAttachmentMetadata = read_json_file(input_dir, "policy/metadata.json")?;
    if &metadata != expected_policy {
        return Err(CliError::attest_error(
            "policy metadata file does not match evidence manifest".to_string(),
        ));
    }
    let relative = safe_relative_path(&expected_policy.source_path)?;
    if !input_dir.join(relative).exists() {
        return Err(CliError::attest_error(format!(
            "policy source file referenced by manifest is missing: {}",
            expected_policy.source_path
        )));
    }
    Ok(())
}

fn verify_disclosure_notice(manifest: &EvidenceExportManifest) -> Result<(), CliError> {
    let expected_notice = maybe_build_disclosure_notice(&manifest.query);
    match (&manifest.disclosure_notice, expected_notice) {
        (Some(actual), Some(expected)) => {
            if actual != &expected {
                return Err(CliError::attest_error(
                    "evidence package disclosure notice does not match the canonical \
                     tenant-scoped disclosure boundary"
                        .to_string(),
                ));
            }
            Ok(())
        }
        (None, Some(_)) => Err(CliError::attest_error(
            "tenant-scoped evidence package is missing the required cross-tenant \
             disclosure notice"
                .to_string(),
        )),
        (Some(_), None) => Err(CliError::attest_error(
            "admin-all evidence package must not carry a tenant-scoped disclosure notice"
                .to_string(),
        )),
        (None, None) => Ok(()),
    }
}

fn verify_federation_policy_attachment(
    input_dir: &Path,
    manifest: &EvidenceExportManifest,
) -> Result<(), CliError> {
    let Some(expected_policy) = &manifest.federation_policy else {
        return Ok(());
    };
    let policy = read_federation_policy(&input_dir.join(federation_policy_relative_path()))?;
    let actual_metadata = federation_policy_metadata(&policy);
    if &actual_metadata != expected_policy {
        return Err(CliError::attest_error(
            "federation policy metadata does not match evidence manifest".to_string(),
        ));
    }
    if manifest.exported_at < policy.body.created_at
        || manifest.exported_at > policy.body.expires_at
    {
        return Err(CliError::attest_error(
            "evidence package export timestamp falls outside the federation policy validity window"
                .to_string(),
        ));
    }
    ensure_query_within_federation_policy(&policy.body.query, &manifest.query)?;
    if policy.body.require_proofs && manifest.counts.uncheckpointed_receipts != 0 {
        return Err(CliError::attest_error(
            "federation policy requires full checkpoint coverage, but the evidence package contains uncheckpointed receipts".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_import_package_data(
    package: &EvidenceImportPackage,
) -> Result<(), CliError> {
    if !is_supported_evidence_export_manifest_schema(&package.manifest.schema) {
        return Err(CliError::attest_error(format!(
            "unsupported evidence manifest schema: expected {}, got {}",
            EVIDENCE_EXPORT_MANIFEST_SCHEMA, package.manifest.schema
        )));
    }
    if package.bundle.query != package.manifest.query {
        return Err(CliError::attest_error(
            "evidence import package query does not match the embedded manifest".to_string(),
        ));
    }
    package
        .bundle
        .query
        .validate_read_boundary()
        .map_err(|error| CliError::attest_error(error.to_string()))?;
    verify_manifest_counts(
        &package.manifest,
        &package.bundle.tool_receipts,
        &package.bundle.child_receipts,
        &package.bundle.checkpoints,
        &package.bundle.capability_lineage,
        &package.bundle.inclusion_proofs,
    )?;
    verify_disclosure_notice(&package.manifest)?;
    let actual_federation_metadata = package
        .federation_policy
        .as_ref()
        .map(federation_policy_metadata);
    if actual_federation_metadata != package.manifest.federation_policy {
        return Err(CliError::attest_error(
            "evidence import federation policy metadata does not match the embedded manifest"
                .to_string(),
        ));
    }
    if let Some(policy) = package.federation_policy.as_ref() {
        verify_federation_policy(policy)?;
        if package.manifest.exported_at < policy.body.created_at
            || package.manifest.exported_at > policy.body.expires_at
        {
            return Err(CliError::attest_error(
                "evidence import package export timestamp falls outside the federation policy validity window"
                    .to_string(),
            ));
        }
        ensure_query_within_federation_policy(&policy.body.query, &package.manifest.query)?;
        if policy.body.require_proofs && package.manifest.counts.uncheckpointed_receipts != 0 {
            return Err(CliError::attest_error(
                "federation policy requires full checkpoint coverage, but the evidence import package contains uncheckpointed receipts".to_string(),
            ));
        }
    }

    let lineage_by_capability = verify_lineage(&package.bundle.capability_lineage)?;
    let tool_receipts_by_seq = verify_tool_receipts(&package.bundle.tool_receipts)?;
    verify_child_receipts(&package.bundle.child_receipts)?;
    let checkpoints_by_seq = verify_checkpoints(&package.bundle.checkpoints)?;
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
    verify_transparency_claim_boundary(
        package.manifest.claim_boundary.as_ref(),
        &package.bundle,
        &transparency,
    )?;
    verify_inclusion_proofs(
        &tool_receipts_by_seq,
        &checkpoints_by_seq,
        &package.bundle.inclusion_proofs,
        package.manifest.counts.uncheckpointed_receipts,
    )?;
    verify_query_scope(
        &package.bundle.query,
        &package.bundle.tool_receipts,
        &package.bundle.child_receipts,
        package.bundle.child_receipt_scope,
        &lineage_by_capability,
    )?;
    Ok(())
}

fn load_verified_evidence_package(input: &Path) -> Result<EvidenceImportPackage, CliError> {
    ensure_existing_dir(input, "evidence package")?;

    let manifest: EvidenceExportManifest = read_json_file(input, "manifest.json")?;
    if !is_supported_evidence_export_manifest_schema(&manifest.schema) {
        return Err(CliError::attest_error(format!(
            "unsupported evidence manifest schema: expected {}, got {}",
            EVIDENCE_EXPORT_MANIFEST_SCHEMA, manifest.schema
        )));
    }

    verify_manifest_file_hashes(input, &manifest)?;
    let query: EvidenceExportQuery = read_json_file(input, "query.json")?;
    if query != manifest.query {
        return Err(CliError::attest_error(
            "query.json does not match the evidence manifest query".to_string(),
        ));
    }

    let tool_receipts: Vec<EvidenceToolReceiptRecord> = read_ndjson_file(input, "receipts.ndjson")?;
    let child_receipts: Vec<EvidenceChildReceiptRecord> =
        read_ndjson_file(input, "child-receipts.ndjson")?;
    let checkpoints: Vec<KernelCheckpoint> = read_ndjson_file(input, "checkpoints.ndjson")?;
    let checkpoint_publications: Vec<CheckpointPublication> =
        read_optional_ndjson_file(input, "checkpoint-publications.ndjson")?;
    let checkpoint_witnesses: Vec<CheckpointWitness> =
        read_optional_ndjson_file(input, "checkpoint-witnesses.ndjson")?;
    let checkpoint_consistency_proofs: Vec<CheckpointConsistencyProof> =
        read_optional_ndjson_file(input, "checkpoint-consistency-proofs.ndjson")?;
    let checkpoint_equivocations: Vec<CheckpointEquivocation> =
        read_optional_ndjson_file(input, "checkpoint-equivocations.ndjson")?;
    let capability_lineage: Vec<CapabilitySnapshot> =
        read_ndjson_file(input, "capability-lineage.ndjson")?;
    let inclusion_proofs: Vec<ReceiptInclusionProof> =
        read_ndjson_file(input, "inclusion-proofs.ndjson")?;
    let retention: EvidenceRetentionMetadata = read_json_file(input, "retention.json")?;

    verify_manifest_counts(
        &manifest,
        &tool_receipts,
        &child_receipts,
        &checkpoints,
        &capability_lineage,
        &inclusion_proofs,
    )?;
    verify_disclosure_notice(&manifest)?;
    verify_policy_attachment(input, &manifest)?;
    verify_federation_policy_attachment(input, &manifest)?;

    let lineage_by_capability = verify_lineage(&capability_lineage)?;
    verify_query_scope(
        &query,
        &tool_receipts,
        &child_receipts,
        manifest.child_receipt_scope,
        &lineage_by_capability,
    )?;
    let tool_receipts_by_seq = verify_tool_receipts(&tool_receipts)?;
    verify_child_receipts(&child_receipts)?;
    let checkpoints_by_seq = verify_checkpoints(&checkpoints)?;
    let child_receipt_scope = manifest.child_receipt_scope;
    let transparency = verify_checkpoint_transparency_records(
        &checkpoints,
        &checkpoint_publications,
        &checkpoint_witnesses,
        &checkpoint_consistency_proofs,
        &checkpoint_equivocations,
    )?;
    verify_inclusion_proofs(
        &tool_receipts_by_seq,
        &checkpoints_by_seq,
        &inclusion_proofs,
        manifest.counts.uncheckpointed_receipts,
    )?;
    let bundle = EvidenceExportBundle {
        query,
        tool_receipts,
        child_receipts,
        child_receipt_scope,
        checkpoints,
        capability_lineage,
        inclusion_proofs,
        uncheckpointed_receipts: Vec::new(),
        retention,
    };
    verify_transparency_claim_boundary(manifest.claim_boundary.as_ref(), &bundle, &transparency)?;

    let federation_policy = if manifest.federation_policy.is_some() {
        Some(read_federation_policy(
            &input.join(federation_policy_relative_path()),
        )?)
    } else {
        None
    };
    let package = EvidenceImportPackage {
        manifest,
        bundle,
        transparency: Some(transparency),
        federation_policy,
    };
    validate_import_package_data(&package)?;
    Ok(package)
}

pub fn load_verified_evidence_package_summary(
    input: &Path,
) -> Result<VerifiedEvidencePackage, CliError> {
    let package = load_verified_evidence_package(input)?;
    let manifest_hash = sha256_hex(&canonical_json_bytes(&package.manifest)?);
    Ok(VerifiedEvidencePackage {
        bundle: package.bundle,
        transparency: package.transparency,
        manifest_schema: package.manifest.schema,
        exported_at: package.manifest.exported_at,
        manifest_hash,
    })
}

pub(crate) fn build_federated_share_import(
    package: &EvidenceImportPackage,
) -> Result<chio_kernel::FederatedEvidenceShareImport, CliError> {
    let federation_policy = package.federation_policy.as_ref().ok_or_else(|| {
        CliError::attest_error(
            "evidence import requires a signed attached federation policy so remote receipt sharing stays bilateral and explicit".to_string(),
        )
    })?;
    let share_descriptor = serde_json::json!({
        "schema": federated_evidence_share_schema_for_manifest(&package.manifest.schema),
        "manifest": &package.manifest,
        "federationPolicy": federation_policy,
    });
    let share_id = format!(
        "share-{}",
        sha256_hex(&canonical_json_bytes(&share_descriptor)?)
    );
    let manifest_hash = sha256_hex(&canonical_json_bytes(&package.manifest)?);
    Ok(chio_kernel::FederatedEvidenceShareImport {
        share_id,
        manifest_hash,
        exported_at: package.manifest.exported_at,
        issuer: federation_policy.body.issuer.clone(),
        partner: federation_policy.body.partner.clone(),
        signer_public_key: federation_policy.body.signer_public_key.to_hex(),
        require_proofs: federation_policy.body.require_proofs,
        query_json: serde_json::to_string(&package.bundle.query)?,
        tool_receipts: package
            .bundle
            .tool_receipts
            .iter()
            .map(|record| chio_kernel::StoredToolReceipt {
                seq: record.seq,
                receipt: record.receipt.clone(),
            })
            .collect(),
        capability_lineage: package.bundle.capability_lineage.clone(),
    })
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
            let bundle = store.build_evidence_export_bundle(&prepared.query)?;
            let transparency =
                store.build_evidence_export_transparency_summary(&bundle.checkpoints)?;
            validate_evidence_bundle_requirements(&bundle, prepared.require_proofs)?;
            RemoteEvidenceExportResponse {
                bundle,
                transparency: Some(transparency),
                federation_policy: prepared.federation_policy,
            }
        }
        (None, Some(control_url)) => {
            let token = super::require_control_token(control_token)?;
            let client = crate::trust_control::build_client(control_url, token)?;
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
            let client = crate::trust_control::build_client(control_url, token)?;
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
mod tests {
    use super::*;

    use chio_core::crypto::Keypair;
    use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction};
    use chio_kernel::{build_checkpoint, build_checkpoint_with_previous};
    use chio_kernel::{
        EvidenceChildReceiptScope, EvidenceExportBundle, EvidenceExportQuery,
        EvidenceRetentionMetadata, EvidenceToolReceiptRecord,
    };

    use chio_test_support::prelude::*;

    fn assert_registry_error(err: &CliError, expected_code: &str, expected_domain: &str) {
        match err {
            CliError::Chio(chio) => {
                assert_eq!(chio.code().as_str(), expected_code);
                assert_eq!(chio.domain().as_str(), expected_domain);
            }
            other => panic!("expected registry-backed CliError::Chio, got: {other:?}"),
        }
    }

    fn unique_test_dir(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "chio-evidence-{name}-{}-{stamp}",
            std::process::id()
        ))
    }

    #[test]
    fn output_path_file_uses_cli_domain() {
        let temp = unique_test_dir("file-output");
        std::fs::create_dir_all(&temp).test_unwrap();
        let output = temp.join("evidence-output");
        std::fs::write(&output, b"not a directory").test_unwrap();

        let error = ensure_clean_output_dir(&output).test_unwrap_err();

        assert_registry_error(&error, "urn:chio:error:cli:other", "cli");
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn output_path_nonempty_directory_uses_cli_domain() {
        let temp = unique_test_dir("nonempty-output");
        std::fs::create_dir_all(&temp).test_unwrap();
        let output = temp.join("evidence-output");
        std::fs::create_dir_all(&output).test_unwrap();
        std::fs::write(output.join("existing.json"), b"{}").test_unwrap();

        let error = ensure_clean_output_dir(&output).test_unwrap_err();

        assert_registry_error(&error, "urn:chio:error:cli:other", "cli");
        let _ = std::fs::remove_dir_all(&temp);
    }

    fn sample_receipt() -> ChioReceipt {
        let keypair = Keypair::generate();
        ChioReceipt::sign(
            ChioReceiptBody {
                id: "receipt-export-1".to_string(),
                timestamp: 1_775_137_626,
                capability_id: "cap-export-1".to_string(),
                tool_server: "export".to_string(),
                tool_name: "publish".to_string(),
                action: ToolCallAction::from_parameters(
                    serde_json::json!({"release":"candidate-1"}),
                )
                .test_unwrap(),
                decision: Some(Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: "content-export-1".to_string(),
                policy_hash: "policy-export-1".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level: chio_core::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .test_unwrap()
    }

    fn sample_bundle() -> EvidenceExportBundle {
        let receipt = sample_receipt();
        let canonical = canonical_json_bytes(&receipt).test_unwrap();
        let checkpoint_keypair = Keypair::generate();
        let checkpoint = build_checkpoint(
            1,
            1,
            1,
            std::slice::from_ref(&canonical),
            &checkpoint_keypair,
        )
        .test_unwrap();
        let tree = chio_core::merkle::MerkleTree::from_leaves(&[canonical]).test_unwrap();
        let proof = chio_kernel::build_inclusion_proof(&tree, 0, checkpoint.body.checkpoint_seq, 1)
            .test_unwrap();
        EvidenceExportBundle {
            query: EvidenceExportQuery::default(),
            tool_receipts: vec![EvidenceToolReceiptRecord { seq: 1, receipt }],
            child_receipts: Vec::new(),
            child_receipt_scope: EvidenceChildReceiptScope::OmittedNoJoinPath,
            checkpoints: vec![checkpoint],
            capability_lineage: Vec::new(),
            inclusion_proofs: vec![proof],
            uncheckpointed_receipts: Vec::new(),
            retention: EvidenceRetentionMetadata {
                live_db_size_bytes: Some(512),
                oldest_live_receipt_timestamp: Some(1_775_137_626),
            },
        }
    }

    fn manifest_for_bundle(bundle: &EvidenceExportBundle) -> EvidenceExportManifest {
        let counts = EvidenceExportCounts {
            tool_receipts: bundle.tool_receipts.len() as u64,
            child_receipts: bundle.child_receipts.len() as u64,
            checkpoints: bundle.checkpoints.len() as u64,
            capability_lineage: bundle.capability_lineage.len() as u64,
            inclusion_proofs: bundle.inclusion_proofs.len() as u64,
            uncheckpointed_receipts: bundle.uncheckpointed_receipts.len() as u64,
        };
        let disclosure_notice = maybe_build_disclosure_notice(&bundle.query);
        EvidenceExportManifest {
            schema: EVIDENCE_EXPORT_MANIFEST_SCHEMA.to_string(),
            exported_at: unix_now(),
            query: bundle.query.clone(),
            proof_coverage: EvidenceProofCoverage {
                checkpointed_receipts: counts
                    .tool_receipts
                    .saturating_sub(counts.uncheckpointed_receipts),
                uncheckpointed_receipts: counts.uncheckpointed_receipts,
            },
            receipt_semantics: evidence_receipt_semantic_summary(&bundle.tool_receipts),
            counts,
            child_receipt_scope: bundle.child_receipt_scope,
            claim_boundary: None,
            files: Vec::new(),
            policy: None,
            federation_policy: None,
            disclosure_notice,
        }
    }

    #[test]
    fn manifest_count_verification_rejects_semantic_drift() {
        let bundle = sample_bundle();
        let mut manifest = manifest_for_bundle(&bundle);
        manifest.receipt_semantics.authorized = 0;

        let error = verify_manifest_counts(
            &manifest,
            &bundle.tool_receipts,
            &bundle.child_receipts,
            &bundle.checkpoints,
            &bundle.capability_lineage,
            &bundle.inclusion_proofs,
        )
        .test_unwrap_err();

        assert!(
            error.to_string().contains("semantic summary"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn query_scope_rejects_tenant_scoped_package_with_mixed_receipt_tenant() {
        let mut receipt = sample_receipt();
        receipt.tenant_id = Some("tenant-b".to_string());
        let tool_receipts = vec![EvidenceToolReceiptRecord { seq: 1, receipt }];
        let error = verify_query_scope(
            &EvidenceExportQuery {
                capability_id: None,
                agent_subject: None,
                since: None,
                until: None,
                tenant: Some("tenant-a".to_string()),
                read_boundary: Some(ReceiptReadBoundary::tenant_scoped("tenant-a")),
            },
            &tool_receipts,
            &[],
            EvidenceChildReceiptScope::OmittedNoJoinPath,
            &BTreeMap::new(),
        )
        .test_unwrap_err();

        assert!(
            error.to_string().contains("outside tenant scope tenant-a"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn query_scope_rejects_admin_tenant_filtered_package_with_mixed_receipt_tenant() {
        let mut receipt = sample_receipt();
        receipt.tenant_id = Some("tenant-b".to_string());
        let tool_receipts = vec![EvidenceToolReceiptRecord { seq: 1, receipt }];
        let error = verify_query_scope(
            &EvidenceExportQuery {
                capability_id: None,
                agent_subject: None,
                since: None,
                until: None,
                tenant: Some("tenant-a".to_string()),
                read_boundary: Some(ReceiptReadBoundary::AdminAll),
            },
            &tool_receipts,
            &[],
            EvidenceChildReceiptScope::OmittedNoJoinPath,
            &BTreeMap::new(),
        )
        .test_unwrap_err();

        assert!(
            error.to_string().contains("outside tenant scope tenant-a"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn merge_export_query_preserves_policy_tenant_scope() {
        let merged = merge_export_query(
            &EvidenceExportQuery {
                capability_id: Some("cap-1".to_string()),
                agent_subject: None,
                since: None,
                until: None,
                tenant: Some("tenant-a".to_string()),
                read_boundary: Some(ReceiptReadBoundary::tenant_scoped("tenant-a")),
            },
            &EvidenceExportQuery {
                capability_id: None,
                agent_subject: Some("agent-1".to_string()),
                since: None,
                until: None,
                tenant: None,
                read_boundary: None,
            },
        )
        .test_unwrap();

        assert_eq!(merged.capability_id.as_deref(), Some("cap-1"));
        assert_eq!(merged.agent_subject.as_deref(), Some("agent-1"));
        assert_eq!(merged.tenant.as_deref(), Some("tenant-a"));
    }

    #[test]
    fn merge_export_query_rejects_tenant_scope_expansion() {
        let error = merge_export_query(
            &EvidenceExportQuery {
                capability_id: None,
                agent_subject: None,
                since: None,
                until: None,
                tenant: Some("tenant-a".to_string()),
                read_boundary: Some(ReceiptReadBoundary::tenant_scoped("tenant-a")),
            },
            &EvidenceExportQuery {
                capability_id: None,
                agent_subject: None,
                since: None,
                until: None,
                tenant: Some("tenant-b".to_string()),
                read_boundary: Some(ReceiptReadBoundary::tenant_scoped("tenant-b")),
            },
        )
        .test_unwrap_err();

        assert!(error.to_string().contains("tenant"));
    }

    #[test]
    fn merge_export_query_allows_admin_policy_to_narrow_to_tenant_filter() {
        let merged = merge_export_query(
            &EvidenceExportQuery {
                capability_id: None,
                agent_subject: None,
                since: None,
                until: None,
                tenant: None,
                read_boundary: Some(ReceiptReadBoundary::AdminAll),
            },
            &EvidenceExportQuery {
                capability_id: None,
                agent_subject: None,
                since: None,
                until: None,
                tenant: Some("tenant-a".to_string()),
                read_boundary: None,
            },
        )
        .test_unwrap();

        assert_eq!(merged.tenant.as_deref(), Some("tenant-a"));
        assert_eq!(merged.read_boundary, Some(ReceiptReadBoundary::AdminAll));
    }

    #[test]
    fn merge_export_query_rejects_request_chosen_boundary_without_policy_binding() {
        let error = merge_export_query(
            &EvidenceExportQuery {
                capability_id: None,
                agent_subject: None,
                since: None,
                until: None,
                tenant: None,
                read_boundary: None,
            },
            &EvidenceExportQuery {
                capability_id: None,
                agent_subject: None,
                since: None,
                until: None,
                tenant: None,
                read_boundary: Some(ReceiptReadBoundary::AdminAll),
            },
        )
        .test_unwrap_err();

        assert!(
            error.to_string().contains("read boundary"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn ensure_query_within_federation_policy_rejects_tenant_scope_expansion() {
        let error = ensure_query_within_federation_policy(
            &EvidenceExportQuery {
                capability_id: None,
                agent_subject: None,
                since: None,
                until: None,
                tenant: Some("tenant-a".to_string()),
                read_boundary: Some(ReceiptReadBoundary::tenant_scoped("tenant-a")),
            },
            &EvidenceExportQuery {
                capability_id: None,
                agent_subject: None,
                since: None,
                until: None,
                tenant: Some("tenant-b".to_string()),
                read_boundary: Some(ReceiptReadBoundary::tenant_scoped("tenant-b")),
            },
        )
        .test_unwrap_err();

        assert!(error.to_string().contains("tenant scope"));
    }

    #[test]
    fn ensure_query_within_federation_policy_rejects_admin_all_under_tenant_scope() {
        let error = ensure_query_within_federation_policy(
            &EvidenceExportQuery {
                capability_id: None,
                agent_subject: None,
                since: None,
                until: None,
                tenant: Some("tenant-a".to_string()),
                read_boundary: Some(ReceiptReadBoundary::tenant_scoped("tenant-a")),
            },
            &EvidenceExportQuery {
                capability_id: None,
                agent_subject: None,
                since: None,
                until: None,
                tenant: Some("tenant-a".to_string()),
                read_boundary: Some(ReceiptReadBoundary::AdminAll),
            },
        )
        .test_unwrap_err();

        assert!(error.to_string().contains("admin-all"));
    }

    #[test]
    fn ensure_query_within_federation_policy_allows_admin_policy_tenant_narrowing() {
        ensure_query_within_federation_policy(
            &EvidenceExportQuery {
                capability_id: None,
                agent_subject: None,
                since: None,
                until: None,
                tenant: None,
                read_boundary: Some(ReceiptReadBoundary::AdminAll),
            },
            &EvidenceExportQuery {
                capability_id: None,
                agent_subject: None,
                since: None,
                until: None,
                tenant: Some("tenant-a".to_string()),
                read_boundary: Some(ReceiptReadBoundary::AdminAll),
            },
        )
        .test_unwrap();
    }

    #[test]
    fn signed_federation_policy_rejects_unbound_read_boundary() {
        let keypair = Keypair::generate();
        let body = FederationPolicyBody {
            schema: FEDERATION_POLICY_SCHEMA.to_string(),
            issuer: "issuer-a".to_string(),
            partner: "partner-b".to_string(),
            signer_public_key: keypair.public_key(),
            created_at: 10,
            expires_at: 20,
            query: EvidenceExportQuery {
                capability_id: None,
                agent_subject: None,
                since: None,
                until: None,
                tenant: None,
                read_boundary: None,
            },
            require_proofs: false,
            purpose: None,
        };
        let (signature, _) = keypair.sign_canonical(&body).test_unwrap();
        let policy = FederationPolicyDocument { body, signature };

        let error = verify_federation_policy(&policy).test_unwrap_err();

        assert!(
            error.to_string().contains("read boundary"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn import_package_requires_explicit_read_boundary() {
        let bundle = sample_bundle();
        let manifest = manifest_for_bundle(&bundle);
        let package = EvidenceImportPackage {
            manifest,
            bundle,
            transparency: None,
            federation_policy: None,
        };
        let error = validate_import_package_data(&package).test_unwrap_err();

        assert!(error.to_string().contains("read boundary"));
    }

    #[test]
    fn checkpoint_transparency_records_match_derived_chain() {
        let kp = Keypair::generate();
        let first =
            build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &kp).test_unwrap();
        let second = build_checkpoint_with_previous(
            2,
            3,
            4,
            &[b"three".to_vec(), b"four".to_vec()],
            &kp,
            Some(&first),
        )
        .test_unwrap();
        let checkpoints = vec![first, second];

        let summary = validate_checkpoint_transparency_summary(&checkpoints).test_unwrap();
        verify_checkpoint_transparency_records(
            &checkpoints,
            &summary.publications,
            &summary.witnesses,
            &summary.consistency_proofs,
            &summary.equivocations,
        )
        .test_unwrap();
    }

    #[test]
    fn checkpoint_transparency_verification_fails_closed_on_equivocation() {
        let kp = Keypair::generate();
        let first =
            build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &kp).test_unwrap();
        let second = build_checkpoint_with_previous(
            2,
            3,
            4,
            &[b"three".to_vec(), b"four".to_vec()],
            &kp,
            Some(&first),
        )
        .test_unwrap();
        let fork = build_checkpoint_with_previous(
            2,
            3,
            4,
            &[b"five".to_vec(), b"six".to_vec()],
            &kp,
            Some(&first),
        )
        .test_unwrap();

        let error =
            validate_checkpoint_transparency_summary(&[first, second, fork]).test_unwrap_err();
        assert!(
            error.to_string().contains("equivocation"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn anchored_transparency_claims_fail_closed_during_export_verification() {
        let bundle = sample_bundle();
        let transparency =
            validate_checkpoint_transparency_summary(&bundle.checkpoints).test_unwrap();
        let anchored_claims = EvidenceTransparencyClaims {
            schema: chio_kernel::evidence_export::EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA.to_string(),
            publication_state:
                chio_kernel::evidence_export::EvidencePublicationState::TrustAnchored,
            trust_anchor: Some("anchor-root-1".to_string()),
            audit: chio_kernel::evidence_export::EvidenceAuditClaims {
                checkpoint_logs: transparency
                    .publications
                    .iter()
                    .map(|publication| publication.log_id.clone())
                    .collect(),
                signed_checkpoints: bundle.checkpoints.len() as u64,
                checkpoint_publications: transparency.publications.len() as u64,
                checkpoint_witnesses: transparency.witnesses.len() as u64,
                checkpoint_consistency_proofs: transparency.consistency_proofs.len() as u64,
                inclusion_proofs: bundle.inclusion_proofs.len() as u64,
                capability_lineage_records: bundle.capability_lineage.len() as u64,
            },
            transparency_preview: Vec::new(),
        };

        let error =
            verify_transparency_claim_boundary(Some(&anchored_claims), &bundle, &transparency)
                .test_unwrap_err();

        assert!(
            error.to_string().contains("claim boundary does not match"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn transparency_claim_boundary_validation_uses_attest_domain() {
        let bundle = sample_bundle();
        let transparency = match validate_checkpoint_transparency_summary(&bundle.checkpoints) {
            Ok(summary) => summary,
            Err(error) => panic!("failed to build transparency summary: {error}"),
        };
        let mut claims = build_evidence_transparency_claims(&bundle, &transparency, None);
        claims.schema = "invalid-schema".to_string();

        let error = match verify_transparency_claim_boundary(Some(&claims), &bundle, &transparency)
        {
            Ok(()) => panic!("invalid transparency claims should fail closed"),
            Err(error) => error,
        };

        assert_registry_error(&error, "urn:chio:error:attest:provenance-missing", "attest");
    }

    #[test]
    fn anchored_transparency_claims_verify_when_publications_carry_valid_bindings() {
        let bundle = sample_bundle();
        let checkpoint = bundle.checkpoints.first().cloned().test_unwrap();
        let mut transparency =
            validate_checkpoint_transparency_summary(&bundle.checkpoints).test_unwrap();
        let binding = chio_core::receipt::CheckpointPublicationTrustAnchorBinding {
            publication_identity: chio_core::receipt::CheckpointPublicationIdentity::new(
                chio_core::receipt::CheckpointPublicationIdentityKind::LocalLog,
                transparency.publications[0].log_id.clone(),
            ),
            trust_anchor_identity: chio_core::receipt::CheckpointTrustAnchorIdentity::new(
                chio_core::receipt::CheckpointTrustAnchorIdentityKind::TransparencyRoot,
                "root-set-1",
            ),
            trust_anchor_ref: "anchor-root-1".to_string(),
            signer_cert_ref: "cert-chain-1".to_string(),
            publication_profile_version: "phase4-pilot".to_string(),
        };
        transparency.publications = vec![
            chio_kernel::checkpoint::build_trust_anchored_checkpoint_publication(
                &checkpoint,
                binding,
            )
            .test_unwrap(),
        ];
        let anchored_claims =
            build_evidence_transparency_claims(&bundle, &transparency, Some("anchor-root-1"));

        verify_checkpoint_transparency_records(
            &bundle.checkpoints,
            &transparency.publications,
            &transparency.witnesses,
            &transparency.consistency_proofs,
            &transparency.equivocations,
        )
        .test_unwrap();
        verify_transparency_claim_boundary(Some(&anchored_claims), &bundle, &transparency)
            .test_unwrap();
    }

    #[test]
    fn evidence_export_fails_closed_on_stale_or_missing_publication() {
        let bundle = sample_bundle();
        let checkpoint = bundle.checkpoints.first().cloned().test_unwrap();
        let mut transparency =
            validate_checkpoint_transparency_summary(&bundle.checkpoints).test_unwrap();
        let binding = chio_core::receipt::CheckpointPublicationTrustAnchorBinding {
            publication_identity: chio_core::receipt::CheckpointPublicationIdentity::new(
                chio_core::receipt::CheckpointPublicationIdentityKind::LocalLog,
                transparency.publications[0].log_id.clone(),
            ),
            trust_anchor_identity: chio_core::receipt::CheckpointTrustAnchorIdentity::new(
                chio_core::receipt::CheckpointTrustAnchorIdentityKind::TransparencyRoot,
                "root-set-1",
            ),
            trust_anchor_ref: "anchor-root-1".to_string(),
            signer_cert_ref: "cert-chain-1".to_string(),
            publication_profile_version: "phase4-pilot".to_string(),
        };
        transparency.publications = vec![
            chio_kernel::checkpoint::build_trust_anchored_checkpoint_publication(
                &checkpoint,
                binding,
            )
            .test_unwrap(),
        ];
        let anchored_claims =
            build_evidence_transparency_claims(&bundle, &transparency, Some("anchor-root-1"));

        let missing_publication =
            validate_checkpoint_transparency_summary(&bundle.checkpoints).test_unwrap();
        let missing_error = verify_transparency_claim_boundary(
            Some(&anchored_claims),
            &bundle,
            &missing_publication,
        )
        .test_unwrap_err();
        assert!(
            missing_error
                .to_string()
                .contains("claim boundary does not match"),
            "unexpected missing-publication error: {missing_error}"
        );

        let mut stale_publications = transparency.publications.clone();
        stale_publications[0].log_tree_size += 1;
        let stale_error = verify_checkpoint_transparency_records(
            &bundle.checkpoints,
            &stale_publications,
            &transparency.witnesses,
            &transparency.consistency_proofs,
            &transparency.equivocations,
        )
        .test_unwrap_err();
        assert!(
            stale_error
                .to_string()
                .contains("checkpoint transparency verification failed"),
            "unexpected stale-publication error: {stale_error}"
        );
    }

    #[test]
    fn tenant_scoped_disclosure_notice_is_built_for_tenant_read_boundary() {
        let query = EvidenceExportQuery::tenant_scoped("tenant-a");
        let notice = maybe_build_disclosure_notice(&query).test_unwrap();
        assert_eq!(notice.schema, EVIDENCE_DISCLOSURE_NOTICE_SCHEMA);
        for required in [
            "batch_start_seq",
            "batch_end_seq",
            "tree_size",
            "merkle_root",
        ] {
            assert!(
                notice
                    .disclosed_checkpoint_body_fields
                    .iter()
                    .any(|field| field == required),
                "{required} must appear in disclosed checkpoint body fields: {:?}",
                notice.disclosed_checkpoint_body_fields,
            );
        }
        for required in ["entry_start_seq", "entry_end_seq", "log_tree_size"] {
            assert!(
                notice
                    .disclosed_publication_fields
                    .iter()
                    .any(|field| field == required),
                "{required} must appear in disclosed publication fields: {:?}",
                notice.disclosed_publication_fields,
            );
        }
        assert!(
            !notice.narrowed_metadata.is_empty(),
            "narrowed metadata list must enumerate the tenant-scoped narrowings",
        );
    }

    #[test]
    fn admin_all_export_carries_no_tenant_disclosure_notice() {
        let query = EvidenceExportQuery::admin_all();
        assert!(maybe_build_disclosure_notice(&query).is_none());
    }

    #[test]
    fn verify_disclosure_notice_rejects_stripped_tenant_notice() {
        let bundle = EvidenceExportBundle {
            query: EvidenceExportQuery::tenant_scoped("tenant-a"),
            tool_receipts: Vec::new(),
            child_receipts: Vec::new(),
            child_receipt_scope: EvidenceChildReceiptScope::OmittedNoJoinPath,
            checkpoints: Vec::new(),
            capability_lineage: Vec::new(),
            inclusion_proofs: Vec::new(),
            uncheckpointed_receipts: Vec::new(),
            retention: EvidenceRetentionMetadata {
                live_db_size_bytes: None,
                oldest_live_receipt_timestamp: None,
            },
        };
        let mut manifest = manifest_for_bundle(&bundle);
        assert!(manifest.disclosure_notice.is_some());
        manifest.disclosure_notice = None;

        let error = verify_disclosure_notice(&manifest).test_unwrap_err();
        assert!(
            error.to_string().contains("disclosure notice"),
            "unexpected error: {error}",
        );
    }

    #[test]
    fn verify_disclosure_notice_rejects_admin_all_with_spurious_notice() {
        let bundle = EvidenceExportBundle {
            query: EvidenceExportQuery::admin_all(),
            tool_receipts: Vec::new(),
            child_receipts: Vec::new(),
            child_receipt_scope: EvidenceChildReceiptScope::OmittedNoJoinPath,
            checkpoints: Vec::new(),
            capability_lineage: Vec::new(),
            inclusion_proofs: Vec::new(),
            uncheckpointed_receipts: Vec::new(),
            retention: EvidenceRetentionMetadata {
                live_db_size_bytes: Some(0),
                oldest_live_receipt_timestamp: None,
            },
        };
        let mut manifest = manifest_for_bundle(&bundle);
        manifest.disclosure_notice = Some(tenant_scoped_disclosure_notice());

        let error = verify_disclosure_notice(&manifest).test_unwrap_err();
        assert!(
            error.to_string().contains("admin-all"),
            "unexpected error: {error}",
        );
    }

    #[test]
    fn verify_disclosure_notice_rejects_tampered_notice() {
        let bundle = EvidenceExportBundle {
            query: EvidenceExportQuery::tenant_scoped("tenant-a"),
            tool_receipts: Vec::new(),
            child_receipts: Vec::new(),
            child_receipt_scope: EvidenceChildReceiptScope::OmittedNoJoinPath,
            checkpoints: Vec::new(),
            capability_lineage: Vec::new(),
            inclusion_proofs: Vec::new(),
            uncheckpointed_receipts: Vec::new(),
            retention: EvidenceRetentionMetadata {
                live_db_size_bytes: None,
                oldest_live_receipt_timestamp: None,
            },
        };
        let mut manifest = manifest_for_bundle(&bundle);
        if let Some(notice) = manifest.disclosure_notice.as_mut() {
            notice.disclosed_checkpoint_body_fields.clear();
        }

        let error = verify_disclosure_notice(&manifest).test_unwrap_err();
        assert!(
            error.to_string().contains("disclosure notice"),
            "unexpected error: {error}",
        );
    }
}
