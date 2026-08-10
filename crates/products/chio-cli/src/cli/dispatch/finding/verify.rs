use super::*;

use std::io::Read;

use base64::Engine as _;
use chio_appraisal::SignedRuntimeAttestationAppraisalReport;
use chio_core_types::capability::runtime_attestation::RuntimeAttestationEvidence;
use chio_core_types::capability::trust_policy::AttestationTrustPolicy;
use chio_core_types::crypto::{sha256_hex, PublicKey};
use chio_core_types::receipt::body::ChioReceipt;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{canonical_json_bytes, canonical_json_bytes_from_str};
use chio_finding::{
    Finding, FindingFacetKind, FindingFacetOutcome, SignedFindingBondBacking,
    SignedFindingChallengeVerifierProfile,
};
use chio_finding_verifier::{
    verify_finding_evidence, FindingBondSnapshot, FindingEvidenceBundle, FindingVerifierDraft,
    FindingVerifierTrustRoots, NoNonceEvidence, ResolvedFindingDeliveryEvidence,
    ResolvedReceiptEvidence, MAX_RAW_FINDING_BYTES,
};
use chio_kernel::checkpoint::{
    CheckpointTransparencySummary, KernelCheckpoint, ReceiptInclusionProof,
};

const FINDING_SCHEMA_JSON: &str =
    include_str!("../../../../../../../spec/schemas/chio-finding/v1/finding.schema.json");
const FINDING_SCHEMA_LABEL: &str = "chio-finding/v1/finding.schema.json";
pub(super) const FINDING_VERIFY_SUPPORT_MAX_BYTES: usize = 512 * 1024;

/// Identifies the resolution rules this surface applied, so a report
/// evaluated here is distinguishable from one evaluated by a venue that
/// resolves nonces, status feeds, or bond snapshots differently.
const RESOLVER_POLICY_ID: &str = "chio-cli/finding-verify";

/// An artifact that cleared the strict raw-first ingress.
pub(super) struct AcceptedFinding {
    pub(super) raw: String,
    pub(super) finding: Finding,
    pub(super) artifact_sha256: String,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_finding_verify(
    file: Option<&Path>,
    id: Option<&str>,
    trust_roots: Option<&Path>,
    evidence: Option<&Path>,
    recipe: Option<&Path>,
    status_rollback_floor: Option<&Path>,
    integrity_only: bool,
    json_output: bool,
    control_url: Option<&str>,
) -> Result<(), CliError> {
    let accepted = match (file, id) {
        (Some(path), None) => {
            let bytes = fs::read(path)?;
            if bytes.len() > MAX_RAW_FINDING_BYTES {
                return Err(CliError::cli_other_error(format!(
                    "{} is {} bytes, above the {MAX_RAW_FINDING_BYTES} byte finding bound",
                    path.display(),
                    bytes.len()
                )));
            }
            let raw = String::from_utf8(bytes).map_err(|error| {
                CliError::cli_other_error(format!("{} is not valid UTF-8: {error}", path.display()))
            })?;
            strict_finding_ingress(raw, &path.display().to_string())?
        }
        (None, Some(finding_id)) => {
            let url = require_control_url(control_url)?;
            let finding_id = require_finding_id(finding_id)?;
            accept_finding_from_venue(url, finding_id)?
        }
        _ => {
            return Err(CliError::cli_other_error(
                "finding verification requires exactly one of --file or --id".to_string(),
            ))
        }
    };

    if integrity_only {
        emit_integrity_only(&accepted, json_output)?;
        return Ok(());
    }

    let Some(trust_roots_path) = trust_roots else {
        emit_integrity_only(&accepted, json_output)?;
        return Err(CliError::cli_other_error(
            "evidence verification requires pinned trust roots via --trust-roots; pass --integrity-only to assert artifact integrity alone"
                .to_string(),
        ));
    };

    let (roots, trust_root_snapshot_sha256) = load_trust_roots(trust_roots_path)?;
    let evidence_file = match evidence {
        Some(path) => load_evidence_file(path)?,
        None => FindingEvidenceFile::default(),
    };
    let recipe_preimage = match recipe {
        Some(path) => Some(read_bounded_support_file(path, "recipe")?),
        None => None,
    };

    let trusted_time = match roots.trusted_time {
        Some(trusted_time) => trusted_time,
        None => unix_seconds_now()?,
    };
    if let Some(authorization) = &roots.status_operator_authorization {
        authorization.validate().map_err(|error| {
            CliError::cli_other_error(format!(
                "finding status operator authorization is invalid: {error}"
            ))
        })?;
    }
    let status_freshness_policy = resolve_status_freshness_policy(
        roots.status_operator_authorization.is_some(),
        roots.status_freshness_policy.as_ref(),
        evidence_file.status_proof_input_b64.is_some(),
        trusted_time,
    )?;
    let status_proof_input = evidence_file
        .status_proof_input_b64
        .as_deref()
        .map(decode_status_proof_input)
        .transpose()?;
    let status_floor_path =
        resolve_status_floor_path(status_proof_input.is_some(), status_rollback_floor)?;
    let trust = FindingVerifierTrustRoots {
        governance_authority: roots.governance_authority,
        profile: roots.profile,
        admitted_kernel_keys: roots.admitted_kernel_keys,
        collateral_authority: roots.collateral_authority,
        runtime_attestation_authority: roots.runtime_attestation_authority,
        appraisal_authority: roots.appraisal_authority,
        attestation_trust_policy: roots.attestation_trust_policy,
        status_operator_authorization: roots.status_operator_authorization,
        status_freshness_policy,
        trusted_time,
        trust_root_snapshot_sha256,
        resolver_policy_sha256: resolver_policy_digest(
            evidence.is_some(),
            recipe_preimage.is_some(),
            status_proof_input.is_some(),
            status_freshness_policy.is_some(),
            status_floor_path.is_some(),
        )?,
        trusted_time_input_sha256: trusted_time_input_digest(trusted_time, roots.trusted_time)?,
    };

    let mut receipts = Vec::with_capacity(evidence_file.receipts.len());
    for entry in evidence_file.receipts {
        let canonical_receipt_bytes = canonical_json_bytes(&entry.receipt)?;
        receipts.push(ResolvedReceiptEvidence {
            receipt: entry.receipt,
            canonical_receipt_bytes,
            inclusion_proof: entry.inclusion_proof,
        });
    }
    let finding_delivery = evidence_file
        .finding_delivery
        .map(|delivery| {
            let canonical_receipt_bytes = canonical_json_bytes(&delivery.receipt.receipt)?;
            Ok::<_, CliError>(ResolvedFindingDeliveryEvidence {
                receipt: ResolvedReceiptEvidence {
                    receipt: delivery.receipt.receipt,
                    canonical_receipt_bytes,
                    inclusion_proof: delivery.receipt.inclusion_proof,
                },
                checkpoints: delivery.checkpoints,
                checkpoint_transparency: delivery.checkpoint_transparency,
            })
        })
        .transpose()?;
    let nonce_resolver = NoNonceEvidence;
    let bundle = FindingEvidenceBundle {
        receipts,
        checkpoints: evidence_file.checkpoints,
        checkpoint_transparency: evidence_file.checkpoint_transparency,
        finding_delivery,
        recipe_preimage: recipe_preimage.as_deref(),
        status_proof_input: status_proof_input.as_deref(),
        runtime_attestation: evidence_file.runtime_attestation,
        runtime_appraisal: evidence_file.runtime_appraisal,
        bond_snapshot: evidence_file.bond_snapshot.map(FindingBondSnapshot::from),
        nonce_resolver: &nonce_resolver,
    };

    let draft = verify_finding_evidence(&accepted.raw, &trust, &bundle).map_err(|error| {
        CliError::cli_other_error(format!("finding evidence verification failed: {error}"))
    })?;
    if let (Some(path), Some(proof_bytes)) = (status_floor_path, status_proof_input.as_deref()) {
        let authorization = trust
            .status_operator_authorization
            .as_ref()
            .ok_or_else(|| CliError::cli_other_error("status authorization is missing".to_string()))?;
        let freshness = trust.status_freshness_policy.ok_or_else(|| {
            CliError::cli_other_error("status freshness policy is missing".to_string())
        })?;
        persist_authenticated_status_retraction(
            path,
            proof_bytes,
            authorization,
            freshness,
            &accepted.finding.finding_id,
            &accepted.finding.status_feed_ref,
        )?;
    }
    if !draft.satisfies_required_facets(&trust.profile.body) {
        return emit_evidence_report(&accepted, &draft, &trust.profile.body, json_output);
    }
    if status_proof_input.is_some()
        && draft.facet_outcome(FindingFacetKind::StatusLiveness)
            != Some(FindingFacetOutcome::Verified)
    {
        emit_evidence_report(&accepted, &draft, &trust.profile.body, json_output)?;
        return Err(CliError::cli_other_error(
            "supplied status proof did not establish live status".to_string(),
        ));
    }
    if let (Some(path), Some(proof_bytes)) = (status_floor_path, status_proof_input.as_deref()) {
        let authorization = trust
            .status_operator_authorization
            .as_ref()
            .ok_or_else(|| CliError::cli_other_error("status authorization is missing".to_string()))?;
        let freshness = trust.status_freshness_policy.ok_or_else(|| {
            CliError::cli_other_error("status freshness policy is missing".to_string())
        })?;
        advance_verified_status_floor(path, proof_bytes, authorization, freshness)?;
    }
    emit_evidence_report(&accepted, &draft, &trust.profile.body, json_output)
}

/// Fetch one stored artifact by its content address and run the strict
/// raw-first ingress over the exact bytes the venue served. The venue
/// serves what it accepted verbatim, so the ingress runs against wire
/// bytes and never against a local reserialization of them.
pub(super) fn accept_finding_from_venue(
    control_url: &str,
    finding_id: &str,
) -> Result<AcceptedFinding, CliError> {
    let raw = fetch_finding_bytes(control_url, finding_id)?;
    if raw.len() > MAX_RAW_FINDING_BYTES {
        return Err(CliError::cli_other_error(format!(
            "finding {finding_id} is {} bytes, above the {MAX_RAW_FINDING_BYTES} byte finding bound",
            raw.len()
        )));
    }
    let accepted = strict_finding_ingress(raw, &format!("finding {finding_id}"))?;
    if accepted.finding.finding_id != finding_id {
        return Err(CliError::cli_other_error(format!(
            "venue returned finding {} for requested id {finding_id}",
            accepted.finding.finding_id
        )));
    }
    Ok(accepted)
}

/// The strict raw-first ingress the publish surface applies, run before
/// any evidence question is asked: an artifact that is not exactly its
/// own canonical serialization is rejected outright rather than
/// normalized into acceptance.
pub(super) fn strict_finding_ingress(
    raw: String,
    source: &str,
) -> Result<AcceptedFinding, CliError> {
    let strict_bytes = canonical_json_bytes_from_str(&raw).map_err(|error| {
        CliError::cli_other_error(format!("{source} is not strict canonical I-JSON: {error}"))
    })?;
    if strict_bytes.as_slice() != raw.as_bytes() {
        return Err(CliError::cli_other_error(format!(
            "{source} bytes are not the canonical serialization"
        )));
    }

    let parsed: serde_json::Value = serde_json::from_str(&raw)?;
    let schema: serde_json::Value = serde_json::from_str(FINDING_SCHEMA_JSON)?;
    chio_spec_validate::validate_value(
        Path::new(FINDING_SCHEMA_LABEL),
        &schema,
        Path::new(source),
        &parsed,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("{source} rejected by the finding schema: {error}"))
    })?;

    let finding: Finding = serde_json::from_str(&raw)?;
    let typed_bytes = canonical_json_bytes(&finding)?;
    if typed_bytes != strict_bytes {
        return Err(CliError::cli_other_error(format!(
            "{source} typed canonical bytes drift from the accepted raw bytes"
        )));
    }

    chio_finding::verify_finding(&finding).map_err(|error| {
        CliError::cli_other_error(format!("{source} failed artifact verification: {error}"))
    })?;

    let artifact_sha256 = sha256_hex(&strict_bytes);
    Ok(AcceptedFinding {
        raw,
        finding,
        artifact_sha256,
    })
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingTrustRootsFile {
    governance_authority: PublicKey,
    profile: SignedFindingChallengeVerifierProfile,
    admitted_kernel_keys: Vec<PublicKey>,
    collateral_authority: PublicKey,
    #[serde(default)]
    runtime_attestation_authority: Option<PublicKey>,
    #[serde(default)]
    appraisal_authority: Option<PublicKey>,
    #[serde(default)]
    attestation_trust_policy: Option<AttestationTrustPolicy>,
    #[serde(default)]
    trusted_time: Option<u64>,
    #[serde(default)]
    status_operator_authorization: Option<chio_finding::FindingStatusOperatorAuthorization>,
    #[serde(default)]
    status_freshness_policy: Option<FindingStatusFreshnessPolicyFile>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingStatusFreshnessPolicyFile {
    max_epoch_age_secs: u64,
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingEvidenceFile {
    #[serde(default)]
    receipts: Vec<FindingEvidenceReceiptEntry>,
    #[serde(default)]
    checkpoints: Vec<KernelCheckpoint>,
    #[serde(default)]
    checkpoint_transparency: CheckpointTransparencySummary,
    #[serde(default)]
    finding_delivery: Option<FindingDeliveryEvidenceEntry>,
    #[serde(default)]
    runtime_attestation: Option<SignedExportEnvelope<RuntimeAttestationEvidence>>,
    #[serde(default)]
    runtime_appraisal: Option<SignedRuntimeAttestationAppraisalReport>,
    #[serde(default)]
    bond_snapshot: Option<FindingBondSnapshotEntry>,
    /// Exact canonical `chio.finding.status-proof-input.v1` bytes, encoded for
    /// transport inside this JSON evidence document.
    #[serde(default)]
    status_proof_input_b64: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingEvidenceReceiptEntry {
    receipt: ChioReceipt,
    inclusion_proof: ReceiptInclusionProof,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingDeliveryEvidenceEntry {
    receipt: FindingEvidenceReceiptEntry,
    checkpoints: Vec<KernelCheckpoint>,
    checkpoint_transparency: CheckpointTransparencySummary,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingBondSnapshotEntry {
    backing: SignedFindingBondBacking,
    live: bool,
    accepted_at: u64,
}

impl From<FindingBondSnapshotEntry> for FindingBondSnapshot {
    fn from(entry: FindingBondSnapshotEntry) -> Self {
        Self {
            backing: entry.backing,
            live: entry.live,
            accepted_at: entry.accepted_at,
        }
    }
}

/// Trust roots and the digest of the exact snapshot they were read from.
/// The digest is taken over the canonicalization of the supplied file so
/// two operators who pin the same roots derive the same commitment.
fn load_trust_roots(path: &Path) -> Result<(FindingTrustRootsFile, String), CliError> {
    let bytes = read_bounded_support_file(path, "trust-roots")?;
    let raw = String::from_utf8(bytes).map_err(|error| {
        CliError::cli_other_error(format!("{} is not valid UTF-8: {error}", path.display()))
    })?;
    let roots: FindingTrustRootsFile = serde_json::from_str(&raw)?;
    let canonical = canonical_json_bytes_from_str(&raw).map_err(|error| {
        CliError::cli_other_error(format!(
            "{} is not strict canonical I-JSON: {error}",
            path.display()
        ))
    })?;
    Ok((roots, sha256_hex(&canonical)))
}

fn load_evidence_file(path: &Path) -> Result<FindingEvidenceFile, CliError> {
    Ok(serde_json::from_slice(&read_bounded_support_file(
        path, "evidence",
    )?)?)
}

fn resolve_status_freshness_policy(
    authorization_present: bool,
    policy: Option<&FindingStatusFreshnessPolicyFile>,
    proof_present: bool,
    trusted_time: u64,
) -> Result<Option<chio_finding::FindingStatusFreshnessPolicy>, CliError> {
    if authorization_present != policy.is_some() {
        return Err(CliError::cli_other_error(
            "finding status operator authorization and freshness policy must be supplied together"
                .to_string(),
        ));
    }
    if proof_present && !authorization_present {
        return Err(CliError::cli_other_error(
            "finding status proof requires a pinned operator authorization and freshness policy"
                .to_string(),
        ));
    }
    let Some(policy) = policy else {
        return Ok(None);
    };
    if policy.max_epoch_age_secs == 0 {
        return Err(CliError::cli_other_error(
            "finding status max_epoch_age_secs must be nonzero".to_string(),
        ));
    }
    Ok(Some(chio_finding::FindingStatusFreshnessPolicy {
        now: trusted_time,
        max_epoch_age_secs: policy.max_epoch_age_secs,
    }))
}

fn decode_status_proof_input(encoded: &str) -> Result<Vec<u8>, CliError> {
    if encoded.len() > chio_finding::MAX_FINDING_STATUS_ENCODED_BYTES {
        return Err(CliError::cli_other_error(
            "finding status proof exceeds the encoded size bound".to_string(),
        ));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| {
            CliError::cli_other_error("finding status proof is not valid base64".to_string())
        })?;
    if bytes.len() > chio_finding::MAX_FINDING_STATUS_PROOF_BYTES {
        return Err(CliError::cli_other_error(
            "finding status proof exceeds the decoded size bound".to_string(),
        ));
    }
    chio_finding::parse_status_proof_input(&bytes).map_err(|error| {
        CliError::cli_other_error(format!(
            "finding status proof is not strict canonical input: {error}"
        ))
    })?;
    Ok(bytes)
}

fn resolve_status_floor_path(
    proof_present: bool,
    path: Option<&Path>,
) -> Result<Option<&Path>, CliError> {
    match (proof_present, path) {
        (true, Some(path)) => Ok(Some(path)),
        (true, None) => Err(CliError::cli_other_error(
            "finding status proof requires a durable floor via --status-rollback-floor"
                .to_string(),
        )),
        (false, Some(_)) => Err(CliError::cli_other_error(
            "--status-rollback-floor requires a status proof in the evidence bundle".to_string(),
        )),
        (false, None) => Ok(None),
    }
}

fn advance_verified_status_floor(
    path: &Path,
    proof_bytes: &[u8],
    authorization: &chio_finding::FindingStatusOperatorAuthorization,
    freshness: chio_finding::FindingStatusFreshnessPolicy,
) -> Result<(), CliError> {
    let proof = chio_finding::parse_status_proof_input(proof_bytes).map_err(|error| {
        CliError::cli_other_error(format!("finding status proof is invalid: {error}"))
    })?;
    let epoch = chio_finding::verify_status_proof_input(&proof, authorization, freshness).map_err(
        |error| {
            CliError::cli_other_error(format!(
                "finding status proof failed durable-floor verification: {error}"
            ))
        },
    )?;
    advance_parsed_status_floor(path, &proof, &epoch, authorization)
}

fn persist_authenticated_status_retraction(
    path: &Path,
    proof_bytes: &[u8],
    authorization: &chio_finding::FindingStatusOperatorAuthorization,
    freshness: chio_finding::FindingStatusFreshnessPolicy,
    expected_finding_id: &str,
    expected_feed_id: &str,
) -> Result<bool, CliError> {
    let proof = chio_finding::parse_status_proof_input(proof_bytes).map_err(|error| {
        CliError::cli_other_error(format!("finding status proof is invalid: {error}"))
    })?;
    let chio_finding::FindingStatusProofInput::Inclusion(inclusion) = &proof else {
        return Ok(false);
    };
    if inclusion.finding_id != expected_finding_id || inclusion.feed_id != expected_feed_id {
        return Ok(false);
    }
    let Ok(epoch) =
        chio_finding::verify_status_proof_input(&proof, authorization, freshness)
    else {
        return Ok(false);
    };
    advance_parsed_status_floor(path, &proof, &epoch, authorization)?;
    Ok(true)
}

fn advance_parsed_status_floor(
    path: &Path,
    proof: &chio_finding::FindingStatusProofInput,
    epoch: &chio_finding::SignedFindingStatusEpoch,
    authorization: &chio_finding::FindingStatusOperatorAuthorization,
) -> Result<(), CliError> {
    let authorization_sha256 = sha256_hex(&canonical_json_bytes(authorization)?);
    let finding_id = proof.finding_id().to_owned();
    let is_retracted = matches!(
        proof,
        chio_finding::FindingStatusProofInput::Inclusion(_)
    );
    advance_status_floor(
        path,
        &FindingStatusFloorObservation {
            feed_id: &epoch.body.feed_id,
            key_domain_nonce: epoch.body.key_domain_nonce,
            map_epoch: epoch.body.map_epoch,
            epoch_id: &epoch.body.status_epoch_id,
            root_hash: &epoch.body.root_hash,
            finding_id: &finding_id,
            is_retracted,
        },
        authorization,
        &authorization_sha256,
    )
}

fn read_bounded_support_file(path: &Path, kind: &str) -> Result<Vec<u8>, CliError> {
    let mut reader = std::fs::File::open(path)?
        .take((FINDING_VERIFY_SUPPORT_MAX_BYTES as u64).saturating_add(1));
    let mut bytes = Vec::with_capacity(FINDING_VERIFY_SUPPORT_MAX_BYTES.saturating_add(1));
    reader.read_to_end(&mut bytes)?;
    if bytes.len() > FINDING_VERIFY_SUPPORT_MAX_BYTES {
        return Err(CliError::cli_other_error(format!(
            "{} is above the {FINDING_VERIFY_SUPPORT_MAX_BYTES} byte {kind} bound",
            path.display()
        )));
    }
    Ok(bytes)
}

fn unix_seconds_now() -> Result<u64, CliError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|error| {
            CliError::cli_other_error(format!("system clock is before the unix epoch: {error}"))
        })
}

fn digest_of(value: &serde_json::Value) -> Result<String, CliError> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}

/// Commits to what this surface actually resolved. Nonce evidence is
/// never resolved here, so the cost facets can only report unavailable;
/// recording that in the policy digest keeps the claim honest.
fn resolver_policy_digest(
    evidence_supplied: bool,
    recipe_supplied: bool,
    status_proof_supplied: bool,
    status_trust_configured: bool,
    durable_status_floor_configured: bool,
) -> Result<String, CliError> {
    digest_of(&serde_json::json!({
        "resolver": RESOLVER_POLICY_ID,
        "evidence_bundle_supplied": evidence_supplied,
        "recipe_preimage_supplied": recipe_supplied,
        "status_proof_supplied": status_proof_supplied,
        "status_trust_configured": status_trust_configured,
        "durable_status_floor_configured": durable_status_floor_configured,
        "nonce_evidence_resolved": false,
    }))
}

fn trusted_time_input_digest(trusted_time: u64, pinned: Option<u64>) -> Result<String, CliError> {
    digest_of(&serde_json::json!({
        "resolver": RESOLVER_POLICY_ID,
        "source": if pinned.is_some() { "pinned" } else { "local_clock" },
        "unix_seconds": trusted_time,
    }))
}

fn facet_label(kind: FindingFacetKind) -> Result<String, CliError> {
    string_label(serde_json::to_value(kind)?, "facet kind")
}

fn outcome_label(outcome: FindingFacetOutcome) -> Result<String, CliError> {
    string_label(serde_json::to_value(outcome)?, "facet outcome")
}

fn string_label(value: serde_json::Value, what: &str) -> Result<String, CliError> {
    match value {
        serde_json::Value::String(label) => Ok(label),
        _ => Err(CliError::cli_other_error(format!(
            "{what} must serialize as a string"
        ))),
    }
}

/// Artifact integrity proves structure, content address, and issuer
/// signature. It says nothing about receipts, checkpoints, cost, recipe,
/// or bond, so every other facet is reported by name as unevaluated
/// rather than left implicit.
fn emit_integrity_only(accepted: &AcceptedFinding, json_output: bool) -> Result<(), CliError> {
    let mut unevaluated = Vec::with_capacity(FindingFacetKind::ALL.len() - 1);
    for kind in FindingFacetKind::ALL {
        if kind != FindingFacetKind::ArtifactIntegrity {
            unevaluated.push(facet_label(kind)?);
        }
    }

    if json_output {
        let report = serde_json::json!({
            "finding_id": accepted.finding.finding_id,
            "artifact_sha256": accepted.artifact_sha256,
            "mode": "integrity_only",
            "artifact_integrity": "verified",
            "facets_not_evaluated": unevaluated,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "finding_id:          {}",
            terminal_safe(&accepted.finding.finding_id)
        );
        println!(
            "artifact_sha256:     {}",
            terminal_safe(&accepted.artifact_sha256)
        );
        println!("mode:                integrity_only");
        println!("artifact_integrity:  verified");
        println!("facets_not_evaluated:");
        for label in &unevaluated {
            println!("  {}", terminal_safe(label));
        }
    }
    Ok(())
}

fn emit_evidence_report(
    accepted: &AcceptedFinding,
    draft: &FindingVerifierDraft,
    profile: &chio_finding::FindingChallengeVerifierProfile,
    json_output: bool,
) -> Result<(), CliError> {
    let required = draft.required_facets(profile);
    let mut required_labels = Vec::with_capacity(required.len());
    let mut unverified = Vec::new();
    let mut failed = Vec::new();
    for kind in &required {
        let label = facet_label(*kind)?;
        if draft.facet_outcome(*kind) != Some(FindingFacetOutcome::Verified) {
            unverified.push(label.clone());
        }
        required_labels.push(label);
    }

    let mut facet_rows = Vec::with_capacity(draft.facets.len());
    for result in &draft.facets {
        let label = facet_label(result.facet)?;
        if result.outcome == FindingFacetOutcome::Failed {
            failed.push(label.clone());
        }
        facet_rows.push(serde_json::json!({
            "facet": label,
            "outcome": outcome_label(result.outcome)?,
            "reason": result.reason,
            "evidence_refs": result.evidence_refs,
        }));
    }

    if json_output {
        let report = serde_json::json!({
            "finding_id": accepted.finding.finding_id,
            "artifact_sha256": draft.finding_artifact_sha256,
            "mode": "evidence",
            "evaluation_time": draft.evaluation_time,
            "resolved_evidence_bundle_sha256": draft.resolved_evidence_bundle_sha256,
            "backing_allocation_id": draft.backing_allocation_id,
            "finding_delivery_receipt_id": draft.finding_delivery_receipt_id,
            "facets": facet_rows,
            "required_facets": required_labels,
            "unverified_required_facets": unverified,
            "failed_facets": failed,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "finding_id:          {}",
            terminal_safe(&accepted.finding.finding_id)
        );
        println!(
            "artifact_sha256:     {}",
            terminal_safe(&draft.finding_artifact_sha256)
        );
        println!("mode:                evidence");
        println!("evaluation_time:     {}", draft.evaluation_time);
        println!(
            "evidence_bundle:     {}",
            terminal_safe(&draft.resolved_evidence_bundle_sha256)
        );
        if let Some(receipt_id) = draft.finding_delivery_receipt_id.as_deref() {
            println!("delivery_receipt:    {}", terminal_safe(receipt_id));
        }
        println!("facets:");
        for result in &draft.facets {
            println!(
                "  {:<28}  {:<12}  {}",
                terminal_safe(&facet_label(result.facet)?),
                terminal_safe(&outcome_label(result.outcome)?),
                terminal_safe(&result.reason)
            );
        }
        println!(
            "required_facets:     {}",
            terminal_safe(&required_labels.join(", "))
        );
        if !failed.is_empty() {
            println!(
                "failed_facets:       {}",
                terminal_safe(&failed.join(", "))
            );
        }
    }

    evidence_report_result(&unverified, &failed)
}

fn evidence_report_result(unverified: &[String], failed: &[String]) -> Result<(), CliError> {
    if !unverified.is_empty() {
        Err(CliError::cli_other_error(format!(
            "required facets not verified: {}",
            unverified.join(", ")
        )))
    } else if !failed.is_empty() {
        Err(CliError::cli_other_error(format!(
            "finding evidence verification failed for facets: {}",
            failed.join(", ")
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUALIFIED_STATUS_PROOF: &[u8] = include_bytes!(
        "../../../../../../../fixtures/proof-room/finding/cognition-market-qualified-profile/attachments/status-proof-input.json"
    );
    const RETRACTED_FINDING_ID: &str =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const RETRACTION_INTENT_ID: &str =
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    fn authenticated_inclusion_fixture() -> Result<
        (
            Vec<u8>,
            chio_finding::FindingStatusOperatorAuthorization,
            chio_finding::FindingStatusFreshnessPolicy,
        ),
        CliError,
    > {
        use chio_core_types::crypto::Keypair;
        use chio_core_types::receipt::lineage::SignedExportEnvelope;
        use chio_revocation_oracle::{
            finding_status_empty_leaf_hash, FindingStatusSparseMap,
            FINDING_STATUS_BRANCH_DOMAIN, FINDING_STATUS_EMPTY_LEAF_DOMAIN,
            FINDING_STATUS_HASH_ALGORITHM, FINDING_STATUS_KEY_DOMAIN_NONCE,
            FINDING_STATUS_KEY_HASH_DOMAIN, FINDING_STATUS_MAP_VERSION,
            FINDING_STATUS_OCCUPIED_LEAF_DOMAIN, FINDING_STATUS_PROOF_SEMANTICS,
            FINDING_STATUS_SPARSE_DEPTH,
        };

        let keypair = Keypair::from_seed(&[42_u8; 32]);
        let authorization = chio_finding::FindingStatusOperatorAuthorization {
            role: chio_finding::FindingStatusOperatorRole::FindingStatusOperator,
            feed_id: "status-feed/cli-review".to_string(),
            operator: chio_finding::FindingAuthorityKeyPolicy {
                authority_id: "cli-status-operator".to_string(),
                key: keypair.public_key(),
                key_epoch: 7,
                valid_from: 1_700_000_000,
                valid_until: 1_800_000_000,
                rotation_policy_ref: "rotation/cli-status-v1".to_string(),
                revocation_status_ref: "revocations/cli-status".to_string(),
            },
            revoked_from: None,
        };
        let mut map = FindingStatusSparseMap::new();
        let root = map
            .insert(RETRACTED_FINDING_ID, RETRACTION_INTENT_ID)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let sparse = map
            .proof(RETRACTED_FINDING_ID)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let mut body = chio_finding::FindingStatusEpoch {
            schema: chio_finding::FINDING_STATUS_EPOCH_SCHEMA_V1.to_string(),
            status_epoch_id: String::new(),
            signature_domain: chio_finding::FINDING_STATUS_SIGNATURE_DOMAIN.to_string(),
            status_map_version: FINDING_STATUS_MAP_VERSION.to_string(),
            proof_semantics: FINDING_STATUS_PROOF_SEMANTICS.to_string(),
            feed_id: authorization.feed_id.clone(),
            key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
            map_epoch: root.map_epoch,
            operator_id: authorization.operator.authority_id.clone(),
            operator_key: keypair.public_key(),
            operator_key_epoch: authorization.operator.key_epoch,
            root_hash: hex::encode(root.root_hash),
            tree_depth: FINDING_STATUS_SPARSE_DEPTH as u16,
            hash_algorithm: FINDING_STATUS_HASH_ALGORITHM.to_string(),
            key_hash_domain: FINDING_STATUS_KEY_HASH_DOMAIN.to_string(),
            empty_leaf_domain: FINDING_STATUS_EMPTY_LEAF_DOMAIN.to_string(),
            occupied_leaf_domain: FINDING_STATUS_OCCUPIED_LEAF_DOMAIN.to_string(),
            branch_domain: FINDING_STATUS_BRANCH_DOMAIN.to_string(),
            empty_leaf_hash: hex::encode(finding_status_empty_leaf_hash()),
            anchor_refs: vec!["anchor/cli-status/1".to_string()],
            generated_at: 1_700_000_100,
            valid_from: 1_700_000_000,
            valid_until: 1_700_000_300,
        };
        body.status_epoch_id = chio_finding::compute_status_epoch_id(&body)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let signed = SignedExportEnvelope::sign(body, &keypair)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let checked_at = 1_700_000_110;
        let proof = chio_finding::build_status_inclusion_proof_input(
            &signed,
            RETRACTED_FINDING_ID,
            RETRACTION_INTENT_ID,
            &sparse,
            checked_at,
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        Ok((
            canonical_json_bytes(&proof)?,
            authorization,
            chio_finding::FindingStatusFreshnessPolicy {
                now: checked_at,
                max_epoch_age_secs: 60,
            },
        ))
    }

    #[test]
    fn evidence_report_rejects_a_failed_optional_facet() {
        let error = evidence_report_result(&[], &["receipt_authenticity".to_string()])
            .unwrap_err()
            .to_string();
        assert!(error.contains("receipt_authenticity"));
    }

    #[test]
    fn finding_verify_preserves_exact_canonical_status_proof_bytes() -> Result<(), CliError> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(QUALIFIED_STATUS_PROOF);
        let decoded = decode_status_proof_input(&encoded)?;
        assert_eq!(decoded, QUALIFIED_STATUS_PROOF);
        Ok(())
    }

    #[test]
    fn finding_verify_binds_status_freshness_to_report_clock() -> Result<(), CliError> {
        let resolved = resolve_status_freshness_policy(
            true,
            Some(&FindingStatusFreshnessPolicyFile {
                max_epoch_age_secs: 90,
            }),
            true,
            1_750_000_030,
        )?
        .ok_or_else(|| CliError::cli_other_error("status policy was not resolved".to_string()))?;
        assert_eq!(resolved.now, 1_750_000_030);
        assert_eq!(resolved.max_epoch_age_secs, 90);
        Ok(())
    }

    #[test]
    fn finding_verify_rejects_status_proof_without_pinned_trust() -> Result<(), CliError> {
        let error = resolve_status_freshness_policy(false, None, true, 1_750_000_030)
            .err()
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "status proof without pinned trust was accepted".to_string(),
                )
            })?;
        assert!(error.to_string().contains("requires a pinned operator"));
        Ok(())
    }

    #[test]
    fn finding_verify_requires_a_durable_status_floor() -> Result<(), CliError> {
        let error = resolve_status_floor_path(true, None)
            .err()
            .ok_or_else(|| CliError::cli_other_error("missing floor was accepted".to_string()))?;
        assert!(error.to_string().contains("--status-rollback-floor"));
        Ok(())
    }

    #[test]
    fn finding_verify_persists_an_authenticated_retraction_before_failure() -> Result<(), CliError> {
        let (proof_bytes, authorization, freshness) = authenticated_inclusion_fixture()?;
        let dir = tempfile::tempdir()?;
        let floor_path = dir.path().join("status-floor.json");
        assert!(persist_authenticated_status_retraction(
            &floor_path,
            &proof_bytes,
            &authorization,
            freshness,
            RETRACTED_FINDING_ID,
            &authorization.feed_id,
        )?);

        let proof = chio_finding::parse_status_proof_input(&proof_bytes)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let map_epoch = match proof {
            chio_finding::FindingStatusProofInput::Inclusion(inclusion) => inclusion.map_epoch,
            chio_finding::FindingStatusProofInput::NonInclusion(_) => {
                return Err(CliError::cli_other_error(
                    "test status proof was not an inclusion".to_string(),
                ));
            }
        };
        let authorization_sha256 = sha256_hex(&canonical_json_bytes(&authorization)?);
        let error = advance_status_floor(
            &floor_path,
            &FindingStatusFloorObservation {
                feed_id: &authorization.feed_id,
                key_domain_nonce: chio_revocation_oracle::FINDING_STATUS_KEY_DOMAIN_NONCE,
                map_epoch: map_epoch.saturating_add(1),
                epoch_id: &"a".repeat(64),
                root_hash: &"b".repeat(64),
                finding_id: RETRACTED_FINDING_ID,
                is_retracted: false,
            },
            &authorization,
            &authorization_sha256,
        )
        .err()
        .ok_or_else(|| CliError::cli_other_error("retracted Finding was revived".to_string()))?;
        assert!(error.to_string().contains("durably retracted"));
        Ok(())
    }

    #[test]
    fn finding_verify_rejects_a_verified_epoch_below_its_durable_floor() -> Result<(), CliError> {
        let proof = chio_finding::parse_status_proof_input(QUALIFIED_STATUS_PROOF)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let chio_finding::FindingStatusProofInput::NonInclusion(non_inclusion) = &proof else {
            return Err(CliError::cli_other_error(
                "qualified proof is not non-inclusion".to_string(),
            ));
        };
        let epoch_bytes = base64::engine::general_purpose::STANDARD
            .decode(&non_inclusion.signed_status_epoch_b64)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let epoch = chio_finding::parse_signed_status_epoch(&epoch_bytes)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let authorization = chio_finding::FindingStatusOperatorAuthorization {
            role: chio_finding::FindingStatusOperatorRole::FindingStatusOperator,
            feed_id: epoch.body.feed_id.clone(),
            operator: chio_finding::FindingAuthorityKeyPolicy {
                authority_id: epoch.body.operator_id.clone(),
                key: epoch.body.operator_key,
                key_epoch: epoch.body.operator_key_epoch,
                valid_from: epoch.body.valid_from,
                valid_until: epoch.body.valid_until,
                rotation_policy_ref: "qualified-status-rotation".to_string(),
                revocation_status_ref: "qualified-status-revocations".to_string(),
            },
            revoked_from: None,
        };
        let authorization_sha256 = sha256_hex(&canonical_json_bytes(&authorization)?);
        let dir = tempfile::tempdir()?;
        let floor_path = dir.path().join("status-floor.json");
        write_status_floor(
            &floor_path,
            &FindingStatusCliFloor {
                schema: TEST_FINDING_STATUS_FLOOR_SCHEMA.to_string(),
                feed_id: epoch.body.feed_id.clone(),
                operator_id: epoch.body.operator_id.clone(),
                rotation_policy_ref: authorization.operator.rotation_policy_ref.clone(),
                operator_key_epoch: epoch.body.operator_key_epoch,
                operator_authorization_sha256: authorization_sha256,
                key_domain_nonce: epoch.body.key_domain_nonce,
                map_epoch: epoch.body.map_epoch.saturating_add(1),
                epoch_id: "a".repeat(64),
                root_hash: "b".repeat(64),
            },
        )?;

        let error = advance_verified_status_floor(
            &floor_path,
            QUALIFIED_STATUS_PROOF,
            &authorization,
            chio_finding::FindingStatusFreshnessPolicy {
                now: non_inclusion.checked_at,
                max_epoch_age_secs: 60,
            },
        )
        .err()
        .ok_or_else(|| CliError::cli_other_error("status rollback was accepted".to_string()))?;
        assert!(
            error.to_string().contains("below the durable rollback floor"),
            "unexpected error: {error}"
        );
        Ok(())
    }
}
