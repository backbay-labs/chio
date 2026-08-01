use super::*;

use std::io::Read;

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
    FindingVerifierTrustRoots, NoNonceEvidence, ResolvedReceiptEvidence, MAX_RAW_FINDING_BYTES,
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
    let trust = FindingVerifierTrustRoots {
        governance_authority: roots.governance_authority,
        profile: roots.profile,
        admitted_kernel_keys: roots.admitted_kernel_keys,
        collateral_authority: roots.collateral_authority,
        runtime_attestation_authority: roots.runtime_attestation_authority,
        appraisal_authority: roots.appraisal_authority,
        attestation_trust_policy: roots.attestation_trust_policy,
        status_operator_authorization: None,
        status_freshness_policy: None,
        trusted_time,
        trust_root_snapshot_sha256,
        resolver_policy_sha256: resolver_policy_digest(
            evidence.is_some(),
            recipe_preimage.is_some(),
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
    let nonce_resolver = NoNonceEvidence;
    let bundle = FindingEvidenceBundle {
        receipts,
        checkpoints: evidence_file.checkpoints,
        checkpoint_transparency: evidence_file.checkpoint_transparency,
        recipe_preimage: recipe_preimage.as_deref(),
        status_proof_input: None,
        runtime_attestation: evidence_file.runtime_attestation,
        runtime_appraisal: evidence_file.runtime_appraisal,
        bond_snapshot: evidence_file.bond_snapshot.map(FindingBondSnapshot::from),
        nonce_resolver: &nonce_resolver,
    };

    let draft = verify_finding_evidence(&accepted.raw, &trust, &bundle).map_err(|error| {
        CliError::cli_other_error(format!("finding evidence verification failed: {error}"))
    })?;
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
    runtime_attestation: Option<SignedExportEnvelope<RuntimeAttestationEvidence>>,
    #[serde(default)]
    runtime_appraisal: Option<SignedRuntimeAttestationAppraisalReport>,
    #[serde(default)]
    bond_snapshot: Option<FindingBondSnapshotEntry>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingEvidenceReceiptEntry {
    receipt: ChioReceipt,
    inclusion_proof: ReceiptInclusionProof,
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
) -> Result<String, CliError> {
    digest_of(&serde_json::json!({
        "resolver": RESOLVER_POLICY_ID,
        "evidence_bundle_supplied": evidence_supplied,
        "recipe_preimage_supplied": recipe_supplied,
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
    for kind in &required {
        let label = facet_label(*kind)?;
        if draft.facet_outcome(*kind) != Some(FindingFacetOutcome::Verified) {
            unverified.push(label.clone());
        }
        required_labels.push(label);
    }

    let mut facet_rows = Vec::with_capacity(draft.facets.len());
    for result in &draft.facets {
        facet_rows.push(serde_json::json!({
            "facet": facet_label(result.facet)?,
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
            "facets": facet_rows,
            "required_facets": required_labels,
            "unverified_required_facets": unverified,
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
    }

    if unverified.is_empty() {
        Ok(())
    } else {
        Err(CliError::cli_other_error(format!(
            "required facets not verified: {}",
            unverified.join(", ")
        )))
    }
}
