use super::*;

pub(super) fn verify_manifest_file_hashes(
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

pub(super) fn verify_query_scope(
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

pub(super) fn verify_tool_receipts(
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
        // Evidence package verification has no policy.crypto_floor input.
        // Keep the compatibility floor explicit here: accept classical and hybrid receipts, while policy-bearing callers enforce
        // their configured floor before export.
        if !record
            .receipt
            .verify_signature_with_floor(ReceiptCryptoFloor::AllowHybrid)
            .map_err(|error| {
                CliError::attest_error(format!(
                    "tool receipt signature verification failed: {}: {error}",
                    record.receipt.id
                ))
            })?
        {
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

pub(super) fn verify_child_receipts(
    child_receipts: &[EvidenceChildReceiptRecord],
) -> Result<(), CliError> {
    let mut seen = BTreeSet::new();
    for record in child_receipts {
        if !seen.insert(record.seq) {
            return Err(CliError::attest_error(format!(
                "duplicate child receipt seq in evidence package: {}",
                record.seq
            )));
        }
        // Evidence package verification has no policy.crypto_floor input.
        // Keep the compatibility floor explicit here: accept classical and hybrid receipts, while policy-bearing callers enforce
        // their configured floor before export.
        if !record
            .receipt
            .verify_signature_with_floor(ReceiptCryptoFloor::AllowHybrid)
            .map_err(|error| {
                CliError::attest_error(format!(
                    "child receipt signature verification failed: {}: {error}",
                    record.receipt.id
                ))
            })?
        {
            return Err(CliError::attest_error(format!(
                "child receipt signature verification failed: {}",
                record.receipt.id
            )));
        }
    }
    Ok(())
}

pub(super) fn verify_checkpoints(
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

pub(super) fn verify_lineage(
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

pub(super) fn validate_checkpoint_transparency_summary(
    checkpoints: &[KernelCheckpoint],
) -> Result<CheckpointTransparencySummary, CliError> {
    validate_checkpoint_transparency(checkpoints).map_err(|error| {
        CliError::attest_error(format!(
            "checkpoint transparency verification failed: {error}"
        ))
    })
}

pub(super) fn verify_checkpoint_transparency_records(
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

pub(super) fn verify_transparency_claim_boundary(
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

pub(super) fn verify_inclusion_proofs(
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

pub(super) fn evidence_receipt_semantic_summary(
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
            && record
                .receipt
                .verify_signature_with_floor(ReceiptCryptoFloor::AllowHybrid)
                .unwrap_or(false)
            && record.receipt.action.verify_hash().unwrap_or(false)
        {
            summary.authorized += 1;
        }
    }
    summary
}

pub(super) fn verify_manifest_counts(
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

pub(super) fn verify_policy_attachment(
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

pub(super) fn verify_disclosure_notice(manifest: &EvidenceExportManifest) -> Result<(), CliError> {
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

pub(super) fn verify_federation_policy_attachment(
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

pub(super) fn load_verified_evidence_package(
    input: &Path,
) -> Result<EvidenceImportPackage, CliError> {
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
