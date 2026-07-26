use super::*;

pub(super) fn verify_issuance_input(
    subject: FinancialCredentialSubjectV1,
    request: FinancialSourceCompletenessAttestationRequestV1,
    proof: &SignedFinancialSourceCompletenessAttestationV1,
    checkpoint: &QualifiedFinancialSourceCheckpointV1,
    now: u64,
) -> Result<VerifiedFinancialCredentialIssuanceV1, FinancialCredentialProjectionError> {
    let source_evidence_class =
        verify_source_completeness_attestation(&request, proof, checkpoint, now)?;
    Ok(VerifiedFinancialCredentialIssuanceV1 {
        subject,
        evidence: FinancialCredentialEvidenceV1 {
            window: request.window,
            source_disclosure: request.disclosure,
            source_completeness_attestations: vec![proof.clone()],
        },
        source_evidence_class,
        proof_issued_at: proof.body.issued_at.max(checkpoint.body.issued_at),
        proof_expires_at: proof.body.expires_at.min(checkpoint.body.expires_at),
    })
}

pub(super) fn verify_source_completeness_attestation(
    request: &FinancialSourceCompletenessAttestationRequestV1,
    proof: &SignedFinancialSourceCompletenessAttestationV1,
    checkpoint: &QualifiedFinancialSourceCheckpointV1,
    now: u64,
) -> Result<ProvenanceEvidenceClass, FinancialCredentialProjectionError> {
    let body = &proof.body;
    let checkpoint_body = &checkpoint.body;
    if body.schema != FINANCIAL_SOURCE_COMPLETENESS_ATTESTATION_SCHEMA_V1
        || body.source_id != checkpoint_body.source_id
        || body.source_family != request.source_family
        || body.subject != request.subject
        || body.source_signer_key != request.source_signer_key
        || body.checkpoint_authority_epoch != checkpoint_body.checkpoint_authority_epoch
        || body.checkpoint_authority_key != checkpoint_body.checkpoint_authority_key
        || proof.signer_key != checkpoint_body.checkpoint_authority_key
        || body.store_generation != checkpoint_body.store_generation
        || body.checkpoint_sequence != checkpoint_body.checkpoint_sequence
        || body.checkpoint_digest != checkpoint.checkpoint_digest
        || body.cutoff != request.cutoff
        || body.cutoff != checkpoint_body.cutoff
        || body.window != request.window
        || body.window != checkpoint_body.window
        || body.range_root != checkpoint_body.range_root
        || body.index_root != checkpoint_body.index_root
        || body.lower_boundary != checkpoint_body.lower_boundary
        || body.upper_boundary != checkpoint_body.upper_boundary
        || body.disclosure_digest != request.disclosure_digest
    {
        return Err(FinancialCredentialProjectionError::InvalidSourceAttestationBinding);
    }
    if !checkpoint_body
        .checkpoint_authority_key
        .verify_canonical(body, &proof.signature)
        .map_err(|_| FinancialCredentialProjectionError::InvalidSourceAttestationSignature)?
    {
        return Err(FinancialCredentialProjectionError::InvalidSourceAttestationSignature);
    }
    let validated_disclosure = validate_financial_source_disclosure(
        request.source_family,
        &request.subject,
        &request.source_signer_key,
        &request.disclosure,
    )?;
    if validated_disclosure.expected_members != request.expected_members
        || validated_disclosure.source_artifact_digests != request.source_artifact_digests
    {
        return Err(FinancialCredentialProjectionError::InvalidSourceAttestationBinding);
    }
    for value in [
        body.checkpoint_authority_epoch,
        body.store_generation,
        body.checkpoint_sequence,
        body.cutoff,
        body.window.starts_at,
        body.window.ends_at,
        body.issued_at,
        body.expires_at,
        now,
    ] {
        ensure_i_json(value)?;
    }
    if body.checkpoint_authority_epoch == 0
        || body.store_generation == 0
        || body.checkpoint_sequence == 0
        || body.committed_leaves.is_empty()
        || body.committed_leaves.len() > MAX_SOURCE_ARTIFACTS
        || body.window.starts_at >= body.window.ends_at
        || body.cutoff != body.window.ends_at
    {
        return Err(FinancialCredentialProjectionError::InvalidSourceAttestationBinding);
    }
    if body.issued_at < body.cutoff
        || body.issued_at >= body.expires_at
        || now < body.issued_at
        || now >= body.expires_at
        || body.issued_at < checkpoint_body.issued_at
        || body.expires_at > checkpoint_body.expires_at
    {
        return Err(FinancialCredentialProjectionError::StaleSourceAttestation);
    }
    if !valid_identifier(&body.source_id)
        || !valid_identifier(&body.attestation_reference)
        || !valid_digest(&body.checkpoint_digest)
        || !valid_digest(&body.range_root)
        || !valid_digest(&body.index_root)
        || !valid_digest(&body.disclosure_digest)
        || body
            .source_artifact_digests
            .iter()
            .any(|digest| !valid_digest(digest))
    {
        return Err(FinancialCredentialProjectionError::InvalidSourceAttestationBinding);
    }
    let index_root = Hash::from_hex(&body.index_root)
        .map_err(|_| FinancialCredentialProjectionError::InvalidSourceAttestationBinding)?;
    if body.committed_leaves.len() != request.expected_members.len() {
        return Err(FinancialCredentialProjectionError::InvalidSourceAttestationBinding);
    }
    let mut previous_index = None;
    let mut previous_query_key = None;
    let mut range_leaves = Vec::with_capacity(body.committed_leaves.len());
    let mut disclosed_artifacts = BTreeSet::new();
    let mut source_evidence_class = request.maximum_source_evidence_class;
    for (committed, expected) in body.committed_leaves.iter().zip(&request.expected_members) {
        verify_committed_leaf_proof(committed, &index_root, checkpoint_body.index_size)?;
        if previous_index.is_some_and(|index| index + 1 != committed.leaf.index)
            || previous_query_key
                .as_ref()
                .is_some_and(|key| key >= &committed.leaf.query_key)
            || committed.leaf.query_key != expected.query_key
            || committed.leaf.source_artifact_digest != expected.source_artifact_digest
        {
            return Err(FinancialCredentialProjectionError::InvalidSourceAttestationBinding);
        }
        previous_index = Some(committed.leaf.index);
        previous_query_key = Some(committed.leaf.query_key.clone());
        disclosed_artifacts.insert(committed.leaf.source_artifact_digest.clone());
        if evidence_class_rank(expected.evidence_class) < evidence_class_rank(source_evidence_class)
        {
            source_evidence_class = expected.evidence_class;
        }
        range_leaves.push(canonical_json_bytes(&committed.leaf).map_err(|error| {
            FinancialCredentialProjectionError::InvalidSource(error.to_string())
        })?);
    }
    count_i_json(body.committed_leaves.len())?;
    let range_tree = MerkleTree::from_leaves(&range_leaves)
        .map_err(|_| FinancialCredentialProjectionError::InvalidSourceAttestationBinding)?;
    if range_tree.root().to_hex() != body.range_root {
        return Err(FinancialCredentialProjectionError::InvalidSourceAttestationBinding);
    }
    let first_index = body
        .committed_leaves
        .first()
        .ok_or(FinancialCredentialProjectionError::InvalidSourceAttestationBinding)?
        .leaf
        .index;
    let first_key = &body
        .committed_leaves
        .first()
        .ok_or(FinancialCredentialProjectionError::InvalidSourceAttestationBinding)?
        .leaf
        .query_key;
    let last_index = body
        .committed_leaves
        .last()
        .ok_or(FinancialCredentialProjectionError::InvalidSourceAttestationBinding)?
        .leaf
        .index;
    let last_key = &body
        .committed_leaves
        .last()
        .ok_or(FinancialCredentialProjectionError::InvalidSourceAttestationBinding)?
        .leaf
        .query_key;
    verify_completeness_boundary(
        &body.lower_boundary,
        first_index,
        first_key,
        true,
        &index_root,
        checkpoint_body.index_size,
        request,
    )?;
    verify_completeness_boundary(
        &body.upper_boundary,
        last_index,
        last_key,
        false,
        &index_root,
        checkpoint_body.index_size,
        request,
    )?;
    let expected_artifacts = request
        .expected_members
        .iter()
        .map(|member| member.source_artifact_digest.clone())
        .collect::<BTreeSet<_>>();
    if disclosed_artifacts != expected_artifacts
        || body.source_artifact_digests != request.source_artifact_digests
        || body.source_evidence_class != source_evidence_class
    {
        return Err(FinancialCredentialProjectionError::InvalidSourceAttestationBinding);
    }
    Ok(source_evidence_class)
}

pub(super) fn validate_source_checkpoint_body(
    body: &FinancialSourceCheckpointBodyV1,
    now: u64,
) -> Result<(), FinancialCredentialProjectionError> {
    for value in [
        body.checkpoint_authority_epoch,
        body.store_generation,
        body.checkpoint_sequence,
        body.cutoff,
        body.window.starts_at,
        body.window.ends_at,
        body.index_size,
        body.issued_at,
        body.expires_at,
        now,
    ] {
        ensure_i_json(value)?;
    }
    if !valid_identifier(&body.source_id)
        || body.checkpoint_authority_epoch == 0
        || body.store_generation == 0
        || body.checkpoint_sequence == 0
        || body.index_size == 0
        || body.window.starts_at >= body.window.ends_at
        || body.cutoff != body.window.ends_at
        || !valid_digest(&body.range_root)
        || !valid_digest(&body.index_root)
    {
        return Err(FinancialCredentialProjectionError::InvalidSourceAuthority);
    }
    if body.issued_at < body.cutoff
        || body.issued_at >= body.expires_at
        || now < body.issued_at
        || now >= body.expires_at
    {
        return Err(FinancialCredentialProjectionError::StaleSourceAttestation);
    }
    Ok(())
}

fn verify_committed_leaf_proof(
    committed: &FinancialSourceCommittedLeafProofV1,
    index_root: &Hash,
    index_size: u64,
) -> Result<(), FinancialCredentialProjectionError> {
    ensure_i_json(committed.leaf.index)?;
    ensure_i_json(committed.index_proof.tree_size)?;
    ensure_i_json(committed.index_proof.leaf_index)?;
    ensure_i_json(committed.leaf.query_key.occurred_at)?;
    if !valid_identifier(&committed.leaf.query_key.subject)
        || !valid_identifier(&committed.leaf.query_key.artifact_id)
        || !valid_digest(&committed.leaf.source_artifact_digest)
        || committed.index_proof.tree_size != index_size
        || committed.index_proof.leaf_index != committed.leaf.index
        || committed.index_proof.audit_path.len() > 64
    {
        return Err(FinancialCredentialProjectionError::InvalidSourceAttestationBinding);
    }
    let proof = MerkleProof {
        tree_size: usize::try_from(committed.index_proof.tree_size)
            .map_err(|_| FinancialCredentialProjectionError::IJsonIntegerOutOfRange)?,
        leaf_index: usize::try_from(committed.index_proof.leaf_index)
            .map_err(|_| FinancialCredentialProjectionError::IJsonIntegerOutOfRange)?,
        audit_path: committed
            .index_proof
            .audit_path
            .iter()
            .map(|hash| {
                Hash::from_hex(hash).map_err(|_| {
                    FinancialCredentialProjectionError::InvalidSourceAttestationBinding
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    let leaf = canonical_json_bytes(&committed.leaf)
        .map_err(|error| FinancialCredentialProjectionError::InvalidSource(error.to_string()))?;
    if !proof.verify(&leaf, index_root) {
        return Err(FinancialCredentialProjectionError::InvalidSourceAttestationBinding);
    }
    Ok(())
}

pub(super) fn verify_completeness_boundary(
    boundary: &FinancialSourceCompletenessBoundaryV1,
    range_index: u64,
    range_key: &FinancialSourceQueryKeyV1,
    lower: bool,
    index_root: &Hash,
    index_size: u64,
    request: &FinancialSourceCompletenessAttestationRequestV1,
) -> Result<(), FinancialCredentialProjectionError> {
    match boundary {
        FinancialSourceCompletenessBoundaryV1::SourceEdge => {
            let at_edge = if lower {
                range_index == 0
            } else {
                range_index
                    .checked_add(1)
                    .is_some_and(|next| next == index_size)
            };
            if !at_edge {
                return Err(FinancialCredentialProjectionError::InvalidSourceAttestationBinding);
            }
        }
        FinancialSourceCompletenessBoundaryV1::Adjacent { leaf_proof } => {
            verify_committed_leaf_proof(leaf_proof, index_root, index_size)?;
            let expected = if lower {
                leaf_proof.leaf.index.checked_add(1)
            } else {
                range_index.checked_add(1)
            };
            let actual = if lower {
                range_index
            } else {
                leaf_proof.leaf.index
            };
            let correctly_ordered = if lower {
                leaf_proof.leaf.query_key < *range_key
            } else {
                leaf_proof.leaf.query_key > *range_key
            };
            if expected != Some(actual)
                || !correctly_ordered
                || query_key_in_requested_range(&leaf_proof.leaf.query_key, request)
            {
                return Err(FinancialCredentialProjectionError::InvalidSourceAttestationBinding);
            }
        }
    }
    Ok(())
}

fn query_key_in_requested_range(
    query_key: &FinancialSourceQueryKeyV1,
    request: &FinancialSourceCompletenessAttestationRequestV1,
) -> bool {
    query_key.source_family == request.source_family
        && query_key.subject == request.subject
        && query_key.occurred_at >= request.window.starts_at
        && query_key.occurred_at < request.window.ends_at
}

pub(super) fn prepare_request(
    source_family: FinancialCredentialFamilyV1,
    subject: String,
    source_signer_key: PublicKey,
    window: FinancialCredentialWindowV1,
    mut artifacts: Vec<FinancialSourceBundleArtifactV1>,
    maximum_source_evidence_class: ProvenanceEvidenceClass,
    mut expected_members: Vec<FinancialSourceExpectedMemberV1>,
) -> Result<FinancialSourceCompletenessAttestationRequestV1, FinancialCredentialProjectionError> {
    let cutoff = window.ends_at;
    if artifacts.is_empty() || artifacts.len() > MAX_SOURCE_ARTIFACTS {
        return Err(FinancialCredentialProjectionError::IncompleteSource);
    }
    ensure_i_json(cutoff)?;
    ensure_i_json(window.starts_at)?;
    ensure_i_json(window.ends_at)?;
    let member_count = count_i_json(expected_members.len())?;
    if window.starts_at >= window.ends_at || cutoff != window.ends_at || member_count == 0 {
        return Err(FinancialCredentialProjectionError::IncompleteSource);
    }
    artifacts.sort_by(|left, right| left.artifact_digest.cmp(&right.artifact_digest));
    if artifacts
        .windows(2)
        .any(|pair| pair[0].artifact_digest == pair[1].artifact_digest)
    {
        return Err(FinancialCredentialProjectionError::IncompleteSource);
    }
    expected_members.sort_by(|left, right| left.query_key.cmp(&right.query_key));
    if expected_members.windows(2).any(|pair| {
        pair[0].query_key >= pair[1].query_key
            || pair[0].source_artifact_digest == pair[1].source_artifact_digest
    }) || expected_members.iter().any(|member| {
        member.query_key.source_family != source_family
            || member.query_key.subject != subject
            || member.query_key.occurred_at < window.starts_at
            || member.query_key.occurred_at >= window.ends_at
    }) {
        return Err(FinancialCredentialProjectionError::IncompleteSource);
    }
    let bundled_member_digests = artifacts
        .iter()
        .filter(|artifact| artifact.role == FinancialSourceArtifactRoleV1::Member)
        .map(|artifact| artifact.artifact_digest.as_str())
        .collect::<BTreeSet<_>>();
    let expected_member_digests = expected_members
        .iter()
        .map(|member| member.source_artifact_digest.as_str())
        .collect::<BTreeSet<_>>();
    if bundled_member_digests != expected_member_digests
        || bundled_member_digests.len() != expected_members.len()
    {
        return Err(FinancialCredentialProjectionError::IncompleteSource);
    }
    let source_artifact_digests = artifacts
        .iter()
        .map(|artifact| artifact.artifact_digest.clone())
        .collect::<Vec<_>>();
    let disclosure = FinancialSourceDisclosureV1::Bundled { artifacts };
    let disclosure_digest = domain_digest(
        SOURCE_DISCLOSURE_DIGEST_DOMAIN,
        &canonical_json_bytes(&disclosure).map_err(|error| {
            FinancialCredentialProjectionError::InvalidSource(error.to_string())
        })?,
    );
    let validated = validate_financial_source_disclosure(
        source_family,
        &subject,
        &source_signer_key,
        &disclosure,
    )?;
    if validated.source_artifact_digests != source_artifact_digests
        || validated.expected_members != expected_members
        || evidence_class_rank(validated.source_evidence_class)
            > evidence_class_rank(maximum_source_evidence_class)
    {
        return Err(FinancialCredentialProjectionError::InvalidSourceAttestationBinding);
    }
    Ok(FinancialSourceCompletenessAttestationRequestV1 {
        source_family,
        subject,
        source_signer_key,
        cutoff,
        window,
        source_artifact_digests,
        disclosure,
        disclosure_digest,
        maximum_source_evidence_class,
        expected_members,
    })
}
