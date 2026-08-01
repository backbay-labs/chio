use super::*;

pub(super) fn validate_evidence_classes(
    credential: &FinancialCredentialEnvelope,
) -> Result<(), CredentialError> {
    use chio_core::capability::governance::ProvenanceEvidenceClass;

    if credential.presentation_evidence_class != ProvenanceEvidenceClass::Asserted {
        return invalid_financial("financial presentation evidence class must be asserted");
    }
    let maximum = match &credential.credential_subject {
        FinancialCredentialSubjectV1::CreditScorecard(subject)
            if subject.imported_signals.accepted_imported_signal_count > 0 =>
        {
            ProvenanceEvidenceClass::Asserted
        }
        FinancialCredentialSubjectV1::SettlementReliability(_)
        | FinancialCredentialSubjectV1::LossHistory(_) => ProvenanceEvidenceClass::Observed,
        _ => ProvenanceEvidenceClass::Verified,
    };
    if evidence_class_rank(credential.source_evidence_class) > evidence_class_rank(maximum) {
        return invalid_financial("financial source evidence class exceeds its family ceiling");
    }
    Ok(())
}

pub(super) fn validate_financial_subject(
    subject: &FinancialCredentialSubjectV1,
) -> Result<(), CredentialError> {
    validate_text("credentialSubject.id", subject.id())?;
    DidChio::from_str(subject.id())?;
    match subject {
        FinancialCredentialSubjectV1::CreditScorecard(subject) => {
            if !subject.overall_score.is_finite() || !(0.0..=1.0).contains(&subject.overall_score) {
                return invalid_financial("overall score must be finite and within [0, 1]");
            }
            if subject.imported_signals.accepted_imported_signal_count
                > subject.imported_signals.imported_signal_count
            {
                return invalid_financial(
                    "accepted imported signal count exceeds imported signal count",
                );
            }
            validate_time(
                "credentialSubject.importedSignals.importedSignalCount",
                subject.imported_signals.imported_signal_count,
            )?;
            validate_time(
                "credentialSubject.importedSignals.acceptedImportedSignalCount",
                subject.imported_signals.accepted_imported_signal_count,
            )?;
        }
        FinancialCredentialSubjectV1::ExposureHistory(subject) => {
            validate_money_groups(&subject.positions)?;
        }
        FinancialCredentialSubjectV1::SettlementReliability(subject) => {
            validate_time("credentialSubject.onTimeCount", subject.on_time_count)?;
            validate_time(
                "credentialSubject.obligationCount",
                subject.obligation_count,
            )?;
            if subject.obligation_count == 0 {
                return invalid_financial("settlement reliability requires a nonzero denominator");
            }
            if subject.on_time_count > subject.obligation_count {
                return invalid_financial("on-time count exceeds obligation count");
            }
            let numerator = u128::from(subject.on_time_count)
                .checked_mul(10_000)
                .ok_or_else(|| invalid_financial_error("settlement ratio overflow"))?;
            let expected = numerator / u128::from(subject.obligation_count);
            if u128::from(subject.on_time_ratio_bps) != expected {
                return invalid_financial("settlement reliability ratio does not match counts");
            }
        }
        FinancialCredentialSubjectV1::PremiumHistory(subject) => {
            validate_time("credentialSubject.quotedCount", subject.quoted_count)?;
            if subject.quoted_count == 0 {
                return invalid_financial("premium history requires at least one quote");
            }
            validate_amounts(&subject.quoted_amounts, false)?;
        }
        FinancialCredentialSubjectV1::LossHistory(subject) => {
            for (field, value) in [
                ("delinquencyCount", subject.delinquency_count),
                ("recoveryCount", subject.recovery_count),
                ("reserveReleaseCount", subject.reserve_release_count),
                ("reserveSlashCount", subject.reserve_slash_count),
                ("writeOffCount", subject.write_off_count),
            ] {
                validate_time(field, value)?;
            }
            validate_amounts(&subject.outstanding_amounts, true)?;
        }
    }
    Ok(())
}

pub(super) fn validate_financial_evidence(
    credential: &FinancialCredentialEnvelope,
    credential_issued_at: u64,
    credential_expires_at: u64,
) -> Result<(), CredentialError> {
    let evidence = &credential.evidence;
    validate_time("evidence.window.startsAt", evidence.window.starts_at)?;
    validate_time("evidence.window.endsAt", evidence.window.ends_at)?;
    if evidence.window.starts_at >= evidence.window.ends_at {
        return invalid_financial("financial evidence window is empty or inverted");
    }
    if matches!(
        &evidence.source_disclosure,
        FinancialSourceDisclosureV1::Resolver { .. }
    ) {
        return Err(CredentialError::FinancialSourceResolverUnavailable);
    }
    let disclosure_digests = validate_financial_source_disclosure(&evidence.source_disclosure)?;
    if evidence.source_completeness_attestations.is_empty()
        || evidence.source_completeness_attestations.len() > MAX_FINANCIAL_BOUNDARY_PROOFS
    {
        return invalid_financial("financial source completeness attestation count is invalid");
    }
    let disclosure_digest = domain_digest(
        FINANCIAL_SOURCE_DISCLOSURE_DIGEST_DOMAIN,
        &evidence.source_disclosure,
    )?;
    let mut covered_digests = BTreeSet::new();
    let mut attestation_keys = BTreeSet::new();
    for attestation in &evidence.source_completeness_attestations {
        let body = &attestation.body;
        if body.schema != FINANCIAL_SOURCE_COMPLETENESS_ATTESTATION_SCHEMA_V1
            || body.source_family != credential.family
            || body.subject != credential.credential_subject.id()
            || body.window != evidence.window
            || body.disclosure_digest != disclosure_digest
            || body.checkpoint_authority_key != attestation.signer_key
        {
            return invalid_financial(
                "financial source completeness attestation binding is invalid",
            );
        }
        let validated_disclosure =
            chio_credit::financial_credentials::validate_financial_source_disclosure(
                credential.family,
                credential.credential_subject.id(),
                &body.source_signer_key,
                &evidence.source_disclosure,
            )
            .map_err(|error| invalid_financial_error(error.to_string()))?;
        for (field, value) in [
            ("checkpointAuthorityEpoch", body.checkpoint_authority_epoch),
            ("storeGeneration", body.store_generation),
            ("checkpointSequence", body.checkpoint_sequence),
            ("cutoff", body.cutoff),
            ("window.startsAt", body.window.starts_at),
            ("window.endsAt", body.window.ends_at),
            ("issuedAt", body.issued_at),
            ("expiresAt", body.expires_at),
        ] {
            validate_time(field, value)?;
        }
        if body.checkpoint_authority_epoch == 0
            || body.store_generation == 0
            || body.checkpoint_sequence == 0
            || body.committed_leaves.is_empty()
            || body.committed_leaves.len() > MAX_FINANCIAL_SOURCE_ARTIFACTS
            || body.cutoff != body.window.ends_at
            || body.issued_at < body.cutoff
            || body.issued_at >= body.expires_at
            || credential_issued_at < body.issued_at
            || credential_issued_at >= body.expires_at
            || credential_expires_at > body.expires_at
        {
            return invalid_financial(
                "financial source completeness attestation validity is invalid",
            );
        }
        validate_text("sourceAttestation.sourceId", &body.source_id)?;
        validate_text(
            "sourceAttestation.attestationReference",
            &body.attestation_reference,
        )?;
        validate_digest(
            "sourceAttestation.checkpointDigest",
            &body.checkpoint_digest,
        )?;
        validate_digest("sourceAttestation.rangeRoot", &body.range_root)?;
        validate_digest("sourceAttestation.indexRoot", &body.index_root)?;
        validate_digest(
            "sourceAttestation.disclosureDigest",
            &body.disclosure_digest,
        )?;
        validate_digest_set(
            "sourceAttestation.sourceArtifactDigests",
            &body.source_artifact_digests,
            MAX_FINANCIAL_SOURCE_ARTIFACTS,
        )?;
        let index_size = body
            .committed_leaves
            .first()
            .ok_or_else(|| invalid_financial_error("financial source range is empty"))?
            .index_proof
            .tree_size;
        let index_root = chio_core::Hash::from_hex(&body.index_root)?;
        if body.committed_leaves.len() != validated_disclosure.expected_members().len() {
            return invalid_financial("financial source member count is inconsistent");
        }
        let mut previous_index = None;
        let mut previous_query_key = None;
        let mut range_leaves = Vec::with_capacity(body.committed_leaves.len());
        let mut attested_artifacts = BTreeSet::new();
        for (committed, expected) in body
            .committed_leaves
            .iter()
            .zip(validated_disclosure.expected_members())
        {
            validate_financial_committed_leaf_proof(committed, &index_root, index_size)?;
            if previous_index.is_some_and(|index| index + 1 != committed.leaf.index)
                || previous_query_key
                    .as_ref()
                    .is_some_and(|key| key >= &committed.leaf.query_key)
                || committed.leaf.query_key != expected.query_key
                || committed.leaf.source_artifact_digest != expected.source_artifact_digest
                || committed.leaf.query_key.source_family != credential.family
                || committed.leaf.query_key.subject != credential.credential_subject.id()
                || committed.leaf.query_key.occurred_at < evidence.window.starts_at
                || committed.leaf.query_key.occurred_at >= evidence.window.ends_at
            {
                return invalid_financial("financial source committed leaves contain a gap");
            }
            previous_index = Some(committed.leaf.index);
            previous_query_key = Some(committed.leaf.query_key.clone());
            attested_artifacts.insert(committed.leaf.source_artifact_digest.clone());
            range_leaves.push(canonical_json_bytes(&committed.leaf)?);
        }
        let range_tree = chio_core::MerkleTree::from_leaves(&range_leaves)?;
        if range_tree.root().to_hex() != body.range_root
            || validated_disclosure.source_evidence_class() != body.source_evidence_class
            || validated_disclosure.source_evidence_class() != credential.source_evidence_class
        {
            return invalid_financial("financial source range derivation is inconsistent");
        }
        let first_index = body
            .committed_leaves
            .first()
            .ok_or_else(|| invalid_financial_error("financial source range is empty"))?
            .leaf
            .index;
        let first_key = &body
            .committed_leaves
            .first()
            .ok_or_else(|| invalid_financial_error("financial source range is empty"))?
            .leaf
            .query_key;
        let last_index = body
            .committed_leaves
            .last()
            .ok_or_else(|| invalid_financial_error("financial source range is empty"))?
            .leaf
            .index;
        let last_key = &body
            .committed_leaves
            .last()
            .ok_or_else(|| invalid_financial_error("financial source range is empty"))?
            .leaf
            .query_key;
        let boundary_context = FinancialCompletenessBoundaryContext {
            index_root: &index_root,
            index_size,
            source_family: credential.family,
            subject: credential.credential_subject.id(),
            window: &evidence.window,
        };
        validate_financial_completeness_boundary(
            &body.lower_boundary,
            first_index,
            first_key,
            true,
            &boundary_context,
        )?;
        validate_financial_completeness_boundary(
            &body.upper_boundary,
            last_index,
            last_key,
            false,
            &boundary_context,
        )?;
        let declared_artifacts = body
            .source_artifact_digests
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let expected_member_artifacts = validated_disclosure
            .expected_members()
            .iter()
            .map(|member| member.source_artifact_digest.clone())
            .collect::<BTreeSet<_>>();
        if body.source_artifact_digests != validated_disclosure.source_artifact_digests()
            || attested_artifacts != expected_member_artifacts
        {
            return invalid_financial("financial source artifact coverage is inconsistent");
        }
        for digest in declared_artifacts {
            if !disclosure_digests.contains(&digest) || !covered_digests.insert(digest) {
                return invalid_financial(
                    "financial source completeness attestation coverage is invalid",
                );
            }
        }
        if !attestation_keys.insert((
            body.source_id.as_str(),
            body.store_generation,
            body.checkpoint_sequence,
        )) {
            return invalid_financial(
                "financial evidence contains duplicate source completeness attestations",
            );
        }
        if !attestation.verify_signature()? {
            return Err(CredentialError::InvalidCredentialSignature);
        }
    }
    if covered_digests != disclosure_digests {
        return invalid_financial(
            "financial source completeness attestation does not cover its disclosure",
        );
    }
    validate_bundled_source_signers(evidence)?;
    Ok(())
}

fn validate_financial_source_disclosure(
    disclosure: &FinancialSourceDisclosureV1,
) -> Result<BTreeSet<String>, CredentialError> {
    match disclosure {
        FinancialSourceDisclosureV1::Bundled { artifacts } => {
            if artifacts.is_empty() || artifacts.len() > MAX_FINANCIAL_SOURCE_ARTIFACTS {
                return invalid_financial("financial source bundle count is invalid");
            }
            let mut total_bytes = 0_usize;
            let mut previous = None;
            let mut digests = BTreeSet::new();
            for artifact in artifacts {
                validate_text("sourceArtifact.artifactSchema", &artifact.artifact_schema)?;
                validate_digest("sourceArtifact.artifactDigest", &artifact.artifact_digest)?;
                let bytes = artifact.canonical_artifact.as_bytes();
                total_bytes = total_bytes
                    .checked_add(bytes.len())
                    .ok_or_else(|| invalid_financial_error("financial source bundle overflows"))?;
                if bytes.is_empty()
                    || bytes.len() > MAX_FINANCIAL_SOURCE_ARTIFACT_BYTES
                    || total_bytes > MAX_FINANCIAL_SOURCE_BUNDLE_BYTES
                {
                    return invalid_financial("financial source bundle size is invalid");
                }
                let value: serde_json::Value = serde_json::from_slice(bytes)
                    .map_err(|error| invalid_financial_error(error.to_string()))?;
                if canonical_json_bytes(&value)? != bytes
                    || domain_digest_bytes(FINANCIAL_SOURCE_ARTIFACT_DIGEST_DOMAIN, bytes)
                        != artifact.artifact_digest
                    || value
                        .get("body")
                        .and_then(|body| body.get("schema"))
                        .and_then(serde_json::Value::as_str)
                        != Some(artifact.artifact_schema.as_str())
                {
                    return invalid_financial("financial source artifact binding is invalid");
                }
                if previous.is_some_and(|prior: &String| prior >= &artifact.artifact_digest)
                    || !digests.insert(artifact.artifact_digest.clone())
                {
                    return invalid_financial(
                        "financial source artifacts must be sorted and unique",
                    );
                }
                previous = Some(&artifact.artifact_digest);
            }
            Ok(digests)
        }
        FinancialSourceDisclosureV1::Resolver { .. } => {
            Err(CredentialError::FinancialSourceResolverUnavailable)
        }
    }
}

fn validate_bundled_source_signers(
    evidence: &FinancialCredentialEvidenceV1,
) -> Result<(), CredentialError> {
    let FinancialSourceDisclosureV1::Bundled { artifacts } = &evidence.source_disclosure else {
        return Ok(());
    };
    for artifact in artifacts {
        let value: serde_json::Value = serde_json::from_str(&artifact.canonical_artifact)
            .map_err(|error| invalid_financial_error(error.to_string()))?;
        let signer = value
            .get("signerKey")
            .ok_or_else(|| invalid_financial_error("bundled source signer is missing"))?;
        let matching_proof = evidence
            .source_completeness_attestations
            .iter()
            .find(|proof| {
                proof
                    .body
                    .source_artifact_digests
                    .contains(&artifact.artifact_digest)
            });
        let Some(proof) = matching_proof else {
            return invalid_financial("bundled source artifact has no proof");
        };
        let expected_signer = serde_json::to_value(&proof.body.source_signer_key)
            .map_err(|error| invalid_financial_error(error.to_string()))?;
        if signer != &expected_signer {
            return invalid_financial(
                "bundled source signer does not match its source completeness attestation",
            );
        }
        let signature_valid = match artifact.artifact_schema.as_str() {
            chio_credit::CREDIT_SCORECARD_SCHEMA => {
                serde_json::from_value::<chio_credit::SignedCreditScorecardReport>(value)
                    .map_err(|error| invalid_financial_error(error.to_string()))?
                    .verify_signature()?
            }
            chio_credit::EXPOSURE_LEDGER_SCHEMA => {
                serde_json::from_value::<chio_credit::SignedExposureLedgerReport>(value)
                    .map_err(|error| invalid_financial_error(error.to_string()))?
                    .verify_signature()?
            }
            chio_credit::underwriting::UNDERWRITING_DECISION_ARTIFACT_SCHEMA => {
                serde_json::from_value::<chio_credit::underwriting::SignedUnderwritingDecision>(
                    value,
                )
                .map_err(|error| invalid_financial_error(error.to_string()))?
                .verify_signature()?
            }
            chio_credit::CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA => {
                serde_json::from_value::<chio_credit::SignedCreditLossLifecycle>(value)
                    .map_err(|error| invalid_financial_error(error.to_string()))?
                    .verify_signature()?
            }
            FINANCIAL_SOURCE_MEMBER_SCHEMA_V1 => {
                serde_json::from_value::<SignedFinancialSourceMemberV1>(value)
                    .map_err(|error| invalid_financial_error(error.to_string()))?
                    .verify_signature()?
            }
            _ => return invalid_financial("bundled source artifact schema is unsupported"),
        };
        if !signature_valid {
            return Err(CredentialError::InvalidCredentialSignature);
        }
    }
    Ok(())
}

fn validate_financial_committed_leaf_proof(
    committed: &FinancialSourceCommittedLeafProofV1,
    index_root: &chio_core::Hash,
    index_size: u64,
) -> Result<(), CredentialError> {
    validate_time("sourceLeaf.index", committed.leaf.index)?;
    validate_time(
        "sourceLeaf.indexProof.treeSize",
        committed.index_proof.tree_size,
    )?;
    validate_time(
        "sourceLeaf.indexProof.leafIndex",
        committed.index_proof.leaf_index,
    )?;
    validate_time(
        "sourceLeaf.queryKey.occurredAt",
        committed.leaf.query_key.occurred_at,
    )?;
    validate_text(
        "sourceLeaf.queryKey.subject",
        &committed.leaf.query_key.subject,
    )?;
    validate_text(
        "sourceLeaf.queryKey.artifactId",
        &committed.leaf.query_key.artifact_id,
    )?;
    validate_digest(
        "sourceLeaf.sourceArtifactDigest",
        &committed.leaf.source_artifact_digest,
    )?;
    if committed.index_proof.tree_size != index_size
        || committed.index_proof.leaf_index != committed.leaf.index
        || committed.index_proof.audit_path.len() > 64
    {
        return invalid_financial("financial source index proof binding is invalid");
    }
    let proof = chio_core::MerkleProof {
        tree_size: usize::try_from(committed.index_proof.tree_size)
            .map_err(|_| invalid_financial_error("financial source tree size overflows"))?,
        leaf_index: usize::try_from(committed.index_proof.leaf_index)
            .map_err(|_| invalid_financial_error("financial source leaf index overflows"))?,
        audit_path: committed
            .index_proof
            .audit_path
            .iter()
            .map(|hash| chio_core::Hash::from_hex(hash))
            .collect::<Result<Vec<_>, _>>()?,
    };
    if !proof.verify(&canonical_json_bytes(&committed.leaf)?, index_root) {
        return invalid_financial("financial source index proof is invalid");
    }
    Ok(())
}

struct FinancialCompletenessBoundaryContext<'a> {
    index_root: &'a chio_core::Hash,
    index_size: u64,
    source_family: FinancialCredentialFamilyV1,
    subject: &'a str,
    window: &'a FinancialCredentialWindowV1,
}

fn validate_financial_completeness_boundary(
    boundary: &FinancialSourceCompletenessBoundaryV1,
    range_index: u64,
    range_key: &FinancialSourceQueryKeyV1,
    lower: bool,
    context: &FinancialCompletenessBoundaryContext<'_>,
) -> Result<(), CredentialError> {
    match boundary {
        FinancialSourceCompletenessBoundaryV1::SourceEdge => {
            let at_edge = if lower {
                range_index == 0
            } else {
                range_index
                    .checked_add(1)
                    .is_some_and(|next| next == context.index_size)
            };
            if !at_edge {
                return invalid_financial("financial source boundary edge is invalid");
            }
        }
        FinancialSourceCompletenessBoundaryV1::Adjacent { leaf_proof } => {
            validate_financial_committed_leaf_proof(
                leaf_proof,
                context.index_root,
                context.index_size,
            )?;
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
            let adjacent_in_range = leaf_proof.leaf.query_key.source_family
                == context.source_family
                && leaf_proof.leaf.query_key.subject == context.subject
                && leaf_proof.leaf.query_key.occurred_at >= context.window.starts_at
                && leaf_proof.leaf.query_key.occurred_at < context.window.ends_at;
            if expected != Some(actual) || !correctly_ordered || adjacent_in_range {
                return invalid_financial("financial source adjacent boundary is invalid");
            }
        }
    }
    Ok(())
}

const fn evidence_class_rank(
    class: chio_core::capability::governance::ProvenanceEvidenceClass,
) -> u8 {
    use chio_core::capability::governance::ProvenanceEvidenceClass;
    match class {
        ProvenanceEvidenceClass::Asserted => 0,
        ProvenanceEvidenceClass::Observed => 1,
        ProvenanceEvidenceClass::Verified => 2,
    }
}

fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String, CredentialError> {
    let canonical = canonical_json_bytes(value)?;
    Ok(domain_digest_bytes(domain, &canonical))
}

fn domain_digest_bytes(domain: &[u8], canonical: &[u8]) -> String {
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(canonical);
    sha256_hex(&preimage)
}

fn validate_money_groups(groups: &[ExposureHistoryPositionV1]) -> Result<(), CredentialError> {
    if groups.is_empty() || groups.len() > MAX_FINANCIAL_POSITIONS {
        return invalid_financial("exposure history position count is invalid");
    }
    let mut currencies = BTreeSet::new();
    for group in groups {
        let amounts = [
            &group.governed_max,
            &group.reserved,
            &group.settled,
            &group.pending,
            &group.failed,
            &group.provisional_loss,
            &group.recovered,
        ];
        for amount in amounts {
            validate_money(amount)?;
            if amount.currency != group.governed_max.currency {
                return invalid_financial("exposure history position mixes currencies");
            }
        }
        if !currencies.insert(group.governed_max.currency.as_str()) {
            return invalid_financial("exposure history contains duplicate currencies");
        }
    }
    Ok(())
}

fn validate_amounts(
    amounts: &[chio_core::capability::scope::MonetaryAmount],
    allow_empty: bool,
) -> Result<(), CredentialError> {
    if (!allow_empty && amounts.is_empty()) || amounts.len() > MAX_FINANCIAL_POSITIONS {
        return invalid_financial("financial monetary aggregate count is invalid");
    }
    let mut currencies = BTreeSet::new();
    for amount in amounts {
        validate_money(amount)?;
        if !currencies.insert(amount.currency.as_str()) {
            return invalid_financial("financial monetary aggregates contain duplicate currencies");
        }
    }
    Ok(())
}

fn validate_money(
    amount: &chio_core::capability::scope::MonetaryAmount,
) -> Result<(), CredentialError> {
    if amount.currency.len() != 3
        || !amount
            .currency
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
    {
        return invalid_financial("financial amount currency must be uppercase ISO 4217");
    }
    validate_time("financialAmount.units", amount.units)?;
    Ok(())
}

fn validate_digest_set(
    field: &str,
    values: &[String],
    maximum: usize,
) -> Result<(), CredentialError> {
    if values.is_empty() || values.len() > maximum {
        return invalid_financial(format!("{field} count is invalid"));
    }
    let mut previous = None;
    for value in values {
        validate_digest(field, value)?;
        if previous.is_some_and(|prior: &String| prior >= value) {
            return invalid_financial(format!("{field} must be sorted and unique"));
        }
        previous = Some(value);
    }
    Ok(())
}

pub(super) fn validate_digest(field: &str, value: &str) -> Result<(), CredentialError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid_financial(format!("{field} must be a lowercase SHA-256 digest"));
    }
    Ok(())
}

pub(super) fn validate_text(field: &str, value: &str) -> Result<(), CredentialError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > MAX_FINANCIAL_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return invalid_financial(format!("{field} is invalid"));
    }
    Ok(())
}

pub(super) fn validate_time(field: &str, value: u64) -> Result<(), CredentialError> {
    if value > I_JSON_MAX_SAFE_INTEGER {
        return invalid_financial(format!("{field} exceeds the I-JSON integer range"));
    }
    Ok(())
}

pub(super) fn invalid_financial<T>(reason: impl Into<String>) -> Result<T, CredentialError> {
    Err(invalid_financial_error(reason))
}

pub(super) fn invalid_financial_error(reason: impl Into<String>) -> CredentialError {
    CredentialError::InvalidFinancialCredential(reason.into())
}
