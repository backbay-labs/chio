use super::error::map_bilateral_error;
use super::support::{
    canonical_json_string, is_sha256_hex, receipt_canonical_digest_hex, validate_hash_record,
    validate_policy_verdict, validate_verdict_string,
};
use super::treaty::{
    resolve_governance_receipt_ref, validate_predicate_operational_refs_match_treaty,
    validate_treaty_binding_ref_for_review, validate_treaty_receipt_refs_match_resolved_receipt,
};
use super::*;

pub fn verify_chio_bilateral_invocation(
    envelope: &DsseEnvelope,
    config: &ChioBilateralVerifierConfig<'_, '_>,
) -> Result<VerifiedBilateralCoSignInvocation, VerifierError> {
    verify_chio_bilateral_invocation_inner(envelope, config, None)
}

pub fn verify_chio_bilateral_invocation_with_frost(
    envelope: &DsseEnvelope,
    config: &ChioBilateralVerifierConfig<'_, '_>,
    authorization: &crate::frost::VerifiedFrostAuthorization,
) -> Result<VerifiedBilateralCoSignInvocation, VerifierError> {
    verify_chio_bilateral_invocation_inner(envelope, config, Some(authorization))
}

fn verify_chio_bilateral_invocation_inner(
    envelope: &DsseEnvelope,
    config: &ChioBilateralVerifierConfig<'_, '_>,
    frost_authorization: Option<&crate::frost::VerifiedFrostAuthorization>,
) -> Result<VerifiedBilateralCoSignInvocation, VerifierError> {
    if envelope.payload_type != crate::bilateral_dsse::PAYLOAD_TYPE_IN_TOTO {
        return Err(VerifierError::DsseMalformed(format!(
            "payloadType {:?} is not application/vnd.in-toto+json",
            envelope.payload_type
        )));
    }
    if envelope.signatures.is_empty() {
        return Err(VerifierError::DsseMalformed(
            "signatures array is empty".to_string(),
        ));
    }

    let (statement, _) = envelope.decode_statement().map_err(map_bilateral_error)?;
    if statement.predicate_type != PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION {
        return Err(VerifierError::PredicateTypeUnrecognised(format!(
            "signature-slice profile {:?} is not strict Chio {:?}",
            statement.predicate_type, PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION
        )));
    }
    if statement.statement_type != STATEMENT_TYPE_V1 {
        return Err(VerifierError::StatementSchemaInvalid(format!(
            "_type {:?} is not {:?}",
            statement.statement_type, STATEMENT_TYPE_V1
        )));
    }
    if statement.subject.len() != 1 {
        return Err(VerifierError::StatementSchemaInvalid(format!(
            "statement.malformed: bilateral envelope must carry exactly 1 subject, got {}",
            statement.subject.len()
        )));
    }

    let pred = &statement.predicate;
    let pinned_a = config
        .base
        .peer_pin_set
        .lookup(&pred.tool_server_a.kernel_id)
        .ok_or_else(|| {
            VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
                "tool_server_a kernel_id {:?} not pinned",
                pred.tool_server_a.kernel_id
            ))
        })?;
    if pinned_a.fingerprint().0 != pred.tool_server_a.passport_key_fingerprint.0 {
        return Err(VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
            "tool_server_a fingerprint mismatch: pinned={} predicate={}",
            pinned_a.fingerprint().0,
            pred.tool_server_a.passport_key_fingerprint.0
        )));
    }
    let pinned_b = config
        .base
        .peer_pin_set
        .lookup(&pred.tool_server_b.kernel_id)
        .ok_or_else(|| {
            VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
                "tool_server_b kernel_id {:?} not pinned",
                pred.tool_server_b.kernel_id
            ))
        })?;
    if pinned_b.fingerprint().0 != pred.tool_server_b.passport_key_fingerprint.0 {
        return Err(VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
            "tool_server_b fingerprint mismatch: pinned={} predicate={}",
            pinned_b.fingerprint().0,
            pred.tool_server_b.passport_key_fingerprint.0
        )));
    }

    let statement = match frost_authorization {
        Some(authorization) => {
            crate::bilateral_dsse::verify_chio_bilateral_dsse_envelope_with_frost(
                envelope,
                &pinned_a.public_key,
                &pinned_b.public_key,
                authorization,
            )
        }
        None => verify_chio_bilateral_dsse_envelope(
            envelope,
            &pinned_a.public_key,
            &pinned_b.public_key,
        ),
    }
    .map_err(map_bilateral_error)?;
    let pred = &statement.predicate;

    require_fresh_ladder_manifest(config.base, &pred.tool_server_a.kernel_id, "tool_server_a")?;
    require_fresh_ladder_manifest(config.base, &pred.tool_server_b.kernel_id, "tool_server_b")?;

    if !config.base.revocation_oracle.is_active_at_epoch(
        &pinned_a.fingerprint(),
        config.base.pinned_epoch.epoch_height,
    ) {
        return Err(VerifierError::PeerRevokedAtEpoch(format!(
            "tool_server_a {} revoked at epoch {}",
            pred.tool_server_a.kernel_id, config.base.pinned_epoch.epoch_height
        )));
    }
    if !config.base.revocation_oracle.is_active_at_epoch(
        &pinned_b.fingerprint(),
        config.base.pinned_epoch.epoch_height,
    ) {
        return Err(VerifierError::PeerRevokedAtEpoch(format!(
            "tool_server_b {} revoked at epoch {}",
            pred.tool_server_b.kernel_id, config.base.pinned_epoch.epoch_height
        )));
    }

    let resolved_receipt = config
        .base
        .receipt_store
        .resolve(&pred.invocation_id)
        .ok_or_else(|| {
            VerifierError::SubjectDigestMismatch(format!(
                "invocation_id {:?} not resolvable in ReceiptStore",
                pred.invocation_id
            ))
        })?;
    let resolved_receipt_signature_valid = resolved_receipt
        .verify_signature()
        .map_err(|e| VerifierError::SubjectDigestMismatch(format!("receipt signature: {e}")))?;
    if !resolved_receipt_signature_valid {
        return Err(VerifierError::SubjectDigestMismatch(
            "resolved receipt signature is invalid".to_string(),
        ));
    }
    if pred.tool_name != resolved_receipt.tool_name {
        return Err(VerifierError::SubjectDigestMismatch(format!(
            "predicate tool_name {:?} != resolved receipt tool_name {:?}",
            pred.tool_name, resolved_receipt.tool_name
        )));
    }
    if resolved_receipt.kernel_key != pinned_b.public_key {
        return Err(VerifierError::PeerUnpinnedOrKeyidMismatch(
            "resolved receipt kernel_key does not match pinned tool_server_b key".to_string(),
        ));
    }
    if pred.receipt_canonical_json.is_some() {
        return Err(VerifierError::PredicateSchemaInvalid(
            "receipt_canonical_json must be absent from strict Chio predicates".to_string(),
        ));
    }
    let tool_args_hash = pred.tool_args_hash.as_ref().ok_or_else(|| {
        VerifierError::PredicateSchemaInvalid("tool_args_hash is required".to_string())
    })?;
    validate_hash_record(tool_args_hash, "tool_args_hash")
        .map_err(VerifierError::PredicateSchemaInvalid)?;
    if !resolved_receipt
        .action
        .verify_hash()
        .map_err(|e| VerifierError::SubjectDigestMismatch(format!("tool args hash: {e}")))?
    {
        return Err(VerifierError::SubjectDigestMismatch(
            "resolved receipt action parameter_hash does not match parameters".to_string(),
        ));
    }
    if tool_args_hash.value != resolved_receipt.action.parameter_hash {
        return Err(VerifierError::SubjectDigestMismatch(format!(
            "predicate tool_args_hash {} != resolved receipt parameter_hash {}",
            tool_args_hash.value, resolved_receipt.action.parameter_hash
        )));
    }

    let resolved_body = resolved_receipt.body();
    let canonical = canonical_json_bytes(&resolved_body)
        .map_err(|e| VerifierError::SubjectDigestMismatch(format!("canonical-json: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    let want_hex = hex::encode(hasher.finalize());

    let subject = &statement.subject[0];
    let expected_subject_name = receipt_subject_name(&resolved_receipt.id);
    if subject.name != expected_subject_name {
        return Err(VerifierError::SubjectDigestMismatch(format!(
            "subject name {} != canonical receipt subject {}",
            subject.name, expected_subject_name
        )));
    }
    if subject.digest.sha256 != want_hex {
        return Err(VerifierError::SubjectDigestMismatch(format!(
            "subject digest {} != sha256(canonical_json(resolved_receipt.body())) {}",
            subject.digest.sha256, want_hex
        )));
    }
    let resolved_receipt_sha256 = receipt_canonical_digest_hex(&resolved_receipt)?;

    let summary = pred.policy_evaluation_summary.as_ref().ok_or_else(|| {
        VerifierError::PolicyVerdictDisagreement(
            "predicate is missing policy_evaluation_summary".to_string(),
        )
    })?;
    validate_policy_verdict(&summary.server_a_verdict, "server_a_verdict")?;
    validate_policy_verdict(&summary.server_b_verdict, "server_b_verdict")?;
    if summary.server_a_verdict.verdict != summary.server_b_verdict.verdict {
        return Err(VerifierError::PolicyVerdictDisagreement(format!(
            "server_a={} server_b={}",
            summary.server_a_verdict.verdict, summary.server_b_verdict.verdict
        )));
    }
    if let Some(joint) = &summary.joint_disposition {
        validate_verdict_string(joint)?;
        if joint != &summary.server_a_verdict.verdict {
            return Err(VerifierError::PolicyVerdictDisagreement(format!(
                "joint_disposition={} disagrees with server_a/b verdict={}",
                joint, summary.server_a_verdict.verdict
            )));
        }
    }
    let joint_verdict = summary.server_a_verdict.verdict.clone();

    let lease_ref = pred.capability_lease_ref.as_ref().ok_or_else(|| {
        VerifierError::CapabilityLeaseExpiredOrUnknown(
            "predicate is missing capability_lease_ref".to_string(),
        )
    })?;
    let resolved_lease = config
        .base
        .lease_registry
        .resolve(&lease_ref.lease_id)
        .ok_or_else(|| {
            VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
                "lease_id {:?} not resolvable in CapabilityLeaseRegistry",
                lease_ref.lease_id
            ))
        })?;
    if resolved_lease.issuer != lease_ref.issuer {
        return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
            "lease issuer mismatch: registry={:?} predicate={:?}",
            resolved_lease.issuer, lease_ref.issuer
        )));
    }
    if resolved_lease.expires_at_unix_ms != lease_ref.expires_at_unix_ms {
        return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
            "lease expiry mismatch: registry={} predicate={}",
            resolved_lease.expires_at_unix_ms, lease_ref.expires_at_unix_ms
        )));
    }
    if resolved_lease.expires_at_unix_ms <= config.base.pinned_epoch.now_unix_ms {
        return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
            "lease expired: expires_at={} <= pinned_epoch.now={}",
            resolved_lease.expires_at_unix_ms, config.base.pinned_epoch.now_unix_ms
        )));
    }
    match (&lease_ref.scope_digest, &resolved_lease.scope_digest_hex) {
        (Some(predicate_scope), Some(registry_scope)) => {
            validate_hash_record(predicate_scope, "capability_lease_ref.scope_digest")
                .map_err(VerifierError::CapabilityLeaseExpiredOrUnknown)?;
            if &predicate_scope.value != registry_scope {
                return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
                    "lease scope_digest mismatch: registry={:?} predicate={:?}",
                    registry_scope, predicate_scope.value
                )));
            }
        }
        (Some(predicate_scope), None) => {
            validate_hash_record(predicate_scope, "capability_lease_ref.scope_digest")
                .map_err(VerifierError::CapabilityLeaseExpiredOrUnknown)?;
            return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
                "predicate names scope_digest={:?} but registry record has no scope_digest_hex",
                predicate_scope.value
            )));
        }
        (None, Some(registry_scope)) => {
            return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
                "registry record carries scope_digest_hex={:?} but predicate omitted scope_digest",
                registry_scope
            )));
        }
        (None, None) => {}
    }

    let class = match config.base.action_classes.get(&pred.tool_name).copied() {
        Some(known) => known,
        None => match config.base.unknown_action_class_policy {
            UnknownActionClassPolicy::Reject => {
                return Err(VerifierError::UnknownActionClass {
                    tool_name: pred.tool_name.clone(),
                });
            }
        },
    };
    let mut resolved_governance_receipt = match class {
        ActionClassKind::Routine => None,
        ActionClassKind::ReceiptBacked => {
            let governance_ref = pred.governance_receipt_ref.as_ref().ok_or_else(|| {
                VerifierError::GovernanceReceiptRequiredMissing(format!(
                    "tool_name {:?} is receipt-backed but predicate omits governance_receipt_ref",
                    pred.tool_name
                ))
            })?;
            Some(resolve_governance_receipt_ref(
                config.base.governance_receipt_store,
                governance_ref,
            )?)
        }
    };

    if let Some(treaty) = pred.treaty_binding_ref.as_ref() {
        validate_treaty_binding_ref_for_review(treaty, "predicate", true)?;
        validate_predicate_operational_refs_match_treaty(pred, treaty)?;
        validate_treaty_receipt_refs_match_resolved_receipt(
            treaty,
            &resolved_receipt,
            &resolved_receipt_sha256,
        )?;
        if resolved_governance_receipt.is_none() {
            if let Some(governance_ref) = pred.governance_receipt_ref.as_ref() {
                resolved_governance_receipt = Some(resolve_governance_receipt_ref(
                    config.base.governance_receipt_store,
                    governance_ref,
                )?);
            }
        }
        if let Some(resolved_governance_receipt) = resolved_governance_receipt.as_ref() {
            if treaty.governance_refs != [resolved_governance_receipt.receipt_id.clone()] {
                return Err(VerifierError::PredicateSchemaInvalid(
                    "strict treaty DSSE governance_refs do not match resolved governance receipt"
                        .to_string(),
                ));
            }
        }
        if treaty.lease_refs != [resolved_lease.lease_id.clone()] {
            return Err(VerifierError::PredicateSchemaInvalid(
                "strict treaty DSSE lease_refs do not match resolved lease".to_string(),
            ));
        }
    }

    if pred.consistency_model != crate::bilateral_dsse::DEFAULT_CONSISTENCY_MODEL {
        let Some(treaty) = pred.treaty_binding_ref.as_ref() else {
            return Err(VerifierError::PredicateSchemaInvalid(format!(
                "consistency_model {:?} is not supported",
                pred.consistency_model
            )));
        };
        if treaty.consistency_model != pred.consistency_model {
            return Err(VerifierError::PredicateSchemaInvalid(
                "strict treaty DSSE consistency_model does not match treaty_binding_ref"
                    .to_string(),
            ));
        }
        if !matches!(
            pred.consistency_model.as_str(),
            "crdt-commutative" | "totally-ordered" | "single-kernel" | "quorum-required"
        ) {
            return Err(VerifierError::PredicateSchemaInvalid(format!(
                "consistency_model {:?} is not supported",
                pred.consistency_model
            )));
        }
        if matches!(
            pred.consistency_model.as_str(),
            "totally-ordered" | "quorum-required"
        ) && pred.consistency_anchor.as_deref().is_none_or(str::is_empty)
        {
            return Err(VerifierError::PredicateSchemaInvalid(
                "strict treaty DSSE ordered consistency requires consistency_anchor".to_string(),
            ));
        }
    }
    let frost_authorization =
        bind_frost_authorization_to_predicate(pred, frost_authorization, config)?;
    Ok(VerifiedBilateralCoSignInvocation {
        statement,
        resolved_receipt,
        resolved_lease,
        resolved_governance_receipt,
        joint_verdict,
        frost_authorization,
    })
}

fn bind_frost_authorization_to_predicate(
    predicate: &BilateralPredicate,
    authorization: Option<&crate::frost::VerifiedFrostAuthorization>,
    config: &ChioBilateralVerifierConfig<'_, '_>,
) -> Result<Option<crate::frost::VerifiedFrostAuthorization>, VerifierError> {
    match predicate.co_sign.as_str() {
        "bilateral_required" | "bilateral_if_cross_org" => {
            if authorization.is_some() {
                return Err(VerifierError::PredicateSchemaInvalid(
                    "verified FROST authorization supplied for a non-n_of_m predicate".to_string(),
                ));
            }
            Ok(None)
        }
        "n_of_m" => {
            let authorization = authorization.ok_or_else(|| {
                VerifierError::PredicateSchemaInvalid(
                    "co_sign n_of_m requires VerifiedFrostAuthorization".to_string(),
                )
            })?;
            let treaty = predicate.treaty_binding_ref.as_ref().ok_or_else(|| {
                VerifierError::PredicateSchemaInvalid(
                    "co_sign n_of_m requires treaty_binding_ref".to_string(),
                )
            })?;
            if predicate.consistency_model != "quorum-required"
                || predicate.consistency_anchor.as_deref() != Some("frost-quorum")
            {
                return Err(VerifierError::PredicateSchemaInvalid(
                    "co_sign n_of_m requires quorum-required consistency anchored by frost-quorum"
                        .to_string(),
                ));
            }
            if authorization.ladder_action_class() != treaty.action_class_id {
                return Err(VerifierError::PredicateSchemaInvalid(
                    "verified FROST action class does not match treaty action class".to_string(),
                ));
            }
            if authorization.scope_id() != treaty.treaty_id {
                return Err(VerifierError::PredicateSchemaInvalid(
                    "verified FROST scope does not match treaty id".to_string(),
                ));
            }
            if authorization.resource_id() != predicate.invocation_id {
                return Err(VerifierError::PredicateSchemaInvalid(
                    "verified FROST resource does not match invocation id".to_string(),
                ));
            }
            let now = config.base.pinned_epoch.now_unix_ms / 1_000;
            if !authorization.is_current_at(now) {
                return Err(VerifierError::PredicateSchemaInvalid(
                    "verified FROST authorization is not current at the pinned epoch".to_string(),
                ));
            }
            Ok(Some(authorization.clone()))
        }
        other => Err(VerifierError::PredicateSchemaInvalid(format!(
            "co_sign {other:?} is unsupported"
        ))),
    }
}

fn require_fresh_ladder_manifest(
    config: &VerifierConfig<'_>,
    kernel_id: &str,
    role: &str,
) -> Result<(), VerifierError> {
    let peer = config
        .peer_pin_set
        .lookup(kernel_id)
        .ok_or_else(|| VerifierError::PeerUnpinnedOrKeyidMismatch(kernel_id.to_string()))?;
    let ladder_manifest_ref = peer.ladder_manifest_ref.as_ref().ok_or_else(|| {
        VerifierError::LadderManifestMissing(format!(
            "{role} {kernel_id} has no pinned ladder manifest reference"
        ))
    })?;
    if !ladder_manifest_ref.is_fresh(config.pinned_epoch.now_unix_ms) {
        return Err(VerifierError::LadderManifestStale(format!(
            "{role} {kernel_id} ladder manifest {:?} is stale at {}",
            ladder_manifest_ref.manifest_id, config.pinned_epoch.now_unix_ms
        )));
    }
    Ok(())
}

/// Fail-closed: any error short-circuits and returns the corresponding
/// `VerifierError` variant whose `.code()` matches the spec §7.1
/// canonical string verbatim.
///
/// **Partial-verifier scope**: this is a partial
/// local verifier. It implements the structural / cryptographic core
/// plus a meaningful subset of the §7 step list but is not full §7
/// conformance: predicate schema fields are missing (e.g.
/// `tool_args_hash`) and the `statement.malformed` vs
/// `dsse.malformed` mapping is approximate. Full schema completion
/// belongs in a separate strict predicate-profile implementation.
pub fn verify_bilateral_cosign_invocation(
    envelope: &DsseEnvelope,
    config: &VerifierConfig<'_>,
) -> Result<VerifiedBilateralCoSignInvocation, VerifierError> {
    // ---- Steps 1-2: parse envelope; base64-decode payload --------------
    if envelope.payload_type != crate::bilateral_dsse::PAYLOAD_TYPE_IN_TOTO {
        return Err(VerifierError::DsseMalformed(format!(
            "payloadType {:?} is not application/vnd.in-toto+json",
            envelope.payload_type
        )));
    }
    if envelope.signatures.is_empty() {
        return Err(VerifierError::DsseMalformed(
            "signatures array is empty".to_string(),
        ));
    }

    let (statement, _) = envelope.decode_statement().map_err(map_bilateral_error)?;

    // ---- Step 3: in-toto v1 schema -------------------------------------
    if statement.statement_type != STATEMENT_TYPE_V1 {
        return Err(VerifierError::StatementSchemaInvalid(format!(
            "_type {:?} is not {:?}",
            statement.statement_type, STATEMENT_TYPE_V1
        )));
    }
    // Single-subject invariant: the bilateral envelope profile
    // binds exactly ONE subject (the receipt body). Rejecting only the
    // empty-list case is fail-OPEN: a signer could insert an arbitrary
    // second subject digest and verifiers that walked the full subject
    // list (the in-toto convention for subject membership) would resolve
    // a different receipt than the producer signed. Mirror the
    // `bilateral_dsse::verify_dsse_envelope` check at this layer so
    // the §7 verifier path also fails closed.
    if statement.subject.len() != 1 {
        return Err(VerifierError::StatementSchemaInvalid(format!(
            "statement.malformed: bilateral envelope must carry exactly 1 subject, got {}",
            statement.subject.len()
        )));
    }

    // ---- Step 4: predicateType is recognised ---------------------------
    if statement.predicate_type != PREDICATE_TYPE_BILATERAL {
        return Err(VerifierError::PredicateTypeUnrecognised(
            statement.predicate_type.clone(),
        ));
    }

    // ---- Step 5: predicate body schema (subset of §5) ------------------
    validate_predicate_required_fields(&statement.predicate)?;

    // ---- Step 6: bind pred ---------------------------------------------
    let pred = &statement.predicate;

    // ---- Step 8: peer pinning ------------------------------------------
    // Peer-pin lookup is the minimum local lookup needed before signature
    // authentication: it provides the trusted public keys for DSSE
    // verification. Receipt, revocation, lease, and governance stores are
    // intentionally queried only after the signatures authenticate.
    let pinned_a = config
        .peer_pin_set
        .lookup(&pred.tool_server_a.kernel_id)
        .ok_or_else(|| {
            VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
                "tool_server_a kernel_id {:?} not pinned",
                pred.tool_server_a.kernel_id
            ))
        })?;
    if pinned_a.fingerprint().0 != pred.tool_server_a.passport_key_fingerprint.0 {
        return Err(VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
            "tool_server_a fingerprint mismatch: pinned={} predicate={}",
            pinned_a.fingerprint().0,
            pred.tool_server_a.passport_key_fingerprint.0
        )));
    }
    let pinned_b = config
        .peer_pin_set
        .lookup(&pred.tool_server_b.kernel_id)
        .ok_or_else(|| {
            VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
                "tool_server_b kernel_id {:?} not pinned",
                pred.tool_server_b.kernel_id
            ))
        })?;
    if pinned_b.fingerprint().0 != pred.tool_server_b.passport_key_fingerprint.0 {
        return Err(VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
            "tool_server_b fingerprint mismatch: pinned={} predicate={}",
            pinned_b.fingerprint().0,
            pred.tool_server_b.passport_key_fingerprint.0
        )));
    }

    // ---- Steps 10-12: DSSE signature authentication -------------------
    verify_dsse_envelope(envelope, &pinned_a.public_key, &pinned_b.public_key)
        .map_err(map_bilateral_error)?;

    // ---- Step 9: revocation at pinned epoch ----------------------------
    if !config
        .revocation_oracle
        .is_active_at_epoch(&pinned_a.fingerprint(), config.pinned_epoch.epoch_height)
    {
        return Err(VerifierError::PeerRevokedAtEpoch(format!(
            "tool_server_a {} revoked at epoch {}",
            pred.tool_server_a.kernel_id, config.pinned_epoch.epoch_height
        )));
    }
    if !config
        .revocation_oracle
        .is_active_at_epoch(&pinned_b.fingerprint(), config.pinned_epoch.epoch_height)
    {
        return Err(VerifierError::PeerRevokedAtEpoch(format!(
            "tool_server_b {} revoked at epoch {}",
            pred.tool_server_b.kernel_id, config.pinned_epoch.epoch_height
        )));
    }

    // ---- Step 7: subject digest = sha256(canonical_json(resolve_receipt.body()))
    // Subject-digest store work is deferred until after DSSE authentication
    // so invalid signatures cannot force receipt-store reads.
    let resolved_receipt = config
        .receipt_store
        .resolve(&pred.invocation_id)
        .ok_or_else(|| {
            VerifierError::SubjectDigestMismatch(format!(
                "invocation_id {:?} not resolvable in ReceiptStore (fail-closed per §7 step 7)",
                pred.invocation_id
            ))
        })?;
    let resolved_receipt_signature_valid = resolved_receipt
        .verify_signature()
        .map_err(|e| VerifierError::SubjectDigestMismatch(format!("receipt signature: {e}")))?;
    if !resolved_receipt_signature_valid {
        return Err(VerifierError::SubjectDigestMismatch(
            "resolved receipt signature is invalid".to_string(),
        ));
    }
    if pred.tool_name != resolved_receipt.tool_name {
        return Err(VerifierError::SubjectDigestMismatch(format!(
            "predicate tool_name {:?} != resolved receipt tool_name {:?}",
            pred.tool_name, resolved_receipt.tool_name
        )));
    }
    if resolved_receipt.kernel_key != pinned_b.public_key {
        return Err(VerifierError::PeerUnpinnedOrKeyidMismatch(
            "resolved receipt kernel_key does not match pinned tool_server_b key".to_string(),
        ));
    }
    let resolved_receipt_canonical = canonical_json_string(&resolved_receipt)
        .map_err(|e| VerifierError::SubjectDigestMismatch(format!("canonical-json: {e}")))?;
    let receipt_canonical_json = pred.receipt_canonical_json.as_ref().ok_or_else(|| {
        VerifierError::PredicateSchemaInvalid(
            "receipt_canonical_json is required for the signature-slice profile".to_string(),
        )
    })?;
    if receipt_canonical_json != &resolved_receipt_canonical {
        return Err(VerifierError::SubjectDigestMismatch(
            "predicate embedded receipt JSON does not match resolved signed receipt".to_string(),
        ));
    }

    let resolved_body = resolved_receipt.body();
    let canonical = canonical_json_bytes(&resolved_body)
        .map_err(|e| VerifierError::SubjectDigestMismatch(format!("canonical-json: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    let want_hex = hex::encode(hasher.finalize());

    let subject = &statement.subject[0];
    let expected_subject_name = receipt_subject_name(&resolved_receipt.id);
    if subject.name != expected_subject_name {
        return Err(VerifierError::SubjectDigestMismatch(format!(
            "subject name {} != canonical receipt subject {}",
            subject.name, expected_subject_name
        )));
    }
    if subject.digest.sha256 != want_hex {
        return Err(VerifierError::SubjectDigestMismatch(format!(
            "subject digest {} != sha256(canonical_json(resolved_receipt.body())) {}",
            subject.digest.sha256, want_hex
        )));
    }

    // ---- Step 13: verdict agreement ------------------------------------
    let summary = pred.policy_evaluation_summary.as_ref().ok_or_else(|| {
        VerifierError::PolicyVerdictDisagreement(
            "predicate is missing policy_evaluation_summary (required for §7 step 13)".to_string(),
        )
    })?;
    validate_policy_verdict(&summary.server_a_verdict, "server_a_verdict")?;
    validate_policy_verdict(&summary.server_b_verdict, "server_b_verdict")?;
    if summary.server_a_verdict.verdict != summary.server_b_verdict.verdict {
        return Err(VerifierError::PolicyVerdictDisagreement(format!(
            "server_a={} server_b={}",
            summary.server_a_verdict.verdict, summary.server_b_verdict.verdict
        )));
    }
    if let Some(joint) = &summary.joint_disposition {
        validate_verdict_string(joint)?;
        if joint != &summary.server_a_verdict.verdict {
            return Err(VerifierError::PolicyVerdictDisagreement(format!(
                "joint_disposition={} disagrees with server_a/b verdict={}",
                joint, summary.server_a_verdict.verdict
            )));
        }
    }
    let joint_verdict = summary.server_a_verdict.verdict.clone();

    // ---- Step 14: capability lease resolution + expiry -----------------
    let lease_ref = pred.capability_lease_ref.as_ref().ok_or_else(|| {
        VerifierError::CapabilityLeaseExpiredOrUnknown(
            "predicate is missing capability_lease_ref (required for §7 step 14)".to_string(),
        )
    })?;
    let resolved_lease = config
        .lease_registry
        .resolve(&lease_ref.lease_id)
        .ok_or_else(|| {
            VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
                "lease_id {:?} not resolvable in CapabilityLeaseRegistry (fail-closed)",
                lease_ref.lease_id
            ))
        })?;
    if resolved_lease.issuer != lease_ref.issuer {
        return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
            "lease issuer mismatch: registry={:?} predicate={:?}",
            resolved_lease.issuer, lease_ref.issuer
        )));
    }
    if resolved_lease.expires_at_unix_ms != lease_ref.expires_at_unix_ms {
        return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
            "lease expiry mismatch: registry={} predicate={}",
            resolved_lease.expires_at_unix_ms, lease_ref.expires_at_unix_ms
        )));
    }
    // Strict-greater per spec line 401: `expires_at_unix_ms > pinned_epoch.now`.
    if resolved_lease.expires_at_unix_ms <= config.pinned_epoch.now_unix_ms {
        return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
            "lease expired: expires_at={} <= pinned_epoch.now={}",
            resolved_lease.expires_at_unix_ms, config.pinned_epoch.now_unix_ms
        )));
    }
    // Scope-digest binding: for a
    // scoped capability lease the predicate's `scope_digest` and the
    // registry record's `scope_digest_hex` must BOTH be present and
    // agree. Treating one-sided presence as "skip validation" lets an
    // envelope claim a specific scope digest while the trusted
    // registry never confirms that scope (or vice versa); step 14
    // would silently accept an unbound or differently-scoped lease.
    // Fail-closed on any mismatch in presence or value.
    match (&lease_ref.scope_digest, &resolved_lease.scope_digest_hex) {
        (Some(predicate_scope), Some(registry_scope)) => {
            validate_hash_record(predicate_scope, "capability_lease_ref.scope_digest")
                .map_err(VerifierError::CapabilityLeaseExpiredOrUnknown)?;
            if &predicate_scope.value != registry_scope {
                return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
                    "lease scope_digest mismatch: registry={:?} predicate={:?}",
                    registry_scope, predicate_scope.value
                )));
            }
        }
        (Some(predicate_scope), None) => {
            validate_hash_record(predicate_scope, "capability_lease_ref.scope_digest")
                .map_err(VerifierError::CapabilityLeaseExpiredOrUnknown)?;
            return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
                "predicate names scope_digest={:?} but registry record has no scope_digest_hex; \
                 cannot confirm lease scope",
                predicate_scope.value
            )));
        }
        (None, Some(registry_scope)) => {
            return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(format!(
                "registry record carries scope_digest_hex={:?} but predicate omitted scope_digest; \
                 cannot confirm lease scope",
                registry_scope
            )));
        }
        (None, None) => {
            // Both sides explicitly omit scope-digest binding; the
            // lease is unscoped on both ends and step 14 accepts it
            // on id+issuer+expiry alone. Unscoped leases are a valid
            // current configuration permitted by the spec.
        }
    }

    // ---- Step 15: governance receipt for receipt-backed classes -------
    //
    // Fail-closed action-class invariant: an unknown `tool_name` is
    // rejected with `governance.unknown_action_class` so a misspelled
    // or missing registration cannot silently downgrade a receipt-backed
    // class to `Routine` (fail-open).
    let class = match config.action_classes.get(&pred.tool_name).copied() {
        Some(known) => known,
        None => match config.unknown_action_class_policy {
            UnknownActionClassPolicy::Reject => {
                return Err(VerifierError::UnknownActionClass {
                    tool_name: pred.tool_name.clone(),
                });
            }
        },
    };
    let resolved_governance_receipt = match class {
        ActionClassKind::Routine => None,
        ActionClassKind::ReceiptBacked => {
            let g = pred.governance_receipt_ref.as_ref().ok_or_else(|| {
                VerifierError::GovernanceReceiptRequiredMissing(format!(
                    "tool_name {:?} is receipt-backed but predicate omits governance_receipt_ref",
                    pred.tool_name
                ))
            })?;
            validate_hash_record(&g.digest, "governance_receipt_ref.digest")
                .map_err(VerifierError::GovernanceReceiptRequiredMissing)?;
            let resolved = config
                .governance_receipt_store
                .resolve(&g.receipt_id)
                .ok_or_else(|| {
                    VerifierError::GovernanceReceiptRequiredMissing(format!(
                        "receipt_id {:?} not resolvable in GovernanceReceiptStore",
                        g.receipt_id
                    ))
                })?;
            if resolved.kernel_id != g.kernel_id {
                return Err(VerifierError::GovernanceReceiptRequiredMissing(format!(
                    "governance receipt kernel_id mismatch: store={:?} predicate={:?}",
                    resolved.kernel_id, g.kernel_id
                )));
            }
            // Recompute the digest of the resolved canonical JSON and
            // compare against the predicate's claimed digest.
            let mut hasher = Sha256::new();
            hasher.update(resolved.canonical_json.as_bytes());
            let want = hex::encode(hasher.finalize());
            if want != g.digest.value {
                return Err(VerifierError::GovernanceReceiptRequiredMissing(format!(
                    "governance receipt digest mismatch: computed={} predicate={}",
                    want, g.digest.value
                )));
            }
            Some(resolved)
        }
    };

    // ---- Step 16: consistency anchor reconciliation -------------------
    //
    // The signature-slice profile deliberately supports only
    // `crdt-commutative`. `verify_dsse_envelope` rejects
    // `totally-ordered` and `quorum-required` before this point with
    // `predicate.schema_invalid`, so this verifier does not expose
    // unreachable `consistency.*` error codes.
    if pred.consistency_model != crate::bilateral_dsse::DEFAULT_CONSISTENCY_MODEL {
        return Err(VerifierError::PredicateSchemaInvalid(format!(
            "consistency_model {:?} is not supported by the signature-slice profile",
            pred.consistency_model
        )));
    }

    // ---- Step 17: success ---------------------------------------------
    Ok(VerifiedBilateralCoSignInvocation {
        statement,
        resolved_receipt,
        resolved_lease,
        resolved_governance_receipt,
        joint_verdict,
        frost_authorization: None,
    })
}

fn validate_predicate_required_fields(pred: &BilateralPredicate) -> Result<(), VerifierError> {
    if pred.schema.as_deref() != Some(PREDICATE_BODY_SCHEMA) {
        return Err(VerifierError::PredicateSchemaInvalid(format!(
            "schema {:?} is not {:?}",
            pred.schema, PREDICATE_BODY_SCHEMA
        )));
    }
    if pred.receipt_canonical_json.is_none() {
        return Err(VerifierError::PredicateSchemaInvalid(
            "receipt_canonical_json is required".to_string(),
        ));
    }
    if pred.tool_args_hash.is_some() {
        return Err(VerifierError::PredicateSchemaInvalid(
            "tool_args_hash is not part of the signature-slice profile".to_string(),
        ));
    }
    if pred.invocation_id.is_empty() {
        return Err(VerifierError::PredicateSchemaInvalid(
            "invocation_id is empty".to_string(),
        ));
    }
    if pred.tool_name.is_empty() {
        return Err(VerifierError::PredicateSchemaInvalid(
            "tool_name is empty".to_string(),
        ));
    }
    if pred.tool_server_a.kernel_id.is_empty() || pred.tool_server_b.kernel_id.is_empty() {
        return Err(VerifierError::PredicateSchemaInvalid(
            "tool_server_*.kernel_id is empty".to_string(),
        ));
    }
    if pred.tool_server_a.alg != "ed25519" || pred.tool_server_b.alg != "ed25519" {
        return Err(VerifierError::PredicateSchemaInvalid(
            "tool_server_*.alg must be ed25519".to_string(),
        ));
    }
    if !is_sha256_hex(&pred.tool_server_a.passport_key_fingerprint.0)
        || !is_sha256_hex(&pred.tool_server_b.passport_key_fingerprint.0)
    {
        return Err(VerifierError::PredicateSchemaInvalid(
            "tool_server_*.passport_key_fingerprint is not 64 lowercase hex".to_string(),
        ));
    }
    if !VALID_CROSS_ORG_VISIBILITY.contains(&pred.cross_org_visibility.as_str()) {
        return Err(VerifierError::PredicateSchemaInvalid(format!(
            "cross_org_visibility {:?} is unsupported",
            pred.cross_org_visibility
        )));
    }
    match pred.co_sign.as_str() {
        "bilateral_required" | "bilateral_if_cross_org" => {}
        "n_of_m" => {
            return Err(VerifierError::PredicateSchemaInvalid(
                "co_sign n_of_m requires the strict verifier API with VerifiedFrostAuthorization"
                    .to_string(),
            ))
        }
        other => {
            return Err(VerifierError::PredicateSchemaInvalid(format!(
                "co_sign {:?} is not in {{bilateral_required, bilateral_if_cross_org}}",
                other
            )))
        }
    }
    Ok(())
}
