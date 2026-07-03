use super::*;

fn delegated_call_chain_is_sender_bound(
    call_chain: Option<&chio_core::capability::governance::GovernedCallChainProvenance>,
) -> bool {
    let Some(call_chain) = call_chain else {
        return false;
    };
    if call_chain.evidence_class
        == chio_core::capability::governance::GovernedProvenanceEvidenceClass::Asserted
    {
        return false;
    }

    let has_local_lineage_link = call_chain.evidence_sources.iter().any(|source| {
        matches!(
            source,
            chio_core::capability::governance::GovernedCallChainEvidenceSource::SessionParentRequestLineage
                | chio_core::capability::governance::GovernedCallChainEvidenceSource::LocalParentReceiptLinkage
                | chio_core::capability::governance::GovernedCallChainEvidenceSource::UpstreamDelegatorProof
        )
    });
    let has_capability_subject_binding = call_chain.evidence_sources.iter().any(|source| {
        matches!(
            source,
            chio_core::capability::governance::GovernedCallChainEvidenceSource::CapabilityDelegatorSubject
                | chio_core::capability::governance::GovernedCallChainEvidenceSource::CapabilityOriginSubject
        )
    });

    has_local_lineage_link
        || (call_chain.evidence_class
            == chio_core::capability::governance::GovernedProvenanceEvidenceClass::Verified
            && has_capability_subject_binding)
}

pub(crate) fn resolve_sender_constraint_subject_key(
    receipt_id: &str,
    receipt_subject_key: Option<&str>,
    lineage_subject_key: Option<&str>,
) -> Result<(String, String), ReceiptStoreError> {
    match (receipt_subject_key, lineage_subject_key) {
        (Some(receipt_key), Some(lineage_key)) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.subjectKey", receipt_key)?;
            ensure_non_empty_profile_value(receipt_id, "capabilitySnapshot.subjectKey", lineage_key)?;
            if receipt_key != lineage_key {
                return Err(invalid_chio_oauth_authorization_profile(
                    receipt_id,
                    format!(
                        "senderConstraint.subjectKey `{receipt_key}` does not match capability snapshot subject `{lineage_key}`"
                    ),
                ));
            }
            Ok((receipt_key.to_string(), "receipt_attribution".to_string()))
        }
        (Some(receipt_key), None) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.subjectKey", receipt_key)?;
            Ok((receipt_key.to_string(), "receipt_attribution".to_string()))
        }
        (None, Some(lineage_key)) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.subjectKey", lineage_key)?;
            Ok((lineage_key.to_string(), "capability_snapshot".to_string()))
        }
        (None, None) => Err(invalid_chio_oauth_authorization_profile(
            receipt_id,
            "sender-constrained profile requires a bound subjectKey from receipt attribution or capability snapshot",
        )),
    }
}

pub(crate) fn resolve_sender_constraint_issuer_key(
    receipt_id: &str,
    receipt_issuer_key: Option<&str>,
    lineage_issuer_key: Option<&str>,
) -> Result<(String, String), ReceiptStoreError> {
    match (receipt_issuer_key, lineage_issuer_key) {
        (Some(receipt_key), Some(lineage_key)) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.issuerKey", receipt_key)?;
            ensure_non_empty_profile_value(receipt_id, "capabilitySnapshot.issuerKey", lineage_key)?;
            if receipt_key != lineage_key {
                return Err(invalid_chio_oauth_authorization_profile(
                    receipt_id,
                    format!(
                        "senderConstraint.issuerKey `{receipt_key}` does not match capability snapshot issuer `{lineage_key}`"
                    ),
                ));
            }
            Ok((receipt_key.to_string(), "receipt_attribution".to_string()))
        }
        (Some(receipt_key), None) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.issuerKey", receipt_key)?;
            Ok((receipt_key.to_string(), "receipt_attribution".to_string()))
        }
        (None, Some(lineage_key)) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.issuerKey", lineage_key)?;
            Ok((lineage_key.to_string(), "capability_snapshot".to_string()))
        }
        (None, None) => Err(invalid_chio_oauth_authorization_profile(
            receipt_id,
            "sender-constrained profile requires a bound issuerKey from receipt attribution or capability snapshot",
        )),
    }
}

pub(crate) fn resolve_sender_constraint_grant(
    receipt_id: &str,
    tool_server: &str,
    tool_name: &str,
    grant_index: Option<u32>,
    grants_json: Option<&str>,
) -> Result<(u32, bool), ReceiptStoreError> {
    let grants_json = grants_json.ok_or_else(|| {
        invalid_chio_oauth_authorization_profile(
            receipt_id,
            "sender-constrained profile requires capability snapshot grants_json",
        )
    })?;
    let scope: ChioScope = serde_json::from_str(grants_json).map_err(|error| {
        invalid_chio_oauth_authorization_profile(
            receipt_id,
            format!("invalid capability snapshot grants_json: {error}"),
        )
    })?;

    if let Some(index) = grant_index {
        let grant = scope.grants.get(index as usize).ok_or_else(|| {
            invalid_chio_oauth_authorization_profile(
                receipt_id,
                format!("matched grant_index `{index}` is outside the capability scope"),
            )
        })?;
        if grant.server_id != tool_server || grant.tool_name != tool_name {
            return Err(invalid_chio_oauth_authorization_profile(
                receipt_id,
                format!(
                    "grant_index `{index}` resolves to {}/{} instead of {tool_server}/{tool_name}",
                    grant.server_id, grant.tool_name
                ),
            ));
        }
        return Ok((index, grant.dpop_required == Some(true)));
    }

    let mut matches = scope
        .grants
        .iter()
        .enumerate()
        .filter(|(_, grant)| grant.server_id == tool_server && grant.tool_name == tool_name);
    let Some((index, grant)) = matches.next() else {
        return Err(invalid_chio_oauth_authorization_profile(
            receipt_id,
            format!("capability snapshot does not contain a grant for {tool_server}/{tool_name}"),
        ));
    };
    if matches.next().is_some() {
        return Err(invalid_chio_oauth_authorization_profile(
            receipt_id,
            format!(
                "capability snapshot contains multiple grants for {tool_server}/{tool_name}; grant_index is required"
            ),
        ));
    }
    Ok((index as u32, grant.dpop_required == Some(true)))
}

pub(crate) struct AuthorizationSenderConstraintArgs<'a> {
    pub(crate) tool_server: &'a str,
    pub(crate) tool_name: &'a str,
    pub(crate) receipt_subject_key: Option<&'a str>,
    pub(crate) receipt_issuer_key: Option<&'a str>,
    pub(crate) lineage_subject_key: Option<&'a str>,
    pub(crate) lineage_issuer_key: Option<&'a str>,
    pub(crate) grant_index: Option<u32>,
    pub(crate) grants_json: Option<&'a str>,
}

pub(crate) fn derive_authorization_sender_constraint(
    receipt_id: &str,
    args: AuthorizationSenderConstraintArgs<'_>,
    transaction_context: &GovernedAuthorizationTransactionContext,
) -> Result<AuthorizationContextSenderConstraint, ReceiptStoreError> {
    let AuthorizationSenderConstraintArgs {
        tool_server,
        tool_name,
        receipt_subject_key,
        receipt_issuer_key,
        lineage_subject_key,
        lineage_issuer_key,
        grant_index,
        grants_json,
    } = args;
    let (subject_key, subject_key_source) = resolve_sender_constraint_subject_key(
        receipt_id,
        receipt_subject_key,
        lineage_subject_key,
    )?;
    let (issuer_key, issuer_key_source) =
        resolve_sender_constraint_issuer_key(receipt_id, receipt_issuer_key, lineage_issuer_key)?;
    let (matched_grant_index, proof_required) = resolve_sender_constraint_grant(
        receipt_id,
        tool_server,
        tool_name,
        grant_index,
        grants_json,
    )?;

    Ok(AuthorizationContextSenderConstraint {
        subject_key,
        subject_key_source,
        issuer_key,
        issuer_key_source,
        matched_grant_index,
        proof_required,
        proof_type: proof_required.then(|| CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP.to_string()),
        proof_schema: proof_required.then(|| DPOP_SCHEMA.to_string()),
        runtime_assurance_bound: transaction_context.runtime_assurance_tier.is_some(),
        delegated_call_chain_bound: delegated_call_chain_is_sender_bound(
            transaction_context.call_chain.as_ref(),
        ),
    })
}

pub(crate) fn invalid_chio_oauth_authorization_profile(
    receipt_id: &str,
    detail: impl AsRef<str>,
) -> ReceiptStoreError {
    ReceiptStoreError::Canonical(format!(
        "receipt {receipt_id} violates Chio OAuth authorization profile: {}",
        detail.as_ref()
    ))
}

pub(crate) fn ensure_non_empty_profile_value(
    receipt_id: &str,
    field: &str,
    value: &str,
) -> Result<(), ReceiptStoreError> {
    if value.trim().is_empty() {
        return Err(invalid_chio_oauth_authorization_profile(
            receipt_id,
            format!("{field} must not be empty"),
        ));
    }
    Ok(())
}

pub(crate) fn validate_chio_oauth_authorization_detail(
    receipt_id: &str,
    detail: &GovernedAuthorizationDetail,
) -> Result<bool, ReceiptStoreError> {
    match detail.detail_type.as_str() {
        CHIO_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE => {
            if detail.locations.is_empty() {
                return Err(invalid_chio_oauth_authorization_profile(
                    receipt_id,
                    "chio_governed_tool must include at least one location",
                ));
            }
            if detail.actions.is_empty() {
                return Err(invalid_chio_oauth_authorization_profile(
                    receipt_id,
                    "chio_governed_tool must include at least one action",
                ));
            }
            for location in &detail.locations {
                ensure_non_empty_profile_value(
                    receipt_id,
                    "authorizationDetails.locations[]",
                    location,
                )?;
            }
            for action in &detail.actions {
                ensure_non_empty_profile_value(
                    receipt_id,
                    "authorizationDetails.actions[]",
                    action,
                )?;
            }
            if detail.commerce.is_some() || detail.metered_billing.is_some() {
                return Err(invalid_chio_oauth_authorization_profile(
                    receipt_id,
                    "chio_governed_tool must not carry commerce or meteredBilling sidecars",
                ));
            }
            Ok(true)
        }
        CHIO_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE => {
            let Some(commerce) = detail.commerce.as_ref() else {
                return Err(invalid_chio_oauth_authorization_profile(
                    receipt_id,
                    "chio_governed_commerce must include commerce detail",
                ));
            };
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.commerce.seller",
                &commerce.seller,
            )?;
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.commerce.sharedPaymentTokenId",
                &commerce.shared_payment_token_id,
            )?;
            if detail.metered_billing.is_some() {
                return Err(invalid_chio_oauth_authorization_profile(
                    receipt_id,
                    "chio_governed_commerce must not carry meteredBilling detail",
                ));
            }
            Ok(false)
        }
        CHIO_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE => {
            let Some(metered) = detail.metered_billing.as_ref() else {
                return Err(invalid_chio_oauth_authorization_profile(
                    receipt_id,
                    "chio_governed_metered_billing must include meteredBilling detail",
                ));
            };
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.meteredBilling.provider",
                &metered.provider,
            )?;
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.meteredBilling.quoteId",
                &metered.quote_id,
            )?;
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.meteredBilling.billingUnit",
                &metered.billing_unit,
            )?;
            if detail.commerce.is_some() {
                return Err(invalid_chio_oauth_authorization_profile(
                    receipt_id,
                    "chio_governed_metered_billing must not carry commerce detail",
                ));
            }
            Ok(false)
        }
        unsupported => Err(invalid_chio_oauth_authorization_profile(
            receipt_id,
            format!("unsupported authorizationDetails.type `{unsupported}`"),
        )),
    }
}

pub(crate) fn validate_chio_oauth_authorization_row(
    row: &AuthorizationContextRow,
) -> Result<(), ReceiptStoreError> {
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "transactionContext.intentId",
        &row.transaction_context.intent_id,
    )?;
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "transactionContext.intentHash",
        &row.transaction_context.intent_hash,
    )?;

    let mut saw_tool_detail = false;
    for detail in &row.authorization_details {
        if validate_chio_oauth_authorization_detail(&row.receipt_id, detail)? {
            saw_tool_detail = true;
        }
    }
    if !saw_tool_detail {
        return Err(invalid_chio_oauth_authorization_profile(
            &row.receipt_id,
            "report must include one chio_governed_tool authorization detail",
        ));
    }

    if let Some(token_id) = row.transaction_context.approval_token_id.as_deref() {
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.approvalTokenId",
            token_id,
        )?;
        let approver_key = row
            .transaction_context
            .approver_key
            .as_deref()
            .ok_or_else(|| {
                invalid_chio_oauth_authorization_profile(
                    &row.receipt_id,
                    "approvalTokenId requires approverKey",
                )
            })?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.approverKey",
            approver_key,
        )?;
        if row.transaction_context.approval_approved.is_none() {
            return Err(invalid_chio_oauth_authorization_profile(
                &row.receipt_id,
                "approvalTokenId requires approvalApproved",
            ));
        }
    }

    if let Some(call_chain) = row.transaction_context.call_chain.as_ref() {
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.callChain.chainId",
            &call_chain.chain_id,
        )?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.callChain.parentRequestId",
            &call_chain.parent_request_id,
        )?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.callChain.originSubject",
            &call_chain.origin_subject,
        )?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.callChain.delegatorSubject",
            &call_chain.delegator_subject,
        )?;
        if let Some(parent_receipt_id) = call_chain.parent_receipt_id.as_deref() {
            ensure_non_empty_profile_value(
                &row.receipt_id,
                "transactionContext.callChain.parentReceiptId",
                parent_receipt_id,
            )?;
        }
        if row.sender_constraint.delegated_call_chain_bound
            && !delegated_call_chain_is_sender_bound(Some(call_chain))
        {
            return Err(invalid_chio_oauth_authorization_profile(
                &row.receipt_id,
                "senderConstraint.delegatedCallChainBound requires corroborated call-chain provenance",
            ));
        }
    }

    if row.transaction_context.runtime_assurance_tier.is_some() {
        let runtime_assurance_schema = row
            .transaction_context
            .runtime_assurance_schema
            .as_deref()
            .ok_or_else(|| {
                invalid_chio_oauth_authorization_profile(
                    &row.receipt_id,
                    "runtimeAssuranceTier requires runtimeAssuranceSchema",
                )
            })?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.runtimeAssuranceSchema",
            runtime_assurance_schema,
        )?;
        row.transaction_context
            .runtime_assurance_verifier_family
            .ok_or_else(|| {
                invalid_chio_oauth_authorization_profile(
                    &row.receipt_id,
                    "runtimeAssuranceTier requires runtimeAssuranceVerifierFamily",
                )
            })?;
        let runtime_assurance_verifier = row
            .transaction_context
            .runtime_assurance_verifier
            .as_deref()
            .ok_or_else(|| {
                invalid_chio_oauth_authorization_profile(
                    &row.receipt_id,
                    "runtimeAssuranceTier requires runtimeAssuranceVerifier",
                )
            })?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.runtimeAssuranceVerifier",
            runtime_assurance_verifier,
        )?;
        let runtime_assurance_evidence_sha256 = row
            .transaction_context
            .runtime_assurance_evidence_sha256
            .as_deref()
            .ok_or_else(|| {
                invalid_chio_oauth_authorization_profile(
                    &row.receipt_id,
                    "runtimeAssuranceTier requires runtimeAssuranceEvidenceSha256",
                )
            })?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.runtimeAssuranceEvidenceSha256",
            runtime_assurance_evidence_sha256,
        )?;
    }

    ensure_non_empty_profile_value(
        &row.receipt_id,
        "senderConstraint.subjectKey",
        &row.sender_constraint.subject_key,
    )?;
    if row.subject_key.as_deref() != Some(row.sender_constraint.subject_key.as_str()) {
        return Err(invalid_chio_oauth_authorization_profile(
            &row.receipt_id,
            "row subjectKey must match senderConstraint.subjectKey",
        ));
    }
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "senderConstraint.subjectKeySource",
        &row.sender_constraint.subject_key_source,
    )?;
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "senderConstraint.issuerKey",
        &row.sender_constraint.issuer_key,
    )?;
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "senderConstraint.issuerKeySource",
        &row.sender_constraint.issuer_key_source,
    )?;
    if row.sender_constraint.proof_required {
        let proof_type = row.sender_constraint.proof_type.as_deref().ok_or_else(|| {
            invalid_chio_oauth_authorization_profile(
                &row.receipt_id,
                "proofRequired requires senderConstraint.proofType",
            )
        })?;
        ensure_non_empty_profile_value(&row.receipt_id, "senderConstraint.proofType", proof_type)?;
        let proof_schema = row
            .sender_constraint
            .proof_schema
            .as_deref()
            .ok_or_else(|| {
                invalid_chio_oauth_authorization_profile(
                    &row.receipt_id,
                    "proofRequired requires senderConstraint.proofSchema",
                )
            })?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "senderConstraint.proofSchema",
            proof_schema,
        )?;
    }

    Ok(())
}

pub(crate) fn chain_is_complete(
    capability_id: &str,
    chain: &[chio_kernel::CapabilitySnapshot],
) -> bool {
    if chain.is_empty() {
        return false;
    }
    let Some(leaf) = chain.last() else {
        return false;
    };
    if leaf.capability_id != capability_id {
        return false;
    }
    if chain
        .first()
        .and_then(|snapshot| snapshot.parent_capability_id.as_ref())
        .is_some()
    {
        return false;
    }
    if chain.windows(2).any(|window| {
        window[1].parent_capability_id.as_deref() != Some(window[0].capability_id.as_str())
    }) {
        return false;
    }
    if leaf.parent_capability_id.is_some() && chain.len() == 1 {
        return false;
    }
    if leaf.delegation_depth as usize != chain.len().saturating_sub(1) {
        return false;
    }
    true
}

pub(crate) fn ratio_option(numerator: u64, denominator: u64) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64)
    }
}

pub(crate) fn compliance_export_scope_note(
    query: &OperatorReportQuery,
    export_query: &EvidenceExportQuery,
) -> Option<String> {
    let mut notes = Vec::new();

    if !query.direct_evidence_export_supported() {
        notes.push(
            "tool filters narrow the operator report only; direct evidence export can scope by capability, agent, and time window".to_string(),
        );
    }

    match export_query.child_receipt_scope() {
        EvidenceChildReceiptScope::TimeWindowContextOnly => notes.push(
            "child receipts are included only as time-window context for this export scope".to_string(),
        ),
        EvidenceChildReceiptScope::OmittedNoJoinPath => notes.push(
            "child receipts are omitted for this export scope because no capability/agent join exists yet".to_string(),
        ),
        EvidenceChildReceiptScope::FullQueryWindow => {}
    }

    if notes.is_empty() {
        None
    } else {
        Some(notes.join(" "))
    }
}
