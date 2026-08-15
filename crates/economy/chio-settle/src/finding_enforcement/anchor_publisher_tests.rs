use super::*;

fn anchor_publisher_policy() -> FindingPenaltyAuthorityPolicy {
    FindingPenaltyAuthorityPolicy {
        authority_id: "anchor-publisher".to_owned(),
        key: Keypair::from_seed(&[7; 32]).public_key(),
        key_epoch: 1,
        valid_from: 1,
        valid_until: 1_800_000_000,
        revocation_status_ref: "revocations/anchor-publisher".to_owned(),
    }
}

fn anchor_publisher_status_at(observed_at: u64) -> SignedFindingAuthorityStatus {
    let policy = anchor_publisher_policy();
    sign(
        FindingAuthorityStatus {
            schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_string(),
            status_ref: policy.revocation_status_ref,
            authority_id: policy.authority_id,
            key: policy.key,
            key_epoch: policy.key_epoch,
            revoked_from: None,
            observed_at,
        },
        &status_keypair(),
    )
}

pub(super) fn plan_with_anchor(
    config: &SettlementChainConfig,
    verified: &VerifiedFindingEnforcement,
    operator_address: &str,
    vault_snapshot: &EvmBondSnapshot,
    proof: &AnchorInclusionProof,
) -> Result<PlannedFindingImpairment, SettlementError> {
    let policy = anchor_publisher_policy();
    let status = anchor_publisher_status_at(TRUSTED_NOW);
    plan_finding_impairment(
        config,
        verified,
        operator_address,
        vault_snapshot,
        proof,
        FindingAnchorPublisherEvidence {
            retained_policy: &policy,
            signed_status: &status,
            status_authority: &status_keypair().public_key(),
            max_status_age_secs: MAX_SNAPSHOT_AGE_SECS,
            trusted_now_secs: TRUSTED_NOW,
        },
    )
}

pub(super) fn plan_reconciliation_with_anchor(
    config: &SettlementChainConfig,
    verified: &ReconciledFindingEnforcement,
    operator_address: &str,
    vault_snapshot: &EvmBondSnapshot,
    proof: &AnchorInclusionProof,
) -> Result<PlannedFindingImpairmentReconciliation, SettlementError> {
    let policy = anchor_publisher_policy();
    let status = anchor_publisher_status_at(TRUSTED_NOW);
    plan_finding_impairment_for_reconciliation(
        config,
        verified,
        operator_address,
        vault_snapshot,
        proof,
        FindingAnchorPublisherEvidence {
            retained_policy: &policy,
            signed_status: &status,
            status_authority: &status_keypair().public_key(),
            max_status_age_secs: MAX_SNAPSHOT_AGE_SECS,
            trusted_now_secs: TRUSTED_NOW,
        },
    )
}

#[test]
fn plan_rejects_an_anchor_receipt_from_another_operation() {
    let verified = verified();
    let error = plan_with_anchor(
        &sample_config(),
        &verified,
        &operator_address(),
        &vault_snapshot(),
        &sample_anchor_proof(),
    )
    .test_expect_err("an unrelated anchored receipt must not authorize impairment");
    assert!(
        error
            .to_string()
            .contains("does not authorize a finding enforcement root"),
        "unexpected rejection: {error}"
    );
}

#[test]
fn plan_rejects_an_anchor_publisher_outside_the_pinned_lifecycle() {
    let verified = verified();
    let proof = enforcement_anchor_proof(&verified);
    let foreign_policy = FindingPenaltyAuthorityPolicy {
        authority_id: "foreign-anchor-publisher".to_owned(),
        key: Keypair::from_seed(&[99; 32]).public_key(),
        key_epoch: 1,
        valid_from: 1,
        valid_until: 1_800_000_000,
        revocation_status_ref: "revocations/foreign-anchor-publisher".to_owned(),
    };
    let foreign_status = sign(
        FindingAuthorityStatus {
            schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_string(),
            status_ref: foreign_policy.revocation_status_ref.clone(),
            authority_id: foreign_policy.authority_id.clone(),
            key: foreign_policy.key.clone(),
            key_epoch: foreign_policy.key_epoch,
            revoked_from: None,
            observed_at: TRUSTED_NOW,
        },
        &status_keypair(),
    );
    let error = plan_finding_impairment(
        &sample_config(),
        &verified,
        &operator_address(),
        &vault_snapshot(),
        &proof,
        FindingAnchorPublisherEvidence {
            retained_policy: &foreign_policy,
            signed_status: &foreign_status,
            status_authority: &status_keypair().public_key(),
            max_status_age_secs: MAX_SNAPSHOT_AGE_SECS,
            trusted_now_secs: TRUSTED_NOW,
        },
    )
    .test_expect_err("a proof-selected anchor publisher must not authorize impairment");
    assert!(
        error
            .to_string()
            .contains("does not match the retained governance policy"),
        "unexpected rejection: {error}"
    );
}
