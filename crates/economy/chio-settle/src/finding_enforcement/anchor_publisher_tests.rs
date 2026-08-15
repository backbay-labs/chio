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

fn anchor_checkpoint_publication_at(
    proof: &AnchorInclusionProof,
    observed_at: u64,
) -> SignedFindingAnchorCheckpointPublication {
    sign(
        FindingAnchorCheckpointPublication {
            schema: FINDING_ANCHOR_CHECKPOINT_PUBLICATION_SCHEMA_V1.to_string(),
            checkpoint_statement_sha256: finding_anchor_checkpoint_statement_sha256(proof)
                .test_expect("checkpoint statement digest"),
            checkpoint_seq: proof.checkpoint_statement.checkpoint_seq,
            published_at: proof.checkpoint_statement.issued_at,
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
    let checkpoint_publication = anchor_checkpoint_publication_at(proof, TRUSTED_NOW);
    plan_finding_impairment(
        config,
        verified,
        operator_address,
        vault_snapshot,
        proof,
        FindingAnchorPublisherEvidence {
            retained_policy: &policy,
            signed_status: &status,
            signed_checkpoint_publication: &checkpoint_publication,
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
    let checkpoint_publication = anchor_checkpoint_publication_at(proof, TRUSTED_NOW);
    plan_finding_impairment_for_reconciliation(
        config,
        verified,
        operator_address,
        vault_snapshot,
        proof,
        FindingAnchorPublisherEvidence {
            retained_policy: &policy,
            signed_status: &status,
            signed_checkpoint_publication: &checkpoint_publication,
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
    let checkpoint_publication = anchor_checkpoint_publication_at(&proof, TRUSTED_NOW);
    let error = plan_finding_impairment(
        &sample_config(),
        &verified,
        &operator_address(),
        &vault_snapshot(),
        &proof,
        FindingAnchorPublisherEvidence {
            retained_policy: &foreign_policy,
            signed_status: &foreign_status,
            signed_checkpoint_publication: &checkpoint_publication,
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

#[test]
fn plan_rejects_anchor_publishers_that_reuse_enforcement_authorities() {
    let verified = verified();
    for key in [
        verified.enforcement().finalization_key.clone(),
        verified.enforcement().penalty_key.clone(),
    ] {
        let mut policy = anchor_publisher_policy();
        policy.key = key;
        let error = require_anchor_publisher_role_separation(&verified, &policy)
            .test_expect_err("an enforcement authority must not publish its own anchor");
        assert!(
            error
                .to_string()
                .contains("distinct from finalization and penalty authorities"),
            "unexpected rejection: {error}"
        );
    }
}

#[test]
fn plan_rejects_anchor_receipt_times_outside_publisher_lifecycle() {
    let verified = verified();
    let mut proof = enforcement_anchor_proof(&verified);
    let policy = anchor_publisher_policy();
    let status = anchor_publisher_status_at(TRUSTED_NOW);
    let checkpoint_publication = anchor_checkpoint_publication_at(&proof, TRUSTED_NOW);
    let status_authority = status_keypair().public_key();
    let evidence = FindingAnchorPublisherEvidence {
        retained_policy: &policy,
        signed_status: &status,
        signed_checkpoint_publication: &checkpoint_publication,
        status_authority: &status_authority,
        max_status_age_secs: MAX_SNAPSHOT_AGE_SECS,
        trusted_now_secs: TRUSTED_NOW,
    };

    proof.receipt.timestamp = policy.valid_until;
    let error = require_anchor_publisher_lifecycle(&proof, evidence)
        .test_expect_err("an expired publisher receipt must be rejected");
    assert!(
        error
            .to_string()
            .contains("receipt was signed outside the retained authority window"),
        "unexpected rejection: {error}"
    );

    proof.receipt.timestamp = proof.checkpoint_statement.issued_at.saturating_add(1);
    let error = require_anchor_publisher_lifecycle(&proof, evidence)
        .test_expect_err("a receipt signed after its checkpoint must be rejected");
    assert!(
        error
            .to_string()
            .contains("receipt was signed after its enclosing checkpoint"),
        "unexpected rejection: {error}"
    );
}

#[test]
fn plan_rejects_checkpoint_publication_for_another_statement() {
    let verified = verified();
    let proof = enforcement_anchor_proof(&verified);
    let policy = anchor_publisher_policy();
    let status = anchor_publisher_status_at(TRUSTED_NOW);
    let mut publication_body = anchor_checkpoint_publication_at(&proof, TRUSTED_NOW).body;
    publication_body.checkpoint_statement_sha256 = "0".repeat(64);
    let publication = sign(publication_body, &status_keypair());
    let status_authority = status_keypair().public_key();
    let error = require_anchor_publisher_lifecycle(
        &proof,
        FindingAnchorPublisherEvidence {
            retained_policy: &policy,
            signed_status: &status,
            signed_checkpoint_publication: &publication,
            status_authority: &status_authority,
            max_status_age_secs: MAX_SNAPSHOT_AGE_SECS,
            trusted_now_secs: TRUSTED_NOW,
        },
    )
    .test_expect_err("publication evidence for another checkpoint must be rejected");
    assert!(
        error
            .to_string()
            .contains("does not bind the exact checkpoint"),
        "unexpected rejection: {error}"
    );
}

#[test]
fn plan_rejects_a_checkpoint_first_observed_after_publisher_revocation() {
    let verified = verified();
    let proof = enforcement_anchor_proof(&verified);
    let policy = anchor_publisher_policy();
    let revoked_from = proof.checkpoint_statement.issued_at.saturating_add(1);
    let status = sign(
        FindingAuthorityStatus {
            schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_string(),
            status_ref: policy.revocation_status_ref.clone(),
            authority_id: policy.authority_id.clone(),
            key: policy.key.clone(),
            key_epoch: policy.key_epoch,
            revoked_from: Some(revoked_from),
            observed_at: TRUSTED_NOW,
        },
        &status_keypair(),
    );
    let publication = anchor_checkpoint_publication_at(&proof, TRUSTED_NOW);
    let status_authority = status_keypair().public_key();
    let error = require_anchor_publisher_lifecycle(
        &proof,
        FindingAnchorPublisherEvidence {
            retained_policy: &policy,
            signed_status: &status,
            signed_checkpoint_publication: &publication,
            status_authority: &status_authority,
            max_status_age_secs: MAX_SNAPSHOT_AGE_SECS,
            trusted_now_secs: TRUSTED_NOW,
        },
    )
    .test_expect_err("a post-revocation publication cannot authenticate a backdated checkpoint");
    assert!(
        error
            .to_string()
            .contains("not independently observed before publisher revocation"),
        "unexpected rejection: {error}"
    );
}
