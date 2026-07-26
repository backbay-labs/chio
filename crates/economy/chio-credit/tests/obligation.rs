use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::sha256_hex;
use chio_credit::obligation::{
    derive_obligation_payee_binding_digest, ObligationAtomInputV1, ObligationAtomV1,
    ObligationCreditElectionV1, ObligationDispositionRecordV1, ObligationDispositionTransitionV1,
    ObligationDispositionV1, ObligationError, OBLIGATION_CLAIM_INDEX_V1,
};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn atom_with(intent: &str, creditor_id: &str) -> Result<ObligationAtomV1, ObligationError> {
    ObligationAtomV1::new(ObligationAtomInputV1 {
        economic_intent_digest: digest(intent),
        source_receipt_id: "receipt-1".to_owned(),
        source_receipt_digest: digest("receipt-1"),
        debtor_id: "did:chio:buyer".to_owned(),
        original_creditor_id: creditor_id.to_owned(),
        original_settlement_destination_ref: "acct:provider-a".to_owned(),
        payee_binding_digest: derive_obligation_payee_binding_digest(
            creditor_id,
            "acct:provider-a",
        )?,
        amount: MonetaryAmount {
            currency: "USD".to_owned(),
            units: 125,
        },
        credit_election: ObligationCreditElectionV1::CreditFacility {
            facility_id: "facility-1".to_owned(),
            authority_digest: digest("credit-authority"),
        },
        pre_action_authority_digest: digest("economic-authority"),
        created_at_unix_ms: 100,
        due_at_unix_ms: 200,
    })
}

fn atom() -> Result<ObligationAtomV1, ObligationError> {
    atom_with("intent-1", "did:chio:provider-a")
}

#[test]
fn obligation_identity_uses_the_fixed_source_claim_preimage() -> TestResult {
    let first = atom()?;
    let preimage = (
        "chio.obligation.id.v1",
        digest("intent-1"),
        digest("receipt-1"),
        OBLIGATION_CLAIM_INDEX_V1,
    );
    let expected = sha256_hex(&canonical_json_bytes(&preimage)?);

    assert_eq!(first.obligation_id(), expected);
    assert_eq!(first.claim_index(), 0);
    assert_eq!(atom()?, first);
    assert_ne!(atom_with("intent-2", "did:chio:provider-a")?, first);
    Ok(())
}

#[test]
fn conflicting_atom_payload_keeps_identity_but_changes_digest() -> TestResult {
    let first = atom()?;
    let different_payee = atom_with("intent-1", "did:chio:provider-b")?;

    assert_eq!(first.obligation_id(), different_payee.obligation_id());
    assert_ne!(first.digest()?, different_payee.digest()?);
    Ok(())
}

#[test]
fn payee_binding_digest_commits_exact_beneficiary_and_destination() -> TestResult {
    let digest =
        derive_obligation_payee_binding_digest("did:chio:provider-a", "acct:provider-primary")?;
    let canonical = canonical_json_bytes(&json!({
        "beneficiaryId": "did:chio:provider-a",
        "settlementDestinationRef": "acct:provider-primary"
    }))?;
    let mut preimage = b"chio.obligation.payee-binding.digest.v1\0".to_vec();
    preimage.extend_from_slice(&canonical);

    assert_eq!(digest, sha256_hex(&preimage));
    assert_ne!(
        digest,
        derive_obligation_payee_binding_digest("did:chio:provider-b", "acct:provider-primary")?
    );
    assert_ne!(
        digest,
        derive_obligation_payee_binding_digest("did:chio:provider-a", "acct:provider-substituted")?
    );
    Ok(())
}

#[test]
fn obligation_atom_rejects_substituted_payee_binding_digest() {
    assert_eq!(
        ObligationAtomV1::new(ObligationAtomInputV1 {
            economic_intent_digest: digest("intent-substituted-payee"),
            source_receipt_id: "receipt-substituted-payee".to_owned(),
            source_receipt_digest: digest("receipt-substituted-payee"),
            debtor_id: "did:chio:buyer".to_owned(),
            original_creditor_id: "did:chio:provider-a".to_owned(),
            original_settlement_destination_ref: "acct:provider-a".to_owned(),
            payee_binding_digest: digest("unrelated-payee-binding"),
            amount: MonetaryAmount {
                currency: "USD".to_owned(),
                units: 125,
            },
            credit_election: ObligationCreditElectionV1::NotCredit,
            pre_action_authority_digest: digest("economic-authority"),
            created_at_unix_ms: 100,
            due_at_unix_ms: 200,
        }),
        Err(ObligationError::InvalidField("payee_binding_digest"))
    );
}

#[test]
fn obligation_disposition_is_exclusive_and_round_release_is_exact() -> TestResult {
    let atom = atom()?;
    let produced = ObligationDispositionRecordV1::produced(&atom)?;
    let reserved = produced.advance(
        &atom,
        ObligationDispositionTransitionV1::ReserveClearing {
            round_id: "round-1".to_owned(),
            authority_digest: digest("reserve-authority"),
        },
    )?;
    assert_eq!(
        reserved.disposition(),
        &ObligationDispositionV1::ClearingReserved {
            round_id: "round-1".to_owned()
        }
    );
    assert!(reserved
        .advance(
            &atom,
            ObligationDispositionTransitionV1::ReleaseClearing {
                round_id: "round-2".to_owned(),
                abort_digest: digest("abort"),
                zero_dispatch_proof_digest: digest("zero-dispatch"),
                authority_digest: digest("release-authority"),
            },
        )
        .is_err());
    let released = reserved.advance(
        &atom,
        ObligationDispositionTransitionV1::ReleaseClearing {
            round_id: "round-1".to_owned(),
            abort_digest: digest("abort"),
            zero_dispatch_proof_digest: digest("zero-dispatch"),
            authority_digest: digest("release-authority"),
        },
    )?;
    assert_eq!(released.disposition(), &ObligationDispositionV1::PerCall);

    let satisfied = reserved.advance(
        &atom,
        ObligationDispositionTransitionV1::SatisfyClearing {
            round_id: "round-1".to_owned(),
            satisfaction_digest: digest("satisfaction"),
            authority_digest: digest("satisfaction-authority"),
        },
    )?;
    assert_eq!(
        satisfied.disposition(),
        &ObligationDispositionV1::ClearingSatisfied {
            round_id: "round-1".to_owned(),
            satisfaction_digest: digest("satisfaction"),
        }
    );
    assert_eq!(satisfied.atom_digest(), reserved.atom_digest());
    assert!(satisfied
        .advance(
            &atom,
            ObligationDispositionTransitionV1::ReleaseClearing {
                round_id: "round-1".to_owned(),
                abort_digest: digest("abort"),
                zero_dispatch_proof_digest: digest("zero-dispatch"),
                authority_digest: digest("release-authority"),
            },
        )
        .is_err());

    let channelized = produced.advance(
        &atom,
        ObligationDispositionTransitionV1::ReserveChannel {
            channel_id: "channel-1".to_owned(),
            reservation_id: "reservation-1".to_owned(),
            authority_digest: digest("channel-authority"),
        },
    )?;
    assert!(channelized
        .advance(
            &atom,
            ObligationDispositionTransitionV1::ReleaseClearing {
                round_id: "round-1".to_owned(),
                abort_digest: digest("abort"),
                zero_dispatch_proof_digest: digest("zero-dispatch"),
                authority_digest: digest("release-authority"),
            },
        )
        .is_err());
    Ok(())
}

#[test]
fn assignment_requires_the_guarded_compare_and_swap() -> TestResult {
    let atom = atom()?;
    let produced = ObligationDispositionRecordV1::produced(&atom)?;
    let original = produced.current_creditor(&atom)?;
    assert_eq!(original.creditor_id(), atom.original_creditor_id());
    assert_eq!(
        original.settlement_destination_ref(),
        atom.original_settlement_destination_ref()
    );

    assert_eq!(
        produced.advance(
            &atom,
            ObligationDispositionTransitionV1::Assign {
                operation_id: digest("assignment-operation"),
                normalized_request_digest: digest("assignment-request"),
                status_proof_digest: digest("assignment-status-proof"),
                agreement_id: "agreement-1".to_owned(),
                creditor_id: "did:chio:factor".to_owned(),
                settlement_destination_ref: "acct:factor".to_owned(),
                authority_digest: digest("assignment-authority"),
            },
        ),
        Err(ObligationError::AssignmentRequiresCompareAndSwap)
    );
    assert_eq!(
        produced.current_creditor(&atom)?.creditor_id(),
        atom.original_creditor_id()
    );
    assert!(produced
        .advance(
            &atom,
            ObligationDispositionTransitionV1::ReserveClearing {
                round_id: "round-1".to_owned(),
                authority_digest: digest("reserve-authority"),
            },
        )
        .is_ok());
    Ok(())
}

#[test]
fn deserialized_assign_transition_cannot_bypass_the_guarded_path() -> TestResult {
    let atom = atom()?;
    let produced = ObligationDispositionRecordV1::produced(&atom)?;
    let transition: ObligationDispositionTransitionV1 = serde_json::from_value(json!({
        "kind": "assign",
        "operation_id": digest("assignment-operation"),
        "normalized_request_digest": digest("assignment-request"),
        "status_proof_digest": digest("assignment-status-proof"),
        "agreement_id": "agreement-1",
        "creditor_id": "did:chio:factor",
        "settlement_destination_ref": "acct:factor",
        "authority_digest": digest("assignment-authority")
    }))?;
    assert_eq!(
        produced.advance(&atom, transition),
        Err(ObligationError::AssignmentRequiresCompareAndSwap)
    );
    Ok(())
}

#[test]
fn persisted_successor_validation_requires_the_exact_transition() -> TestResult {
    let atom = atom()?;
    let produced = ObligationDispositionRecordV1::produced(&atom)?;
    let reserved = produced.advance(
        &atom,
        ObligationDispositionTransitionV1::ReserveClearing {
            round_id: "round-1".to_owned(),
            authority_digest: digest("reserve-authority"),
        },
    )?;
    produced.validate_successor(&atom, &reserved)?;

    let mut changed = serde_json::to_value(&reserved)?;
    changed["lastTransition"]["round_id"] = json!("round-2");
    let changed: ObligationDispositionRecordV1 = serde_json::from_value(changed)?;
    assert_eq!(
        produced.validate_successor(&atom, &changed),
        Err(ObligationError::InvalidField("disposition_transition"))
    );
    assert_eq!(
        reserved.validate_successor(&atom, &reserved),
        Err(ObligationError::InvalidField("disposition_successor"))
    );
    Ok(())
}

#[test]
fn obligation_disposition_rejects_impossible_serialized_heads() -> TestResult {
    let atom = atom()?;
    let produced = ObligationDispositionRecordV1::produced(&atom)?;
    let reserved = produced.advance(
        &atom,
        ObligationDispositionTransitionV1::ReserveClearing {
            round_id: "round-1".to_owned(),
            authority_digest: digest("reserve-authority"),
        },
    )?;

    let mut false_genesis = serde_json::to_value(&reserved)?;
    false_genesis["version"] = json!(1);
    false_genesis["lifecycleFence"] = json!(1);
    let false_genesis: ObligationDispositionRecordV1 = serde_json::from_value(false_genesis)?;
    assert_eq!(
        false_genesis.validate_against(&atom),
        Err(ObligationError::InvalidField("disposition_transition"))
    );

    let mut divergent_fence = serde_json::to_value(&reserved)?;
    divergent_fence["lifecycleFence"] = json!(3);
    let divergent_fence: ObligationDispositionRecordV1 = serde_json::from_value(divergent_fence)?;
    assert_eq!(
        divergent_fence.validate_against(&atom),
        Err(ObligationError::InvalidField("lifecycle_fence"))
    );
    Ok(())
}
