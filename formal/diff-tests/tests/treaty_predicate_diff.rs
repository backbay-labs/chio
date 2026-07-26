#![cfg(not(target_arch = "wasm32"))]

//! Differential evidence for the bounded treaty predicate fragment.
//!
//! The reference interpreter in `formal/diff-tests` and the production
//! evaluator in `chio-runtime-core` are separate implementations. This test
//! converts shared data only; it does not share an evaluator helper.

use chio_formal_diff_tests::generators::{
    arb_spec_treaty_constitution, arb_spec_treaty_predicate, arb_spec_treaty_receipt_view,
};
use chio_formal_diff_tests::spec::{
    SpecTreatyAdmissionDecision, SpecTreatyConstitution, SpecTreatyEvidenceDigest,
    SpecTreatyPredicate, SpecTreatyPredicateAtom, SpecTreatyReceiptView,
};
use chio_runtime_core::{
    bounded_treaty_constitution_refines_on, evaluate_bounded_treaty_constitution,
    evaluate_bounded_treaty_predicate, BoundedAdmissionDecision, BoundedEvidenceDigest,
    BoundedTreatyConstitution, BoundedTreatyPredicate, BoundedTreatyPredicateAtom,
    BoundedTreatyReceiptView,
};
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 1_024,
        max_shrink_iters: 10_000,
        ..ProptestConfig::default()
    }
}

fn implementation_decision(decision: SpecTreatyAdmissionDecision) -> BoundedAdmissionDecision {
    match decision {
        SpecTreatyAdmissionDecision::Allow => BoundedAdmissionDecision::Allow,
        SpecTreatyAdmissionDecision::Deny => BoundedAdmissionDecision::Deny,
    }
}

fn implementation_evidence(evidence: &SpecTreatyEvidenceDigest) -> BoundedEvidenceDigest {
    BoundedEvidenceDigest {
        evidence_class: evidence.evidence_class.clone(),
        digest: evidence.digest.clone(),
    }
}

fn implementation_receipt(receipt: &SpecTreatyReceiptView) -> BoundedTreatyReceiptView {
    BoundedTreatyReceiptView {
        receipt_id: receipt.receipt_id.clone(),
        receipt_hash: receipt.receipt_hash.clone(),
        action_class: receipt.action_class.clone(),
        participant_kernel_ids: receipt.participant_kernel_ids.clone(),
        ladder_mode_rank: receipt.ladder_mode_rank,
        live_continuation_ids: receipt.live_continuation_ids.clone(),
        decision: implementation_decision(receipt.decision),
        failure_code: receipt.failure_code.clone(),
        evidence_digests: receipt
            .evidence_digests
            .iter()
            .map(implementation_evidence)
            .collect(),
    }
}

fn implementation_atom(atom: &SpecTreatyPredicateAtom) -> BoundedTreatyPredicateAtom {
    match atom {
        SpecTreatyPredicateAtom::ScopeContains(target) => {
            BoundedTreatyPredicateAtom::ScopeContains {
                target: target.clone(),
            }
        }
        SpecTreatyPredicateAtom::ParticipantKernelIdEquals(kernel_id) => {
            BoundedTreatyPredicateAtom::ParticipantKernelIdEquals {
                kernel_id: kernel_id.clone(),
            }
        }
        SpecTreatyPredicateAtom::ActionClassIn(class) => {
            BoundedTreatyPredicateAtom::ActionClassIn {
                class: class.clone(),
            }
        }
        SpecTreatyPredicateAtom::LadderModeAtLeastRank(rank) => {
            BoundedTreatyPredicateAtom::LadderModeAtLeastRank { rank: *rank }
        }
        SpecTreatyPredicateAtom::ReceiptHashEquals(hash) => {
            BoundedTreatyPredicateAtom::ReceiptHashEquals { hash: hash.clone() }
        }
        SpecTreatyPredicateAtom::ContinuationLive(continuation_id) => {
            BoundedTreatyPredicateAtom::ContinuationLive {
                continuation_id: continuation_id.clone(),
            }
        }
        SpecTreatyPredicateAtom::DecisionEquals(decision) => {
            BoundedTreatyPredicateAtom::DecisionEquals {
                decision: implementation_decision(*decision),
            }
        }
        SpecTreatyPredicateAtom::FailureCodeEquals(code) => {
            BoundedTreatyPredicateAtom::FailureCodeEquals { code: code.clone() }
        }
        SpecTreatyPredicateAtom::EvidenceDigestEquals {
            evidence_class,
            digest,
        } => BoundedTreatyPredicateAtom::EvidenceDigestEquals {
            evidence_class: evidence_class.clone(),
            digest: digest.clone(),
        },
    }
}

fn implementation_predicate(predicate: &SpecTreatyPredicate) -> BoundedTreatyPredicate {
    match predicate {
        SpecTreatyPredicate::Atom(atom) => BoundedTreatyPredicate::Atom {
            atom: implementation_atom(atom),
        },
        SpecTreatyPredicate::Top => BoundedTreatyPredicate::Top,
        SpecTreatyPredicate::Bot => BoundedTreatyPredicate::Bot,
        SpecTreatyPredicate::Conj(left, right) => BoundedTreatyPredicate::Conj {
            left: Box::new(implementation_predicate(left)),
            right: Box::new(implementation_predicate(right)),
        },
        SpecTreatyPredicate::Disj(left, right) => BoundedTreatyPredicate::Disj {
            left: Box::new(implementation_predicate(left)),
            right: Box::new(implementation_predicate(right)),
        },
        SpecTreatyPredicate::Neg(predicate) => BoundedTreatyPredicate::Neg {
            predicate: Box::new(implementation_predicate(predicate)),
        },
    }
}

fn implementation_constitution(constitution: &SpecTreatyConstitution) -> BoundedTreatyConstitution {
    BoundedTreatyConstitution {
        predicates: constitution
            .predicates
            .iter()
            .map(implementation_predicate)
            .collect(),
    }
}

#[test]
fn treaty_predicate_diff_each_atom_has_a_matching_case() {
    let receipt = SpecTreatyReceiptView {
        receipt_id: "receipt-a".to_string(),
        receipt_hash: "hash-a".to_string(),
        action_class: "workflow.destructive.vendor_call".to_string(),
        participant_kernel_ids: vec![
            "kernel-a".to_string(),
            "kernel-a".to_string(),
            "kernel-b".to_string(),
        ],
        ladder_mode_rank: 2,
        live_continuation_ids: vec![
            "continuation-live".to_string(),
            "continuation-live".to_string(),
        ],
        decision: SpecTreatyAdmissionDecision::Deny,
        failure_code: Some("chio_treaty_stale".to_string()),
        evidence_digests: vec![
            SpecTreatyEvidenceDigest {
                evidence_class: "bilateral_dsse".to_string(),
                digest: "hash-a".to_string(),
            },
            SpecTreatyEvidenceDigest {
                evidence_class: "bilateral_dsse".to_string(),
                digest: "hash-a".to_string(),
            },
        ],
    };
    let atoms = [
        SpecTreatyPredicateAtom::ScopeContains(receipt.receipt_id.clone()),
        SpecTreatyPredicateAtom::ParticipantKernelIdEquals("kernel-b".to_string()),
        SpecTreatyPredicateAtom::ActionClassIn(receipt.action_class.clone()),
        SpecTreatyPredicateAtom::LadderModeAtLeastRank(2),
        SpecTreatyPredicateAtom::ReceiptHashEquals(receipt.receipt_hash.clone()),
        SpecTreatyPredicateAtom::ContinuationLive("continuation-live".to_string()),
        SpecTreatyPredicateAtom::DecisionEquals(SpecTreatyAdmissionDecision::Deny),
        SpecTreatyPredicateAtom::FailureCodeEquals("chio_treaty_stale".to_string()),
        SpecTreatyPredicateAtom::EvidenceDigestEquals {
            evidence_class: "bilateral_dsse".to_string(),
            digest: "hash-a".to_string(),
        },
    ];
    let implementation_receipt = implementation_receipt(&receipt);
    for atom in atoms {
        let predicate = SpecTreatyPredicate::Atom(atom);
        assert!(predicate.denote(&receipt));
        assert!(evaluate_bounded_treaty_predicate(
            &implementation_predicate(&predicate),
            &implementation_receipt
        ));
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn treaty_predicate_diff_denotation_agrees(
        predicate in arb_spec_treaty_predicate(),
        receipt in arb_spec_treaty_receipt_view(),
    ) {
        let expected = predicate.denote(&receipt);
        let actual = evaluate_bounded_treaty_predicate(
            &implementation_predicate(&predicate),
            &implementation_receipt(&receipt),
        );
        prop_assert_eq!(actual, expected);
    }

    #[test]
    fn treaty_predicate_diff_constitution_agrees(
        constitution in arb_spec_treaty_constitution(),
        receipt in arb_spec_treaty_receipt_view(),
    ) {
        let expected = constitution.admits(&receipt);
        let actual = evaluate_bounded_treaty_constitution(
            &implementation_constitution(&constitution),
            &implementation_receipt(&receipt),
        );
        prop_assert_eq!(actual, expected);
    }

    #[test]
    fn treaty_predicate_diff_finite_refinement_agrees(
        new in arb_spec_treaty_constitution(),
        old in arb_spec_treaty_constitution(),
        domain in prop::collection::vec(arb_spec_treaty_receipt_view(), 0..8),
    ) {
        let expected = new.refines_on(&old, &domain);
        let implementation_domain: Vec<_> =
            domain.iter().map(implementation_receipt).collect();
        let actual = bounded_treaty_constitution_refines_on(
            &implementation_constitution(&new),
            &implementation_constitution(&old),
            &implementation_domain,
        );
        prop_assert_eq!(actual, expected);
    }
}
