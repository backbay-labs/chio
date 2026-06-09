use std::collections::{BTreeMap, BTreeSet};

use chio_adversarial_suite::{bundled_cases, AttackClass, CaseError, ExpectedVerdict};

const ATTEST_CLASSES: &[AttackClass] = &[
    AttackClass::AnchorGrafted,
    AttackClass::SigstoreBundlePayloadMismatch,
];

#[test]
fn attest_verify_adversarial_suite_answer_key_denies_attestation_classes() -> Result<(), CaseError>
{
    // Load raw bundled cases and filter to ATTEST_CLASSES first so this gate
    // does not couple to pending vectors in unrelated attack classes (which
    // would otherwise fail `into_coverage_case` and break this test for
    // reasons outside attest-verify's scope).
    let cases = bundled_cases()?;
    let mut counts = BTreeMap::<AttackClass, usize>::new();
    let expected_classes = ATTEST_CLASSES.iter().copied().collect::<BTreeSet<_>>();

    for case in cases {
        if !expected_classes.contains(&case.class) {
            continue;
        }
        // In-scope attestation cases must not be pending; coverage eligibility
        // is enforced after class filtering.
        let coverage_case = case.into_coverage_case()?;
        let case = coverage_case.as_case();

        assert_eq!(
            case.expected_verdict,
            ExpectedVerdict::Deny,
            "attestation adversarial case {} must deny",
            case.id
        );
        assert!(
            !case.expected_reason.trim().is_empty(),
            "attestation adversarial case {} must pin a deny reason",
            case.id
        );
        assert!(
            !case.threat_id.trim().is_empty(),
            "attestation adversarial case {} must cite a threat",
            case.id
        );
        assert!(
            case.artifact
                .as_object()
                .is_some_and(|object| !object.is_empty()),
            "attestation adversarial case {} must carry a non-empty artifact",
            case.id
        );

        *counts.entry(case.class).or_default() += 1;
    }

    for class in ATTEST_CLASSES {
        assert_eq!(
            counts.get(class).copied().unwrap_or_default(),
            5,
            "attestation adversarial class {} should have five vectors",
            class.as_str()
        );
    }

    Ok(())
}
