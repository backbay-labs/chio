use std::collections::{BTreeMap, BTreeSet};

use chio_adversarial_suite::{bundled_coverage_cases, AttackClass, CaseError, ExpectedVerdict};

const KERNEL_CLASSES: &[AttackClass] = &[
    AttackClass::ClockRewound,
    AttackClass::FutureDated,
    AttackClass::ReplayedNonce,
    AttackClass::PartialSignature,
    AttackClass::ScopeSuperset,
    AttackClass::RevocationRollback,
    AttackClass::AnchorGrafted,
];

#[test]
fn kernel_core_adversarial_suite_answer_key_denies_kernel_classes() -> Result<(), CaseError> {
    let cases = bundled_coverage_cases()?;
    let mut counts = BTreeMap::<AttackClass, usize>::new();
    let expected_classes = KERNEL_CLASSES.iter().copied().collect::<BTreeSet<_>>();

    for coverage_case in cases {
        let case = coverage_case.as_case();
        if !expected_classes.contains(&case.class) {
            continue;
        }

        assert_eq!(
            case.expected_verdict,
            ExpectedVerdict::Deny,
            "kernel adversarial case {} must deny",
            case.id
        );
        assert!(
            !case.expected_reason.trim().is_empty(),
            "kernel adversarial case {} must pin a deny reason",
            case.id
        );
        assert!(
            case.artifact
                .as_object()
                .is_some_and(|object| !object.is_empty()),
            "kernel adversarial case {} must carry a non-empty artifact",
            case.id
        );

        *counts.entry(case.class).or_default() += 1;
    }

    for class in KERNEL_CLASSES {
        assert_eq!(
            counts.get(class).copied().unwrap_or_default(),
            5,
            "kernel adversarial class {} should have five vectors",
            class.as_str()
        );
    }

    Ok(())
}
