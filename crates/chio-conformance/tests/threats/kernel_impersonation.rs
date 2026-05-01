// M05.P5.T3 test body for threat ID `kernel_impersonation`.
//
// Threat: kernel_impersonation (Kernel impersonation).
// Surfaces: hosted_mcp, native_chio.
//
// Coverage strategy: the M05.P1 corpus carries anchor-grafted and
// partial-signature cases that cite kernel_impersonation; these
// vectors exercise forged checkpoint signatures and incomplete
// quorum signatures that a forged kernel could try to present as
// authentic. The corpus DENY-asserts those cases through the
// chio-attest-verify integration test; this stub asserts the
// pinning side: that at least one anchor-grafted case is a
// non-pending DENY case that cites this threat ID.

use super::common::{assert_threat_covered_by_corpus, corpus_cases_for};
use chio_adversarial_suite::AttackClass;

#[test]
fn threat_kernel_impersonation_is_covered() {
    // covers: kernel_impersonation
    assert_threat_covered_by_corpus("kernel_impersonation");
}

#[test]
fn threat_kernel_impersonation_includes_anchor_grafted() {
    // covers: kernel_impersonation
    //
    // The anchor-grafted attack class is the canonical
    // kernel-impersonation vector: a receipt root whose checkpoint
    // signature was lifted from a different kernel and grafted onto
    // a forged trace. If this class disappears from the threat ID's
    // case set the test fails so the M05 audit doc and the threat
    // taxonomy stay in sync.
    let cases = corpus_cases_for("kernel_impersonation");
    let has_anchor_grafted = cases
        .iter()
        .any(|case| case.class == AttackClass::AnchorGrafted);
    assert!(
        has_anchor_grafted,
        "kernel_impersonation must be backed by at least one anchor-grafted case"
    );
}
