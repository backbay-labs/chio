// M05.P5.T3 test body for threat ID `capability_token_theft`.
//
// The codegen pass (M05.P5.T2) will refuse to overwrite this file
// because the body has been populated; re-running
// `chio-spec-codegen --threat-model` is safe.
//
// Threat: capability_token_theft (Capability token theft).
// Surfaces: trust_control, hosted_mcp, native_chio.
//
// Coverage strategy: the M05.P1 adversarial corpus carries
// scope-superset and partial-signature cases that cite this threat
// ID. Each case is DENY-asserted by chio-kernel-core and
// chio-attest-verify in their own integration tests. This stub
// asserts the corpus side of the contract: at least one non-pending
// DENY case in `crates/chio-adversarial-suite/cases/` cites
// `capability_token_theft` and ships a non-empty `expected_reason`.
// The downstream deny-assertion is the kernel-core and attest-verify
// suites; this test fails if the corpus is silently emptied or the
// threat ID is renamed without a coordinated update.

use super::common::{assert_threat_covered_by_corpus, corpus_cases_for};
use chio_adversarial_suite::AttackClass;

#[test]
fn threat_capability_token_theft_is_covered() {
    // covers: capability_token_theft
    assert_threat_covered_by_corpus("capability_token_theft");
}

#[test]
fn threat_capability_token_theft_cites_expected_classes() {
    // covers: capability_token_theft
    //
    // Pin both ScopeSuperset (a stolen token presented with a wider scope
    // than the parent grant authorized) and PartialSignature (a token
    // whose detached signature has been re-targeted) as required attack
    // classes. If either disappears from the threat ID's case set the
    // corpus binding has lost a vector that the M05 audit doc claims and
    // the trajectory-3 advisory reclassification must be re-pinned.
    let cases = corpus_cases_for("capability_token_theft");
    let classes: std::collections::BTreeSet<_> =
        cases.iter().map(|c| format!("{:?}", c.class)).collect();
    assert!(
        cases
            .iter()
            .any(|c| c.class == AttackClass::ScopeSuperset),
        "capability_token_theft must be backed by at least one scope_superset case; got {classes:?}"
    );
    assert!(
        cases
            .iter()
            .any(|c| c.class == AttackClass::PartialSignature),
        "capability_token_theft must be backed by at least one partial_signature case; got {classes:?}"
    );
}
