// M05.P5.T3 test body for threat ID `delegation_chain_abuse`.
//
// Threat: delegation_chain_abuse (Delegation chain abuse).
// Surfaces: trust_control, native_chio, hosted_mcp.
//
// Coverage strategy: the M05.P1 corpus carries scope-superset and
// revocation-rollback cases that cite delegation_chain_abuse. The
// scope-superset class exercises the canonical capability-algebra
// invariant that a child grant's scope is a subset of its parent;
// vectors that violate it are DENY-asserted by chio-kernel-core
// and chio-attest-verify. The revocation-rollback class exercises
// the trajectory-2 M04 sparse-Merkle revocation oracle's
// soft-dependency surface: a grant whose parent has been revoked
// must not satisfy a downstream issuance, even if the runtime sees
// a stale revocation snapshot.
//
// algebra-oracle: delegated_scope_is_subset_of_parent

use super::common::{assert_threat_covered_by_corpus, corpus_cases_for};
use chio_adversarial_suite::AttackClass;

#[test]
fn threat_delegation_chain_abuse_is_covered() {
    // covers: delegation_chain_abuse
    assert_threat_covered_by_corpus("delegation_chain_abuse");
}

#[test]
fn threat_delegation_chain_abuse_includes_scope_superset() {
    // covers: delegation_chain_abuse
    //
    // The scope-superset class is the algebra-oracle anchor for
    // this threat: every delegated grant must be a strict subset
    // of its parent. If the class disappears from the threat ID's
    // case set the algebra invariant has lost its corpus binding
    // and the M05 audit doc must be re-pinned.
    let cases = corpus_cases_for("delegation_chain_abuse");
    let has_scope_superset = cases
        .iter()
        .any(|case| case.class == AttackClass::ScopeSuperset);
    assert!(
        has_scope_superset,
        "delegation_chain_abuse must be backed by at least one \
         scope_superset corpus case (algebra-oracle: \
         delegated_scope_is_subset_of_parent)"
    );
}
