// M05.P5.T3 test body for threat ID `native_channel_replay`.
//
// Threat: native_channel_replay (Replay attacks on the native channel).
// Surfaces: native_chio.
//
// Coverage strategy: the M05.P1 corpus carries replayed-nonce,
// clock-rewound, future-dated, and anchor-grafted cases that all
// cite this threat ID. The first three exercise pure replay
// scenarios on the native framed lane (resubmitting a sender-proof
// nonce, presenting a credential whose iat / nbf is in the past or
// future relative to the verifier's clock); anchor-grafted cases
// exercise the receipt-side replay vector (lifting a checkpoint
// signature from one trace and grafting it onto a forged trace).
// All deny-assert at chio-kernel-core and chio-attest-verify; this
// test asserts the corpus side of the contract.

use super::common::{assert_threat_covered_by_corpus, corpus_cases_for};

#[test]
fn threat_native_channel_replay_is_covered() {
    // covers: native_channel_replay
    assert_threat_covered_by_corpus("native_channel_replay");
}

#[test]
fn threat_native_channel_replay_has_multiple_classes() {
    // covers: native_channel_replay
    //
    // Replay on the native channel is intentionally backed by more
    // than one attack class so a single class regression does not
    // strip threat coverage entirely. Assert at least two distinct
    // classes are present.
    let cases = corpus_cases_for("native_channel_replay");
    let classes: std::collections::BTreeSet<_> =
        cases.iter().map(|c| format!("{:?}", c.class)).collect();
    assert!(
        classes.len() >= 2,
        "native_channel_replay must be backed by at least two attack classes; got {:?}",
        classes
    );
}
