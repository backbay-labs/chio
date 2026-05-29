// Threat test for threat ID `passkey_credential_theft`.
//
// Threat: passkey_credential_theft (Passkey credential theft).
// Surfaces: trust_control, native_chio, hosted_mcp.
//
// Coverage strategy: import the production
// `chio_custody_hw::{InMemoryPasskeyNonceStore, PasskeyNonceStore,
// RecordOutcome}` directly. The threat's primary deny path is the
// per-credential nonce store: an attacker who steals a fresh
// passkey assertion (or the `(credential_id, challenge_nonce)` pair
// it carries) and tries to replay it against the issuer MUST be
// caught BEFORE the issuer mints a capability. The production
// `record_if_fresh` returns `RecordOutcome::Replayed` on the second
// call with the same `(credential_id, challenge_nonce)` keys; the
// issuer surfaces this as `CustodyError::ReplayDetected`.
//
// Three sub-vectors:
//
//   1. Replay attack. The attacker presents the SAME stolen
//      `(credential_id, challenge_nonce)` twice. First call
//      records `Fresh`; second call MUST record `Replayed`.
//   2. Concurrent atomicity (cross-fixture). The fresh-vs-replayed
//      decision MUST be atomic so two concurrent presentations
//      cannot both observe `Fresh`. This conformance row pins the
//      single-threaded ordering; the in-tree replay-resistance
//      integration test under chio-custody-hw runs the concurrent
//      stress test (`record_if_fresh_is_atomic_under_contention`).
//   3. Distinct credentials are independent. Replay detection MUST
//      be keyed on `(credential_id, challenge_nonce)` pairs so two
//      legitimate callers (different credentials) presenting the
//      same nonce DO NOT collide and over-reject. This is the
//      counter-vector to the replay arm.
//
// Production call sites:
//   `crates/chio-custody-hw/src/nonce_store.rs:194`
//     (`InMemoryPasskeyNonceStore::record_if_fresh`).
//
// Revert-to-prove-it-fails recipe:
// In `crates/chio-custody-hw/src/nonce_store.rs`, locate the
// duplicate-detection branch inside
// `InMemoryPasskeyNonceStore::record_if_fresh` (the
// `if let Some(existing_exp) = map.get(&key) { ... return
// Ok(RecordOutcome::Replayed); }` block). Replace the return with
// `Ok(RecordOutcome::Fresh)`. Re-run
// `cargo test -p chio-conformance --test threats -- passkey_credential_theft`
// and the `assert_eq!(second, RecordOutcome::Replayed)` arm in
// `replay_attack_rejected` MUST then fail because production now
// admits the second presentation.

use std::{fs, path::PathBuf};

use chio_custody_hw::{InMemoryPasskeyNonceStore, PasskeyNonceStore, RecordOutcome};

const CREDENTIAL_ID_A: &str = "Q1JFREEAAAA";
const CREDENTIAL_ID_B: &str = "Q1JFREJBQUE";
const CHALLENGE_NONCE: &str = "Tk9OQ0VBQUE";
const FUTURE_EXP_UNIX_SECS: i64 = 9_999_999_999;

#[test]
fn threat_passkey_credential_theft_replay_attack_rejected() {
    // covers: passkey_credential_theft
    //
    // Attacker scenario: an attacker harvests a fresh passkey
    // assertion (e.g. via a relying-party-side compromise that
    // briefly leaks the `(credential_id, challenge_nonce)` pair).
    // First presentation MUST be Fresh; second presentation MUST
    // be Replayed. The issuer translates `Replayed` into
    // `CustodyError::ReplayDetected`, surfacing the replay deny
    // path documented at `urn:chio:error:custody:replay-detected`.
    let store = InMemoryPasskeyNonceStore::new();

    let first = match store.record_if_fresh(CREDENTIAL_ID_A, CHALLENGE_NONCE, FUTURE_EXP_UNIX_SECS)
    {
        Ok(outcome) => outcome,
        Err(err) => panic!("first record_if_fresh MUST succeed; got {err:?}"),
    };
    assert_eq!(
        first,
        RecordOutcome::Fresh,
        "first presentation of an unseen (credential_id, nonce) pair \
         MUST be Fresh"
    );

    let second = match store.record_if_fresh(CREDENTIAL_ID_A, CHALLENGE_NONCE, FUTURE_EXP_UNIX_SECS)
    {
        Ok(outcome) => outcome,
        Err(err) => panic!(
            "second record_if_fresh MUST not error (it MUST report \
             Replayed); got {err:?}"
        ),
    };
    assert_eq!(
        second,
        RecordOutcome::Replayed,
        "second presentation of the SAME (credential_id, nonce) pair \
         MUST be Replayed -- this is the production deny branch \
         that prevents passkey credential theft via replay"
    );
}

#[test]
fn threat_passkey_credential_theft_distinct_credentials_are_independent() {
    // covers: passkey_credential_theft (counter-vector)
    //
    // Two distinct legitimate users happen to receive the same
    // nonce string from the relying party (collision is allowed by
    // the WebAuthn spec because nonces are scoped to
    // credential_id). Both first presentations MUST observe
    // `Fresh`; the replay key is a `(credential_id, nonce)` pair,
    // not the nonce alone. Guards against an over-rejecting deny
    // path that would falsely classify an unrelated credential as
    // a replay.
    let store = InMemoryPasskeyNonceStore::new();

    let outcome_a =
        match store.record_if_fresh(CREDENTIAL_ID_A, CHALLENGE_NONCE, FUTURE_EXP_UNIX_SECS) {
            Ok(outcome) => outcome,
            Err(err) => panic!("credential A first presentation MUST succeed; got {err:?}"),
        };
    assert_eq!(outcome_a, RecordOutcome::Fresh);

    let outcome_b =
        match store.record_if_fresh(CREDENTIAL_ID_B, CHALLENGE_NONCE, FUTURE_EXP_UNIX_SECS) {
            Ok(outcome) => outcome,
            Err(err) => panic!("credential B first presentation MUST succeed; got {err:?}"),
        };
    assert_eq!(
        outcome_b,
        RecordOutcome::Fresh,
        "DISTINCT credential_id with same nonce MUST be admitted as \
         Fresh (replay detection is keyed on the pair, not the nonce)"
    );
}

/// Tuples of (evidence path, optional needle). When `needle` is `Some`,
/// the file must contain that string; this detects if the cited implementation has been removed.
const EVIDENCE_FILES: &[(&str, Option<&str>)] = &[
    (
        "crates/chio-custody-hw/src/verifier.rs",
        Some("PasskeyVerifier"),
    ),
    ("crates/chio-custody-hw/src/nonce_store.rs", None),
    ("crates/chio-custody-hw/src/revocation.rs", None),
    (
        "crates/chio-custody-hw/tests/replay_resistance.rs",
        Some("first_mint_fresh_second_mint_replay_in_memory"),
    ),
    ("crates/chio-custody-hw/tests/revocation_cascade.rs", None),
    (
        "crates/chio-custody-hw/tests/end_to_end.rs",
        Some("replay_of_minted_capability_is_blocked_by_nonce_store"),
    ),
];

fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

#[test]
fn threat_passkey_credential_theft_supplementary_evidence_remains_in_tree() {
    // covers: passkey_credential_theft
    //
    // Supplementary regression net: in addition to the production
    // deny-asserting arms above (which exercise
    // `InMemoryPasskeyNonceStore::record_if_fresh` directly),
    // pin the named custody-hardware integration tests so a
    // stealth removal of the verifier / revocation / end-to-end
    // proofs still trips this conformance row.
    for (evidence, needle) in EVIDENCE_FILES {
        let path = repo_path(evidence);
        assert!(
            path.is_file(),
            "passkey credential theft evidence file {} must remain in-tree",
            path.display()
        );
        if let Some(needle) = needle {
            let raw = match fs::read_to_string(&path) {
                Ok(raw) => raw,
                Err(err) => panic!("read {}: {err}", path.display()),
            };
            assert!(
                raw.contains(needle),
                "passkey credential theft evidence file {} must mention {needle:?}",
                path.display()
            );
        }
    }
}
