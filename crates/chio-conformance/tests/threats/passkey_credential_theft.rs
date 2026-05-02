// M05.P4.T2 test body for threat ID `passkey_credential_theft`.
//
// Threat: passkey_credential_theft (Passkey credential theft).
// Surfaces: trust_control, native_chio, hosted_mcp.
//
// Coverage strategy: M10.P2 shipped the custody hardware verifier,
// replay-resistant nonce store, revocation cascade, and end-to-end
// passkey capability dispatch tests. This stub pins those evidence
// files so the JSON reclassification cannot outlive the code.

use std::path::PathBuf;

const EVIDENCE_FILES: &[&str] = &[
    "crates/chio-custody-hw/src/verifier.rs",
    "crates/chio-custody-hw/src/nonce_store.rs",
    "crates/chio-custody-hw/src/revocation.rs",
    "crates/chio-custody-hw/tests/replay_resistance.rs",
    "crates/chio-custody-hw/tests/revocation_cascade.rs",
    "crates/chio-custody-hw/tests/end_to_end.rs",
];

fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

#[test]
fn threat_passkey_credential_theft_is_covered() {
    // covers: passkey_credential_theft
    for evidence in EVIDENCE_FILES {
        let path = repo_path(evidence);
        assert!(
            path.is_file(),
            "passkey credential theft evidence file {} must remain in-tree",
            path.display()
        );
    }
}
