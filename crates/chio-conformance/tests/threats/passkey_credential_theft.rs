// M05.P4.T2 test body for threat ID `passkey_credential_theft`.
//
// Threat: passkey_credential_theft (Passkey credential theft).
// Surfaces: trust_control, native_chio, hosted_mcp.
//
// Coverage strategy: M10.P2 shipped the custody hardware verifier,
// replay-resistant nonce store, revocation cascade, and end-to-end
// passkey capability dispatch tests. This stub pins those evidence
// files so the JSON reclassification cannot outlive the code.

use std::{fs, path::PathBuf};

/// Tuples of (evidence path, optional needle). When `needle` is `Some`,
/// the file must additionally contain that string; this guards against
/// the file being kept as a no-op stub while the cited functionality
/// has been gutted. When `needle` is `None`, only file existence is
/// pinned (used for source modules whose internal symbols are not part
/// of the M10.P2 stable contract).
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
fn threat_passkey_credential_theft_is_covered() {
    // covers: passkey_credential_theft
    //
    // Pin the M10.P2 custody-hardware evidence: file existence plus
    // the named test functions and verifier type the coverage.yaml
    // closure cites. A bare existence check is not enough because
    // the cited tests are the failure-path exercise; if either is
    // renamed without updating this pin the threat closure must be
    // re-audited.
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
