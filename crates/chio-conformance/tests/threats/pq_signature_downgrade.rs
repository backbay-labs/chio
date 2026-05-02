// M05.P4.T1 test body for threat ID `pq_signature_downgrade`.
//
// Threat: pq_signature_downgrade (Post-quantum signature downgrade).
// Surfaces: trust_control, hosted_mcp, native_chio.
//
// Coverage strategy: the migration and kernel signing suites now
// exercise the crypto-floor transition. This stub pins the evidence
// paths and function names that reject classical-only artifacts under
// pq_required and only load PQ signing material after a verified
// self-quote binds the runtime.

use std::{fs, path::PathBuf};

fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn assert_file_contains(relative: &str, needle: &str) {
    let path = repo_path(relative);
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) => panic!("read {}: {error}", path.display()),
    };
    assert!(
        raw.contains(needle),
        "{} must contain evidence function {needle}",
        path.display()
    );
}

#[test]
fn threat_pq_signature_downgrade_is_covered() {
    // covers: pq_signature_downgrade
    assert_file_contains(
        "crates/chio-attest-verify/tests/migration.rs",
        "stage3_pq_required_accepts_rolled_hybrid_and_rejects_v318_bundle",
    );
    assert_file_contains(
        "crates/chio-attest-verify/tests/v318_migration.rs",
        "v318_fixture_rejected_under_pq_required",
    );
    assert_file_contains(
        "crates/chio-kernel/tests/pq_key_load_after_self_quote.rs",
        "rejected_self_quote_refuses_to_load_pq_key",
    );
    assert_file_contains(
        "crates/chio-kernel/tests/hybrid_receipt_sign.rs",
        "pq_required_with_seed_constructs_hybrid_backend",
    );
}
