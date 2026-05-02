// M05.P4.T1 test body for threat ID `tee_quote_forgery`.
//
// Threat: tee_quote_forgery (TEE quote forgery or misbinding).
// Surfaces: hosted_mcp, native_chio.
//
// Coverage strategy: chio-attest-verify owns the quote validators and
// fixture suites for Nitro, TDX, and SEV-SNP. This stub pins those
// evidence files plus the kernel self-quote gate that refuses to load
// PQ signing material until verified runtime evidence binds the key.

use std::path::PathBuf;

const EVIDENCE_FILES: &[&str] = &[
    "crates/chio-attest-verify/tests/cross_backend_conformance.rs",
    "crates/chio-attest-verify/tests/expect_report_data.rs",
    "crates/chio-attest-verify/tests/tdx_integration.rs",
    "crates/chio-attest-verify/tests/sev_snp_integration.rs",
    "crates/chio-attest-verify/tests/nitro_unit.rs",
    "crates/chio-attest-verify/tests/nitro_root_rotation.rs",
    "crates/chio-kernel/tests/pq_key_load_after_self_quote.rs",
];

fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

#[test]
fn threat_tee_quote_forgery_is_covered() {
    // covers: tee_quote_forgery
    for evidence in EVIDENCE_FILES {
        let path = repo_path(evidence);
        assert!(
            path.is_file(),
            "TEE quote forgery evidence file {} must remain in-tree",
            path.display()
        );
    }
}

#[test]
fn threat_tee_quote_forgery_pins_self_quote_gate() {
    // covers: tee_quote_forgery
    let path = repo_path("crates/chio-kernel/tests/pq_key_load_after_self_quote.rs");
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) => panic!("read {}: {error}", path.display()),
    };
    assert!(
        raw.contains("allow_hybrid_loads_pq_only_after_verified_self_quote"),
        "self-quote gate evidence must stay pinned for tee_quote_forgery"
    );
}
