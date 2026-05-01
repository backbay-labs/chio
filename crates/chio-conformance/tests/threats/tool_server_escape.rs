// M05.P5.T3 test body for threat ID `tool_server_escape`.
//
// Threat: tool_server_escape (Tool server escape).
// Surfaces: kernel_to_tool.
//
// Coverage strategy: tool-server escape is exercised by two
// disjoint M05 surfaces.
//
// 1. The chio-adversarial-suite corpus carries a
//    `sigstore_bundle_payload_mismatch` case that cites this threat
//    ID; it represents a tool / guard module whose bundle subject
//    digest does not match the loaded payload digest, which is the
//    signed-but-malicious lane for escapes that bypass the kernel
//    by impersonating an approved tool module.
//
// 2. The M05.P3 wasm-guard escape harness ships eight named escape
//    classes that all yield typed `WasmGuardError` outcomes; that
//    harness is the runtime side of the same threat ID and is wired
//    through `cargo test -p chio-wasm-guards --test escape`.
//
// This test asserts the corpus side, plus that the
// chio-wasm-guards escape harness directory is present in-tree as
// the runtime evidence pointer. Failing this test means either the
// corpus was emptied or the escape harness was removed; either is
// a coordinated change that must update this assertion.

use std::path::PathBuf;

use super::common::{assert_threat_covered_by_corpus, corpus_cases_for};
use chio_adversarial_suite::AttackClass;

#[test]
fn threat_tool_server_escape_is_covered() {
    // covers: tool_server_escape
    assert_threat_covered_by_corpus("tool_server_escape");
}

#[test]
fn threat_tool_server_escape_includes_signed_but_malicious() {
    // covers: tool_server_escape
    let cases = corpus_cases_for("tool_server_escape");
    let has_bundle_mismatch = cases
        .iter()
        .any(|case| case.class == AttackClass::SigstoreBundlePayloadMismatch);
    assert!(
        has_bundle_mismatch,
        "tool_server_escape must be backed by at least one \
         sigstore_bundle_payload_mismatch corpus case"
    );
}

#[test]
fn threat_tool_server_escape_runtime_harness_is_present() {
    // covers: tool_server_escape
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let escape_dir = manifest_dir
        .join("../chio-wasm-guards/tests/escape")
        .canonicalize();
    assert!(
        escape_dir.is_ok(),
        "expected wasm-guard escape harness directory to be present in-tree"
    );
}
