// Smoke tests treat a missing or empty corpus directory as a hard failure;
// `unwrap`/`expect` allowed here because the panic IS the test signal.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Smoke tests for libFuzzer targets.
//!
//! Each target gets a `<target>_smoke` test that loads its seed corpus and
//! exercises the corresponding entry point, catching panics introduced by
//! upstream changes between scheduled fuzz campaigns.
//!
//! The harness panics if a corpus directory is missing, unreadable, or empty
//! - a renamed directory or typo'd target name would otherwise produce a
//! silent vacuous pass without feeding any bytes through the entry point.

use std::fs;
use std::path::PathBuf;

/// Resolve a seed-corpus directory by target name. Lives under
/// `<CARGO_MANIFEST_DIR>/corpus/<name>` per the cargo-fuzz layout.
fn corpus_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join(name)
}

fn each_seed<F: FnMut(&[u8])>(target: &str, mut f: F) -> usize {
    let dir = corpus_dir(target);
    assert!(
        dir.is_dir(),
        "corpus directory missing for target {target}: {}",
        dir.display()
    );
    let entries = fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("read_dir({}) failed: {err}", dir.display()));
    let mut count: usize = 0;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => panic!("corpus entry error in {}: {err}", dir.display()),
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let bytes =
            fs::read(&path).unwrap_or_else(|err| panic!("read({}) failed: {err}", path.display()));
        f(&bytes);
        count += 1;
    }
    count
}

fn assert_seed_floor<F: FnMut(&[u8])>(target: &str, f: F) {
    let processed = each_seed(target, f);
    assert!(
        processed > 0,
        "smoke test for {target} processed zero seed files; corpus dir is empty (expected at least one .bin under fuzz/corpus/{target}/)"
    );
}

#[test]
fn jwt_vc_verify_smoke() {
    use chio_credentials::fuzz::fuzz_jwt_vc_verify;
    assert_seed_floor("jwt_vc_verify", fuzz_jwt_vc_verify);
}

#[test]
fn oid4vp_presentation_smoke() {
    use chio_credentials::fuzz::fuzz_oid4vp_presentation;
    assert_seed_floor("oid4vp_presentation", fuzz_oid4vp_presentation);
}

#[test]
fn did_resolve_smoke() {
    use chio_did::fuzz::fuzz_did_resolve;
    assert_seed_floor("did_resolve", fuzz_did_resolve);
}

#[test]
fn anchor_bundle_verify_smoke() {
    use chio_anchor::fuzz::fuzz_anchor_bundle_verify;
    assert_seed_floor("anchor_bundle_verify", fuzz_anchor_bundle_verify);
}

#[test]
fn mcp_envelope_decode_smoke() {
    use chio_mcp_edge::fuzz::fuzz_mcp_envelope_decode;
    assert_seed_floor("mcp_envelope_decode", fuzz_mcp_envelope_decode);
}

#[test]
fn a2a_envelope_decode_smoke() {
    use chio_a2a_adapter::fuzz::fuzz_a2a_envelope_decode;
    assert_seed_floor("a2a_envelope_decode", fuzz_a2a_envelope_decode);
}

#[test]
fn acp_envelope_decode_smoke() {
    use chio_acp_edge::fuzz::fuzz_acp_envelope_decode;
    assert_seed_floor("acp_envelope_decode", fuzz_acp_envelope_decode);
}

#[test]
fn wasm_preinstantiate_validate_smoke() {
    use chio_wasm_guards::fuzz::fuzz_wasm_preinstantiate_validate;
    assert_seed_floor(
        "wasm_preinstantiate_validate",
        fuzz_wasm_preinstantiate_validate,
    );
}

#[test]
fn wit_host_call_boundary_smoke() {
    use chio_wasm_guards::fuzz::fuzz_wit_host_call_boundary;
    assert_seed_floor("wit_host_call_boundary", fuzz_wit_host_call_boundary);
}

#[test]
fn chio_yaml_parse_smoke() {
    use chio_config::fuzz::fuzz_chio_yaml_parse;
    assert_seed_floor("chio_yaml_parse", fuzz_chio_yaml_parse);
}

#[test]
fn openapi_ingest_smoke() {
    use chio_openapi_mcp_bridge::fuzz::fuzz_openapi_ingest;
    assert_seed_floor("openapi_ingest", fuzz_openapi_ingest);
}

#[test]
fn receipt_log_replay_smoke() {
    use chio_kernel_core::fuzz::fuzz_receipt_log_replay;
    assert_seed_floor("receipt_log_replay", fuzz_receipt_log_replay);
}
