// Smoke tests treat a missing or empty corpus directory as a hard failure;
// `unwrap`/`expect` allowed here because the panic IS the test signal.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Smoke tests for libFuzzer targets.
//!
//! Corpus-backed targets get a `<target>_smoke` test that loads their seed
//! corpus and exercises the corresponding entry point, catching panics
//! introduced by upstream changes between scheduled fuzz campaigns.
//!
//! The harness panics if a corpus directory is missing, unreadable, or empty
//! - a renamed directory or typo'd target name would otherwise produce a
//! silent vacuous pass without feeding any bytes through the entry point.
//!
//! The inventory tests below keep this honest: every cargo-fuzz binary must
//! appear in the scheduled workflow matrix, and every scheduled target must
//! be declared either as corpus-smoked here or as intentionally outside this
//! reusable smoke harness.

use std::fs;
use std::path::PathBuf;

const MINIMUM_SEED_COUNT: usize = 3;

const CORPUS_SMOKE_TARGETS: &[&str] = &[
    "a2a_envelope_decode",
    "acp_envelope_decode",
    "anchor_bundle_verify",
    "chio_yaml_parse",
    "did_resolve",
    "eval_receipt_bundle",
    "federation_trust_establishment",
    "jwt_vc_verify",
    "mcp_envelope_decode",
    "oid4vp_presentation",
    "openapi_ingest",
    "receipt_log_replay",
    "underwriting_policy_input",
    "wasm_guard_escape",
    "wasm_guard_smith",
    "wasm_preinstantiate_validate",
    "wit_host_call_boundary",
];

const NO_IN_PROCESS_SMOKE_TARGETS: &[&str] = &[
    "attest_verify",
    "canonical_json",
    "capability_receipt",
    "fuzz_merkle_checkpoint",
    "fuzz_policy_parse_compile",
    "policy_analyze",
    "fuzz_sql_parser",
    "fuzz_tool_action",
    "manifest_roundtrip",
    "revocation_oracle_merkle",
];

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
        processed >= MINIMUM_SEED_COUNT,
        "smoke test for {target} processed {processed} seed files; expected at least {MINIMUM_SEED_COUNT} under fuzz/corpus/{target}/"
    );
}

fn repo_file(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join(path)
}

fn cargo_fuzz_bins() -> Vec<String> {
    let manifest = fs::read_to_string(repo_file("fuzz/Cargo.toml")).unwrap();
    let mut in_bin = false;
    let mut bins = Vec::new();
    for line in manifest.lines() {
        if line.trim() == "[[bin]]" {
            in_bin = true;
            continue;
        }
        if !in_bin {
            continue;
        }
        if let Some(name) = line
            .trim()
            .strip_prefix("name = \"")
            .and_then(|rest| rest.strip_suffix('"'))
        {
            bins.push(name.to_owned());
            in_bin = false;
        }
    }
    bins
}

fn workflow_fuzz_targets() -> Vec<String> {
    let workflow = fs::read_to_string(repo_file(".github/workflows/fuzz.yml")).unwrap();
    let mut targets = Vec::new();
    let mut in_target_matrix = false;
    for line in workflow.lines() {
        if line == "        target:" {
            in_target_matrix = true;
            continue;
        }
        if !in_target_matrix {
            continue;
        }
        if let Some(target) = line.trim().strip_prefix("- ") {
            targets.push(target.to_owned());
            continue;
        }
        if !line.trim().is_empty() {
            break;
        }
    }
    targets
}

fn owners_toml_targets() -> Vec<String> {
    let owners = fs::read_to_string(repo_file("fuzz/owners.toml")).unwrap();
    owners
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("[targets.")
                .and_then(|rest| rest.strip_suffix(']'))
                .map(str::to_owned)
        })
        .collect()
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

#[test]
fn fuzz_workflow_matrix_matches_cargo_bins() {
    assert_eq!(sorted(cargo_fuzz_bins()), sorted(workflow_fuzz_targets()));
}

#[test]
fn owners_toml_covers_all_matrix_targets() {
    assert_eq!(
        sorted(owners_toml_targets()),
        sorted(workflow_fuzz_targets())
    );
}

#[test]
fn all_matrix_targets_meet_seed_floor() {
    for target in workflow_fuzz_targets() {
        let count = each_seed(&target, |_| {});
        assert!(
            count >= MINIMUM_SEED_COUNT,
            "target {target} has {count} seeds; expected at least {MINIMUM_SEED_COUNT}"
        );
    }
}

#[test]
fn all_matrix_targets_have_declared_smoke_posture() {
    let mut declared: Vec<String> = CORPUS_SMOKE_TARGETS
        .iter()
        .chain(NO_IN_PROCESS_SMOKE_TARGETS.iter())
        .map(|target| (*target).to_owned())
        .collect();
    declared.sort();
    declared.dedup();

    assert_eq!(declared, sorted(workflow_fuzz_targets()));

    for target in CORPUS_SMOKE_TARGETS {
        let processed = each_seed(target, |_| {});
        assert!(
            processed >= MINIMUM_SEED_COUNT,
            "corpus-smoked target {target} has {processed} seeds; expected at least {MINIMUM_SEED_COUNT}"
        );
    }
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
fn wasm_guard_escape_smoke() {
    use chio_wasm_guards::fuzz::fuzz_wasm_guard_escape;
    assert_seed_floor("wasm_guard_escape", fuzz_wasm_guard_escape);
}

#[test]
fn wasm_guard_smith_smoke() {
    use chio_wasm_guards::fuzz::fuzz_wasm_guard_smith;
    assert_seed_floor("wasm_guard_smith", fuzz_wasm_guard_smith);
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

#[test]
fn eval_receipt_bundle_smoke() {
    use chio_fuzz::entries::eval_receipt_bundle;
    assert_seed_floor("eval_receipt_bundle", eval_receipt_bundle);
}

#[test]
fn federation_trust_establishment_smoke() {
    use chio_fuzz::entries::federation_trust_establishment;
    assert_seed_floor(
        "federation_trust_establishment",
        federation_trust_establishment,
    );
}

#[test]
fn underwriting_policy_input_smoke() {
    use chio_fuzz::entries::underwriting_policy_input;
    assert_seed_floor("underwriting_policy_input", underwriting_policy_input);
}
