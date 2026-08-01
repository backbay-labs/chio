#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use chio_conformance::capture_runtime_revocation_trace;

const EXPECTED_FIXTURES: usize = 50;

#[test]
fn replay_manifest_corpus_exercises_real_runtime_trace_boundaries() {
    let root = workspace_root();
    let fixtures = collect_fixture_files(&root.join("tests/replay/fixtures"));
    assert_eq!(fixtures.len(), EXPECTED_FIXTURES);

    let mut names = BTreeSet::new();
    let mut seed_indices = BTreeSet::new();
    for fixture in fixtures {
        let bytes = fs::read(&fixture).expect("read replay manifest");
        let manifest: serde_json::Value =
            serde_json::from_slice(&bytes).expect("parse replay manifest");
        let name = manifest
            .get("name")
            .and_then(serde_json::Value::as_str)
            .expect("manifest name");
        let seed_index = manifest
            .get("fixed_nonce_seed_index")
            .and_then(serde_json::Value::as_u64)
            .expect("manifest seed index");
        assert!(names.insert(name.to_string()), "duplicate manifest name");
        assert!(seed_indices.insert(seed_index), "duplicate seed index");

        let context = format!("{name}:{}", chio_core::sha256_hex(&bytes));
        let (trace, observer_key) =
            capture_runtime_revocation_trace(&context).expect("capture runtime trace");
        let decoded = chio_trace_validate::decode_observations(&trace, &[observer_key])
            .expect("decode captured trace");
        let chio_trace_validate::ObservationEvent::Revoke {
            capability_id: revoked_ancestor,
            ..
        } = &decoded.observations()[1].body.event
        else {
            panic!("second observation is not a revocation");
        };
        let chio_trace_validate::ObservationEvent::Evaluate {
            receipt,
            revocation_subject_ids,
            revocation_source_id,
            ..
        } = &decoded.observations()[2].body.event
        else {
            panic!("third observation is not an evaluation");
        };
        assert_ne!(&receipt.capability_id, revoked_ancestor);
        assert_eq!(
            revocation_subject_ids,
            &[receipt.capability_id.clone(), revoked_ancestor.clone()]
        );
        assert_eq!(revocation_source_id.as_ref(), Some(revoked_ancestor));
        let projection = chio_trace_validate::project_revocation_trace(&decoded)
            .expect("project captured trace");
        assert_eq!(projection.events().len(), 3);
        assert_eq!(projection.action_coverage().revoke, 1);
        assert_eq!(projection.action_coverage().evaluate, 2);
        assert_eq!(projection.action_coverage().post_revocation_evaluate, 1);
        let witnesses = projection.invariant_witnesses();
        assert!(witnesses.allow_receipt >= 1);
        assert!(witnesses.ordered_receipt_pair >= 1);
        assert!(witnesses.attenuated_admission >= 1);
        assert!(witnesses.nonzero_revocation_epoch >= 1);
    }

    assert_eq!(names.len(), EXPECTED_FIXTURES);
    assert_eq!(
        seed_indices,
        (0..EXPECTED_FIXTURES as u64).collect::<BTreeSet<_>>()
    );
}

fn collect_fixture_files(root: &Path) -> Vec<PathBuf> {
    fn visit(path: &Path, output: &mut Vec<PathBuf>) {
        let metadata = fs::symlink_metadata(path).expect("fixture metadata");
        assert!(
            !metadata.file_type().is_symlink(),
            "fixture symlink rejected"
        );
        if metadata.is_file() {
            if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
                output.push(path.to_path_buf());
            }
            return;
        }
        let mut children = fs::read_dir(path)
            .expect("read fixture directory")
            .map(|entry| entry.expect("fixture entry").path())
            .collect::<Vec<_>>();
        children.sort();
        for child in children {
            visit(&child, output);
        }
    }

    let mut output = Vec::new();
    visit(root, &mut output);
    output
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root")
        .to_path_buf()
}
