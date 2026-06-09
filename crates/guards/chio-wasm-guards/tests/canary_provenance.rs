use chio_wasm_guards::{CanaryCorpus, CANARY_FIXTURE_COUNT};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn corpora_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/corpora")
}

fn guard_id_from_path(path: &std::path::Path) -> Result<String, std::io::Error> {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .ok_or_else(|| std::io::Error::other("corpus path has no guard id"))
}

#[test]
fn all_canary_corpora_are_frozen_and_manifest_verified() -> TestResult {
    let root = corpora_root();
    let mut checked = 0_usize;

    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let canary_dir = entry.path().join("canary");
        if !canary_dir.is_dir() {
            continue;
        }

        let guard_id = guard_id_from_path(&entry.path())?;
        let corpus = CanaryCorpus::from_dir(&guard_id, &canary_dir)?;
        assert_eq!(corpus.fixtures().len(), CANARY_FIXTURE_COUNT);
        assert_eq!(corpus.guard_id(), guard_id);

        let provenance_path = canary_dir.join("PROVENANCE.md");
        let provenance = std::fs::read_to_string(&provenance_path)?;
        for required in [
            "hand-curated",
            "frozen on commit",
            "guard major-version bump",
            "MANIFEST.sha256",
            "fixture count must remain 32",
        ] {
            assert!(
                provenance.contains(required),
                "{} missing required phrase {required:?}",
                provenance_path.display()
            );
        }

        checked += 1;
    }

    assert!(checked > 0, "expected at least one canary corpus");
    Ok(())
}
