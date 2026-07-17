// CLI-side replay fixture layout checks for `chio replay --bless`.

use super::*;

pub(crate) fn validate_replay_bless_into_path(
    path: &Path,
) -> Result<chio_replay_corpus::ReplayScenario, CliError> {
    chio_replay_corpus::validate_scenario_dir(path).map_err(map_replay_fixture_error)
}

pub(crate) fn map_replay_fixture_error(error: chio_replay_corpus::WriterError) -> CliError {
    match error {
        chio_replay_corpus::WriterError::Io { path, source } => CliError::cli_io_error(format!(
            "invalid replay fixture directory {}: {source}",
            path.display()
        )),
        other => {
            CliError::replay_fixture_error(format!("invalid replay fixture directory: {other}"))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_bless_layout_tests {
    use super::*;

    #[test]
    fn into_path_yields_family_and_name() {
        let scenario =
            validate_replay_bless_into_path(Path::new("tests/replay/goldens/family/name")).unwrap();
        assert_eq!(scenario.family, "family");
        assert_eq!(scenario.name, "name");
    }

    #[test]
    fn into_path_accepts_existing_fixture_files() {
        let temp = tempfile::tempdir().unwrap();
        let fixture_dir = temp.path().join("family").join("name");
        std::fs::create_dir_all(&fixture_dir).unwrap();
        std::fs::write(
            fixture_dir.join(chio_replay_corpus::CHECKPOINT_FILENAME),
            b"{}",
        )
        .unwrap();
        std::fs::write(fixture_dir.join(chio_replay_corpus::RECEIPTS_FILENAME), b"").unwrap();
        std::fs::write(fixture_dir.join(chio_replay_corpus::ROOT_FILENAME), b"00").unwrap();

        let scenario = validate_replay_bless_into_path(&fixture_dir).unwrap();
        assert_eq!(scenario.family, "family");
        assert_eq!(scenario.name, "name");
    }

    #[test]
    fn into_path_rejects_existing_file_target() {
        let temp = tempfile::tempdir().unwrap();
        let fixture_file = temp.path().join("family").join("name");
        std::fs::create_dir_all(fixture_file.parent().unwrap()).unwrap();
        std::fs::write(&fixture_file, b"not a directory").unwrap();

        let error = validate_replay_bless_into_path(&fixture_file).unwrap_err();
        assert!(error
            .to_string()
            .contains("target exists but is not a directory"));
    }

    #[test]
    fn into_path_rejects_unexpected_existing_entries() {
        let temp = tempfile::tempdir().unwrap();
        let fixture_dir = temp.path().join("family").join("name");
        std::fs::create_dir_all(&fixture_dir).unwrap();
        std::fs::write(fixture_dir.join("extra.txt"), b"extra").unwrap();

        let error = validate_replay_bless_into_path(&fixture_dir).unwrap_err();
        assert!(error
            .to_string()
            .contains("invalid replay fixture directory"));
    }
}
