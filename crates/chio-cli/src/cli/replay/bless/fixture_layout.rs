// CLI-side replay fixture layout checks for `chio replay --bless`.

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplayBlessScenario {
    family: String,
    name: String,
}

fn validate_replay_bless_into_path(path: &Path) -> Result<ReplayBlessScenario, CliError> {
    let scenario = chio_replay_corpus::scenario_from_dir(path).map_err(|error| {
        CliError::replay_mismatch_error(format!("invalid replay fixture directory: {error}"))
    })?;
    ensure_replay_fixture_target_allows_write(path)?;
    Ok(ReplayBlessScenario {
        family: scenario.family,
        name: scenario.name,
    })
}

fn ensure_replay_fixture_target_allows_write(path: &Path) -> Result<(), CliError> {
    match std::fs::metadata(path) {
        Ok(metadata) if !metadata.is_dir() => Err(CliError::replay_mismatch_error(format!(
            "invalid replay fixture directory: target is not a directory: {}",
            path.display()
        ))),
        Ok(_) => ensure_existing_replay_fixture_files(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CliError::replay_mismatch_error(format!(
            "invalid replay fixture directory: {}: {error}",
            path.display()
        ))),
    }
}

fn ensure_existing_replay_fixture_files(path: &Path) -> Result<(), CliError> {
    let expected = std::collections::BTreeSet::from([
        chio_replay_corpus::CHECKPOINT_FILENAME,
        chio_replay_corpus::RECEIPTS_FILENAME,
        chio_replay_corpus::ROOT_FILENAME,
    ]);
    let entries = std::fs::read_dir(path).map_err(|error| {
        CliError::replay_mismatch_error(format!(
            "invalid replay fixture directory: {}: {error}",
            path.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::replay_mismatch_error(format!(
                "invalid replay fixture directory: {}: {error}",
                path.display()
            ))
        })?;
        let file_type = entry.file_type().map_err(|error| {
            CliError::replay_mismatch_error(format!(
                "invalid replay fixture directory: {}: {error}",
                entry.path().display()
            ))
        })?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            return Err(CliError::replay_mismatch_error(format!(
                "invalid replay fixture directory: non-UTF-8 entry in {}",
                path.display()
            )));
        };
        if !file_type.is_file() || !expected.contains(name.as_str()) {
            return Err(CliError::replay_mismatch_error(format!(
                "invalid replay fixture directory: unexpected entry {}",
                entry.path().display()
            )));
        }
    }
    Ok(())
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
        std::fs::write(fixture_dir.join(chio_replay_corpus::CHECKPOINT_FILENAME), b"{}").unwrap();
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
            .contains("target is not a directory"));
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
