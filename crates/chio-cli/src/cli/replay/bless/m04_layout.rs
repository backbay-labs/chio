// CLI-side M04 fixture layout checks for `chio replay --bless`.

fn validate_replay_bless_into_path(path: &Path) -> Result<chio_replay_corpus::M04Scenario, CliError> {
    chio_replay_corpus::validate_m04_scenario_dir(path)
        .map_err(|error| CliError::Other(format!("invalid M04 fixture directory: {error}")))
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
}
