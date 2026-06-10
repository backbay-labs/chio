use std::fs;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;

use crate::{ScenarioDescriptor, ScenarioResult};

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error in {path}: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

pub fn load_scenarios_from_dir(
    path: impl AsRef<Path>,
) -> Result<Vec<ScenarioDescriptor>, LoadError> {
    let path = path.as_ref();
    let mut scenarios = read_json_files::<ScenarioDescriptor>(path)?;
    if scenarios.is_empty() {
        return Err(empty_scenario_directory_error(path));
    }
    scenarios.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(scenarios)
}

pub fn load_results_from_dir(path: impl AsRef<Path>) -> Result<Vec<ScenarioResult>, LoadError> {
    let mut results = Vec::new();
    for file_path in collect_json_files(path.as_ref())? {
        let content = fs::read_to_string(&file_path)?;
        match serde_json::from_str::<Vec<ScenarioResult>>(&content) {
            Ok(mut batch) => results.append(&mut batch),
            Err(_) => {
                let record = deserialize::<ScenarioResult>(&file_path, &content)?;
                results.push(record);
            }
        }
    }
    results.sort_by(|left, right| {
        left.scenario_id
            .cmp(&right.scenario_id)
            .then_with(|| left.peer.cmp(&right.peer))
            .then_with(|| left.deployment_mode.cmp(&right.deployment_mode))
            .then_with(|| left.transport.cmp(&right.transport))
    });
    Ok(results)
}

fn read_json_files<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>, LoadError> {
    let mut items = Vec::new();
    for file_path in collect_json_files(path)? {
        let content = fs::read_to_string(&file_path)?;
        items.push(deserialize::<T>(&file_path, &content)?);
    }
    Ok(items)
}

fn deserialize<T: DeserializeOwned>(path: &Path, content: &str) -> Result<T, LoadError> {
    serde_json::from_str(content).map_err(|source| LoadError::Json {
        path: path.display().to_string(),
        source,
    })
}

fn collect_json_files(path: &Path) -> Result<Vec<PathBuf>, LoadError> {
    require_json_directory(path)?;
    let mut files = Vec::new();
    walk_json_files(path, &mut files)?;
    files.sort();
    Ok(files)
}

fn empty_scenario_directory_error(path: &Path) -> LoadError {
    LoadError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "conformance scenario directory {} is empty: expected at least one JSON scenario",
            path.display()
        ),
    ))
}

fn require_json_directory(path: &Path) -> Result<(), LoadError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        LoadError::Io(std::io::Error::new(
            source.kind(),
            format!(
                "conformance JSON directory {} is not readable: {source}",
                path.display()
            ),
        ))
    })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(LoadError::Io(std::io::Error::other(format!(
            "refusing symlinked conformance fixture directory: {}",
            path.display()
        ))));
    }
    if !file_type.is_dir() {
        return Err(LoadError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "conformance JSON directory {} is not a directory",
                path.display()
            ),
        )));
    }
    Ok(())
}

fn walk_json_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), LoadError> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(LoadError::Io(std::io::Error::other(format!(
                "refusing symlink in conformance fixture tree: {}",
                entry_path.display()
            ))));
        }
        if file_type.is_dir() {
            walk_json_files(&entry_path, files)?;
        } else if file_type.is_file()
            && entry_path.extension().and_then(|value| value.to_str()) == Some("json")
        {
            files.push(entry_path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn unique_dir(prefix: &str) -> Result<PathBuf, LoadError> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_nanos();
        Ok(std::env::temp_dir().join(format!("{prefix}-{nonce}")))
    }

    #[test]
    fn loads_scenarios_and_results_from_json_directories() -> Result<(), LoadError> {
        let dir = unique_dir("chio-conformance-load")?;
        fs::create_dir_all(dir.join("scenarios"))?;
        fs::create_dir_all(dir.join("results"))?;

        fs::write(
            dir.join("scenarios/initialize.json"),
            r#"{
              "id": "initialize",
              "title": "Initialize",
              "area": "lifecycle",
              "category": "mcp-core",
              "specVersions": ["2025-11-25"],
              "transport": ["stdio"],
              "peerRoles": ["client_to_chio_server"],
              "deploymentModes": ["wrapped_stdio"],
              "requiredCapabilities": {"server": [], "client": []},
              "tags": ["mcp-core"],
              "expected": "pass"
            }"#,
        )?;
        fs::write(
            dir.join("results/results.json"),
            r#"[{
              "scenarioId": "initialize",
              "peer": "js",
              "peerRole": "client_to_chio_server",
              "deploymentMode": "wrapped_stdio",
              "transport": "stdio",
              "specVersion": "2025-11-25",
              "category": "mcp-core",
              "status": "pass",
              "durationMs": 12,
              "assertions": [{"name": "initialize_succeeds", "status": "pass"}]
            }]"#,
        )?;

        let scenarios = load_scenarios_from_dir(dir.join("scenarios"))?;
        let results = load_results_from_dir(dir.join("results"))?;

        assert_eq!(scenarios.len(), 1);
        assert_eq!(results.len(), 1);
        assert_eq!(scenarios[0].id, "initialize");
        assert_eq!(results[0].peer, "js");
        Ok(())
    }

    #[test]
    fn load_scenarios_rejects_missing_directory() -> Result<(), LoadError> {
        let dir = unique_dir("chio-conformance-load-missing-scenarios")?;
        let _ = fs::remove_dir_all(&dir);

        match load_scenarios_from_dir(&dir) {
            Ok(scenarios) => panic!("missing scenario directory should fail: {scenarios:?}"),
            Err(error) => assert!(error.to_string().contains("directory")),
        }
        Ok(())
    }

    #[test]
    fn load_scenarios_rejects_empty_directory() -> Result<(), LoadError> {
        let dir = unique_dir("chio-conformance-load-empty-scenarios")?;
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;

        match load_scenarios_from_dir(&dir) {
            Ok(scenarios) => panic!("empty scenario directory should fail: {scenarios:?}"),
            Err(error) => assert!(error.to_string().contains("empty")),
        }

        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn load_results_rejects_missing_directory() -> Result<(), LoadError> {
        let dir = unique_dir("chio-conformance-load-missing-results")?;
        let _ = fs::remove_dir_all(&dir);

        match load_results_from_dir(&dir) {
            Ok(results) => panic!("missing results directory should fail: {results:?}"),
            Err(error) => assert!(error.to_string().contains("directory")),
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn collect_json_files_rejects_symlinked_json_file() -> Result<(), LoadError> {
        let dir = unique_dir("chio-conformance-load-symlink")?;
        let outside = unique_dir("chio-conformance-load-outside")?;
        fs::create_dir_all(&dir)?;
        fs::create_dir_all(&outside)?;
        fs::write(outside.join("escape.json"), "{}")?;
        std::os::unix::fs::symlink(outside.join("escape.json"), dir.join("escape.json"))?;

        match collect_json_files(&dir) {
            Ok(files) => panic!("symlinked JSON should fail closed: {files:?}"),
            Err(error) => assert!(error.to_string().contains("symlink")),
        }
        let _ = fs::remove_dir_all(dir);
        let _ = fs::remove_dir_all(outside);
        Ok(())
    }
}
