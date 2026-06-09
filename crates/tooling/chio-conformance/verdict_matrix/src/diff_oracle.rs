use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

use super::driver::{VerdictScenario, REASON_NONE};
use super::{VerdictTuple, MANIFEST_SCHEMA, SCENARIO_SCHEMA};

const SCENARIO_INDEX_ALGORITHM: &str = "sha256(relative-path-tab-file-sha256-newline)";

#[derive(Debug, Error)]
pub enum DiffOracleError {
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse TOML {path}: {source}")]
    Toml {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("failed to parse YAML {path}: {source}")]
    Yaml {
        path: PathBuf,
        source: serde_yaml::Error,
    },
    #[error("failed to list {path}: {source}")]
    List {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("manifest violation: {0}")]
    Manifest(String),
    #[error("registry violation: {0}")]
    Registry(String),
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerdictMatrixManifest {
    pub schema: String,
    pub version: u64,
    pub scenario_spec: String,
    pub corpus: ManifestCorpus,
    #[serde(default)]
    pub drivers: ManifestDrivers,
    #[serde(default)]
    pub oracle: Option<OracleManifest>,
}

impl VerdictMatrixManifest {
    pub fn validate(&self) -> Result<(), DiffOracleError> {
        if self.schema != MANIFEST_SCHEMA {
            return Err(DiffOracleError::Manifest(format!(
                "schema must be `{MANIFEST_SCHEMA}`"
            )));
        }
        if self.scenario_spec != SCENARIO_SCHEMA {
            return Err(DiffOracleError::Manifest(format!(
                "scenario_spec must be `{SCENARIO_SCHEMA}`"
            )));
        }
        if self.corpus.scenario_count == 0 {
            return Err(DiffOracleError::Manifest(String::from(
                "corpus.scenario_count must be greater than zero",
            )));
        }
        if self.corpus.scenario_root.trim().is_empty() {
            return Err(DiffOracleError::Manifest(String::from(
                "corpus.scenario_root must be set",
            )));
        }
        if self.corpus.scenario_index_algorithm != SCENARIO_INDEX_ALGORITHM {
            return Err(DiffOracleError::Manifest(format!(
                "corpus.scenario_index_algorithm must be `{SCENARIO_INDEX_ALGORITHM}`"
            )));
        }
        let Some(index_digest) = scenario_index_digest(&self.corpus.scenario_index_hash) else {
            return Err(DiffOracleError::Manifest(String::from(
                "corpus.scenario_index_hash must be a sha256-prefixed lowercase hex digest",
            )));
        };
        if !is_sha256_hex(&self.corpus.corpus_sha256) {
            return Err(DiffOracleError::Manifest(String::from(
                "corpus.corpus_sha256 must be a lowercase hex SHA-256 digest",
            )));
        }
        if self.corpus.corpus_sha256 != index_digest {
            return Err(DiffOracleError::Manifest(String::from(
                "corpus.corpus_sha256 must match the digest in corpus.scenario_index_hash",
            )));
        }
        if !self.corpus.categories.is_empty() {
            let category_total: usize = self.corpus.categories.values().copied().sum();
            if category_total != self.corpus.scenario_count {
                return Err(DiffOracleError::Manifest(format!(
                    "corpus.categories sums to {category_total}, but scenario_count is {}",
                    self.corpus.scenario_count
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManifestCorpus {
    pub status: String,
    pub scenario_count: usize,
    pub scenario_root: String,
    pub scenario_index_algorithm: String,
    pub scenario_index_hash: String,
    pub corpus_sha256: String,
    #[serde(default)]
    pub categories: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ManifestDrivers {
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(flatten)]
    pub configured: BTreeMap<String, DriverManifest>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DriverManifest {
    pub status: String,
    pub entrypoint: String,
    #[serde(default)]
    pub command: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OracleManifest {
    #[serde(default)]
    pub tuple_fields: Vec<String>,
    #[serde(default)]
    pub reason_registry: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverReport {
    pub driver: String,
    pub tuples: BTreeMap<String, VerdictTuple>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TupleDivergence {
    pub scenario_id: String,
    pub driver: String,
    pub expected: Option<VerdictTuple>,
    pub actual: Option<VerdictTuple>,
}

#[derive(Debug, Deserialize)]
struct ErrorRegistry {
    #[serde(default)]
    codes: Vec<ErrorRegistryCode>,
}

#[derive(Debug, Deserialize)]
struct ErrorRegistryCode {
    urn: String,
}

pub fn load_manifest(path: &Path) -> Result<VerdictMatrixManifest, DiffOracleError> {
    let text = fs::read_to_string(path).map_err(|source| DiffOracleError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let manifest =
        toml::from_str::<VerdictMatrixManifest>(&text).map_err(|source| DiffOracleError::Toml {
            path: path.to_path_buf(),
            source,
        })?;
    manifest.validate()?;
    Ok(manifest)
}

pub fn verify_manifest_corpus_hash(
    verdict_matrix_root: &Path,
    manifest: &VerdictMatrixManifest,
) -> Result<(), DiffOracleError> {
    let scenario_root = verdict_matrix_root.join(&manifest.corpus.scenario_root);
    let files = scenario_files(&scenario_root)?;
    if files.len() != manifest.corpus.scenario_count {
        return Err(DiffOracleError::Manifest(format!(
            "manifest scenario_count is {}, but {} JSON scenarios were found",
            manifest.corpus.scenario_count,
            files.len()
        )));
    }
    let actual_hash = scenario_index_hash(&scenario_root)?;
    let expected_hash = manifest.corpus.scenario_index_hash.as_str();
    if expected_hash != actual_hash {
        return Err(DiffOracleError::Manifest(format!(
            "scenario_index_hash mismatch: expected {expected_hash}, actual {actual_hash}"
        )));
    }
    let Some(actual_digest) = scenario_index_digest(&actual_hash) else {
        return Err(DiffOracleError::Manifest(format!(
            "computed scenario_index_hash has invalid format: {actual_hash}"
        )));
    };
    if manifest.corpus.corpus_sha256 != actual_digest {
        return Err(DiffOracleError::Manifest(format!(
            "corpus_sha256 mismatch: expected {}, actual {actual_digest}",
            manifest.corpus.corpus_sha256
        )));
    }
    Ok(())
}

pub fn scenario_index_hash(scenario_root: &Path) -> Result<String, DiffOracleError> {
    let files = scenario_files(scenario_root)?;
    let mut index = String::new();
    for file in files {
        let bytes = fs::read(&file).map_err(|source| DiffOracleError::Read {
            path: file.clone(),
            source,
        })?;
        let relative = file.strip_prefix(scenario_root).map_err(|error| {
            DiffOracleError::Manifest(format!(
                "scenario path {} is not under {}: {error}",
                file.display(),
                scenario_root.display()
            ))
        })?;
        index.push_str(&path_to_slash(relative));
        index.push('\t');
        index.push_str(&chio_core::sha256_hex(&bytes));
        index.push('\n');
    }
    Ok(format!(
        "sha256:{}",
        chio_core::sha256_hex(index.as_bytes())
    ))
}

pub fn scenario_files(root: &Path) -> Result<Vec<PathBuf>, DiffOracleError> {
    let mut files = Vec::new();
    collect_json_files(root, &mut files)?;
    files.sort();
    Ok(files)
}

pub fn diff_expected_reports(
    expected: &BTreeMap<String, VerdictTuple>,
    reports: &[DriverReport],
) -> Vec<TupleDivergence> {
    let mut divergences = Vec::new();
    for (scenario_id, expected_tuple) in expected {
        let normalized_expected = expected_tuple.clone().normalized();
        for report in reports {
            match report.tuples.get(scenario_id) {
                Some(actual) if actual.clone().normalized() == normalized_expected => {}
                Some(actual) => divergences.push(TupleDivergence {
                    scenario_id: scenario_id.clone(),
                    driver: report.driver.clone(),
                    expected: Some(normalized_expected.clone()),
                    actual: Some(actual.clone().normalized()),
                }),
                None => divergences.push(TupleDivergence {
                    scenario_id: scenario_id.clone(),
                    driver: report.driver.clone(),
                    expected: Some(normalized_expected.clone()),
                    actual: None,
                }),
            }
        }
    }
    for report in reports {
        for scenario_id in report.tuples.keys() {
            if !expected.contains_key(scenario_id) {
                divergences.push(TupleDivergence {
                    scenario_id: scenario_id.clone(),
                    driver: report.driver.clone(),
                    expected: None,
                    actual: report
                        .tuples
                        .get(scenario_id)
                        .map(|tuple| tuple.clone().normalized()),
                });
            }
        }
    }
    divergences
}

pub fn diff_manifest_reports(
    manifest: &VerdictMatrixManifest,
    expected: &BTreeMap<String, VerdictTuple>,
    reports: &[DriverReport],
) -> Vec<TupleDivergence> {
    let mut divergences = Vec::new();
    for required_driver in &manifest.drivers.required {
        if reports
            .iter()
            .any(|report| report.driver == *required_driver)
        {
            continue;
        }
        for (scenario_id, expected_tuple) in expected {
            divergences.push(TupleDivergence {
                scenario_id: scenario_id.clone(),
                driver: required_driver.clone(),
                expected: Some(expected_tuple.clone().normalized()),
                actual: None,
            });
        }
    }

    divergences.extend(diff_expected_reports(expected, reports));
    divergences
}

pub fn expected_tuple_map(scenarios: &[VerdictScenario]) -> BTreeMap<String, VerdictTuple> {
    scenarios
        .iter()
        .map(|scenario| (scenario.id.clone(), scenario.expected.clone().normalized()))
        .collect()
}

pub fn report_tuple_map(
    outcomes: &[(String, Option<VerdictTuple>)],
) -> BTreeMap<String, VerdictTuple> {
    outcomes
        .iter()
        .filter_map(|(scenario_id, tuple)| {
            tuple
                .clone()
                .map(|actual| (scenario_id.clone(), actual.normalized()))
        })
        .collect()
}

pub fn load_error_registry_urns(path: &Path) -> Result<BTreeSet<String>, DiffOracleError> {
    let text = fs::read_to_string(path).map_err(|source| DiffOracleError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let registry =
        serde_yaml::from_str::<ErrorRegistry>(&text).map_err(|source| DiffOracleError::Yaml {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(registry.codes.into_iter().map(|code| code.urn).collect())
}

pub fn validate_reason_codes(
    scenarios: &[VerdictScenario],
    registry: &BTreeSet<String>,
) -> Result<(), DiffOracleError> {
    for scenario in scenarios {
        let reason = scenario.expected.reason_code.as_str();
        if reason == REASON_NONE || registry.contains(reason) {
            continue;
        }
        return Err(DiffOracleError::Registry(format!(
            "scenario {} uses unregistered reason code {reason}",
            scenario.id
        )));
    }
    Ok(())
}

fn collect_json_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), DiffOracleError> {
    let entries = fs::read_dir(path).map_err(|source| DiffOracleError::List {
        path: path.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| DiffOracleError::List {
            path: path.to_path_buf(),
            source,
        })?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            collect_json_files(&entry_path, files)?;
        } else if entry_path
            .extension()
            .and_then(|extension| extension.to_str())
            == Some("json")
        {
            files.push(entry_path);
        }
    }
    Ok(())
}

fn path_to_slash(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<String>>()
        .join("/")
}

fn scenario_index_digest(index_hash: &str) -> Option<&str> {
    let digest = index_hash.strip_prefix("sha256:")?;
    if is_sha256_hex(digest) {
        Some(digest)
    } else {
        None
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}
