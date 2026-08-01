use std::fs;
use std::path::{Path, PathBuf};

use crate::CliError;

use super::super::read_utf8_json_file;

pub(crate) fn load_runtime_orchestration_profile(
    path: &Path,
) -> Result<chio_runtime::RuntimeOrchestrationProfile, CliError> {
    let profile = chio_runtime::runtime_orchestration_profile_from_json(&read_utf8_json_file(
        path,
        "Chio runtime orchestration profile",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime orchestration profile: {error}"))
    })?;
    chio_runtime::validate_runtime_orchestration_profile(&profile).map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime orchestration profile: {error}"))
    })?;
    Ok(profile)
}

pub(crate) fn load_runtime_run_contract(
    path: &Path,
) -> Result<chio_runtime::RuntimeRunContract, CliError> {
    let contract = chio_runtime::runtime_run_contract_from_json(&read_utf8_json_file(
        path,
        "Chio runtime run contract",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chio runtime run contract: {error}")))?;
    chio_runtime::validate_runtime_run_contract(&contract).map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime run contract: {error}"))
    })?;
    Ok(contract)
}

pub(crate) fn ensure_runtime_evidence_dir(evidence_dir: &Path) -> Result<(), CliError> {
    fs::create_dir_all(evidence_dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to create Chio runtime evidence directory {}: {error}",
            evidence_dir.display()
        ))
    })
}

pub(crate) fn sorted_child_dirs(path: &Path) -> Result<Vec<PathBuf>, CliError> {
    let mut dirs = Vec::new();
    for entry in fs::read_dir(path).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chio runtime runs directory {}: {error}",
            path.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chio runtime runs directory entry: {error}"
            ))
        })?;
        if entry.path().is_dir() {
            dirs.push(entry.path());
        }
    }
    dirs.sort();
    Ok(dirs)
}

pub(crate) fn validate_runtime_relative_path(relative_path: &str) -> Result<(), CliError> {
    if relative_path.trim() != relative_path
        || relative_path.is_empty()
        || relative_path.starts_with('/')
        || relative_path.contains('\\')
        || relative_path.contains(':')
        || relative_path.contains("//")
        || relative_path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(CliError::cli_other_error(format!(
            "Chio runtime artifact path {relative_path:?} is not safe relative evidence"
        )));
    }
    Ok(())
}
