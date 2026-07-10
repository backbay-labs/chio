use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::CliError;

use super::types::SignedCertificationCheck;
use super::verify::verify_signed_certification_check;

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn normalize_registry_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

pub(crate) fn require_certification_discovery_path(path: Option<&Path>) -> Result<&Path, CliError> {
    path.ok_or_else(|| {
        CliError::attest_error(
            "certification discovery requires --certification-discovery-file when not using --control-url"
                .to_string(),
        )
    })
}

pub(crate) fn require_existing_dir(path: &Path, label: &str) -> Result<(), CliError> {
    if !path.exists() {
        return Err(CliError::attest_error(format!(
            "{label} directory does not exist: {}",
            path.display()
        )));
    }
    if !path.is_dir() {
        return Err(CliError::attest_error(format!(
            "{label} path must be a directory: {}",
            path.display()
        )));
    }
    Ok(())
}

pub(crate) fn ensure_parent_dir(path: &Path) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

pub(crate) fn load_signed_certification_check(
    path: &Path,
) -> Result<SignedCertificationCheck, CliError> {
    let artifact: SignedCertificationCheck = serde_json::from_slice(&fs::read(path)?)?;
    verify_signed_certification_check(&artifact)?;
    Ok(artifact)
}
