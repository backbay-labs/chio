use std::fs;
use std::path::Path;

use crate::RuntimeLoopbackError;

pub(crate) fn write_runtime_json_artifact<T: serde::Serialize>(
    out_dir: &Path,
    role: &str,
    relative_path: &str,
    value: &T,
    label: &str,
    entries: &mut Vec<chio_runtime_core::RuntimeEvidenceManifestEntry>,
    evidence_paths: &mut Vec<String>,
) -> Result<String, RuntimeLoopbackError> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|error| RuntimeLoopbackError::message(format!("{label}: {error}")))?;
    write_runtime_json_artifact_string(out_dir, role, relative_path, &json, entries, evidence_paths)
}

pub(crate) fn write_runtime_json_artifact_string(
    out_dir: &Path,
    role: &str,
    relative_path: &str,
    json: &str,
    entries: &mut Vec<chio_runtime_core::RuntimeEvidenceManifestEntry>,
    evidence_paths: &mut Vec<String>,
) -> Result<String, RuntimeLoopbackError> {
    validate_runtime_relative_path(relative_path)?;
    let json_with_newline = format!("{json}\n");
    let sha256 = chio_core::sha256_hex(json_with_newline.as_bytes());
    let byte_count = u64::try_from(json_with_newline.len()).map_err(|error| {
        RuntimeLoopbackError::message(format!("Chio runtime artifact byte count: {error}"))
    })?;
    write_json_string(&out_dir.join(relative_path), &json_with_newline)?;
    entries.push(chio_runtime_core::RuntimeEvidenceManifestEntry {
        role: role.to_string(),
        path: relative_path.to_string(),
        sha256: sha256.clone(),
        byte_count,
    });
    if !evidence_paths.iter().any(|path| path == relative_path) {
        evidence_paths.push(relative_path.to_string());
    }
    Ok(sha256)
}

fn validate_runtime_relative_path(relative_path: &str) -> Result<(), RuntimeLoopbackError> {
    if !is_safe_runtime_relative_path(relative_path) {
        return Err(RuntimeLoopbackError::message(format!(
            "Chio runtime artifact path {relative_path:?} is not safe relative evidence"
        )));
    }
    Ok(())
}

fn is_safe_runtime_relative_path(relative_path: &str) -> bool {
    relative_path.trim() == relative_path
        && !relative_path.is_empty()
        && !relative_path.starts_with('/')
        && !relative_path.contains('\\')
        && !relative_path.contains(':')
        && !relative_path.contains("//")
        && relative_path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

pub(crate) fn canonical_sha256_json<T: serde::Serialize>(
    value: &T,
    label: &str,
) -> Result<String, RuntimeLoopbackError> {
    let bytes = chio_core_types::canonical::canonical_json_bytes(value)
        .map_err(|error| RuntimeLoopbackError::message(format!("{label}: {error}")))?;
    Ok(chio_core::sha256_hex(&bytes))
}

pub(crate) fn read_utf8_json_file(
    path: &Path,
    label: &str,
) -> Result<String, RuntimeLoopbackError> {
    let bytes = fs::read(path).map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "failed to read {label} {}: {error}",
            path.display()
        ))
    })?;
    String::from_utf8(bytes).map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "{label} {} is not UTF-8 JSON: {error}",
            path.display()
        ))
    })
}

pub(crate) fn write_json_string(path: &Path, json: &str) -> Result<(), RuntimeLoopbackError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "failed to create Chio output directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
    }
    fs::write(path, json).map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "failed to write Chio JSON {}: {error}",
            path.display()
        ))
    })
}

/// Derive second-denominated capability bounds from a millisecond scenario clock.
pub fn runtime_loopback_capability_window(now_unix_ms: u64) -> (u64, u64) {
    let scenario_now_secs = now_unix_ms / 1000;
    (
        scenario_now_secs.saturating_sub(60),
        scenario_now_secs.saturating_add(157_680_000),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn runtime_relative_path_helper_accepts_only_safe_evidence_paths() {
        for path in ["proof-package.json", "steps/workflow-step-1.json"] {
            assert!(super::is_safe_runtime_relative_path(path), "{path}");
        }

        for path in [
            "",
            " proof-package.json",
            "proof-package.json ",
            "/proof-package.json",
            "steps\\proof-package.json",
            "C:proof-package.json",
            "steps//proof-package.json",
            "steps/./proof-package.json",
            "steps/../proof-package.json",
        ] {
            assert!(!super::is_safe_runtime_relative_path(path), "{path}");
        }
    }
}
