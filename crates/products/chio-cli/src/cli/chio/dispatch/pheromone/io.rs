use super::{read_utf8_json_file, RelaySigningKeyDocument};
use crate::CliError;
use chio_core::crypto::Keypair;
use serde::de::DeserializeOwned;
use std::fs;
use std::path::Path;

pub(crate) fn read_json_documents_from_dir<T: DeserializeOwned>(
    dir: &Path,
    label: &str,
    schema: &str,
) -> Result<Vec<T>, CliError> {
    let entries = fs::read_dir(dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chio {label} dir {}: {error}",
            dir.display()
        ))
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chio {label} dir entry {}: {error}",
                dir.display()
            ))
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();
    let mut documents = Vec::new();
    for path in paths {
        let json = read_utf8_json_file(&path, label)?;
        let value: serde_json::Value = serde_json::from_str(&json).map_err(|error| {
            CliError::cli_other_error(format!("Chio {label} {}: {error}", path.display()))
        })?;
        if value.get("schema").and_then(|schema| schema.as_str()) != Some(schema) {
            continue;
        }
        let document = serde_json::from_str(&json).map_err(|error| {
            CliError::cli_other_error(format!("Chio {label} {}: {error}", path.display()))
        })?;
        documents.push(document);
    }
    Ok(documents)
}

pub(crate) fn read_json_file<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T, CliError> {
    serde_json::from_str(&read_utf8_json_file(path, label)?)
        .map_err(|error| CliError::cli_other_error(format!("{label} {}: {error}", path.display())))
}

pub(crate) fn load_relay_signing_key(path: &Path) -> Result<(String, Keypair), CliError> {
    let json = read_utf8_json_file(path, "Chio relay signing key")?;
    let document: RelaySigningKeyDocument = serde_json::from_str(&json)
        .map_err(|error| CliError::cli_other_error(format!("Chio relay signing key: {error}")))?;
    if document.kernel_id.trim().is_empty() {
        return Err(CliError::cli_other_error(
            "Chio relay signing key: kernel id is empty",
        ));
    }
    let keypair = Keypair::from_seed_hex(document.seed_hex.trim())
        .map_err(|error| CliError::cli_other_error(format!("Chio relay signing key: {error}")))?;
    Ok((document.kernel_id, keypair))
}

pub(crate) fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| {
            let millis = duration.as_millis();
            u64::try_from(millis).unwrap_or(u64::MAX)
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{load_relay_signing_key, read_json_documents_from_dir};

    #[test]
    fn directory_read_errors_use_chio_boundary_label() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let missing = tempdir.path().join("missing");
        let error = read_json_documents_from_dir::<serde_json::Value>(
            &missing,
            "relay event",
            "chio.pheromone.relay-event.v1",
        )
        .expect_err("missing directory should fail")
        .to_string();

        assert!(error.contains("Chio relay event dir"));
    }

    #[test]
    fn relay_signing_key_errors_use_chio_boundary_label() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let key_path = tempdir.path().join("relay-key.json");
        std::fs::write(&key_path, "{}").expect("write key");

        let error = match load_relay_signing_key(&key_path) {
            Ok(_) => panic!("malformed key should fail"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("Chio relay signing key"));
    }
}
