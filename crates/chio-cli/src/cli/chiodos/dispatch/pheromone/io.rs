fn read_json_documents_from_dir<T: DeserializeOwned>(
    dir: &Path,
    label: &str,
    schema: &str,
) -> Result<Vec<T>, CliError> {
    let entries = fs::read_dir(dir).map_err(|error| {
        CliError::cli_io_error(format!("failed to read Chiodos {label} dir {}: {error}", dir.display()))
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos {label} dir entry {}: {error}",
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
            CliError::cli_other_error(format!("Chiodos {label} {}: {error}", path.display()))
        })?;
        if value.get("schema").and_then(|schema| schema.as_str()) != Some(schema) {
            continue;
        }
        let document = serde_json::from_str(&json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos {label} {}: {error}", path.display()))
        })?;
        documents.push(document);
    }
    Ok(documents)
}

fn read_json_file<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T, CliError> {
    serde_json::from_str(&read_utf8_json_file(path, label)?)
        .map_err(|error| CliError::cli_other_error(format!("{label} {}: {error}", path.display())))
}



fn load_relay_signing_key(path: &Path) -> Result<(String, Keypair), CliError> {
    let json = read_utf8_json_file(path, "Chiodos relay signing key")?;
    let document: RelaySigningKeyDocument = serde_json::from_str(&json).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay signing key: {error}"))
    })?;
    if document.kernel_id.trim().is_empty() {
        return Err(CliError::cli_other_error(
            "Chiodos relay signing key: kernel id is empty",
        ));
    }
    let keypair = Keypair::from_seed_hex(document.seed_hex.trim())
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay signing key: {error}")))?;
    Ok((document.kernel_id, keypair))
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| {
            let millis = duration.as_millis();
            u64::try_from(millis).unwrap_or(u64::MAX)
        })
        .unwrap_or(0)
}
