fn read_utf8_json_file(path: &Path, label: &str) -> Result<String, CliError> {
    let bytes = fs::read(path).map_err(|error| {
        CliError::cli_io_error(format!("failed to read {label} {}: {error}", path.display()))
    })?;
    String::from_utf8(bytes).map_err(|error| {
        CliError::cli_other_error(format!("{label} {} is not UTF-8 JSON: {error}", path.display()))
    })
}

fn write_json_string(path: &Path, json: &str) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| {
                CliError::cli_io_error(format!(
                    "failed to create Chiodos output directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
    }
    fs::write(path, json).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to write Chiodos JSON {}: {error}",
            path.display()
        ))
    })
}
