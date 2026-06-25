use super::CliError;
use std::{fs, path::Path};

pub(super) fn strip_collected_bundle_outputs(bundle: &Path) -> Result<(), CliError> {
    for relative_dir in ["negatives", "roots", "ui", "verifier"] {
        remove_dir_if_exists(&bundle.join(relative_dir))?;
    }
    for relative_file in ["bundle-signature.dsse.json", "manifest.json"] {
        remove_file_if_exists(&bundle.join(relative_file))?;
    }
    Ok(())
}

fn remove_dir_if_exists(path: &Path) -> Result<(), CliError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CliError::from(error)),
    }
}

fn remove_file_if_exists(path: &Path) -> Result<(), CliError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CliError::from(error)),
    }
}
