use super::super::*;

pub(crate) fn current_utc_date() -> String {
    Utc::now().format("%Y-%m-%d").to_string()
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn unique_temp_dir(prefix: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("{prefix}-{stamp}-{}", std::process::id()))
}

pub(crate) fn read_json_file<T: for<'de> serde::Deserialize<'de>>(
    path: &Path,
) -> Result<T, CliError> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

pub(crate) fn write_json_file<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

pub(crate) fn ensure_empty_directory(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        if !path.is_dir() {
            return Err(CliError::Other(format!(
                "output path must be a directory: {}",
                path.display()
            )));
        }
        if fs::read_dir(path)?.next().is_some() {
            return Err(CliError::Other(format!(
                "output directory must be empty: {}",
                path.display()
            )));
        }
    } else {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

pub(crate) fn relative_display(root: &Path, path: &Path) -> Result<String, CliError> {
    path.strip_prefix(root)
        .map(|relative| relative.display().to_string())
        .map_err(|error| CliError::Other(error.to_string()))
}

pub(crate) fn copy_file(src: &Path, dst: &Path) -> Result<(), CliError> {
    let parent = dst.parent().ok_or_else(|| {
        CliError::Other(format!(
            "destination path is missing parent directory: {}",
            dst.display()
        ))
    })?;
    fs::create_dir_all(parent)?;
    fs::copy(src, dst)?;
    Ok(())
}

pub(crate) fn load_bundle_manifests(
    paths: &[PathBuf],
) -> Result<Vec<MercuryBundleManifest>, CliError> {
    paths
        .iter()
        .map(|path| {
            let manifest: MercuryBundleManifest = read_json_file(path)?;
            manifest
                .validate()
                .map_err(|error| CliError::Other(error.to_string()))?;
            Ok(manifest)
        })
        .collect()
}

pub(crate) fn write_bundle_manifests(
    dir: &Path,
    manifests: &[MercuryBundleManifest],
) -> Result<Vec<PathBuf>, CliError> {
    if manifests.len() == 1 {
        let path = dir.with_file_name("bundle-manifest.json");
        write_json_file(&path, &manifests[0])?;
        return Ok(vec![path]);
    }

    fs::create_dir_all(dir)?;
    let mut paths = Vec::with_capacity(manifests.len());
    for (index, manifest) in manifests.iter().enumerate() {
        let path = dir.join(bundle_manifest_file_name(index, &manifest.bundle_id)?);
        write_json_file(&path, manifest)?;
        paths.push(path);
    }
    Ok(paths)
}

pub(crate) fn bundle_manifest_file_name(index: usize, bundle_id: &str) -> Result<String, CliError> {
    if bundle_id.trim() != bundle_id
        || bundle_id.is_empty()
        || bundle_id == "."
        || bundle_id == ".."
        || bundle_id.contains('/')
        || bundle_id.contains('\\')
        || bundle_id.contains(':')
        || bundle_id.chars().any(char::is_control)
    {
        return Err(CliError::Other(format!(
            "bundle_id {bundle_id:?} is not safe for a bundle manifest file name"
        )));
    }
    Ok(format!("{:02}-{bundle_id}.json", index + 1))
}
