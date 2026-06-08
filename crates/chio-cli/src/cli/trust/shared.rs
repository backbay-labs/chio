use super::*;

pub(crate) struct QueryBackend<'a> {
    pub(crate) json_output: bool,
    pub(crate) receipt_db_path: Option<&'a Path>,
    pub(crate) control_url: Option<&'a str>,
    pub(crate) control_token: Option<&'a str>,
}

/// Derive a trusted-kernel-key list from an authority seed file. Returns the
/// loaded public key (so locally signed receipts can pass reputation integrity
/// validation) or an empty vec when no seed file is configured. See
/// `chio-reputation::receipt_integrity_valid`.
pub(crate) fn trusted_kernel_keys_from_authority(
    authority_seed_path: Option<&Path>,
) -> Result<Vec<String>, CliError> {
    let Some(path) = authority_seed_path else {
        return Ok(Vec::new());
    };
    let keypair = load_or_create_authority_keypair(path)?;
    Ok(vec![keypair.public_key().to_hex()])
}

pub(crate) struct BudgetQueryBackend<'a> {
    pub(crate) query: QueryBackend<'a>,
    pub(crate) budget_db_path: Option<&'a Path>,
    pub(crate) certification_registry_file: Option<&'a Path>,
    /// Optional authority seed file used to derive the trusted kernel key
    /// for local reputation scoring. Plumbing this through means receipts
    /// signed by the local kernel are not silently filtered out as unsigned.
    /// See `chio-reputation::receipt_integrity_valid`.
    pub(crate) authority_seed_path: Option<&'a Path>,
}

pub(crate) struct SignedQueryBackend<'a> {
    pub(crate) query: QueryBackend<'a>,
    pub(crate) budget_db_path: Option<&'a Path>,
    pub(crate) authority_seed_path: Option<&'a Path>,
    pub(crate) authority_db_path: Option<&'a Path>,
    pub(crate) certification_registry_file: Option<&'a Path>,
}

pub(crate) fn load_json_or_yaml<T: DeserializeOwned>(path: &Path) -> Result<T, CliError> {
    let contents = fs::read_to_string(path)?;
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "yaml" | "yml"))
    {
        Ok(serde_yml::from_str(&contents)?)
    } else if let Ok(value) = serde_json::from_str(&contents) {
        Ok(value)
    } else {
        Ok(serde_yml::from_str(&contents)?)
    }
}
