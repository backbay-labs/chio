use super::*;
use std::path::{Path, PathBuf};

pub(super) struct PublicSettlementRuntimeHashes {
    pub(super) root_registry: String,
    pub(super) identity_registry: String,
    pub(super) escrow: String,
    pub(super) bond_vault: String,
}

pub(super) fn public_settlement_runtime_hashes(
    bundle: &Path,
    expected_package_id: &str,
    context_path: &Path,
) -> Result<PublicSettlementRuntimeHashes, CliError> {
    let package_path = ensure_chio_web3_contract_package_in_bundle(bundle)?;
    let package = read_json_value(&package_path)?;
    let package_id = required_json_string(&package, "package_id", &package_path)?;
    if package_id != expected_package_id {
        return Err(CliError::cli_other_error(format!(
            "public settlement contract package mismatch for {}: expected {}, package {} declares {}",
            context_path.display(),
            expected_package_id,
            package_path.display(),
            package_id
        )));
    }
    Ok(PublicSettlementRuntimeHashes {
        root_registry: contract_package_runtime_hash(&package, "root_registry", &package_path)?,
        identity_registry: contract_package_runtime_hash(
            &package,
            "identity_registry",
            &package_path,
        )?,
        escrow: contract_package_runtime_hash(&package, "escrow", &package_path)?,
        bond_vault: contract_package_runtime_hash(&package, "bond_vault", &package_path)?,
    })
}

fn find_chio_web3_contract_package(bundle: &Path) -> Result<PathBuf, CliError> {
    let workspace_package = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../")
        .join(CHIO_WEB3_CONTRACT_PACKAGE_PATH);
    let cwd_packages = std::env::current_dir()
        .ok()
        .into_iter()
        .map(|cwd| cwd.join(CHIO_WEB3_CONTRACT_PACKAGE_PATH));
    let candidates = cwd_packages
        .chain(std::iter::once(workspace_package))
        .chain(
            bundle
                .ancestors()
                .map(|ancestor| ancestor.join(CHIO_WEB3_CONTRACT_PACKAGE_PATH)),
        );
    for candidate in candidates {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(CliError::cli_other_error(format!(
        "could not locate {CHIO_WEB3_CONTRACT_PACKAGE_PATH} for public settlement fixture {}",
        bundle.display()
    )))
}

fn ensure_chio_web3_contract_package_in_bundle(bundle: &Path) -> Result<PathBuf, CliError> {
    let source = find_chio_web3_contract_package(bundle)?;
    let destination = bundle.join(CHIO_WEB3_CONTRACT_PACKAGE_PATH);
    if source != destination {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&source, &destination)?;
    }
    Ok(destination)
}

fn contract_package_runtime_hash(
    package: &serde_json::Value,
    kind: &str,
    package_path: &Path,
) -> Result<String, CliError> {
    let contracts = package
        .get("contracts")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "web3 contract package contracts must be an array: {}",
                package_path.display()
            ))
        })?;
    for contract in contracts {
        if contract.get("kind").and_then(serde_json::Value::as_str) == Some(kind) {
            return contract
                .get("deployed_runtime_codehash")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string)
                .ok_or_else(|| {
                    CliError::cli_other_error(format!(
                        "web3 contract package kind {kind} missing deployed_runtime_codehash: {}",
                        package_path.display()
                    ))
                });
        }
    }
    Err(CliError::cli_other_error(format!(
        "web3 contract package missing contract kind {kind}: {}",
        package_path.display()
    )))
}
