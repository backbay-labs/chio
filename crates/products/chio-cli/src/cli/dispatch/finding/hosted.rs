use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_control_plane::trust_control::finding_hosted_profile::{
    FindingHostedCanaryDecision, FindingHostedCanaryObservation, FindingHostedEdgeProfile,
    FindingHostedProfile,
    FindingHostedRollbackReason, FindingHostedSignerTransport, FindingHostedSigningRole,
    FINDING_HOSTED_PROFILE_SCHEMA,
};
use sha2::{Digest as _, Sha256};

use super::*;

const MAX_HOSTED_PROFILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CANARY_OBSERVATION_BYTES: u64 = 64 * 1024;

pub(super) fn cmd_finding_operator_evaluate_canary(
    profile_path: &Path,
    observation_path: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let profile: FindingHostedProfile = read_canonical_private_json(
        profile_path,
        MAX_HOSTED_PROFILE_BYTES,
        "hosted profile",
    )?;
    profile.validate().map_err(CliError::cli_other_error)?;
    let observation: FindingHostedCanaryObservation = read_canonical_private_json(
        observation_path,
        MAX_CANARY_OBSERVATION_BYTES,
        "canary observation",
    )?;
    let decision = profile.evaluate_canary(&observation);
    let (name, reason) = match decision {
        FindingHostedCanaryDecision::Promote => ("promote", None),
        FindingHostedCanaryDecision::Rollback(reason) => {
            ("rollback", Some(rollback_reason_name(reason)))
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema": "chio.finding.hosted-canary-decision.v1",
                "deploymentId": profile.deployment_id,
                "decision": name,
                "reason": reason,
            }))?
        );
    } else {
        println!("canary_decision: {name}");
        if let Some(reason) = reason {
            println!("reason:          {reason}");
        }
    }
    if matches!(decision, FindingHostedCanaryDecision::Rollback(_)) {
        return Err(CliError::cli_other_error(
            "hosted canary requires rollback".to_owned(),
        ));
    }
    Ok(())
}

fn rollback_reason_name(reason: FindingHostedRollbackReason) -> &'static str {
    match reason {
        FindingHostedRollbackReason::Binding => "binding",
        FindingHostedRollbackReason::ObservationWindow => "observation_window",
        FindingHostedRollbackReason::Availability => "availability",
        FindingHostedRollbackReason::ErrorRate => "error_rate",
        FindingHostedRollbackReason::Latency => "latency",
        FindingHostedRollbackReason::QueueAge => "queue_age",
        FindingHostedRollbackReason::SecurityInvariant => "security_invariant",
    }
}

fn read_canonical_private_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    maximum: u64,
    label: &str,
) -> Result<T, CliError> {
    let (mut file, metadata) = open_regular_nofollow(path)?;
    require_private_file(path, &metadata)?;
    if metadata.len() == 0 || metadata.len() > maximum {
        return Err(CliError::cli_other_error(format!(
            "{label} exceeds its byte bound"
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    let raw = std::str::from_utf8(&bytes)
        .map_err(|_| CliError::cli_other_error(format!("{label} is not UTF-8")))?;
    let canonical = chio_core::canonical::canonical_json_bytes_from_str(raw).map_err(|error| {
        CliError::cli_other_error(format!("{label} is not strict canonical JSON: {error}"))
    })?;
    if canonical != bytes {
        return Err(CliError::cli_other_error(format!(
            "{label} bytes are not canonical JSON"
        )));
    }
    serde_json::from_slice(&bytes).map_err(Into::into)
}

pub(super) fn cmd_finding_operator_validate_hosted(
    profile_path: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let (mut profile_file, metadata) = open_regular_nofollow(profile_path)?;
    require_private_file(profile_path, &metadata)?;
    if metadata.len() == 0 || metadata.len() > MAX_HOSTED_PROFILE_BYTES {
        return Err(CliError::cli_other_error(
            "hosted profile exceeds its byte bound".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    profile_file.read_to_end(&mut bytes)?;
    let raw = std::str::from_utf8(&bytes)
        .map_err(|_| CliError::cli_other_error("hosted profile is not UTF-8".to_owned()))?;
    let canonical = chio_core::canonical::canonical_json_bytes_from_str(raw).map_err(|error| {
        CliError::cli_other_error(format!("hosted profile is not strict canonical JSON: {error}"))
    })?;
    if canonical != bytes {
        return Err(CliError::cli_other_error(
            "hosted profile bytes are not canonical JSON".to_owned(),
        ));
    }
    let profile: FindingHostedProfile = serde_json::from_slice(&bytes)?;
    profile.validate().map_err(CliError::cli_other_error)?;
    validate_referenced_files(&profile)?;
    validate_secret_environment(&profile)?;
    profile
        .authenticator_config()
        .map_err(CliError::cli_other_error)?;
    profile
        .load_api_key_pepper()
        .map_err(CliError::cli_other_error)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliError::cli_other_error("system clock is before Unix epoch".to_owned()))?
        .as_secs();
    profile.load_tls(now).map_err(CliError::cli_other_error)?;
    profile
        .load_trusted_proxy()
        .map_err(CliError::cli_other_error)?;
    for role in FindingHostedSigningRole::ALL {
        profile.load_signer(role).map_err(CliError::cli_other_error)?;
    }
    profile
        .load_bond_observer()
        .map_err(CliError::cli_other_error)?;
    profile
        .load_impairment_publisher()
        .map_err(CliError::cli_other_error)?;
    profile
        .load_worker_executor()
        .map_err(CliError::cli_other_error)?;

    let report = serde_json::json!({
        "schema": "chio.finding.hosted-profile-validation.v1",
        "profileSchema": FINDING_HOSTED_PROFILE_SCHEMA,
        "deploymentId": profile.deployment_id,
        "publicEndpoint": profile.public_endpoint,
        "tenantCount": profile.tenants.len(),
        "signerCount": profile.signers.len(),
        "workerMaxInstances": profile.worker.max_instances,
        "artifactSha256": profile.release.artifact_sha256,
        "valid": true,
    });
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("hosted_profile: valid");
        println!("deployment:     {}", terminal_safe(&profile.deployment_id));
        println!("endpoint:       {}", terminal_safe(&profile.public_endpoint));
        println!("tenants:        {}", profile.tenants.len());
        println!("signers:        {}", profile.signers.len());
    }
    Ok(())
}

fn validate_referenced_files(profile: &FindingHostedProfile) -> Result<(), CliError> {
    if let FindingHostedEdgeProfile::NativeTls {
        certificate_chain_path,
        private_key_path,
        client_ca_path,
        ..
    } = &profile.edge
    {
        validate_file(Path::new(certificate_chain_path), FileClass::ReadOnly)?;
        validate_file(Path::new(private_key_path), FileClass::Private)?;
        if let Some(client_ca_path) = client_ca_path {
            validate_file(Path::new(client_ca_path), FileClass::ReadOnly)?;
        }
    }
    validate_file(
        Path::new(&profile.database.ca_certificate_path),
        FileClass::ReadOnly,
    )?;
    validate_file(
        Path::new(&profile.worker.worker_binary),
        FileClass::Executable,
    )?;
    validate_file(
        Path::new(&profile.worker.firecracker_binary),
        FileClass::Executable,
    )?;
    validate_file(
        Path::new(&profile.worker.jailer_binary),
        FileClass::Executable,
    )?;
    let kernel = Path::new(&profile.worker.kernel_image);
    let rootfs = Path::new(&profile.worker.rootfs_image);
    for (path, expected, label) in [
        (
            Path::new(&profile.worker.worker_binary),
            &profile.worker.worker_binary_sha256,
            "finding worker binary",
        ),
        (
            Path::new(&profile.worker.firecracker_binary),
            &profile.worker.firecracker_sha256,
            "Firecracker binary",
        ),
        (
            Path::new(&profile.worker.jailer_binary),
            &profile.worker.jailer_sha256,
            "Firecracker jailer",
        ),
    ] {
        if sha256_file(path)? != *expected {
            return Err(CliError::cli_other_error(format!(
                "{label} digest does not match the hosted profile"
            )));
        }
    }
    validate_file(kernel, FileClass::ReadOnly)?;
    validate_file(rootfs, FileClass::ReadOnly)?;
    if sha256_file(kernel)? != profile.worker.kernel_sha256 {
        return Err(CliError::cli_other_error(
            "worker kernel image digest does not match the hosted profile".to_owned(),
        ));
    }
    if sha256_file(rootfs)? != profile.worker.rootfs_sha256 {
        return Err(CliError::cli_other_error(
            "worker rootfs image digest does not match the hosted profile".to_owned(),
        ));
    }
    let jail = std::fs::symlink_metadata(&profile.worker.jail_root)?;
    if !jail.is_dir() || jail.file_type().is_symlink() {
        return Err(CliError::cli_other_error(
            "worker jail root must be a real directory".to_owned(),
        ));
    }
    require_not_group_or_world_writable(Path::new(&profile.worker.jail_root), &jail)?;
    let artifact_store = std::fs::symlink_metadata(&profile.worker.artifact_store_root)?;
    if !artifact_store.is_dir() || artifact_store.file_type().is_symlink() {
        return Err(CliError::cli_other_error(
            "worker artifact store root must be a real directory".to_owned(),
        ));
    }
    require_not_group_or_world_writable(
        Path::new(&profile.worker.artifact_store_root),
        &artifact_store,
    )
}

fn validate_secret_environment(profile: &FindingHostedProfile) -> Result<(), CliError> {
    require_secret_env(&profile.database.url_env)?;
    require_secret_env(&profile.payment.bearer_token_env)?;
    require_secret_env(&profile.bond_observer.bearer_token_env)?;
    require_secret_env(&profile.impairment_publisher.bearer_token_env)?;
    require_secret_env(&profile.identity.api_key_pepper_env)?;
    if let FindingHostedEdgeProfile::TrustedProxy {
        authentication_token_env,
        ..
    } = &profile.edge
    {
        require_secret_env(authentication_token_env)?;
    }
    for signer in &profile.signers {
        let env_name = match &signer.transport {
            FindingHostedSignerTransport::Http {
                bearer_token_env, ..
            } => bearer_token_env,
            FindingHostedSignerTransport::VaultTransit { token_env, .. } => token_env,
        };
        require_secret_env(env_name)?;
    }
    Ok(())
}

fn require_secret_env(name: &str) -> Result<(), CliError> {
    let value = std::env::var(name).map_err(|_| {
        CliError::cli_other_error(format!("required hosted secret environment variable {name} is missing"))
    })?;
    if value.is_empty() || value.len() > 16 * 1024 || value.chars().any(char::is_control) {
        return Err(CliError::cli_other_error(format!(
            "required hosted secret environment variable {name} is invalid"
        )));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum FileClass {
    Private,
    ReadOnly,
    Executable,
}

fn validate_file(path: &Path, class: FileClass) -> Result<(), CliError> {
    let (_file, metadata) = open_regular_nofollow(path)?;
    match class {
        FileClass::Private => require_private_file(path, &metadata),
        FileClass::ReadOnly => require_not_group_or_world_writable(path, &metadata),
        FileClass::Executable => {
            require_not_group_or_world_writable(path, &metadata)?;
            require_executable(path, &metadata)
        }
    }
}

fn open_regular_nofollow(path: &Path) -> Result<(File, Metadata), CliError> {
    let link_metadata = std::fs::symlink_metadata(path)?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        return Err(CliError::cli_other_error(format!(
            "{} must be a regular non-symlink file",
            path.display()
        )));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || !same_file(&link_metadata, &opened) {
        return Err(CliError::cli_other_error(format!(
            "{} changed while it was opened",
            path.display()
        )));
    }
    file.seek(SeekFrom::Start(0))?;
    Ok((file, opened))
}

#[cfg(unix)]
fn same_file(before: &Metadata, after: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    before.dev() == after.dev() && before.ino() == after.ino()
}

#[cfg(not(unix))]
fn same_file(before: &Metadata, after: &Metadata) -> bool {
    before.len() == after.len() && before.modified().ok() == after.modified().ok()
}

#[cfg(unix)]
fn require_private_file(path: &Path, metadata: &Metadata) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt as _;
    if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(CliError::cli_other_error(format!(
            "{} must be owned by the current user with mode 0600 or stricter",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_private_file(_path: &Path, _metadata: &Metadata) -> Result<(), CliError> {
    Ok(())
}

#[cfg(unix)]
fn require_not_group_or_world_writable(
    path: &Path,
    metadata: &Metadata,
) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt as _;
    if metadata.mode() & 0o022 != 0 {
        return Err(CliError::cli_other_error(format!(
            "{} must not be group or world writable",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_not_group_or_world_writable(
    _path: &Path,
    _metadata: &Metadata,
) -> Result<(), CliError> {
    Ok(())
}

#[cfg(unix)]
fn require_executable(path: &Path, metadata: &Metadata) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt as _;
    if metadata.mode() & 0o111 == 0 {
        return Err(CliError::cli_other_error(format!(
            "{} is not executable",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_executable(_path: &Path, _metadata: &Metadata) -> Result<(), CliError> {
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, CliError> {
    let (mut file, _) = open_regular_nofollow(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_secret_references_fail_closed() {
        assert!(require_secret_env("CHIO_TEST_SECRET_THAT_MUST_NOT_EXIST_9F31").is_err());
    }
}
