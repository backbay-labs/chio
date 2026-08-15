use super::CliError;

use std::collections::BTreeSet;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

const FINDING_STATUS_FLOOR_MAX_BYTES: usize = 16 * 1024;
const FINDING_STATUS_FLOOR_SCHEMA_V1: &str = "chio.finding.status-cli-floor.v1";
const FINDING_STATUS_FLOOR_SCHEMA_V2: &str = "chio.finding.status-cli-floor.v2";
const FINDING_STATUS_RETRACTION_MAX_BYTES: usize = 4 * 1024;
const FINDING_STATUS_RETRACTION_SCHEMA_V1: &str = "chio.finding.status-cli-retraction.v1";
const FINDING_STATUS_TRUSTED_TIME_MAX_BYTES: usize = 512;
const FINDING_STATUS_TRUSTED_TIME_SCHEMA_V1: &str = "chio.finding.status-cli-trusted-time.v1";

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FindingStatusCliFloor {
    pub(super) schema: String,
    pub(super) feed_id: String,
    pub(super) operator_id: String,
    pub(super) rotation_policy_ref: String,
    pub(super) operator_key_epoch: u64,
    #[serde(default)]
    pub(super) operator_key: Option<chio_core_types::PublicKey>,
    pub(super) operator_authorization_sha256: String,
    pub(super) key_domain_nonce: u64,
    pub(super) map_epoch: u64,
    pub(super) epoch_id: String,
    pub(super) root_hash: String,
    pub(super) trusted_time_floor: u64,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FindingStatusCliFloorV1 {
    pub(super) schema: String,
    pub(super) feed_id: String,
    pub(super) operator_id: String,
    pub(super) rotation_policy_ref: String,
    pub(super) operator_key_epoch: u64,
    #[serde(default)]
    pub(super) operator_key: Option<chio_core_types::PublicKey>,
    pub(super) operator_authorization_sha256: String,
    pub(super) key_domain_nonce: u64,
    pub(super) map_epoch: u64,
    pub(super) epoch_id: String,
    pub(super) root_hash: String,
    #[serde(default)]
    pub(super) retracted_finding_ids: BTreeSet<String>,
}

enum FindingStatusCliFloorState {
    V1(FindingStatusCliFloorV1),
    V2(FindingStatusCliFloor),
}

impl FindingStatusCliFloorV1 {
    fn into_v2(self, trusted_now: u64) -> (FindingStatusCliFloor, BTreeSet<String>) {
        (
            FindingStatusCliFloor {
                schema: FINDING_STATUS_FLOOR_SCHEMA_V2.to_owned(),
                feed_id: self.feed_id,
                operator_id: self.operator_id,
                rotation_policy_ref: self.rotation_policy_ref,
                operator_key_epoch: self.operator_key_epoch,
                operator_key: self.operator_key,
                operator_authorization_sha256: self.operator_authorization_sha256,
                key_domain_nonce: self.key_domain_nonce,
                map_epoch: self.map_epoch,
                epoch_id: self.epoch_id,
                root_hash: self.root_hash,
                trusted_time_floor: trusted_now,
            },
            self.retracted_finding_ids,
        )
    }
}

#[derive(Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct FindingStatusCliRetraction {
    schema: String,
    feed_id: String,
    operator_id: String,
    rotation_policy_ref: String,
    key_domain_nonce: u64,
    finding_id: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct FindingStatusCliTrustedTime {
    schema: String,
    trusted_time_floor: u64,
}

pub(super) struct FindingStatusFloorObservation<'a> {
    pub(super) feed_id: &'a str,
    pub(super) key_domain_nonce: u64,
    pub(super) map_epoch: u64,
    pub(super) epoch_id: &'a str,
    pub(super) root_hash: &'a str,
    pub(super) finding_id: &'a str,
    pub(super) is_retracted: bool,
}

pub(super) struct FindingStatusFloorLock {
    _file: std::fs::File,
}

impl FindingStatusFloorLock {
    pub(super) fn acquire(floor_path: &Path) -> Result<Self, CliError> {
        let file_name = floor_path.file_name().ok_or_else(|| {
            CliError::cli_other_error(
                "finding status rollback floor path has no file name".to_owned(),
            )
        })?;
        let mut lock_name = file_name.to_os_string();
        lock_name.push(".lock");
        let path = floor_path.with_file_name(lock_name);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| {
                CliError::cli_io_error(format!(
                    "failed to open finding status rollback-floor lock {}: {error}",
                    path.display()
                ))
            })?;
        file.try_lock().map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to acquire finding status rollback-floor lock {}: {error}",
                path.display()
            ))
        })?;
        Ok(Self { _file: file })
    }
}

fn read_canonical_state(
    path: &Path,
    max_bytes: usize,
    kind: &str,
) -> Result<Option<Vec<u8>>, CliError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CliError::cli_other_error(format!(
            "{} is not a regular {kind} file",
            path.display()
        )));
    }
    let mut reader = std::fs::File::open(path)?.take((max_bytes as u64).saturating_add(1));
    let mut bytes = Vec::with_capacity(max_bytes.saturating_add(1));
    reader.read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(CliError::cli_other_error(format!(
            "{} exceeds the finding status {kind} bound",
            path.display()
        )));
    }
    let raw = std::str::from_utf8(&bytes).map_err(|error| {
        CliError::cli_other_error(format!("{} is not valid UTF-8: {error}", path.display()))
    })?;
    let canonical = chio_core::canonical::canonical_json_bytes_from_str(raw).map_err(|error| {
        CliError::cli_other_error(format!(
            "{} is not strict canonical I-JSON: {error}",
            path.display()
        ))
    })?;
    if canonical != bytes {
        return Err(CliError::cli_other_error(format!(
            "{} is not canonical {kind} serialization",
            path.display()
        )));
    }
    Ok(Some(bytes))
}

fn write_canonical_state<T: serde::Serialize>(
    path: &Path,
    value: &T,
    max_bytes: usize,
    kind: &str,
) -> Result<(), CliError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(CliError::cli_other_error(format!(
            "finding status {kind} directory {} does not exist",
            parent.display()
        )));
    }
    let file_name = path.file_name().ok_or_else(|| {
        CliError::cli_other_error(format!("finding status {kind} path has no file name"))
    })?;
    let bytes = chio_core::canonical_json_bytes(value)?;
    if bytes.len() > max_bytes {
        return Err(CliError::cli_other_error(format!(
            "finding status {kind} serialization exceeds its {max_bytes} byte bound"
        )));
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| CliError::cli_other_error(format!("system clock is invalid: {error}")))?
        .as_nanos();
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(file_name);
    temp_name.push(format!(".tmp-{}-{nonce}", std::process::id()));
    let temp_path = parent.join(temp_name);
    let write_result = (|| -> Result<(), CliError> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp_path, path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    write_result
}

fn read_status_floor_state(
    path: &Path,
) -> Result<Option<FindingStatusCliFloorState>, CliError> {
    let Some(bytes) = read_canonical_state(
        path,
        FINDING_STATUS_FLOOR_MAX_BYTES,
        "rollback-floor",
    )? else {
        return Ok(None);
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            CliError::cli_other_error("finding status rollback floor has no schema".to_owned())
        })?;
    match schema {
        FINDING_STATUS_FLOOR_SCHEMA_V1 => Ok(Some(FindingStatusCliFloorState::V1(
            serde_json::from_value(value)?,
        ))),
        FINDING_STATUS_FLOOR_SCHEMA_V2 => Ok(Some(FindingStatusCliFloorState::V2(
            serde_json::from_value(value)?,
        ))),
        _ => Err(CliError::cli_other_error(
            "finding status rollback floor schema is unsupported".to_owned(),
        )),
    }
}

#[cfg(test)]
pub(super) fn read_status_floor(path: &Path) -> Result<Option<FindingStatusCliFloor>, CliError> {
    match read_status_floor_state(path)? {
        Some(FindingStatusCliFloorState::V2(floor)) => Ok(Some(floor)),
        Some(FindingStatusCliFloorState::V1(_)) => Err(CliError::cli_other_error(
            "finding status v1 rollback floor requires a verified migration".to_owned(),
        )),
        None => Ok(None),
    }
}

pub(super) fn write_status_floor(
    path: &Path,
    floor: &FindingStatusCliFloor,
) -> Result<(), CliError> {
    write_canonical_state(
        path,
        floor,
        FINDING_STATUS_FLOOR_MAX_BYTES,
        "rollback-floor",
    )
}

fn status_trusted_time_path(floor_path: &Path) -> Result<PathBuf, CliError> {
    let file_name = floor_path.file_name().ok_or_else(|| {
        CliError::cli_other_error("finding status rollback floor path has no file name".to_owned())
    })?;
    let mut trusted_time_name = file_name.to_os_string();
    trusted_time_name.push(".trusted-time");
    Ok(floor_path.with_file_name(trusted_time_name))
}

fn read_trusted_time_floor(floor_path: &Path) -> Result<Option<u64>, CliError> {
    let path = status_trusted_time_path(floor_path)?;
    let Some(bytes) = read_canonical_state(
        &path,
        FINDING_STATUS_TRUSTED_TIME_MAX_BYTES,
        "trusted-time floor",
    )?
    else {
        return Ok(None);
    };
    let state: FindingStatusCliTrustedTime = serde_json::from_slice(&bytes)?;
    if state.schema != FINDING_STATUS_TRUSTED_TIME_SCHEMA_V1 || state.trusted_time_floor == 0 {
        return Err(CliError::cli_other_error(
            "finding status trusted-time floor is invalid".to_owned(),
        ));
    }
    Ok(Some(state.trusted_time_floor))
}

pub(super) fn advance_trusted_time_locked(
    floor_path: &Path,
    trusted_now: u64,
) -> Result<(), CliError> {
    require_trusted_time(floor_path, trusted_now)?;
    if read_trusted_time_floor(floor_path)?.is_some_and(|current| current >= trusted_now) {
        return Ok(());
    }
    let path = status_trusted_time_path(floor_path)?;
    write_canonical_state(
        &path,
        &FindingStatusCliTrustedTime {
            schema: FINDING_STATUS_TRUSTED_TIME_SCHEMA_V1.to_owned(),
            trusted_time_floor: trusted_now,
        },
        FINDING_STATUS_TRUSTED_TIME_MAX_BYTES,
        "trusted-time floor",
    )
}

fn status_retraction_directory(floor_path: &Path) -> Result<PathBuf, CliError> {
    let file_name = floor_path.file_name().ok_or_else(|| {
        CliError::cli_other_error("finding status rollback floor path has no file name".to_owned())
    })?;
    let mut directory_name = file_name.to_os_string();
    directory_name.push(".retractions");
    Ok(floor_path.with_file_name(directory_name))
}

fn status_retraction_path(floor_path: &Path, finding_id: &str) -> Result<PathBuf, CliError> {
    let digest = chio_core::sha256_hex(finding_id.as_bytes());
    Ok(status_retraction_directory(floor_path)?.join(format!("{digest}.json")))
}

fn validate_retraction_directory(path: &Path) -> Result<bool, CliError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::cli_other_error(format!(
            "{} is not a regular finding status retraction directory",
            path.display()
        )));
    }
    Ok(true)
}

fn ensure_retraction_directory(floor_path: &Path) -> Result<PathBuf, CliError> {
    let directory = status_retraction_directory(floor_path)?;
    if !validate_retraction_directory(&directory)? {
        std::fs::create_dir(&directory)?;
        let parent = directory.parent().unwrap_or_else(|| Path::new("."));
        std::fs::File::open(parent)?.sync_all()?;
    }
    if !validate_retraction_directory(&directory)? {
        return Err(CliError::cli_other_error(format!(
            "{} did not resolve to a finding status retraction directory",
            directory.display()
        )));
    }
    Ok(directory)
}

fn expected_retraction(
    status: &FindingStatusFloorObservation<'_>,
    authorization: &chio_finding::FindingStatusOperatorAuthorization,
) -> FindingStatusCliRetraction {
    FindingStatusCliRetraction {
        schema: FINDING_STATUS_RETRACTION_SCHEMA_V1.to_owned(),
        feed_id: status.feed_id.to_owned(),
        operator_id: authorization.operator.authority_id.clone(),
        rotation_policy_ref: authorization.operator.rotation_policy_ref.clone(),
        key_domain_nonce: status.key_domain_nonce,
        finding_id: status.finding_id.to_owned(),
    }
}

fn read_status_retraction(
    floor_path: &Path,
    status: &FindingStatusFloorObservation<'_>,
    authorization: &chio_finding::FindingStatusOperatorAuthorization,
) -> Result<bool, CliError> {
    let directory = status_retraction_directory(floor_path)?;
    if !validate_retraction_directory(&directory)? {
        return Ok(false);
    }
    let path = status_retraction_path(floor_path, status.finding_id)?;
    let Some(bytes) = read_canonical_state(
        &path,
        FINDING_STATUS_RETRACTION_MAX_BYTES,
        "retraction",
    )? else {
        return Ok(false);
    };
    let persisted: FindingStatusCliRetraction = serde_json::from_slice(&bytes)?;
    if persisted != expected_retraction(status, authorization) {
        return Err(CliError::cli_other_error(format!(
            "{} binds a different finding status retraction",
            path.display()
        )));
    }
    Ok(true)
}

fn persist_status_retraction(
    floor_path: &Path,
    status: &FindingStatusFloorObservation<'_>,
    authorization: &chio_finding::FindingStatusOperatorAuthorization,
) -> Result<(), CliError> {
    if read_status_retraction(floor_path, status, authorization)? {
        return Ok(());
    }
    let directory = ensure_retraction_directory(floor_path)?;
    let path = directory.join(format!(
        "{}.json",
        chio_core::sha256_hex(status.finding_id.as_bytes())
    ));
    write_canonical_state(
        &path,
        &expected_retraction(status, authorization),
        FINDING_STATUS_RETRACTION_MAX_BYTES,
        "retraction",
    )
}

#[cfg(test)]
pub(super) fn advance_status_floor(
    path: &Path,
    status: &FindingStatusFloorObservation<'_>,
    authorization: &chio_finding::FindingStatusOperatorAuthorization,
    authorization_sha256: &str,
    trusted_now: u64,
) -> Result<(), CliError> {
    let _lock = FindingStatusFloorLock::acquire(path)?;
    advance_status_floor_locked(
        path,
        status,
        authorization,
        authorization_sha256,
        trusted_now,
    )
}

pub(super) fn require_trusted_time(path: &Path, trusted_now: u64) -> Result<(), CliError> {
    if trusted_now == 0 {
        return Err(CliError::cli_other_error(
            "finding status trusted time must be positive".to_owned(),
        ));
    }
    let mut durable_floor = read_trusted_time_floor(path)?.unwrap_or_default();
    if let Some(FindingStatusCliFloorState::V2(current)) = read_status_floor_state(path)? {
        durable_floor = durable_floor.max(current.trusted_time_floor);
    }
    if trusted_now < durable_floor {
        return Err(CliError::cli_other_error(format!(
            "finding status host clock rolled back below the durable trusted-time floor {durable_floor}"
        )));
    }
    Ok(())
}

pub(super) fn advance_status_floor_locked(
    path: &Path,
    status: &FindingStatusFloorObservation<'_>,
    authorization: &chio_finding::FindingStatusOperatorAuthorization,
    authorization_sha256: &str,
    trusted_now: u64,
) -> Result<(), CliError> {
    advance_trusted_time_locked(path, trusted_now)?;
    let (current, legacy_retractions) = match read_status_floor_state(path)? {
        Some(FindingStatusCliFloorState::V1(floor)) => {
            let (floor, retractions) = floor.into_v2(trusted_now);
            (Some(floor), retractions)
        }
        Some(FindingStatusCliFloorState::V2(floor)) => (Some(floor), BTreeSet::new()),
        None => (None, BTreeSet::new()),
    };
    if let Some(current) = current.as_ref() {
        if current.schema != FINDING_STATUS_FLOOR_SCHEMA_V2
            || current.feed_id != status.feed_id
            || current.operator_id != authorization.operator.authority_id
            || current.rotation_policy_ref != authorization.operator.rotation_policy_ref
            || current.key_domain_nonce != status.key_domain_nonce
        {
            return Err(CliError::cli_other_error(
                "finding status rollback floor binds a different feed or operator".to_owned(),
            ));
        }
        if authorization.operator.key_epoch < current.operator_key_epoch {
            return Err(CliError::cli_other_error(
                "finding status operator authorization regressed".to_owned(),
            ));
        }
        if authorization.operator.key_epoch == current.operator_key_epoch {
            match current.operator_key.as_ref() {
                Some(key) if key != &authorization.operator.key => {
                    return Err(CliError::cli_other_error(
                        "finding status operator key equivocated within one epoch".to_owned(),
                    ));
                }
                None if authorization_sha256 != current.operator_authorization_sha256 => {
                    return Err(CliError::cli_other_error(
                        "legacy finding status floor cannot authenticate a same-epoch authorization refresh"
                            .to_owned(),
                    ));
                }
                Some(_) | None => {}
            }
        }
    }

    let is_durably_retracted = legacy_retractions.contains(status.finding_id)
        || read_status_retraction(path, status, authorization)?;
    if !status.is_retracted && is_durably_retracted {
        return Err(CliError::cli_other_error(
            "finding status response attempts to revive a durably retracted Finding".to_owned(),
        ));
    }
    if status.is_retracted && !is_durably_retracted {
        // Retain an authenticated retraction even when its epoch is below the
        // global floor. The floor must still reject the rollback and remain
        // unchanged, but a later higher-epoch non-inclusion must not revive
        // this Finding.
        persist_status_retraction(path, status, authorization)?;
    }

    if let Some(current) = current.as_ref() {
        if status.map_epoch < current.map_epoch {
            return Err(CliError::cli_other_error(
                "finding status response is below the durable rollback floor".to_owned(),
            ));
        }
        if status.map_epoch == current.map_epoch
            && (status.epoch_id != current.epoch_id || status.root_hash != current.root_hash)
        {
            return Err(CliError::cli_other_error(
                "finding status response equivocates at the durable rollback floor".to_owned(),
            ));
        }
        if authorization_sha256 != current.operator_authorization_sha256
            && status.map_epoch == current.map_epoch
        {
            return Err(CliError::cli_other_error(
                "finding status authorization refresh did not advance the durable map epoch"
                    .to_owned(),
            ));
        }
        for finding_id in &legacy_retractions {
            if finding_id.len() != 64
                || !finding_id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(CliError::cli_other_error(
                    "finding status v1 rollback floor contains an invalid retraction id"
                        .to_owned(),
                ));
            }
            persist_status_retraction(
                path,
                &FindingStatusFloorObservation {
                    feed_id: &current.feed_id,
                    key_domain_nonce: current.key_domain_nonce,
                    map_epoch: current.map_epoch,
                    epoch_id: &current.epoch_id,
                    root_hash: &current.root_hash,
                    finding_id,
                    is_retracted: true,
                },
                authorization,
            )?;
        }
    }

    write_status_floor(
        path,
        &FindingStatusCliFloor {
            schema: FINDING_STATUS_FLOOR_SCHEMA_V2.to_owned(),
            feed_id: status.feed_id.to_owned(),
            operator_id: authorization.operator.authority_id.clone(),
            rotation_policy_ref: authorization.operator.rotation_policy_ref.clone(),
            operator_key_epoch: authorization.operator.key_epoch,
            operator_key: Some(authorization.operator.key.clone()),
            operator_authorization_sha256: authorization_sha256.to_owned(),
            key_domain_nonce: status.key_domain_nonce,
            map_epoch: status.map_epoch,
            epoch_id: status.epoch_id.to_owned(),
            root_hash: status.root_hash.to_owned(),
            trusted_time_floor: trusted_now,
        },
    )
}

#[cfg(test)]
pub(super) const TEST_FINDING_STATUS_FLOOR_SCHEMA: &str = FINDING_STATUS_FLOOR_SCHEMA_V2;
