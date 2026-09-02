use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chio_core::canonical::canonical_json_bytes;
use chio_core::sha256_hex;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::admission_operation_store::{
    load_admission_commit_head, verify_admission_commit_chain, verify_admission_commit_suffix,
    AdmissionCommitHead, GENESIS_CHAIN_DIGEST,
};

use super::global_commit_chain::{
    verify_global_commit_chain, verify_global_commit_suffix, verify_global_projection_head,
    GlobalCommitHead, GLOBAL_GENESIS_DIGEST,
};

use super::SqliteServingOwnerError;

const SLOT_SIZE: usize = 1024;
const SLOT_COUNT: usize = 2;
const FILE_SIZE: usize = SLOT_SIZE * SLOT_COUNT;
const COMMIT_MARKER: &[u8; 8] = b"CHIOA1OK";
const LENGTH_OFFSET: usize = COMMIT_MARKER.len();
const CHECKSUM_OFFSET: usize = LENGTH_OFFSET + 4;
const PAYLOAD_OFFSET: usize = CHECKSUM_OFFSET + 64;
const MAX_PAYLOAD_BYTES: usize = SLOT_SIZE - PAYLOAD_OFFSET;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AnchorRecord {
    format: String,
    generation: u64,
    store_uuid: String,
    owner_epoch: u64,
    serving_lease_id: Option<String>,
    admission_commit_head: u64,
    admission_commit_chain_digest: String,
    trusted_time_high_water_unix_ms: u64,
    global_commit_head: u64,
    global_commit_chain_digest: String,
}

struct DatabaseState {
    store_uuid: String,
    owner_epoch: u64,
    serving_lease_id: Option<String>,
    commit: AdmissionCommitHead,
    global_commit: GlobalCommitHead,
}

struct LoadedAnchor {
    record: AnchorRecord,
    corrupt_slot: bool,
}

pub(crate) struct RollbackAnchor {
    file: File,
    lock_root: PathBuf,
    lock_path: PathBuf,
    expected_device: u64,
    expected_inode: u64,
    /// Held across every slot read and the whole rotation that clears a
    /// marker, rewrites the slot, and restores it. The serving owner is one
    /// process by construction, so this is the whole population of anchor
    /// readers and writers: a reader never observes the rotation, which
    /// leaves damage as the only explanation for a slot that does not
    /// decode.
    rotation: Mutex<()>,
}

impl RollbackAnchor {
    pub(crate) fn new(
        file: File,
        lock_root: &Path,
        store_uuid: &str,
        expected_device: u64,
        expected_inode: u64,
    ) -> Result<Self, SqliteServingOwnerError> {
        let anchor = Self {
            file,
            lock_root: lock_root.to_path_buf(),
            lock_path: lock_root.join(format!("{store_uuid}.lock")),
            expected_device,
            expected_inode,
            rotation: Mutex::new(()),
        };
        anchor.validate_identity()?;
        Ok(anchor)
    }

    pub(crate) fn reconcile_startup(
        &self,
        connection: &Connection,
    ) -> Result<(), SqliteServingOwnerError> {
        let _rotation = self.hold_rotation()?;
        self.validate_identity()?;
        let database = DatabaseState::load_verified(connection)?;
        match self.load_record()? {
            Some(loaded) => {
                prove_extension(connection, &loaded.record, &database)?;
                if loaded.corrupt_slot && !database_strictly_extends(&loaded.record, &database) {
                    return Err(invalid(
                        "corrupt rollback anchor slot has no strict database extension",
                    ));
                }
                if loaded.record != database.record(loaded.record.generation) {
                    self.write_next(&database, loaded.record.generation)?;
                }
            }
            None => {
                return Err(invalid("serving rollback anchor is absent"));
            }
        }
        Ok(())
    }

    pub(crate) fn migrate_offline(
        &self,
        connection: &Connection,
    ) -> Result<(), SqliteServingOwnerError> {
        let _rotation = self.hold_rotation()?;
        self.validate_identity()?;
        let database = DatabaseState::load_verified(connection)?;
        match self.load_record()? {
            Some(loaded) => {
                prove_extension(connection, &loaded.record, &database)?;
                if loaded.corrupt_slot && !database_strictly_extends(&loaded.record, &database) {
                    return Err(invalid(
                        "corrupt rollback anchor slot has no strict database extension",
                    ));
                }
                if loaded.record != database.record(loaded.record.generation) {
                    self.write_next(&database, loaded.record.generation)?;
                }
            }
            None => {
                return Err(invalid(
                    "existing authority store has no protected rollback anchor",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn seed_new(&self, connection: &Connection) -> Result<(), SqliteServingOwnerError> {
        let _rotation = self.hold_rotation()?;
        self.validate_identity()?;
        if self.load_record()?.is_some() {
            return Err(invalid("new authority rollback anchor is not empty"));
        }
        let database = DatabaseState::load_verified(connection)?;
        self.write_next(&database, 0)
    }

    pub(crate) fn verify_current(
        &self,
        connection: &Connection,
    ) -> Result<(), SqliteServingOwnerError> {
        let _rotation = self.hold_rotation()?;
        self.validate_identity()?;
        let database = DatabaseState::load_current(connection)?;
        let loaded = self
            .load_record()?
            .ok_or_else(|| invalid("serving rollback anchor is absent"))?;
        if loaded.corrupt_slot {
            return Err(invalid("serving rollback anchor contains a corrupt slot"));
        }
        if loaded.record != database.record(loaded.record.generation) {
            return Err(invalid(
                "authority database does not match its serving rollback anchor",
            ));
        }
        Ok(())
    }

    /// Verify the authority database still extends its anchor.
    ///
    /// A serving-owner commit legitimately puts the database ahead of the
    /// anchor until the writer syncs it, so a reader on another connection
    /// cannot require equality. It requires the same proof the writer runs:
    /// a matching store, no counter behind the anchored one, and the
    /// anchored digests present in both commit chains. A restored database
    /// fails the bounds, and one whose history diverged fails the suffix
    /// proof even when its reported head sits above the anchor. The caller
    /// establishes that this process still owns the serving lease.
    ///
    /// The anchor must be read before the caller pins the database
    /// snapshot it will prove. The writer syncs the anchor after its
    /// commit lands, so an anchor read afterwards can carry a head the
    /// pinned snapshot has not reached, which is indistinguishable here
    /// from a database that fell behind.
    pub(crate) fn verify_extends(
        &self,
        connection: &Connection,
        anchored: &AnchorRecord,
    ) -> Result<(), SqliteServingOwnerError> {
        self.validate_identity()?;
        let database = DatabaseState::load_current(connection)?;
        prove_extension(connection, anchored, &database)
    }

    /// The record the anchor last committed.
    ///
    /// Anchor reads exclude the rotation, so no slot this observes is
    /// mid-write: a slot that does not decode was damaged, and denies.
    pub(crate) fn committed_record(&self) -> Result<AnchorRecord, SqliteServingOwnerError> {
        let _rotation = self.hold_rotation()?;
        self.validate_identity()?;
        let loaded = self
            .load_record()?
            .ok_or_else(|| invalid("serving rollback anchor is absent"))?;
        if loaded.corrupt_slot {
            return Err(invalid("serving rollback anchor contains a corrupt slot"));
        }
        Ok(loaded.record)
    }

    pub(crate) fn sync_after_commit(
        &self,
        connection: &Connection,
    ) -> Result<(), SqliteServingOwnerError> {
        let _rotation = self.hold_rotation()?;
        self.validate_identity()?;
        let database = DatabaseState::load_current(connection)?;
        let loaded = self
            .load_record()?
            .ok_or_else(|| invalid("serving rollback anchor is absent"))?;
        if loaded.corrupt_slot {
            return Err(invalid("serving rollback anchor contains a corrupt slot"));
        }
        prove_extension(connection, &loaded.record, &database)?;
        if loaded.record != database.record(loaded.record.generation) {
            self.write_next(&database, loaded.record.generation)?;
        }
        Ok(())
    }

    fn write_next(
        &self,
        database: &DatabaseState,
        current_generation: u64,
    ) -> Result<(), SqliteServingOwnerError> {
        let generation = current_generation
            .checked_add(1)
            .ok_or_else(|| invalid("serving rollback anchor generation overflowed"))?;
        let record = database.record(generation);
        record.validate()?;
        let payload = canonical_json_bytes(&record)
            .map_err(|error| invalid(format!("rollback anchor encoding failed: {error}")))?;
        if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
            return Err(invalid("serving rollback anchor exceeds its fixed slot"));
        }
        self.ensure_shape()?;
        let slot_index = usize::try_from((generation - 1) % 2)
            .map_err(|_| invalid("serving rollback anchor slot overflowed"))?;
        let offset = slot_index * SLOT_SIZE;

        write_all_at(&self.file, &[0_u8; COMMIT_MARKER.len()], offset)?;
        self.file.sync_data()?;

        let mut slot = [0_u8; SLOT_SIZE];
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| invalid("serving rollback anchor payload length overflowed"))?;
        slot[LENGTH_OFFSET..CHECKSUM_OFFSET].copy_from_slice(&payload_len.to_be_bytes());
        let checksum = sha256_hex(&payload);
        slot[CHECKSUM_OFFSET..PAYLOAD_OFFSET].copy_from_slice(checksum.as_bytes());
        slot[PAYLOAD_OFFSET..PAYLOAD_OFFSET + payload.len()].copy_from_slice(&payload);
        write_all_at(&self.file, &slot, offset)?;
        self.file.sync_data()?;
        write_all_at(&self.file, COMMIT_MARKER, offset)?;
        self.file.sync_all()?;
        self.validate_identity()?;

        let persisted = self
            .load_record()?
            .ok_or_else(|| invalid("serving rollback anchor write was not durable"))?;
        if persisted.corrupt_slot || persisted.record != record {
            return Err(invalid("serving rollback anchor write did not round trip"));
        }
        Ok(())
    }

    /// Exclude the rotation from anchor reads for the caller's whole
    /// operation. A rotation clears a slot marker before installing the
    /// next record, and a reader that saw that interval could not tell it
    /// from a slot the storage damaged.
    fn hold_rotation(&self) -> Result<std::sync::MutexGuard<'_, ()>, SqliteServingOwnerError> {
        self.rotation
            .lock()
            .map_err(|_| invalid("serving rollback anchor rotation lock is poisoned"))
    }

    fn load_record(&self) -> Result<Option<LoadedAnchor>, SqliteServingOwnerError> {
        self.ensure_shape()?;
        let mut records = Vec::with_capacity(SLOT_COUNT);
        let mut invalid_slot = None;
        for slot_index in 0..SLOT_COUNT {
            let mut slot = [0_u8; SLOT_SIZE];
            read_exact_at(&self.file, &mut slot, slot_index * SLOT_SIZE)?;
            let marker = &slot[..COMMIT_MARKER.len()];
            if marker.iter().all(|byte| *byte == 0) {
                if slot[COMMIT_MARKER.len()..].iter().any(|byte| *byte != 0) {
                    invalid_slot = Some(invalid(
                        "serving rollback anchor uncommitted slot is corrupt",
                    ));
                }
                continue;
            }
            let decoded = if marker == COMMIT_MARKER {
                decode_slot(&slot)
            } else {
                Err(invalid("serving rollback anchor commit marker is corrupt"))
            };
            match decoded {
                Ok(record) => records.push(record),
                Err(error) => invalid_slot = Some(error),
            }
        }
        records.sort_by_key(|record| record.generation);
        if records.len() == 2 {
            let prior = &records[0];
            let current = &records[1];
            if prior
                .generation
                .checked_add(1)
                .is_none_or(|next| next != current.generation)
                || !record_extends(current, prior)
            {
                return Err(invalid(
                    "serving rollback anchor slots are not one monotonic history",
                ));
            }
        }
        match records.pop() {
            Some(record) => Ok(Some(LoadedAnchor {
                record,
                corrupt_slot: invalid_slot.is_some(),
            })),
            None => invalid_slot.map_or(Ok(None), Err),
        }
    }

    fn ensure_shape(&self) -> Result<(), SqliteServingOwnerError> {
        let length = self.file.metadata()?.len();
        if length == 0 {
            self.file.set_len(
                u64::try_from(FILE_SIZE)
                    .map_err(|_| invalid("serving rollback anchor size overflowed"))?,
            )?;
            self.file.sync_all()?;
        } else if length
            != u64::try_from(FILE_SIZE)
                .map_err(|_| invalid("serving rollback anchor size overflowed"))?
        {
            return Err(invalid("serving rollback anchor has an invalid size"));
        }
        Ok(())
    }

    fn validate_identity(&self) -> Result<(), SqliteServingOwnerError> {
        validate_secure_lock_root(&self.lock_root)?;
        let path_metadata = fs::symlink_metadata(&self.lock_path)?;
        let file_metadata = self.file.metadata()?;
        for metadata in [&path_metadata, &file_metadata] {
            validate_lock_metadata(metadata)?;
            if metadata_device(metadata)? != self.expected_device
                || metadata_inode(metadata)? != self.expected_inode
            {
                return Err(invalid("serving rollback anchor inode changed"));
            }
        }
        Ok(())
    }
}

impl DatabaseState {
    fn load_verified(connection: &Connection) -> Result<Self, SqliteServingOwnerError> {
        let commit = verify_admission_commit_chain(connection)?;
        let global_commit = verify_global_commit_chain(connection)?;
        Self::load_owner(connection, commit, global_commit)
    }

    fn load_current(connection: &Connection) -> Result<Self, SqliteServingOwnerError> {
        let commit = load_admission_commit_head(connection)?;
        let global_commit = verify_global_projection_head(connection)?;
        Self::load_owner(connection, commit, global_commit)
    }

    fn load_owner(
        connection: &Connection,
        commit: AdmissionCommitHead,
        global_commit: GlobalCommitHead,
    ) -> Result<Self, SqliteServingOwnerError> {
        let (store_uuid, owner_epoch, serving_lease_id): (String, i64, Option<String>) = connection
            .query_row(
            "SELECT store_uuid, owner_epoch, lease_id FROM chio_serving_owner WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let owner_epoch =
            u64::try_from(owner_epoch).map_err(|_| invalid("serving owner epoch is negative"))?;
        validate_store_uuid(&store_uuid)?;
        validate_serving_lease(owner_epoch, serving_lease_id.as_deref())?;
        Ok(Self {
            store_uuid,
            owner_epoch,
            serving_lease_id,
            commit,
            global_commit,
        })
    }

    fn record(&self, generation: u64) -> AnchorRecord {
        AnchorRecord {
            format: "chio.sqlite-authority-rollback-anchor-global.v1".to_string(),
            generation,
            store_uuid: self.store_uuid.clone(),
            owner_epoch: self.owner_epoch,
            serving_lease_id: self.serving_lease_id.clone(),
            admission_commit_head: self.commit.head_sequence,
            admission_commit_chain_digest: self.commit.chain_digest.clone(),
            trusted_time_high_water_unix_ms: self.commit.trusted_time_high_water_unix_ms,
            global_commit_head: self.global_commit.head_sequence,
            global_commit_chain_digest: self.global_commit.chain_digest.clone(),
        }
    }
}

impl AnchorRecord {
    fn validate(&self) -> Result<(), SqliteServingOwnerError> {
        if self.format != "chio.sqlite-authority-rollback-anchor-global.v1" || self.generation == 0
        {
            return Err(invalid("serving rollback anchor version is invalid"));
        }
        validate_store_uuid(&self.store_uuid)?;
        validate_serving_lease(self.owner_epoch, self.serving_lease_id.as_deref())?;
        if !is_digest(&self.admission_commit_chain_digest)
            || (self.admission_commit_head == 0
                && (self.admission_commit_chain_digest != GENESIS_CHAIN_DIGEST
                    || self.trusted_time_high_water_unix_ms != 0))
            || (self.admission_commit_head > 0 && self.trusted_time_high_water_unix_ms == 0)
        {
            return Err(invalid("serving rollback anchor admission head is invalid"));
        }
        if !is_digest(&self.global_commit_chain_digest)
            || (self.global_commit_head == 0
                && self.global_commit_chain_digest != GLOBAL_GENESIS_DIGEST)
        {
            return Err(invalid("serving rollback anchor global head is invalid"));
        }
        Ok(())
    }

    fn commit_head(&self) -> AdmissionCommitHead {
        AdmissionCommitHead {
            head_sequence: self.admission_commit_head,
            chain_digest: self.admission_commit_chain_digest.clone(),
            trusted_time_high_water_unix_ms: self.trusted_time_high_water_unix_ms,
        }
    }

    fn global_commit_head(&self) -> GlobalCommitHead {
        GlobalCommitHead {
            head_sequence: self.global_commit_head,
            chain_digest: self.global_commit_chain_digest.clone(),
        }
    }
}

fn prove_extension(
    connection: &Connection,
    anchor: &AnchorRecord,
    database: &DatabaseState,
) -> Result<(), SqliteServingOwnerError> {
    anchor.validate()?;
    if database.store_uuid != anchor.store_uuid
        || database.owner_epoch < anchor.owner_epoch
        || (database.owner_epoch == anchor.owner_epoch
            && database.serving_lease_id != anchor.serving_lease_id)
        || database.commit.head_sequence < anchor.admission_commit_head
        || database.commit.trusted_time_high_water_unix_ms < anchor.trusted_time_high_water_unix_ms
        || database.global_commit.head_sequence < anchor.global_commit_head
    {
        return Err(invalid("authority database is behind its rollback anchor"));
    }
    verify_admission_commit_suffix(connection, &anchor.commit_head(), &database.commit)?;
    verify_global_commit_suffix(
        connection,
        &anchor.global_commit_head(),
        &database.global_commit,
    )?;
    Ok(())
}

fn database_strictly_extends(anchor: &AnchorRecord, database: &DatabaseState) -> bool {
    database.owner_epoch > anchor.owner_epoch
        || database.commit.head_sequence > anchor.admission_commit_head
        || database.commit.trusted_time_high_water_unix_ms > anchor.trusted_time_high_water_unix_ms
        || database.global_commit.head_sequence > anchor.global_commit_head
}

fn record_extends(current: &AnchorRecord, prior: &AnchorRecord) -> bool {
    current.store_uuid == prior.store_uuid
        && current.owner_epoch >= prior.owner_epoch
        && (current.owner_epoch != prior.owner_epoch
            || current.serving_lease_id == prior.serving_lease_id)
        && current.admission_commit_head >= prior.admission_commit_head
        && current.trusted_time_high_water_unix_ms >= prior.trusted_time_high_water_unix_ms
        && (current.admission_commit_head != prior.admission_commit_head
            || current.admission_commit_chain_digest == prior.admission_commit_chain_digest)
        && current.global_commit_head >= prior.global_commit_head
        && (current.global_commit_head != prior.global_commit_head
            || current.global_commit_chain_digest == prior.global_commit_chain_digest)
}

fn decode_slot(slot: &[u8; SLOT_SIZE]) -> Result<AnchorRecord, SqliteServingOwnerError> {
    let payload_len = u32::from_be_bytes(
        slot[LENGTH_OFFSET..CHECKSUM_OFFSET]
            .try_into()
            .map_err(|_| invalid("serving rollback anchor length is corrupt"))?,
    );
    let payload_len = usize::try_from(payload_len)
        .map_err(|_| invalid("serving rollback anchor length overflowed"))?;
    if payload_len == 0 || payload_len > MAX_PAYLOAD_BYTES {
        return Err(invalid("serving rollback anchor length is invalid"));
    }
    let payload_end = PAYLOAD_OFFSET + payload_len;
    if slot[payload_end..].iter().any(|byte| *byte != 0) {
        return Err(invalid("serving rollback anchor padding is corrupt"));
    }
    let payload = &slot[PAYLOAD_OFFSET..payload_end];
    if slot[CHECKSUM_OFFSET..PAYLOAD_OFFSET] != sha256_hex(payload).as_bytes()[..] {
        return Err(invalid("serving rollback anchor checksum is invalid"));
    }
    let record: AnchorRecord = serde_json::from_slice(payload)
        .map_err(|error| invalid(format!("serving rollback anchor is invalid JSON: {error}")))?;
    if canonical_json_bytes(&record)
        .map_err(|error| invalid(format!("rollback anchor encoding failed: {error}")))?
        != payload
    {
        return Err(invalid("serving rollback anchor is not canonical JSON"));
    }
    record.validate()?;
    Ok(record)
}

fn validate_store_uuid(value: &str) -> Result<(), SqliteServingOwnerError> {
    let parsed = uuid::Uuid::parse_str(value)
        .map_err(|_| invalid("serving rollback anchor store UUID is invalid"))?;
    if parsed.get_version_num() != 7 || parsed.to_string() != value {
        return Err(invalid("serving rollback anchor store UUID is invalid"));
    }
    Ok(())
}

fn validate_serving_lease(
    owner_epoch: u64,
    lease_id: Option<&str>,
) -> Result<(), SqliteServingOwnerError> {
    match (owner_epoch, lease_id) {
        (0, None) => Ok(()),
        (0, Some(_)) | (_, None) => Err(invalid(
            "serving rollback anchor lease does not match its owner epoch",
        )),
        (_, Some(lease_id)) => {
            let parsed = uuid::Uuid::parse_str(lease_id)
                .map_err(|_| invalid("serving rollback anchor lease ID is invalid"))?;
            if parsed.get_version_num() != 7 || parsed.to_string() != lease_id {
                return Err(invalid("serving rollback anchor lease ID is invalid"));
            }
            Ok(())
        }
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(unix)]
fn validate_secure_lock_root(path: &Path) -> Result<(), SqliteServingOwnerError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(invalid("serving rollback anchor lock root is insecure"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_secure_lock_root(_path: &Path) -> Result<(), SqliteServingOwnerError> {
    Err(invalid(
        "sqlite serving rollback anchors require Unix file identity",
    ))
}

#[cfg(unix)]
fn validate_lock_metadata(metadata: &fs::Metadata) -> Result<(), SqliteServingOwnerError> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(invalid("serving rollback anchor inode is insecure"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_lock_metadata(_metadata: &fs::Metadata) -> Result<(), SqliteServingOwnerError> {
    Err(invalid(
        "sqlite serving rollback anchors require Unix file identity",
    ))
}

#[cfg(unix)]
fn metadata_device(metadata: &fs::Metadata) -> Result<u64, SqliteServingOwnerError> {
    use std::os::unix::fs::MetadataExt;

    Ok(metadata.dev())
}

#[cfg(not(unix))]
fn metadata_device(_metadata: &fs::Metadata) -> Result<u64, SqliteServingOwnerError> {
    Err(invalid(
        "sqlite serving rollback anchors require Unix file identity",
    ))
}

#[cfg(unix)]
fn metadata_inode(metadata: &fs::Metadata) -> Result<u64, SqliteServingOwnerError> {
    use std::os::unix::fs::MetadataExt;

    Ok(metadata.ino())
}

#[cfg(not(unix))]
fn metadata_inode(_metadata: &fs::Metadata) -> Result<u64, SqliteServingOwnerError> {
    Err(invalid(
        "sqlite serving rollback anchors require Unix file identity",
    ))
}

#[cfg(unix)]
fn read_exact_at(file: &File, mut bytes: &mut [u8], mut offset: usize) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;

    while !bytes.is_empty() {
        let read = file.read_at(bytes, io_offset(offset)?)?;
        if read == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        offset += read;
        bytes = &mut bytes[read..];
    }
    Ok(())
}

#[cfg(not(unix))]
fn read_exact_at(_file: &File, _bytes: &mut [u8], _offset: usize) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "sqlite serving rollback anchors require Unix positioned I/O",
    ))
}

#[cfg(unix)]
fn write_all_at(file: &File, mut bytes: &[u8], mut offset: usize) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;

    while !bytes.is_empty() {
        let written = file.write_at(bytes, io_offset(offset)?)?;
        if written == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
        }
        offset += written;
        bytes = &bytes[written..];
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_all_at(_file: &File, _bytes: &[u8], _offset: usize) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "sqlite serving rollback anchors require Unix positioned I/O",
    ))
}

fn invalid(detail: impl Into<String>) -> SqliteServingOwnerError {
    SqliteServingOwnerError::Invalid(detail.into())
}

fn io_offset(offset: usize) -> std::io::Result<u64> {
    u64::try_from(offset).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "rollback anchor offset overflowed u64",
        )
    })
}

#[cfg(all(test, unix))]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::fs::{self, File, OpenOptions};
    use std::io::{Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core::canonical::canonical_json_bytes;
    use chio_core::{sha256_hex, StoreMutationFence};
    use chio_kernel::admission_operation::{
        AdmissionDigest, AdmissionIdentifier, AdmissionOperationBindingInputV1,
        AdmissionOperationBindingV1, AdmissionOperationKind, AdmissionOperationStore,
        AdmissionOperationV1, AdmissionParticipantRequirements, AdmissionRequestBindingV1,
        AuthenticatedRequestNamespace, SideEffectClass,
    };
    use rusqlite::{params, Connection};
    use serde::Serialize;
    use tempfile::TempDir;

    use crate::{SqliteAuthorityStore, SqliteServingOwnerError};

    use super::{
        decode_slot, COMMIT_MARKER, GENESIS_CHAIN_DIGEST, PAYLOAD_OFFSET, SLOT_COUNT, SLOT_SIZE,
    };

    struct Fixture {
        _temp: TempDir,
        database: PathBuf,
        lock_root: PathBuf,
        authority: SqliteAuthorityStore,
    }

    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().expect("tempdir");
        super::super::tests::secure_directory(temp.path());
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        super::super::tests::create_lock_root(&lock_root);
        SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
        let authority =
            SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open serving");
        Fixture {
            _temp: temp,
            database,
            lock_root,
            authority,
        }
    }

    fn operation(fence: &StoreMutationFence, request_id: &str) -> AdmissionOperationV1 {
        let identifier =
            |field, value: &str| AdmissionIdentifier::try_new(field, value).expect("identifier");
        let digest = |field, byte: char| {
            AdmissionDigest::try_new(field, byte.to_string().repeat(64)).expect("digest")
        };
        let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
            kind: AdmissionOperationKind::ToolDispatch,
            namespace: AuthenticatedRequestNamespace::for_local_system(identifier(
                "coordinator_authority_id",
                "rollback-anchor-tests",
            ))
            .expect("namespace"),
            request_id: identifier("request_id", request_id),
            capability_id: identifier("capability_id", "capability-anchor"),
            authorization_capability_hash: digest("authorization_capability_hash", 'a'),
            request_binding: AdmissionRequestBindingV1::new(
                digest("immutable_request_hash", 'b'),
                AdmissionParticipantRequirements {
                    budget_capture: true,
                    broker_attempt: true,
                    ..AdmissionParticipantRequirements::NONE
                },
            )
            .expect("request binding"),
            policy_hash: digest("policy_hash", 'c'),
            effect_class: SideEffectClass::SideEffecting,
        })
        .expect("operation binding");
        AdmissionOperationV1::prepare(binding, fence.owner_epoch).expect("operation")
    }

    fn now_ms() -> u64 {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_millis(),
        )
        .expect("millisecond clock")
    }

    fn begin(authority: &SqliteAuthorityStore, request_id: &str, trusted_now: u64) {
        let operation = operation(&authority.mutation_fence(), request_id);
        authority
            .admission_operation_store()
            .begin(&operation, &authority.mutation_fence(), trusted_now)
            .expect("begin operation");
    }

    fn lock_path(lock_root: &Path, authority: &SqliteAuthorityStore) -> PathBuf {
        lock_root.join(format!("{}.lock", authority.mutation_fence().store_uuid))
    }

    fn database_snapshot(authority: &SqliteAuthorityStore, database: &Path, target: &Path) {
        let connection = authority.connection.lock().expect("authority connection");
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint snapshot");
        fs::copy(database, target).expect("copy snapshot");
    }

    fn restore_file_in_place(target: &Path, source: &Path) {
        let mut input = File::open(source).expect("open snapshot");
        let mut output = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(target)
            .expect("open restore target");
        std::io::copy(&mut input, &mut output).expect("restore bytes");
        output.sync_all().expect("sync restored file");
        for suffix in ["-wal", "-shm"] {
            let sidecar = PathBuf::from(format!("{}{suffix}", target.display()));
            let _ = fs::remove_file(sidecar);
        }
    }

    fn overwrite_at(path: &Path, offset: u64, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .expect("open anchor");
        file.seek(SeekFrom::Start(offset)).expect("seek anchor");
        file.write_all(bytes).expect("write anchor");
        file.sync_all().expect("sync anchor");
    }

    fn newest_slot_offset(path: &Path) -> u64 {
        let bytes = fs::read(path).expect("read anchor slots");
        (0..SLOT_COUNT)
            .filter_map(|slot_index| {
                let start = slot_index * SLOT_SIZE;
                let end = start + SLOT_SIZE;
                let slot: [u8; SLOT_SIZE] = bytes[start..end]
                    .try_into()
                    .expect("fixed-size anchor slot");
                if slot[..COMMIT_MARKER.len()] != COMMIT_MARKER[..] {
                    return None;
                }
                decode_slot(&slot)
                    .ok()
                    .map(|record| (record.generation, start))
            })
            .max_by_key(|(generation, _)| *generation)
            .map(|(_, offset)| u64::try_from(offset).expect("anchor slot offset"))
            .expect("committed anchor slot")
    }

    /// Rotation is excluded from anchor reads, so a slot a reader finds
    /// cleared was not caught mid-write. An external rollback that clears
    /// the newest slot to strand the companion on the prior record denies.
    #[test]
    fn companion_reads_reject_a_cleared_slot_marker() {
        let fixture = fixture();
        begin(&fixture.authority, "request-rotation-a", now_ms());
        begin(&fixture.authority, "request-rotation-b", now_ms());
        let anchor = lock_path(&fixture.lock_root, &fixture.authority);
        overwrite_at(
            &anchor,
            newest_slot_offset(&anchor),
            &[0_u8; COMMIT_MARKER.len()],
        );

        assert!(
            matches!(
                fixture.authority.owner.companion_anchor(),
                Err(SqliteServingOwnerError::Invalid(_))
            ),
            "a companion read denies a slot whose commit marker was cleared"
        );
    }

    /// The anchor advances after the commit it records, so an anchor read
    /// once a snapshot is pinned can carry a head that snapshot never sees.
    /// The read path captures the anchor first for exactly this reason.
    #[test]
    fn a_companion_snapshot_proves_against_the_anchor_it_captured() {
        let fixture = fixture();
        begin(&fixture.authority, "request-order-a", now_ms());
        let owner = &fixture.authority.owner;

        let captured = owner.companion_anchor().expect("companion anchor");
        let mut companion = Connection::open(&fixture.database).expect("companion connection");
        let snapshot = companion
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .expect("companion snapshot");
        owner
            .verify_companion_custody(&snapshot, &captured)
            .expect("the captured anchor admits its own snapshot");

        begin(&fixture.authority, "request-order-b", now_ms());

        owner
            .verify_companion_custody(&snapshot, &captured)
            .expect("a commit after the snapshot does not invalidate it");
        let advanced = owner.companion_anchor().expect("companion anchor");
        assert!(
            matches!(
                owner.verify_companion_custody(&snapshot, &advanced),
                Err(SqliteServingOwnerError::Invalid(_))
            ),
            "an anchor read after the snapshot outruns what it can prove"
        );
        snapshot.commit().expect("release companion snapshot");
    }

    /// The exclusion must not be bought by failing reads that race a
    /// commit: discovery runs on this path while the writer works.
    #[test]
    fn companion_reads_survive_concurrent_commits() {
        let fixture = fixture();
        let authority = Arc::new(fixture.authority);
        let writer = Arc::clone(&authority);
        let commits = std::thread::spawn(move || {
            for index in 0..48 {
                begin(&writer, &format!("request-concurrent-{index}"), now_ms());
            }
        });

        let mut companion = Connection::open(&fixture.database).expect("companion connection");
        let mut reads = 0_u32;
        while !commits.is_finished() {
            // The read protocol discovery uses: one deferred transaction
            // pins the snapshot the head and its chain are read from.
            let anchored = authority
                .owner
                .companion_anchor()
                .expect("companion anchor");
            let snapshot = companion
                .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
                .expect("companion snapshot");
            authority
                .owner
                .verify_companion_custody(&snapshot, &anchored)
                .expect("a companion read admits while the writer commits");
            snapshot.commit().expect("release companion snapshot");
            reads += 1;
        }
        commits.join().expect("writer thread");
        assert!(reads > 0, "the reader must observe the writer working");
    }

    /// Tolerating the rotation window must not extend to a slot that claims
    /// to be committed and does not decode, which no interleaving produces.
    #[test]
    fn companion_reads_reject_a_slot_that_claims_a_corrupt_commit() {
        let fixture = fixture();
        begin(&fixture.authority, "request-corrupt-a", now_ms());
        begin(&fixture.authority, "request-corrupt-b", now_ms());
        let anchor = lock_path(&fixture.lock_root, &fixture.authority);
        overwrite_at(
            &anchor,
            newest_slot_offset(&anchor) + u64::try_from(PAYLOAD_OFFSET).expect("payload offset"),
            b"not-canonical-json",
        );

        assert!(
            matches!(
                fixture.authority.owner.companion_anchor(),
                Err(SqliteServingOwnerError::Invalid(_))
            ),
            "a companion read denies a slot that claims a commit it cannot decode"
        );
    }

    /// A companion read runs on its own connection and legitimately observes
    /// the database one commit ahead of the anchor, so it cannot demand an
    /// equal head. Comparing heads alone would let a database restored behind
    /// the anchor pass by claiming a head above it, which is what a rolled
    /// back status database serving stale live rows looks like.
    #[test]
    fn companion_reads_reject_a_restored_database_claiming_a_higher_head() {
        let fixture = fixture();
        begin(&fixture.authority, "request-companion-a", now_ms());
        let snapshot = fixture._temp.path().join("companion-snapshot.db");
        database_snapshot(&fixture.authority, &fixture.database, &snapshot);
        begin(&fixture.authority, "request-companion-b", now_ms());

        let companion = Connection::open(&fixture.database).expect("companion connection");
        let anchored = fixture
            .authority
            .owner
            .companion_anchor()
            .expect("companion anchor");
        fixture
            .authority
            .owner
            .verify_companion_custody(&companion, &anchored)
            .expect("an untampered companion read is admitted");
        drop(companion);

        // The owner outlives the store the way it outlives an in-flight
        // read, so the anchor still holds the head this database committed.
        let owner = Arc::clone(&fixture.authority.owner);
        drop(fixture.authority);

        let forged = Connection::open(&snapshot).expect("snapshot connection");
        forged
            .execute(
                r#"
                UPDATE admission_operation_commit_meta
                SET head_sequence = head_sequence + 8,
                    head_chain_digest = ?1,
                    trusted_time_high_water_unix_ms =
                        trusted_time_high_water_unix_ms + 60000
                WHERE singleton = 1
                "#,
                ["f".repeat(64)],
            )
            .expect("forge a head above the anchored one");
        drop(forged);
        restore_file_in_place(&fixture.database, &snapshot);

        let restored = Connection::open(&fixture.database).expect("restored connection");
        let anchored = owner.companion_anchor().expect("companion anchor");
        assert!(matches!(
            owner.verify_companion_custody(&restored, &anchored),
            Err(SqliteServingOwnerError::Invalid(_))
        ));
    }

    #[test]
    fn in_place_snapshot_rollback_cannot_remove_replay_or_time_heads() {
        let fixture = fixture();
        let snapshot = fixture._temp.path().join("older.db");
        let now = now_ms();
        begin(&fixture.authority, "request-before-snapshot", now);
        database_snapshot(&fixture.authority, &fixture.database, &snapshot);
        begin(&fixture.authority, "request-after-snapshot", now + 1);
        drop(fixture.authority);

        restore_file_in_place(&fixture.database, &snapshot);
        assert!(matches!(
            SqliteAuthorityStore::open_serving(&fixture.database, &fixture.lock_root),
            Err(SqliteServingOwnerError::Invalid(_))
        ));
    }

    #[test]
    fn database_ahead_of_anchor_is_reconciled_before_serving() {
        let fixture = fixture();
        let lock = lock_path(&fixture.lock_root, &fixture.authority);
        let prior_anchor = fs::read(&lock).expect("read prior anchor");
        let fence = fixture.authority.mutation_fence();
        let operation = operation(&fence, "request-db-ahead");
        fixture
            .authority
            .admission_operation_store()
            .begin(&operation, &fence, now_ms())
            .expect("begin operation");
        drop(fixture.authority);

        fs::write(&lock, prior_anchor).expect("restore prior anchor");
        File::open(&lock).expect("anchor").sync_all().expect("sync");
        let recovered = SqliteAuthorityStore::open_serving(&fixture.database, &fixture.lock_root)
            .expect("reconcile DB-ahead anchor");
        assert!(recovered
            .admission_operation_store()
            .load_by_operation_id(operation.binding().operation_id())
            .expect("load")
            .is_some());
    }

    #[test]
    fn database_ahead_of_surviving_anchor_recovers_torn_newest_slot() {
        for corrupt_payload in [false, true] {
            let fixture = fixture();
            let lock = lock_path(&fixture.lock_root, &fixture.authority);
            begin(
                &fixture.authority,
                if corrupt_payload {
                    "request-torn-payload"
                } else {
                    "request-torn-marker"
                },
                now_ms(),
            );
            drop(fixture.authority);

            let target_offset = newest_slot_offset(&lock);
            if corrupt_payload {
                overwrite_at(
                    &lock,
                    target_offset + u64::try_from(COMMIT_MARKER.len() + 4).expect("offset"),
                    b"z",
                );
            } else {
                overwrite_at(&lock, target_offset, &[0_u8; COMMIT_MARKER.len()]);
                overwrite_at(&lock, target_offset, b"CHIO");
            }
            SqliteAuthorityStore::open_serving(&fixture.database, &fixture.lock_root)
                .expect("recover from torn target slot");
        }
    }

    #[test]
    fn corrupt_newest_slot_cannot_launder_database_rollback_to_surviving_anchor() {
        let fixture = fixture();
        let snapshot = fixture._temp.path().join("surviving-anchor.db");
        let lock = lock_path(&fixture.lock_root, &fixture.authority);
        database_snapshot(&fixture.authority, &fixture.database, &snapshot);
        begin(&fixture.authority, "request-after-snapshot", now_ms());
        drop(fixture.authority);

        let target_offset = newest_slot_offset(&lock);
        overwrite_at(
            &lock,
            target_offset + u64::try_from(COMMIT_MARKER.len() + 4).expect("offset"),
            b"z",
        );
        restore_file_in_place(&fixture.database, &snapshot);

        assert!(matches!(
            SqliteAuthorityStore::open_serving(&fixture.database, &fixture.lock_root),
            Err(SqliteServingOwnerError::Invalid(message))
                if message.contains("no strict database extension")
        ));
    }

    #[test]
    fn anchor_corruption_without_a_valid_slot_fails_closed() {
        let fixture = fixture();
        let lock = lock_path(&fixture.lock_root, &fixture.authority);
        drop(fixture.authority);
        overwrite_at(&lock, 0, b"BADMARK!");
        overwrite_at(
            &lock,
            u64::try_from(SLOT_SIZE).expect("slot size"),
            b"BADMARK!",
        );

        assert!(matches!(
            SqliteAuthorityStore::open_serving(&fixture.database, &fixture.lock_root),
            Err(SqliteServingOwnerError::Invalid(_))
        ));
    }

    #[test]
    fn existing_store_with_a_missing_anchor_cannot_be_reseeded() {
        let fixture = fixture();
        let lock = lock_path(&fixture.lock_root, &fixture.authority);
        drop(fixture.authority);
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&lock)
            .expect("truncate anchor")
            .sync_all()
            .expect("sync empty anchor");

        assert!(matches!(
            SqliteAuthorityStore::open_serving(&fixture.database, &fixture.lock_root),
            Err(SqliteServingOwnerError::Invalid(_))
        ));
        assert!(matches!(
            SqliteAuthorityStore::provision(&fixture.database, &fixture.lock_root),
            Err(SqliteServingOwnerError::Invalid(message))
                if message.contains("no protected rollback anchor")
        ));
        assert!(matches!(
            SqliteAuthorityStore::open_serving(&fixture.database, &fixture.lock_root),
            Err(SqliteServingOwnerError::Invalid(_))
        ));
    }

    #[test]
    fn equal_epoch_with_a_different_serving_lease_is_rejected() {
        let fixture = fixture();
        drop(fixture.authority);
        let replacement = uuid::Uuid::now_v7().to_string();
        let connection = Connection::open(&fixture.database).expect("tamper connection");
        connection
            .execute_batch("DROP TRIGGER chio_serving_leases_close_only;")
            .expect("drop lease trigger");
        connection
            .execute(
                "UPDATE chio_serving_leases SET lease_id = ?1 WHERE owner_epoch = 1",
                [&replacement],
            )
            .expect("replace historical lease");
        connection
            .execute(
                "UPDATE chio_serving_owner SET lease_id = ?1 WHERE singleton = 1",
                [&replacement],
            )
            .expect("replace active lease");
        super::super::initialize_serving_lease_schema(&connection)
            .expect("restore exact lease schema");
        super::super::verify_authority_store_invariants(&connection)
            .expect("alternate lease satisfies database invariants");
        drop(connection);

        assert!(matches!(
            SqliteAuthorityStore::open_serving(&fixture.database, &fixture.lock_root),
            Err(SqliteServingOwnerError::Invalid(_))
        ));
    }

    #[derive(Serialize)]
    struct TestChainEntry<'a> {
        format: &'static str,
        previous_chain_digest: &'a str,
        commit_sequence: u64,
        operation_id: &'a str,
        operation_version: u64,
        mutation_kind: &'a str,
        operation_digest: &'a str,
        recovery_claim_digest: Option<&'a str>,
        store_uuid: &'a str,
        store_lease_id: &'a str,
        store_owner_epoch: u64,
        recorded_at_unix_ms: u64,
    }

    #[test]
    fn equal_length_divergent_commit_history_is_rejected() {
        let fixture = fixture();
        let fence = fixture.authority.mutation_fence();
        let first = operation(&fence, "request-chain-a");
        let recorded_at = now_ms();
        fixture
            .authority
            .admission_operation_store()
            .begin(&first, &fence, recorded_at)
            .expect("begin first history");
        drop(fixture.authority);

        let alternate = operation(&fence, "request-chain-b");
        let encoded = canonical_json_bytes(&alternate.to_persisted()).expect("encode alternate");
        let operation_digest = sha256_hex(&encoded);
        let chain_digest = sha256_hex(
            &canonical_json_bytes(&TestChainEntry {
                format: "chio.admission-operation-commit-chain.v1",
                previous_chain_digest: GENESIS_CHAIN_DIGEST,
                commit_sequence: 1,
                operation_id: alternate.binding().operation_id().as_str(),
                operation_version: 1,
                mutation_kind: "begin",
                operation_digest: &operation_digest,
                recovery_claim_digest: None,
                store_uuid: &fence.store_uuid,
                store_lease_id: &fence.lease_id,
                store_owner_epoch: fence.owner_epoch,
                recorded_at_unix_ms: recorded_at,
            })
            .expect("encode chain"),
        );
        let replay = alternate.replay_key();
        let connection = Connection::open(&fixture.database).expect("tamper connection");
        connection
            .execute_batch(
                r#"
                PRAGMA foreign_keys = OFF;
                DROP TRIGGER admission_operations_immutable_identity;
                DROP TRIGGER admission_operations_versioned_body;
                DROP TRIGGER admission_operation_commits_immutable;
                "#,
            )
            .expect("drop history guards");
        connection
            .execute(
                r#"
                UPDATE admission_operations
                SET operation_id = ?1, request_namespace_digest = ?2,
                    request_id = ?3, operation_json = ?4
                WHERE operation_id = ?5
                "#,
                params![
                    alternate.binding().operation_id().as_str(),
                    replay.request_namespace_digest.as_str(),
                    replay.request_id.as_str(),
                    encoded,
                    first.binding().operation_id().as_str(),
                ],
            )
            .expect("replace operation history");
        connection
            .execute(
                r#"
                UPDATE admission_operation_commits
                SET operation_id = ?1, operation_digest = ?2, chain_digest = ?3
                WHERE commit_sequence = 1
                "#,
                params![
                    alternate.binding().operation_id().as_str(),
                    operation_digest,
                    chain_digest,
                ],
            )
            .expect("replace commit history");
        connection
            .execute(
                "UPDATE admission_operation_commit_meta SET head_chain_digest = ?1 WHERE singleton = 1",
                [chain_digest],
            )
            .expect("replace chain head");
        connection
            .execute_batch(include_str!("../admission_operation_store.sql"))
            .expect("restore history guards");
        crate::admission_operation_store::verify_admission_operation_invariants(&connection)
            .expect("alternate equal-length history is internally valid");
        drop(connection);

        assert!(matches!(
            SqliteAuthorityStore::open_serving(&fixture.database, &fixture.lock_root),
            Err(SqliteServingOwnerError::Invalid(_))
        ));
    }
}
