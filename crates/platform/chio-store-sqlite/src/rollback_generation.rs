use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use chio_core::canonical::canonical_json_bytes;
use chio_core::sha256_hex;
use serde::{Deserialize, Serialize};

const SLOT_SIZE: usize = 512;
const SLOT_COUNT: usize = 2;
const FILE_SIZE: usize = SLOT_SIZE * SLOT_COUNT;
const COMMIT_MARKER: &[u8; 8] = b"CHIOG1OK";
const LENGTH_OFFSET: usize = COMMIT_MARKER.len();
const CHECKSUM_OFFSET: usize = LENGTH_OFFSET + 4;
const PAYLOAD_OFFSET: usize = CHECKSUM_OFFSET + 64;
const MAX_PAYLOAD_BYTES: usize = SLOT_SIZE - PAYLOAD_OFFSET;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GenerationRecord {
    anchor_instance_id: String,
    format: String,
    record_generation: u64,
    scope_sha256: String,
    store_generation: u64,
}

struct LoadedRecord {
    record: GenerationRecord,
    corrupt_slot: bool,
    interrupted_slot: bool,
}

static PROCESS_ANCHOR_LOCKS: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Mutex<()>>>>> = OnceLock::new();

pub(crate) struct RollbackGenerationAnchor {
    file: File,
    root: PathBuf,
    path: PathBuf,
    expected_device: u64,
    expected_inode: u64,
    scope_sha256: String,
    process_lock: Arc<Mutex<()>>,
}

impl RollbackGenerationAnchor {
    pub(crate) fn open(root: &Path, scope: &[u8]) -> Result<Self, String> {
        validate_secure_root(root)?;
        let root = fs::canonicalize(root)
            .map_err(|error| format!("rollback anchor root is unavailable: {error}"))?;
        let scope_sha256 = sha256_hex(scope);
        let path = root.join(format!("{scope_sha256}.generation-anchor"));
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options
            .open(&path)
            .map_err(|error| format!("rollback anchor open failed: {error}"))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("rollback anchor metadata failed: {error}"))?;
        validate_anchor_metadata(&metadata)?;
        let expected_device = metadata_device(&metadata)?;
        let expected_inode = metadata_inode(&metadata)?;
        let process_lock = process_anchor_lock(&path)?;
        let anchor = Self {
            file,
            root,
            path,
            expected_device,
            expected_inode,
            scope_sha256,
            process_lock,
        };
        anchor.validate_identity()?;
        Ok(anchor)
    }

    pub(crate) fn bind_initial_while(
        &self,
        load: impl FnOnce() -> Result<(u64, bool), String>,
    ) -> Result<(), String> {
        self.with_lock(|| {
            let (store_generation, allow_seed) = load()?;
            match self.load_record()? {
                Some(loaded) => {
                    if loaded.corrupt_slot {
                        return Err("rollback anchor contains a corrupt slot".to_string());
                    }
                    self.validate_record(&loaded.record)?;
                    if loaded.interrupted_slot && loaded.record.store_generation != store_generation
                    {
                        return Err(
                            "interrupted rollback anchor does not match the store generation"
                                .to_string(),
                        );
                    }
                    if loaded.record.store_generation != store_generation {
                        return Err("store is behind its protected rollback generation".to_string());
                    }
                    Ok(())
                }
                None if allow_seed && store_generation == 0 => {
                    self.write_next(0, 0, &uuid::Uuid::now_v7().to_string())
                }
                None => Err("protected rollback generation is absent".to_string()),
            }
        })
    }

    pub(crate) fn instance_id(&self) -> Result<String, String> {
        self.with_lock(|| {
            let loaded = self
                .load_record()?
                .ok_or_else(|| "protected rollback generation is absent".to_string())?;
            if loaded.corrupt_slot {
                return Err("rollback anchor contains a corrupt slot".to_string());
            }
            self.validate_record(&loaded.record)?;
            Ok(loaded.record.anchor_instance_id)
        })
    }

    pub(crate) fn verify(&self, store_generation: u64) -> Result<(), String> {
        self.verify_while(|| Ok(store_generation))
    }

    pub(crate) fn verify_while(
        &self,
        load: impl FnOnce() -> Result<u64, String>,
    ) -> Result<(), String> {
        self.with_lock(|| {
            let store_generation = load()?;
            let loaded = self
                .load_record()?
                .ok_or_else(|| "protected rollback generation is absent".to_string())?;
            if loaded.corrupt_slot {
                return Err("rollback anchor contains a corrupt slot".to_string());
            }
            self.validate_record(&loaded.record)?;
            if loaded.interrupted_slot && loaded.record.store_generation != store_generation {
                return Err(
                    "interrupted rollback anchor does not match the store generation".to_string(),
                );
            }
            if loaded.record.store_generation != store_generation {
                return Err("store does not match its protected rollback generation".to_string());
            }
            Ok(())
        })
    }

    pub(crate) fn advance_while(
        &self,
        expected: u64,
        next: u64,
        operation: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        if expected.checked_add(1) != Some(next) {
            return Err("rollback generation must advance by exactly one".to_string());
        }
        self.with_lock(|| {
            let loaded = self
                .load_record()?
                .ok_or_else(|| "protected rollback generation is absent".to_string())?;
            if loaded.corrupt_slot {
                return Err("rollback anchor contains a corrupt slot".to_string());
            }
            self.validate_record(&loaded.record)?;
            if loaded.record.store_generation != expected {
                return Err("rollback generation compare-and-advance failed".to_string());
            }
            self.write_next(
                loaded.record.record_generation,
                next,
                &loaded.record.anchor_instance_id,
            )?;
            operation()
        })
    }

    fn with_lock<T>(&self, operation: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        let _process_guard = self
            .process_lock
            .lock()
            .map_err(|_| "rollback anchor process lock is poisoned".to_string())?;
        self.validate_identity()?;
        self.file
            .lock()
            .map_err(|error| format!("rollback anchor lock failed: {error}"))?;
        let result = operation();
        let unlock = self
            .file
            .unlock()
            .map_err(|error| format!("rollback anchor unlock failed: {error}"));
        match (result, unlock) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    fn write_next(
        &self,
        current_record_generation: u64,
        store_generation: u64,
        anchor_instance_id: &str,
    ) -> Result<(), String> {
        let record_generation = current_record_generation
            .checked_add(1)
            .ok_or_else(|| "rollback anchor record generation overflowed".to_string())?;
        let record = GenerationRecord {
            anchor_instance_id: anchor_instance_id.to_owned(),
            format: "chio.sqlite-rollback-generation.v1".to_string(),
            record_generation,
            scope_sha256: self.scope_sha256.clone(),
            store_generation,
        };
        self.validate_record(&record)?;
        let payload = canonical_json_bytes(&record)
            .map_err(|error| format!("rollback anchor encoding failed: {error}"))?;
        if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
            return Err("rollback anchor record exceeds its fixed slot".to_string());
        }
        self.ensure_shape()?;
        let slot_index = usize::try_from((record_generation - 1) % 2)
            .map_err(|_| "rollback anchor slot overflowed".to_string())?;
        let offset = slot_index * SLOT_SIZE;

        write_all_at(&self.file, &[0_u8; COMMIT_MARKER.len()], offset)
            .map_err(|error| format!("rollback anchor marker clear failed: {error}"))?;
        self.file
            .sync_data()
            .map_err(|error| format!("rollback anchor marker sync failed: {error}"))?;

        let mut slot = [0_u8; SLOT_SIZE];
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| "rollback anchor payload length overflowed".to_string())?;
        slot[LENGTH_OFFSET..CHECKSUM_OFFSET].copy_from_slice(&payload_len.to_be_bytes());
        slot[CHECKSUM_OFFSET..PAYLOAD_OFFSET].copy_from_slice(sha256_hex(&payload).as_bytes());
        slot[PAYLOAD_OFFSET..PAYLOAD_OFFSET + payload.len()].copy_from_slice(&payload);
        write_all_at(&self.file, &slot, offset)
            .map_err(|error| format!("rollback anchor slot write failed: {error}"))?;
        self.file
            .sync_data()
            .map_err(|error| format!("rollback anchor slot sync failed: {error}"))?;
        write_all_at(&self.file, COMMIT_MARKER, offset)
            .map_err(|error| format!("rollback anchor commit failed: {error}"))?;
        self.file
            .sync_all()
            .map_err(|error| format!("rollback anchor commit sync failed: {error}"))?;
        self.validate_identity()?;

        let persisted = self
            .load_record()?
            .ok_or_else(|| "rollback anchor write was not durable".to_string())?;
        if persisted.corrupt_slot || persisted.interrupted_slot || persisted.record != record {
            return Err("rollback anchor write did not round trip".to_string());
        }
        Ok(())
    }

    fn load_record(&self) -> Result<Option<LoadedRecord>, String> {
        self.ensure_shape()?;
        let mut records = Vec::with_capacity(SLOT_COUNT);
        let mut corrupt_slot = false;
        let mut interrupted_slot = false;
        for slot_index in 0..SLOT_COUNT {
            let mut slot = [0_u8; SLOT_SIZE];
            read_exact_at(&self.file, &mut slot, slot_index * SLOT_SIZE)
                .map_err(|error| format!("rollback anchor read failed: {error}"))?;
            let marker = &slot[..COMMIT_MARKER.len()];
            if marker.iter().all(|byte| *byte == 0) {
                if slot[COMMIT_MARKER.len()..].iter().any(|byte| *byte != 0) {
                    interrupted_slot = true;
                }
                continue;
            }
            if marker != COMMIT_MARKER {
                corrupt_slot = true;
                continue;
            }
            match self.decode_slot(&slot) {
                Ok(record) => records.push(record),
                Err(_) => corrupt_slot = true,
            }
        }
        records.sort_by_key(|record| record.record_generation);
        if records.len() == 2 {
            let prior = &records[0];
            let current = &records[1];
            if prior.record_generation.checked_add(1) != Some(current.record_generation)
                || current.scope_sha256 != prior.scope_sha256
                || current.anchor_instance_id != prior.anchor_instance_id
                || current.store_generation < prior.store_generation
            {
                return Err("rollback anchor slots do not form one monotonic history".to_string());
            }
        }
        let Some(record) = records.pop() else {
            if corrupt_slot || interrupted_slot {
                return Err("rollback anchor has no committed slot".to_string());
            }
            return Ok(None);
        };
        Ok(Some(LoadedRecord {
            record,
            corrupt_slot,
            interrupted_slot,
        }))
    }

    fn decode_slot(&self, slot: &[u8; SLOT_SIZE]) -> Result<GenerationRecord, String> {
        let payload_len = u32::from_be_bytes(
            slot[LENGTH_OFFSET..CHECKSUM_OFFSET]
                .try_into()
                .map_err(|_| "rollback anchor length is corrupt".to_string())?,
        );
        let payload_len = usize::try_from(payload_len)
            .map_err(|_| "rollback anchor length overflowed".to_string())?;
        if payload_len == 0 || payload_len > MAX_PAYLOAD_BYTES {
            return Err("rollback anchor length is invalid".to_string());
        }
        let payload_end = PAYLOAD_OFFSET + payload_len;
        if slot[payload_end..].iter().any(|byte| *byte != 0) {
            return Err("rollback anchor padding is corrupt".to_string());
        }
        let payload = &slot[PAYLOAD_OFFSET..payload_end];
        if slot[CHECKSUM_OFFSET..PAYLOAD_OFFSET] != sha256_hex(payload).as_bytes()[..] {
            return Err("rollback anchor checksum is invalid".to_string());
        }
        let record: GenerationRecord = serde_json::from_slice(payload)
            .map_err(|error| format!("rollback anchor is invalid JSON: {error}"))?;
        if canonical_json_bytes(&record)
            .map_err(|error| format!("rollback anchor encoding failed: {error}"))?
            != payload
        {
            return Err("rollback anchor is not canonical JSON".to_string());
        }
        self.validate_record(&record)?;
        Ok(record)
    }

    fn validate_record(&self, record: &GenerationRecord) -> Result<(), String> {
        let anchor_instance_id = uuid::Uuid::parse_str(&record.anchor_instance_id)
            .map_err(|_| "rollback anchor instance id is invalid".to_string())?;
        if record.format != "chio.sqlite-rollback-generation.v1"
            || record.record_generation == 0
            || record.scope_sha256 != self.scope_sha256
            || anchor_instance_id.to_string() != record.anchor_instance_id
        {
            return Err("rollback anchor record is invalid".to_string());
        }
        Ok(())
    }

    fn ensure_shape(&self) -> Result<(), String> {
        let length = self
            .file
            .metadata()
            .map_err(|error| format!("rollback anchor metadata failed: {error}"))?
            .len();
        let expected =
            u64::try_from(FILE_SIZE).map_err(|_| "rollback anchor size overflowed".to_string())?;
        if length == 0 {
            self.file
                .set_len(expected)
                .map_err(|error| format!("rollback anchor sizing failed: {error}"))?;
            self.file
                .sync_all()
                .map_err(|error| format!("rollback anchor sizing sync failed: {error}"))?;
        } else if length != expected {
            return Err("rollback anchor has an invalid size".to_string());
        }
        Ok(())
    }

    fn validate_identity(&self) -> Result<(), String> {
        validate_secure_root(&self.root)?;
        let path_metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| format!("rollback anchor path metadata failed: {error}"))?;
        let file_metadata = self
            .file
            .metadata()
            .map_err(|error| format!("rollback anchor file metadata failed: {error}"))?;
        for metadata in [&path_metadata, &file_metadata] {
            validate_anchor_metadata(metadata)?;
            if metadata_device(metadata)? != self.expected_device
                || metadata_inode(metadata)? != self.expected_inode
            {
                return Err("rollback anchor inode changed".to_string());
            }
        }
        Ok(())
    }
}

fn process_anchor_lock(path: &Path) -> Result<Arc<Mutex<()>>, String> {
    let locks = PROCESS_ANCHOR_LOCKS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut locks = locks
        .lock()
        .map_err(|_| "rollback anchor lock registry is poisoned".to_string())?;
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(path).and_then(Weak::upgrade) {
        return Ok(lock);
    }
    let lock = Arc::new(Mutex::new(()));
    locks.insert(path.to_path_buf(), Arc::downgrade(&lock));
    Ok(lock)
}

#[cfg(unix)]
fn validate_secure_root(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("rollback anchor root metadata failed: {error}"))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err("rollback anchor root has unsafe ownership or permissions".to_string());
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_secure_root(_path: &Path) -> Result<(), String> {
    Err("rollback generation anchors require Unix file identity".to_string())
}

#[cfg(unix)]
fn validate_anchor_metadata(metadata: &fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
    {
        return Err("rollback anchor file has unsafe ownership or permissions".to_string());
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_anchor_metadata(_metadata: &fs::Metadata) -> Result<(), String> {
    Err("rollback generation anchors require Unix file identity".to_string())
}

#[cfg(unix)]
fn metadata_device(metadata: &fs::Metadata) -> Result<u64, String> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(metadata.dev())
}

#[cfg(not(unix))]
fn metadata_device(_metadata: &fs::Metadata) -> Result<u64, String> {
    Err("rollback generation anchors require Unix file identity".to_string())
}

#[cfg(unix)]
fn metadata_inode(metadata: &fs::Metadata) -> Result<u64, String> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(metadata.ino())
}

#[cfg(not(unix))]
fn metadata_inode(_metadata: &fs::Metadata) -> Result<u64, String> {
    Err("rollback generation anchors require Unix file identity".to_string())
}

#[cfg(unix)]
fn read_exact_at(file: &File, mut bytes: &mut [u8], mut offset: usize) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt as _;

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
        "rollback generation anchors require Unix positioned I/O",
    ))
}

#[cfg(unix)]
fn write_all_at(file: &File, mut bytes: &[u8], mut offset: usize) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt as _;

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
        "rollback generation anchors require Unix positioned I/O",
    ))
}

fn io_offset(offset: usize) -> std::io::Result<u64> {
    u64::try_from(offset).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "rollback anchor offset overflowed",
        )
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn secure_root(path: &Path) {
        assert!(fs::set_permissions(path, fs::Permissions::from_mode(0o700)).is_ok());
    }

    #[test]
    fn independent_anchors_receive_distinct_global_instance_ids() {
        let Ok(first_root) = tempfile::tempdir() else {
            panic!("create first anchor root");
        };
        let Ok(second_root) = tempfile::tempdir() else {
            panic!("create second anchor root");
        };
        secure_root(first_root.path());
        secure_root(second_root.path());
        let first = match RollbackGenerationAnchor::open(first_root.path(), b"shared-scope") {
            Ok(anchor) => anchor,
            Err(error) => panic!("open first anchor: {error}"),
        };
        let second = match RollbackGenerationAnchor::open(second_root.path(), b"shared-scope") {
            Ok(anchor) => anchor,
            Err(error) => panic!("open second anchor: {error}"),
        };
        assert!(first.bind_initial_while(|| Ok((0, true))).is_ok());
        assert!(second.bind_initial_while(|| Ok((0, true))).is_ok());
        let Ok(first_id) = first.instance_id() else {
            panic!("load first anchor id");
        };
        let Ok(second_id) = second.instance_id() else {
            panic!("load second anchor id");
        };
        assert_ne!(first_id, second_id);
    }

    #[test]
    fn marker_cleared_inactive_slot_recovers_from_surviving_generation() {
        let Ok(root) = tempfile::tempdir() else {
            panic!("create anchor root");
        };
        secure_root(root.path());
        let anchor = match RollbackGenerationAnchor::open(root.path(), b"interrupted-rewrite") {
            Ok(anchor) => anchor,
            Err(error) => panic!("open anchor: {error}"),
        };
        assert!(anchor.bind_initial_while(|| Ok((0, true))).is_ok());
        let mut store_generation = 0;
        assert!(anchor
            .advance_while(0, 1, || {
                store_generation = 1;
                Ok(())
            })
            .is_ok());

        assert!(write_all_at(&anchor.file, &[0_u8; COMMIT_MARKER.len()], 0).is_ok());
        assert!(anchor.file.sync_data().is_ok());
        assert!(anchor.verify(store_generation).is_ok());
        assert!(anchor
            .advance_while(1, 2, || {
                store_generation = 2;
                Ok(())
            })
            .is_ok());
        assert!(anchor.verify(store_generation).is_ok());
    }
}
