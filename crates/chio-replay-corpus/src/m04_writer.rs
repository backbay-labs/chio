//! Writer for graduating TEE captures into the M04 replay fixture shape.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use chio_core::canonical_json_bytes;
use chio_tee_frame::{Frame, Verdict};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{dedupe_last_wins, reredact_default};

/// M04 receipt-stream filename.
pub const RECEIPTS_FILENAME: &str = "receipts.ndjson";
/// M04 checkpoint filename.
pub const CHECKPOINT_FILENAME: &str = "checkpoint.json";
/// M04 Merkle-root filename.
pub const ROOT_FILENAME: &str = "root.hex";

const ROOT_LEN: usize = 32;
const ROOT_HEX_LEN: usize = ROOT_LEN * 2;
const TMP_SUFFIX: &str = ".tmp";
const CHECKPOINT_SCHEMA: &str = "chio.replay.m04.bless-checkpoint/v1";

/// Parsed `<family>/<name>` scenario identity from an M04 fixture directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M04Scenario {
    /// Scenario family directory.
    pub family: String,
    /// Scenario leaf directory.
    pub name: String,
}

impl M04Scenario {
    fn id(&self) -> String {
        format!("{}/{}", self.family, self.name)
    }
}

/// Per-file byte sizes from a successful fixture write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M04ByteSizes {
    /// Byte length of `receipts.ndjson`.
    pub receipts: u64,
    /// Byte length of `checkpoint.json`.
    pub checkpoint: u64,
    /// Byte length of `root.hex`.
    pub root: u64,
}

/// Summary returned after writing one M04 fixture directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M04FixtureSummary {
    /// Directory written.
    pub dir: PathBuf,
    /// Scenario identity inferred from the directory.
    pub scenario: M04Scenario,
    /// Frames observed before dedupe.
    pub frames_in: usize,
    /// Frames retained after canonical-invocation last-wins dedupe.
    pub frames_after_dedupe: usize,
    /// Number of receipt lines written.
    pub receipt_count: usize,
    /// Lowercase 64-character root written to `root.hex`.
    pub root_hex: String,
    /// Per-file byte sizes.
    pub byte_sizes: M04ByteSizes,
}

/// Errors emitted by the M04 fixture writer.
#[derive(Debug, Error)]
pub enum M04WriterError {
    /// Input capture did not contain any frames.
    #[error("cannot bless an empty capture")]
    EmptyCapture,
    /// Target path does not contain a `<family>/<name>` suffix.
    #[error("fixture directory must end in <family>/<name>: {0}")]
    InvalidScenarioDir(PathBuf),
    /// Target path contains a non-UTF-8 component.
    #[error("fixture directory component is not valid UTF-8: {0}")]
    NonUtf8Component(PathBuf),
    /// Existing target directory contains files outside the M04 shape.
    #[error("fixture directory contains non-M04 entry: {0}")]
    ExtraEntry(PathBuf),
    /// Existing target path is not a directory.
    #[error("fixture target exists but is not a directory: {0}")]
    TargetNotDirectory(PathBuf),
    /// Canonical JSON serialization failed.
    #[error("canonical JSON failed: {0}")]
    Canonical(#[from] chio_core::Error),
    /// Existing corpus normalization failed.
    #[error("replay corpus normalization failed: {0}")]
    Corpus(#[from] crate::ReplayCorpusError),
    /// Current default redactor failed closed.
    #[error("default redactor failed: {0}")]
    Redact(#[from] chio_tee::RedactError),
    /// Re-redacted invocation bytes were no longer valid JSON.
    #[error("redacted invocation for frame {event_id} is not JSON: {detail}")]
    RedactedInvocationJson { event_id: String, detail: String },
    /// Filesystem error while staging or committing fixture files.
    #[error("I/O error at {path}: {source}")]
    Io {
        /// Path being operated on.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
}

/// Parse and validate that `dir` has an M04 `<family>/<name>` suffix.
pub fn scenario_from_dir(dir: &Path) -> Result<M04Scenario, M04WriterError> {
    let mut normal_components = Vec::new();
    for component in dir.components() {
        match component {
            Component::Normal(value) => {
                let Some(text) = value.to_str() else {
                    return Err(M04WriterError::NonUtf8Component(dir.to_path_buf()));
                };
                normal_components.push(text.to_string());
            }
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {}
        }
    }

    if normal_components.len() < 2 {
        return Err(M04WriterError::InvalidScenarioDir(dir.to_path_buf()));
    }

    let name = normal_components
        .pop()
        .ok_or_else(|| M04WriterError::InvalidScenarioDir(dir.to_path_buf()))?;
    let family = normal_components
        .pop()
        .ok_or_else(|| M04WriterError::InvalidScenarioDir(dir.to_path_buf()))?;

    if !valid_segment(&family) || !valid_segment(&name) {
        return Err(M04WriterError::InvalidScenarioDir(dir.to_path_buf()));
    }

    Ok(M04Scenario { family, name })
}

/// Verify an existing target is either absent or already shaped like M04.
pub fn validate_m04_scenario_dir(dir: &Path) -> Result<M04Scenario, M04WriterError> {
    let scenario = scenario_from_dir(dir)?;
    ensure_existing_shape_allows_write(dir)?;
    Ok(scenario)
}

/// Write a capture into one M04-compatible fixture directory.
pub fn write_m04_fixture<I>(
    dir: impl AsRef<Path>,
    frames: I,
) -> Result<M04FixtureSummary, M04WriterError>
where
    I: IntoIterator<Item = Frame>,
{
    let dir = dir.as_ref();
    let scenario = validate_m04_scenario_dir(dir)?;
    let frames: Vec<Frame> = frames.into_iter().collect();
    if frames.is_empty() {
        return Err(M04WriterError::EmptyCapture);
    }
    let frames_in = frames.len();
    let retained = dedupe_last_wins(frames)?;
    if retained.is_empty() {
        return Err(M04WriterError::EmptyCapture);
    }

    let mut set = M04FixtureSet::new(dir, scenario.clone());
    let mut root_receipts = Vec::new();
    let mut redaction_pass_ids = BTreeSet::new();

    for retained_frame in &retained {
        let stripped = stripped_receipt(&retained_frame.frame)?;
        redaction_pass_ids.insert(stripped.redaction_pass_id);
        if !root_receipts.is_empty() {
            root_receipts.push(b'\n');
        }
        root_receipts.extend_from_slice(&stripped.canonical_receipt);
        set.append_canonical_receipt(stripped.canonical_receipt);
    }

    let checkpoint = json!({
        "schema": CHECKPOINT_SCHEMA,
        "source_schema": chio_tee_frame::FRAME_VERSION,
        "scenario": scenario.id(),
        "family": scenario.family,
        "name": scenario.name,
        "frames_in": frames_in,
        "frames_after_dedupe": retained.len(),
        "redaction_pass_ids": redaction_pass_ids.into_iter().collect::<Vec<_>>(),
    });
    let checkpoint_bytes = canonical_json_bytes(&checkpoint)?;
    let root = root_bytes(&root_receipts, &checkpoint_bytes);
    set.set_checkpoint(checkpoint_bytes);
    set.set_root(root);

    let committed = set.commit()?;
    verify_exact_m04_shape(&committed.dir)?;

    Ok(M04FixtureSummary {
        dir: committed.dir,
        scenario: committed.scenario,
        frames_in,
        frames_after_dedupe: retained.len(),
        receipt_count: committed.receipt_count,
        root_hex: committed.root_hex,
        byte_sizes: committed.byte_sizes,
    })
}

fn valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn ensure_existing_shape_allows_write(dir: &Path) -> Result<(), M04WriterError> {
    match fs::metadata(dir) {
        Ok(meta) if !meta.is_dir() => Err(M04WriterError::TargetNotDirectory(dir.to_path_buf())),
        Ok(_) => verify_exact_m04_shape_or_empty(dir),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(M04WriterError::Io {
            path: dir.to_path_buf(),
            source,
        }),
    }
}

fn verify_exact_m04_shape_or_empty(dir: &Path) -> Result<(), M04WriterError> {
    let mut entries = fs::read_dir(dir).map_err(|source| M04WriterError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    entries.try_for_each(|entry| {
        let entry = entry.map_err(|source| M04WriterError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| M04WriterError::Io {
            path: path.clone(),
            source,
        })?;
        if !file_type.is_file() || !is_m04_filename(&entry.file_name()) {
            return Err(M04WriterError::ExtraEntry(path));
        }
        Ok(())
    })
}

fn verify_exact_m04_shape(dir: &Path) -> Result<(), M04WriterError> {
    let mut seen = BTreeSet::new();
    let entries = fs::read_dir(dir).map_err(|source| M04WriterError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| M04WriterError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| M04WriterError::Io {
            path: path.clone(),
            source,
        })?;
        let name = entry.file_name();
        if !file_type.is_file() || !is_m04_filename(&name) {
            return Err(M04WriterError::ExtraEntry(path));
        }
        if let Some(name) = name.to_str() {
            seen.insert(name.to_string());
        }
    }
    let expected = BTreeSet::from([
        RECEIPTS_FILENAME.to_string(),
        CHECKPOINT_FILENAME.to_string(),
        ROOT_FILENAME.to_string(),
    ]);
    if seen == expected {
        Ok(())
    } else {
        Err(M04WriterError::InvalidScenarioDir(dir.to_path_buf()))
    }
}

fn is_m04_filename(name: &std::ffi::OsStr) -> bool {
    matches!(
        name.to_str(),
        Some(RECEIPTS_FILENAME | CHECKPOINT_FILENAME | ROOT_FILENAME)
    )
}

struct StrippedReceipt {
    canonical_receipt: Vec<u8>,
    redaction_pass_id: String,
}

fn stripped_receipt(frame: &Frame) -> Result<StrippedReceipt, M04WriterError> {
    let invocation_bytes = canonical_json_bytes(&frame.invocation)?;
    let redacted = reredact_default(&invocation_bytes)?;
    let invocation: Value = serde_json::from_slice(&redacted.bytes).map_err(|error| {
        M04WriterError::RedactedInvocationJson {
            event_id: frame.event_id.clone(),
            detail: error.to_string(),
        }
    })?;
    let receipt = json!({
        "invocation": invocation,
        "verdict": verdict_label(frame.verdict),
        "deny_reason": frame.deny_reason.clone(),
        "would_have_blocked": frame.would_have_blocked,
    });
    Ok(StrippedReceipt {
        canonical_receipt: canonical_json_bytes(&receipt)?,
        redaction_pass_id: redacted.pass_id,
    })
}

fn verdict_label(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
        Verdict::Rewrite => "rewrite",
    }
}

fn root_bytes(receipts_without_final_lf: &[u8], checkpoint: &[u8]) -> [u8; ROOT_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(receipts_without_final_lf);
    hasher.update(checkpoint);
    let digest = hasher.finalize();
    let mut root = [0u8; ROOT_LEN];
    root.copy_from_slice(&digest);
    root
}

struct M04FixtureSet {
    dir: PathBuf,
    scenario: M04Scenario,
    receipts: Vec<u8>,
    receipt_count: usize,
    checkpoint: Option<Vec<u8>>,
    root: Option<[u8; ROOT_LEN]>,
}

struct M04CommittedSet {
    dir: PathBuf,
    scenario: M04Scenario,
    receipt_count: usize,
    root_hex: String,
    byte_sizes: M04ByteSizes,
}

impl M04FixtureSet {
    fn new(dir: &Path, scenario: M04Scenario) -> Self {
        Self {
            dir: dir.to_path_buf(),
            scenario,
            receipts: Vec::new(),
            receipt_count: 0,
            checkpoint: None,
            root: None,
        }
    }

    fn append_canonical_receipt(&mut self, receipt: Vec<u8>) {
        self.receipts.extend_from_slice(&receipt);
        self.receipts.push(b'\n');
        self.receipt_count = self.receipt_count.saturating_add(1);
    }

    fn set_checkpoint(&mut self, checkpoint: Vec<u8>) {
        self.checkpoint = Some(checkpoint);
    }

    fn set_root(&mut self, root: [u8; ROOT_LEN]) {
        self.root = Some(root);
    }

    fn commit(self) -> Result<M04CommittedSet, M04WriterError> {
        let Some(checkpoint) = self.checkpoint else {
            return Err(M04WriterError::InvalidScenarioDir(self.dir));
        };
        let Some(root) = self.root else {
            return Err(M04WriterError::InvalidScenarioDir(self.dir));
        };
        if self.receipt_count == 0 {
            return Err(M04WriterError::EmptyCapture);
        }
        fs::create_dir_all(&self.dir).map_err(|source| M04WriterError::Io {
            path: self.dir.clone(),
            source,
        })?;

        let receipts_path = self.dir.join(RECEIPTS_FILENAME);
        let checkpoint_path = self.dir.join(CHECKPOINT_FILENAME);
        let root_path = self.dir.join(ROOT_FILENAME);
        let root_hex = hex::encode(root);
        if root_hex.len() != ROOT_HEX_LEN {
            return Err(M04WriterError::Io {
                path: root_path,
                source: io::Error::new(io::ErrorKind::InvalidData, "root hex length drifted"),
            });
        }

        let staged = [
            (receipts_path, self.receipts),
            (checkpoint_path, checkpoint),
            (root_path, root_hex.as_bytes().to_vec()),
        ];

        let mut tmp_paths = Vec::new();
        for (path, bytes) in &staged {
            let tmp = staging_path(path);
            stage_file(&tmp, bytes)?;
            tmp_paths.push(tmp);
        }

        for ((path, _), tmp) in staged.iter().zip(tmp_paths.iter()) {
            if let Err(err) = fs::rename(tmp, path) {
                cleanup_tmp(&tmp_paths);
                return Err(M04WriterError::Io {
                    path: path.clone(),
                    source: err,
                });
            }
        }

        Ok(M04CommittedSet {
            dir: self.dir.clone(),
            scenario: self.scenario,
            receipt_count: self.receipt_count,
            root_hex,
            byte_sizes: M04ByteSizes {
                receipts: file_size(&self.dir.join(RECEIPTS_FILENAME))?,
                checkpoint: file_size(&self.dir.join(CHECKPOINT_FILENAME))?,
                root: file_size(&self.dir.join(ROOT_FILENAME))?,
            },
        })
    }
}

fn staging_path(path: &Path) -> PathBuf {
    let mut staging = path.as_os_str().to_owned();
    staging.push(TMP_SUFFIX);
    PathBuf::from(staging)
}

fn stage_file(path: &Path, bytes: &[u8]) -> Result<(), M04WriterError> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|source| M04WriterError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(bytes).map_err(|source| M04WriterError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| M04WriterError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn cleanup_tmp(paths: &[PathBuf]) {
    for path in paths {
        let _ = fs::remove_file(path);
    }
}

fn file_size(path: &Path) -> Result<u64, M04WriterError> {
    fs::metadata(path)
        .map(|meta| meta.len())
        .map_err(|source| M04WriterError::Io {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_tee_frame::{FrameInputs, Otel, Provenance, Upstream, UpstreamSystem};
    use serde_json::json;

    fn frame(event_id: &str, invocation: Value, verdict: Verdict) -> Frame {
        Frame::build(FrameInputs {
            event_id: event_id.to_string(),
            ts: "2026-04-25T18:02:11.418Z".to_string(),
            tee_id: "tee-test-1".to_string(),
            upstream: Upstream {
                system: UpstreamSystem::Openai,
                operation: "responses.create".to_string(),
                api_version: "2025-10-01".to_string(),
            },
            invocation,
            provenance: Provenance {
                otel: Otel {
                    trace_id: "0".repeat(32),
                    span_id: "0".repeat(16),
                },
                supply_chain: None,
            },
            request_blob_sha256: "a".repeat(64),
            response_blob_sha256: "b".repeat(64),
            redaction_pass_id: "m06-redactors@1.4.0+default".to_string(),
            verdict,
            deny_reason: match verdict {
                Verdict::Allow => None,
                Verdict::Deny | Verdict::Rewrite => Some("guard:pii.email".to_string()),
            },
            would_have_blocked: !matches!(verdict, Verdict::Allow),
            tenant_sig: format!("ed25519:{}", "A".repeat(86)),
        })
        .unwrap()
    }

    #[test]
    fn writes_m04_shape_and_strips_capture_only_fields() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp
            .path()
            .join("openai_responses_shadow")
            .join("tool_call_with_pii");
        let frames = vec![
            frame(
                "01H7ZZZZZZZZZZZZZZZZZZZZZA",
                json!({"tool":"send","email":"alice@example.com"}),
                Verdict::Allow,
            ),
            frame(
                "01H7ZZZZZZZZZZZZZZZZZZZZZB",
                json!({"email":"alice@example.com","tool":"send"}),
                Verdict::Deny,
            ),
        ];

        let summary = write_m04_fixture(&dir, frames).unwrap();

        assert_eq!(summary.frames_in, 2);
        assert_eq!(summary.frames_after_dedupe, 1);
        assert_eq!(summary.receipt_count, 1);
        assert_eq!(summary.byte_sizes.root, 64);
        assert_eq!(summary.root_hex.len(), 64);
        assert!(dir.join(RECEIPTS_FILENAME).is_file());
        assert!(dir.join(CHECKPOINT_FILENAME).is_file());
        assert!(dir.join(ROOT_FILENAME).is_file());

        let receipts = fs::read_to_string(dir.join(RECEIPTS_FILENAME)).unwrap();
        assert!(receipts.ends_with('\n'));
        assert!(!receipts.contains("tenant_sig"));
        assert!(!receipts.contains("request_blob"));
        assert!(!receipts.contains("response_blob"));
        assert!(!receipts.contains("alice@example.com"));
        assert!(receipts.contains("[REDACTED-EMAIL]"));
        assert!(receipts.contains("\"verdict\":\"deny\""));

        let checkpoint = fs::read_to_string(dir.join(CHECKPOINT_FILENAME)).unwrap();
        assert!(checkpoint.starts_with("{\"family\""));
        assert!(checkpoint.contains("\"scenario\":\"openai_responses_shadow/tool_call_with_pii\""));
    }

    #[test]
    fn refuses_existing_non_m04_directory_shape() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("family").join("name");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("extra.txt"), b"no").unwrap();

        let err = validate_m04_scenario_dir(&dir).unwrap_err();
        assert!(matches!(err, M04WriterError::ExtraEntry(_)));
    }

    #[test]
    fn root_matches_receipts_without_final_lf_plus_checkpoint() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("family").join("name");
        let summary = write_m04_fixture(
            &dir,
            vec![frame(
                "01H7ZZZZZZZZZZZZZZZZZZZZZC",
                json!({"tool":"noop"}),
                Verdict::Allow,
            )],
        )
        .unwrap();

        let receipts = fs::read(dir.join(RECEIPTS_FILENAME)).unwrap();
        let checkpoint = fs::read(dir.join(CHECKPOINT_FILENAME)).unwrap();
        let receipts_without_lf = &receipts[..receipts.len() - 1];
        let root = root_bytes(receipts_without_lf, &checkpoint);
        assert_eq!(hex::encode(root), summary.root_hex);
    }
}
