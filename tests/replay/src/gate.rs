//! CLI-facing replay-gate validation and bless plumbing.
//!
//! This module intentionally stays scoped to the `tests/replay` corpus. It
//! validates the checked-in goldens by regenerating candidate bytes from the
//! paired fixture manifests, then comparing raw artifact bytes through
//! [`crate::byte_compare`]. It does not claim parity with the production
//! `chio replay` receipt-log command.

use std::fs;
use std::path::Component;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::bless::{
    append_audit_line, evaluate_gate_real, BlessGateError, SystemFs, AUDIT_LOG_RELATIVE_PATH,
};
use crate::byte_compare::{compare_artifacts, ArtifactKind, ByteDiff};
use crate::driver::ScenarioDriver;
use crate::fs_iter::{self, FsIterError};
use crate::golden_format::{self, CHECKPOINT_FILENAME, RECEIPTS_FILENAME, ROOT_FILENAME};
use crate::golden_reader::{GoldenLoaded, GoldenReaderError};
use crate::golden_writer::{GoldenSet, GoldenWriterError};

/// JSON schema identifier emitted by `--json`.
pub const REPORT_SCHEMA: &str = "chio.replay.report/v1";

/// Exit code for a clean replay-gate run.
pub const EXIT_CLEAN: i32 = 0;

/// Exit code for byte or root drift.
pub const EXIT_DRIFT: i32 = 10;

/// Exit code for parse / fixture-shape errors.
pub const EXIT_PARSE: i32 = 30;

/// Exit code for ordinary CLI / bless-gate errors.
pub const EXIT_CLI_ERROR: i32 = 1;

/// A single replay-gate divergence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Divergence {
    /// Fixture label, usually `<family>/<name>`.
    pub fixture: String,
    /// Divergence kind, e.g. `receipts`, `checkpoint`, `root_hex`.
    pub kind: String,
    /// Human-readable detail.
    pub detail: String,
}

/// Structured report returned by validation and bless paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayReport {
    /// Whether the run was accepted.
    pub accepted: bool,
    /// Number of fixtures checked or written.
    pub checked_fixtures: usize,
    /// Deterministic aggregate root over checked fixture roots.
    pub computed_root: String,
    /// Optional expected root passed on the CLI.
    pub expected_root: Option<String>,
    /// Divergences found during validation.
    pub divergences: Vec<Divergence>,
}

impl ReplayReport {
    /// Exit code implied by this report.
    pub fn exit_code(&self) -> i32 {
        if self.divergences.is_empty() {
            EXIT_CLEAN
        } else {
            EXIT_DRIFT
        }
    }

    /// Render the report as JSON.
    pub fn to_json_value(&self) -> Value {
        let divergences: Vec<Value> = self
            .divergences
            .iter()
            .map(|divergence| {
                json!({
                    "fixture": divergence.fixture,
                    "kind": divergence.kind,
                    "detail": divergence.detail,
                })
            })
            .collect();

        json!({
            "schema": REPORT_SCHEMA,
            "accepted": self.accepted,
            "checkedFixtures": self.checked_fixtures,
            "computedRoot": self.computed_root,
            "expectedRoot": self.expected_root,
            "divergences": divergences,
        })
    }

    /// Render a terse human-readable summary.
    pub fn to_text(&self) -> String {
        if self.accepted {
            format!(
                "accepted: checked {} fixture(s), computed root {}",
                self.checked_fixtures, self.computed_root
            )
        } else {
            let mut lines = vec![format!(
                "rejected: {} divergence(s) across {} fixture(s)",
                self.divergences.len(),
                self.checked_fixtures
            )];
            for divergence in &self.divergences {
                lines.push(format!(
                    "{} {}: {}",
                    divergence.fixture, divergence.kind, divergence.detail
                ));
            }
            lines.join("\n")
        }
    }
}

/// Errors emitted by the replay-gate CLI layer.
#[derive(Debug, Error)]
pub enum ReplayGateError {
    /// Input shape was invalid or unsupported.
    #[error("{0}")]
    InvalidInput(String),

    /// Filesystem enumeration failed.
    #[error("{0}")]
    FsIter(#[from] FsIterError),

    /// A goldens directory failed load-time validation.
    #[error("{0}")]
    GoldenReader(#[from] GoldenReaderError),

    /// A golden write failed during `--bless`.
    #[error("{0}")]
    GoldenWriter(#[from] GoldenWriterError),

    /// JSON read or parse failure.
    #[error("{0}")]
    Json(String),

    /// The CHIO_BLESS gate refused the operation.
    #[error("{0}")]
    Bless(#[from] BlessGateError),
}

impl ReplayGateError {
    /// Exit code for this error class.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::GoldenReader(_) | Self::Json(_) => EXIT_PARSE,
            Self::InvalidInput(_) | Self::FsIter(_) | Self::GoldenWriter(_) | Self::Bless(_) => {
                EXIT_CLI_ERROR
            }
        }
    }
}

#[derive(Debug, Clone)]
struct CandidateArtifacts {
    receipt: Value,
    checkpoint_value: Value,
    receipts: Vec<u8>,
    checkpoint_bytes: Vec<u8>,
    root_hex: String,
    root: [u8; 32],
}

#[derive(Debug, Clone)]
struct FixtureManifest {
    path: PathBuf,
    family: String,
    scenario_name: String,
    scenario_leaf: String,
    value: Value,
}

impl FixtureManifest {
    fn label(&self) -> String {
        format!("{}/{}", self.family, self.scenario_leaf)
    }
}

struct PreparedGoldenWrite {
    label: String,
    root_hex: String,
    set: GoldenSet,
}

/// Validate a goldens root or single scenario directory.
pub fn validate_goldens(
    input: &Path,
    expect_root: Option<&str>,
) -> Result<ReplayReport, ReplayGateError> {
    let input = normalize_existing_path(input)?;
    let scenario_dirs = discover_golden_dirs(&input)?;
    if scenario_dirs.is_empty() {
        return Err(ReplayGateError::InvalidInput(format!(
            "no replay goldens found under {}",
            input.display()
        )));
    }

    let mut divergences = Vec::new();
    let mut roots = Vec::new();

    for scenario_dir in &scenario_dirs {
        let identity = identity_from_golden_dir(&input, scenario_dir)?;
        let expected = GoldenLoaded::load(scenario_dir)?;
        let manifest_path = manifest_path_for_identity(&identity);
        let manifest = load_manifest(&manifest_path)?;
        let candidate = synthesize_candidate(&manifest)?;
        let scenario_diffs = compare_artifacts(
            &expected,
            &candidate.receipts,
            &candidate.checkpoint_bytes,
            &candidate.root_hex,
        );
        for diff in scenario_diffs {
            divergences.push(render_byte_diff(&identity.label(), diff));
        }
        roots.push((identity.label(), candidate.root_hex));
    }

    let computed_root = report_root(&roots);
    if let Some(expected_root) = expect_root {
        validate_root_hex(expected_root)?;
        if expected_root != computed_root {
            divergences.push(Divergence {
                fixture: "aggregate".to_string(),
                kind: "merkle_mismatch".to_string(),
                detail: format!("expected {expected_root}, computed {computed_root}"),
            });
        }
    }

    Ok(ReplayReport {
        accepted: divergences.is_empty(),
        checked_fixtures: scenario_dirs.len(),
        computed_root,
        expected_root: expect_root.map(str::to_string),
        divergences,
    })
}

/// Bless one fixture manifest or all fixture manifests under a directory.
pub fn bless(input: Option<&Path>) -> Result<ReplayReport, ReplayGateError> {
    let workspace = workspace_root();
    let target = match input {
        Some(path) => normalize_existing_path(path)?,
        None => workspace.join("tests/replay/fixtures"),
    };

    let writes = plan_bless_writes(&workspace, &target)?;
    let roots: Vec<(String, String)> = writes
        .iter()
        .map(|write| (write.label.clone(), write.root_hex.clone()))
        .collect();

    let ctx = evaluate_gate_real(target.clone(), Utc::now())?;
    append_audit_line(&SystemFs, &workspace.join(AUDIT_LOG_RELATIVE_PATH), &ctx)?;

    for write in writes {
        commit_prepared_write(write.set)?;
    }

    let checked_fixtures = roots.len();
    let computed_root = report_root(&roots);
    Ok(ReplayReport {
        accepted: true,
        checked_fixtures,
        computed_root,
        expected_root: None,
        divergences: Vec::new(),
    })
}

fn plan_bless_writes(
    workspace: &Path,
    target: &Path,
) -> Result<Vec<PreparedGoldenWrite>, ReplayGateError> {
    let manifests = discover_fixture_manifests(target)?;
    if manifests.is_empty() {
        return Err(ReplayGateError::InvalidInput(format!(
            "no replay fixture manifests found under {}",
            target.display()
        )));
    }

    let goldens_root = workspace.join("tests/replay/goldens");
    let mut writes = Vec::new();
    for manifest_path in &manifests {
        let manifest = load_manifest(manifest_path)?;
        let candidate = synthesize_candidate(&manifest)?;
        let scenario_dir = scenario_dir_for_manifest(&goldens_root, &manifest)?;
        let set = prepare_golden_set(&candidate, &scenario_dir)?;
        writes.push(PreparedGoldenWrite {
            label: manifest.label(),
            root_hex: candidate.root_hex,
            set,
        });
    }
    Ok(writes)
}

fn normalize_existing_path(path: &Path) -> Result<PathBuf, ReplayGateError> {
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| {
                ReplayGateError::InvalidInput(format!("failed to read current directory: {source}"))
            })?
            .join(path)
    };
    if !candidate.exists() {
        return Err(ReplayGateError::InvalidInput(format!(
            "input path does not exist: {}",
            candidate.display()
        )));
    }
    Ok(candidate)
}

fn discover_golden_dirs(input: &Path) -> Result<Vec<PathBuf>, ReplayGateError> {
    if is_golden_dir(input) {
        return Ok(vec![input.to_path_buf()]);
    }
    if !input.is_dir() {
        return Err(ReplayGateError::InvalidInput(format!(
            "expected a replay goldens directory, got {}",
            input.display()
        )));
    }

    let root_files = fs_iter::walk_files_sorted(input, |path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .map(|name| name == ROOT_FILENAME)
            .unwrap_or(false)
    })?;
    let mut dirs = Vec::new();
    for root_file in root_files {
        let dir = root_file.parent().ok_or_else(|| {
            ReplayGateError::InvalidInput(format!(
                "root file has no parent directory: {}",
                root_file.display()
            ))
        })?;
        if is_golden_dir(dir) {
            dirs.push(dir.to_path_buf());
        }
    }
    Ok(dirs)
}

fn is_golden_dir(path: &Path) -> bool {
    path.join(RECEIPTS_FILENAME).is_file()
        && path.join(CHECKPOINT_FILENAME).is_file()
        && path.join(ROOT_FILENAME).is_file()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScenarioIdentity {
    family: String,
    leaf: String,
}

impl ScenarioIdentity {
    fn label(&self) -> String {
        format!("{}/{}", self.family, self.leaf)
    }
}

fn identity_from_golden_dir(
    input_root: &Path,
    scenario_dir: &Path,
) -> Result<ScenarioIdentity, ReplayGateError> {
    if let Ok(relative) = scenario_dir.strip_prefix(input_root) {
        let parts: Vec<String> = relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy().into_owned())
            .collect();
        if parts.len() == 2 {
            return Ok(ScenarioIdentity {
                family: parts[0].clone(),
                leaf: parts[1].clone(),
            });
        }
    }

    let leaf = scenario_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            ReplayGateError::InvalidInput(format!(
                "could not determine scenario name from {}",
                scenario_dir.display()
            ))
        })?;
    let family = scenario_dir
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            ReplayGateError::InvalidInput(format!(
                "could not determine scenario family from {}",
                scenario_dir.display()
            ))
        })?;

    Ok(ScenarioIdentity {
        family: family.to_string(),
        leaf: leaf.to_string(),
    })
}

fn manifest_path_for_identity(identity: &ScenarioIdentity) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(&identity.family)
        .join(format!("{}.json", identity.leaf))
}

fn discover_fixture_manifests(input: &Path) -> Result<Vec<PathBuf>, ReplayGateError> {
    if input.is_file() {
        if input.extension().and_then(|ext| ext.to_str()) == Some("json") {
            return Ok(vec![input.to_path_buf()]);
        }
        return Err(ReplayGateError::InvalidInput(format!(
            "expected a JSON fixture manifest, got {}",
            input.display()
        )));
    }
    if !input.is_dir() {
        return Err(ReplayGateError::InvalidInput(format!(
            "expected a fixture manifest or directory, got {}",
            input.display()
        )));
    }
    fs_iter::walk_files_sorted(input, |path| {
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("json"))
            .unwrap_or(false)
    })
    .map_err(ReplayGateError::from)
}

fn load_manifest(path: &Path) -> Result<FixtureManifest, ReplayGateError> {
    let bytes = fs::read(path).map_err(|source| {
        ReplayGateError::Json(format!("read {} failed: {source}", path.display()))
    })?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|source| {
        ReplayGateError::Json(format!("parse {} failed: {source}", path.display()))
    })?;
    let family = require_str(&value, "family", path)?;
    let scenario_name = require_str(&value, "name", path)?;
    let scenario_leaf = validate_manifest_identity(path, &family, &scenario_name)?;
    Ok(FixtureManifest {
        path: path.to_path_buf(),
        family,
        scenario_name,
        scenario_leaf,
        value,
    })
}

fn validate_manifest_identity(
    path: &Path,
    family: &str,
    scenario_name: &str,
) -> Result<String, ReplayGateError> {
    validate_identity_segment("family", family, path)?;
    let (name_family, scenario_leaf) = parse_scenario_name(scenario_name, path)?;
    if name_family != family {
        return Err(ReplayGateError::Json(format!(
            "manifest {} name family {name_family:?} does not match family {family:?}",
            path.display()
        )));
    }

    let file_family = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            ReplayGateError::Json(format!(
                "manifest {} path does not include a family directory",
                path.display()
            ))
        })?;
    let file_leaf = path
        .file_stem()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            ReplayGateError::Json(format!(
                "manifest {} path does not include a JSON file stem",
                path.display()
            ))
        })?;
    if file_family != family || file_leaf != scenario_leaf {
        return Err(ReplayGateError::Json(format!(
            "manifest {} identity {family}/{scenario_leaf} does not match file path {file_family}/{file_leaf}",
            path.display()
        )));
    }

    Ok(scenario_leaf)
}

fn parse_scenario_name(
    scenario_name: &str,
    path: &Path,
) -> Result<(String, String), ReplayGateError> {
    let mut parts = scenario_name.split('/');
    let family = parts.next().ok_or_else(|| {
        ReplayGateError::Json(format!(
            "manifest {} has empty scenario name",
            path.display()
        ))
    })?;
    let leaf = parts.next().ok_or_else(|| {
        ReplayGateError::Json(format!(
            "manifest {} scenario name must be <family>/<leaf>",
            path.display()
        ))
    })?;
    if parts.next().is_some() {
        return Err(ReplayGateError::Json(format!(
            "manifest {} scenario name must be <family>/<leaf>",
            path.display()
        )));
    }
    validate_identity_segment("name family", family, path)?;
    validate_identity_segment("name leaf", leaf, path)?;
    Ok((family.to_string(), leaf.to_string()))
}

fn validate_identity_segment(field: &str, value: &str, path: &Path) -> Result<(), ReplayGateError> {
    let mut components = Path::new(value).components();
    let safe_component =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    let safe_chars = !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
    if safe_component && safe_chars {
        Ok(())
    } else {
        Err(ReplayGateError::Json(format!(
            "manifest {} has unsafe {field} segment {value:?}",
            path.display()
        )))
    }
}

fn scenario_dir_for_manifest(
    goldens_root: &Path,
    manifest: &FixtureManifest,
) -> Result<PathBuf, ReplayGateError> {
    let root = goldens_root.canonicalize().map_err(|source| {
        ReplayGateError::InvalidInput(format!(
            "goldens root {} could not be canonicalized: {source}",
            goldens_root.display()
        ))
    })?;
    let scenario_dir = root.join(&manifest.family).join(&manifest.scenario_leaf);
    let effective_dir = effective_write_path(&scenario_dir)?;
    if !effective_dir.starts_with(&root) {
        return Err(ReplayGateError::InvalidInput(format!(
            "golden output path {} escapes goldens root {}",
            effective_dir.display(),
            root.display()
        )));
    }
    Ok(scenario_dir)
}

fn effective_write_path(path: &Path) -> Result<PathBuf, ReplayGateError> {
    if path.exists() {
        return path.canonicalize().map_err(|source| {
            ReplayGateError::InvalidInput(format!(
                "golden output path {} could not be canonicalized: {source}",
                path.display()
            ))
        });
    }
    let parent = path.parent().ok_or_else(|| {
        ReplayGateError::InvalidInput(format!(
            "golden output path has no parent: {}",
            path.display()
        ))
    })?;
    if parent.exists() {
        let parent = parent.canonicalize().map_err(|source| {
            ReplayGateError::InvalidInput(format!(
                "golden output parent {} could not be canonicalized: {source}",
                parent.display()
            ))
        })?;
        let file_name = path.file_name().ok_or_else(|| {
            ReplayGateError::InvalidInput(format!(
                "golden output path has no leaf: {}",
                path.display()
            ))
        })?;
        return Ok(parent.join(file_name));
    }
    Ok(path.to_path_buf())
}

fn synthesize_candidate(manifest: &FixtureManifest) -> Result<CandidateArtifacts, ReplayGateError> {
    let mut driver = ScenarioDriver::new().map_err(|source| {
        ReplayGateError::InvalidInput(format!(
            "driver init failed for {}: {source}",
            manifest.path.display()
        ))
    })?;

    let expected_verdict = require_str(&manifest.value, "expected_verdict", &manifest.path)?;
    let clock = require_str(&manifest.value, "clock", &manifest.path)?;
    let seed_index = require_u64(&manifest.value, "fixed_nonce_seed_index", &manifest.path)?;

    for _ in 0..seed_index {
        let _ = driver.next_nonce();
    }

    let nonce_hex = hex::encode(driver.next_nonce());
    let issuer_hex = hex::encode(driver.verifying_key().to_bytes());
    let receipt = json!({
        "scenario": manifest.scenario_name,
        "verdict": expected_verdict,
        "nonce": nonce_hex,
    });
    let checkpoint = json!({
        "scenario": manifest.scenario_name,
        "clock": clock,
        "issuer": issuer_hex,
    });

    let receipt_bytes = golden_format::canonical_json_bytes(&receipt).map_err(|source| {
        ReplayGateError::Json(format!(
            "canonicalize receipt for {} failed: {source}",
            manifest.path.display()
        ))
    })?;
    let checkpoint_bytes = golden_format::canonical_json_bytes(&checkpoint).map_err(|source| {
        ReplayGateError::Json(format!(
            "canonicalize checkpoint for {} failed: {source}",
            manifest.path.display()
        ))
    })?;

    let mut hasher = Sha256::new();
    hasher.update(&receipt_bytes);
    hasher.update(&checkpoint_bytes);
    let digest = hasher.finalize();
    let mut root = [0u8; 32];
    root.copy_from_slice(&digest);

    let mut receipts = receipt_bytes;
    receipts.push(b'\n');
    Ok(CandidateArtifacts {
        receipt,
        checkpoint_value: checkpoint,
        receipts,
        checkpoint_bytes,
        root_hex: hex::encode(root),
        root,
    })
}

fn prepare_golden_set(
    candidate: &CandidateArtifacts,
    scenario_dir: &Path,
) -> Result<GoldenSet, ReplayGateError> {
    let mut set = GoldenSet::new(scenario_dir);
    set.append_receipt(&candidate.receipt)?;
    set.set_checkpoint(&candidate.checkpoint_value)?;
    set.set_root(candidate.root);
    Ok(set)
}

fn commit_prepared_write(set: GoldenSet) -> Result<(), ReplayGateError> {
    let _ = set.commit()?;
    Ok(())
}

fn require_str(value: &Value, key: &str, path: &Path) -> Result<String, ReplayGateError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            ReplayGateError::Json(format!(
                "manifest {} missing required string key {key:?}",
                path.display()
            ))
        })
}

fn require_u64(value: &Value, key: &str, path: &Path) -> Result<u64, ReplayGateError> {
    value.get(key).and_then(Value::as_u64).ok_or_else(|| {
        ReplayGateError::Json(format!(
            "manifest {} missing required u64 key {key:?}",
            path.display()
        ))
    })
}

fn render_byte_diff(fixture: &str, diff: ByteDiff) -> Divergence {
    match diff {
        ByteDiff::Equal => Divergence {
            fixture: fixture.to_string(),
            kind: "equal".to_string(),
            detail: "no difference".to_string(),
        },
        ByteDiff::Different {
            kind,
            expected_len,
            actual_len,
            first_diff_offset,
            ..
        } => Divergence {
            fixture: fixture.to_string(),
            kind: artifact_kind(kind).to_string(),
            detail: format!(
                "expected_len={expected_len} actual_len={actual_len} first_diff_offset={first_diff_offset}"
            ),
        },
    }
}

fn artifact_kind(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::Receipts => "receipts",
        ArtifactKind::Checkpoint => "checkpoint",
        ArtifactKind::RootHex => "root_hex",
    }
}

fn aggregate_root(roots: &[(String, String)]) -> String {
    let mut hasher = Sha256::new();
    for (label, root_hex) in roots {
        hasher.update(label.as_bytes());
        hasher.update([0]);
        hasher.update(root_hex.as_bytes());
        hasher.update([b'\n']);
    }
    hex::encode(hasher.finalize())
}

fn report_root(roots: &[(String, String)]) -> String {
    match roots {
        [(_, root_hex)] => root_hex.clone(),
        _ => aggregate_root(roots),
    }
}

fn validate_root_hex(root: &str) -> Result<(), ReplayGateError> {
    if root.len() != 64 || !root.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        return Err(ReplayGateError::InvalidInput(format!(
            "--expect-root must be exactly 64 lowercase hex chars, got {root:?}"
        )));
    }
    Ok(())
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use std::fs;

    use serde_json::json;
    use tempfile::TempDir;

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    use super::*;

    fn write_manifest(dir: &TempDir, family: &str, leaf: &str, value: Value) -> PathBuf {
        let family_dir = dir.path().join(family);
        fs::create_dir_all(&family_dir).expect("family dir must be created");
        let path = family_dir.join(format!("{leaf}.json"));
        fs::write(&path, serde_json::to_vec(&value).unwrap()).expect("manifest must be written");
        path
    }

    fn valid_manifest(family: &str, leaf: &str) -> Value {
        json!({
            "clock": "2026-01-01T00:00:00Z",
            "expected_verdict": "allow",
            "family": family,
            "fixed_nonce_seed_index": 0,
            "name": format!("{family}/{leaf}"),
        })
    }

    #[test]
    fn load_manifest_rejects_path_escape_family() {
        let dir = TempDir::new().expect("tempdir must be created");
        let path = write_manifest(
            &dir,
            "safe",
            "leaf",
            json!({
                "family": "../../../docs",
                "name": "../../../docs/leaf",
            }),
        );

        let err = load_manifest(&path).expect_err("unsafe family must reject");

        assert!(
            err.to_string().contains("unsafe family segment"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn load_manifest_rejects_name_mismatch_with_file_path() {
        let dir = TempDir::new().expect("tempdir must be created");
        let path = write_manifest(&dir, "safe", "leaf", valid_manifest("safe", "other_leaf"));

        let err = load_manifest(&path).expect_err("file path mismatch must reject");

        assert!(
            err.to_string().contains("does not match file path"),
            "unexpected error: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn scenario_dir_for_manifest_rejects_goldens_symlink_escape() {
        let dir = TempDir::new().expect("tempdir must be created");
        let goldens_root = dir.path().join("goldens");
        let outside = dir.path().join("outside");
        fs::create_dir_all(&goldens_root).expect("goldens root must be created");
        fs::create_dir_all(&outside).expect("outside dir must be created");
        symlink(&outside, goldens_root.join("safe")).expect("symlink must be created");
        let manifest = FixtureManifest {
            path: dir.path().join("safe/leaf.json"),
            family: "safe".to_string(),
            scenario_name: "safe/leaf".to_string(),
            scenario_leaf: "leaf".to_string(),
            value: valid_manifest("safe", "leaf"),
        };

        let err = scenario_dir_for_manifest(&goldens_root, &manifest)
            .expect_err("symlink escape must reject");

        assert!(
            err.to_string().contains("escapes goldens root"),
            "unexpected error: {err}"
        );
    }
}
