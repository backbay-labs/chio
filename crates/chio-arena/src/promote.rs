use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use chio_core::canonical_json_bytes;
use chio_core::crypto::sha256_hex;
use chio_replay_corpus::{write_m04_fixture, M04ByteSizes, M04WriterError};
use chio_tee_frame::{Frame, FrameError, FrameInputs, Otel, Provenance, Upstream, UpstreamSystem};
use serde::{Deserialize, Serialize};

use crate::runtime::{ArenaReceipt, ArenaRun};
use crate::scenario::{DeterminismWitness, Scenario, ScenarioVerdict};

/// Arena manifest filename.
pub const ARENA_MANIFEST_FILENAME: &str = "arena.json";
const ARENA_BUNDLE_SCHEMA: &str = "chio.arena.bundle/v1";

/// Summary returned by [`write_arena_bundle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArenaBundleSummary {
    /// Bundle directory.
    pub dir: PathBuf,
    /// Scenario id.
    pub scenario_id: String,
    /// M04 replay root.
    pub root_hex: String,
    /// Number of receipts written.
    pub receipt_count: usize,
    /// M04 byte sizes.
    pub m04_byte_sizes: M04ByteSizes,
    /// Arena manifest path.
    pub manifest_path: PathBuf,
}

/// Arena manifest written next to M04 bundle files.
pub type ArenaBundleManifest = ArenaManifestBundle;

/// Arena manifest body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArenaManifestBundle {
    /// Manifest schema.
    pub schema_version: String,
    /// Scenario id.
    pub scenario_id: String,
    /// Determinism witness.
    pub witness: DeterminismWitness,
    /// M04 root.
    pub root_hex: String,
    /// Number of signed receipts.
    pub receipt_count: usize,
    /// Per-step entries.
    pub steps: Vec<ArenaManifestStep>,
}

/// Per-step manifest entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArenaManifestStep {
    /// Step id.
    pub step_id: String,
    /// Kernel request id.
    pub request_id: String,
    /// Arena verdict.
    pub verdict: ArenaManifestVerdict,
    /// Signed receipt id.
    pub receipt_id: String,
}

/// Manifest verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArenaManifestVerdict {
    /// Allowed.
    Allow,
    /// Denied.
    Deny,
    /// Rewritten.
    Rewrite,
}

impl From<ScenarioVerdict> for ArenaManifestVerdict {
    fn from(value: ScenarioVerdict) -> Self {
        match value {
            ScenarioVerdict::Allow => Self::Allow,
            ScenarioVerdict::Deny => Self::Deny,
            ScenarioVerdict::Rewrite => Self::Rewrite,
        }
    }
}

/// Bundle writer errors.
#[derive(Debug, thiserror::Error)]
pub enum PromoteError {
    /// Scenario and run ids differ.
    #[error("arena run scenario {run_id} does not match scenario {scenario_id}")]
    ScenarioMismatch {
        /// Scenario id.
        scenario_id: String,
        /// Run id.
        run_id: String,
    },
    /// Run has no receipts.
    #[error("arena run has no receipts")]
    EmptyRun,
    /// Canonical JSON failed.
    #[error("canonical JSON failed: {0}")]
    Canonical(#[from] chio_core::Error),
    /// TEE frame build failed.
    #[error("arena frame failed validation: {0}")]
    Frame(#[from] FrameError),
    /// M04 writer failed.
    #[error("M04 fixture write failed: {0}")]
    M04(#[from] M04WriterError),
    /// I/O failed.
    #[error("I/O error at {path}: {source}")]
    Io {
        /// Path being written.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
}

/// Write an M04-compatible bundle plus `arena.json`.
pub fn write_arena_bundle(
    dir: impl AsRef<Path>,
    scenario: &Scenario,
    run: &ArenaRun,
) -> Result<ArenaBundleSummary, PromoteError> {
    let dir = dir.as_ref();
    if scenario.id != run.scenario_id {
        return Err(PromoteError::ScenarioMismatch {
            scenario_id: scenario.id.clone(),
            run_id: run.scenario_id.clone(),
        });
    }
    if run.receipts.is_empty() {
        return Err(PromoteError::EmptyRun);
    }

    remove_existing_manifest(dir)?;
    let frames = run
        .receipts
        .iter()
        .enumerate()
        .map(|(index, receipt)| frame_from_receipt(index, scenario, receipt))
        .collect::<Result<Vec<_>, _>>()?;
    let m04 = write_m04_fixture(dir, frames)?;
    let manifest = ArenaManifestBundle {
        schema_version: ARENA_BUNDLE_SCHEMA.to_string(),
        scenario_id: scenario.id.clone(),
        witness: scenario.determinism_witness(),
        root_hex: m04.root_hex.clone(),
        receipt_count: m04.receipt_count,
        steps: run
            .receipts
            .iter()
            .map(|receipt| ArenaManifestStep {
                step_id: receipt.step_id.clone(),
                request_id: receipt.request_id.clone(),
                verdict: receipt.verdict.into(),
                receipt_id: receipt.receipt.id.clone(),
            })
            .collect(),
    };
    let manifest_path = dir.join(ARENA_MANIFEST_FILENAME);
    write_canonical_manifest(&manifest_path, &manifest)?;

    Ok(ArenaBundleSummary {
        dir: m04.dir,
        scenario_id: scenario.id.clone(),
        root_hex: m04.root_hex,
        receipt_count: m04.receipt_count,
        m04_byte_sizes: m04.byte_sizes,
        manifest_path,
    })
}

fn frame_from_receipt(
    index: usize,
    scenario: &Scenario,
    receipt: &ArenaReceipt,
) -> Result<Frame, PromoteError> {
    let receipt_bytes = canonical_json_bytes(&receipt.receipt)?;
    let arena_receipt_bytes = canonical_json_bytes(receipt)?;
    let invocation = serde_json::json!({
        "scenario_id": scenario.id,
        "step_id": receipt.step_id,
        "request_id": receipt.request_id,
        "receipt_id": receipt.receipt.id,
    });
    Frame::build(FrameInputs {
        event_id: format!("01M08ARENA{index:016}"),
        ts: scenario.virtual_clock_start.clone(),
        tee_id: "arena-p1".to_string(),
        upstream: Upstream {
            system: UpstreamSystem::Mcp,
            operation: "tool.call".to_string(),
            api_version: "arena-v1".to_string(),
        },
        invocation,
        provenance: Provenance {
            otel: Otel {
                trace_id: format!("{index:032x}"),
                span_id: format!("{index:016x}"),
            },
            supply_chain: None,
        },
        request_blob_sha256: sha256_hex(&receipt_bytes),
        response_blob_sha256: sha256_hex(&arena_receipt_bytes),
        redaction_pass_id: "m08-arena@0.1.0+p1".to_string(),
        verdict: frame_verdict(receipt.verdict),
        deny_reason: frame_deny_reason(receipt),
        would_have_blocked: receipt.verdict != ScenarioVerdict::Allow,
        tenant_sig: format!("ed25519:{}", "A".repeat(86)),
    })
    .map_err(PromoteError::Frame)
}

fn frame_verdict(verdict: ScenarioVerdict) -> chio_tee_frame::Verdict {
    match verdict {
        ScenarioVerdict::Allow => chio_tee_frame::Verdict::Allow,
        ScenarioVerdict::Deny => chio_tee_frame::Verdict::Deny,
        ScenarioVerdict::Rewrite => chio_tee_frame::Verdict::Rewrite,
    }
}

fn frame_deny_reason(receipt: &ArenaReceipt) -> Option<String> {
    match receipt.verdict {
        ScenarioVerdict::Allow => None,
        ScenarioVerdict::Deny => Some(
            receipt
                .reason
                .clone()
                .unwrap_or_else(|| "arena:expected_deny".to_string()),
        ),
        ScenarioVerdict::Rewrite => Some(
            receipt
                .reason
                .clone()
                .unwrap_or_else(|| "arena:expected_rewrite".to_string()),
        ),
    }
}

fn remove_existing_manifest(dir: &Path) -> Result<(), PromoteError> {
    let manifest = dir.join(ARENA_MANIFEST_FILENAME);
    match fs::remove_file(&manifest) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(PromoteError::Io {
            path: manifest,
            source,
        }),
    }
}

fn write_canonical_manifest(
    path: &Path,
    manifest: &ArenaManifestBundle,
) -> Result<(), PromoteError> {
    let bytes = canonical_json_bytes(manifest)?;
    fs::write(path, bytes).map_err(|source| PromoteError::Io {
        path: path.to_path_buf(),
        source,
    })
}
