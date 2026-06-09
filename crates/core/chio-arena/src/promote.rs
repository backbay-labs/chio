use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use chio_core::canonical_json_bytes;
use chio_core::crypto::sha256_hex;
use chio_replay_corpus::{write_fixture, ByteSizes, WriterError};
use chio_tee_frame::{Frame, FrameError, FrameInputs, Otel, Provenance, Upstream, UpstreamSystem};
use serde::{Deserialize, Serialize};

use crate::runtime::{ArenaReceipt, ArenaRun};
use crate::scenario::{DeterminismWitness, Scenario, ScenarioVerdict};

/// Arena manifest filename.
pub const ARENA_MANIFEST_FILENAME: &str = "arena.json";
const ARENA_BUNDLE_SCHEMA: &str = "chio.arena.bundle/v1";
/// Schema marker used by auto-promoted fixture descriptors.
pub const ARENA_FIXTURE_SCHEMA: &str = "chio.arena.fixture/v1";
/// Schema marker used by auto-promoted adversarial-suite cases.
pub const ARENA_ADVERSARIAL_CASE_SCHEMA: &str = "chio.arena.adversarial-case/v1";
/// Default per-run cap on auto-promoted fixtures (matches the
/// CHIO_BLESS gate per-PR cap of 5).
pub const ARENA_PROMOTE_CAP_DEFAULT: usize = 5;

/// Summary returned by [`write_arena_bundle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArenaBundleSummary {
    /// Bundle directory.
    pub dir: PathBuf,
    /// Scenario id.
    pub scenario_id: String,
    /// Replay root.
    pub root_hex: String,
    /// Number of receipts written.
    pub receipt_count: usize,
    /// Byte sizes.
    pub byte_sizes: ByteSizes,
    /// Arena manifest path.
    pub manifest_path: PathBuf,
}

/// Arena manifest written next to bundle files.
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
    /// Replay root.
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
    /// Run contains a receipt for a step not present in the scenario.
    #[error("arena run receipt references unknown scenario step {step_id}")]
    UnknownReceiptStep {
        /// Receipt step id.
        step_id: String,
    },
    /// Canonical JSON failed.
    #[error("canonical JSON failed: {0}")]
    Canonical(#[from] chio_core::Error),
    /// TEE frame build failed.
    #[error("arena frame failed validation: {0}")]
    Frame(#[from] FrameError),
    /// Fixture writer failed.
    #[error("fixture write failed: {0}")]
    Writer(#[from] WriterError),
    /// I/O failed.
    #[error("I/O error at {path}: {source}")]
    Io {
        /// Path being written.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
    /// CHIO_BLESS gate clause refused promotion.
    #[error("CHIO_BLESS gate refused promotion: {clause}")]
    BlessGate {
        /// Clause message.
        clause: String,
    },
    /// Per-run cap was set to zero.
    #[error("auto-promotion cap must be at least 1")]
    ZeroCap,
}

/// Write a replay-compatible bundle plus `arena.json`.
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
    validate_run_receipts_belong_to_scenario(scenario, run)?;

    remove_existing_manifest(dir)?;
    let frames = run
        .receipts
        .iter()
        .enumerate()
        .map(|(index, receipt)| frame_from_receipt(index, scenario, receipt))
        .collect::<Result<Vec<_>, _>>()?;
    let fixture = write_fixture(dir, frames)?;
    let manifest = ArenaManifestBundle {
        schema_version: ARENA_BUNDLE_SCHEMA.to_string(),
        scenario_id: scenario.id.clone(),
        witness: scenario.determinism_witness(),
        root_hex: fixture.root_hex.clone(),
        receipt_count: fixture.receipt_count,
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
        dir: fixture.dir,
        scenario_id: scenario.id.clone(),
        root_hex: fixture.root_hex,
        receipt_count: fixture.receipt_count,
        byte_sizes: fixture.byte_sizes,
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
        event_id: format!("01ARENA000{index:016}"),
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
        redaction_pass_id: "arena-redaction@0.1.0+p1".to_string(),
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

/// Environment access for the CHIO_BLESS gate. Tests inject a stub.
pub trait BlessEnv {
    /// Read an environment variable.
    fn var(&self, name: &str) -> Option<String>;
}

/// Process-environment implementation of [`BlessEnv`].
pub struct ProcessBlessEnv;

impl BlessEnv for ProcessBlessEnv {
    fn var(&self, name: &str) -> Option<String> {
        match env::var_os(name) {
            Some(value) => OsString::into_string(value).ok(),
            None => None,
        }
    }
}

/// Outcome reported by [`promote_to_fixtures`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArenaPromotionSummary {
    /// Promoted fixture paths.
    pub fixtures: Vec<PathBuf>,
    /// Effective `BLESS_REASON` recorded.
    pub bless_reason: String,
    /// Family namespace used.
    pub family: String,
    /// Per-run cap that was enforced.
    pub cap: usize,
    /// Total receipts scanned.
    pub receipts_scanned: usize,
    /// Receipts that were skipped because they matched the cap budget.
    pub receipts_skipped_cap: usize,
}

/// Outcome reported by [`promote_to_adversarial_suite`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdversarialSuiteSummary {
    /// Per-class JSON files that were written.
    pub cases: Vec<PathBuf>,
    /// Whether the live suite was used (true) or the soft-disabled
    /// `target/arena/promote-pending/` holding directory.
    pub live_target: bool,
    /// Resolved root directory.
    pub root: PathBuf,
}

/// Soft-gate inputs for the auto-promotion path. The CHIO_BLESS
/// gate is reused unchanged; this checks the env vars locally so arena
/// callers do not need to invoke the bless script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArenaPromotionGate {
    /// Effective `CHIO_BLESS`.
    pub chio_bless: String,
    /// Effective `BLESS_REASON`.
    pub bless_reason: String,
    /// Whether `CI` was observed truthy.
    pub ci: bool,
}

impl ArenaPromotionGate {
    /// Read the gate inputs from the supplied environment.
    pub fn read(env: &dyn BlessEnv) -> Result<Self, PromoteError> {
        let chio_bless = env.var("CHIO_BLESS").unwrap_or_default();
        if chio_bless != "1" {
            return Err(PromoteError::BlessGate {
                clause: "CHIO_BLESS env var must be exactly \"1\"".to_string(),
            });
        }
        let bless_reason = env.var("BLESS_REASON").unwrap_or_default();
        if bless_reason.trim().is_empty() {
            return Err(PromoteError::BlessGate {
                clause: "BLESS_REASON must be set and non-empty".to_string(),
            });
        }
        if !bless_reason.starts_with("arena:") {
            return Err(PromoteError::BlessGate {
                clause: format!(
                    "BLESS_REASON must start with arena:<scenario-id>, got {bless_reason:?}"
                ),
            });
        }
        let ci_value = env.var("CI").unwrap_or_default();
        let ci = matches!(
            ci_value.as_str(),
            "1" | "true" | "TRUE" | "True" | "yes" | "YES"
        );
        if ci {
            return Err(PromoteError::BlessGate {
                clause: "CHIO_BLESS may not run in CI (CI env var observed truthy)".to_string(),
            });
        }
        Ok(Self {
            chio_bless,
            bless_reason,
            ci,
        })
    }
}

/// Per-class adversarial-suite promotion target on disk.
fn adversarial_class_dirname(class: &str) -> String {
    class
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn validate_run_receipts_belong_to_scenario(
    scenario: &Scenario,
    run: &ArenaRun,
) -> Result<(), PromoteError> {
    let scenario_steps = scenario
        .steps
        .iter()
        .map(|step| step.id.as_str())
        .collect::<BTreeSet<_>>();
    for receipt in &run.receipts {
        if !scenario_steps.contains(receipt.step_id.as_str()) {
            return Err(PromoteError::UnknownReceiptStep {
                step_id: receipt.step_id.clone(),
            });
        }
    }
    Ok(())
}

/// Auto-promote failing arena scenarios to the fixture corpus under
/// `tests/replay/fixtures/arena/<class>/<hash>.json`.
///
/// This function honours the CHIO_BLESS gate clauses: `CHIO_BLESS`
/// must be exactly `"1"`, `BLESS_REASON` must start with
/// `arena:<scenario-id>`, and `CI` must be unset / falsy. The per-run
/// cap (default 5, matching the per-PR cap) clamps how many
/// fixtures land in one call.
///
/// Only [`ScenarioVerdict::Deny`] receipts (the failures the arena is meant to
/// graduate) are written. Allowed and rewritten steps are skipped.
pub fn promote_to_fixtures(
    scenario: &Scenario,
    run: &ArenaRun,
    fixtures_root: &Path,
    class: &str,
    cap: usize,
    env: &dyn BlessEnv,
) -> Result<ArenaPromotionSummary, PromoteError> {
    let gate = ArenaPromotionGate::read(env)?;
    let expected_reason = format!("arena:{}", scenario.id);
    if gate.bless_reason != expected_reason {
        return Err(PromoteError::BlessGate {
            clause: format!(
                "BLESS_REASON {actual:?} does not match arena:<scenario-id> for {expected:?}",
                actual = gate.bless_reason,
                expected = expected_reason,
            ),
        });
    }
    if scenario.id != run.scenario_id {
        return Err(PromoteError::ScenarioMismatch {
            scenario_id: scenario.id.clone(),
            run_id: run.scenario_id.clone(),
        });
    }
    validate_run_receipts_belong_to_scenario(scenario, run)?;
    if cap == 0 {
        return Err(PromoteError::ZeroCap);
    }

    let family = adversarial_class_dirname(class);
    let class_dir = fixtures_root.join("arena").join(&family);
    fs::create_dir_all(&class_dir).map_err(|source| PromoteError::Io {
        path: class_dir.clone(),
        source,
    })?;

    let mut fixtures = Vec::new();
    let mut skipped_cap = 0;
    // Match the documented contract: only `Deny` receipts are graduated to
    // fixtures. `Allow` and `Rewrite` are skipped so downstream
    // replay consumers do not receive unexpected fixture types.
    for receipt in run
        .receipts
        .iter()
        .filter(|r| matches!(r.verdict, ScenarioVerdict::Deny))
    {
        if fixtures.len() >= cap {
            skipped_cap += 1;
            continue;
        }
        let fixture = build_fixture(scenario, receipt, class, &gate)?;
        let bytes = canonical_json_bytes(&fixture)?;
        let hash = sha256_hex(&bytes);
        let path = class_dir.join(format!("{}.json", &hash[..16]));
        fs::write(&path, &bytes).map_err(|source| PromoteError::Io {
            path: path.clone(),
            source,
        })?;
        fixtures.push(path);
    }

    Ok(ArenaPromotionSummary {
        fixtures,
        bless_reason: gate.bless_reason,
        family,
        cap,
        receipts_scanned: run.receipts.len(),
        receipts_skipped_cap: skipped_cap,
    })
}

/// Auto-promote failing scenarios to the chio-adversarial-suite
/// per-class corpus.
///
/// When `crates/chio-adversarial-suite/cases/` is absent, the writer
/// falls back to `target/arena/promote-pending/`. The returned summary
/// records which target was chosen.
pub fn promote_to_adversarial_suite(
    scenario: &Scenario,
    run: &ArenaRun,
    workspace_root: &Path,
    class: &str,
) -> Result<AdversarialSuiteSummary, PromoteError> {
    if scenario.id != run.scenario_id {
        return Err(PromoteError::ScenarioMismatch {
            scenario_id: scenario.id.clone(),
            run_id: run.scenario_id.clone(),
        });
    }
    validate_run_receipts_belong_to_scenario(scenario, run)?;

    let family = adversarial_class_dirname(class);
    let live_root = workspace_root
        .join("crates")
        .join("chio-adversarial-suite")
        .join("cases");
    let live_target = live_root.is_dir();
    let root = if live_target {
        live_root
    } else {
        workspace_root
            .join("target")
            .join("arena")
            .join("promote-pending")
            .join("chio-adversarial-suite")
            .join("cases")
    };
    let class_dir = root.join(&family);
    fs::create_dir_all(&class_dir).map_err(|source| PromoteError::Io {
        path: class_dir.clone(),
        source,
    })?;

    let mut cases = Vec::new();
    for receipt in run
        .receipts
        .iter()
        .filter(|r| matches!(r.verdict, ScenarioVerdict::Deny | ScenarioVerdict::Rewrite))
    {
        let case = build_adversarial_case(scenario, receipt, class)?;
        let bytes = canonical_json_bytes(&case)?;
        let hash = sha256_hex(&bytes);
        let path = class_dir.join(format!("{}.json", &hash[..16]));
        fs::write(&path, &bytes).map_err(|source| PromoteError::Io {
            path: path.clone(),
            source,
        })?;
        cases.push(path);
    }

    Ok(AdversarialSuiteSummary {
        cases,
        live_target,
        root,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ArenaFixture {
    schema_version: String,
    family: String,
    name: String,
    intent: String,
    expected_verdict: String,
    expected_failure_class: Option<String>,
    clock: String,
    fixed_nonce_seed_index: u64,
    tags: Vec<String>,
    bless_reason: String,
    arena: ArenaFixtureBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ArenaFixtureBody {
    scenario_id: String,
    step_id: String,
    request_id: String,
    receipt_id: String,
    verdict: String,
    reason: Option<String>,
    witness: DeterminismWitness,
    receipt_sha256: String,
}

fn build_fixture(
    scenario: &Scenario,
    receipt: &ArenaReceipt,
    class: &str,
    gate: &ArenaPromotionGate,
) -> Result<ArenaFixture, PromoteError> {
    let receipt_bytes = canonical_json_bytes(&receipt.receipt)?;
    let family = adversarial_class_dirname(class);
    let name = format!("arena/{family}/{}", receipt.step_id);
    let verdict = match receipt.verdict {
        ScenarioVerdict::Allow => "allow",
        ScenarioVerdict::Deny => "deny",
        ScenarioVerdict::Rewrite => "rewrite",
    };
    Ok(ArenaFixture {
        schema_version: ARENA_FIXTURE_SCHEMA.to_string(),
        family: format!("arena/{family}"),
        name,
        intent: format!(
            "Auto-promoted from arena scenario {} ({class} class).",
            scenario.id
        ),
        expected_verdict: verdict.to_string(),
        expected_failure_class: match receipt.verdict {
            ScenarioVerdict::Allow => None,
            _ => Some(class.to_string()),
        },
        clock: scenario.virtual_clock_start.clone(),
        fixed_nonce_seed_index: scenario.rng_seed,
        tags: vec!["arena".to_string(), class.to_string()],
        bless_reason: gate.bless_reason.clone(),
        arena: ArenaFixtureBody {
            scenario_id: scenario.id.clone(),
            step_id: receipt.step_id.clone(),
            request_id: receipt.request_id.clone(),
            receipt_id: receipt.receipt.id.clone(),
            verdict: verdict.to_string(),
            reason: receipt.reason.clone(),
            witness: scenario.determinism_witness(),
            receipt_sha256: sha256_hex(&receipt_bytes),
        },
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AdversarialCase {
    schema_version: String,
    case_id: String,
    class: String,
    scenario_id: String,
    step_id: String,
    receipt_id: String,
    verdict: String,
    reason: Option<String>,
    witness: DeterminismWitness,
    receipt_sha256: String,
    metadata: BTreeMap<String, String>,
}

fn build_adversarial_case(
    scenario: &Scenario,
    receipt: &ArenaReceipt,
    class: &str,
) -> Result<AdversarialCase, PromoteError> {
    // Propagate canonical-JSON serialisation failure instead of silently
    // hashing the empty byte string, which would emit an
    // attacker-friendly "all-zeros" `receipt_sha256` while still claiming
    // the case promoted successfully. The analogous `build_fixture`
    // already propagates this error.
    let receipt_bytes = canonical_json_bytes(&receipt.receipt)?;
    let mut metadata = BTreeMap::new();
    metadata.insert("scenario_title".to_string(), scenario.title.clone());
    metadata.insert("origin".to_string(), "chio-arena".to_string());
    Ok(AdversarialCase {
        schema_version: ARENA_ADVERSARIAL_CASE_SCHEMA.to_string(),
        case_id: format!("{}#{}", scenario.id, receipt.step_id),
        class: class.to_string(),
        scenario_id: scenario.id.clone(),
        step_id: receipt.step_id.clone(),
        receipt_id: receipt.receipt.id.clone(),
        verdict: match receipt.verdict {
            ScenarioVerdict::Allow => "allow".to_string(),
            ScenarioVerdict::Deny => "deny".to_string(),
            ScenarioVerdict::Rewrite => "rewrite".to_string(),
        },
        reason: receipt.reason.clone(),
        witness: scenario.determinism_witness(),
        receipt_sha256: sha256_hex(&receipt_bytes),
        metadata,
    })
}
