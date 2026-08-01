use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use toml::Value as TomlValue;

use crate::{workspace_root, XtaskError};

const COVERAGE_SCHEMA: &str = "chio.proof-coverage.v1";
const GENERATOR_VERSION: u32 = 3;
const MARKDOWN_PATH: &str = "docs/formal/COVERAGE.md";
const JSON_PATH: &str = "target/formal/coverage.json";
const COMMIT_TOKEN: &str = "@GIT_COMMIT@";
const GENERATOR_SOURCE_PATHS: [&str; 12] = [
    "xtask/src/proof_coverage.rs",
    "xtask/src/proof_coverage/build.rs",
    "xtask/src/proof_coverage/common.rs",
    "xtask/src/proof_coverage/evidence.rs",
    "xtask/src/proof_coverage/mapping.rs",
    "xtask/src/proof_coverage/mutation_inputs.rs",
    "xtask/src/proof_coverage/mutation_reports.rs",
    "xtask/src/proof_coverage/refinement.rs",
    "xtask/src/proof_coverage/render.rs",
    "xtask/src/proof_coverage/tests/aeneas.rs",
    "xtask/src/proof_coverage/tests/mod.rs",
    "xtask/src/proof_coverage/tests/mutation.rs",
];
const BASE_LANES: [&str; 8] = [
    "lean", "aeneas", "creusot", "kani", "tla", "diff", "fuzz", "mutants",
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct MappingRow {
    section: String,
    property: String,
    source: String,
    rust_paths: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct MappingParse {
    rows: Vec<MappingRow>,
    warnings: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct MappingSource {
    lane: Option<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct MappingSurfaceResolution {
    surfaces: Vec<String>,
    unresolved: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct KaniHarness {
    #[serde(rename = "crate")]
    crate_name: String,
    harness: String,
    lane: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    primary_rust_symbol: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct CoverageRow {
    surface: String,
    lanes: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug, Deserialize)]
struct ProofManifest {
    schema: String,
    #[serde(default)]
    covered_rust_modules: Vec<String>,
    #[serde(default)]
    covered_rust_symbols: Vec<String>,
    #[serde(default)]
    property_matrix: Vec<String>,
    #[serde(default)]
    required_property_ids: Vec<String>,
    #[serde(default)]
    rust_refinement_lanes: Vec<String>,
    #[serde(default)]
    excluded_surfaces: Vec<String>,
    #[serde(default)]
    mirror: Vec<MirrorEntry>,
}

#[derive(Clone, Debug, Deserialize)]
struct MirrorEntry {
    model_file: String,
    model_kind: String,
    relationship: String,
    rust_source: String,
    rust_symbols: Vec<String>,
    normalized_sha256: String,
}

#[derive(Debug, Deserialize)]
struct TheoremInventory {
    schema: String,
    #[serde(default)]
    assumptions: Vec<TheoremEntry>,
    #[serde(default)]
    theorems: Vec<TheoremEntry>,
}

#[derive(Clone, Debug, Deserialize)]
struct TheoremEntry {
    id: String,
    file: String,
    kind: String,
    #[serde(rename = "claimClass")]
    claim_class: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(rename = "rootImported")]
    root_imported: bool,
    #[serde(rename = "mapsTo", default)]
    maps_to: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct KaniManifest {
    schema: String,
    #[serde(default)]
    harness: Vec<KaniHarness>,
}

#[derive(Debug, Deserialize)]
struct FuzzMap {
    #[serde(default)]
    targets: BTreeMap<String, FuzzTarget>,
}

#[derive(Clone, Debug, Deserialize)]
struct FuzzTarget {
    #[serde(rename = "crate")]
    crate_name: String,
    path: String,
    #[serde(default)]
    triggers: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FuzzOwners {
    #[serde(default)]
    targets: BTreeMap<String, FuzzOwner>,
}

#[derive(Clone, Debug, Deserialize)]
struct FuzzOwner {
    #[serde(rename = "crate")]
    crate_name: String,
    path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoomHarness {
    #[serde(rename = "crate")]
    crate_name: String,
    test: String,
    max_preemptions: u32,
    lane: String,
    scope: String,
    notes: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoomManifest {
    schema: String,
    #[serde(default)]
    harness: Vec<LoomHarness>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DstHarness {
    #[serde(rename = "crate")]
    crate_name: String,
    test: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DstManifest {
    schema: String,
    #[serde(default)]
    harness: Vec<DstHarness>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractTwin {
    contract: String,
    production: String,
}

#[derive(Debug, Deserialize)]
struct MutationConfig {
    #[serde(default)]
    additional_cargo_test_args: Vec<String>,
    #[serde(default)]
    examine_globs: Vec<String>,
    #[serde(default)]
    exclude_globs: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FormalMutationRegistry {
    schema: String,
    #[serde(default)]
    historical_evidence: Vec<String>,
    target: Vec<FormalMutationTarget>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FormalMutationTarget {
    name: String,
    lane: String,
    source: String,
    report: String,
    activation_target_percent: f64,
    inventory_sha256: String,
    rust_paths: Vec<String>,
    #[serde(default)]
    latest_full_cycle: Option<FormalMutationObservation>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FormalMutationObservation {
    commit: String,
    measured_at: String,
    evidence: String,
    report_sha256: String,
    enumerated: usize,
    killed: usize,
    survived: usize,
    unviable: usize,
    timeout: usize,
    activation_ratio_percent: f64,
}

#[derive(Debug, Deserialize)]
struct SpecMutationInputRegistry {
    schema: String,
    negative_registry: String,
    #[serde(default)]
    spec: Vec<SpecMutationInputSpec>,
    #[serde(default)]
    seed: Vec<SpecMutationInputSeed>,
}

#[derive(Clone, Debug, Deserialize)]
struct SpecMutationInputSpec {
    name: String,
    path: String,
    cfg: String,
    invariant: String,
    length: usize,
}

#[derive(Clone, Debug, Deserialize)]
struct SpecMutationInputSeed {
    name: String,
    negative_spec: String,
}

#[derive(Debug, Deserialize)]
struct NegativeMutationInputRegistry {
    schema: String,
    #[serde(default)]
    negative: Vec<NegativeMutationInput>,
}

#[derive(Clone, Debug, Deserialize)]
struct NegativeMutationInput {
    spec: String,
    cfg: String,
    falsifies: String,
    length: usize,
    timeout_secs: usize,
    runtime_test: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct MutationVerdictCounts {
    killed: usize,
    survived: usize,
    unviable: usize,
    timeout: usize,
}

impl MutationVerdictCounts {
    fn sampled(self) -> Result<usize, String> {
        self.killed
            .checked_add(self.survived)
            .and_then(|value| value.checked_add(self.unviable))
            .and_then(|value| value.checked_add(self.timeout))
            .ok_or_else(|| "formal mutation verdict count overflow".to_string())
    }

    fn score_denominator(self) -> Result<usize, String> {
        self.killed
            .checked_add(self.survived)
            .and_then(|value| value.checked_add(self.timeout))
            .ok_or_else(|| "formal mutation score denominator overflow".to_string())
    }

    fn activation_ratio_percent(self) -> Result<f64, String> {
        let denominator = self.score_denominator()?;
        Ok(if denominator == 0 {
            0.0
        } else {
            100.0 * self.killed as f64 / denominator as f64
        })
    }

    fn completion_ratio_percent(self) -> Result<f64, String> {
        let sampled = self.sampled()?;
        let completed = self
            .killed
            .checked_add(self.survived)
            .and_then(|value| value.checked_add(self.unviable))
            .ok_or_else(|| "formal mutation completion count overflow".to_string())?;
        Ok(if sampled == 0 {
            0.0
        } else {
            100.0 * completed as f64 / sampled as f64
        })
    }

    fn increment(&mut self, verdict: &str) -> Result<(), String> {
        let count = match verdict {
            "killed" => &mut self.killed,
            "survived" => &mut self.survived,
            "unviable" => &mut self.unviable,
            "timeout" => &mut self.timeout,
            _ => return Err(format!("invalid formal mutation verdict: {verdict}")),
        };
        *count = count
            .checked_add(1)
            .ok_or_else(|| "formal mutation verdict count overflow".to_string())?;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct AssumptionRegistry {
    schema: String,
    #[serde(default)]
    required_assumption_ids: Vec<String>,
    #[serde(default)]
    assumptions: Vec<String>,
    #[serde(default)]
    retired_assumption_ids: Vec<String>,
    #[serde(default)]
    retired_assumptions: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct InputDigest {
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Serialize)]
struct ArtifactRecord {
    id: String,
    lane: String,
    primary_surface: String,
    related_surfaces: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    qualifiers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize)]
struct UnattributedArtifact {
    id: String,
    lane: String,
    reason: String,
    related_properties: Vec<String>,
    related_surfaces: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    qualifiers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize)]
struct AssumptionSummary {
    id: String,
    status: String,
}

#[derive(Clone, Debug, Serialize)]
struct ReviewLink {
    id: String,
    kind: String,
    relationship: String,
    source: String,
    target: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    qualifiers: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct CoverageDocument {
    schema: String,
    generator_version: u32,
    commit: String,
    input_digest: String,
    inputs: Vec<InputDigest>,
    lanes: Vec<String>,
    rows: Vec<CoverageRow>,
    artifacts: Vec<ArtifactRecord>,
    unattributed_artifacts: Vec<UnattributedArtifact>,
    assumptions: Vec<AssumptionSummary>,
    excluded_surfaces: Vec<String>,
    review_links: Vec<ReviewLink>,
    lane_postures: BTreeMap<String, String>,
    parse_warnings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_members: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CargoPackage {
    id: String,
    name: String,
    manifest_path: String,
    targets: Vec<CargoTarget>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CargoTarget {
    name: String,
    kind: Vec<String>,
    src_path: String,
}

#[derive(Clone, Debug, Serialize)]
struct WorkspacePackage {
    name: String,
    root: String,
    lib_names: Vec<String>,
}

#[derive(Debug)]
struct WorkspaceCatalog {
    packages: BTreeMap<String, WorkspacePackage>,
    lib_to_package: BTreeMap<String, String>,
    projection_sha256: String,
}

#[derive(Debug)]
struct CoverageBuild {
    commit: String,
    input_digest: String,
    inputs: Vec<InputDigest>,
    lanes: Vec<String>,
    rows: Vec<CoverageRow>,
    artifacts: Vec<ArtifactRecord>,
    unattributed_artifacts: Vec<UnattributedArtifact>,
    assumptions: Vec<AssumptionSummary>,
    excluded_surfaces: Vec<String>,
    review_links: Vec<ReviewLink>,
    lane_postures: BTreeMap<String, String>,
    parse_warnings: Vec<String>,
}

pub(crate) fn run(check: bool) -> Result<(), XtaskError> {
    let root = workspace_root()?;
    let build = build_coverage(&root).map_err(XtaskError::ProofCoverage)?;
    let markdown = render_document(&build).map_err(XtaskError::ProofCoverage)?;
    let document = CoverageDocument {
        schema: COVERAGE_SCHEMA.to_string(),
        generator_version: GENERATOR_VERSION,
        commit: build.commit.clone(),
        input_digest: build.input_digest.clone(),
        inputs: build.inputs.clone(),
        lanes: build.lanes.clone(),
        rows: build.rows.clone(),
        artifacts: build.artifacts.clone(),
        unattributed_artifacts: build.unattributed_artifacts.clone(),
        assumptions: build.assumptions.clone(),
        excluded_surfaces: build.excluded_surfaces.clone(),
        review_links: build.review_links.clone(),
        lane_postures: build.lane_postures.clone(),
        parse_warnings: build.parse_warnings.clone(),
    };
    let json = serde_json::to_string_pretty(&document)
        .map_err(|error| XtaskError::ProofCoverage(format!("JSON render failed: {error}")))?
        + "\n";
    write_output(&root.join(JSON_PATH), &json)?;

    let markdown_path = root.join(MARKDOWN_PATH);
    if check {
        let existing = fs::read_to_string(&markdown_path)
            .map_err(|error| XtaskError::Io(MARKDOWN_PATH.to_string(), error))?;
        verify_committed_markdown(&existing, &markdown).map_err(XtaskError::ProofCoverage)?;
        println!(
            "proof-coverage: {} rows and {} artifacts match",
            build.rows.len(),
            build.artifacts.len()
        );
    } else {
        write_output(&markdown_path, &markdown)?;
        println!(
            "proof-coverage: wrote {MARKDOWN_PATH} and {JSON_PATH} ({} rows, {} artifacts)",
            build.rows.len(),
            build.artifacts.len()
        );
    }
    Ok(())
}

pub(crate) fn checked_committed_markdown(root: &Path) -> Result<String, XtaskError> {
    let build = build_coverage(root).map_err(XtaskError::ProofCoverage)?;
    let generated = render_document(&build).map_err(XtaskError::ProofCoverage)?;
    let existing = fs::read_to_string(root.join(MARKDOWN_PATH))
        .map_err(|error| XtaskError::Io(MARKDOWN_PATH.to_string(), error))?;
    verify_committed_markdown(&existing, &generated).map_err(XtaskError::ProofCoverage)?;
    Ok(existing)
}

mod build;
mod common;
mod evidence;
mod mapping;
mod mutation_inputs;
mod mutation_reports;
mod refinement;
mod render;

use build::*;
use common::*;
use evidence::*;
use mapping::*;
use mutation_inputs::*;
use mutation_reports::*;
use refinement::*;
use render::*;

#[cfg(test)]
mod tests;
