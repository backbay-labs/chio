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

fn build_coverage(root: &Path) -> Result<CoverageBuild, String> {
    let mut input_hashes = BTreeMap::new();
    let workspace = workspace_catalog(root)?;
    input_hashes.insert(
        "cargo-metadata://workspace-packages".to_string(),
        workspace.projection_sha256.clone(),
    );
    let _generator = read_input(root, "xtask/src/proof_coverage.rs", &mut input_hashes)?;

    let manifest_raw = read_input(root, "formal/proof-manifest.toml", &mut input_hashes)?;
    let manifest: ProofManifest = parse_toml("formal/proof-manifest.toml", &manifest_raw)?;
    if manifest.schema != "chio.proof-manifest.v1" {
        return Err(format!(
            "unsupported proof manifest schema: {}",
            manifest.schema
        ));
    }
    let property_ids = property_ids(&manifest)?;
    let mut review_links = mirror_review_links(&manifest.mirror)?;

    let inventory_raw = read_input(root, "formal/theorem-inventory.json", &mut input_hashes)?;
    let inventory: TheoremInventory = serde_json::from_str(&inventory_raw)
        .map_err(|error| format!("cannot parse formal/theorem-inventory.json: {error}"))?;
    if inventory.schema != "chio.theorem-inventory.v1" {
        return Err(format!(
            "unsupported theorem inventory schema: {}",
            inventory.schema
        ));
    }
    validate_theorem_properties(&inventory, &property_ids)?;

    let mapping_raw = read_input(root, "formal/MAPPING.md", &mut input_hashes)?;
    let mapping = parse_mapping(&mapping_raw);

    let assumptions_raw = read_input(root, "formal/assumptions.toml", &mut input_hashes)?;
    let assumptions_registry: AssumptionRegistry =
        parse_toml("formal/assumptions.toml", &assumptions_raw)?;
    let assumptions = assumption_summaries(&assumptions_registry)?;

    let kani_raw = read_input(root, ".kani/harnesses.toml", &mut input_hashes)?;
    let kani: KaniManifest = parse_toml(".kani/harnesses.toml", &kani_raw)?;
    if kani.schema != "chio.kani.multi-crate.v1" {
        return Err(format!("unsupported Kani manifest schema: {}", kani.schema));
    }
    validate_kani_crates(&kani.harness, &workspace.packages.keys().cloned().collect())?;
    reject_duplicate_harnesses(&kani.harness)?;

    let fuzz_raw = read_input(root, "fuzz/target-map.toml", &mut input_hashes)?;
    let fuzz_map: FuzzMap = parse_toml("fuzz/target-map.toml", &fuzz_raw)?;
    let fuzz_owners_raw = read_input(root, "fuzz/owners.toml", &mut input_hashes)?;
    let fuzz_owners: FuzzOwners = parse_toml("fuzz/owners.toml", &fuzz_owners_raw)?;

    let mutants_raw = read_input(root, ".cargo/mutants.toml", &mut input_hashes)?;
    let mutants: MutationConfig = parse_toml(".cargo/mutants.toml", &mutants_raw)?;
    let mutants_baseline_raw = read_input(
        root,
        "docs/fuzzing/trust-boundary-mutants-baseline.toml",
        &mut input_hashes,
    )?;
    validate_mutation_baseline(&mutants_baseline_raw)?;
    let formal_mutations_raw =
        read_input(root, "formal/mutation/registry.toml", &mut input_hashes)?;
    let formal_mutations: FormalMutationRegistry =
        parse_toml("formal/mutation/registry.toml", &formal_mutations_raw)?;
    if formal_mutations.schema != "chio.formal-mutation-coverage.v1" {
        return Err(format!(
            "unsupported formal mutation registry schema: {}",
            formal_mutations.schema
        ));
    }
    let mut historical_evidence = BTreeSet::new();
    for evidence in &formal_mutations.historical_evidence {
        let normalized = normalized_repo_path(evidence)?;
        if normalized != *evidence
            || !normalized.starts_with("formal/mutation/evidence/")
            || !historical_evidence.insert(normalized.clone())
        {
            return Err(format!(
                "formal mutation historical evidence path is invalid or repeated: {evidence}"
            ));
        }
        let _ = read_input(root, &normalized, &mut input_hashes)?;
    }
    let workspace_rust_files = workspace_rust_files(root)?;
    input_hashes.insert(
        "git-worktree://rust-files".to_string(),
        ordered_string_digest(&workspace_rust_files),
    );
    let releases_raw = read_input(root, "releases.toml", &mut input_hashes)?;
    let lane_postures = lane_postures(&releases_raw)?;

    let mut lanes = BASE_LANES
        .iter()
        .map(|lane| (*lane).to_string())
        .collect::<Vec<_>>();
    let mut rows = BTreeMap::<String, CoverageRow>::new();
    let mut artifacts = BTreeMap::<String, ArtifactRecord>::new();
    let mut unattributed = Vec::new();

    let mut covered_surfaces = Vec::new();
    for module in &manifest.covered_rust_modules {
        let path = normalized_repo_path(module)?;
        if !root.join(&path).is_file() {
            return Err(format!("covered Rust module not found: {module}"));
        }
        let surface = surface_from_repo_path(&path, &workspace, true)?;
        ensure_row(&mut rows, &surface);
        covered_surfaces.push(surface);
    }
    for symbol in &manifest.covered_rust_symbols {
        let surface = surface_from_symbol(symbol, root, &workspace)
            .ok_or_else(|| format!("covered Rust symbol has no workspace surface: {symbol}"))?;
        ensure_row(&mut rows, &surface);
    }
    for harness in &kani.harness {
        ensure_row(&mut rows, &crate_surface(&harness.crate_name));
    }

    let mut mapping_surfaces = BTreeMap::<String, Vec<String>>::new();
    for row in &mapping.rows {
        let source = validate_mapping_source(row, root, &mut input_hashes)?;
        let resolution = surfaces_from_mapping(&row.rust_paths, root, &workspace)?;
        let candidates = if resolution.unresolved.is_empty() {
            resolution.surfaces.clone()
        } else {
            Vec::new()
        };
        mapping_surfaces
            .entry(row.property.clone())
            .or_default()
            .extend(candidates);
        if let Some(lane) = source.lane {
            let id = format!("formal/MAPPING.md::{}/{}", row.section, row.property);
            if resolution.unresolved.is_empty() {
                add_or_unattribute(
                    &mut rows,
                    &mut artifacts,
                    &mut unattributed,
                    id,
                    &lane,
                    resolution.surfaces,
                    "MAPPING row has no resolvable Rust surface",
                    Vec::new(),
                )?;
            } else {
                unattributed.push(UnattributedArtifact {
                    id,
                    lane,
                    reason: format!(
                        "MAPPING row contains unresolved Rust references: {}",
                        resolution.unresolved.join(", ")
                    ),
                    related_properties: Vec::new(),
                    related_surfaces: resolution.surfaces,
                    qualifiers: BTreeMap::new(),
                });
            }
        }
    }
    for surfaces in mapping_surfaces.values_mut() {
        surfaces.sort();
        surfaces.dedup();
    }

    add_kani_artifacts(
        root,
        &workspace,
        &kani.harness,
        &mapping_surfaces,
        &mut rows,
        &mut artifacts,
    )?;
    add_refinement_artifacts(
        root,
        &workspace,
        &manifest,
        &kani.harness,
        &mut input_hashes,
        &mut rows,
        &mut artifacts,
        &mut unattributed,
        &mut review_links,
    )?;
    add_fuzz_artifacts(
        root,
        &workspace,
        &fuzz_map,
        &fuzz_owners,
        &mut rows,
        &mut artifacts,
    )?;
    let mutant_config_paths = files_in_dir(root, "audits/mutation/per-crate-configs", "toml")?;
    unattributed.push(UnattributedArtifact {
        id: "docs/fuzzing/trust-boundary-mutants-baseline.toml".to_string(),
        lane: "mutants".to_string(),
        reason: "aggregate mutation baseline has no per-crate Rust-surface result".to_string(),
        related_properties: Vec::new(),
        related_surfaces: Vec::new(),
        qualifiers: BTreeMap::from([("scope".to_string(), "aggregate".to_string())]),
    });
    let active_mutant_configs = add_mutant_artifacts(
        root,
        &workspace,
        &mutants,
        &workspace_rust_files,
        &mut input_hashes,
        &mut rows,
        &mut artifacts,
        &mut unattributed,
        &mutant_config_paths,
    )?;
    add_formal_mutation_artifacts(
        root,
        &workspace,
        &formal_mutations.target,
        &mut input_hashes,
        &mut rows,
        &mut artifacts,
        &mut unattributed,
    )?;
    add_inventory_artifacts(&inventory, &mut unattributed);
    add_diff_artifacts(root, &mut input_hashes, &mut unattributed)?;
    add_optional_concurrency_artifacts(
        root,
        &workspace,
        &mut input_hashes,
        &mut lanes,
        &mapping_surfaces,
        &mut rows,
        &mut artifacts,
    )?;

    for row in rows.values_mut() {
        for lane in &lanes {
            row.lanes.entry(lane.clone()).or_default();
        }
    }
    for surface in &covered_surfaces {
        let Some(row) = rows.get(surface) else {
            return Err(format!(
                "covered Rust module has no coverage row: {surface}"
            ));
        };
        if row.lanes.values().all(BTreeSet::is_empty) {
            return Err(format!(
                "covered Rust module has no declared lane artifact: {surface}"
            ));
        }
    }
    validate_primary_attribution(&kani.harness, &fuzz_map, &active_mutant_configs, &rows)?;
    validate_mutant_classification(&mutant_config_paths, &artifacts, &unattributed)?;

    let mut rows = rows.into_values().collect::<Vec<_>>();
    rows.sort_by(|left, right| left.surface.cmp(&right.surface));
    let artifacts = artifacts.into_values().collect::<Vec<_>>();
    unattributed.sort_by(|left, right| left.id.cmp(&right.id));
    review_links.sort_by(|left, right| left.id.cmp(&right.id));
    let inputs = input_hashes
        .into_iter()
        .map(|(path, sha256)| InputDigest { path, sha256 })
        .collect::<Vec<_>>();
    let input_digest = combined_input_digest(&inputs);
    let commit = git_commit(root)?;

    Ok(CoverageBuild {
        commit,
        input_digest,
        inputs,
        lanes,
        rows,
        artifacts,
        unattributed_artifacts: unattributed,
        assumptions,
        excluded_surfaces: manifest.excluded_surfaces,
        review_links,
        lane_postures,
        parse_warnings: mapping.warnings,
    })
}

fn parse_mapping(input: &str) -> MappingParse {
    let mut parsed = MappingParse::default();
    let mut section = String::new();
    let mut headers: Option<Vec<String>> = None;

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if let Some(heading) = line.strip_prefix("## ") {
            section = heading.trim().to_string();
            headers = None;
            continue;
        }
        if !(line.starts_with('|') && line.ends_with('|')) {
            if !line.is_empty() {
                headers = None;
            }
            continue;
        }
        let cells = markdown_cells(line);
        if headers.is_none() {
            let looks_like_property_header = cells.iter().any(|cell| {
                cell == "Property"
                    || cell == "Source"
                    || cell.starts_with("Source ")
                    || cell == "Rust path constrained"
            });
            if looks_like_property_header {
                let mut missing = Vec::new();
                if !cells.iter().any(|cell| cell == "Property") {
                    missing.push("Property");
                }
                if !cells
                    .iter()
                    .any(|cell| cell == "Source" || cell.starts_with("Source "))
                {
                    missing.push("Source");
                }
                if !cells.iter().any(|cell| cell == "Rust path constrained") {
                    missing.push("Rust path constrained");
                }
                if !missing.is_empty() {
                    parsed.warnings.push(format!(
                        "line {line_number}: property table missing required columns: {}",
                        missing.join(", ")
                    ));
                    continue;
                }
                headers = Some(cells);
            }
            continue;
        }
        let Some(table_headers) = headers.as_ref() else {
            continue;
        };
        if separator_cells(&cells) {
            continue;
        }
        if cells.len() != table_headers.len() {
            parsed.warnings.push(format!(
                "line {line_number}: expected {} cells, found {}",
                table_headers.len(),
                cells.len()
            ));
            continue;
        }
        let Some(property_index) = table_headers.iter().position(|cell| cell == "Property") else {
            continue;
        };
        let Some(source_index) = table_headers
            .iter()
            .position(|cell| cell == "Source" || cell.starts_with("Source "))
        else {
            continue;
        };
        let Some(rust_index) = table_headers
            .iter()
            .position(|cell| cell == "Rust path constrained")
        else {
            continue;
        };
        parsed.rows.push(MappingRow {
            section: section.clone(),
            property: strip_code_span(&cells[property_index]),
            source: strip_code_span(&cells[source_index]),
            rust_paths: cells[rust_index].clone(),
        });
    }
    parsed
}

fn validate_kani_crates(
    harnesses: &[KaniHarness],
    workspace_members: &BTreeSet<String>,
) -> Result<(), String> {
    for harness in harnesses {
        if !workspace_members.contains(&harness.crate_name) {
            return Err(format!(
                "Kani harness {} names non-workspace crate {}",
                harness.harness, harness.crate_name
            ));
        }
    }
    Ok(())
}

fn render_markdown(
    rows: &[CoverageRow],
    lanes: &[String],
    artifact_records: &[ArtifactRecord],
) -> String {
    let qualifiers = artifact_records
        .iter()
        .map(|artifact| (&artifact.id, &artifact.qualifiers))
        .collect::<BTreeMap<_, _>>();
    let mut output = String::from("| Surface");
    for lane in lanes {
        output.push_str(" | ");
        output.push_str(lane);
    }
    output.push_str(" |\n| ---");
    for _ in lanes {
        output.push_str(" | ---:");
    }
    output.push_str(" |\n");
    for row in rows {
        output.push_str("| `");
        output.push_str(&row.surface);
        output.push('`');
        for lane in lanes {
            output.push_str(" | ");
            match row.lanes.get(lane).map(BTreeSet::len).unwrap_or(0) {
                0 => output.push('-'),
                count => output.push_str(&count.to_string()),
            }
        }
        output.push_str(" |\n");
    }
    output.push_str("\n## Evidence Details\n\n");
    for row in rows {
        output.push_str("### `");
        output.push_str(&row.surface);
        output.push_str("`\n\n");
        for lane in lanes {
            let Some(artifacts) = row.lanes.get(lane).filter(|values| !values.is_empty()) else {
                continue;
            };
            output.push_str("**");
            output.push_str(lane);
            output.push_str("**\n\n");
            for artifact in artifacts {
                output.push_str("- `");
                output.push_str(artifact);
                output.push('`');
                if let Some(values) = qualifiers.get(artifact).filter(|values| !values.is_empty()) {
                    output.push_str(" (");
                    output.push_str(&render_qualifiers(values));
                    output.push(')');
                }
                output.push('\n');
            }
            output.push('\n');
        }
    }
    output
}

fn render_qualifiers(qualifiers: &BTreeMap<String, String>) -> String {
    qualifiers
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn markdown_cells(line: &str) -> Vec<String> {
    line.trim_matches('|')
        .split('|')
        .map(|cell| cell.trim().to_string())
        .collect()
}

fn separator_cells(cells: &[String]) -> bool {
    !cells.is_empty()
        && cells.iter().all(|cell| {
            let trimmed = cell.trim_matches(':');
            trimmed.len() >= 3 && trimmed.bytes().all(|byte| byte == b'-')
        })
}

fn strip_code_span(value: &str) -> String {
    value
        .strip_prefix('`')
        .and_then(|inner| inner.strip_suffix('`'))
        .unwrap_or(value)
        .to_string()
}

fn parse_toml<T>(path: &str, raw: &str) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    toml::from_str(raw).map_err(|error| format!("cannot parse {path}: {error}"))
}

fn read_input(
    root: &Path,
    relative: &str,
    inputs: &mut BTreeMap<String, String>,
) -> Result<String, String> {
    let path = normalized_repo_path(relative)?;
    let bytes =
        fs::read(root.join(&path)).map_err(|error| format!("cannot read {path}: {error}"))?;
    let raw = String::from_utf8(bytes.clone())
        .map_err(|error| format!("coverage input is not UTF-8 ({path}): {error}"))?;
    inputs.insert(path, sha256_hex(&bytes));
    Ok(raw)
}

fn normalized_repo_path(path: &str) -> Result<String, String> {
    let candidate = Path::new(path);
    if candidate.is_absolute()
        || candidate
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "path must be normalized and repository-relative: {path}"
        ));
    }
    Ok(candidate.to_string_lossy().replace('\\', "/"))
}

fn workspace_catalog(root: &Path) -> Result<WorkspaceCatalog, String> {
    let output = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(root)
        .output()
        .map_err(|error| format!("cannot run cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let metadata: CargoMetadata = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("cannot parse cargo metadata: {error}"))?;
    let workspace_ids = metadata
        .workspace_members
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut projection = Vec::new();
    for package in metadata.packages {
        if !workspace_ids.contains(&package.id) {
            continue;
        }
        let manifest = Path::new(&package.manifest_path);
        let relative_manifest = manifest.strip_prefix(root).map_err(|_| {
            format!(
                "workspace package manifest is outside the repository: {}",
                package.manifest_path
            )
        })?;
        let Some(package_root) = relative_manifest.parent() else {
            return Err(format!(
                "workspace package manifest has no parent: {}",
                package.manifest_path
            ));
        };
        let mut lib_names = package
            .targets
            .iter()
            .filter(|target| target.kind.iter().any(|kind| kind == "lib"))
            .map(|target| target.name.clone())
            .collect::<Vec<_>>();
        lib_names.sort();
        lib_names.dedup();
        projection.push(WorkspacePackage {
            name: package.name,
            root: package_root.to_string_lossy().replace('\\', "/"),
            lib_names,
        });
    }
    projection.sort_by(|left, right| left.name.cmp(&right.name));
    let projection_bytes = serde_json::to_vec(&projection)
        .map_err(|error| format!("cannot render workspace metadata projection: {error}"))?;
    let projection_sha256 = sha256_hex(&projection_bytes);
    let mut packages = BTreeMap::new();
    let mut lib_to_package = BTreeMap::new();
    for package in projection {
        for namespace in package
            .lib_names
            .iter()
            .cloned()
            .chain([package.name.replace('-', "_")])
        {
            if let Some(previous) = lib_to_package.insert(namespace.clone(), package.name.clone()) {
                if previous != package.name {
                    return Err(format!(
                        "Rust namespace {namespace} is ambiguous between {previous} and {}",
                        package.name
                    ));
                }
            }
        }
        if packages.insert(package.name.clone(), package).is_some() {
            return Err("duplicate workspace package name".to_string());
        }
    }
    Ok(WorkspaceCatalog {
        packages,
        lib_to_package,
        projection_sha256,
    })
}

fn property_ids(manifest: &ProofManifest) -> Result<BTreeSet<String>, String> {
    let mut properties = BTreeSet::new();
    for encoded in &manifest.property_matrix {
        let parts = encoded.split('|').collect::<Vec<_>>();
        if parts.len() != 4 || parts[0].is_empty() {
            return Err(format!("invalid property_matrix row: {encoded}"));
        }
        if !properties.insert(parts[0].to_string()) {
            return Err(format!("duplicate property_matrix id: {}", parts[0]));
        }
    }
    let required = manifest
        .required_property_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if properties != required {
        return Err(format!(
            "property_matrix ids do not match required_property_ids: matrix={properties:?} required={required:?}"
        ));
    }
    Ok(properties)
}

fn mirror_review_links(entries: &[MirrorEntry]) -> Result<Vec<ReviewLink>, String> {
    let mut pairs = BTreeSet::new();
    let mut links = Vec::with_capacity(entries.len());
    for entry in entries {
        let valid_relationship = matches!(
            (entry.model_kind.as_str(), entry.relationship.as_str()),
            ("lean", "transliteration")
                | ("lean", "abstraction_anchor")
                | ("tla", "abstraction_anchor")
        );
        if !valid_relationship {
            return Err(format!(
                "invalid mirror model kind or relationship: {} {}",
                entry.model_kind, entry.relationship
            ));
        }
        if entry.rust_symbols.is_empty() {
            return Err(format!(
                "mirror entry has no Rust symbols: {}",
                entry.rust_source
            ));
        }
        if !is_sha256(&entry.normalized_sha256) {
            return Err(format!(
                "mirror entry has invalid normalized_sha256: {}",
                entry.rust_source
            ));
        }
        let pair = (entry.rust_source.clone(), entry.model_file.clone());
        if !pairs.insert(pair) {
            return Err(format!(
                "duplicate mirror review link: {} and {}",
                entry.rust_source, entry.model_file
            ));
        }
        links.push(ReviewLink {
            id: format!(
                "formal/proof-manifest.toml::mirror::{}->{}",
                entry.rust_source, entry.model_file
            ),
            kind: "manual_mirror".to_string(),
            relationship: entry.relationship.clone(),
            source: entry.rust_source.clone(),
            target: entry.model_file.clone(),
            qualifiers: BTreeMap::from([
                ("model_kind".to_string(), entry.model_kind.clone()),
                (
                    "normalized_sha256".to_string(),
                    entry.normalized_sha256.clone(),
                ),
                ("rust_symbols".to_string(), entry.rust_symbols.join(",")),
            ]),
        });
    }
    Ok(links)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_theorem_properties(
    inventory: &TheoremInventory,
    property_ids: &BTreeSet<String>,
) -> Result<(), String> {
    let mut ids = BTreeSet::new();
    for theorem in inventory.assumptions.iter().chain(&inventory.theorems) {
        if !ids.insert(theorem.id.clone()) {
            return Err(format!("duplicate theorem inventory id: {}", theorem.id));
        }
        for property in &theorem.maps_to {
            if !property_ids.contains(property) {
                return Err(format!(
                    "theorem {} maps to unknown property {property}",
                    theorem.id
                ));
            }
        }
    }
    Ok(())
}

fn assumption_summaries(registry: &AssumptionRegistry) -> Result<Vec<AssumptionSummary>, String> {
    if registry.schema != "chio.formal-assumptions.v1" {
        return Err(format!(
            "unsupported assumption registry schema: {}",
            registry.schema
        ));
    }
    let active = encoded_ids(&registry.assumptions, 4, "assumptions")?;
    let retired = encoded_ids(&registry.retired_assumptions, 5, "retired_assumptions")?;
    let required = registry
        .required_assumption_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let retired_required = registry
        .retired_assumption_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if active != required {
        return Err("active assumption rows do not match required_assumption_ids".to_string());
    }
    if retired != retired_required {
        return Err("retired assumption rows do not match retired_assumption_ids".to_string());
    }
    let mut summaries = active
        .into_iter()
        .map(|id| AssumptionSummary {
            id,
            status: "required".to_string(),
        })
        .chain(retired.into_iter().map(|id| AssumptionSummary {
            id,
            status: "retired".to_string(),
        }))
        .collect::<Vec<_>>();
    summaries.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(summaries)
}

fn encoded_ids(rows: &[String], fields: usize, label: &str) -> Result<BTreeSet<String>, String> {
    let mut ids = BTreeSet::new();
    for row in rows {
        let parts = row.split('|').collect::<Vec<_>>();
        if parts.len() != fields || parts[0].is_empty() {
            return Err(format!("invalid {label} row: {row}"));
        }
        if !ids.insert(parts[0].to_string()) {
            return Err(format!("duplicate {label} id: {}", parts[0]));
        }
    }
    Ok(ids)
}

fn reject_duplicate_harnesses(harnesses: &[KaniHarness]) -> Result<(), String> {
    let mut ids = BTreeSet::new();
    for harness in harnesses {
        let id = format!("{}/{}", harness.crate_name, harness.harness);
        if !ids.insert(id.clone()) {
            return Err(format!("duplicate Kani harness: {id}"));
        }
    }
    Ok(())
}

fn crate_surface(crate_name: &str) -> String {
    format!("{crate_name}::*")
}

fn ensure_row(rows: &mut BTreeMap<String, CoverageRow>, surface: &str) {
    rows.entry(surface.to_string())
        .or_insert_with(|| CoverageRow {
            surface: surface.to_string(),
            lanes: BTreeMap::new(),
        });
}

fn add_artifact(
    rows: &mut BTreeMap<String, CoverageRow>,
    artifacts: &mut BTreeMap<String, ArtifactRecord>,
    id: String,
    lane: &str,
    primary_surface: String,
    mut related_surfaces: Vec<String>,
) -> Result<(), String> {
    if artifacts.contains_key(&id) {
        return Err(format!("duplicate coverage artifact id: {id}"));
    }
    related_surfaces.retain(|surface| surface != &primary_surface);
    related_surfaces.sort();
    related_surfaces.dedup();
    ensure_row(rows, &primary_surface);
    let Some(row) = rows.get_mut(&primary_surface) else {
        return Err(format!("coverage row disappeared: {primary_surface}"));
    };
    row.lanes
        .entry(lane.to_string())
        .or_default()
        .insert(id.clone());
    artifacts.insert(
        id.clone(),
        ArtifactRecord {
            id,
            lane: lane.to_string(),
            primary_surface,
            related_surfaces,
            qualifiers: BTreeMap::new(),
        },
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn add_or_unattribute(
    rows: &mut BTreeMap<String, CoverageRow>,
    artifacts: &mut BTreeMap<String, ArtifactRecord>,
    unattributed: &mut Vec<UnattributedArtifact>,
    id: String,
    lane: &str,
    mut surfaces: Vec<String>,
    reason: &str,
    related_properties: Vec<String>,
) -> Result<(), String> {
    surfaces.sort();
    surfaces.dedup();
    let candidates = conservative_primary_candidates(&surfaces);
    if candidates.is_empty() {
        let reason = if surface_packages(&surfaces).len() > 1 {
            "evidence spans multiple Rust packages without a primary surface"
        } else {
            reason
        };
        unattributed.push(UnattributedArtifact {
            id,
            lane: lane.to_string(),
            reason: reason.to_string(),
            related_properties,
            related_surfaces: surfaces,
            qualifiers: BTreeMap::new(),
        });
        Ok(())
    } else {
        let primary = candidates[0].clone();
        add_artifact(rows, artifacts, id, lane, primary, surfaces)
    }
}

fn surface_packages(surfaces: &[String]) -> BTreeSet<String> {
    surfaces
        .iter()
        .filter_map(|surface| {
            surface
                .split_once("::")
                .map(|(package, _)| package.to_string())
        })
        .collect()
}

fn conservative_primary_candidates(surfaces: &[String]) -> Vec<String> {
    let unique = surfaces.iter().cloned().collect::<BTreeSet<_>>();
    if unique.len() == 1 {
        return unique.into_iter().collect();
    }
    let packages = surface_packages(&unique.iter().cloned().collect::<Vec<_>>());
    if packages.len() == 1 {
        return packages
            .into_iter()
            .map(|package| crate_surface(&package))
            .collect();
    }
    Vec::new()
}

fn conservative_harness_attribution(
    mut surfaces: Vec<String>,
    fallback: String,
) -> (String, Vec<String>) {
    surfaces.sort();
    surfaces.dedup();
    let candidates = conservative_primary_candidates(&surfaces);
    let primary = candidates.into_iter().next().unwrap_or(fallback);
    (primary, surfaces)
}

fn surface_from_repo_path(
    relative: &str,
    workspace: &WorkspaceCatalog,
    file_specific: bool,
) -> Result<String, String> {
    let path = normalized_repo_path(relative)?;
    let owner = workspace
        .packages
        .values()
        .filter(|package| Path::new(&path).starts_with(&package.root))
        .max_by_key(|package| Path::new(&package.root).components().count())
        .ok_or_else(|| format!("Rust path is not owned by a workspace package: {path}"))?;
    if !file_specific
        || Path::new(&path)
            .extension()
            .and_then(|value| value.to_str())
            != Some("rs")
    {
        return Ok(crate_surface(&owner.name));
    }
    let package_relative = Path::new(&path)
        .strip_prefix(&owner.root)
        .map_err(|_| format!("cannot relativize {path} against {}", owner.root))?;
    let display_relative = package_relative
        .strip_prefix("src")
        .unwrap_or(package_relative)
        .to_string_lossy()
        .replace('\\', "/");
    Ok(format!("{}::{display_relative}", owner.name))
}

fn surface_from_symbol(symbol: &str, root: &Path, workspace: &WorkspaceCatalog) -> Option<String> {
    let namespace = symbol.split("::").next()?;
    let package_name = workspace.lib_to_package.get(namespace)?;
    let package = workspace.packages.get(package_name)?;
    let mut segments = symbol.split("::");
    let _namespace = segments.next()?;
    let module = segments.next();
    if let Some(module) = module {
        let direct = format!("{}/src/{module}.rs", package.root);
        if root.join(&direct).is_file() {
            return surface_from_repo_path(&direct, workspace, true).ok();
        }
        let nested = format!("{}/src/{module}/mod.rs", package.root);
        if root.join(&nested).is_file() {
            return surface_from_repo_path(&nested, workspace, true).ok();
        }
    }
    Some(crate_surface(package_name))
}

fn validate_mapping_source(
    row: &MappingRow,
    root: &Path,
    inputs: &mut BTreeMap<String, String>,
) -> Result<MappingSource, String> {
    let explicit = code_spans(&row.source)
        .into_iter()
        .find(|candidate| candidate.contains('/') && Path::new(candidate).extension().is_some());
    let path = match explicit {
        Some(path) => path,
        None if row.section.starts_with("Kani public harnesses") => {
            "crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs".to_string()
        }
        None => {
            return Err(format!(
                "MAPPING row has no source path: {}/{}",
                row.section, row.property
            ))
        }
    };
    let path = normalized_repo_path(&path)?;
    let raw = read_input(root, &path, inputs)?;
    if !source_defines_property(&path, &raw, &row.property) {
        return Err(format!(
            "MAPPING source does not define property {}: {path}",
            row.property
        ));
    }
    let lane = if path.starts_with("formal/tla/") || path.starts_with("formal/apalache/") {
        if Path::new(&path)
            .extension()
            .and_then(|value| value.to_str())
            != Some("tla")
        {
            return Err(format!("MAPPING TLA source has wrong extension: {path}"));
        }
        Some("tla".to_string())
    } else if path.starts_with("formal/lean4/") {
        if Path::new(&path)
            .extension()
            .and_then(|value| value.to_str())
            != Some("lean")
        {
            return Err(format!("MAPPING Lean source has wrong extension: {path}"));
        }
        Some("lean".to_string())
    } else if Path::new(&path)
        .extension()
        .and_then(|value| value.to_str())
        == Some("rs")
    {
        None
    } else {
        return Err(format!("unsupported MAPPING source: {path}"));
    };
    Ok(MappingSource { lane })
}

fn source_defines_property(path: &str, raw: &str, property: &str) -> bool {
    match Path::new(path).extension().and_then(|value| value.to_str()) {
        Some("tla") => raw.lines().any(|line| {
            line.trim_start()
                .strip_prefix(property)
                .is_some_and(|rest| rest.trim_start().starts_with("=="))
        }),
        Some("lean") => ["theorem", "lemma", "def", "axiom"]
            .iter()
            .any(|kind| raw.contains(&format!("{kind} {property}"))),
        Some("rs") => raw.contains(&format!("fn {property}")),
        _ => false,
    }
}

fn surfaces_from_mapping(
    rust_cell: &str,
    root: &Path,
    workspace: &WorkspaceCatalog,
) -> Result<MappingSurfaceResolution, String> {
    let mut surfaces = BTreeSet::new();
    let mut unresolved = BTreeSet::new();
    let mut namespace_prefix: Option<String> = None;
    for code in code_spans(rust_cell) {
        if let Some(start) = code.find("crates/") {
            let candidate = &code[start..];
            let path = if let Some(end) = candidate.find(".rs") {
                &candidate[..end + 3]
            } else {
                candidate
                    .split(|character: char| {
                        character.is_whitespace() || matches!(character, ',' | '(' | ')')
                    })
                    .next()
                    .unwrap_or(candidate)
            };
            let path = path.trim_end_matches([':', ';']);
            let normalized = normalized_repo_path(path)?;
            if !root.join(&normalized).is_file() {
                unresolved.insert(normalized);
                continue;
            }
            if let Ok(surface) = surface_from_repo_path(&normalized, workspace, true) {
                surfaces.insert(surface);
            } else {
                unresolved.insert(normalized);
            }
            continue;
        }
        let symbol = if workspace
            .lib_to_package
            .contains_key(code.split("::").next().unwrap_or_default())
        {
            let segments = code.split("::").collect::<Vec<_>>();
            if segments.len() > 2 {
                namespace_prefix = Some(segments[..segments.len() - 1].join("::"));
            }
            code.clone()
        } else if code.contains("::") {
            match &namespace_prefix {
                Some(prefix) => format!("{prefix}::{code}"),
                None => {
                    unresolved.insert(code);
                    continue;
                }
            }
        } else {
            continue;
        };
        if let Some(surface) = surface_from_symbol(&symbol, root, workspace) {
            surfaces.insert(surface);
        } else {
            unresolved.insert(symbol);
        }
    }
    Ok(MappingSurfaceResolution {
        surfaces: surfaces.into_iter().collect(),
        unresolved: unresolved.into_iter().collect(),
    })
}

fn code_spans(value: &str) -> Vec<String> {
    let mut spans = value
        .split('`')
        .skip(1)
        .step_by(2)
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if spans.is_empty() {
        spans.push(value.trim().to_string());
    }
    spans
}

fn workspace_rust_files(root: &Path) -> Result<Vec<String>, String> {
    let output = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .current_dir(root)
        .output()
        .map_err(|error| format!("cannot list workspace files: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mut files = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| {
            std::str::from_utf8(path)
                .map_err(|error| format!("workspace path is not UTF-8: {error}"))
                .and_then(normalized_repo_path)
        })
        .collect::<Result<Vec<_>, _>>()?;
    files.retain(|path| Path::new(path).extension().and_then(|value| value.to_str()) == Some("rs"));
    files.sort();
    files.dedup();
    Ok(files)
}

fn glob_segment_matches(pattern: &str, name: &str) -> bool {
    let parts = pattern.split('*').collect::<Vec<_>>();
    if parts.len() == 1 {
        return pattern == name;
    }
    let mut cursor = 0usize;
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if index == 0 {
            if !name[cursor..].starts_with(part) {
                return false;
            }
            cursor += part.len();
        } else if index == parts.len() - 1 {
            if !name[cursor..].ends_with(part) {
                return false;
            }
        } else if let Some(found) = name[cursor..].find(part) {
            cursor += found + part.len();
        } else {
            return false;
        }
    }
    true
}

fn path_glob_matches(pattern: &str, path: &str) -> bool {
    fn matches_components(pattern: &[&str], path: &[&str]) -> bool {
        let Some((head, tail)) = pattern.split_first() else {
            return path.is_empty();
        };
        if *head == "**" {
            return (0..=path.len()).any(|skip| matches_components(tail, &path[skip..]));
        }
        let Some((path_head, path_tail)) = path.split_first() else {
            return false;
        };
        glob_segment_matches(head, path_head) && matches_components(tail, path_tail)
    }

    matches_components(
        &pattern.split('/').collect::<Vec<_>>(),
        &path.split('/').collect::<Vec<_>>(),
    )
}

fn expand_mutation_globs(
    globs: &[String],
    tracked_files: &[String],
) -> Result<BTreeSet<String>, String> {
    expand_globs(globs, tracked_files, true)
}

fn expand_globs(
    globs: &[String],
    tracked_files: &[String],
    require_each_match: bool,
) -> Result<BTreeSet<String>, String> {
    let mut expanded = BTreeSet::new();
    for glob in globs {
        let pattern = normalized_repo_path(glob)?;
        if pattern.contains(['?', '[', ']']) {
            return Err(format!("unsupported mutation glob syntax: {glob}"));
        }
        let matches = tracked_files
            .iter()
            .filter(|path| path_glob_matches(&pattern, path))
            .cloned()
            .collect::<Vec<_>>();
        if require_each_match && matches.is_empty() {
            return Err(format!(
                "mutation glob matches no workspace Rust file: {glob}"
            ));
        }
        expanded.extend(matches);
    }
    Ok(expanded)
}

fn effective_mutation_files(
    config: &MutationConfig,
    tracked_files: &[String],
) -> Result<BTreeSet<String>, String> {
    let examined = expand_mutation_globs(&config.examine_globs, tracked_files)?;
    let excluded = expand_globs(&config.exclude_globs, tracked_files, false)?;
    let effective = examined
        .difference(&excluded)
        .cloned()
        .collect::<BTreeSet<_>>();
    if effective.is_empty() {
        return Err("mutation config has no effective workspace Rust files".to_string());
    }
    Ok(effective)
}

fn package_for_path<'a>(
    path: &str,
    workspace: &'a WorkspaceCatalog,
) -> Result<&'a WorkspacePackage, String> {
    workspace
        .packages
        .values()
        .filter(|package| Path::new(path).starts_with(&package.root))
        .max_by_key(|package| Path::new(&package.root).components().count())
        .ok_or_else(|| format!("Rust path is not owned by a workspace package: {path}"))
}

fn package_for_globs(
    config: &MutationConfig,
    tracked_files: &[String],
    workspace: &WorkspaceCatalog,
) -> Result<(String, Vec<String>, BTreeSet<String>), String> {
    let matches = effective_mutation_files(config, tracked_files)?;
    let mut packages = BTreeSet::new();
    let mut related = BTreeSet::new();
    for path in &matches {
        let owner = package_for_path(path, workspace)?;
        packages.insert(owner.name.clone());
        related.insert(surface_from_repo_path(path, workspace, true)?);
    }
    if packages.len() != 1 {
        return Err(format!(
            "mutation config spans multiple packages: {packages:?}"
        ));
    }
    let Some(package) = packages.into_iter().next() else {
        return Err("mutation config contains no examine_globs".to_string());
    };
    Ok((package, related.into_iter().collect(), matches))
}

fn add_kani_artifacts(
    root: &Path,
    workspace: &WorkspaceCatalog,
    harnesses: &[KaniHarness],
    mapping_surfaces: &BTreeMap<String, Vec<String>>,
    rows: &mut BTreeMap<String, CoverageRow>,
    artifacts: &mut BTreeMap<String, ArtifactRecord>,
) -> Result<(), String> {
    for harness in harnesses {
        if !matches!(harness.lane.as_str(), "pr" | "nightly") {
            return Err(format!(
                "Kani harness {} has unsupported lane {}",
                harness.harness, harness.lane
            ));
        }
        let surfaces = mapping_surfaces
            .get(&harness.harness)
            .cloned()
            .unwrap_or_default();
        let fallback = infer_harness_surface(harness, root, workspace);
        let (primary, related) = if let Some(symbol) = &harness.primary_rust_symbol {
            let primary = surface_from_symbol(symbol, root, workspace).ok_or_else(|| {
                format!(
                    "Kani harness {} has an unresolved primary_rust_symbol: {symbol}",
                    harness.harness
                )
            })?;
            if !surfaces.contains(&primary) {
                return Err(format!(
                    "Kani harness {} primary_rust_symbol is absent from its MAPPING surfaces: {symbol}",
                    harness.harness
                ));
            }
            (primary, surfaces)
        } else {
            conservative_harness_attribution(surfaces, fallback)
        };
        let id = format!(
            ".kani/harnesses.toml::{}/{}",
            harness.crate_name, harness.harness
        );
        add_artifact(rows, artifacts, id.clone(), "kani", primary, related)?;
        let Some(artifact) = artifacts.get_mut(&id) else {
            return Err(format!("Kani artifact disappeared: {id}"));
        };
        artifact
            .qualifiers
            .insert("execution_lane".to_string(), harness.lane.clone());
        if harness.notes.to_ascii_uppercase().contains("MODEL-ONLY") {
            artifact
                .qualifiers
                .insert("scope".to_string(), "model-only".to_string());
        }
    }
    Ok(())
}

fn infer_harness_surface(
    harness: &KaniHarness,
    root: &Path,
    workspace: &WorkspaceCatalog,
) -> String {
    let module = if harness.crate_name == "chio-kernel-core"
        && matches!(
            harness.harness.as_str(),
            "public_sign_receipt_accepts_matching_content_hash"
                | "public_sign_receipt_refuses_content_hash_mismatch"
        ) {
        Some("receipts")
    } else {
        None
    };
    if let (Some(module), Some(package)) = (module, workspace.packages.get(&harness.crate_name)) {
        let path = format!("{}/src/{module}.rs", package.root);
        if root.join(&path).is_file() {
            if let Ok(surface) = surface_from_repo_path(&path, workspace, true) {
                return surface;
            }
        }
    }
    crate_surface(&harness.crate_name)
}

#[allow(clippy::too_many_arguments)]
fn add_refinement_artifacts(
    root: &Path,
    workspace: &WorkspaceCatalog,
    manifest: &ProofManifest,
    flat_harnesses: &[KaniHarness],
    inputs: &mut BTreeMap<String, String>,
    rows: &mut BTreeMap<String, CoverageRow>,
    artifacts: &mut BTreeMap<String, ArtifactRecord>,
    unattributed: &mut Vec<UnattributedArtifact>,
    review_links: &mut Vec<ReviewLink>,
) -> Result<(), String> {
    for encoded in &manifest.rust_refinement_lanes {
        let parts = encoded.split('|').collect::<Vec<_>>();
        if parts.len() != 3 {
            return Err(format!("invalid rust_refinement_lanes row: {encoded}"));
        }
        let lane = parts[0];
        let posture = parts[1];
        let path = normalized_repo_path(parts[2])?;
        let expected_schema = expected_refinement_schema(lane, posture, &path)?;
        let raw = read_input(root, &path, inputs)?;
        let value: TomlValue = parse_toml(&path, &raw)?;
        let schema = value
            .get("schema")
            .and_then(TomlValue::as_str)
            .ok_or_else(|| format!("refinement manifest has no schema: {path}"))?;
        if schema != expected_schema {
            return Err(format!(
                "unsupported refinement manifest schema in {path}: expected={expected_schema} actual={schema}"
            ));
        }
        if path.ends_with("kani-public-harnesses.toml") {
            validate_legacy_kani_alias(&value, flat_harnesses)?;
        }
        if lane == "kani" {
            for symbol in required_toml_string_array(&value, "covered_symbols", &path)? {
                if surface_from_symbol(&symbol, root, workspace).is_none() {
                    return Err(format!(
                        "Kani covered symbol has no workspace surface in {path}: {symbol}"
                    ));
                }
            }
        } else if lane == "creusot" {
            let covered_symbols = required_toml_string_array(&value, "covered_symbols", &path)?;
            for symbol in &covered_symbols {
                let id = format!("{path}::{symbol}");
                let surfaces = surface_from_symbol(symbol, root, workspace)
                    .into_iter()
                    .collect::<Vec<_>>();
                add_or_unattribute(
                    rows,
                    artifacts,
                    unattributed,
                    id,
                    lane,
                    surfaces,
                    "refinement symbol has no workspace surface",
                    Vec::new(),
                )?;
            }
            review_links.extend(contract_twin_review_links(&value, &path, &covered_symbols)?);
            for (index, goal) in required_toml_string_array(&value, "contract_goals", &path)?
                .into_iter()
                .enumerate()
            {
                unattributed.push(UnattributedArtifact {
                    id: format!("{path}::goal-{}:{goal}", index + 1),
                    lane: lane.to_string(),
                    reason: "registry does not link this goal to one covered symbol".to_string(),
                    related_properties: Vec::new(),
                    related_surfaces: Vec::new(),
                    qualifiers: BTreeMap::new(),
                });
            }
        } else if lane == "aeneas" {
            for (source, extracted) in aeneas_extracted_symbols_by_source(&value, &path)? {
                let normalized = normalized_repo_path(&source)?;
                let _source_raw = read_input(root, &normalized, inputs)?;
                let surface = surface_from_repo_path(&normalized, workspace, true).ok();
                for symbol in extracted {
                    let id = format!("{path}::{symbol}");
                    if let Some(surface) = surface.clone() {
                        add_artifact(rows, artifacts, id, lane, surface, Vec::new())?;
                    } else {
                        unattributed.push(UnattributedArtifact {
                            id,
                            lane: lane.to_string(),
                            reason: "extraction source is not a workspace Rust surface".to_string(),
                            related_properties: Vec::new(),
                            related_surfaces: Vec::new(),
                            qualifiers: BTreeMap::new(),
                        });
                    }
                }
            }
        } else {
            return Err(format!("unsupported refinement lane in {path}: {lane}"));
        }
    }
    Ok(())
}

fn aeneas_extracted_symbols(value: &TomlValue, path: &str) -> Result<Vec<String>, String> {
    if path != "formal/aeneas/production.toml" {
        return required_toml_string_array(value, "extracted_symbols", path);
    }

    let targets = value
        .get("targets")
        .and_then(TomlValue::as_array)
        .ok_or_else(|| format!("Aeneas production manifest has no targets: {path}"))?;
    if targets.is_empty() {
        return Err(format!(
            "Aeneas production manifest has empty targets: {path}"
        ));
    }

    let mut names = BTreeSet::new();
    let mut symbols = BTreeSet::new();
    let mut extracted = Vec::new();
    for target in targets {
        let name = target
            .get("name")
            .and_then(TomlValue::as_str)
            .ok_or_else(|| format!("Aeneas production target has no name: {path}"))?;
        if !names.insert(name.to_string()) {
            return Err(format!(
                "Aeneas production manifest has duplicate target {name}: {path}"
            ));
        }
        if target.get("status").and_then(TomlValue::as_str) != Some("generated_equivalence") {
            return Err(format!(
                "Aeneas production target is not equivalence-checked: {path}::{name}"
            ));
        }

        let functions = required_toml_string_array(target, "functions", path)?;
        let theorem_rows = required_toml_string_array(target, "equivalence_theorems", path)?;
        let mut theorem_symbols = BTreeSet::new();
        for row in theorem_rows {
            let Some((symbol, theorem)) = row.split_once('|') else {
                return Err(format!(
                    "Aeneas production target has malformed theorem row: {path}::{name}::{row}"
                ));
            };
            if symbol.is_empty()
                || theorem.is_empty()
                || !theorem_symbols.insert(symbol.to_string())
            {
                return Err(format!(
                    "Aeneas production target has invalid theorem row: {path}::{name}::{row}"
                ));
            }
        }
        let function_symbols = functions.iter().cloned().collect::<BTreeSet<_>>();
        if function_symbols != theorem_symbols {
            return Err(format!(
                "Aeneas production target theorem inventory mismatch: {path}::{name}"
            ));
        }
        for function in functions {
            if !symbols.insert(function.clone()) {
                return Err(format!(
                    "Aeneas production manifest has duplicate function {function}: {path}"
                ));
            }
            extracted.push(function);
        }
    }
    Ok(extracted)
}

fn aeneas_extracted_symbols_by_source(
    value: &TomlValue,
    path: &str,
) -> Result<Vec<(String, Vec<String>)>, String> {
    let extracted = aeneas_extracted_symbols(value, path)?;
    if path != "formal/aeneas/production.toml" {
        let source = value
            .get("source")
            .and_then(TomlValue::as_str)
            .ok_or_else(|| format!("Aeneas manifest has no source: {path}"))?;
        return Ok(vec![(source.to_string(), extracted)]);
    }

    let sources = value
        .get("sources")
        .and_then(TomlValue::as_array)
        .ok_or_else(|| format!("Aeneas production manifest has no sources: {path}"))?;
    if sources.is_empty() {
        return Err(format!(
            "Aeneas production manifest has empty sources: {path}"
        ));
    }

    let mut source_paths = BTreeMap::new();
    for source in sources {
        let id = source
            .get("id")
            .and_then(TomlValue::as_str)
            .ok_or_else(|| format!("Aeneas production source has no id: {path}"))?;
        let source_path = source
            .get("path")
            .and_then(TomlValue::as_str)
            .ok_or_else(|| format!("Aeneas production source has no path: {path}::{id}"))?;
        if source_paths
            .insert(id.to_string(), (source_path.to_string(), Vec::new()))
            .is_some()
        {
            return Err(format!(
                "Aeneas production manifest has duplicate source {id}: {path}"
            ));
        }
    }

    let targets = value
        .get("targets")
        .and_then(TomlValue::as_array)
        .ok_or_else(|| format!("Aeneas production manifest has no targets: {path}"))?;
    for target in targets {
        let name = target
            .get("name")
            .and_then(TomlValue::as_str)
            .unwrap_or("<unnamed>");
        let source_id = target
            .get("source")
            .and_then(TomlValue::as_str)
            .ok_or_else(|| format!("Aeneas production target has no source: {path}::{name}"))?;
        let (_, symbols) = source_paths.get_mut(source_id).ok_or_else(|| {
            format!("Aeneas production target has unknown source: {path}::{name}::{source_id}")
        })?;
        symbols.extend(required_toml_string_array(target, "functions", path)?);
    }

    let attributed = source_paths
        .values()
        .map(|(_, symbols)| symbols.len())
        .sum::<usize>();
    if attributed != extracted.len() {
        return Err(format!(
            "Aeneas production source attribution is incomplete: {path}"
        ));
    }
    Ok(source_paths.into_values().collect())
}

fn contract_twin_review_links(
    value: &TomlValue,
    path: &str,
    covered_symbols: &[String],
) -> Result<Vec<ReviewLink>, String> {
    const CONTRACT_PREFIX: &str = "formal/rust-verification/creusot-core::";

    let raw_twins = value
        .get("contract_twin")
        .cloned()
        .ok_or_else(|| format!("refinement manifest has no contract_twin: {path}"))?;
    let twins: Vec<ContractTwin> = raw_twins
        .try_into()
        .map_err(|error| format!("invalid contract_twin entries in {path}: {error}"))?;
    if twins.is_empty() {
        return Err(format!(
            "refinement manifest has empty contract_twin: {path}"
        ));
    }

    let mut contracts = BTreeSet::new();
    let mut productions = BTreeSet::new();
    for twin in &twins {
        if !twin.contract.ends_with("_contract") || !is_rust_identifier(&twin.contract) {
            return Err(format!(
                "invalid Creusot contract twin name in {path}: {}",
                twin.contract
            ));
        }
        if !is_rust_identifier(&twin.production) {
            return Err(format!(
                "invalid Creusot production twin name in {path}: {}",
                twin.production
            ));
        }
        if !contracts.insert(twin.contract.clone()) {
            return Err(format!(
                "duplicate Creusot contract twin in {path}: {}",
                twin.contract
            ));
        }
        if !productions.insert(twin.production.clone()) {
            return Err(format!(
                "duplicate Creusot production twin in {path}: {}",
                twin.production
            ));
        }
    }

    let covered_contracts = covered_symbols
        .iter()
        .filter_map(|symbol| symbol.strip_prefix(CONTRACT_PREFIX))
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    if contracts != covered_contracts {
        return Err(format!(
            "Creusot contract_twin names do not match covered_symbols in {path}: twins={contracts:?} covered={covered_contracts:?}"
        ));
    }

    let mut links = twins
        .into_iter()
        .map(|twin| ReviewLink {
            id: format!("{path}::contract_twin::{}", twin.contract),
            kind: "creusot_contract_twin".to_string(),
            relationship: "single_sourced_body".to_string(),
            source: format!(
                "crates/kernel/chio-kernel-core/src/formal_aeneas.rs::{}",
                twin.production
            ),
            target: format!(
                "formal/rust-verification/creusot-core/src/lib.rs::{}",
                twin.contract
            ),
            qualifiers: BTreeMap::new(),
        })
        .collect::<Vec<_>>();
    links.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(links)
}

fn is_rust_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn expected_refinement_schema(
    lane: &str,
    posture: &str,
    path: &str,
) -> Result<&'static str, String> {
    match (lane, posture, path) {
        ("creusot", "required", "formal/rust-verification/creusot-contracts.toml") => {
            Ok("chio.creusot-contracts.v1")
        }
        ("kani", "required", "formal/rust-verification/kani-harnesses.toml") => {
            Ok("chio.kani-harnesses.v1")
        }
        ("kani", "required", "formal/rust-verification/kani-public-harnesses.toml") => {
            Ok("chio.kani-public-harnesses.v1")
        }
        ("aeneas", "pilot", "formal/aeneas/pilot.toml") => Ok("chio.aeneas-pilot.v1"),
        ("aeneas", "production", "formal/aeneas/production.toml") => {
            Ok("chio.aeneas-production.v1")
        }
        _ => Err(format!(
            "unsupported refinement registry declaration: {lane}|{posture}|{path}"
        )),
    }
}

fn validate_legacy_kani_alias(
    value: &TomlValue,
    flat_harnesses: &[KaniHarness],
) -> Result<(), String> {
    let crate_name = value
        .get("crate")
        .and_then(TomlValue::as_str)
        .ok_or_else(|| "legacy Kani manifest has no crate".to_string())?;
    let lanes = value
        .get("lanes")
        .and_then(TomlValue::as_table)
        .ok_or_else(|| "legacy Kani manifest has no lanes table".to_string())?;
    let mut legacy = BTreeSet::new();
    for lane in lanes.values() {
        for harness in lane
            .get("harnesses")
            .and_then(TomlValue::as_array)
            .into_iter()
            .flatten()
        {
            let Some(name) = harness.as_str() else {
                return Err("legacy Kani harness name is not a string".to_string());
            };
            legacy.insert(name.to_string());
        }
    }
    let flat = flat_harnesses
        .iter()
        .filter(|harness| harness.crate_name == crate_name)
        .map(|harness| harness.harness.clone())
        .collect::<BTreeSet<_>>();
    if legacy != flat {
        return Err(format!(
            "legacy Kani manifest disagrees with .kani/harnesses.toml for {crate_name}"
        ));
    }
    Ok(())
}

fn toml_string_array(value: &TomlValue, key: &str) -> Result<Vec<String>, String> {
    let Some(array) = value.get(key).and_then(TomlValue::as_array) else {
        return Ok(Vec::new());
    };
    array
        .iter()
        .map(|item| {
            item.as_str()
                .map(ToString::to_string)
                .ok_or_else(|| format!("{key} contains a non-string value"))
        })
        .collect()
}

fn required_toml_string_array(
    value: &TomlValue,
    key: &str,
    path: &str,
) -> Result<Vec<String>, String> {
    if value.get(key).is_none() {
        return Err(format!("refinement manifest has no {key}: {path}"));
    }
    let values = toml_string_array(value, key)?;
    if values.is_empty() {
        return Err(format!("refinement manifest has empty {key}: {path}"));
    }
    Ok(values)
}

fn add_fuzz_artifacts(
    root: &Path,
    workspace: &WorkspaceCatalog,
    fuzz_map: &FuzzMap,
    owners: &FuzzOwners,
    rows: &mut BTreeMap<String, CoverageRow>,
    artifacts: &mut BTreeMap<String, ArtifactRecord>,
) -> Result<(), String> {
    validate_fuzz_owner_keys(fuzz_map, owners)?;
    let mut source_paths = BTreeSet::new();
    for (name, target) in &fuzz_map.targets {
        if !workspace.packages.contains_key(&target.crate_name) {
            return Err(format!(
                "fuzz target {name} names non-workspace crate {}",
                target.crate_name
            ));
        }
        let source_path = normalized_repo_path(&target.path)?;
        if !root.join(&source_path).is_file() {
            return Err(format!("fuzz target source not found: {source_path}"));
        }
        if !source_paths.insert(source_path.clone()) {
            return Err(format!("multiple fuzz targets use source {source_path}"));
        }
        let owner = owners
            .targets
            .get(name)
            .ok_or_else(|| format!("fuzz target has no owner: {name}"))?;
        if owner.crate_name != target.crate_name {
            return Err(format!("fuzz owner crate mismatch for target {name}"));
        }
        let owner_path = normalized_repo_path(&owner.path)?;
        let package = workspace
            .packages
            .get(&owner.crate_name)
            .ok_or_else(|| format!("unknown fuzz owner crate: {}", owner.crate_name))?;
        if owner_path != package.root {
            return Err(format!("fuzz owner path mismatch for target {name}"));
        }
        let mut related = target
            .triggers
            .iter()
            .filter(|trigger| !trigger.contains('*'))
            .filter_map(|trigger| {
                let normalized = normalized_repo_path(trigger).ok()?;
                if root.join(&normalized).is_file()
                    && Path::new(&normalized)
                        .extension()
                        .and_then(|value| value.to_str())
                        == Some("rs")
                {
                    surface_from_repo_path(&normalized, workspace, true).ok()
                } else {
                    None
                }
            })
            .filter(|surface| surface.starts_with(&format!("{}::", target.crate_name)))
            .collect::<Vec<_>>();
        related.sort();
        related.dedup();
        let primary = if related.len() == 1 {
            related.remove(0)
        } else {
            crate_surface(&target.crate_name)
        };
        add_artifact(
            rows,
            artifacts,
            format!("fuzz/target-map.toml::{name}"),
            "fuzz",
            primary,
            related,
        )?;
    }
    Ok(())
}

fn validate_fuzz_owner_keys(fuzz_map: &FuzzMap, owners: &FuzzOwners) -> Result<(), String> {
    let targets = fuzz_map.targets.keys().cloned().collect::<BTreeSet<_>>();
    let owner_targets = owners.targets.keys().cloned().collect::<BTreeSet<_>>();
    if targets != owner_targets {
        let missing = targets
            .difference(&owner_targets)
            .cloned()
            .collect::<Vec<_>>();
        let stale = owner_targets
            .difference(&targets)
            .cloned()
            .collect::<Vec<_>>();
        return Err(format!(
            "fuzz owner keys do not match target map: missing={missing:?} stale={stale:?}"
        ));
    }
    Ok(())
}

fn files_in_dir(root: &Path, directory: &str, extension: &str) -> Result<Vec<String>, String> {
    let directory = normalized_repo_path(directory)?;
    let mut paths = Vec::new();
    for entry in fs::read_dir(root.join(&directory))
        .map_err(|error| format!("cannot read directory {directory}: {error}"))?
    {
        let entry = entry.map_err(|error| format!("cannot read {directory} entry: {error}"))?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|value| value.to_str()) == Some(extension) {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| format!("discovered path escaped repository: {}", path.display()))?;
            paths.push(relative.to_string_lossy().replace('\\', "/"));
        }
    }
    paths.sort();
    Ok(paths)
}

#[allow(clippy::too_many_arguments)]
fn add_mutant_artifacts(
    root: &Path,
    workspace: &WorkspaceCatalog,
    workspace_config: &MutationConfig,
    tracked_files: &[String],
    inputs: &mut BTreeMap<String, String>,
    rows: &mut BTreeMap<String, CoverageRow>,
    artifacts: &mut BTreeMap<String, ArtifactRecord>,
    unattributed: &mut Vec<UnattributedArtifact>,
    config_paths: &[String],
) -> Result<Vec<String>, String> {
    let workspace_matches = effective_mutation_files(workspace_config, tracked_files)?;
    let mut active_by_package = BTreeMap::<String, BTreeSet<String>>::new();
    for path in workspace_matches {
        let package = package_for_path(&path, workspace)?;
        active_by_package
            .entry(package.name.clone())
            .or_default()
            .insert(path);
    }
    for (package, files) in &active_by_package {
        let mut related = files
            .iter()
            .map(|path| surface_from_repo_path(path, workspace, true))
            .collect::<Result<Vec<_>, _>>()?;
        related.sort();
        related.dedup();
        let id = format!(".cargo/mutants.toml::{package}");
        add_artifact(
            rows,
            artifacts,
            id.clone(),
            "mutants",
            crate_surface(package),
            related,
        )?;
        let Some(artifact) = artifacts.get_mut(&id) else {
            return Err(format!("workspace mutation artifact disappeared: {id}"));
        };
        artifact
            .qualifiers
            .insert("scope".to_string(), "workspace-active".to_string());
    }
    let mut active_configs = Vec::new();
    for path in config_paths {
        let raw = read_input(root, path, inputs)?;
        let config: MutationConfig = parse_toml(path, &raw)?;
        let (package, related, matched_files) =
            package_for_globs(&config, tracked_files, workspace)?;
        if let Some(index) = config
            .additional_cargo_test_args
            .iter()
            .position(|argument| argument == "--package")
        {
            let declared = config
                .additional_cargo_test_args
                .get(index + 1)
                .ok_or_else(|| format!("mutation config has --package without a value: {path}"))?;
            if declared != &package {
                return Err(format!(
                    "mutation config package mismatch in {path}: declared={declared} paths={package}"
                ));
            }
        }
        let canonical_name =
            Path::new(path).file_stem().and_then(|value| value.to_str()) == Some(package.as_str());
        if !canonical_name {
            unattributed.push(UnattributedArtifact {
                id: path.clone(),
                lane: "mutants".to_string(),
                reason: "historical replay config is not a current mutation-lane declaration"
                    .to_string(),
                related_properties: Vec::new(),
                related_surfaces: related,
                qualifiers: BTreeMap::from([("status".to_string(), "historical".to_string())]),
            });
            continue;
        }
        let scope = if let Some(workspace_files) = active_by_package.get(&package) {
            if !matched_files.is_subset(workspace_files) {
                let stale = matched_files
                    .difference(workspace_files)
                    .cloned()
                    .collect::<Vec<_>>();
                return Err(format!(
                    "mutation config {path} names files outside the live workspace lane: {stale:?}"
                ));
            }
            if &matched_files == workspace_files {
                "workspace-exact"
            } else {
                "workspace-subset"
            }
        } else if mutation_evidence_references_config(root, &package, path, inputs)? {
            "recorded-local"
        } else {
            unattributed.push(UnattributedArtifact {
                id: path.clone(),
                lane: "mutants".to_string(),
                reason:
                    "mutation config has neither live workspace-lane scope nor recorded evidence"
                        .to_string(),
                related_properties: Vec::new(),
                related_surfaces: related,
                qualifiers: BTreeMap::from([("status".to_string(), "inactive".to_string())]),
            });
            continue;
        };
        let primary = crate_surface(&package);
        add_artifact(rows, artifacts, path.clone(), "mutants", primary, related)?;
        let Some(artifact) = artifacts.get_mut(path) else {
            return Err(format!("mutation artifact disappeared: {path}"));
        };
        artifact
            .qualifiers
            .insert("scope".to_string(), scope.to_string());
        active_configs.push(path.clone());
    }
    Ok(active_configs)
}

fn mutation_evidence_references_config(
    root: &Path,
    package: &str,
    config_path: &str,
    inputs: &mut BTreeMap<String, String>,
) -> Result<bool, String> {
    let directory = format!("audits/evidence/mutants/{package}");
    if !root.join(&directory).is_dir() {
        return Ok(false);
    }
    for path in files_in_dir(root, &directory, "json")? {
        let raw = read_input(root, &path, inputs)?;
        let evidence: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|error| format!("cannot parse mutation evidence {path}: {error}"))?;
        if mutation_evidence_is_complete(&evidence, package, config_path, &path)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn regular_mutation_input_bytes(root: &Path, relative: &str) -> Result<(String, Vec<u8>), String> {
    let path = normalized_repo_path(relative)?;
    if path.is_empty() {
        return Err("formal mutation input path is empty".to_string());
    }
    let absolute = root.join(&path);
    let mut component_path = root.to_path_buf();
    for component in Path::new(&path).components() {
        component_path.push(component.as_os_str());
        let component_metadata = fs::symlink_metadata(&component_path).map_err(|error| {
            format!("formal mutation input is not a repository file ({path}): {error}")
        })?;
        if component_metadata.file_type().is_symlink() {
            return Err(format!("formal mutation input traverses a symlink: {path}"));
        }
    }
    let metadata = fs::symlink_metadata(&absolute).map_err(|error| {
        format!("formal mutation input is not a repository file ({path}): {error}")
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "formal mutation input is not a non-symlink regular repository file: {path}"
        ));
    }
    let canonical_root = fs::canonicalize(root)
        .map_err(|error| format!("cannot resolve repository root: {error}"))?;
    let canonical_path = fs::canonicalize(&absolute)
        .map_err(|error| format!("cannot resolve formal mutation input {path}: {error}"))?;
    if canonical_path.strip_prefix(&canonical_root).is_err() {
        return Err(format!(
            "formal mutation input escapes the repository: {path}"
        ));
    }
    let bytes = fs::read(&absolute)
        .map_err(|error| format!("cannot read formal mutation input {path}: {error}"))?;
    Ok((path, bytes))
}

fn regular_mutation_input_text(root: &Path, relative: &str) -> Result<(String, String), String> {
    let (path, bytes) = regular_mutation_input_bytes(root, relative)?;
    let raw = String::from_utf8(bytes)
        .map_err(|error| format!("formal mutation input is not UTF-8 ({path}): {error}"))?;
    Ok((path, raw))
}

fn mutation_input_at_commit(root: &Path, commit: &str, relative: &str) -> Result<Vec<u8>, String> {
    let tree_entry = Command::new("git")
        .args(["ls-tree", "-z", "--full-tree", commit, "--", relative])
        .current_dir(root)
        .output()
        .map_err(|error| {
            format!("cannot inspect formal mutation evidence commit {commit}: {error}")
        })?;
    if !tree_entry.status.success() {
        return Err(format!(
            "cannot inspect formal mutation evidence commit {commit}: {}",
            String::from_utf8_lossy(&tree_entry.stderr).trim()
        ));
    }
    let entries = tree_entry
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>();
    if entries.len() != 1 {
        return Err(format!(
            "formal mutation evidence commit {commit} does not contain exactly one input entry for {relative}"
        ));
    }
    let entry = String::from_utf8(entries[0].to_vec()).map_err(|error| {
        format!("formal mutation evidence tree entry is not UTF-8 ({relative}): {error}")
    })?;
    let (metadata, path) = entry
        .split_once('\t')
        .ok_or_else(|| format!("formal mutation evidence tree entry is malformed: {relative}"))?;
    let fields = metadata.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 3
        || !matches!(fields[0], "100644" | "100755")
        || fields[1] != "blob"
        || fields[2].len() != 40
        || path != relative
    {
        return Err(format!(
            "formal mutation evidence commit {commit} input is not a regular file: {relative}"
        ));
    }
    let blob = Command::new("git")
        .args(["cat-file", "blob", fields[2]])
        .current_dir(root)
        .output()
        .map_err(|error| {
            format!("cannot read formal mutation evidence blob for {relative}: {error}")
        })?;
    if !blob.status.success() {
        return Err(format!(
            "cannot read formal mutation evidence blob for {relative}: {}",
            String::from_utf8_lossy(&blob.stderr).trim()
        ));
    }
    Ok(blob.stdout)
}

fn validate_mutation_evidence_commit(root: &Path, commit: &str) -> Result<(), String> {
    let object_type = Command::new("git")
        .args(["cat-file", "-t", commit])
        .current_dir(root)
        .output()
        .map_err(|error| {
            format!("cannot inspect formal mutation evidence object {commit}: {error}")
        })?;
    if !object_type.status.success() || object_type.stdout != b"commit\n" {
        return Err(format!(
            "formal mutation evidence object is not a commit: {commit}"
        ));
    }
    let ancestor = Command::new("git")
        .args(["merge-base", "--is-ancestor", commit, "HEAD"])
        .current_dir(root)
        .output()
        .map_err(|error| {
            format!("cannot verify formal mutation evidence ancestry for {commit}: {error}")
        })?;
    if !ancestor.status.success() {
        return Err(format!(
            "formal mutation evidence commit is not an ancestor of HEAD: {commit}"
        ));
    }
    Ok(())
}

fn insert_formal_mutation_input(
    root: &Path,
    relative: &str,
    expected: &mut BTreeMap<String, String>,
    coverage_inputs: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    let (path, bytes) = regular_mutation_input_bytes(root, relative)?;
    let digest = sha256_hex(&bytes);
    expected.insert(path.clone(), digest.clone());
    coverage_inputs.insert(path, digest);
    Ok(())
}

fn regular_files_in_directory(
    root: &Path,
    relative: &str,
    extension: &str,
    recursive: bool,
) -> Result<BTreeSet<String>, String> {
    fn visit(
        root: &Path,
        directory: &Path,
        extension: &str,
        recursive: bool,
        paths: &mut BTreeSet<String>,
    ) -> Result<(), String> {
        let metadata = fs::symlink_metadata(directory).map_err(|error| {
            format!(
                "cannot inspect formal mutation input directory {}: {error}",
                directory.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "formal mutation input directory is not a non-symlink directory: {}",
                directory.display()
            ));
        }
        let mut entries = fs::read_dir(directory)
            .map_err(|error| {
                format!(
                    "cannot read formal mutation input directory {}: {error}",
                    directory.display()
                )
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                format!(
                    "cannot read formal mutation input directory entry in {}: {error}",
                    directory.display()
                )
            })?;
        entries.sort_by_key(fs::DirEntry::path);
        for entry in entries {
            let absolute = entry.path();
            let entry_metadata = fs::symlink_metadata(&absolute).map_err(|error| {
                format!(
                    "cannot inspect formal mutation dependency {}: {error}",
                    absolute.display()
                )
            })?;
            if entry_metadata.file_type().is_symlink() {
                let matches_extension =
                    absolute.extension().and_then(|value| value.to_str()) == Some(extension);
                if matches_extension || recursive {
                    return Err(format!(
                        "formal mutation dependency is a symlink: {}",
                        absolute.display()
                    ));
                }
                continue;
            }
            if entry_metadata.is_dir() {
                if recursive {
                    visit(root, &absolute, extension, true, paths)?;
                }
                continue;
            }
            if !entry_metadata.is_file()
                || absolute.extension().and_then(|value| value.to_str()) != Some(extension)
            {
                continue;
            }
            let relative_path = absolute.strip_prefix(root).map_err(|_| {
                format!(
                    "formal mutation dependency escaped the repository: {}",
                    absolute.display()
                )
            })?;
            let relative_path = relative_path.to_str().ok_or_else(|| {
                format!(
                    "formal mutation dependency path is not UTF-8: {}",
                    absolute.display()
                )
            })?;
            paths.insert(normalized_repo_path(relative_path)?);
        }
        Ok(())
    }

    let directory = normalized_repo_path(relative)?;
    let mut paths = BTreeSet::new();
    visit(
        root,
        &root.join(directory),
        extension,
        recursive,
        &mut paths,
    )?;
    Ok(paths)
}

fn spec_mutation_input_registry(root: &Path) -> Result<SpecMutationInputRegistry, String> {
    const ALLOWLIST: &str = "formal/apalache/spec-mutants-allowlist.toml";
    let (_, allowlist_raw) = regular_mutation_input_text(root, ALLOWLIST)?;
    let allowlist: SpecMutationInputRegistry = parse_toml(ALLOWLIST, &allowlist_raw)?;
    if allowlist.schema != "chio.spec-mutants-allowlist.v1" || allowlist.spec.is_empty() {
        return Err(
            "spec mutation allowlist has an unsupported schema or no specifications".to_string(),
        );
    }
    Ok(allowlist)
}

fn spec_mutation_allowlist_specs(
    root: &Path,
) -> Result<BTreeMap<String, SpecMutationInputSpec>, String> {
    let allowlist = spec_mutation_input_registry(root)?;
    let mut specs = BTreeMap::new();
    let mut paths = BTreeSet::new();
    let mut cfgs = BTreeSet::new();
    for spec in allowlist.spec {
        let path = normalized_repo_path(&spec.path)?;
        let cfg = normalized_repo_path(&spec.cfg)?;
        if spec.name.is_empty()
            || !spec.name.chars().all(|character| {
                character.is_ascii_alphanumeric() || character == '_' || character == '-'
            })
            || path != spec.path
            || cfg != spec.cfg
            || !paths.insert(path)
            || !cfgs.insert(cfg)
            || spec.invariant.is_empty()
            || !spec
                .invariant
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
            || spec.length == 0
            || specs.insert(spec.name.clone(), spec).is_some()
        {
            return Err("spec mutation allowlist has an invalid or repeated source".to_string());
        }
    }
    Ok(specs)
}

fn spec_mutation_source_map(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let specs = spec_mutation_allowlist_specs(root)?;
    let sources = specs
        .into_iter()
        .map(|(name, spec)| (spec.path, name))
        .collect();
    Ok(sources)
}

fn spec_mutation_negative_registry(
    root: &Path,
) -> Result<(String, Vec<NegativeMutationInput>), String> {
    const NEGATIVE_SCHEMA: &str = "chio.apalache-negative.v1";

    let allowlist = spec_mutation_input_registry(root)?;
    let negative_registry = normalized_repo_path(&allowlist.negative_registry)?;
    if negative_registry != allowlist.negative_registry {
        return Err("spec mutation negative registry path is not normalized".to_string());
    }
    let (_, negative_raw) = regular_mutation_input_text(root, &negative_registry)?;
    let negative: NegativeMutationInputRegistry = parse_toml(&negative_registry, &negative_raw)?;
    if negative.schema != NEGATIVE_SCHEMA || negative.negative.is_empty() {
        return Err(
            "spec mutation negative registry has an unsupported schema or no entries".to_string(),
        );
    }
    let mut specs = BTreeSet::new();
    let mut cfgs = BTreeSet::new();
    for entry in &negative.negative {
        if normalized_repo_path(&entry.spec)? != entry.spec
            || normalized_repo_path(&entry.cfg)? != entry.cfg
            || !specs.insert(entry.spec.clone())
            || !cfgs.insert(entry.cfg.clone())
            || entry.falsifies.is_empty()
            || !entry
                .falsifies
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
            || entry.length == 0
            || entry.timeout_secs == 0
        {
            return Err(
                "spec mutation negative registry has an invalid or repeated entry".to_string(),
            );
        }
    }
    Ok((negative_registry, negative.negative))
}

fn spec_mutation_seed_registry(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let allowlist = spec_mutation_input_registry(root)?;
    let (_, negative_entries) = spec_mutation_negative_registry(root)?;
    let negative_specs = negative_entries
        .into_iter()
        .map(|entry| entry.spec)
        .collect::<BTreeSet<_>>();
    let mut seeds = BTreeMap::new();
    let mut negative_seed_specs = BTreeSet::new();
    for seed in allowlist.seed {
        let negative_spec = normalized_repo_path(&seed.negative_spec)?;
        if seed.name.is_empty()
            || !seed.name.chars().all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
            })
            || negative_spec != seed.negative_spec
            || !negative_specs.contains(&negative_spec)
            || seeds.insert(seed.name, negative_spec.clone()).is_some()
            || !negative_seed_specs.insert(negative_spec)
        {
            return Err(
                "spec mutation allowlist has an invalid or repeated historical seed".to_string(),
            );
        }
    }
    Ok(seeds)
}

fn spec_mutation_expected_input_paths(root: &Path) -> Result<BTreeSet<String>, String> {
    const ALLOWLIST: &str = "formal/apalache/spec-mutants-allowlist.toml";

    let allowlist = spec_mutation_input_registry(root)?;
    let (negative_registry, negative_entries) = spec_mutation_negative_registry(root)?;
    let mut paths = BTreeSet::from([
        ALLOWLIST.to_string(),
        negative_registry.clone(),
        "formal/MAPPING.md".to_string(),
        "scripts/check-apalache-negative.sh".to_string(),
        "scripts/lib/apalache_evidence.py".to_string(),
        "scripts/spec-mutants.py".to_string(),
        "tools/install-apalache.sh".to_string(),
    ]);
    for spec in &allowlist.spec {
        let source = normalized_repo_path(&spec.path)?;
        paths.insert(source.clone());
        paths.insert(normalized_repo_path(&spec.cfg)?);
        let parent = Path::new(&source)
            .parent()
            .and_then(Path::to_str)
            .ok_or_else(|| format!("spec mutation source has no repository parent: {source}"))?;
        paths.extend(regular_files_in_directory(root, parent, "tla", false)?);
    }
    let mut negative_parents = BTreeSet::new();
    for entry in negative_entries {
        let source = normalized_repo_path(&entry.spec)?;
        paths.insert(source.clone());
        paths.insert(normalized_repo_path(&entry.cfg)?);
        let parent = Path::new(&source)
            .parent()
            .and_then(Path::to_str)
            .ok_or_else(|| {
                format!("negative mutation source has no repository parent: {source}")
            })?;
        negative_parents.insert(parent.to_string());
        if !entry.runtime_test.starts_with("n/a") {
            let runtime_path = entry
                .runtime_test
                .split("::")
                .next()
                .filter(|path| !path.is_empty())
                .ok_or_else(|| "negative mutation runtime test has no file path".to_string())?;
            paths.insert(normalized_repo_path(runtime_path)?);
        }
    }
    for parent in negative_parents {
        paths.extend(regular_files_in_directory(root, &parent, "tla", false)?);
    }
    Ok(paths)
}

fn proof_mutation_expected_input_paths(root: &Path) -> Result<BTreeSet<String>, String> {
    let mut paths = BTreeSet::from([
        "Cargo.toml".to_string(),
        "Cargo.lock".to_string(),
        ".cargo/config.toml".to_string(),
        "crates/kernel/chio-kernel-core/Cargo.toml".to_string(),
        "crates/core/chio-core-types/Cargo.toml".to_string(),
        "rust-toolchain.toml".to_string(),
        "formal/rust-verification/formal-mutants.toml".to_string(),
        "scripts/proof-mutants.py".to_string(),
        "scripts/proof-mutants.sh".to_string(),
        "scripts/kani-mutant-killer.sh".to_string(),
        "scripts/check-kani-core.sh".to_string(),
    ]);
    paths.extend(regular_files_in_directory(
        root,
        "crates/kernel/chio-kernel-core/src",
        "rs",
        true,
    )?);
    paths.extend(regular_files_in_directory(
        root,
        "crates/core/chio-core-types/src",
        "rs",
        true,
    )?);
    Ok(paths)
}

fn formal_mutation_expected_inputs(
    root: &Path,
    lane: &str,
    coverage_inputs: &mut BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, String> {
    let paths = match lane {
        "spec-mutants" => spec_mutation_expected_input_paths(root)?,
        "proof-mutants" => proof_mutation_expected_input_paths(root)?,
        _ => return Err(format!("unsupported formal mutation input lane: {lane}")),
    };
    let mut expected = BTreeMap::new();
    for path in paths {
        insert_formal_mutation_input(root, &path, &mut expected, coverage_inputs)?;
    }
    Ok(expected)
}

#[allow(clippy::too_many_arguments)]
fn add_formal_mutation_artifacts(
    root: &Path,
    workspace: &WorkspaceCatalog,
    targets: &[FormalMutationTarget],
    inputs: &mut BTreeMap<String, String>,
    rows: &mut BTreeMap<String, CoverageRow>,
    artifacts: &mut BTreeMap<String, ArtifactRecord>,
    unattributed: &mut Vec<UnattributedArtifact>,
) -> Result<(), String> {
    if targets.is_empty() {
        return Err("formal mutation registry has no targets".to_string());
    }
    let mut names = BTreeSet::new();
    let mut lane_inventory_digests = BTreeMap::<String, String>::new();
    for target in targets {
        if target.name.is_empty()
            || !target.name.chars().all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
            })
            || !names.insert(target.name.clone())
        {
            return Err(format!(
                "formal mutation target has an invalid or repeated name: {}",
                target.name
            ));
        }
        if !matches!(target.lane.as_str(), "spec-mutants" | "proof-mutants") {
            return Err(format!(
                "formal mutation target {} has unsupported lane {}",
                target.name, target.lane
            ));
        }
        if !target.activation_target_percent.is_finite()
            || !(0.0..=100.0).contains(&target.activation_target_percent)
        {
            return Err(format!(
                "formal mutation target {} has an invalid activation target",
                target.name
            ));
        }
        if target.inventory_sha256.len() != 64
            || !target
                .inventory_sha256
                .chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
        {
            return Err(format!(
                "formal mutation target {} has an invalid inventory digest",
                target.name
            ));
        }
        if let Some(existing) = lane_inventory_digests.get(&target.lane) {
            if existing != &target.inventory_sha256 {
                return Err(format!(
                    "formal mutation lane {} has inconsistent inventory digests",
                    target.lane
                ));
            }
        } else {
            lane_inventory_digests.insert(target.lane.clone(), target.inventory_sha256.clone());
        }
        let source = normalized_repo_path(&target.source)?;
        if source != target.source {
            return Err(format!(
                "formal mutation target {} source is not a normalized repository path",
                target.name
            ));
        }
        let current_mutation_inputs = formal_mutation_expected_inputs(root, &target.lane, inputs)?;
        if !current_mutation_inputs.contains_key(&source) {
            return Err(format!(
                "formal mutation target {} source is outside the complete {} input set",
                target.name, target.lane
            ));
        }
        let (_, source_raw) = regular_mutation_input_text(root, &source)?;
        if target.lane == "spec-mutants" {
            if Path::new(&source)
                .extension()
                .and_then(|value| value.to_str())
                != Some("tla")
                || !source_raw.contains(" MODULE ")
            {
                return Err(format!(
                    "spec mutation target {} does not name a TLA+ module",
                    target.name
                ));
            }
        } else if !matches!(
            source.as_str(),
            "crates/kernel/chio-kernel-core/src/formal_core.rs"
                | "crates/kernel/chio-kernel-core/src/formal_aeneas.rs"
        ) {
            return Err(format!(
                "proof mutation target {} escapes the pure model files",
                target.name
            ));
        }
        let report = normalized_repo_path(&target.report)?;
        if !report.starts_with("target/formal/") {
            return Err(format!(
                "formal mutation target {} report is outside target/formal",
                target.name
            ));
        }
        if target.rust_paths.is_empty() {
            return Err(format!(
                "formal mutation target {} has no Rust paths",
                target.name
            ));
        }
        let mut surfaces = Vec::new();
        let mut seen_paths = BTreeSet::new();
        for rust_path in &target.rust_paths {
            let path = normalized_repo_path(rust_path)?;
            if Path::new(&path)
                .extension()
                .and_then(|value| value.to_str())
                != Some("rs")
                || !seen_paths.insert(path.clone())
            {
                return Err(format!(
                    "formal mutation target {} has an invalid or repeated Rust path: {}",
                    target.name, rust_path
                ));
            }
            let _ = read_input(root, &path, inputs)?;
            surfaces.push(surface_from_repo_path(&path, workspace, true)?);
        }
        let id = format!("formal/mutation/registry.toml::{}", target.name);
        add_or_unattribute(
            rows,
            artifacts,
            unattributed,
            id.clone(),
            "mutants",
            surfaces,
            "formal mutation target has no conservative primary Rust surface",
            Vec::new(),
        )?;
        let mut qualifiers = BTreeMap::from([
            ("mutation_lane".to_string(), target.lane.clone()),
            (
                "activation_target_percent".to_string(),
                format_percent(target.activation_target_percent),
            ),
            (
                "inventory_sha256".to_string(),
                target.inventory_sha256.clone(),
            ),
            ("report".to_string(), report),
        ]);
        if let Some(observation) = &target.latest_full_cycle {
            validate_formal_mutation_observation(
                root,
                inputs,
                target,
                observation,
                &current_mutation_inputs,
            )?;
            qualifiers.insert("measurement".to_string(), "full-cycle".to_string());
            qualifiers.insert(
                "activation_ratio_percent".to_string(),
                format_percent(observation.activation_ratio_percent),
            );
            qualifiers.insert("measured_at".to_string(), observation.measured_at.clone());
            qualifiers.insert("evidence".to_string(), observation.evidence.clone());
            qualifiers.insert("commit".to_string(), observation.commit.clone());
            if target.lane == "spec-mutants" {
                let source = spec_mutation_source_map(root)?
                    .get(&target.source)
                    .cloned()
                    .ok_or_else(|| {
                        format!(
                            "formal mutation target {} source is absent from the specification allowlist",
                            target.name
                        )
                    })?;
                qualifiers.insert("source_aggregate".to_string(), source);
            } else {
                qualifiers.insert("source_aggregate".to_string(), target.source.clone());
            }
        } else {
            qualifiers.insert("measurement".to_string(), "pending".to_string());
        }
        if let Some(artifact) = artifacts.get_mut(&id) {
            artifact.qualifiers = qualifiers;
        } else if let Some(artifact) = unattributed.iter_mut().find(|artifact| artifact.id == id) {
            artifact.qualifiers = qualifiers;
        } else {
            return Err(format!(
                "formal mutation target disappeared after attribution: {}",
                target.name
            ));
        }
    }
    Ok(())
}

fn format_percent(value: f64) -> String {
    let rendered = format!("{value:.3}");
    rendered
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

fn valid_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
    {
        return false;
    }
    let number =
        |range: std::ops::Range<usize>| value.get(range).and_then(|part| part.parse::<u32>().ok());
    matches!(number(0..4), Some(1..=9999))
        && matches!(number(5..7), Some(1..=12))
        && matches!(number(8..10), Some(1..=31))
        && matches!(number(11..13), Some(0..=23))
        && matches!(number(14..16), Some(0..=59))
        && matches!(number(17..19), Some(0..=60))
}

fn validate_formal_mutation_observation(
    root: &Path,
    inputs: &mut BTreeMap<String, String>,
    target: &FormalMutationTarget,
    observation: &FormalMutationObservation,
    current_inputs: &BTreeMap<String, String>,
) -> Result<(), String> {
    if observation.commit.len() != 40
        || !observation
            .commit
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        return Err(format!(
            "formal mutation target {} has an invalid observation commit",
            target.name
        ));
    }
    if !valid_utc_timestamp(&observation.measured_at) {
        return Err(format!(
            "formal mutation target {} has an invalid observation timestamp",
            target.name
        ));
    }
    let evidence = normalized_repo_path(&observation.evidence)?;
    if !evidence.starts_with("formal/mutation/evidence/")
        || Path::new(&evidence)
            .extension()
            .and_then(|value| value.to_str())
            != Some("json")
    {
        return Err(format!(
            "formal mutation target {} evidence must be a JSON file below formal/mutation/evidence",
            target.name
        ));
    }
    if observation.report_sha256.len() != 64
        || !observation
            .report_sha256
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        return Err(format!(
            "formal mutation target {} has an invalid report hash",
            target.name
        ));
    }
    let (_, raw_report) = regular_mutation_input_text(root, &evidence)?;
    inputs.insert(evidence.clone(), sha256_hex(raw_report.as_bytes()));
    if sha256_hex(raw_report.as_bytes()) != observation.report_sha256 {
        return Err(format!(
            "formal mutation target {} report hash does not match its evidence",
            target.name
        ));
    }
    let report: serde_json::Value = serde_json::from_str(&raw_report).map_err(|error| {
        format!(
            "formal mutation target {} has invalid report JSON: {error}",
            target.name
        )
    })?;
    validate_formal_mutation_report(root, target, observation, &report, current_inputs)?;
    Ok(())
}

fn validate_mutation_score(
    value: &serde_json::Value,
    counts: MutationVerdictCounts,
    activation_target_percent: f64,
    viability_target_percent: Option<f64>,
    label: &str,
) -> Result<bool, String> {
    let aggregate = value
        .as_object()
        .ok_or_else(|| format!("formal mutation report {label} is not an object"))?;
    let expected_usize = [
        ("sampled", counts.sampled()?),
        ("killed", counts.killed),
        ("survived", counts.survived),
        ("unviable", counts.unviable),
        ("timeout", counts.timeout),
        ("score_denominator", counts.score_denominator()?),
    ];
    for (field, expected) in expected_usize {
        if aggregate.get(field).and_then(serde_json::Value::as_u64) != u64::try_from(expected).ok()
        {
            return Err(format!(
                "formal mutation report {label} has an inconsistent {field}"
            ));
        }
    }
    let activation = counts.activation_ratio_percent()?;
    let completion = counts.completion_ratio_percent()?;
    for (field, expected) in [
        ("activation_ratio_percent", activation),
        ("completion_ratio_percent", completion),
        ("activation_target_percent", activation_target_percent),
    ] {
        if aggregate
            .get(field)
            .and_then(serde_json::Value::as_f64)
            .is_none_or(|actual| (actual - expected).abs() > 0.000_5)
        {
            return Err(format!(
                "formal mutation report {label} has an inconsistent {field}"
            ));
        }
    }
    if aggregate
        .get("timeout_policy")
        .and_then(serde_json::Value::as_str)
        != Some("timeouts count as not killed")
    {
        return Err(format!(
            "formal mutation report {label} has an inconsistent timeout policy"
        ));
    }
    let activation_met = activation + 0.000_5 >= activation_target_percent;
    if let Some(viability_target) = viability_target_percent {
        let sampled = counts.sampled()?;
        let viability = if sampled == 0 {
            0.0
        } else {
            100.0 * counts.score_denominator()? as f64 / sampled as f64
        };
        for (field, expected) in [
            ("viability_ratio_percent", viability),
            ("viability_target_percent", viability_target),
        ] {
            if aggregate
                .get(field)
                .and_then(serde_json::Value::as_f64)
                .is_none_or(|actual| (actual - expected).abs() > 0.000_5)
            {
                return Err(format!(
                    "formal mutation report {label} has an inconsistent {field}"
                ));
            }
        }
        let viability_met = viability + 0.000_5 >= viability_target;
        if aggregate
            .get("activation_threshold_met")
            .and_then(serde_json::Value::as_bool)
            != Some(activation_met)
            || aggregate
                .get("viability_met")
                .and_then(serde_json::Value::as_bool)
                != Some(viability_met)
        {
            return Err(format!(
                "formal mutation report {label} has inconsistent proof thresholds"
            ));
        }
        return Ok(activation_met && viability_met);
    }
    Ok(activation_met)
}

fn is_lowercase_sha256(value: Option<&str>) -> bool {
    value.is_some_and(|hash| {
        hash.len() == 64
            && hash
                .chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    })
}

fn is_registered_negative_trace_path(path: &str, spec: &str) -> bool {
    if path.contains(['\\', '\r', '\n', '\t']) {
        return false;
    }
    let parts = path.split('/').collect::<Vec<_>>();
    if parts.len() < 6
        || parts
            .iter()
            .any(|part| part.is_empty() || matches!(*part, "." | ".."))
        || parts.first() != Some(&"target")
        || parts.get(1) != Some(&"formal")
    {
        return false;
    }
    let Some(spec_stem) = Path::new(spec).file_stem().and_then(|value| value.to_str()) else {
        return false;
    };
    let tail = &parts[parts.len() - 4..];
    let Some(number) = tail[3]
        .strip_prefix("violation")
        .and_then(|value| value.strip_suffix(".itf.json"))
    else {
        return false;
    };
    tail[0] == "registered-negative"
        && tail[1] == spec_stem
        && tail[2] == "run"
        && !number.is_empty()
        && number.chars().all(|character| character.is_ascii_digit())
}

fn validate_spec_mutation_positive_baselines(
    root: &Path,
    target: &FormalMutationTarget,
    report: &serde_json::Value,
) -> Result<(), String> {
    let expected_specs = spec_mutation_allowlist_specs(root)?;
    let baselines = report
        .get("positive_baselines")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            format!(
                "formal mutation target {} report has no positive baseline evidence",
                target.name
            )
        })?;
    let expected_keys = BTreeSet::from([
        "spec",
        "path",
        "cfg",
        "invariant",
        "length",
        "verdict",
        "apalache_exit",
        "wall_secs",
        "log_sha256",
    ]);
    let mut seen = BTreeSet::new();
    for baseline in baselines {
        let object = baseline.as_object().ok_or_else(|| {
            format!(
                "formal mutation target {} positive baseline evidence is not an object",
                target.name
            )
        })?;
        if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_keys {
            return Err(format!(
                "formal mutation target {} positive baseline evidence has invalid fields",
                target.name
            ));
        }
        let name = object
            .get("spec")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                format!(
                    "formal mutation target {} positive baseline evidence has no specification",
                    target.name
                )
            })?;
        let expected = expected_specs.get(name).ok_or_else(|| {
            format!(
                "formal mutation target {} positive baseline evidence is absent from the allowlist",
                target.name
            )
        })?;
        let wall_secs = object.get("wall_secs").and_then(serde_json::Value::as_f64);
        if !seen.insert(name)
            || object.get("path").and_then(serde_json::Value::as_str)
                != Some(expected.path.as_str())
            || object.get("cfg").and_then(serde_json::Value::as_str) != Some(expected.cfg.as_str())
            || object.get("invariant").and_then(serde_json::Value::as_str)
                != Some(expected.invariant.as_str())
            || object.get("length").and_then(serde_json::Value::as_u64)
                != u64::try_from(expected.length).ok()
            || object.get("verdict").and_then(serde_json::Value::as_str) != Some("survived")
            || object
                .get("apalache_exit")
                .and_then(serde_json::Value::as_i64)
                != Some(0)
            || wall_secs.is_none_or(|value| !value.is_finite() || value < 0.0)
            || !is_lowercase_sha256(object.get("log_sha256").and_then(serde_json::Value::as_str))
        {
            return Err(format!(
                "formal mutation target {} has invalid positive baseline evidence for {name}",
                target.name
            ));
        }
    }
    if seen
        != expected_specs
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
    {
        return Err(format!(
            "formal mutation target {} positive baseline evidence does not cover the exact allowlist",
            target.name
        ));
    }
    Ok(())
}

fn validate_spec_mutation_preflight(
    root: &Path,
    target: &FormalMutationTarget,
    report: &serde_json::Value,
    inventory: &[serde_json::Value],
    mutants: &[serde_json::Value],
) -> Result<(), String> {
    validate_spec_mutation_positive_baselines(root, target, report)?;
    let mut inventory_seeds = BTreeMap::<String, String>::new();
    let mut inventory_seed_ids = BTreeSet::new();
    let mut inventory_by_id = BTreeMap::new();
    for entry in inventory {
        let object = entry.as_object().ok_or_else(|| {
            format!(
                "formal mutation target {} specification inventory entry is not an object",
                target.name
            )
        })?;
        let identifier = object
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                format!(
                    "formal mutation target {} specification inventory entry has no id",
                    target.name
                )
            })?;
        inventory_by_id.insert(identifier, object);
        if let Some(seed) = object.get("registered_seed") {
            let name = seed.as_str().ok_or_else(|| {
                format!(
                    "formal mutation target {} inventory has an invalid registered seed",
                    target.name
                )
            })?;
            if name.is_empty()
                || !name.chars().all(|character| {
                    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
                })
                || inventory_seeds
                    .insert(name.to_string(), identifier.to_string())
                    .is_some()
                || !inventory_seed_ids.insert(identifier.to_string())
            {
                return Err(format!(
                    "formal mutation target {} inventory has an invalid or repeated registered seed",
                    target.name
                ));
            }
        }
    }
    let expected_seed_specs = spec_mutation_seed_registry(root)?;
    if inventory_seeds.keys().collect::<BTreeSet<_>>()
        != expected_seed_specs.keys().collect::<BTreeSet<_>>()
    {
        return Err(format!(
            "formal mutation target {} inventory does not cover the exact historical seed registry",
            target.name
        ));
    }

    let registered_seeds = report
        .get("registered_seeds")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            format!(
                "formal mutation target {} report has no registered seed evidence",
                target.name
            )
        })?;
    let mut declared_seeds = BTreeMap::new();
    let mut declared_seed_ids = BTreeSet::new();
    for entry in registered_seeds {
        let object = entry.as_object().ok_or_else(|| {
            format!(
                "formal mutation target {} registered seed evidence is not an object",
                target.name
            )
        })?;
        let name = object
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                format!(
                    "formal mutation target {} registered seed evidence has no name",
                    target.name
                )
            })?;
        let identifier = object
            .get("mutant_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                format!(
                    "formal mutation target {} registered seed evidence has no mutant id",
                    target.name
                )
            })?;
        let negative_spec = object
            .get("negative_spec")
            .and_then(serde_json::Value::as_str);
        if object.len() != 4
            || negative_spec != expected_seed_specs.get(name).map(String::as_str)
            || object.get("status").and_then(serde_json::Value::as_str) != Some("subsumed")
            || declared_seeds
                .insert(name.to_string(), identifier.to_string())
                .is_some()
            || !declared_seed_ids.insert(identifier.to_string())
        {
            return Err(format!(
                "formal mutation target {} has repeated registered seed evidence",
                target.name
            ));
        }
    }
    if declared_seeds != inventory_seeds {
        return Err(format!(
            "formal mutation target {} registered seed evidence does not match its inventory",
            target.name
        ));
    }

    let mut results_by_id = BTreeMap::new();
    for mutant in mutants {
        let object = mutant.as_object().ok_or_else(|| {
            format!(
                "formal mutation target {} specification result is not an object",
                target.name
            )
        })?;
        let identifier = object
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                format!(
                    "formal mutation target {} specification result has no id",
                    target.name
                )
            })?;
        let expected = inventory_by_id.get(identifier).ok_or_else(|| {
            format!(
                "formal mutation target {} specification result is absent from its inventory",
                target.name
            )
        })?;
        if object.get("registered_seed") != expected.get("registered_seed")
            || results_by_id.insert(identifier, object).is_some()
        {
            return Err(format!(
                "formal mutation target {} specification result has invalid seed attribution",
                target.name
            ));
        }
    }
    for (name, identifier) in &inventory_seeds {
        if results_by_id
            .get(identifier.as_str())
            .and_then(|result| result.get("verdict"))
            .and_then(serde_json::Value::as_str)
            != Some("killed")
        {
            return Err(format!(
                "formal mutation target {} registered seed {name} was not killed",
                target.name
            ));
        }
    }

    let (_, expected_negative) = spec_mutation_negative_registry(root)?;
    let expected_by_spec = expected_negative
        .iter()
        .map(|entry| (entry.spec.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let registered_negative = report
        .get("registered_negative")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            format!(
                "formal mutation target {} report has no registered negative preflight evidence",
                target.name
            )
        })?;
    let mut seen_specs = BTreeSet::new();
    let mut seen_traces = BTreeSet::new();
    for entry in registered_negative {
        let object = entry.as_object().ok_or_else(|| {
            format!(
                "formal mutation target {} registered negative evidence is not an object",
                target.name
            )
        })?;
        let spec = object
            .get("spec")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                format!(
                    "formal mutation target {} registered negative evidence has no specification",
                    target.name
                )
            })?;
        let expected = expected_by_spec.get(spec).ok_or_else(|| {
            format!(
                "formal mutation target {} registered negative evidence is absent from the registry",
                target.name
            )
        })?;
        let trace = object
            .get("trace")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if !seen_specs.insert(spec)
            || !seen_traces.insert(trace)
            || object.get("cfg").and_then(serde_json::Value::as_str) != Some(expected.cfg.as_str())
            || object.get("invariant").and_then(serde_json::Value::as_str)
                != Some(expected.falsifies.as_str())
            || object.get("length").and_then(serde_json::Value::as_u64)
                != u64::try_from(expected.length).ok()
            || object
                .get("timeout_secs")
                .and_then(serde_json::Value::as_u64)
                != u64::try_from(expected.timeout_secs).ok()
            || object.get("verdict").and_then(serde_json::Value::as_str) != Some("killed")
            || !is_lowercase_sha256(object.get("log_sha256").and_then(serde_json::Value::as_str))
            || !is_lowercase_sha256(
                object
                    .get("trace_sha256")
                    .and_then(serde_json::Value::as_str),
            )
            || !is_registered_negative_trace_path(trace, spec)
        {
            return Err(format!(
                "formal mutation target {} has invalid registered negative evidence for {spec}",
                target.name
            ));
        }
    }
    if seen_specs != expected_by_spec.keys().copied().collect::<BTreeSet<_>>() {
        return Err(format!(
            "formal mutation target {} registered negative evidence does not cover the exact registry",
            target.name
        ));
    }
    Ok(())
}

fn validate_formal_mutation_report(
    root: &Path,
    target: &FormalMutationTarget,
    observation: &FormalMutationObservation,
    report: &serde_json::Value,
    current_inputs: &BTreeMap<String, String>,
) -> Result<(), String> {
    let expected_schema = match target.lane.as_str() {
        "spec-mutants" => "chio.spec-mutants-report.v1",
        "proof-mutants" => "chio.proof-mutants-report.v1",
        _ => {
            return Err(format!(
                "formal mutation target {} has unsupported report lane",
                target.name
            ));
        }
    };
    if report.get("schema").and_then(serde_json::Value::as_str) != Some(expected_schema)
        || report.get("commit").and_then(serde_json::Value::as_str)
            != Some(observation.commit.as_str())
        || report
            .get("measured_at")
            .and_then(serde_json::Value::as_str)
            != Some(observation.measured_at.as_str())
        || report
            .get("full_cycle")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        || report
            .get("worktree")
            .and_then(serde_json::Value::as_object)
            .is_none_or(|worktree| {
                worktree.len() != 1
                    || worktree.get("clean").and_then(serde_json::Value::as_bool) != Some(true)
            })
    {
        return Err(format!(
            "formal mutation target {} evidence is not a matching clean full-cycle report",
            target.name
        ));
    }
    let tools = report
        .get("tools")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            format!(
                "formal mutation target {} report has no tool versions",
                target.name
            )
        })?;
    let expected_tools = if target.lane == "spec-mutants" {
        vec![("apalache", "0.50.1")]
    } else {
        vec![
            ("cargo_mutants", "25.3.1"),
            ("kani", "0.67.0"),
            ("rustc", "1.93.0"),
        ]
    };
    if expected_tools.iter().any(|(tool, version)| {
        tools.get(*tool).and_then(serde_json::Value::as_str) != Some(*version)
    }) {
        return Err(format!(
            "formal mutation target {} report tool versions do not match the pinned lane",
            target.name
        ));
    }
    let report_inputs = report
        .get("inputs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            format!(
                "formal mutation target {} report has no inputs",
                target.name
            )
        })?;
    let mut reported_inputs = BTreeMap::new();
    for input in report_inputs {
        let path = input
            .get("path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                format!(
                    "formal mutation target {} report has an input without a path",
                    target.name
                )
            })?;
        let hash = input
            .get("sha256")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                format!(
                    "formal mutation target {} report has an input without a hash",
                    target.name
                )
            })?;
        if normalized_repo_path(path)? != path
            || hash.len() != 64
            || !hash
                .chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
            || reported_inputs.insert(path, hash).is_some()
        {
            return Err(format!(
                "formal mutation target {} report has an invalid or repeated input",
                target.name
            ));
        }
        let (_, bytes) = regular_mutation_input_bytes(root, path)?;
        if sha256_hex(&bytes) != hash {
            return Err(format!(
                "formal mutation target {} report input does not match current repository file {}",
                target.name, path
            ));
        }
    }
    let expected_paths = current_inputs.keys().cloned().collect::<BTreeSet<_>>();
    let reported_paths = reported_inputs
        .keys()
        .map(|path| (*path).to_string())
        .collect::<BTreeSet<_>>();
    if reported_paths != expected_paths {
        let missing = expected_paths
            .difference(&reported_paths)
            .cloned()
            .collect::<Vec<_>>();
        let unexpected = reported_paths
            .difference(&expected_paths)
            .cloned()
            .collect::<Vec<_>>();
        return Err(format!(
            "formal mutation target {} report input set does not match the complete {} lane: missing={missing:?} unexpected={unexpected:?}",
            target.name, target.lane
        ));
    }
    for (path, hash) in current_inputs {
        if reported_inputs.get(path.as_str()).copied() != Some(hash.as_str()) {
            return Err(format!(
                "formal mutation target {} report does not match current input {}",
                target.name, path
            ));
        }
    }
    validate_mutation_evidence_commit(root, &observation.commit)?;
    for (path, hash) in &reported_inputs {
        let committed = mutation_input_at_commit(root, &observation.commit, path)?;
        let committed_hash = sha256_hex(&committed);
        if committed_hash.as_str() != *hash {
            return Err(format!(
                "formal mutation target {} report input does not match its evidence commit {}: {}",
                target.name, observation.commit, path
            ));
        }
    }
    let mutants = report
        .get("mutants")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            format!(
                "formal mutation target {} report has no mutants",
                target.name
            )
        })?;
    if report.get("enumerated").and_then(serde_json::Value::as_u64)
        != u64::try_from(mutants.len()).ok()
    {
        return Err(format!(
            "formal mutation target {} report enumerated count does not match its inventory",
            target.name
        ));
    }
    let inventory = report
        .get("inventory")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            format!(
                "formal mutation target {} report has no full inventory",
                target.name
            )
        })?;
    if inventory.len() != mutants.len() {
        return Err(format!(
            "formal mutation target {} report inventory size does not match its results",
            target.name
        ));
    }
    let encoded_inventory = serde_json::to_vec(inventory).map_err(|error| {
        format!(
            "formal mutation target {} inventory cannot be encoded: {error}",
            target.name
        )
    })?;
    let computed_inventory_sha256 = sha256_hex(&encoded_inventory);
    if report
        .get("inventory_sha256")
        .and_then(serde_json::Value::as_str)
        != Some(computed_inventory_sha256.as_str())
        || computed_inventory_sha256 != target.inventory_sha256
    {
        return Err(format!(
            "formal mutation target {} report inventory digest does not match its registry",
            target.name
        ));
    }
    let mut inventory_by_id =
        BTreeMap::<String, &serde_json::Map<String, serde_json::Value>>::new();
    for entry in inventory {
        let object = entry.as_object().ok_or_else(|| {
            format!(
                "formal mutation target {} inventory entry is not an object",
                target.name
            )
        })?;
        let identifier = object
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                format!(
                    "formal mutation target {} inventory entry has no id",
                    target.name
                )
            })?;
        if identifier.len() != 20
            || !identifier
                .chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
            || inventory_by_id
                .insert(identifier.to_string(), object)
                .is_some()
        {
            return Err(format!(
                "formal mutation target {} report has an invalid or repeated inventory id",
                target.name
            ));
        }
    }
    for mutant in mutants {
        let object = mutant.as_object().ok_or_else(|| {
            format!(
                "formal mutation target {} mutant result is not an object",
                target.name
            )
        })?;
        let identifier = object
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                format!(
                    "formal mutation target {} report has a mutant without an id",
                    target.name
                )
            })?;
        let expected = inventory_by_id.get(identifier).ok_or_else(|| {
            format!(
                "formal mutation target {} result is absent from the reviewed inventory",
                target.name
            )
        })?;
        if expected
            .iter()
            .any(|(key, value)| object.get(key) != Some(value))
        {
            return Err(format!(
                "formal mutation target {} result differs from the reviewed inventory",
                target.name
            ));
        }
    }
    let expected_spec_sources = if target.lane == "spec-mutants" {
        Some(spec_mutation_source_map(root)?)
    } else {
        None
    };
    let mut report_counts = MutationVerdictCounts::default();
    let mut source_counts = BTreeMap::<String, MutationVerdictCounts>::new();
    let mut mutant_ids = BTreeSet::new();
    let mut target_source_seen = false;
    for mutant in mutants {
        let identifier = mutant
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                format!(
                    "formal mutation target {} report has a mutant without an id",
                    target.name
                )
            })?;
        if identifier.len() != 20
            || !identifier
                .chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
            || !mutant_ids.insert(identifier)
        {
            return Err(format!(
                "formal mutation target {} report has an invalid or repeated mutant id",
                target.name
            ));
        }
        let verdict = mutant
            .get("verdict")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                format!(
                    "formal mutation target {} report has a mutant without a verdict",
                    target.name
                )
            })?;
        report_counts.increment(verdict).map_err(|error| {
            format!(
                "formal mutation target {} report has invalid verdict {verdict}: {error}",
                target.name
            )
        })?;
        let source_path_field = if target.lane == "spec-mutants" {
            "path"
        } else {
            "file"
        };
        let source_path = mutant
            .get(source_path_field)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                format!(
                    "formal mutation target {} report has a mutant without a source path",
                    target.name
                )
            })?;
        if normalized_repo_path(source_path)? != source_path {
            return Err(format!(
                "formal mutation target {} report has a mutant with an invalid source path",
                target.name
            ));
        }
        target_source_seen |= source_path == target.source;
        if let Some(expected_sources) = &expected_spec_sources {
            let source = mutant
                .get("spec")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "formal mutation target {} report has a mutant without a specification source",
                        target.name
                    )
                })?;
            if expected_sources.get(source_path).map(String::as_str) != Some(source) {
                return Err(format!(
                    "formal mutation target {} report has an invalid specification source mapping",
                    target.name
                ));
            }
            source_counts
                .entry(source.to_string())
                .or_default()
                .increment(verdict)?;
        } else {
            source_counts
                .entry(source_path.to_string())
                .or_default()
                .increment(verdict)?;
        }
    }
    if target.lane == "spec-mutants" {
        validate_spec_mutation_preflight(root, target, report, inventory, mutants)?;
    }
    if !target_source_seen {
        return Err(format!(
            "formal mutation target {} report inventory does not cover its source",
            target.name
        ));
    }
    let aggregate = report.get("aggregate").ok_or_else(|| {
        format!(
            "formal mutation target {} report has no aggregate",
            target.name
        )
    })?;
    let observation_counts = MutationVerdictCounts {
        killed: observation.killed,
        survived: observation.survived,
        unviable: observation.unviable,
        timeout: observation.timeout,
    };
    if observation_counts.sampled()? != observation.enumerated || observation.enumerated == 0 {
        return Err(format!(
            "formal mutation target {} observation counts do not match",
            target.name
        ));
    }
    if target.lane == "spec-mutants" {
        if report_counts.unviable != 0 || observation.unviable != 0 {
            return Err(format!(
                "formal mutation target {} specification report has unviable mutants",
                target.name
            ));
        }
        let expected_sources = expected_spec_sources
            .as_ref()
            .ok_or_else(|| "spec mutation source registry disappeared".to_string())?;
        let expected_source_names = expected_sources.values().cloned().collect::<BTreeSet<_>>();
        let mutant_source_names = source_counts.keys().cloned().collect::<BTreeSet<_>>();
        if mutant_source_names != expected_source_names {
            return Err(format!(
                "formal mutation target {} report source set is incomplete: expected={expected_source_names:?} actual={mutant_source_names:?}",
                target.name
            ));
        }
        let source_aggregates = report
            .get("source_aggregates")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                format!(
                    "formal mutation target {} report has no source aggregates",
                    target.name
                )
            })?;
        let aggregate_source_names = source_aggregates.keys().cloned().collect::<BTreeSet<_>>();
        if aggregate_source_names != mutant_source_names {
            return Err(format!(
                "formal mutation target {} source aggregate set does not match its mutant sources: aggregates={aggregate_source_names:?} mutants={mutant_source_names:?}",
                target.name
            ));
        }
        let mut every_source_met = true;
        for (source, counts) in &source_counts {
            let source_aggregate = source_aggregates.get(source).ok_or_else(|| {
                format!(
                    "formal mutation target {} report lost source aggregate {source}",
                    target.name
                )
            })?;
            let computed_met = validate_mutation_score(
                source_aggregate,
                *counts,
                target.activation_target_percent,
                None,
                &format!("source aggregate {source}"),
            )?;
            let recorded_met = source_aggregate
                .get("activation_met")
                .and_then(serde_json::Value::as_bool);
            if recorded_met != Some(computed_met) {
                return Err(format!(
                    "formal mutation target {} source aggregate {source} has an inconsistent activation result",
                    target.name
                ));
            }
            if !computed_met {
                every_source_met = false;
            }
        }
        let global_met = validate_mutation_score(
            aggregate,
            report_counts,
            target.activation_target_percent,
            None,
            "global aggregate",
        )?;
        let global = aggregate
            .get("global_activation_met")
            .and_then(serde_json::Value::as_bool);
        let sources = aggregate
            .get("source_activation_met")
            .and_then(serde_json::Value::as_bool);
        let combined = aggregate
            .get("activation_met")
            .and_then(serde_json::Value::as_bool);
        if global != Some(global_met)
            || sources != Some(every_source_met)
            || combined != Some(global_met && every_source_met)
        {
            return Err(format!(
                "formal mutation target {} report has inconsistent global or source activation results",
                target.name
            ));
        }
        if !global_met || !every_source_met || combined != Some(true) {
            return Err(format!(
                "formal mutation target {} report does not meet every source activation target",
                target.name
            ));
        }
        let target_source = expected_sources.get(&target.source).ok_or_else(|| {
            format!(
                "formal mutation target {} source is absent from the specification allowlist",
                target.name
            )
        })?;
        let target_counts = source_counts.get(target_source).ok_or_else(|| {
            format!(
                "formal mutation target {} report has no counts for its source",
                target.name
            )
        })?;
        if observation_counts != *target_counts
            || observation.enumerated != target_counts.sampled()?
            || (observation.activation_ratio_percent - target_counts.activation_ratio_percent()?)
                .abs()
                > 0.000_5
        {
            return Err(format!(
                "formal mutation target {} observation does not match its source aggregate",
                target.name
            ));
        }
    } else {
        let actual_sources = source_counts.keys().cloned().collect::<BTreeSet<_>>();
        let source_aggregates = report
            .get("source_aggregates")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                format!(
                    "formal mutation target {} proof report has no source aggregates",
                    target.name
                )
            })?;
        if source_aggregates.keys().cloned().collect::<BTreeSet<_>>() != actual_sources {
            return Err(format!(
                "formal mutation target {} proof source aggregates are incomplete",
                target.name
            ));
        }
        let mut every_source_met = true;
        for (source, counts) in &source_counts {
            let source_aggregate = &source_aggregates[source];
            let computed_met = validate_mutation_score(
                source_aggregate,
                *counts,
                target.activation_target_percent,
                Some(80.0),
                &format!("proof source aggregate {source}"),
            )?;
            if source_aggregate
                .get("activation_met")
                .and_then(serde_json::Value::as_bool)
                != Some(computed_met)
            {
                return Err(format!(
                    "formal mutation target {} proof source aggregate has an inconsistent activation result: {source}",
                    target.name
                ));
            }
            every_source_met &= computed_met;
        }
        let global_met = validate_mutation_score(
            aggregate,
            report_counts,
            target.activation_target_percent,
            Some(80.0),
            "proof global aggregate",
        )?;
        if aggregate
            .get("global_activation_met")
            .and_then(serde_json::Value::as_bool)
            != Some(global_met)
            || aggregate
                .get("source_activation_met")
                .and_then(serde_json::Value::as_bool)
                != Some(every_source_met)
            || aggregate
                .get("activation_met")
                .and_then(serde_json::Value::as_bool)
                != Some(global_met && every_source_met)
            || !global_met
            || !every_source_met
        {
            return Err(format!(
                "formal mutation target {} proof report does not meet every source threshold",
                target.name
            ));
        }
        let target_counts = source_counts.get(&target.source).ok_or_else(|| {
            format!(
                "formal mutation target {} proof report has no counts for its source",
                target.name
            )
        })?;
        if observation_counts != *target_counts
            || observation.enumerated != target_counts.sampled()?
            || (observation.activation_ratio_percent - target_counts.activation_ratio_percent()?)
                .abs()
                > 0.000_5
        {
            return Err(format!(
                "formal mutation target {} observation does not match its proof source aggregate",
                target.name
            ));
        }
    }
    let expected = observation_counts.activation_ratio_percent()?;
    if !observation.activation_ratio_percent.is_finite()
        || (observation.activation_ratio_percent - expected).abs() > 0.000_5
    {
        return Err(format!(
            "formal mutation target {} observation activation ratio does not match timeout-aware counts",
            target.name
        ));
    }
    Ok(())
}

fn mutation_evidence_is_complete(
    evidence: &serde_json::Value,
    package: &str,
    config_path: &str,
    evidence_path: &str,
) -> Result<bool, String> {
    let evidence_package = evidence
        .get("crate")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("mutation evidence has no crate: {evidence_path}"))?;
    if evidence_package != package {
        return Ok(false);
    }
    let command = evidence
        .get("command")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("mutation evidence has no command: {evidence_path}"))?;
    let command_parts = command.split_whitespace().collect::<Vec<_>>();
    if !command_parts
        .windows(2)
        .any(|parts| parts[0] == "--config" && parts[1] == config_path)
    {
        return Ok(false);
    }
    let finished = evidence
        .get("ran_finished_at")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| !value.trim().is_empty());
    let evaluated = evidence
        .get("evaluated")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let total = evidence
        .get("total_discovered")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let full_result = evidence
        .get("result_label")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value.starts_with("FULL"));
    if !finished || evaluated == 0 || evaluated != total || !full_result {
        return Err(format!(
            "mutation evidence is not a completed full result: {evidence_path}"
        ));
    }
    Ok(true)
}

fn validate_mutation_baseline(raw: &str) -> Result<(), String> {
    let value: TomlValue = parse_toml("docs/fuzzing/trust-boundary-mutants-baseline.toml", raw)?;
    let aggregate = value
        .get("aggregate")
        .and_then(TomlValue::as_table)
        .ok_or_else(|| "mutation baseline has no aggregate table".to_string())?;
    for key in [
        "scope",
        "crate_entries",
        "evaluated_mutants_total",
        "measured_kill_rate_excluding_unviable",
        "baseline_status",
    ] {
        if !aggregate.contains_key(key) {
            return Err(format!("mutation baseline aggregate has no {key}"));
        }
    }
    Ok(())
}

fn add_inventory_artifacts(
    inventory: &TheoremInventory,
    unattributed: &mut Vec<UnattributedArtifact>,
) {
    for theorem in inventory.assumptions.iter().chain(&inventory.theorems) {
        unattributed.push(UnattributedArtifact {
            id: format!("formal/theorem-inventory.json::{}", theorem.id),
            lane: "lean".to_string(),
            reason: if theorem.root_imported {
                format!(
                    "{} has property links but no machine-readable Rust surface link",
                    theorem.file
                )
            } else {
                "theorem is not root imported".to_string()
            },
            related_properties: theorem.maps_to.clone(),
            related_surfaces: Vec::new(),
            qualifiers: BTreeMap::from([
                ("claim_class".to_string(), theorem.claim_class.clone()),
                ("kind".to_string(), theorem.kind.clone()),
                (
                    "status".to_string(),
                    theorem
                        .status
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                ),
            ]),
        });
    }
}

fn add_diff_artifacts(
    root: &Path,
    inputs: &mut BTreeMap<String, String>,
    unattributed: &mut Vec<UnattributedArtifact>,
) -> Result<(), String> {
    for path in files_in_dir(root, "formal/diff-tests/tests", "rs")? {
        let _raw = read_input(root, &path, inputs)?;
        unattributed.push(UnattributedArtifact {
            id: path,
            lane: "diff".to_string(),
            reason: "differential-test files have no machine-readable Rust surface registry"
                .to_string(),
            related_properties: Vec::new(),
            related_surfaces: Vec::new(),
            qualifiers: BTreeMap::new(),
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn add_optional_concurrency_artifacts(
    root: &Path,
    workspace: &WorkspaceCatalog,
    inputs: &mut BTreeMap<String, String>,
    lanes: &mut Vec<String>,
    mapping_surfaces: &BTreeMap<String, Vec<String>>,
    rows: &mut BTreeMap<String, CoverageRow>,
    artifacts: &mut BTreeMap<String, ArtifactRecord>,
) -> Result<(), String> {
    let loom_path = ".loom/harnesses.toml";
    if root.join(loom_path).is_file() {
        let raw = read_input(root, loom_path, inputs)?;
        let manifest: LoomManifest = parse_toml(loom_path, &raw)?;
        if manifest.schema != "chio.loom.v1" {
            return Err(format!(
                "unsupported loom manifest schema: {}",
                manifest.schema
            ));
        }
        if manifest.harness.is_empty() {
            return Err("loom manifest contains no harnesses".to_string());
        }
        lanes.push("loom".to_string());
        let mut loom_ids = BTreeSet::new();
        for harness in manifest.harness {
            let package = workspace.packages.get(&harness.crate_name).ok_or_else(|| {
                format!(
                    "loom test {} names non-workspace crate {}",
                    harness.test, harness.crate_name
                )
            })?;
            validate_loom_harness(root, package, &harness)?;
            let loom_id = format!("{}/{}", harness.crate_name, harness.test);
            if !loom_ids.insert(loom_id.clone()) {
                return Err(format!("duplicate loom harness: {loom_id}"));
            }
            let short_name = harness.test.rsplit("::").next().unwrap_or(&harness.test);
            let surfaces = mapping_surfaces
                .get(short_name)
                .cloned()
                .unwrap_or_default();
            let (primary, related) =
                conservative_harness_attribution(surfaces, crate_surface(&harness.crate_name));
            let artifact_id = format!("{loom_path}::{loom_id}");
            add_artifact(
                rows,
                artifacts,
                artifact_id.clone(),
                "loom",
                primary,
                related,
            )?;
            let artifact = artifacts
                .get_mut(&artifact_id)
                .ok_or_else(|| format!("internal missing loom artifact: {artifact_id}"))?;
            artifact.qualifiers.insert("lane".to_string(), harness.lane);
            artifact.qualifiers.insert(
                "max_preemptions".to_string(),
                harness.max_preemptions.to_string(),
            );
            artifact
                .qualifiers
                .insert("scope".to_string(), harness.scope);
        }
    }

    let dst_path = ".dst/harnesses.toml";
    if root.join(dst_path).is_file() {
        let raw = read_input(root, dst_path, inputs)?;
        let manifest: DstManifest = parse_toml(dst_path, &raw)?;
        if manifest.schema != "chio.dst.v1" {
            return Err(format!(
                "unsupported DST manifest schema: {}",
                manifest.schema
            ));
        }
        if manifest.harness.is_empty() {
            return Err("DST manifest contains no harnesses".to_string());
        }
        lanes.push("dst".to_string());
        let mut ids = BTreeSet::new();
        for harness in manifest.harness {
            if harness.crate_name.trim().is_empty() || harness.test.trim().is_empty() {
                return Err("DST harness crate and test must be non-empty".to_string());
            }
            if !workspace.packages.contains_key(&harness.crate_name) {
                return Err(format!(
                    "DST test {} names non-workspace crate {}",
                    harness.test, harness.crate_name
                ));
            }
            let id = format!("{}/{}", harness.crate_name, harness.test);
            if !ids.insert(id.clone()) {
                return Err(format!("duplicate DST harness: {id}"));
            }
            let short_name = harness.test.rsplit("::").next().unwrap_or(&harness.test);
            let surfaces = mapping_surfaces
                .get(short_name)
                .cloned()
                .unwrap_or_default();
            let (primary, related) =
                conservative_harness_attribution(surfaces, crate_surface(&harness.crate_name));
            let artifact_id = format!("{dst_path}::{id}");
            add_artifact(
                rows,
                artifacts,
                artifact_id.clone(),
                "dst",
                primary,
                related,
            )?;
            let artifact = artifacts
                .get_mut(&artifact_id)
                .ok_or_else(|| format!("internal missing DST artifact: {artifact_id}"))?;
            artifact.qualifiers.insert(
                "scope".to_string(),
                "single_process_single_store".to_string(),
            );
        }
    }
    lanes.sort_by_key(|lane| {
        BASE_LANES
            .iter()
            .position(|known| known == lane)
            .unwrap_or(BASE_LANES.len())
    });
    Ok(())
}

fn validate_loom_harness(
    root: &Path,
    package: &WorkspacePackage,
    harness: &LoomHarness,
) -> Result<(), String> {
    if harness.crate_name.trim().is_empty()
        || harness.test.trim().is_empty()
        || harness.notes.trim().is_empty()
    {
        return Err("loom harness crate, test, and notes must be non-empty".to_string());
    }
    if harness.max_preemptions == 0 {
        return Err(format!(
            "loom harness max_preemptions must be positive: {}",
            harness.test
        ));
    }
    if !matches!(harness.lane.as_str(), "pr" | "nightly") {
        return Err(format!(
            "loom harness has unsupported lane {}: {}",
            harness.lane, harness.test
        ));
    }
    if harness.scope != "bounded_abstract_model" {
        return Err(format!(
            "loom harness has unsupported scope {}: {}",
            harness.scope, harness.test
        ));
    }
    let components = harness.test.split("::").collect::<Vec<_>>();
    if components.len() != 2 || components.iter().any(|component| component.is_empty()) {
        return Err(format!(
            "loom harness test must be <integration-target>::<test-name>: {}",
            harness.test
        ));
    }
    let source = root
        .join(&package.root)
        .join("tests")
        .join(format!("{}.rs", components[0]));
    if !source.is_file() {
        return Err(format!(
            "loom integration-test target not found for {}: {}",
            harness.test,
            source.display()
        ));
    }
    let raw = fs::read_to_string(&source).map_err(|error| {
        format!(
            "cannot read loom integration-test target {}: {error}",
            source.display()
        )
    })?;
    let parsed = syn::parse_file(&raw).map_err(|error| {
        format!(
            "cannot parse loom integration-test target {}: {error}",
            source.display()
        )
    })?;
    let mut tests = BTreeSet::new();
    collect_rust_tests(&parsed.items, "", &mut tests);
    let test_name = components[1];
    if !tests.contains(test_name) {
        return Err(format!(
            "loom test not found in {}: {test_name}",
            source.display()
        ));
    }
    Ok(())
}

fn collect_rust_tests(items: &[syn::Item], prefix: &str, tests: &mut BTreeSet<String>) {
    for item in items {
        match item {
            syn::Item::Fn(function)
                if function
                    .attrs
                    .iter()
                    .any(|attribute| attribute.path().is_ident("test")) =>
            {
                let name = function.sig.ident.to_string();
                tests.insert(if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}::{name}")
                });
            }
            syn::Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    let name = module.ident.to_string();
                    let nested_prefix = if prefix.is_empty() {
                        name
                    } else {
                        format!("{prefix}::{name}")
                    };
                    collect_rust_tests(nested, &nested_prefix, tests);
                }
            }
            _ => {}
        }
    }
}

fn lane_postures(raw: &str) -> Result<BTreeMap<String, String>, String> {
    let value: TomlValue = parse_toml("releases.toml", raw)?;
    let Some(gates) = value.get("gates").and_then(TomlValue::as_table) else {
        return Ok(BTreeMap::new());
    };
    let mut postures = BTreeMap::new();
    for (lane, gate) in gates {
        if lane.trim().is_empty() {
            return Err("releases.toml contains an empty gate name".to_string());
        }
        let posture = gate
            .get("posture")
            .and_then(TomlValue::as_str)
            .ok_or_else(|| format!("releases.toml gate {lane} has no posture"))?;
        if !matches!(posture, "advisory" | "required") {
            return Err(format!(
                "releases.toml gate {lane} has unsupported posture: {posture}"
            ));
        }
        postures.insert(lane.clone(), posture.to_string());
    }
    Ok(postures)
}

fn validate_primary_attribution(
    harnesses: &[KaniHarness],
    fuzz_map: &FuzzMap,
    mutant_configs: &[String],
    rows: &BTreeMap<String, CoverageRow>,
) -> Result<(), String> {
    for harness in harnesses {
        let id = format!(
            ".kani/harnesses.toml::{}/{}",
            harness.crate_name, harness.harness
        );
        require_single_artifact(rows, "kani", &id)?;
    }
    for name in fuzz_map.targets.keys() {
        require_single_artifact(rows, "fuzz", &format!("fuzz/target-map.toml::{name}"))?;
    }
    for path in mutant_configs {
        require_single_artifact(rows, "mutants", path)?;
    }
    Ok(())
}

fn validate_mutant_classification(
    config_paths: &[String],
    artifacts: &BTreeMap<String, ArtifactRecord>,
    unattributed: &[UnattributedArtifact],
) -> Result<(), String> {
    for path in config_paths {
        let primary_count = usize::from(
            artifacts
                .get(path)
                .is_some_and(|artifact| artifact.lane == "mutants"),
        );
        let unattributed_count = unattributed
            .iter()
            .filter(|artifact| artifact.id == *path && artifact.lane == "mutants")
            .count();
        if primary_count + unattributed_count != 1 {
            return Err(format!(
                "mutation config must have exactly one classification: {path} primary={primary_count} unattributed={unattributed_count}"
            ));
        }
    }
    Ok(())
}

fn require_single_artifact(
    rows: &BTreeMap<String, CoverageRow>,
    lane: &str,
    artifact: &str,
) -> Result<(), String> {
    let count = rows
        .values()
        .filter(|row| {
            row.lanes
                .get(lane)
                .is_some_and(|artifacts| artifacts.contains(artifact))
        })
        .count();
    if count != 1 {
        return Err(format!(
            "artifact must have exactly one primary row: {artifact} count={count}"
        ));
    }
    Ok(())
}

fn render_document(build: &CoverageBuild) -> Result<String, String> {
    let mut output = String::from(
        "<!-- Generated by `cargo xtask gen proof-coverage`. Do not edit. -->\n\n# Proof Coverage\n\n",
    );
    output.push_str(
        "This matrix joins declared verification evidence to its primary Rust surface. A populated cell is an artifact count, not a completeness claim. Full artifact identifiers appear below the matrix. Claim wording remains governed by [CLAIM_REGISTRY.md](../reference/CLAIM_REGISTRY.md).\n\n",
    );
    output.push_str(
        "Theorem inventory and differential-test artifacts without a machine-readable Rust link are listed as unattributed. They are not assigned by naming heuristics. Qualifiers preserve theorem status and Kani execution or model scope. Empty cells are deliberate.\n\n## Surface Matrix\n\n",
    );
    output.push_str(&render_markdown(
        &build.rows,
        &build.lanes,
        &build.artifacts,
    ));
    output.push_str("## Related Surfaces\n\n");
    let mut related_count = 0usize;
    for artifact in &build.artifacts {
        if artifact.related_surfaces.is_empty() {
            continue;
        }
        related_count += 1;
        output.push_str("- `");
        output.push_str(&artifact.id);
        output.push_str("`: ");
        output.push_str(
            &artifact
                .related_surfaces
                .iter()
                .map(|surface| format!("`{surface}`"))
                .collect::<Vec<_>>()
                .join(", "),
        );
        output.push('\n');
    }
    if related_count == 0 {
        output.push_str("- None.\n");
    }

    output.push_str("\n## Unattributed Artifacts\n\n");
    if build.unattributed_artifacts.is_empty() {
        output.push_str("- None.\n");
    } else {
        for artifact in &build.unattributed_artifacts {
            output.push_str("- `");
            output.push_str(&artifact.id);
            output.push_str("` (`");
            output.push_str(&artifact.lane);
            output.push_str("`)");
            if !artifact.qualifiers.is_empty() {
                output.push_str(" (");
                output.push_str(&render_qualifiers(&artifact.qualifiers));
                output.push(')');
            }
            output.push_str(": ");
            output.push_str(&artifact.reason);
            if !artifact.related_properties.is_empty() {
                output.push_str(" Properties: ");
                output.push_str(&artifact.related_properties.join(", "));
                output.push('.');
            }
            if !artifact.related_surfaces.is_empty() {
                output.push_str(" Related surfaces: ");
                output.push_str(
                    &artifact
                        .related_surfaces
                        .iter()
                        .map(|surface| format!("`{surface}`"))
                        .collect::<Vec<_>>()
                        .join(", "),
                );
                output.push('.');
            }
            output.push('\n');
        }
    }

    output.push_str("\n## Non-Proof Linkage Metadata\n\n");
    output.push_str(
        "These drift-checked manual mirrors and contract twins are review navigation only. They do not populate evidence cells, prove semantic equivalence, or license formal claims.\n\n",
    );
    if build.review_links.is_empty() {
        output.push_str("- None.\n");
    } else {
        for link in &build.review_links {
            output.push_str("- `");
            output.push_str(&link.id);
            output.push_str("` (`");
            output.push_str(&link.kind);
            output.push_str("`, `");
            output.push_str(&link.relationship);
            output.push_str("`): `");
            output.push_str(&link.source);
            output.push_str("` -> `");
            output.push_str(&link.target);
            output.push('`');
            if !link.qualifiers.is_empty() {
                output.push_str(" (");
                output.push_str(&render_qualifiers(&link.qualifiers));
                output.push(')');
            }
            output.push('\n');
        }
    }

    output.push_str("\n## Assumption Boundary\n\n");
    for assumption in &build.assumptions {
        output.push_str("- `");
        output.push_str(&assumption.id);
        output.push_str("`: ");
        output.push_str(&assumption.status);
        output.push('\n');
    }
    output.push_str("\n## Excluded Surfaces\n\n");
    for excluded in &build.excluded_surfaces {
        output.push_str("- ");
        output.push_str(excluded);
        output.push('\n');
    }
    if !build.lane_postures.is_empty() {
        output.push_str("\n## Lane Postures\n\n");
        for (lane, posture) in &build.lane_postures {
            output.push_str("- `");
            output.push_str(lane);
            output.push_str("`: ");
            output.push_str(posture);
            output.push('\n');
        }
    }
    output.push_str("\n## Generation\n\n");
    output.push_str(&format!("- Generator version: `{GENERATOR_VERSION}`\n"));
    output.push_str("- Regenerate: `cargo xtask gen proof-coverage`\n");
    output.push_str(&format!("- Input digest: `{}`\n", build.input_digest));
    output.push_str(&format!(
        "- Git commit: `{COMMIT_TOKEN}` (resolved in coverage.json and Proof Room packages)\n"
    ));
    output.push_str(
        "- Row identity: file rows use package-relative Rust paths; crate-only artifacts use `package::*`.\n\n### Inputs\n\n",
    );
    for input in &build.inputs {
        output.push_str("- `");
        output.push_str(&input.path);
        output.push_str("`: `");
        output.push_str(&input.sha256);
        output.push_str("`\n");
    }
    if !build.parse_warnings.is_empty() {
        output.push_str("\n### Parse Warnings\n\n");
        for warning in &build.parse_warnings {
            output.push_str("- ");
            output.push_str(warning);
            output.push('\n');
        }
    }

    for line in output.lines().filter(|line| line.starts_with('|')) {
        if line.len() > 120 {
            return Err(format!(
                "coverage matrix row exceeds 120 columns ({}): {line}",
                line.len()
            ));
        }
    }
    Ok(output)
}

fn combined_input_digest(inputs: &[InputDigest]) -> String {
    let mut hasher = Sha256::new();
    for input in inputs {
        hasher.update((input.path.len() as u64).to_be_bytes());
        hasher.update(input.path.as_bytes());
        hasher.update((input.sha256.len() as u64).to_be_bytes());
        hasher.update(input.sha256.as_bytes());
    }
    digest_hex(&hasher.finalize())
}

fn ordered_string_digest(values: &[String]) -> String {
    let mut hasher = Sha256::new();
    for value in values {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    digest_hex(&hasher.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest_hex(&digest)
}

fn digest_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn git_commit(root: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .map_err(|error| format!("cannot run git rev-parse HEAD: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse HEAD failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let commit = String::from_utf8(output.stdout)
        .map_err(|error| format!("git commit is not UTF-8: {error}"))?
        .trim()
        .to_string();
    if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "git rev-parse HEAD returned invalid commit: {commit}"
        ));
    }
    Ok(commit)
}

fn write_output(path: &Path, content: &str) -> Result<(), XtaskError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| XtaskError::Io(parent.display().to_string(), error))?;
    }
    fs::write(path, content).map_err(|error| XtaskError::Io(path.display().to_string(), error))
}

fn first_difference(existing: &str, generated: &str) -> String {
    let existing_lines = existing.lines().collect::<Vec<_>>();
    let generated_lines = generated.lines().collect::<Vec<_>>();
    let count = existing_lines.len().max(generated_lines.len());
    for index in 0..count {
        if existing_lines.get(index) != generated_lines.get(index) {
            return format!(
                " (first difference at line {}: existing={:?}, generated={:?})",
                index + 1,
                existing_lines.get(index).copied().unwrap_or("<missing>"),
                generated_lines.get(index).copied().unwrap_or("<missing>")
            );
        }
    }
    String::new()
}

fn verify_committed_markdown(existing: &str, generated: &str) -> Result<(), String> {
    if existing == generated {
        return Ok(());
    }
    Err(format!(
        "{MARKDOWN_PATH} is stale; run `cargo xtask gen proof-coverage`{}",
        first_difference(existing, generated)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lean_abstraction_anchor_is_review_metadata() {
        let entries = [MirrorEntry {
            model_file: "formal/lean4/Chio/Chio/Treaty/PredicateLang.lean".to_string(),
            model_kind: "lean".to_string(),
            relationship: "abstraction_anchor".to_string(),
            rust_source: "crates/kernel/chio-runtime-core/src/treaty.rs".to_string(),
            rust_symbols: vec!["evaluate_cross_boundary_admission".to_string()],
            normalized_sha256: "0".repeat(64),
        }];

        let links = match mirror_review_links(&entries) {
            Ok(links) => links,
            Err(error) => panic!("valid Lean anchor was rejected: {error}"),
        };
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].relationship, "abstraction_anchor");
    }

    #[test]
    fn current_mapping_parses_without_warnings() {
        let parsed = parse_mapping(include_str!("../../formal/MAPPING.md"));

        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        assert_eq!(parsed.rows.len(), 94);
    }

    #[test]
    fn malformed_mapping_row_produces_a_deterministic_warning() {
        let input = "## TLA properties\n\n| Property | Source | Rust path constrained | Evidence |\n| --- | --- | --- | --- |\n| `Good` | `formal/tla/Good.tla` | `crates/core/chio-core/src/lib.rs` | none |\n| `Broken` | only two cells |\n";

        let first = parse_mapping(input);
        let second = parse_mapping(input);
        assert_eq!(first, second);
        assert_eq!(first.rows.len(), 1);
        assert_eq!(first.warnings, vec!["line 6: expected 4 cells, found 2"]);

        let renamed = parse_mapping(
            "| Property | Source | Rust implementation |\n| --- | --- | --- |\n| `P` | `formal/tla/P.tla` | `crates/core/chio-core/src/lib.rs` |\n",
        );
        assert_eq!(renamed.rows.len(), 0);
        assert_eq!(
            renamed.warnings,
            vec!["line 1: property table missing required columns: Rust path constrained"]
        );

        let renamed_property = parse_mapping(
            "| Invariant | Source | Rust path constrained |\n| --- | --- | --- |\n| `P` | `formal/tla/P.tla` | `crates/core/chio-core/src/lib.rs` |\n",
        );
        assert_eq!(renamed_property.rows.len(), 0);
        assert_eq!(
            renamed_property.warnings,
            vec!["line 1: property table missing required columns: Property"]
        );
    }

    #[test]
    fn committed_markdown_drift_is_rejected() {
        if let Err(error) = verify_committed_markdown("same\n", "same\n") {
            panic!("matching Markdown was rejected: {error}");
        }
        let error = match verify_committed_markdown("stale\n", "generated\n") {
            Ok(()) => panic!("stale Markdown unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("first difference at line 1"));
        assert!(error.contains("stale"));
        assert!(error.contains("generated"));
    }

    #[test]
    fn mapping_source_and_rust_path_validation_fail_closed() {
        let root = std::env::temp_dir().join(format!(
            "chio-proof-coverage-mapping-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        if let Err(error) = fs::create_dir_all(root.join("formal/tla")) {
            panic!("cannot create mapping fixture: {error}");
        }
        if let Err(error) = fs::write(root.join("formal/tla/Test.tla"), "Present == TRUE\n") {
            panic!("cannot write mapping fixture: {error}");
        }
        let row = MappingRow {
            section: "TLA properties".to_string(),
            property: "Missing".to_string(),
            source: "`formal/tla/Test.tla`".to_string(),
            rust_paths: "`crates/core/chio-core-types/src/missing.rs`".to_string(),
        };
        let error = match validate_mapping_source(&row, &root, &mut BTreeMap::new()) {
            Ok(_) => panic!("missing source property unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("does not define property Missing"));

        let workspace = WorkspaceCatalog {
            packages: BTreeMap::from([(
                "chio-core-types".to_string(),
                WorkspacePackage {
                    name: "chio-core-types".to_string(),
                    root: "crates/core/chio-core-types".to_string(),
                    lib_names: vec!["chio_core_types".to_string()],
                },
            )]),
            lib_to_package: BTreeMap::new(),
            projection_sha256: String::new(),
        };
        let resolution = match surfaces_from_mapping(&row.rust_paths, &root, &workspace) {
            Ok(resolution) => resolution,
            Err(error) => panic!("Rust path resolution failed: {error}"),
        };
        assert!(resolution.surfaces.is_empty());
        assert_eq!(
            resolution.unresolved,
            vec!["crates/core/chio-core-types/src/missing.rs"]
        );
        if let Err(error) = fs::remove_dir_all(&root) {
            panic!("cannot remove mapping fixture: {error}");
        }
    }

    #[test]
    fn multi_file_evidence_uses_conservative_ownership() {
        let mut rows = BTreeMap::new();
        let mut artifacts = BTreeMap::new();
        let mut unattributed = Vec::new();
        if let Err(error) = add_or_unattribute(
            &mut rows,
            &mut artifacts,
            &mut unattributed,
            "same-package".to_string(),
            "tla",
            vec![
                "chio-kernel::budget_store.rs".to_string(),
                "chio-kernel::receipt_store.rs".to_string(),
            ],
            "missing",
            Vec::new(),
        ) {
            panic!("same-package attribution failed: {error}");
        }
        assert_eq!(
            artifacts
                .get("same-package")
                .map(|artifact| artifact.primary_surface.as_str()),
            Some("chio-kernel::*")
        );

        if let Err(error) = add_or_unattribute(
            &mut rows,
            &mut artifacts,
            &mut unattributed,
            "cross-package".to_string(),
            "tla",
            vec![
                "chio-kernel::receipt_store.rs".to_string(),
                "chio-kernel-core::evaluate.rs".to_string(),
            ],
            "missing",
            Vec::new(),
        ) {
            panic!("cross-package attribution failed: {error}");
        }
        assert!(!artifacts.contains_key("cross-package"));
        assert!(unattributed.iter().any(|artifact| {
            artifact.id == "cross-package" && artifact.reason.contains("multiple Rust packages")
        }));

        let (primary, related) = conservative_harness_attribution(
            vec![
                "chio-kernel::receipt_store.rs".to_string(),
                "chio-kernel-core::evaluate.rs".to_string(),
            ],
            "chio-kernel-core::*".to_string(),
        );
        assert_eq!(primary, "chio-kernel-core::*");
        assert_eq!(related.len(), 2);
    }

    #[test]
    fn mutation_globs_require_live_files_and_apply_exclusions() {
        let tracked = vec![
            "crates/guards/chio-policy/src/evaluate.rs".to_string(),
            "crates/guards/chio-policy/src/tests.rs".to_string(),
        ];
        let config = MutationConfig {
            additional_cargo_test_args: Vec::new(),
            examine_globs: vec!["crates/guards/chio-policy/src/*.rs".to_string()],
            exclude_globs: vec!["**/tests.rs".to_string()],
        };
        let effective = match effective_mutation_files(&config, &tracked) {
            Ok(files) => files,
            Err(error) => panic!("valid mutation globs failed: {error}"),
        };
        assert_eq!(
            effective,
            BTreeSet::from(["crates/guards/chio-policy/src/evaluate.rs".to_string()])
        );

        let error = match expand_mutation_globs(&["crates/missing/*.rs".to_string()], &tracked) {
            Ok(_) => panic!("stale mutation glob unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("matches no workspace Rust file"));
    }

    #[test]
    fn recorded_mutation_evidence_requires_completed_structured_result() {
        let config = "audits/mutation/per-crate-configs/chio-weights.toml";
        let valid = serde_json::json!({
            "crate": "chio-weights",
            "command": format!("cargo mutants --config {config} -p chio-weights"),
            "ran_finished_at": "2026-05-08T16:28:14Z",
            "evaluated": 66,
            "total_discovered": 66,
            "result_label": "FULL-BELOW-TARGET"
        });
        assert_eq!(
            mutation_evidence_is_complete(&valid, "chio-weights", config, "fixture"),
            Ok(true)
        );

        let substring_only = serde_json::json!({
            "crate": "chio-weights",
            "command": format!("echo prefix-{config}"),
            "ran_finished_at": "2026-05-08T16:28:14Z",
            "evaluated": 66,
            "total_discovered": 66,
            "result_label": "FULL-BELOW-TARGET"
        });
        assert_eq!(
            mutation_evidence_is_complete(&substring_only, "chio-weights", config, "fixture"),
            Ok(false)
        );

        let incomplete = serde_json::json!({
            "crate": "chio-weights",
            "command": format!("cargo mutants --config {config}"),
            "ran_finished_at": "2026-05-08T16:28:14Z",
            "evaluated": 1,
            "total_discovered": 66,
            "result_label": "FULL-BELOW-TARGET"
        });
        let error =
            match mutation_evidence_is_complete(&incomplete, "chio-weights", config, "fixture") {
                Ok(_) => panic!("incomplete mutation evidence unexpectedly passed"),
                Err(error) => error,
            };
        assert!(error.contains("not a completed full result"));
    }

    #[test]
    fn nonexistent_kani_crate_fails_closed() {
        let harnesses = vec![KaniHarness {
            crate_name: "missing-crate".to_string(),
            harness: "public_missing".to_string(),
            lane: "pr".to_string(),
            notes: String::new(),
            primary_rust_symbol: None,
        }];
        let workspace_members = BTreeSet::from(["chio-core".to_string()]);

        let error = match validate_kani_crates(&harnesses, &workspace_members) {
            Ok(()) => panic!("nonexistent crate unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("missing-crate"));
        assert!(error.contains("public_missing"));
    }

    #[test]
    fn fuzz_owner_keys_must_match_targets_exactly() {
        let fuzz_map = FuzzMap {
            targets: BTreeMap::from([(
                "target-a".to_string(),
                FuzzTarget {
                    crate_name: "chio-core".to_string(),
                    path: "fuzz/fuzz_targets/target-a.rs".to_string(),
                    triggers: Vec::new(),
                },
            )]),
        };
        let missing = FuzzOwners {
            targets: BTreeMap::new(),
        };
        let error = match validate_fuzz_owner_keys(&fuzz_map, &missing) {
            Ok(()) => panic!("missing fuzz owner unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("missing=[\"target-a\"]"));

        let stale = FuzzOwners {
            targets: BTreeMap::from([
                (
                    "target-a".to_string(),
                    FuzzOwner {
                        crate_name: "chio-core".to_string(),
                        path: "crates/core/chio-core".to_string(),
                    },
                ),
                (
                    "target-b".to_string(),
                    FuzzOwner {
                        crate_name: "chio-core".to_string(),
                        path: "crates/core/chio-core".to_string(),
                    },
                ),
            ]),
        };
        let error = match validate_fuzz_owner_keys(&fuzz_map, &stale) {
            Ok(()) => panic!("stale fuzz owner unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("stale=[\"target-b\"]"));
    }

    #[test]
    fn unmapped_kani_fallback_is_limited_to_known_receipt_harnesses() {
        let root = match workspace_root() {
            Ok(root) => root,
            Err(error) => panic!("workspace root failed: {error}"),
        };
        let workspace = WorkspaceCatalog {
            packages: BTreeMap::from([(
                "chio-kernel-core".to_string(),
                WorkspacePackage {
                    name: "chio-kernel-core".to_string(),
                    root: "crates/kernel/chio-kernel-core".to_string(),
                    lib_names: vec!["chio_kernel_core".to_string()],
                },
            )]),
            lib_to_package: BTreeMap::new(),
            projection_sha256: String::new(),
        };
        let unknown = KaniHarness {
            crate_name: "chio-kernel-core".to_string(),
            harness: "future_unmapped_harness".to_string(),
            lane: "pr".to_string(),
            notes: String::new(),
            primary_rust_symbol: None,
        };
        let receipt = KaniHarness {
            crate_name: "chio-kernel-core".to_string(),
            harness: "public_sign_receipt_refuses_content_hash_mismatch".to_string(),
            lane: "pr".to_string(),
            notes: String::new(),
            primary_rust_symbol: None,
        };

        assert_eq!(
            infer_harness_surface(&unknown, &root, &workspace),
            "chio-kernel-core::*"
        );
        assert_eq!(
            infer_harness_surface(&receipt, &root, &workspace),
            "chio-kernel-core::receipts.rs"
        );
    }

    #[test]
    fn matrix_rows_stay_within_source_width_limit() {
        let mut row = CoverageRow {
            surface: "chio-kernel-core::evaluate.rs".to_string(),
            ..CoverageRow::default()
        };
        row.lanes.insert(
            "lean".to_string(),
            BTreeSet::from([
                "proof.evalToolCall_total".to_string(),
                "proof.evalToolCall_out_of_scope_denies".to_string(),
            ]),
        );
        let lanes = vec!["lean".to_string(), "kani".to_string()];

        let markdown = render_markdown(&[row], &lanes, &[]);
        assert!(markdown.lines().all(|line| line.len() <= 120));
        assert!(markdown.contains("proof.evalToolCall_total"));
    }

    #[test]
    fn current_registries_have_total_primary_attribution() {
        let root = match workspace_root() {
            Ok(root) => root,
            Err(error) => panic!("workspace root failed: {error}"),
        };
        let build = match build_coverage(&root) {
            Ok(build) => build,
            Err(error) => panic!("coverage build failed: {error}"),
        };

        assert!(
            build.parse_warnings.is_empty(),
            "{:?}",
            build.parse_warnings
        );
        let kani: KaniManifest = match parse_toml(
            ".kani/harnesses.toml",
            include_str!("../../.kani/harnesses.toml"),
        ) {
            Ok(kani) => kani,
            Err(error) => panic!("Kani registry parse failed: {error}"),
        };
        let fuzz_map: FuzzMap = match parse_toml(
            "fuzz/target-map.toml",
            include_str!("../../fuzz/target-map.toml"),
        ) {
            Ok(fuzz_map) => fuzz_map,
            Err(error) => panic!("fuzz registry parse failed: {error}"),
        };
        let inventory: TheoremInventory =
            match serde_json::from_str(include_str!("../../formal/theorem-inventory.json")) {
                Ok(inventory) => inventory,
                Err(error) => panic!("theorem inventory parse failed: {error}"),
            };
        let mutant_configs = match files_in_dir(&root, "audits/mutation/per-crate-configs", "toml")
        {
            Ok(paths) => paths,
            Err(error) => panic!("mutation config discovery failed: {error}"),
        };
        let diff_tests = match files_in_dir(&root, "formal/diff-tests/tests", "rs") {
            Ok(paths) => paths,
            Err(error) => panic!("differential test discovery failed: {error}"),
        };
        assert_eq!(
            build
                .artifacts
                .iter()
                .filter(|artifact| artifact.id.starts_with(".kani/harnesses.toml::"))
                .count(),
            kani.harness.len()
        );
        assert_eq!(
            build
                .artifacts
                .iter()
                .filter(|artifact| artifact.lane == "kani")
                .count(),
            kani.harness.len()
        );
        assert_eq!(
            build
                .artifacts
                .iter()
                .filter(|artifact| artifact.id.starts_with("fuzz/target-map.toml::"))
                .count(),
            fuzz_map.targets.len()
        );
        let classified_mutants = build
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact
                    .id
                    .starts_with("audits/mutation/per-crate-configs/")
            })
            .count()
            + build
                .unattributed_artifacts
                .iter()
                .filter(|artifact| {
                    artifact
                        .id
                        .starts_with("audits/mutation/per-crate-configs/")
                })
                .count();
        assert_eq!(classified_mutants, mutant_configs.len());
        assert!(build.unattributed_artifacts.iter().any(|artifact| {
            artifact.id.ends_with("chio-guards-2026-05-08-subset.toml")
                && artifact.qualifiers.get("status").map(String::as_str) == Some("historical")
        }));
        assert!(build.artifacts.iter().any(|artifact| {
            artifact.id == ".cargo/mutants.toml::chio-credentials"
                && artifact.primary_surface == "chio-credentials::*"
        }));
        assert_eq!(
            build
                .unattributed_artifacts
                .iter()
                .filter(|artifact| { artifact.id.starts_with("formal/theorem-inventory.json::") })
                .count(),
            inventory.assumptions.len() + inventory.theorems.len()
        );
        assert_eq!(
            build
                .unattributed_artifacts
                .iter()
                .filter(|artifact| artifact.id.starts_with("formal/diff-tests/tests/"))
                .count(),
            diff_tests.len()
        );
        let manual_mirror_count = build
            .review_links
            .iter()
            .filter(|link| link.kind == "manual_mirror")
            .count();
        let contract_twin_count = build
            .review_links
            .iter()
            .filter(|link| link.kind == "creusot_contract_twin")
            .count();
        let proof_manifest: ProofManifest = match parse_toml(
            "formal/proof-manifest.toml",
            include_str!("../../formal/proof-manifest.toml"),
        ) {
            Ok(manifest) => manifest,
            Err(error) => panic!("proof manifest parse failed: {error}"),
        };
        let creusot: TomlValue = match parse_toml(
            "formal/rust-verification/creusot-contracts.toml",
            include_str!("../../formal/rust-verification/creusot-contracts.toml"),
        ) {
            Ok(manifest) => manifest,
            Err(error) => panic!("Creusot registry parse failed: {error}"),
        };
        let expected_twins = creusot
            .get("contract_twin")
            .and_then(TomlValue::as_array)
            .map_or(0, Vec::len);
        assert_eq!(manual_mirror_count, proof_manifest.mirror.len());
        assert_eq!(contract_twin_count, expected_twins);
        assert!(build.artifacts.iter().all(|artifact| {
            !artifact.id.contains("::mirror::") && !artifact.id.contains("::contract_twin::")
        }));
    }

    #[test]
    fn rendering_is_byte_deterministic() {
        let root = match workspace_root() {
            Ok(root) => root,
            Err(error) => panic!("workspace root failed: {error}"),
        };
        let build = match build_coverage(&root) {
            Ok(build) => build,
            Err(error) => panic!("coverage build failed: {error}"),
        };
        let first = match render_document(&build) {
            Ok(markdown) => markdown,
            Err(error) => panic!("first render failed: {error}"),
        };
        let second = match render_document(&build) {
            Ok(markdown) => markdown,
            Err(error) => panic!("second render failed: {error}"),
        };

        assert_eq!(first.as_bytes(), second.as_bytes());
        assert!(first.contains(COMMIT_TOKEN));
        assert!(first.contains(&build.input_digest));
        assert!(first.contains("scope=model-only"));
        assert!(first.contains("status=assumed"));
        assert!(first.contains("status=unknown"));
        assert!(first.contains("## Non-Proof Linkage Metadata"));
        assert!(first.contains("do not populate evidence cells"));
    }

    #[test]
    fn optional_registry_files_add_concurrency_lanes() {
        let root = std::env::temp_dir().join(format!(
            "chio-proof-coverage-optional-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        for directory in [".loom", ".dst", "crates/kernel/chio-kernel/tests"] {
            if let Err(error) = fs::create_dir_all(root.join(directory)) {
                panic!("cannot create optional registry fixture: {error}");
            }
        }
        if let Err(error) = fs::write(
            root.join(".loom/harnesses.toml"),
            "schema = \"chio.loom.v1\"\n\n[[harness]]\ncrate = \"chio-kernel\"\ntest = \"loom_concurrency::drop_race\"\nmax_preemptions = 3\nlane = \"nightly\"\nscope = \"bounded_abstract_model\"\nnotes = \"drop race model\"\n",
        ) {
            panic!("cannot write loom fixture: {error}");
        }
        if let Err(error) = fs::write(
            root.join("crates/kernel/chio-kernel/tests/loom_concurrency.rs"),
            "#[test]\nfn drop_race() {}\n",
        ) {
            panic!("cannot write loom source fixture: {error}");
        }
        if let Err(error) = fs::write(
            root.join(".dst/harnesses.toml"),
            "schema = \"chio.dst.v1\"\n\n[[harness]]\ncrate = \"chio-kernel\"\ntest = \"dst_drop_race\"\n",
        ) {
            panic!("cannot write DST fixture: {error}");
        }
        let workspace = WorkspaceCatalog {
            packages: BTreeMap::from([(
                "chio-kernel".to_string(),
                WorkspacePackage {
                    name: "chio-kernel".to_string(),
                    root: "crates/kernel/chio-kernel".to_string(),
                    lib_names: vec!["chio_kernel".to_string()],
                },
            )]),
            lib_to_package: BTreeMap::new(),
            projection_sha256: String::new(),
        };
        let mut inputs = BTreeMap::new();
        let mut lanes = BASE_LANES
            .iter()
            .map(|lane| (*lane).to_string())
            .collect::<Vec<_>>();
        let mapping = BTreeMap::from([(
            "drop_race".to_string(),
            vec!["chio-kernel::kernel_drop_guard.rs".to_string()],
        )]);
        let mut rows = BTreeMap::new();
        let mut artifacts = BTreeMap::new();

        if let Err(error) = add_optional_concurrency_artifacts(
            &root,
            &workspace,
            &mut inputs,
            &mut lanes,
            &mapping,
            &mut rows,
            &mut artifacts,
        ) {
            panic!("optional registry load failed: {error}");
        }

        assert!(lanes.iter().any(|lane| lane == "loom"));
        assert!(lanes.iter().any(|lane| lane == "dst"));
        assert_eq!(
            artifacts
                .get(".loom/harnesses.toml::chio-kernel/loom_concurrency::drop_race")
                .map(|artifact| artifact.primary_surface.as_str()),
            Some("chio-kernel::kernel_drop_guard.rs")
        );
        assert_eq!(
            artifacts
                .get(".loom/harnesses.toml::chio-kernel/loom_concurrency::drop_race")
                .and_then(|artifact| artifact.qualifiers.get("lane"))
                .map(String::as_str),
            Some("nightly")
        );
        assert_eq!(
            artifacts
                .get(".loom/harnesses.toml::chio-kernel/loom_concurrency::drop_race")
                .and_then(|artifact| artifact.qualifiers.get("scope"))
                .map(String::as_str),
            Some("bounded_abstract_model")
        );
        let package = match workspace.packages.get("chio-kernel") {
            Some(package) => package,
            None => panic!("loom fixture package is missing"),
        };
        let missing_test = LoomHarness {
            crate_name: "chio-kernel".to_string(),
            test: "loom_concurrency::missing_test".to_string(),
            max_preemptions: 3,
            lane: "nightly".to_string(),
            scope: "bounded_abstract_model".to_string(),
            notes: "missing test".to_string(),
        };
        let error = match validate_loom_harness(&root, package, &missing_test) {
            Ok(()) => panic!("missing loom test unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("loom test not found"));
        assert_eq!(
            artifacts
                .get(".dst/harnesses.toml::chio-kernel/dst_drop_race")
                .map(|artifact| artifact.primary_surface.as_str()),
            Some("chio-kernel::*")
        );
        if let Err(error) = fs::remove_file(root.join(".loom/harnesses.toml")) {
            panic!("cannot remove loom fixture: {error}");
        }
        if let Err(error) = fs::write(
            root.join(".dst/harnesses.toml"),
            "schema = \"chio.dst.v1\"\n",
        ) {
            panic!("cannot write malformed DST fixture: {error}");
        }
        let mut malformed_inputs = BTreeMap::new();
        let mut malformed_lanes = BASE_LANES
            .iter()
            .map(|lane| (*lane).to_string())
            .collect::<Vec<_>>();
        let mut malformed_rows = BTreeMap::new();
        let mut malformed_artifacts = BTreeMap::new();
        let error = match add_optional_concurrency_artifacts(
            &root,
            &workspace,
            &mut malformed_inputs,
            &mut malformed_lanes,
            &BTreeMap::new(),
            &mut malformed_rows,
            &mut malformed_artifacts,
        ) {
            Ok(()) => panic!("empty DST registry unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("contains no harnesses"));
        if let Err(error) = fs::remove_dir_all(&root) {
            panic!("cannot remove optional registry fixture: {error}");
        }
    }

    #[test]
    fn loom_registry_schema_and_values_fail_closed() {
        let missing_field = "schema = \"chio.loom.v1\"\n\n[[harness]]\ncrate = \"chio-kernel\"\ntest = \"loom_concurrency::drop_race\"\nlane = \"nightly\"\nscope = \"bounded_abstract_model\"\nnotes = \"drop race\"\n";
        let error = match parse_toml::<LoomManifest>("fixture", missing_field) {
            Ok(_) => panic!("loom harness without max_preemptions unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("max_preemptions"));

        let unknown_field = "schema = \"chio.loom.v1\"\n\n[[harness]]\ncrate = \"chio-kernel\"\ntest = \"loom_concurrency::drop_race\"\nmax_preemptions = 3\nlane = \"nightly\"\nscope = \"bounded_abstract_model\"\nnotes = \"drop race\"\nfuture = true\n";
        let error = match parse_toml::<LoomManifest>("fixture", unknown_field) {
            Ok(_) => panic!("unknown loom harness field unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("unknown field"));

        let package = WorkspacePackage {
            name: "chio-kernel".to_string(),
            root: "crates/kernel/chio-kernel".to_string(),
            lib_names: Vec::new(),
        };
        let mut harness = LoomHarness {
            crate_name: "chio-kernel".to_string(),
            test: "loom_concurrency::drop_race".to_string(),
            max_preemptions: 0,
            lane: "nightly".to_string(),
            scope: "bounded_abstract_model".to_string(),
            notes: "drop race".to_string(),
        };
        let error = match validate_loom_harness(Path::new("/missing"), &package, &harness) {
            Ok(()) => panic!("zero loom preemptions unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("must be positive"));

        harness.max_preemptions = 3;
        harness.lane = "weekly".to_string();
        let error = match validate_loom_harness(Path::new("/missing"), &package, &harness) {
            Ok(()) => panic!("unknown loom lane unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("unsupported lane"));

        harness.lane = "nightly".to_string();
        harness.scope = "production_primitive_proof".to_string();
        let error = match validate_loom_harness(Path::new("/missing"), &package, &harness) {
            Ok(()) => panic!("unknown loom scope unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("unsupported scope"));

        harness.scope = "bounded_abstract_model".to_string();
        harness.test = "drop_race".to_string();
        let error = match validate_loom_harness(Path::new("/missing"), &package, &harness) {
            Ok(()) => panic!("malformed loom test name unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("<integration-target>::<test-name>"));

        harness.test = "loom_concurrency::drop_race".to_string();
        harness.notes = "  ".to_string();
        let error = match validate_loom_harness(Path::new("/missing"), &package, &harness) {
            Ok(()) => panic!("blank loom notes unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("must be non-empty"));

        let dst_unknown = "schema = \"chio.dst.v1\"\n\n[[harness]]\ncrate = \"chio-kernel\"\ntest = \"dst_drop_race\"\nseed = 1\n";
        let error = match parse_toml::<DstManifest>("fixture", dst_unknown) {
            Ok(_) => panic!("unknown DST harness field unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("unknown field"));
    }

    #[test]
    fn lane_postures_reject_missing_posture() {
        let valid =
            "[gates.lean-build]\nposture = \"required\"\n\n[gates.kani]\nposture = \"advisory\"\n";
        let postures = match lane_postures(valid) {
            Ok(postures) => postures,
            Err(error) => panic!("valid gate posture failed: {error}"),
        };
        assert_eq!(
            postures.get("lean-build").map(String::as_str),
            Some("required")
        );
        assert_eq!(postures.get("kani").map(String::as_str), Some("advisory"));

        let error = match lane_postures("[gates.lean-build]\nworkflow = \"ci.yml\"\n") {
            Ok(_) => panic!("missing posture unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("lean-build"));
        assert!(error.contains("posture"));

        let error = match lane_postures("[gates.lean-build]\nposture = \"blocking\"\n") {
            Ok(_) => panic!("unsupported posture unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("unsupported posture"));
    }

    #[test]
    fn refinement_registry_schema_and_fields_are_exact() {
        assert_eq!(
            expected_refinement_schema(
                "kani",
                "required",
                "formal/rust-verification/kani-harnesses.toml"
            ),
            Ok("chio.kani-harnesses.v1")
        );
        let error = match expected_refinement_schema(
            "kani",
            "required",
            "formal/rust-verification/future.toml",
        ) {
            Ok(_) => panic!("unknown refinement registry unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("unsupported refinement registry declaration"));

        let value: TomlValue = match parse_toml("fixture", "schema = \"chio.test.v1\"\n") {
            Ok(value) => value,
            Err(error) => panic!("fixture parse failed: {error}"),
        };
        let error = match required_toml_string_array(&value, "covered_symbols", "fixture") {
            Ok(_) => panic!("missing refinement field unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("has no covered_symbols"));

        let twins: TomlValue = match parse_toml(
            "fixture",
            "covered_symbols = [\"formal/rust-verification/creusot-core::allows_contract\"]\n\n[[contract_twin]]\ncontract = \"allows_contract\"\nproduction = \"allows\"\n",
        ) {
            Ok(value) => value,
            Err(error) => panic!("contract twin fixture parse failed: {error}"),
        };
        let links = match contract_twin_review_links(
            &twins,
            "fixture",
            &["formal/rust-verification/creusot-core::allows_contract".to_string()],
        ) {
            Ok(links) => links,
            Err(error) => panic!("valid contract twin failed: {error}"),
        };
        assert_eq!(links.len(), 1);

        let error = match contract_twin_review_links(
            &twins,
            "fixture",
            &[
                "formal/rust-verification/creusot-core::allows_contract".to_string(),
                "formal/rust-verification/creusot-core::stale_contract".to_string(),
            ],
        ) {
            Ok(_) => panic!("stale covered contract unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("do not match covered_symbols"));
    }

    fn mutation_fixture_root(label: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "chio-proof-coverage-{label}-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn write_mutation_fixture(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            if let Err(error) = fs::create_dir_all(parent) {
                panic!("cannot create mutation fixture directory: {error}");
            }
        }
        if let Err(error) = fs::write(path, contents) {
            panic!("cannot write mutation fixture {relative}: {error}");
        }
    }

    fn commit_mutation_fixture(root: &Path) -> String {
        for arguments in [
            vec!["init", "--quiet"],
            vec!["add", "."],
            vec![
                "-c",
                "user.name=Chio Test",
                "-c",
                "user.email=chio-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "test: fixture",
            ],
        ] {
            let output = match Command::new("git")
                .args(&arguments)
                .current_dir(root)
                .output()
            {
                Ok(output) => output,
                Err(error) => panic!("cannot run Git for mutation fixture: {error}"),
            };
            if !output.status.success() {
                panic!(
                    "cannot prepare mutation fixture commit with {arguments:?}: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
        }
        match git_commit(root) {
            Ok(commit) => commit,
            Err(error) => panic!("cannot resolve mutation fixture commit: {error}"),
        }
    }

    fn mutation_fixture_git(root: &Path, arguments: &[&str]) -> String {
        let output = match Command::new("git")
            .args(arguments)
            .current_dir(root)
            .output()
        {
            Ok(output) => output,
            Err(error) => panic!("cannot run Git for mutation fixture: {error}"),
        };
        if !output.status.success() {
            panic!(
                "mutation fixture Git command failed with {arguments:?}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn mutation_inventory(lane: &str, source: &str, count: usize) -> Vec<serde_json::Value> {
        let source_key = if lane == "spec-mutants" {
            "path"
        } else {
            "file"
        };
        let source_name = Path::new(source)
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("Fixture");
        (0..count)
            .map(|index| {
                let id = format!("{:020x}", index + 1);
                let mut mutant = serde_json::json!({"id": id});
                mutant[source_key] = serde_json::json!(source);
                if lane == "spec-mutants" {
                    mutant["spec"] = serde_json::json!(source_name);
                    if index == 0 {
                        mutant["registered_seed"] = serde_json::json!("fixture-seed");
                    }
                }
                mutant
            })
            .collect()
    }

    fn mutation_target(lane: &str, source: &str) -> FormalMutationTarget {
        let inventory = mutation_inventory(lane, source, 10);
        let encoded = match serde_json::to_vec(&inventory) {
            Ok(value) => value,
            Err(error) => panic!("cannot encode mutation fixture inventory: {error}"),
        };
        FormalMutationTarget {
            name: "fixture-model".to_string(),
            lane: lane.to_string(),
            source: source.to_string(),
            report: format!("target/formal/{lane}/outcomes.json"),
            activation_target_percent: 90.0,
            inventory_sha256: sha256_hex(&encoded),
            rust_paths: vec![source.to_string()],
            latest_full_cycle: None,
        }
    }

    fn mutation_observation(commit: &str) -> FormalMutationObservation {
        FormalMutationObservation {
            commit: commit.to_string(),
            measured_at: "2026-07-10T12:00:00Z".to_string(),
            evidence: "formal/mutation/evidence/fixture-model.json".to_string(),
            report_sha256: "2".repeat(64),
            enumerated: 10,
            killed: 9,
            survived: 0,
            unviable: 0,
            timeout: 1,
            activation_ratio_percent: 90.0,
        }
    }

    fn spec_score_fixture(
        counts: MutationVerdictCounts,
        activation_target_percent: f64,
    ) -> serde_json::Value {
        let sampled = match counts.sampled() {
            Ok(value) => value,
            Err(error) => panic!("cannot count specification score fixture: {error}"),
        };
        let denominator = match counts.score_denominator() {
            Ok(value) => value,
            Err(error) => panic!("cannot score specification fixture: {error}"),
        };
        let activation = match counts.activation_ratio_percent() {
            Ok(value) => value,
            Err(error) => panic!("cannot score specification fixture: {error}"),
        };
        let completion = match counts.completion_ratio_percent() {
            Ok(value) => value,
            Err(error) => panic!("cannot score specification fixture: {error}"),
        };
        serde_json::json!({
            "sampled": sampled,
            "killed": counts.killed,
            "survived": counts.survived,
            "unviable": counts.unviable,
            "timeout": counts.timeout,
            "score_denominator": denominator,
            "timeout_policy": "timeouts count as not killed",
            "activation_ratio_percent": activation,
            "completion_ratio_percent": completion,
            "activation_target_percent": activation_target_percent,
            "activation_met": activation + 0.000_5 >= activation_target_percent,
        })
    }

    fn proof_score_fixture(
        counts: MutationVerdictCounts,
        activation_target_percent: f64,
    ) -> serde_json::Value {
        let mut score = spec_score_fixture(counts, activation_target_percent);
        let sampled = match counts.sampled() {
            Ok(value) => value,
            Err(error) => panic!("cannot count proof score fixture: {error}"),
        };
        let denominator = match counts.score_denominator() {
            Ok(value) => value,
            Err(error) => panic!("cannot score proof fixture: {error}"),
        };
        let viability = if sampled == 0 {
            0.0
        } else {
            100.0 * denominator as f64 / sampled as f64
        };
        let activation_met = score["activation_met"].as_bool() == Some(true);
        let viability_met = viability + 0.000_5 >= 80.0;
        score["activation_threshold_met"] = serde_json::json!(activation_met);
        score["viability_ratio_percent"] = serde_json::json!(viability);
        score["viability_target_percent"] = serde_json::json!(80.0);
        score["viability_met"] = serde_json::json!(viability_met);
        score["activation_met"] = serde_json::json!(activation_met && viability_met);
        score
    }

    fn registered_negative_fixture(root: &Path) -> serde_json::Value {
        let (_, negative_entries) = match spec_mutation_negative_registry(root) {
            Ok(value) => value,
            Err(error) => panic!("cannot read specification preflight fixture: {error}"),
        };
        serde_json::Value::Array(
            negative_entries
                .into_iter()
                .map(|entry| {
                    let stem = Path::new(&entry.spec)
                        .file_stem()
                        .and_then(|value| value.to_str())
                        .unwrap_or("Broken");
                    serde_json::json!({
                        "spec": entry.spec,
                        "cfg": entry.cfg,
                        "invariant": entry.falsifies,
                        "length": entry.length,
                        "timeout_secs": entry.timeout_secs,
                        "verdict": "killed",
                        "log_sha256": "0".repeat(64),
                        "trace": format!(
                            "target/formal/spec-mutants/registered-negative/{stem}/run/violation1.itf.json"
                        ),
                        "trace_sha256": "1".repeat(64),
                    })
                })
                .collect(),
        )
    }

    fn positive_baselines_fixture(root: &Path) -> serde_json::Value {
        let specs = match spec_mutation_allowlist_specs(root) {
            Ok(value) => value,
            Err(error) => panic!("cannot read specification baseline fixture: {error}"),
        };
        serde_json::Value::Array(
            specs
                .into_values()
                .map(|spec| {
                    serde_json::json!({
                        "spec": spec.name,
                        "path": spec.path,
                        "cfg": spec.cfg,
                        "invariant": spec.invariant,
                        "length": spec.length,
                        "verdict": "survived",
                        "apalache_exit": 0,
                        "wall_secs": 1.25,
                        "log_sha256": "2".repeat(64),
                    })
                })
                .collect(),
        )
    }

    fn mutation_report(
        root: &Path,
        target: &FormalMutationTarget,
        observation: &FormalMutationObservation,
        inputs: &BTreeMap<String, String>,
    ) -> serde_json::Value {
        let verdicts = [
            ("killed", observation.killed),
            ("survived", observation.survived),
            ("unviable", observation.unviable),
            ("timeout", observation.timeout),
        ]
        .into_iter()
        .flat_map(|(verdict, count)| std::iter::repeat_n(verdict, count))
        .collect::<Vec<_>>();
        let source_name = Path::new(&target.source)
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("Fixture");
        let inventory = mutation_inventory(&target.lane, &target.source, observation.enumerated);
        let mutants = inventory
            .iter()
            .cloned()
            .zip(verdicts)
            .map(|(mut mutant, verdict)| {
                mutant["verdict"] = serde_json::json!(verdict);
                mutant
            })
            .collect::<Vec<_>>();
        let inventory_bytes = match serde_json::to_vec(&inventory) {
            Ok(value) => value,
            Err(error) => panic!("cannot encode report inventory fixture: {error}"),
        };
        let mut report = serde_json::json!({
            "schema": if target.lane == "spec-mutants" {
                "chio.spec-mutants-report.v1"
            } else {
                "chio.proof-mutants-report.v1"
            },
            "commit": observation.commit,
            "measured_at": observation.measured_at,
            "full_cycle": true,
            "worktree": {"clean": true},
            "enumerated": observation.enumerated,
            "inventory": inventory,
            "inventory_sha256": sha256_hex(&inventory_bytes),
            "tools": if target.lane == "spec-mutants" {
                serde_json::json!({"apalache": "0.50.1"})
            } else {
                serde_json::json!({
                    "cargo_mutants": "25.3.1",
                    "kani": "0.67.0",
                    "rustc": "1.93.0",
                })
            },
            "inputs": inputs.iter().map(|(path, sha256)| {
                serde_json::json!({"path": path, "sha256": sha256})
            }).collect::<Vec<_>>(),
            "mutants": mutants,
            "aggregate": {
                "sampled": observation.enumerated,
                "killed": observation.killed,
                "survived": observation.survived,
                "unviable": observation.unviable,
                "timeout": observation.timeout,
                "activation_ratio_percent": observation.activation_ratio_percent,
            },
        });
        let counts = MutationVerdictCounts {
            killed: observation.killed,
            survived: observation.survived,
            unviable: observation.unviable,
            timeout: observation.timeout,
        };
        if target.lane == "spec-mutants" {
            let activation_met =
                observation.activation_ratio_percent + 0.000_5 >= target.activation_target_percent;
            let score = spec_score_fixture(counts, target.activation_target_percent);
            let mut source_aggregates = serde_json::Map::new();
            source_aggregates.insert(source_name.to_string(), score.clone());
            report["source_aggregates"] = serde_json::Value::Object(source_aggregates);
            report["aggregate"] = score;
            report["aggregate"]["global_activation_met"] = serde_json::json!(activation_met);
            report["aggregate"]["source_activation_met"] = serde_json::json!(activation_met);
            report["registered_seeds"] = serde_json::json!([{
                "name": "fixture-seed",
                "mutant_id": "00000000000000000001",
                "negative_spec": "formal/apalache/_negative_tests/FixtureBroken.tla",
                "status": "subsumed",
            }]);
            report["registered_negative"] = registered_negative_fixture(root);
            report["positive_baselines"] = positive_baselines_fixture(root);
        } else {
            let score = proof_score_fixture(counts, target.activation_target_percent);
            let activation_met = score["activation_met"].as_bool() == Some(true);
            report["source_aggregates"] = serde_json::json!({target.source.clone(): score.clone()});
            report["aggregate"] = score;
            report["aggregate"]["global_activation_met"] = serde_json::json!(activation_met);
            report["aggregate"]["source_activation_met"] = serde_json::json!(activation_met);
        }
        report
    }

    fn single_input_fixture(
        label: &str,
    ) -> (
        std::path::PathBuf,
        FormalMutationTarget,
        FormalMutationObservation,
        BTreeMap<String, String>,
        serde_json::Value,
    ) {
        let root = mutation_fixture_root(label);
        let source = "crates/kernel/chio-kernel-core/src/formal_core.rs";
        write_mutation_fixture(&root, source, "pub fn model() -> bool { true }\n");
        let (_, bytes) = match regular_mutation_input_bytes(&root, source) {
            Ok(value) => value,
            Err(error) => panic!("cannot hash mutation fixture: {error}"),
        };
        let inputs = BTreeMap::from([(source.to_string(), sha256_hex(&bytes))]);
        let target = mutation_target("proof-mutants", source);
        let commit = commit_mutation_fixture(&root);
        let observation = mutation_observation(&commit);
        let report = mutation_report(&root, &target, &observation, &inputs);
        (root, target, observation, inputs, report)
    }

    fn specification_preflight_fixture(
        label: &str,
    ) -> (
        std::path::PathBuf,
        FormalMutationTarget,
        FormalMutationObservation,
        BTreeMap<String, String>,
        serde_json::Value,
    ) {
        let root = mutation_fixture_root(label);
        for (path, contents) in [
            (
                "formal/apalache/spec-mutants-allowlist.toml",
                "schema = \"chio.spec-mutants-allowlist.v1\"\nnegative_registry = \"formal/apalache/_negative_tests/REGISTRY.toml\"\n\n[[spec]]\nname = \"Fixture\"\npath = \"formal/apalache/Fixture.tla\"\ncfg = \"formal/apalache/MCFixture.cfg\"\ninvariant = \"SafetyInv\"\nlength = 4\n\n[[seed]]\nname = \"fixture-seed\"\nnegative_spec = \"formal/apalache/_negative_tests/FixtureBroken.tla\"\n",
            ),
            (
                "formal/apalache/_negative_tests/REGISTRY.toml",
                "schema = \"chio.apalache-negative.v1\"\n\n[[negative]]\nspec = \"formal/apalache/_negative_tests/FixtureBroken.tla\"\ncfg = \"formal/apalache/_negative_tests/MCFixtureBroken.cfg\"\nfalsifies = \"SafetyInv\"\nlength = 4\ntimeout_secs = 30\nruntime_test = \"n/a (fixture)\"\n",
            ),
            (
                "formal/apalache/Fixture.tla",
                "---- MODULE Fixture ----\n====\n",
            ),
            ("formal/apalache/MCFixture.cfg", "INVARIANT SafetyInv\n"),
            (
                "formal/apalache/_negative_tests/FixtureBroken.tla",
                "---- MODULE FixtureBroken ----\n====\n",
            ),
            (
                "formal/apalache/_negative_tests/MCFixtureBroken.cfg",
                "INVARIANT SafetyInv\n",
            ),
            ("formal/MAPPING.md", "# Mapping\n"),
            ("scripts/check-apalache-negative.sh", "exit 0\n"),
            ("scripts/lib/apalache_evidence.py", "SCHEMA = 1\n"),
            ("scripts/spec-mutants.py", "SCHEMA = 1\n"),
            ("tools/install-apalache.sh", "exit 0\n"),
        ] {
            write_mutation_fixture(&root, path, contents);
        }
        let commit = commit_mutation_fixture(&root);
        let mut coverage_inputs = BTreeMap::new();
        let inputs =
            match formal_mutation_expected_inputs(&root, "spec-mutants", &mut coverage_inputs) {
                Ok(inputs) => inputs,
                Err(error) => panic!("cannot build specification preflight inputs: {error}"),
            };
        let target = mutation_target("spec-mutants", "formal/apalache/Fixture.tla");
        let observation = mutation_observation(&commit);
        let report = mutation_report(&root, &target, &observation, &inputs);
        (root, target, observation, inputs, report)
    }

    #[test]
    fn formal_mutation_observation_counts_timeouts_in_activation() {
        let (root, target, valid, current_inputs, report) = single_input_fixture("timeout-aware");
        if let Err(error) =
            validate_formal_mutation_report(&root, &target, &valid, &report, &current_inputs)
        {
            panic!("valid timeout-aware observation failed: {error}");
        }

        let evidence_path = root.join(&valid.evidence);
        if let Some(parent) = evidence_path.parent() {
            if let Err(error) = fs::create_dir_all(parent) {
                panic!("cannot create formal mutation evidence fixture: {error}");
            }
        }
        let encoded = match serde_json::to_vec(&report) {
            Ok(encoded) => encoded,
            Err(error) => panic!("cannot encode formal mutation evidence fixture: {error}"),
        };
        if let Err(error) = fs::write(&evidence_path, &encoded) {
            panic!("cannot write formal mutation evidence fixture: {error}");
        }
        let bound = FormalMutationObservation {
            report_sha256: sha256_hex(&encoded),
            ..valid.clone()
        };
        let mut evidence_inputs = BTreeMap::new();
        if let Err(error) = validate_formal_mutation_observation(
            &root,
            &mut evidence_inputs,
            &target,
            &bound,
            &current_inputs,
        ) {
            panic!("report-backed formal mutation observation failed: {error}");
        }
        assert!(evidence_inputs.contains_key(&valid.evidence));

        let invalid = FormalMutationObservation {
            activation_ratio_percent: 100.0,
            ..valid
        };
        let mut invalid_report = report;
        invalid_report["aggregate"]["activation_ratio_percent"] = serde_json::json!(100.0);
        let error = match validate_formal_mutation_report(
            &root,
            &target,
            &invalid,
            &invalid_report,
            &current_inputs,
        ) {
            Ok(()) => panic!("timeout-excluding ratio unexpectedly passed"),
            Err(error) => error,
        };
        assert!(
            error.contains("proof global aggregate has an inconsistent activation_ratio_percent"),
            "unexpected error: {error}"
        );
        if let Err(error) = fs::remove_dir_all(&root) {
            panic!("cannot remove mutation fixture: {error}");
        }
    }

    #[test]
    fn formal_mutation_report_rejects_noncanonical_worktree_evidence() {
        let (root, target, observation, inputs, mut report) =
            single_input_fixture("worktree-evidence");
        report["worktree"]["status_sha256"] = serde_json::json!("0".repeat(64));
        let error =
            match validate_formal_mutation_report(&root, &target, &observation, &report, &inputs) {
                Ok(()) => panic!("noncanonical worktree evidence unexpectedly passed"),
                Err(error) => error,
            };
        assert!(error.contains("matching clean full-cycle report"));
        if let Err(error) = fs::remove_dir_all(&root) {
            panic!("cannot remove mutation fixture: {error}");
        }
    }

    #[test]
    fn spec_mutation_report_binds_registered_seeds_to_killed_inventory_results() {
        let (root, target, observation, inputs, report) =
            specification_preflight_fixture("registered-seeds");
        let mut omitted = report.clone();
        omitted["registered_seeds"] = serde_json::json!([]);
        let error = match validate_formal_mutation_report(
            &root,
            &target,
            &observation,
            &omitted,
            &inputs,
        ) {
            Ok(()) => panic!("omitted registered seed unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("registered seed evidence does not match its inventory"));

        for (label, invalid) in [
            {
                let mut value = report.clone();
                value["registered_seeds"][0]["negative_spec"] =
                    serde_json::json!("formal/apalache/_negative_tests/OtherBroken.tla");
                ("negative specification", value)
            },
            {
                let mut value = report.clone();
                value["registered_seeds"][0]["status"] = serde_json::json!("pending");
                ("status", value)
            },
        ] {
            let error = match validate_formal_mutation_report(
                &root,
                &target,
                &observation,
                &invalid,
                &inputs,
            ) {
                Ok(()) => panic!("invalid registered seed {label} unexpectedly passed"),
                Err(error) => error,
            };
            assert!(
                error.contains("registered seed"),
                "unexpected error: {error}"
            );
        }

        let mut survivor = report;
        survivor["mutants"][0]["verdict"] = serde_json::json!("survived");
        let error =
            match validate_formal_mutation_report(&root, &target, &observation, &survivor, &inputs)
            {
                Ok(()) => panic!("surviving registered seed unexpectedly passed"),
                Err(error) => error,
            };
        assert!(error.contains("registered seed fixture-seed was not killed"));
        if let Err(error) = fs::remove_dir_all(&root) {
            panic!("cannot remove mutation fixture: {error}");
        }
    }

    #[test]
    fn spec_mutation_report_binds_exact_registered_negative_preflight() {
        let (root, target, observation, inputs, report) =
            specification_preflight_fixture("registered-negative");
        for (label, invalid) in [
            {
                let mut value = report.clone();
                value["registered_negative"] = serde_json::json!([]);
                ("omitted", value)
            },
            {
                let mut value = report.clone();
                value["registered_negative"][0]["invariant"] = serde_json::json!("OtherInvariant");
                ("mismatched", value)
            },
            {
                let mut value = report.clone();
                value["registered_negative"][0]["log_sha256"] = serde_json::json!("A".repeat(64));
                ("hash", value)
            },
            {
                let mut value = report.clone();
                value["registered_negative"][0]["trace"] =
                    serde_json::json!(
                        "target/formal/../escaped/registered-negative/FixtureBroken/run/violation1.itf.json"
                    );
                ("trace", value)
            },
        ] {
            let error = match validate_formal_mutation_report(
                &root,
                &target,
                &observation,
                &invalid,
                &inputs,
            ) {
                Ok(()) => {
                    panic!("invalid registered negative evidence unexpectedly passed: {label}")
                }
                Err(error) => error,
            };
            assert!(
                error.contains("registered negative"),
                "unexpected {label} error: {error}"
            );
        }
        if let Err(error) = fs::remove_dir_all(&root) {
            panic!("cannot remove mutation fixture: {error}");
        }
    }

    #[test]
    fn spec_mutation_report_binds_exact_positive_baselines() {
        let (root, target, observation, inputs, report) =
            specification_preflight_fixture("positive-baselines");
        for (label, invalid) in [
            {
                let mut value = report.clone();
                let Some(object) = value.as_object_mut() else {
                    panic!("positive baseline report fixture is not an object");
                };
                object.remove("positive_baselines");
                ("missing", value)
            },
            {
                let mut value = report.clone();
                let mut extra = value["positive_baselines"][0].clone();
                extra["spec"] = serde_json::json!("Extra");
                let Some(baselines) = value["positive_baselines"].as_array_mut() else {
                    panic!("positive baseline fixture is not an array");
                };
                baselines.push(extra);
                ("extra", value)
            },
            {
                let mut value = report.clone();
                let duplicate = value["positive_baselines"][0].clone();
                let Some(baselines) = value["positive_baselines"].as_array_mut() else {
                    panic!("positive baseline fixture is not an array");
                };
                baselines.push(duplicate);
                ("duplicate", value)
            },
            {
                let mut value = report.clone();
                value["positive_baselines"][0]["invariant"] = serde_json::json!("OtherInvariant");
                ("metadata", value)
            },
            {
                let mut value = report.clone();
                value["positive_baselines"][0]["apalache_exit"] = serde_json::json!(12);
                ("nonzero exit", value)
            },
            {
                let mut value = report.clone();
                value["positive_baselines"][0]["verdict"] = serde_json::json!("killed");
                ("killed", value)
            },
            {
                let mut value = report.clone();
                value["positive_baselines"][0]["log_sha256"] = serde_json::json!("A".repeat(64));
                ("hash", value)
            },
            {
                let mut value = report.clone();
                value["positive_baselines"][0]["wall_secs"] = serde_json::json!(-0.1);
                ("wall time", value)
            },
        ] {
            let error = match validate_formal_mutation_report(
                &root,
                &target,
                &observation,
                &invalid,
                &inputs,
            ) {
                Ok(()) => panic!("invalid positive baseline unexpectedly passed: {label}"),
                Err(error) => error,
            };
            assert!(
                error.contains("positive baseline"),
                "unexpected {label} error: {error}"
            );
        }
        if let Err(error) = fs::remove_dir_all(&root) {
            panic!("cannot remove mutation fixture: {error}");
        }
    }

    #[test]
    fn formal_mutation_report_requires_the_exact_current_input_set() {
        let (root, target, observation, current_inputs, report) =
            single_input_fixture("exact-inputs");
        let mut missing = report.clone();
        missing["inputs"] = serde_json::json!([]);
        let error = match validate_formal_mutation_report(
            &root,
            &target,
            &observation,
            &missing,
            &current_inputs,
        ) {
            Ok(()) => panic!("report with a missing input unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("input set does not match the complete proof-mutants lane"));
        assert!(error.contains("formal_core.rs"));

        write_mutation_fixture(&root, "extra.txt", "extra\n");
        let (_, bytes) = match regular_mutation_input_bytes(&root, "extra.txt") {
            Ok(value) => value,
            Err(error) => panic!("cannot hash extra mutation input: {error}"),
        };
        let mut unexpected = report;
        let Some(inputs) = unexpected["inputs"].as_array_mut() else {
            panic!("fixture report inputs are not an array");
        };
        inputs.push(serde_json::json!({
            "path": "extra.txt",
            "sha256": sha256_hex(&bytes),
        }));
        let error = match validate_formal_mutation_report(
            &root,
            &target,
            &observation,
            &unexpected,
            &current_inputs,
        ) {
            Ok(()) => panic!("report with an unexpected input unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("unexpected=[\"extra.txt\"]"));
        if let Err(error) = fs::remove_dir_all(&root) {
            panic!("cannot remove mutation fixture: {error}");
        }
    }

    #[test]
    fn formal_mutation_report_binds_inputs_to_its_evidence_commit() {
        let (root, target, mut observation, current_inputs, mut report) =
            single_input_fixture("commit-inputs");
        let source = "crates/kernel/chio-kernel-core/src/formal_core.rs";
        write_mutation_fixture(&root, source, "pub fn model() -> bool { false }\n");
        let different_commit = commit_mutation_fixture(&root);
        write_mutation_fixture(&root, source, "pub fn model() -> bool { true }\n");
        observation.commit.clone_from(&different_commit);
        report["commit"] = serde_json::json!(different_commit);
        let error = match validate_formal_mutation_report(
            &root,
            &target,
            &observation,
            &report,
            &current_inputs,
        ) {
            Ok(()) => panic!("report bound to different committed inputs unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("does not match its evidence commit"));
        assert!(error.contains(source));
        if let Err(error) = fs::remove_dir_all(&root) {
            panic!("cannot remove mutation fixture: {error}");
        }
    }

    #[test]
    fn formal_mutation_report_requires_an_ancestor_commit_object() {
        let (root, target, observation, current_inputs, report) =
            single_input_fixture("commit-object");
        let tree = mutation_fixture_git(&root, &["rev-parse", "HEAD^{tree}"]);
        let unrelated = mutation_fixture_git(
            &root,
            &[
                "-c",
                "user.name=Chio Test",
                "-c",
                "user.email=chio-test@example.invalid",
                "commit-tree",
                &tree,
                "-m",
                "test: unrelated fixture",
            ],
        );
        for (object, expected) in [
            (tree, "evidence object is not a commit"),
            (unrelated, "evidence commit is not an ancestor of HEAD"),
        ] {
            let mut forged_observation = observation.clone();
            forged_observation.commit.clone_from(&object);
            let mut forged_report = report.clone();
            forged_report["commit"] = serde_json::json!(object);
            let error = match validate_formal_mutation_report(
                &root,
                &target,
                &forged_observation,
                &forged_report,
                &current_inputs,
            ) {
                Ok(()) => panic!("non-ancestor evidence object unexpectedly passed"),
                Err(error) => error,
            };
            assert!(error.contains(expected), "unexpected error: {error}");
        }
        if let Err(error) = fs::remove_dir_all(&root) {
            panic!("cannot remove mutation fixture: {error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn formal_mutation_report_rejects_symlink_inputs() {
        use std::os::unix::fs::symlink;

        let (root, target, observation, current_inputs, mut report) =
            single_input_fixture("symlink-input");
        write_mutation_fixture(&root, "real.txt", "bound\n");
        if let Err(error) = symlink("real.txt", root.join("linked.txt")) {
            panic!("cannot create mutation input symlink: {error}");
        }
        let Some(inputs) = report["inputs"].as_array_mut() else {
            panic!("fixture report inputs are not an array");
        };
        inputs.push(serde_json::json!({
            "path": "linked.txt",
            "sha256": sha256_hex(b"bound\n"),
        }));
        let error = match validate_formal_mutation_report(
            &root,
            &target,
            &observation,
            &report,
            &current_inputs,
        ) {
            Ok(()) => panic!("report with a symlink input unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("traverses a symlink"));
        assert!(error.contains("linked.txt"));
        if let Err(error) = fs::remove_dir_all(&root) {
            panic!("cannot remove mutation fixture: {error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn formal_mutation_observation_rejects_symlink_evidence() {
        use std::os::unix::fs::symlink;

        let (root, target, observation, current_inputs, report) =
            single_input_fixture("symlink-evidence");
        let encoded = match serde_json::to_vec(&report) {
            Ok(encoded) => encoded,
            Err(error) => panic!("cannot encode symlink evidence fixture: {error}"),
        };
        let retained = root.join("retained-report.json");
        if let Err(error) = fs::write(&retained, &encoded) {
            panic!("cannot write retained report fixture: {error}");
        }
        let evidence = root.join(&observation.evidence);
        if let Some(parent) = evidence.parent() {
            if let Err(error) = fs::create_dir_all(parent) {
                panic!("cannot create evidence directory: {error}");
            }
        }
        if let Err(error) = symlink(&retained, &evidence) {
            panic!("cannot create retained report symlink: {error}");
        }
        let bound = FormalMutationObservation {
            report_sha256: sha256_hex(&encoded),
            ..observation
        };
        let error = match validate_formal_mutation_observation(
            &root,
            &mut BTreeMap::new(),
            &target,
            &bound,
            &current_inputs,
        ) {
            Ok(()) => panic!("symlinked retained mutation evidence unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("traverses a symlink"));
        if let Err(error) = fs::remove_dir_all(&root) {
            panic!("cannot remove mutation fixture: {error}");
        }
    }

    #[test]
    fn formal_mutation_report_rejects_non_regular_inputs() {
        let (root, target, observation, current_inputs, mut report) =
            single_input_fixture("non-regular-input");
        if let Err(error) = fs::create_dir_all(root.join("input-directory")) {
            panic!("cannot create non-regular mutation input: {error}");
        }
        let Some(inputs) = report["inputs"].as_array_mut() else {
            panic!("fixture report inputs are not an array");
        };
        inputs.push(serde_json::json!({
            "path": "input-directory",
            "sha256": "a".repeat(64),
        }));
        let error = match validate_formal_mutation_report(
            &root,
            &target,
            &observation,
            &report,
            &current_inputs,
        ) {
            Ok(()) => panic!("report with a non-regular input unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("non-symlink regular repository file"));
        assert!(error.contains("input-directory"));
        if let Err(error) = fs::remove_dir_all(&root) {
            panic!("cannot remove mutation fixture: {error}");
        }
    }

    #[test]
    fn spec_mutation_report_rejects_stale_cfg_import_and_negative_registry() {
        let root = mutation_fixture_root("spec-dependencies");
        let fixtures = [
            (
                "formal/apalache/spec-mutants-allowlist.toml",
                "schema = \"chio.spec-mutants-allowlist.v1\"\nnegative_registry = \"formal/apalache/_negative_tests/REGISTRY.toml\"\n\n[[spec]]\nname = \"Fixture\"\npath = \"formal/apalache/Fixture.tla\"\ncfg = \"formal/apalache/MCFixture.cfg\"\ninvariant = \"SafetyInv\"\nlength = 4\n\n[[seed]]\nname = \"fixture-seed\"\nnegative_spec = \"formal/apalache/_negative_tests/FixtureBroken.tla\"\n",
            ),
            (
                "formal/apalache/_negative_tests/REGISTRY.toml",
                "schema = \"chio.apalache-negative.v1\"\n\n[[negative]]\nspec = \"formal/apalache/_negative_tests/FixtureBroken.tla\"\ncfg = \"formal/apalache/_negative_tests/MCFixtureBroken.cfg\"\nfalsifies = \"SafetyInv\"\nlength = 4\ntimeout_secs = 30\nruntime_test = \"crates/kernel/chio-kernel/src/tests.rs::fixture\"\n",
            ),
            ("formal/apalache/Fixture.tla", "---- MODULE Fixture ----\nEXTENDS Common\n====\n"),
            ("formal/apalache/Common.tla", "---- MODULE Common ----\n====\n"),
            ("formal/apalache/MCFixture.cfg", "INVARIANT SafetyInv\n"),
            (
                "formal/apalache/_negative_tests/FixtureBroken.tla",
                "---- MODULE FixtureBroken ----\nEXTENDS Common\n====\n",
            ),
            (
                "formal/apalache/_negative_tests/Common.tla",
                "---- MODULE Common ----\n====\n",
            ),
            (
                "formal/apalache/_negative_tests/MCFixtureBroken.cfg",
                "INVARIANT SafetyInv\n",
            ),
            ("crates/kernel/chio-kernel/src/tests.rs", "fn fixture() {}\n"),
            ("formal/MAPPING.md", "# Mapping\n"),
            ("scripts/check-apalache-negative.sh", "exit 0\n"),
            ("scripts/lib/apalache_evidence.py", "SCHEMA = 1\n"),
            ("scripts/spec-mutants.py", "SCHEMA = 1\n"),
            ("tools/install-apalache.sh", "exit 0\n"),
        ];
        for (path, contents) in fixtures {
            write_mutation_fixture(&root, path, contents);
        }
        let commit = commit_mutation_fixture(&root);
        let mut coverage_inputs = BTreeMap::new();
        let expected =
            match formal_mutation_expected_inputs(&root, "spec-mutants", &mut coverage_inputs) {
                Ok(expected) => expected,
                Err(error) => panic!("cannot build specification mutation inputs: {error}"),
            };
        for path in [
            "formal/apalache/MCFixture.cfg",
            "formal/apalache/Common.tla",
            "formal/apalache/_negative_tests/Common.tla",
            "formal/apalache/_negative_tests/REGISTRY.toml",
        ] {
            assert!(expected.contains_key(path), "missing expected input {path}");
        }
        let target = mutation_target("spec-mutants", "formal/apalache/Fixture.tla");
        let observation = mutation_observation(&commit);
        let report = mutation_report(&root, &target, &observation, &expected);
        if let Err(error) =
            validate_formal_mutation_report(&root, &target, &observation, &report, &expected)
        {
            panic!("valid specification mutation dependencies failed: {error}");
        }
        for (path, original) in [
            ("formal/apalache/MCFixture.cfg", "INVARIANT SafetyInv\n"),
            (
                "formal/apalache/Common.tla",
                "---- MODULE Common ----\n====\n",
            ),
            (
                "formal/apalache/_negative_tests/REGISTRY.toml",
                "schema = \"chio.apalache-negative.v1\"\n\n[[negative]]\nspec = \"formal/apalache/_negative_tests/FixtureBroken.tla\"\ncfg = \"formal/apalache/_negative_tests/MCFixtureBroken.cfg\"\nfalsifies = \"SafetyInv\"\nlength = 4\ntimeout_secs = 30\nruntime_test = \"crates/kernel/chio-kernel/src/tests.rs::fixture\"\n",
            ),
        ] {
            write_mutation_fixture(&root, path, "stale\n");
            let error = match validate_formal_mutation_report(
                &root,
                &target,
                &observation,
                &report,
                &expected,
            ) {
                Ok(()) => panic!("stale specification dependency unexpectedly passed: {path}"),
                Err(error) => error,
            };
            assert!(error.contains(path), "unexpected error: {error}");
            write_mutation_fixture(&root, path, original);
        }
        if let Err(error) = fs::remove_dir_all(&root) {
            panic!("cannot remove mutation fixture: {error}");
        }
    }

    #[test]
    fn spec_mutation_report_rejects_weak_source_despite_strong_global_activation() {
        let root = mutation_fixture_root("weak-spec-source");
        let fixtures = [
            (
                "formal/apalache/spec-mutants-allowlist.toml",
                "schema = \"chio.spec-mutants-allowlist.v1\"\nnegative_registry = \"formal/apalache/_negative_tests/REGISTRY.toml\"\n\n[[spec]]\nname = \"Strong\"\npath = \"formal/apalache/Strong.tla\"\ncfg = \"formal/apalache/MCStrong.cfg\"\ninvariant = \"SafetyInv\"\nlength = 4\n\n[[spec]]\nname = \"Weak\"\npath = \"formal/apalache/Weak.tla\"\ncfg = \"formal/apalache/MCWeak.cfg\"\ninvariant = \"SafetyInv\"\nlength = 4\n",
            ),
            (
                "formal/apalache/_negative_tests/REGISTRY.toml",
                "schema = \"chio.apalache-negative.v1\"\n\n[[negative]]\nspec = \"formal/apalache/_negative_tests/Broken.tla\"\ncfg = \"formal/apalache/_negative_tests/MCBroken.cfg\"\nfalsifies = \"SafetyInv\"\nlength = 4\ntimeout_secs = 30\nruntime_test = \"n/a (fixture)\"\n",
            ),
            ("formal/apalache/Strong.tla", "---- MODULE Strong ----\n====\n"),
            ("formal/apalache/Weak.tla", "---- MODULE Weak ----\n====\n"),
            ("formal/apalache/MCStrong.cfg", "INVARIANT SafetyInv\n"),
            ("formal/apalache/MCWeak.cfg", "INVARIANT SafetyInv\n"),
            (
                "formal/apalache/_negative_tests/Broken.tla",
                "---- MODULE Broken ----\n====\n",
            ),
            (
                "formal/apalache/_negative_tests/MCBroken.cfg",
                "INVARIANT SafetyInv\n",
            ),
            ("formal/MAPPING.md", "# Mapping\n"),
            ("scripts/check-apalache-negative.sh", "exit 0\n"),
            ("scripts/lib/apalache_evidence.py", "SCHEMA = 1\n"),
            ("scripts/spec-mutants.py", "SCHEMA = 1\n"),
            ("tools/install-apalache.sh", "exit 0\n"),
        ];
        for (path, contents) in fixtures {
            write_mutation_fixture(&root, path, contents);
        }
        let commit = commit_mutation_fixture(&root);
        let mut coverage_inputs = BTreeMap::new();
        let inputs =
            match formal_mutation_expected_inputs(&root, "spec-mutants", &mut coverage_inputs) {
                Ok(inputs) => inputs,
                Err(error) => panic!("cannot build weak-source mutation inputs: {error}"),
            };
        let strong_counts = MutationVerdictCounts {
            killed: 18,
            ..MutationVerdictCounts::default()
        };
        let weak_counts = MutationVerdictCounts {
            killed: 1,
            survived: 1,
            ..MutationVerdictCounts::default()
        };
        let global_counts = MutationVerdictCounts {
            killed: 19,
            survived: 1,
            ..MutationVerdictCounts::default()
        };
        let mut target = mutation_target("spec-mutants", "formal/apalache/Weak.tla");
        let observation = FormalMutationObservation {
            enumerated: 2,
            killed: 1,
            survived: 1,
            timeout: 0,
            activation_ratio_percent: 50.0,
            ..mutation_observation(&commit)
        };
        let mut mutants = Vec::new();
        for (source, path, counts) in [
            ("Strong", "formal/apalache/Strong.tla", strong_counts),
            ("Weak", "formal/apalache/Weak.tla", weak_counts),
        ] {
            let verdicts = [("killed", counts.killed), ("survived", counts.survived)]
                .into_iter()
                .flat_map(|(verdict, count)| std::iter::repeat_n(verdict, count));
            for verdict in verdicts {
                mutants.push(serde_json::json!({
                    "id": format!("{:020x}", mutants.len() + 1),
                    "spec": source,
                    "path": path,
                    "verdict": verdict,
                }));
            }
        }
        let inventory = mutants
            .iter()
            .cloned()
            .map(|mut mutant| {
                let Some(object) = mutant.as_object_mut() else {
                    panic!("weak-source inventory fixture is not an object");
                };
                object.remove("verdict");
                mutant
            })
            .collect::<Vec<_>>();
        let inventory_bytes = match serde_json::to_vec(&inventory) {
            Ok(value) => value,
            Err(error) => panic!("cannot encode weak-source inventory: {error}"),
        };
        target.inventory_sha256 = sha256_hex(&inventory_bytes);
        let strong_score = spec_score_fixture(strong_counts, target.activation_target_percent);
        let weak_score = spec_score_fixture(weak_counts, target.activation_target_percent);
        let mut global_score = spec_score_fixture(global_counts, target.activation_target_percent);
        assert_eq!(
            global_score["activation_ratio_percent"],
            serde_json::json!(95.0)
        );
        global_score["global_activation_met"] = serde_json::json!(true);
        global_score["source_activation_met"] = serde_json::json!(false);
        global_score["activation_met"] = serde_json::json!(false);
        let report = serde_json::json!({
            "schema": "chio.spec-mutants-report.v1",
            "commit": observation.commit,
            "measured_at": observation.measured_at,
            "full_cycle": true,
            "worktree": {"clean": true},
            "enumerated": mutants.len(),
            "inventory": inventory,
            "inventory_sha256": target.inventory_sha256.clone(),
            "tools": {"apalache": "0.50.1"},
            "inputs": inputs.iter().map(|(path, sha256)| {
                serde_json::json!({"path": path, "sha256": sha256})
            }).collect::<Vec<_>>(),
            "mutants": mutants,
            "registered_seeds": [],
            "registered_negative": registered_negative_fixture(&root),
            "positive_baselines": positive_baselines_fixture(&root),
            "source_aggregates": {
                "Strong": strong_score,
                "Weak": weak_score,
            },
            "aggregate": global_score,
        });
        let error =
            match validate_formal_mutation_report(&root, &target, &observation, &report, &inputs) {
                Ok(()) => panic!("globally strong report with a weak source unexpectedly passed"),
                Err(error) => error,
            };
        assert!(
            error.contains("does not meet every source activation target"),
            "unexpected error: {error}"
        );

        let mut passing_report = report;
        let Some(mutants) = passing_report["mutants"].as_array_mut() else {
            panic!("weak-source fixture mutants are not an array");
        };
        let Some(weak_survivor) = mutants.iter_mut().find(|mutant| {
            mutant.get("spec").and_then(serde_json::Value::as_str) == Some("Weak")
                && mutant.get("verdict").and_then(serde_json::Value::as_str) == Some("survived")
        }) else {
            panic!("weak-source fixture has no survivor");
        };
        weak_survivor["verdict"] = serde_json::json!("killed");
        let passing_weak_counts = MutationVerdictCounts {
            killed: 2,
            ..MutationVerdictCounts::default()
        };
        let passing_global_counts = MutationVerdictCounts {
            killed: 20,
            ..MutationVerdictCounts::default()
        };
        passing_report["source_aggregates"]["Weak"] =
            spec_score_fixture(passing_weak_counts, target.activation_target_percent);
        passing_report["aggregate"] =
            spec_score_fixture(passing_global_counts, target.activation_target_percent);
        passing_report["aggregate"]["global_activation_met"] = serde_json::json!(true);
        passing_report["aggregate"]["source_activation_met"] = serde_json::json!(true);
        let source_observation = FormalMutationObservation {
            enumerated: 2,
            killed: 2,
            survived: 0,
            timeout: 0,
            activation_ratio_percent: 100.0,
            ..observation.clone()
        };
        if let Err(error) = validate_formal_mutation_report(
            &root,
            &target,
            &source_observation,
            &passing_report,
            &inputs,
        ) {
            panic!("source-scoped specification observation failed: {error}");
        }
        let global_observation = FormalMutationObservation {
            enumerated: 20,
            killed: 20,
            survived: 0,
            timeout: 0,
            activation_ratio_percent: 100.0,
            ..observation
        };
        let error = match validate_formal_mutation_report(
            &root,
            &target,
            &global_observation,
            &passing_report,
            &inputs,
        ) {
            Ok(()) => panic!("global counts unexpectedly passed as a source observation"),
            Err(error) => error,
        };
        assert!(
            error.contains("observation does not match its source aggregate"),
            "unexpected error: {error}"
        );
        if let Err(error) = fs::remove_dir_all(&root) {
            panic!("cannot remove mutation fixture: {error}");
        }
    }

    #[test]
    fn proof_mutation_report_rejects_stale_compiled_dependencies() {
        let root = mutation_fixture_root("proof-dependencies");
        let fixtures = [
            ("Cargo.toml", "[workspace]\nresolver = \"2\"\n"),
            ("Cargo.lock", "version = 4\n"),
            (".cargo/config.toml", "[alias]\nxtask = \"run\"\n"),
            (
                "crates/kernel/chio-kernel-core/Cargo.toml",
                "[package]\nname = \"chio-kernel-core\"\n",
            ),
            (
                "crates/core/chio-core-types/Cargo.toml",
                "[package]\nname = \"chio-core-types\"\n",
            ),
            ("rust-toolchain.toml", "[toolchain]\nchannel = \"1.88\"\n"),
            (
                "formal/rust-verification/formal-mutants.toml",
                "test_tool = \"cargo\"\n",
            ),
            ("scripts/proof-mutants.py", "SCHEMA = 1\n"),
            ("scripts/proof-mutants.sh", "exit 0\n"),
            ("scripts/kani-mutant-killer.sh", "exit 0\n"),
            ("scripts/check-kani-core.sh", "exit 0\n"),
            (
                "crates/kernel/chio-kernel-core/src/lib.rs",
                "mod oracle;\nmod formal_core;\nmod formal_aeneas;\n",
            ),
            (
                "crates/kernel/chio-kernel-core/src/oracle.rs",
                "pub fn oracle() -> bool { true }\n",
            ),
            (
                "crates/kernel/chio-kernel-core/src/formal_core.rs",
                "pub fn model() -> bool { true }\n",
            ),
            (
                "crates/kernel/chio-kernel-core/src/formal_aeneas.rs",
                "pub fn model() -> bool { true }\n",
            ),
            ("crates/core/chio-core-types/src/lib.rs", "mod imported;\n"),
            (
                "crates/core/chio-core-types/src/imported.rs",
                "pub const BOUND: bool = true;\n",
            ),
        ];
        for (path, contents) in fixtures {
            write_mutation_fixture(&root, path, contents);
        }
        let commit = commit_mutation_fixture(&root);
        let mut coverage_inputs = BTreeMap::new();
        let expected =
            match formal_mutation_expected_inputs(&root, "proof-mutants", &mut coverage_inputs) {
                Ok(expected) => expected,
                Err(error) => panic!("cannot build proof mutation inputs: {error}"),
            };
        for path in [
            "Cargo.toml",
            "Cargo.lock",
            ".cargo/config.toml",
            "crates/kernel/chio-kernel-core/Cargo.toml",
            "crates/core/chio-core-types/Cargo.toml",
            "scripts/proof-mutants.sh",
            "crates/kernel/chio-kernel-core/src/oracle.rs",
            "crates/core/chio-core-types/src/imported.rs",
        ] {
            assert!(expected.contains_key(path), "missing expected input {path}");
        }
        let target = mutation_target(
            "proof-mutants",
            "crates/kernel/chio-kernel-core/src/formal_core.rs",
        );
        let observation = mutation_observation(&commit);
        let report = mutation_report(&root, &target, &observation, &expected);
        if let Err(error) =
            validate_formal_mutation_report(&root, &target, &observation, &report, &expected)
        {
            panic!("valid proof mutation dependencies failed: {error}");
        }
        for (path, original) in [
            (
                "crates/kernel/chio-kernel-core/src/oracle.rs",
                "pub fn oracle() -> bool { true }\n",
            ),
            (
                "crates/core/chio-core-types/src/imported.rs",
                "pub const BOUND: bool = true;\n",
            ),
            ("scripts/proof-mutants.sh", "exit 0\n"),
            ("Cargo.lock", "version = 4\n"),
            (".cargo/config.toml", "[alias]\nxtask = \"run\"\n"),
        ] {
            write_mutation_fixture(&root, path, "stale\n");
            let error = match validate_formal_mutation_report(
                &root,
                &target,
                &observation,
                &report,
                &expected,
            ) {
                Ok(()) => panic!("stale proof dependency unexpectedly passed: {path}"),
                Err(error) => error,
            };
            assert!(error.contains(path), "unexpected error: {error}");
            write_mutation_fixture(&root, path, original);
        }
        if let Err(error) = fs::remove_dir_all(&root) {
            panic!("cannot remove mutation fixture: {error}");
        }
    }

    #[test]
    fn formal_mutation_report_preserves_per_target_source_attribution() {
        let root = mutation_fixture_root("source-attribution");
        let first = "crates/kernel/chio-kernel-core/src/formal_core.rs";
        let second = "crates/kernel/chio-kernel-core/src/formal_aeneas.rs";
        write_mutation_fixture(&root, first, "pub fn first() {}\n");
        write_mutation_fixture(&root, second, "pub fn second() {}\n");
        let commit = commit_mutation_fixture(&root);
        let mut inputs = BTreeMap::new();
        for source in [first, second] {
            let (_, bytes) = match regular_mutation_input_bytes(&root, source) {
                Ok(value) => value,
                Err(error) => panic!("cannot hash source fixture: {error}"),
            };
            inputs.insert(source.to_string(), sha256_hex(&bytes));
        }
        let first_target = mutation_target("proof-mutants", first);
        let mut second_target = mutation_target("proof-mutants", second);
        second_target
            .inventory_sha256
            .clone_from(&first_target.inventory_sha256);
        let observation = mutation_observation(&commit);
        let mut report = mutation_report(&root, &first_target, &observation, &inputs);
        if let Err(error) =
            validate_formal_mutation_report(&root, &first_target, &observation, &report, &inputs)
        {
            panic!("first target attribution failed: {error}");
        }
        report["source_aggregates"][first]["activation_met"] = serde_json::json!(false);
        let error = match validate_formal_mutation_report(
            &root,
            &first_target,
            &observation,
            &report,
            &inputs,
        ) {
            Ok(()) => panic!("contradictory proof source activation unexpectedly passed"),
            Err(error) => error,
        };
        assert!(
            error.contains("proof source aggregate has an inconsistent activation result"),
            "unexpected error: {error}"
        );
        report["source_aggregates"][first]["activation_met"] = serde_json::json!(true);
        let error = match validate_formal_mutation_report(
            &root,
            &second_target,
            &observation,
            &report,
            &inputs,
        ) {
            Ok(()) => panic!("report lacking the second target source unexpectedly passed"),
            Err(error) => error,
        };
        assert!(
            error.contains("inventory does not cover its source"),
            "unexpected error: {error}"
        );
        if let Err(error) = fs::remove_dir_all(&root) {
            panic!("cannot remove mutation fixture: {error}");
        }
    }

    #[test]
    fn aeneas_production_targets_require_generated_equivalence() {
        assert_eq!(
            expected_refinement_schema("aeneas", "production", "formal/aeneas/production.toml"),
            Ok("chio.aeneas-production.v1")
        );

        let fixture = r#"
[[targets]]
name = "decision_core"
status = "generated_equivalence"
functions = ["nonce_admits"]
equivalence_theorems = ["nonce_admits|Chio.Proofs.generated_nonce_admits_eq_mirror"]

[[targets]]
name = "reservation_ledger"
status = "generated_equivalence"
functions = ["ledger_is_terminal", "ledger_apply"]
equivalence_theorems = [
  "ledger_is_terminal|Chio.Proofs.generated_ledger_is_terminal_eq_model",
  "ledger_apply|Chio.Proofs.generated_ledger_apply_eq_model",
]
"#;
        let value = match parse_toml("fixture", fixture) {
            Ok(value) => value,
            Err(error) => panic!("Aeneas production fixture parse failed: {error}"),
        };
        assert_eq!(
            aeneas_extracted_symbols(&value, "formal/aeneas/production.toml"),
            Ok(vec![
                "nonce_admits".to_string(),
                "ledger_is_terminal".to_string(),
                "ledger_apply".to_string(),
            ])
        );

        let downgraded = fixture.replacen(
            "status = \"generated_equivalence\"",
            "status = \"extraction_only\"",
            1,
        );
        let value = match parse_toml("fixture", &downgraded) {
            Ok(value) => value,
            Err(error) => panic!("downgraded Aeneas fixture parse failed: {error}"),
        };
        let error = match aeneas_extracted_symbols(&value, "formal/aeneas/production.toml") {
            Ok(_) => panic!("downgraded Aeneas target unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("not equivalence-checked"));

        let missing_theorem = fixture.replacen(
            "ledger_apply|Chio.Proofs.generated_ledger_apply_eq_model",
            "unregistered_function|Chio.Proofs.generated_ledger_apply_eq_model",
            1,
        );
        let value = match parse_toml("fixture", &missing_theorem) {
            Ok(value) => value,
            Err(error) => panic!("mismatched Aeneas fixture parse failed: {error}"),
        };
        let error = match aeneas_extracted_symbols(&value, "formal/aeneas/production.toml") {
            Ok(_) => panic!("mismatched Aeneas theorem inventory unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("theorem inventory mismatch"));
    }

    #[test]
    fn aeneas_production_symbols_are_attributed_to_their_sources() {
        let fixture = r#"
[[sources]]
id = "economy"
path = "crates/economy/chio-credit/src/formal_economy.rs"

[[sources]]
id = "kernel"
path = "crates/kernel/chio-kernel-core/src/formal_aeneas.rs"

[[targets]]
name = "kernel_core"
source = "kernel"
status = "generated_equivalence"
functions = ["nonce_admits"]
equivalence_theorems = ["nonce_admits|Chio.Proofs.generated_nonce_admits_eq_mirror"]

[[targets]]
name = "economy_conversion"
source = "economy"
status = "generated_equivalence"
functions = ["convert_ceil_scalar", "convert_floor_scalar"]
equivalence_theorems = [
  "convert_ceil_scalar|Chio.Proofs.generated_convert_ceil_scalar_eq_model",
  "convert_floor_scalar|Chio.Proofs.generated_convert_floor_scalar_eq_model",
]
"#;
        let value = match parse_toml("fixture", fixture) {
            Ok(value) => value,
            Err(error) => panic!("Aeneas source fixture parse failed: {error}"),
        };
        assert_eq!(
            aeneas_extracted_symbols_by_source(&value, "formal/aeneas/production.toml"),
            Ok(vec![
                (
                    "crates/economy/chio-credit/src/formal_economy.rs".to_string(),
                    vec![
                        "convert_ceil_scalar".to_string(),
                        "convert_floor_scalar".to_string(),
                    ],
                ),
                (
                    "crates/kernel/chio-kernel-core/src/formal_aeneas.rs".to_string(),
                    vec!["nonce_admits".to_string()],
                ),
            ])
        );

        let unknown_source = fixture.replacen("source = \"economy\"", "source = \"missing\"", 1);
        let value = match parse_toml("fixture", &unknown_source) {
            Ok(value) => value,
            Err(error) => panic!("unknown-source fixture parse failed: {error}"),
        };
        let error =
            match aeneas_extracted_symbols_by_source(&value, "formal/aeneas/production.toml") {
                Ok(_) => panic!("unknown Aeneas source unexpectedly passed"),
                Err(error) => error,
            };
        assert!(error.contains("unknown source"));
    }
}
