use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use toml::Value as TomlValue;

use crate::{workspace_root, XtaskError};

const COVERAGE_SCHEMA: &str = "chio.proof-coverage.v1";
const GENERATOR_VERSION: u32 = 2;
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
            conservative_primary_candidates(&resolution.surfaces)
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
        *surfaces = conservative_primary_candidates(surfaces);
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
            ("lean", "transliteration") | ("tla", "abstraction_anchor")
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
        let (primary, related) = conservative_harness_attribution(surfaces, fallback);
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
            let extracted = required_toml_string_array(&value, "extracted_symbols", &path)?;
            let source = value.get("source").and_then(TomlValue::as_str);
            let source = source.ok_or_else(|| format!("Aeneas manifest has no source: {path}"))?;
            let normalized = normalized_repo_path(source)?;
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
        } else {
            return Err(format!("unsupported refinement lane in {path}: {lane}"));
        }
    }
    Ok(())
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
            add_artifact(
                rows,
                artifacts,
                format!("{dst_path}::{id}"),
                "dst",
                crate_surface(&harness.crate_name),
                Vec::new(),
            )?;
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
    let components = harness.test.split("::").collect::<Vec<_>>();
    if components.len() < 2 || components.iter().any(|component| component.is_empty()) {
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
    let test_name = components[1..].join("::");
    if !tests.contains(&test_name) {
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
    fn current_mapping_parses_without_warnings() {
        let parsed = parse_mapping(include_str!("../../formal/MAPPING.md"));

        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        assert_eq!(parsed.rows.len(), 39);
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
        };
        let receipt = KaniHarness {
            crate_name: "chio-kernel-core".to_string(),
            harness: "public_sign_receipt_refuses_content_hash_mismatch".to_string(),
            lane: "pr".to_string(),
            notes: String::new(),
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
            "schema = \"chio.loom.v1\"\n\n[[harness]]\ncrate = \"chio-kernel\"\ntest = \"loom_concurrency::drop_race\"\nmax_preemptions = 3\nlane = \"nightly\"\nnotes = \"drop race model\"\n",
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
        let package = match workspace.packages.get("chio-kernel") {
            Some(package) => package,
            None => panic!("loom fixture package is missing"),
        };
        let missing_test = LoomHarness {
            crate_name: "chio-kernel".to_string(),
            test: "loom_concurrency::missing_test".to_string(),
            max_preemptions: 3,
            lane: "nightly".to_string(),
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
        let missing_field = "schema = \"chio.loom.v1\"\n\n[[harness]]\ncrate = \"chio-kernel\"\ntest = \"loom_concurrency::drop_race\"\nlane = \"nightly\"\nnotes = \"drop race\"\n";
        let error = match parse_toml::<LoomManifest>("fixture", missing_field) {
            Ok(_) => panic!("loom harness without max_preemptions unexpectedly passed"),
            Err(error) => error,
        };
        assert!(error.contains("max_preemptions"));

        let unknown_field = "schema = \"chio.loom.v1\"\n\n[[harness]]\ncrate = \"chio-kernel\"\ntest = \"loom_concurrency::drop_race\"\nmax_preemptions = 3\nlane = \"nightly\"\nnotes = \"drop race\"\nfuture = true\n";
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
}
