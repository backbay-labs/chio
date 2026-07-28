use super::*;

pub(super) fn add_inventory_artifacts(
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

pub(super) fn add_diff_artifacts(
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
pub(super) fn add_optional_concurrency_artifacts(
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

pub(super) fn validate_loom_harness(
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

pub(super) fn collect_rust_tests(items: &[syn::Item], prefix: &str, tests: &mut BTreeSet<String>) {
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

pub(super) fn lane_postures(raw: &str) -> Result<BTreeMap<String, String>, String> {
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

pub(super) fn validate_primary_attribution(
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

pub(super) fn validate_mutant_classification(
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

pub(super) fn require_single_artifact(
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
