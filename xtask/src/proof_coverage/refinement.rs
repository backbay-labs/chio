use super::*;

pub(super) fn add_kani_artifacts(
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

pub(super) fn infer_harness_surface(
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
pub(super) fn add_refinement_artifacts(
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

pub(super) fn aeneas_extracted_symbols(
    value: &TomlValue,
    path: &str,
) -> Result<Vec<String>, String> {
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

pub(super) fn aeneas_extracted_symbols_by_source(
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

pub(super) fn contract_twin_review_links(
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

pub(super) fn is_rust_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

pub(super) fn expected_refinement_schema(
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

pub(super) fn validate_legacy_kani_alias(
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

pub(super) fn toml_string_array(value: &TomlValue, key: &str) -> Result<Vec<String>, String> {
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

pub(super) fn required_toml_string_array(
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

pub(super) fn add_fuzz_artifacts(
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

pub(super) fn validate_fuzz_owner_keys(
    fuzz_map: &FuzzMap,
    owners: &FuzzOwners,
) -> Result<(), String> {
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

pub(super) fn files_in_dir(
    root: &Path,
    directory: &str,
    extension: &str,
) -> Result<Vec<String>, String> {
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
