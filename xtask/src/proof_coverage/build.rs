use super::*;

pub(super) fn build_coverage(root: &Path) -> Result<CoverageBuild, String> {
    let mut input_hashes = BTreeMap::new();
    let workspace = workspace_catalog(root)?;
    input_hashes.insert(
        "cargo-metadata://workspace-packages".to_string(),
        workspace.projection_sha256.clone(),
    );
    for path in GENERATOR_SOURCE_PATHS {
        let _generator = read_input(root, path, &mut input_hashes)?;
    }

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
