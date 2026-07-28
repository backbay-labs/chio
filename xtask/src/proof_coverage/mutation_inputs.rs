use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn add_mutant_artifacts(
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

pub(super) fn mutation_evidence_references_config(
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

pub(super) fn regular_mutation_input_bytes(
    root: &Path,
    relative: &str,
) -> Result<(String, Vec<u8>), String> {
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

pub(super) fn regular_mutation_input_text(
    root: &Path,
    relative: &str,
) -> Result<(String, String), String> {
    let (path, bytes) = regular_mutation_input_bytes(root, relative)?;
    let raw = String::from_utf8(bytes)
        .map_err(|error| format!("formal mutation input is not UTF-8 ({path}): {error}"))?;
    Ok((path, raw))
}

pub(super) fn mutation_input_at_commit(
    root: &Path,
    commit: &str,
    relative: &str,
) -> Result<Vec<u8>, String> {
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

pub(super) fn validate_mutation_evidence_commit(root: &Path, commit: &str) -> Result<(), String> {
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

pub(super) fn insert_formal_mutation_input(
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

pub(super) fn regular_files_in_directory(
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

pub(super) fn spec_mutation_input_registry(
    root: &Path,
) -> Result<SpecMutationInputRegistry, String> {
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

pub(super) fn spec_mutation_allowlist_specs(
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

pub(super) fn spec_mutation_source_map(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let specs = spec_mutation_allowlist_specs(root)?;
    let sources = specs
        .into_iter()
        .map(|(name, spec)| (spec.path, name))
        .collect();
    Ok(sources)
}

pub(super) fn spec_mutation_negative_registry(
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

pub(super) fn spec_mutation_seed_registry(root: &Path) -> Result<BTreeMap<String, String>, String> {
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

pub(super) fn spec_mutation_expected_input_paths(root: &Path) -> Result<BTreeSet<String>, String> {
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

pub(super) fn proof_mutation_expected_input_paths(root: &Path) -> Result<BTreeSet<String>, String> {
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

pub(super) fn formal_mutation_expected_inputs(
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
pub(super) fn add_formal_mutation_artifacts(
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

pub(super) fn format_percent(value: f64) -> String {
    let rendered = format!("{value:.3}");
    rendered
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

pub(super) fn valid_utc_timestamp(value: &str) -> bool {
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

pub(super) fn validate_formal_mutation_observation(
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

pub(super) fn validate_mutation_score(
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
