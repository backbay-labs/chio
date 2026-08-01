use super::*;

pub(super) fn parse_toml<T>(path: &str, raw: &str) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    toml::from_str(raw).map_err(|error| format!("cannot parse {path}: {error}"))
}

pub(super) fn read_input(
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

pub(super) fn normalized_repo_path(path: &str) -> Result<String, String> {
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

pub(super) fn workspace_catalog(root: &Path) -> Result<WorkspaceCatalog, String> {
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

pub(super) fn property_ids(manifest: &ProofManifest) -> Result<BTreeSet<String>, String> {
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

pub(super) fn mirror_review_links(entries: &[MirrorEntry]) -> Result<Vec<ReviewLink>, String> {
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

pub(super) fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn validate_theorem_properties(
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

pub(super) fn assumption_summaries(
    registry: &AssumptionRegistry,
) -> Result<Vec<AssumptionSummary>, String> {
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

pub(super) fn encoded_ids(
    rows: &[String],
    fields: usize,
    label: &str,
) -> Result<BTreeSet<String>, String> {
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

pub(super) fn reject_duplicate_harnesses(harnesses: &[KaniHarness]) -> Result<(), String> {
    let mut ids = BTreeSet::new();
    for harness in harnesses {
        let id = format!("{}/{}", harness.crate_name, harness.harness);
        if !ids.insert(id.clone()) {
            return Err(format!("duplicate Kani harness: {id}"));
        }
    }
    Ok(())
}

pub(super) fn crate_surface(crate_name: &str) -> String {
    format!("{crate_name}::*")
}

pub(super) fn ensure_row(rows: &mut BTreeMap<String, CoverageRow>, surface: &str) {
    rows.entry(surface.to_string())
        .or_insert_with(|| CoverageRow {
            surface: surface.to_string(),
            lanes: BTreeMap::new(),
        });
}

pub(super) fn add_artifact(
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
pub(super) fn add_or_unattribute(
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

pub(super) fn surface_packages(surfaces: &[String]) -> BTreeSet<String> {
    surfaces
        .iter()
        .filter_map(|surface| {
            surface
                .split_once("::")
                .map(|(package, _)| package.to_string())
        })
        .collect()
}

pub(super) fn conservative_primary_candidates(surfaces: &[String]) -> Vec<String> {
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

pub(super) fn conservative_harness_attribution(
    mut surfaces: Vec<String>,
    fallback: String,
) -> (String, Vec<String>) {
    surfaces.sort();
    surfaces.dedup();
    let candidates = conservative_primary_candidates(&surfaces);
    let primary = candidates.into_iter().next().unwrap_or(fallback);
    (primary, surfaces)
}

pub(super) fn surface_from_repo_path(
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

pub(super) fn surface_from_symbol(
    symbol: &str,
    root: &Path,
    workspace: &WorkspaceCatalog,
) -> Option<String> {
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

pub(super) fn validate_mapping_source(
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

pub(super) fn source_defines_property(path: &str, raw: &str, property: &str) -> bool {
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

pub(super) fn surfaces_from_mapping(
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

pub(super) fn code_spans(value: &str) -> Vec<String> {
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

pub(super) fn workspace_rust_files(root: &Path) -> Result<Vec<String>, String> {
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

pub(super) fn glob_segment_matches(pattern: &str, name: &str) -> bool {
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

pub(super) fn path_glob_matches(pattern: &str, path: &str) -> bool {
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

pub(super) fn expand_mutation_globs(
    globs: &[String],
    tracked_files: &[String],
) -> Result<BTreeSet<String>, String> {
    expand_globs(globs, tracked_files, true)
}

pub(super) fn expand_globs(
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

pub(super) fn effective_mutation_files(
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

pub(super) fn package_for_path<'a>(
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

pub(super) fn package_for_globs(
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
