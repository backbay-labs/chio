use super::*;

pub(super) fn is_lowercase_sha256(value: Option<&str>) -> bool {
    value.is_some_and(|hash| {
        hash.len() == 64
            && hash
                .chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    })
}

pub(super) fn is_registered_negative_trace_path(path: &str, spec: &str) -> bool {
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

pub(super) fn validate_spec_mutation_positive_baselines(
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

pub(super) fn validate_spec_mutation_preflight(
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

pub(super) fn validate_formal_mutation_report(
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

pub(super) fn mutation_evidence_is_complete(
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

pub(super) fn validate_mutation_baseline(raw: &str) -> Result<(), String> {
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
