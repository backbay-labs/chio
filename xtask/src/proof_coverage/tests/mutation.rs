use super::*;

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
    let inputs = match formal_mutation_expected_inputs(&root, "spec-mutants", &mut coverage_inputs)
    {
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
    let (root, target, observation, inputs, mut report) = single_input_fixture("worktree-evidence");
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
    let error =
        match validate_formal_mutation_report(&root, &target, &observation, &omitted, &inputs) {
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
        match validate_formal_mutation_report(&root, &target, &observation, &survivor, &inputs) {
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
    let (root, target, observation, current_inputs, report) = single_input_fixture("exact-inputs");
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
    let (root, target, observation, current_inputs, report) = single_input_fixture("commit-object");
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
    let inputs = match formal_mutation_expected_inputs(&root, "spec-mutants", &mut coverage_inputs)
    {
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
        let error =
            match validate_formal_mutation_report(&root, &target, &observation, &report, &expected)
            {
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
    let error =
        match validate_formal_mutation_report(&root, &first_target, &observation, &report, &inputs)
        {
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
