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
    let parsed = parse_mapping(include_str!("../../../../formal/MAPPING.md"));

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
    let error = match mutation_evidence_is_complete(&incomplete, "chio-weights", config, "fixture")
    {
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
        include_str!("../../../../.kani/harnesses.toml"),
    ) {
        Ok(kani) => kani,
        Err(error) => panic!("Kani registry parse failed: {error}"),
    };
    let fuzz_map: FuzzMap = match parse_toml(
        "fuzz/target-map.toml",
        include_str!("../../../../fuzz/target-map.toml"),
    ) {
        Ok(fuzz_map) => fuzz_map,
        Err(error) => panic!("fuzz registry parse failed: {error}"),
    };
    let inventory: TheoremInventory =
        match serde_json::from_str(include_str!("../../../../formal/theorem-inventory.json")) {
            Ok(inventory) => inventory,
            Err(error) => panic!("theorem inventory parse failed: {error}"),
        };
    let mutant_configs = match files_in_dir(&root, "audits/mutation/per-crate-configs", "toml") {
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
        include_str!("../../../../formal/proof-manifest.toml"),
    ) {
        Ok(manifest) => manifest,
        Err(error) => panic!("proof manifest parse failed: {error}"),
    };
    let creusot: TomlValue = match parse_toml(
        "formal/rust-verification/creusot-contracts.toml",
        include_str!("../../../../formal/rust-verification/creusot-contracts.toml"),
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

mod aeneas;
mod mutation;
