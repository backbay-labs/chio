// Typed handlers for chio-runtime facets, mirroring runtime gate scripts and
// launch assurance requirements. Included into `fixtures.rs` via `include!`
// so the handlers share that module's private helpers (ScratchDir, require_cli,
// run_cargo_test, validate_document, the JSON mutators, canonical_sha256) while
// keeping runtime handlers focused.
//
// The runtime scripts are far more imperative than the pheromone gates: each
// drives a multi-step `chio runtime ...` CLI pipeline, materializes derived
// fixtures, and asserts on report contents. Those steps live here as typed
// Rust; the manifest carries only the static validate pairs and cargo-test
// tails.

// -- Runtime CLI / fs helpers ----------------------------------------------

/// The CHIO_RUNTIME schema directory the scripts referenced as
/// `spec/schemas/chio-runtime/v1`.
fn runtime_schema_dir(root: &Path) -> PathBuf {
    root.join("spec/schemas/chio-runtime/v1")
}

/// Validate a document against a chio-runtime schema named by bare filename.
fn validate_runtime(root: &Path, schema_file: &str, doc: &Path) -> Result<(), XtaskError> {
    validate_document(&runtime_schema_dir(root).join(schema_file), doc)
}

/// SHA-256 of a file's raw bytes, lowercase hex (matches `shasum -a 256`).
fn file_sha256(path: &Path) -> Result<String, XtaskError> {
    use sha2::{Digest, Sha256};
    let bytes = fs::read(path).map_err(|err| XtaskError::Io(display(path), err))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let mut hex = String::with_capacity(64);
    for byte in hasher.finalize() {
        hex.push_str(&format!("{byte:02x}"));
    }
    Ok(hex)
}

/// Run a `chio` CLI invocation through `cargo run -p chio-cli --bin chio --`,
/// returning whether it succeeded. The runtime scripts call the `chio` binary
/// either with or without the explicit `--bin chio`; the binary is unambiguous,
/// so this always pins it.
fn run_chio(root: &Path, chio_args: &[&str]) -> Result<bool, XtaskError> {
    let mut args = vec!["-p", "chio-cli", "--bin", "chio", "--"];
    args.extend_from_slice(chio_args);
    run_cli(root, &args)
}

fn require_chio(root: &Path, chio_args: &[&str]) -> Result<(), XtaskError> {
    if run_chio(root, chio_args)? {
        Ok(())
    } else {
        Err(XtaskError::Process(format!(
            "expected chio {chio_args:?} to succeed"
        )))
    }
}

fn reject_chio(root: &Path, chio_args: &[&str], detail: &str) -> Result<(), XtaskError> {
    if run_chio(root, chio_args)? {
        Err(XtaskError::Process(format!(
            "negative assertion failed: {detail}"
        )))
    } else {
        Ok(())
    }
}

/// Run a `chio` CLI invocation expected to fail, then confirm its combined
/// stdout/stderr carries an expected marker. Reproduces the runtime scripts'
/// `! cargo run ... 2>err; grep -q "<marker>" err` negatives, which both require
/// the non-zero exit AND pin the specific failure message (so a different,
/// unrelated failure cannot masquerade as the expected one).
fn reject_chio_with_marker(
    root: &Path,
    chio_args: &[&str],
    marker: &str,
    detail: &str,
) -> Result<(), XtaskError> {
    let mut args = vec!["-p", "chio-cli", "--bin", "chio", "--"];
    args.extend_from_slice(chio_args);
    let output = Command::new("cargo")
        .arg("run")
        .args(&args)
        .current_dir(root)
        .output()
        .map_err(|err| XtaskError::Io("cargo run".into(), err))?;
    if output.status.success() {
        return Err(XtaskError::Process(format!(
            "negative assertion failed: {detail}"
        )));
    }
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !combined.contains(marker) {
        return Err(XtaskError::Process(format!(
            "negative assertion failed: {detail} (expected marker {marker:?} in output)"
        )));
    }
    Ok(())
}

/// Confirm `report[field] == expected` (string), failing closed otherwise. This
/// is the Rust equivalent of the scripts' `grep -q '"field": "expected"'` and
/// the python `report.get(field)` assertions.
fn assert_report_str(report: &Path, field: &str, expected: &str) -> Result<(), XtaskError> {
    let value = load_json(report)?;
    if str_field(&value, field) == Some(expected) {
        Ok(())
    } else {
        Err(invalid(&format!(
            "{}: expected {field}=={expected}, found {:?}",
            display(report),
            str_field(&value, field)
        )))
    }
}

/// Confirm `report[field] == expected` (bool), failing closed otherwise.
fn assert_report_bool(report: &Path, field: &str, expected: bool) -> Result<(), XtaskError> {
    let value = load_json(report)?;
    if value.get(field) == Some(&Value::Bool(expected)) {
        Ok(())
    } else {
        Err(invalid(&format!(
            "{}: expected {field}=={expected}, found {:?}",
            display(report),
            value.get(field)
        )))
    }
}

// -- runtime-spine-fixtures ------------------------------------------------

/// Validate runtime-derived signed bodies against their schemas, enforce the
/// scenario admission-profile/bundle native-schema assertion, and run the
/// static validate block from the manifest.
fn handle_spine_fixtures(
    root: &Path,
    manifest: &RuntimeManifest,
    facet: &RuntimeFacet,
) -> Result<(), XtaskError> {
    let fixture_dir = root.join(&facet.fixture_dir);

    // Build and validate the three signed bodies (trust / peer-weights / policy)
    // the script derives from their unsigned fixtures, and assert the scenario
    // steps carry Chio-native admission profiles and bundles.
    let scratch = ScratchDir::new("spine-fixtures")?;
    spine_build_and_validate_signed_bodies(root, &fixture_dir, &scratch)?;
    spine_assert_scenario_native(&fixture_dir)?;

    // Static schema-only validate pairs from the manifest.
    run_runtime_validate_pairs(root, manifest, facet)
}

/// Wrap an unsigned body in a signed envelope with filler signer/signature
/// bytes (matching the script's `signed_body` python) and validate it against
/// the named schema. The peer-weights body's `PEER_WEIGHTS_SHA256` token is
/// substituted with a 64-char filler, exactly as the script does.
fn spine_build_and_validate_signed_bodies(
    root: &Path,
    fixture_dir: &Path,
    scratch: &ScratchDir,
) -> Result<(), XtaskError> {
    let cases = [
        ("runtime-trust-body.json", "verifier-trust-bundle.schema.json"),
        ("runtime-peer-weights-body.json", "peer-weights.schema.json"),
        ("runtime-policy-body.json", "pheromone-policy.schema.json"),
    ];
    for (source, schema) in cases {
        let mut body = load_json(&fixture_dir.join(source))?;
        if str_field(&body, "peerWeightsSha256") == Some("PEER_WEIGHTS_SHA256") {
            set_str(&mut body, "peerWeightsSha256", &"e".repeat(64));
        }
        let envelope = serde_json::json!({
            "body": body,
            "signerKey": "a".repeat(64),
            "signature": "b".repeat(128),
        });
        let out = scratch.join(&format!("{source}.signed.json"));
        write_json(&out, &envelope)?;
        validate_runtime(root, schema, &out)?;
    }
    Ok(())
}

/// Assert each scenario step carries a Chio-native admission profile/bundle.
fn spine_assert_scenario_native(fixture_dir: &Path) -> Result<(), XtaskError> {
    let scenario = load_json(&fixture_dir.join("scenario.json"))?;
    let steps = scenario
        .get("steps")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("scenario fixture has no steps array"))?;
    for (index, step) in steps.iter().enumerate() {
        let profile = step.get("admissionProfile").unwrap_or(&Value::Null);
        let bundle = step.get("admissionBundle").unwrap_or(&Value::Null);
        if str_field(profile, "schema") != Some("chio.runtime.admission-profile.v1") {
            return Err(invalid(&format!(
                "scenario step {index} admission profile is not Chio-native"
            )));
        }
        if str_field(bundle, "schema") != Some("chio.runtime.admission-bundle.v1") {
            return Err(invalid(&format!(
                "scenario step {index} admission bundle is not Chio-native"
            )));
        }
    }
    Ok(())
}

// -- runtime-spine ---------------------------------------------------------

/// `check-chio-runtime-spine.sh`. Schema-only runs the spine-fixtures facet plus
/// the two attest validations (manifest). `all` adds the runtime-core test
/// suite, the chio-kernel runtime filter, the positive admission pipeline, and
/// the negative replay/mismatch assertions. `negative-only` runs the positive
/// pipeline (its prerequisite) then the negatives.
fn handle_spine(
    root: &Path,
    manifest: &RuntimeManifest,
    facet: &RuntimeFacet,
    mode: Mode,
) -> Result<(), XtaskError> {
    // Schema block (always): spine-fixtures, then the two attest validations.
    let spine_fixtures = manifest
        .facet_by_name("runtime-spine-fixtures")
        .ok_or_else(|| XtaskError::Manifest("runtime-spine-fixtures facet missing".into()))?;
    handle_spine_fixtures(root, manifest, spine_fixtures)?;
    run_runtime_validate_pairs(root, manifest, facet)?;

    if mode == Mode::SchemaOnly {
        return Ok(());
    }

    if mode == Mode::All {
        run_runtime_cargo_tests(root, facet)?;
        run_cargo_test_filtered(
            root,
            &to_owned(&["-p", "chio-kernel", "chio_runtime", "--lib"]),
        )?;
    }

    // Both `all` and `negative-only` run the positive pipeline (the negatives
    // depend on the store/inputs it leaves behind) then the negatives.
    let scratch = ScratchDir::new("runtime-spine")?;
    let inputs = spine_run_positive(root, facet, &scratch)?;
    spine_run_negative(root, &scratch, &inputs)
}

/// The signed inputs the spine positive pipeline produces and the negative
/// pipeline reuses.
struct SpineInputs {
    request: PathBuf,
    profile: PathBuf,
    bundle: PathBuf,
    trust_input: PathBuf,
    trusted_verifiers: PathBuf,
    query_report_signed: PathBuf,
    policy: PathBuf,
    peer_weights: PathBuf,
    store: PathBuf,
    trust_floor: PathBuf,
}

/// The positive admission pipeline: sign the trust input, build trusted
/// verifiers, hash and sign peer weights, sign policy and query report, then run
/// `runtime admit` and assert the report/store/trust-floor contents, finishing
/// with the treaty buyer hero-loop packet check.
fn spine_run_positive(
    root: &Path,
    facet: &RuntimeFacet,
    scratch: &ScratchDir,
) -> Result<SpineInputs, XtaskError> {
    let fixture_dir = root.join(&facet.fixture_dir);
    let copy = |name: &str| -> Result<PathBuf, XtaskError> {
        let dst = scratch.join(name);
        fs::copy(fixture_dir.join(name), &dst)
            .map_err(|err| XtaskError::Io(display(&dst), err))?;
        Ok(dst)
    };
    let profile = copy("profile.json")?;
    let request = copy("request.json")?;
    let bundle = copy("bundle.json")?;
    let seed = copy("verifier.seed")?;
    let trust_body = copy("runtime-trust-body.json")?;
    let query_report = copy("pheromone-query-report.json")?;
    let peer_weights_body = copy("runtime-peer-weights-body.json")?;
    let policy_body = copy("runtime-policy-body.json")?;

    let trust_input = scratch.join("runtime-trust-input.json");
    require_chio(
        root,
        &[
            "runtime",
            "sign-trust-input",
            "--body",
            &display(&trust_body),
            "--signing-seed-file",
            &display(&seed),
            "--out",
            &display(&trust_input),
        ],
    )?;
    validate_runtime(root, "verifier-trust-bundle.schema.json", &trust_input)?;

    let trusted_verifiers = scratch.join("trusted-verifiers.json");
    spine_build_trusted_verifiers(&trust_input, &trusted_verifiers)?;
    validate_runtime(root, "trusted-verifiers.schema.json", &trusted_verifiers)?;

    let peer_weights_hash = scratch.join("runtime-peer-weights.sha256");
    require_chio(
        root,
        &[
            "runtime",
            "peer-weights",
            "hash",
            "--body",
            &display(&peer_weights_body),
            "--out",
            &display(&peer_weights_hash),
        ],
    )?;
    spine_patch_policy_peer_weights(&policy_body, &peer_weights_hash)?;

    let peer_weights = scratch.join("runtime-peer-weights.json");
    require_chio(
        root,
        &[
            "runtime",
            "peer-weights",
            "sign",
            "--body",
            &display(&peer_weights_body),
            "--signing-seed-file",
            &display(&seed),
            "--out",
            &display(&peer_weights),
        ],
    )?;
    let policy = scratch.join("runtime-policy.json");
    require_chio(
        root,
        &[
            "runtime",
            "policy",
            "sign",
            "--body",
            &display(&policy_body),
            "--signing-seed-file",
            &display(&seed),
            "--out",
            &display(&policy),
        ],
    )?;
    let query_report_signed = scratch.join("pheromone-query-report.signed.json");
    require_chio(
        root,
        &[
            "runtime",
            "pheromone",
            "sign-query-report",
            "--body",
            &display(&query_report),
            "--signing-seed-file",
            &display(&seed),
            "--out",
            &display(&query_report_signed),
        ],
    )?;
    validate_runtime(root, "peer-weights.schema.json", &peer_weights)?;
    validate_runtime(root, "pheromone-policy.schema.json", &policy)?;

    let store = scratch.join("admission-store.json");
    let trust_floor = scratch.join("runtime-trust-floor-live.json");
    let report = scratch.join("admission-report.json");
    let inputs = SpineInputs {
        request,
        profile,
        bundle,
        trust_input,
        trusted_verifiers,
        query_report_signed,
        policy,
        peer_weights,
        store,
        trust_floor,
    };
    let admit_args = spine_admit_args(&inputs, "1800000001000", &report);
    require_chio(root, &borrow(&admit_args))?;
    validate_runtime(root, "admission-report.schema.json", &report)?;
    validate_runtime(root, "admission-store.schema.json", &inputs.store)?;
    validate_runtime(root, "trust-floor-state.schema.json", &inputs.trust_floor)?;
    spine_assert_admission(&report, &inputs.store, &inputs.trust_floor)?;

    run_bash_with_arg(root, "scripts/check-chio-treaty-buyer-hero-loop.sh", "--packet-only")?;
    Ok(inputs)
}

/// Build the `runtime admit` argv shared by the positive run and the negatives.
fn spine_admit_args<'a>(
    inputs: &'a SpineInputs,
    now_unix_ms: &'a str,
    report: &'a Path,
) -> Vec<String> {
    vec![
        "runtime".into(),
        "admit".into(),
        "--request".into(),
        display(&inputs.request),
        "--admission-profile".into(),
        display(&inputs.profile),
        "--admission-bundle".into(),
        display(&inputs.bundle),
        "--runtime-trust-input".into(),
        display(&inputs.trust_input),
        "--trusted-verifiers".into(),
        display(&inputs.trusted_verifiers),
        "--pheromone-query-report".into(),
        display(&inputs.query_report_signed),
        "--runtime-pheromone-policy".into(),
        display(&inputs.policy),
        "--runtime-peer-weights".into(),
        display(&inputs.peer_weights),
        "--store".into(),
        display(&inputs.store),
        "--trust-floor-state".into(),
        display(&inputs.trust_floor),
        "--now-unix-ms".into(),
        now_unix_ms.into(),
        "--report".into(),
        display(report),
    ]
}

/// The replay (destructive lease) and request-binding-mismatch negatives.
fn spine_run_negative(
    root: &Path,
    scratch: &ScratchDir,
    inputs: &SpineInputs,
) -> Result<(), XtaskError> {
    // Destructive lease replay: re-admit the same request must fail.
    let replay_report = scratch.join("replay-report.json");
    let replay_args = spine_admit_args(inputs, "1800000002000", &replay_report);
    reject_chio(
        root,
        &borrow(&replay_args),
        "expected destructive lease replay to fail",
    )?;
    validate_runtime(root, "admission-report.schema.json", &replay_report)?;
    assert_report_bool(&replay_report, "accepted", false)?;
    assert_report_str(&replay_report, "failureCode", "destructive_lease_replay")?;

    // Request binding mismatch: a request with a different toolArgsSha256 must
    // fail with request_binding_mismatch.
    let mismatch_request = scratch.join("request-mismatch.json");
    let mut request = load_json(&inputs.request)?;
    set_str(&mut request, "toolArgsSha256", &"d".repeat(64));
    write_json(&mismatch_request, &request)?;
    let mismatch_store = scratch.join("mismatch-store.json");
    let mismatch_floor = scratch.join("mismatch-trust-floor-live.json");
    let mismatch_report = scratch.join("mismatch-report.json");
    let mismatch_inputs = SpineInputs {
        request: mismatch_request,
        store: mismatch_store,
        trust_floor: mismatch_floor,
        profile: inputs.profile.clone(),
        bundle: inputs.bundle.clone(),
        trust_input: inputs.trust_input.clone(),
        trusted_verifiers: inputs.trusted_verifiers.clone(),
        query_report_signed: inputs.query_report_signed.clone(),
        policy: inputs.policy.clone(),
        peer_weights: inputs.peer_weights.clone(),
    };
    let mismatch_args = spine_admit_args(&mismatch_inputs, "1800000001000", &mismatch_report);
    reject_chio(
        root,
        &borrow(&mismatch_args),
        "expected request binding mismatch to fail",
    )?;
    validate_runtime(root, "admission-report.schema.json", &mismatch_report)?;
    assert_report_str(&mismatch_report, "failureCode", "request_binding_mismatch")
}

/// Build the trusted-verifiers document from a signed trust input. The
/// active-status verifier key is derived from the signed body and signer key.
fn spine_build_trusted_verifiers(signed: &Path, out: &Path) -> Result<(), XtaskError> {
    let value = load_json(signed)?;
    let body = value
        .get("body")
        .ok_or_else(|| invalid("signed trust input has no body"))?;
    let verifier_id = str_field(body, "verifierId")
        .ok_or_else(|| invalid("signed trust input body has no verifierId"))?;
    let key_id = str_field(body, "keyId")
        .ok_or_else(|| invalid("signed trust input body has no keyId"))?;
    let signer_key = str_field(&value, "signerKey")
        .ok_or_else(|| invalid("signed trust input has no signerKey"))?;
    let trusted = serde_json::json!({
        "schema": "chio.runtime.trusted-verifiers.v1",
        "verifierKeys": [
            {
                "verifierId": verifier_id,
                "keyId": key_id,
                "publicKey": signer_key,
                "validFromUnixMs": 1_800_000_000_000_i64,
                "validUntilUnixMs": 1_800_003_600_000_i64,
                "status": "active",
            }
        ],
    });
    write_json(out, &trusted)
}

/// Substitute the `PEER_WEIGHTS_SHA256` token in the policy body with the hash
/// the CLI emitted.
fn spine_patch_policy_peer_weights(policy_body: &Path, hash_file: &Path) -> Result<(), XtaskError> {
    let hash = fs::read_to_string(hash_file)
        .map_err(|err| XtaskError::Io(display(hash_file), err))?
        .trim()
        .to_string();
    let body = fs::read_to_string(policy_body)
        .map_err(|err| XtaskError::Io(display(policy_body), err))?
        .replace("PEER_WEIGHTS_SHA256", &hash);
    fs::write(policy_body, body).map_err(|err| XtaskError::Io(display(policy_body), err))
}

/// Assert the positive admission report, store, and trust-floor invariants.
fn spine_assert_admission(
    report: &Path,
    store: &Path,
    trust_floor: &Path,
) -> Result<(), XtaskError> {
    let report_value = load_json(report)?;
    if str_field(&report_value, "schema") != Some("chio.runtime.admission-report.v1") {
        return Err(invalid("runtime admission report schema mismatch"));
    }
    if report_value.get("accepted") != Some(&Value::Bool(true)) {
        return Err(invalid("runtime admission report was not accepted"));
    }
    let store_value = load_json(store)?;
    if str_field(&store_value, "schema") != Some("chio.runtime.admission-store.v1") {
        return Err(invalid("runtime admission store schema mismatch"));
    }
    if array_len(&store_value, "bundles") != Some(1) {
        return Err(invalid("runtime admission store did not retain admission bundle"));
    }
    if array_len(&store_value, "consumedLeaseIds") != Some(1) {
        return Err(invalid("runtime admission store did not retain lease replay fence"));
    }
    if store_value
        .get("trustFloors")
        .map(|v| !v.is_null())
        .unwrap_or(false)
    {
        return Err(invalid("runtime admission store leaked separate trust-floor state"));
    }
    let floor_value = load_json(trust_floor)?;
    if str_field(&floor_value, "schema") != Some("chio.runtime.trust-floor-state.v1") {
        return Err(invalid("runtime trust-floor state schema mismatch"));
    }
    if array_len(&floor_value, "entries") != Some(1) {
        return Err(invalid("runtime trust-floor state did not persist verifier floor"));
    }
    let metadata = report_value
        .get("receiptMetadata")
        .and_then(|m| m.get("chio_runtime"))
        .unwrap_or(&Value::Null);
    if str_field(metadata, "admission_id") != Some("adm-live-1") {
        return Err(invalid("runtime admission metadata did not bind admission id"));
    }
    if metadata.get("destructive") != Some(&Value::Bool(true)) {
        return Err(invalid("runtime admission metadata did not record destructive step"));
    }
    let advisory = report_value.get("pheromoneAdvisory").unwrap_or(&Value::Null);
    if advisory.get("observeOnly") != Some(&Value::Bool(true)) {
        return Err(invalid(
            "runtime admission report did not record observe-only pheromone advisory",
        ));
    }
    if metadata
        .get("pheromone_advisory")
        .and_then(|a| a.get("observeOnly"))
        != Some(&Value::Bool(true))
    {
        return Err(invalid(
            "runtime admission metadata did not preserve observe-only pheromone advisory",
        ));
    }
    Ok(())
}

fn array_len(value: &Value, key: &str) -> Option<usize> {
    value.get(key).and_then(Value::as_array).map(|a| a.len())
}

fn borrow(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

/// Run a bash script with a single argument, current-dir at the workspace root.
fn run_bash_with_arg(root: &Path, script: &str, arg: &str) -> Result<(), XtaskError> {
    let status = Command::new("bash")
        .arg(script)
        .arg(arg)
        .current_dir(root)
        .status()
        .map_err(|err| XtaskError::Io(format!("bash {script} {arg}"), err))?;
    if !status.success() {
        return Err(XtaskError::Process(format!(
            "bash {script} {arg} exited {}",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(())
}

// -- runtime-proof-parity --------------------------------------------------

/// `all` runs the three runtime-core proof filters, the fixture-generation +
/// verify-proof flow, the chio-cli runtime test, then the full spine.
/// `schema-only` / `negative-only` delegate to spine.
fn handle_proof_parity(
    root: &Path,
    manifest: &RuntimeManifest,
    facet: &RuntimeFacet,
    mode: Mode,
) -> Result<(), XtaskError> {
    let spine = manifest
        .facet_by_name("runtime-spine")
        .ok_or_else(|| XtaskError::Manifest("runtime-spine facet missing".into()))?;

    if mode == Mode::SchemaOnly {
        return handle_spine(root, manifest, spine, Mode::SchemaOnly);
    }
    if mode == Mode::NegativeOnly {
        return handle_spine(root, manifest, spine, Mode::NegativeOnly);
    }

    run_runtime_cargo_tests(root, facet)?;
    proof_parity_fixture_tests(root)?;
    handle_spine(root, manifest, spine, Mode::All)
}

/// Generate the three-vendor fixtures into a scratch dir, validate the proof
/// package / disclosure proof / federation bundles, run buyer verify-proof, and
/// validate the rerun verifier report.
fn proof_parity_fixture_tests(root: &Path) -> Result<(), XtaskError> {
    let scratch = ScratchDir::new("proof-parity")?;
    let out_dir = scratch.join("fixtures");
    require_cli(
        root,
        &[
            "-p",
            "chio-three-vendor-example",
            "--bin",
            "generate-chio-three-vendor-fixtures",
            "--",
            "--out-dir",
            &display(&out_dir),
        ],
    )?;
    let attest = root.join("spec/schemas/chio-attest/v1");
    let federation = root.join("spec/schemas/chio-federation/v1");
    validate_document(
        &attest.join("proof-package.schema.json"),
        &out_dir.join("buyer-auditor-proof-package.json"),
    )?;
    validate_document(
        &attest.join("selective-disclosure-proof.schema.json"),
        &out_dir.join("selective-disclosure-proof.json"),
    )?;
    validate_document(
        &federation.join("verifier-trust-bundle.schema.json"),
        &out_dir.join("verifier-trust-bundle.json"),
    )?;
    validate_document(
        &federation.join("verification-context.schema.json"),
        &out_dir.join("verification-context.json"),
    )?;
    let rerun = out_dir.join("verifier-report-rerun.json");
    require_chio(
        root,
        &[
            "attest",
            "buyer",
            "verify-proof",
            "--package",
            &display(&out_dir.join("buyer-auditor-proof-package.json")),
            "--trust-bundle",
            &display(&out_dir.join("verifier-trust-bundle.json")),
            "--context",
            &display(&out_dir.join("verification-context.json")),
            "--report",
            &display(&rerun),
        ],
    )?;
    validate_document(&attest.join("verifier-report.schema.json"), &rerun)
}

// -- runtime-policy --------------------------------------------------------

/// `check-chio-runtime-policy.sh`. `schema-only` validates the four inline
/// policy fixtures; `negative-only` runs the runtime-core/CLI policy tests;
/// `all` does both plus the full spine.
fn handle_policy(
    root: &Path,
    manifest: &RuntimeManifest,
    facet: &RuntimeFacet,
    mode: Mode,
) -> Result<(), XtaskError> {
    if mode != Mode::NegativeOnly {
        policy_schema_checks(root)?;
    }
    if mode != Mode::SchemaOnly {
        run_runtime_cargo_tests(root, facet)?;
    }
    if mode == Mode::All {
        let spine = manifest
            .facet_by_name("runtime-spine")
            .ok_or_else(|| XtaskError::Manifest("runtime-spine facet missing".into()))?;
        handle_spine(root, manifest, spine, Mode::All)?;
    }
    Ok(())
}

/// Materialize and validate the four inline policy fixtures the script wrote
/// (peer-weights envelope, policy envelope, policy decision, trust-floor state).
fn policy_schema_checks(root: &Path) -> Result<(), XtaskError> {
    let scratch = ScratchDir::new("runtime-policy")?;
    let cases: [(&str, &str, Value); 4] = [
        (
            "runtime-peer-weights.json",
            "peer-weights.schema.json",
            policy_peer_weights_fixture(),
        ),
        (
            "runtime-policy.json",
            "pheromone-policy.schema.json",
            policy_envelope_fixture(),
        ),
        (
            "runtime-policy-decision.json",
            "pheromone-policy-decision.schema.json",
            policy_decision_fixture(),
        ),
        (
            "runtime-trust-floor-state.json",
            "trust-floor-state.schema.json",
            policy_trust_floor_fixture(),
        ),
    ];
    for (name, schema, value) in cases {
        let path = scratch.join(name);
        write_json(&path, &value)?;
        validate_runtime(root, schema, &path)?;
    }
    Ok(())
}

fn policy_peer_weights_fixture() -> Value {
    serde_json::json!({
        "body": {
            "schema": "chio.runtime.peer-weights.v1",
            "verifierId": "did:chio:buyer-verifier",
            "keyId": "verifier-key-1",
            "reputationEpoch": 7,
            "issuedAtUnixMs": 1_800_000_000_000_i64,
            "expiresAtUnixMs": 1_800_003_600_000_i64,
            "weights": [ { "peerKernelId": "kernel.vendor-b", "weight": 1.0 } ]
        },
        "signerKey": "a".repeat(64),
        "signature": "b".repeat(128),
    })
}

fn policy_envelope_fixture() -> Value {
    serde_json::json!({
        "body": {
            "schema": "chio.runtime.pheromone-policy.v1",
            "policyId": "policy-runtime-risk",
            "verifierId": "did:chio:buyer-verifier",
            "keyId": "verifier-key-1",
            "policyVersion": 1,
            "mode": "enforce",
            "issuedAtUnixMs": 1_800_000_000_000_i64,
            "expiresAtUnixMs": 1_800_003_600_000_i64,
            "allowedReputationEpochs": [7],
            "maxQueryReportAgeMs": 60000,
            "minDistinctOriginPairs": 1,
            "runtimeTrustBundleSha256": "b".repeat(64),
            "peerWeightsSha256": "c".repeat(64),
            "rules": [
                {
                    "ruleId": "deny-high-runtime-risk",
                    "subjectClass": "workflow.destructive_step",
                    "subjectClassNamespace": "chio.runtime",
                    "actionClassId": "*",
                    "direction": "deny_if_at_or_above",
                    "thresholdTotalStrength": 0.75,
                    "effect": "deny"
                }
            ]
        },
        "signerKey": "a".repeat(64),
        "signature": "b".repeat(128),
    })
}

fn policy_decision_fixture() -> Value {
    serde_json::json!({
        "schema": "chio.runtime.pheromone-policy-decision.v1",
        "enforced": true,
        "decision": "deny",
        "policyId": "policy-runtime-risk",
        "policySha256": "a".repeat(64),
        "queryReportSha256": "b".repeat(64),
        "peerWeightsSha256": "c".repeat(64),
        "reputationEpoch": 7,
        "matchedRuleId": "deny-high-runtime-risk",
        "reasonCode": "runtime_pheromone_policy_deny"
    })
}

fn policy_trust_floor_fixture() -> Value {
    serde_json::json!({
        "schema": "chio.runtime.trust-floor-state.v1",
        "entries": [
            {
                "verifierId": "did:chio:buyer-verifier",
                "keyId": "verifier-key-1",
                "highestVersion": 2,
                "latestBundleSha256": "a".repeat(64),
                "latestRevocationCheckpointSha256": "d".repeat(64)
            }
        ]
    })
}

fn handle_attack_simulation(
    root: &Path,
    manifest: &RuntimeManifest,
    facet: &RuntimeFacet,
    mode: Mode,
) -> Result<(), XtaskError> {
    run_runtime_validate_pairs(root, manifest, facet)?;
    if mode == Mode::SchemaOnly {
        return Ok(());
    }
    run_runtime_cargo_tests(root, facet)
}

fn handle_chaos(
    root: &Path,
    manifest: &RuntimeManifest,
    facet: &RuntimeFacet,
    mode: Mode,
) -> Result<(), XtaskError> {
    run_runtime_validate_pairs(root, manifest, facet)?;
    if mode == Mode::SchemaOnly {
        return Ok(());
    }
    run_runtime_cargo_tests(root, facet)
}

include!("fixtures_runtime_ops.rs");
