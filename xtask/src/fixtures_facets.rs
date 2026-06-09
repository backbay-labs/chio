// Per-facet imperative handlers, pre-schema guards, and the metadata
// assertions ported from each script's embedded python block. Included into
// `fixtures.rs` via `include!` so the handlers share the module's private
// helpers while keeping each file under the 2000-line hygiene cap.

/// A unique temp directory cleaned up on drop. `unwrap`/`expect` are denied, so
/// cleanup is best-effort and ignores errors in `Drop`.
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new(label: &str) -> Result<Self, XtaskError> {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "chio-fixtures-{label}-{}-{}",
            std::process::id(),
            scratch_counter()
        );
        path.push(unique);
        fs::create_dir_all(&path).map_err(|err| XtaskError::Io(display(&path), err))?;
        Ok(Self { path })
    }

    fn join(&self, child: &str) -> PathBuf {
        self.path.join(child)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn scratch_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

// -- Pre-schema guards -----------------------------------------------------

/// Run the retired-marker / runbook / fixture-name guards a facet performs
/// before its schema block. The retired marker is assembled at runtime as
/// `"chio" + "dos"` so this gate file never embeds the joined literal it
/// screens for.
pub(crate) fn pre_schema_guard(root: &Path, facet: &Facet) -> Result<(), XtaskError> {
    match facet.kind.as_str() {
        "transit" => guard_no_marker_in_file(
            &root.join("spec/CHIO_PHEROMONE.md"),
            &retired_marker(),
            "active Chio pheromone spec must not cite retired docs or labels",
        ),
        "relay" => guard_no_chio_in_file(
            &root.join("docs/release/CHIO_PHEROMONE_RELAY_RUNBOOK.md"),
            "active Chio pheromone relay runbook must not cite Chio-named docs or labels",
        ),
        "directory_lifecycle" => guard_no_chio_in_tree(
            &root.join(&facet.fixture_dir),
            "active Chio pheromone relay fixtures must not cite Chio-named docs or labels",
        ),
        "relay_alert_assurance" => guard_assurance_no_legacy_marker(&root.join(&facet.fixture_dir)),
        _ => Ok(()),
    }
}

/// Runtime-assembled retired marker (`chio` + `dos`).
fn retired_marker() -> String {
    let mut marker = String::from("chio");
    marker.push_str("dos");
    marker
}

/// Fail if a case-insensitive marker appears in a file (matches the scripts'
/// `rg -n -i "$retired_marker"` guard).
fn guard_no_marker_in_file(
    path: &Path,
    marker: &str,
    message: &str,
) -> Result<(), XtaskError> {
    let text = fs::read_to_string(path).map_err(|err| XtaskError::Io(display(path), err))?;
    if text.to_ascii_lowercase().contains(&marker.to_ascii_lowercase()) {
        return Err(XtaskError::Validation(message.into()));
    }
    Ok(())
}

/// Fail if any of the Chio/CHIO/chio spellings appears in a file (matches the
/// relay runbook guard, which is intentionally case-sensitive across spellings).
fn guard_no_chio_in_file(path: &Path, message: &str) -> Result<(), XtaskError> {
    let text = fs::read_to_string(path).map_err(|err| XtaskError::Io(display(path), err))?;
    if text.contains("Chio") || text.contains("CHIO") || text.contains("chio") {
        return Err(XtaskError::Validation(message.into()));
    }
    Ok(())
}

/// Fail if any of the Chio spellings appears in any file under a tree (the
/// directory-lifecycle fixture guard).
fn guard_no_chio_in_tree(dir: &Path, message: &str) -> Result<(), XtaskError> {
    for path in walk_files(dir)? {
        let text =
            fs::read_to_string(&path).map_err(|err| XtaskError::Io(display(&path), err))?;
        if text.contains("Chio") || text.contains("CHIO") || text.contains("chio") {
            return Err(XtaskError::Validation(format!(
                "{message}: {}",
                display(&path)
            )));
        }
    }
    Ok(())
}

/// Fail if any assurance fixture JSON cites the retired relay surface. The
/// markers (`<retired>-relay`, `<retired>-pheromone-relay`, the runbook file
/// name) are assembled at runtime from `"chio" + "dos"`.
fn guard_assurance_no_legacy_marker(dir: &Path) -> Result<(), XtaskError> {
    let retired = retired_marker();
    let markers = [
        format!("{retired}-relay"),
        format!("{retired}-pheromone-relay"),
        format!("{}_PHEROMONE_RELAY_RUNBOOK.md", retired.to_ascii_uppercase()),
    ];
    for path in walk_files(dir)? {
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text =
            fs::read_to_string(&path).map_err(|err| XtaskError::Io(display(&path), err))?;
        for marker in &markers {
            if text.contains(marker) {
                return Err(XtaskError::Validation(format!(
                    "active Chio relay alert assurance fixture has legacy marker {marker}: {}",
                    display(&path)
                )));
            }
        }
    }
    Ok(())
}

/// Recursively collect every regular file under a directory, sorted.
fn walk_files(dir: &Path) -> Result<Vec<PathBuf>, XtaskError> {
    let mut out = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let entries = fs::read_dir(&current).map_err(|err| XtaskError::Io(display(&current), err))?;
        for entry in entries {
            let entry = entry.map_err(|err| XtaskError::Io(display(&current), err))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|err| XtaskError::Io(display(&path), err))?;
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

// -- Metadata assertions for the imperative facets -------------------------

fn metadata_transit(fixture_dir: &Path) -> Result<(), XtaskError> {
    let deposit = load_json(&fixture_dir.join("deposit.json"))?;
    let batch = load_json(&fixture_dir.join("gossip-batch.json"))?;
    let policy_envelope = load_json(&fixture_dir.join("transit-policy.json"))?;
    let concentration = load_json(&fixture_dir.join("concentration.json"))?;

    if policy_envelope.get("body").is_none()
        || policy_envelope.get("signerKey").is_none()
        || policy_envelope.get("signature").is_none()
    {
        return Err(invalid("transit policy must be a signed runtime-policy envelope"));
    }
    if str_field(&deposit, "schema") != Some("chio.pheromone-deposit.v1") {
        return Err(invalid("deposit fixture has wrong schema"));
    }
    if deposit.get("workflow_context").is_none() {
        return Err(invalid("deposit fixture must bind workflow context"));
    }
    let commitment = deposit
        .get("cost_commitment")
        .ok_or_else(|| invalid("deposit fixture must carry observation cost commitment"))?;
    if str_field(commitment, "schema") != Some("chio.pheromone-cost-commitment.v1") {
        return Err(invalid("cost commitment fixture has wrong schema"));
    }
    if str_field(
        deposit.get("workflow_context").unwrap_or(&Value::Null),
        "workflow_id",
    ) != Some("wf-chio-refund-001")
    {
        return Err(invalid("deposit workflow context does not bind the reference workflow"));
    }
    if str_field(&batch, "schema") != Some("chio.pheromone-batch.v1") {
        return Err(invalid("batch fixture has wrong schema"));
    }
    let frames = batch.get("frames").and_then(Value::as_array);
    if frames.map(|f| f.len()) != Some(1) {
        return Err(invalid("batch fixture must carry one relayed frame"));
    }
    if str_field(&concentration, "schema") != Some("chio.pheromone-concentration.v1") {
        return Err(invalid("concentration fixture has wrong schema"));
    }
    metadata_negative_codes(
        fixture_dir,
        "negative-cases.json",
        "id",
        &[
            "workflow-receipt-hash-mismatch",
            "dsse-hash-mismatch",
            "missing-cost-commitment",
            "stale-transit-policy",
        ],
    )
}

fn metadata_runtime(_root: &Path, fixture_dir: &Path) -> Result<(), XtaskError> {
    let policy_envelope = load_json(&fixture_dir.join("transit-policy.json"))?;
    let receive = load_json(&fixture_dir.join("receive-report.json"))?;
    let query = load_json(&fixture_dir.join("query-report.json"))?;
    let weights = load_json(&fixture_dir.join("peer-weights.json"))?;

    if policy_envelope.get("body").is_none()
        || policy_envelope.get("signerKey").is_none()
        || policy_envelope.get("signature").is_none()
    {
        return Err(invalid("runtime policy must be a signed envelope"));
    }
    if str_field(&receive, "schema") != Some("chio.pheromone.receive-report.v1")
        || receive.get("accepted") != Some(&Value::Bool(true))
    {
        return Err(invalid("committed receive report must be accepted"));
    }
    if str_field(&receive, "batchOutcome") != Some("accepted") {
        return Err(invalid("committed receive report must carry accepted batch outcome"));
    }
    if str_field(&query, "schema") != Some("chio.pheromone.query-report.v1")
        || query.get("accepted") != Some(&Value::Bool(true))
    {
        return Err(invalid("committed query report must be accepted"));
    }
    if str_field(&weights, "schema") != Some("chio.pheromone.peer-weights.v1") {
        return Err(invalid("peer weights fixture has wrong schema"));
    }
    Ok(())
}

fn metadata_relay(fixture_dir: &Path) -> Result<(), XtaskError> {
    let peer_directory = load_json(&fixture_dir.join("peer-directory.json"))?;
    if str_field(&peer_directory, "localKernelId") != Some("did:chio:dataco") {
        return Err(invalid("relay peer directory local kernel is not verifier-owned dataco"));
    }
    if str_field(&peer_directory, "schema") != Some("chio.pheromone.peer-directory.v1") {
        return Err(invalid("relay peer directory schema mismatch"));
    }
    if peer_directory
        .get("peers")
        .and_then(Value::as_array)
        .map(|p| p.is_empty())
        .unwrap_or(true)
    {
        return Err(invalid("relay peer directory has no pinned peers"));
    }
    metadata_negative_codes(
        fixture_dir,
        "negative-cases.json",
        "expectedFailureCode",
        &["unknown_peer", "body_hash_mismatch", "relay_nonce_replay", "endpoint_denied"],
    )
}

fn metadata_directory_lifecycle(fixture_dir: &Path) -> Result<(), XtaskError> {
    let state = load_json(&fixture_dir.join("peer-directory-state.json"))?;
    let active = state.get("active").cloned().unwrap_or(Value::Null);
    if active.get("version").and_then(Value::as_i64) != Some(2) {
        return Err(invalid("peer-directory state fixture is not at version 2"));
    }
    let removed = active
        .get("removedPeerIds")
        .and_then(Value::as_array)
        .map(|ids| {
            ids.iter()
                .any(|id| id.as_str() == Some("did:chio:buyer-kernel"))
        })
        .unwrap_or(false);
    if !removed {
        return Err(invalid("peer-directory state fixture does not quarantine the removed buyer peer"));
    }
    metadata_negative_codes(
        fixture_dir,
        "negative-cases.json",
        "expectedFailureCode",
        &[
            "peer_directory_state_invalid",
            "peer_directory_rollback",
            "peer_removed",
            "supervisor_profile_invalid",
        ],
    )
}

fn metadata_relay_observability(fixture_dir: &Path) -> Result<(), XtaskError> {
    metadata_negative_codes(
        fixture_dir,
        "negative-cases.json",
        "expectedFailureCode",
        &[
            "directory_expiring",
            "dead_letters_present",
            "relay_nonce_replay",
            "schema_validation_failed",
        ],
    )?;
    let metrics = load_json(&fixture_dir.join("relay-metrics-snapshot.json"))?;
    let disallowed = [
        "peer", "peer_id", "treaty", "treaty_id", "hash", "nonce", "cursor", "outbox_id",
    ];
    if let Some(samples) = metrics.get("samples").and_then(Value::as_array) {
        for sample in samples {
            if let Some(labels) = sample.get("labels").and_then(Value::as_object) {
                for key in labels.keys() {
                    if disallowed.contains(&key.as_str()) {
                        return Err(invalid(&format!(
                            "relay metrics fixture uses unbounded label: {key}"
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}

fn metadata_relay_alert_routing(fixture_dir: &Path) -> Result<(), XtaskError> {
    metadata_negative_codes(
        fixture_dir,
        "relay-alert-negative-cases.json",
        "id",
        &[
            "inline-token",
            "dynamic-url",
            "stale-report",
            "kernel-mismatch",
            "source-hash-mismatch",
            "overlong-suppression",
            "critical-suppression",
            "dedupe-collision",
            "missing-evidence",
            "timestamp-regression",
            "unknown-code-default-allow",
            "unbounded-label-leakage",
            "missing-metrics-false-all-clear",
        ],
    )?;
    let alert_report = load_json(&fixture_dir.join("relay-alert-report.json"))?;
    if alert_report.get("accepted") != Some(&Value::Bool(false))
        || str_field(&alert_report, "code") != Some("alerts_firing")
    {
        return Err(invalid("degraded alert report must remain firing"));
    }
    let trend = load_json(&fixture_dir.join("relay-trend-report.json"))?;
    let trend_codes: std::collections::BTreeSet<&str> = trend
        .get("points")
        .and_then(Value::as_array)
        .map(|points| {
            points
                .iter()
                .filter_map(|point| point.get("code").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    for required in ["dead_letters_present", "relay_nonce_replay", "endpoint_denied"] {
        if !trend_codes.contains(required) {
            return Err(invalid(&format!("trend report missing {required}")));
        }
    }
    Ok(())
}

fn str_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn invalid(message: &str) -> XtaskError {
    XtaskError::Validation(message.to_string())
}

// -- Imperative bodies -----------------------------------------------------

/// `transit`: cargo tests, then (mode == All) fixture regen via the generator
/// and a `cmp` of the five fixtures against the freshly-generated copies.
fn handle_transit(root: &Path, facet: &Facet, mode: Mode) -> Result<(), XtaskError> {
    run_cargo_tests(root, facet)?;
    if mode == Mode::NegativeOnly {
        return Ok(());
    }
    let scratch = ScratchDir::new("transit")?;
    let out_dir = scratch.join("pheromone");
    let out_arg = display(&out_dir);
    require_cli(
        root,
        &[
            "-p",
            "chio-three-vendor-example",
            "--bin",
            "generate-chio-three-vendor-fixtures",
            "--",
            "--pheromone-out-dir",
            &out_arg,
        ],
    )?;
    let fixture_dir = root.join(&facet.fixture_dir);
    for filename in [
        "deposit.json",
        "gossip-batch.json",
        "transit-policy.json",
        "concentration.json",
        "negative-cases.json",
    ] {
        cmp_files(&fixture_dir.join(filename), &out_dir.join(filename))?;
    }
    Ok(())
}

/// `runtime`: cargo tests, then (mode == All) regen + cmp of the eight runtime
/// fixtures and the receive/query CLI orchestration, then recurse into
/// `transit` (full).
fn handle_runtime(
    root: &Path,
    manifest: &Manifest,
    facet: &Facet,
    mode: Mode,
) -> Result<(), XtaskError> {
    if mode == Mode::NegativeOnly {
        // Negative-only runs the targeted rejection tests, not the full suite.
        for tail in RUNTIME_NEGATIVE_TESTS {
            run_cargo_test(root, &to_owned(tail))?;
        }
        return Ok(());
    }
    run_cargo_tests(root, facet)?;

    let scratch = ScratchDir::new("runtime")?;
    let out_dir = scratch.join("pheromone");
    let out_arg = display(&out_dir);
    require_cli(
        root,
        &[
            "-p",
            "chio-three-vendor-example",
            "--bin",
            "generate-chio-three-vendor-fixtures",
            "--",
            "--pheromone-out-dir",
            &out_arg,
        ],
    )?;
    let fixture_dir = root.join(&facet.fixture_dir);
    for filename in [
        "deposit.json",
        "gossip-batch.json",
        "transit-policy.json",
        "concentration.json",
        "negative-cases.json",
        "receive-report.json",
        "query-report.json",
        "peer-weights.json",
    ] {
        cmp_files(&fixture_dir.join(filename), &out_dir.join(filename))?;
    }

    run_recursion(root, manifest, facet)
}

const RUNTIME_NEGATIVE_TESTS: [&[&str]; 4] = [
    &[
        "-p",
        "chio-pheromone-runtime",
        "--test",
        "runtime_receiver",
        "runtime_policy_loader_rejects",
        "--",
        "--nocapture",
    ],
    &[
        "-p",
        "chio-pheromone-runtime",
        "--test",
        "runtime_receiver",
        "storage_commit_failure_is_reported_without_accepting_frame",
        "--",
        "--nocapture",
    ],
    &[
        "-p",
        "chio-pheromone-runtime",
        "--test",
        "runtime_receiver",
        "sqlite_receive_rolls_back_accepted_state_when_report_persistence_fails",
        "--",
        "--nocapture",
    ],
    &[
        "-p",
        "chio-pheromone",
        "--test",
        "pheromone_substrate",
        "observation_cost_commitment_rejects_untrusted_invalid_and_revoked_roots",
        "--",
        "--nocapture",
    ],
];

/// `relay`: the env-branch cargo tests (with the 9-entry `--skip` list), the
/// chio-cli pheromone test, then (mode == All) the heavy CLI orchestration with
/// the three negative assertions, then recurse into `runtime` (full).
/// `mode == NegativeOnly` runs the orchestration then the signed-request test
/// and exits before recursion.
fn handle_relay(
    root: &Path,
    manifest: &Manifest,
    facet: &Facet,
    mode: Mode,
) -> Result<(), XtaskError> {
    run_relay_unit_tests(root)?;
    run_cargo_tests(root, facet)?;

    relay_cli_orchestration(root, facet)?;

    if mode == Mode::NegativeOnly {
        run_cargo_test(
            root,
            &to_owned(&[
                "-p",
                "chio-pheromone-relay",
                "signed_relay_request_verifies_payload_hash_sender_and_replay_nonce",
            ]),
        )?;
        return Ok(());
    }

    run_recursion(root, manifest, facet)
}

/// The `CHIO_RELAY_RUN_BIND_TESTS` env branch. When set to `1`, run the full
/// relay suite single-threaded; otherwise run the `relay` integration test with
/// the 9-entry skip list.
fn run_relay_unit_tests(root: &Path) -> Result<(), XtaskError> {
    let run_bind = std::env::var("CHIO_RELAY_RUN_BIND_TESTS")
        .map(|value| value == "1")
        .unwrap_or(false);
    if run_bind {
        run_cargo_test(
            root,
            &to_owned(&[
                "-p",
                "chio-pheromone-relay",
                "--",
                "--test-threads=1",
            ]),
        )
    } else {
        let mut tail = vec![
            "-p".to_string(),
            "chio-pheromone-relay".to_string(),
            "--test".to_string(),
            "relay".to_string(),
            "--".to_string(),
            "--test-threads=1".to_string(),
        ];
        for skip in RELAY_SKIP_TESTS {
            tail.push("--skip".to_string());
            tail.push(skip.to_string());
        }
        run_cargo_test(root, &tail)
    }
}

const RELAY_SKIP_TESTS: [&str; 9] = [
    "service::loopback_http_delivery_posts_signed_batch_to_receiver",
    "service::relay_catchup_rejects_origin_only_peer_role",
    "service::relay_catchup_rejects_returned_frame_with_unpinned_transit_ladder",
    "service::relay_observability_endpoint_requires_operator_token_when_configured",
    "service::relay_rejects_authenticated_batch_above_peer_frame_limit",
    "service::relay_rejects_authenticated_batch_for_unsubscribed_treaty",
    "service::relay_rejects_authenticated_batch_from_non_origin_peer_role",
    "service::relay_rejects_authenticated_batch_with_unpinned_transit_ladder",
    "service::relay_tick_delivers_leased_batches_with_real_request_signature",
];

/// The relay `status` / `tick` / `enqueue` / `catchup` CLI orchestration,
/// including the three deliberate negative assertions (untrusted action class,
/// empty batch, catchup without/over peer-directory bounds).
fn relay_cli_orchestration(root: &Path, facet: &Facet) -> Result<(), XtaskError> {
    let scratch = ScratchDir::new("relay")?;
    let fixture_dir = root.join(&facet.fixture_dir);
    let pheromone_dir = root.join("examples/chio-3vendor/fixtures/pheromone");
    let schema_dir = root.join("spec/schemas/chio-pheromone/v1");

    let signing_key = scratch.join("relay-signing-key.json");
    write_signing_key(&signing_key)?;

    let store = scratch.join("relay.sqlite3");
    let status_report = scratch.join("status.json");
    require_cli(
        root,
        &[
            "-p",
            "chio-cli",
            "--bin",
            "chio",
            "--",
            "pheromone",
            "relay",
            "status",
            "--store",
            &display(&store),
            "--report",
            &display(&status_report),
        ],
    )?;
    validate_document(&schema_dir.join("relay-operator-report.schema.json"), &status_report)?;

    let peer_directory = fixture_dir.join("peer-directory.json");
    let tick_report = scratch.join("tick.json");
    require_cli(
        root,
        &[
            "-p",
            "chio-cli",
            "--bin",
            "chio",
            "--",
            "pheromone",
            "relay",
            "tick",
            "--store",
            &display(&store),
            "--peer-directory",
            &display(&peer_directory),
            "--now-unix-ms",
            "1766000000500",
            "--max-batches",
            "4",
            "--signing-key",
            &display(&signing_key),
            "--report",
            &display(&tick_report),
        ],
    )?;
    validate_document(&schema_dir.join("relay-tick-report.schema.json"), &tick_report)?;

    // The auditor catchup batch and signed transit policy are produced by the
    // generator; build them, then exercise enqueue/catchup with the negative
    // assertions. These derived fixtures depend on the source batch + policy.
    let auditor = relay_build_auditor_inputs(root, &scratch, &pheromone_dir)?;

    let trust_bundle = root.join("examples/chio-3vendor/fixtures/verifier-trust-bundle.json");
    let peer_state = fixture_dir.join("peer-directory-state.json");
    let trusted_issuers = fixture_dir.join("trusted-peer-directory-issuers.json");
    let enqueue_report = scratch.join("enqueue.json");
    require_cli(
        root,
        &[
            "-p",
            "chio-cli",
            "--bin",
            "chio",
            "--",
            "pheromone",
            "relay",
            "enqueue",
            "--store",
            &display(&store),
            "--batch",
            &display(&auditor.catchup_batch),
            "--transit-policy",
            &display(&auditor.transit_policy),
            "--trust-bundle",
            &display(&trust_bundle),
            "--peer-directory-state",
            &display(&peer_state),
            "--trusted-issuers",
            &display(&trusted_issuers),
            "--now-unix-ms",
            "1766000000500",
            "--report",
            &display(&enqueue_report),
        ],
    )?;
    validate_document(&schema_dir.join("relay-operator-report.schema.json"), &enqueue_report)?;
    assert_detail_contains(&enqueue_report, "pending=1", "enqueue did not create a pending outbox row")?;

    // Negative: untrusted transit action class must be rejected.
    let bad_report = scratch.join("enqueue-bad-action-class.json");
    reject_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "enqueue",
            "--store", &display(&store),
            "--batch", &display(&auditor.bad_batch),
            "--transit-policy", &display(&auditor.transit_policy),
            "--trust-bundle", &display(&trust_bundle),
            "--peer-directory-state", &display(&peer_state),
            "--trusted-issuers", &display(&trusted_issuers),
            "--now-unix-ms", "1766000000500",
            "--report", &display(&bad_report),
        ],
        "relay enqueue unexpectedly accepted an untrusted transit action class",
    )?;

    // Negative: empty gossip batch must be rejected.
    let empty_report = scratch.join("enqueue-empty-batch.json");
    reject_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "enqueue",
            "--store", &display(&store),
            "--batch", &display(&auditor.empty_batch),
            "--transit-policy", &display(&auditor.transit_policy),
            "--trust-bundle", &display(&trust_bundle),
            "--peer-directory-state", &display(&peer_state),
            "--trusted-issuers", &display(&trusted_issuers),
            "--now-unix-ms", "1766000000500",
            "--report", &display(&empty_report),
        ],
        "relay enqueue unexpectedly accepted an empty gossip batch",
    )?;

    // Negative: catchup without peer-directory state must fail.
    let catchup_no_dir = scratch.join("catchup-without-directory.json");
    reject_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "catchup",
            "--store", &display(&store),
            "--peer", "did:chio:auditor-kernel",
            "--treaty", "treaty:auditor-dataco:support-ops",
            "--after-cursor", "0",
            "--limit", "16",
            "--report", &display(&catchup_no_dir),
        ],
        "relay catchup unexpectedly succeeded without peer-directory state",
    )?;

    // Negative: catchup over the peer-directory frame bound must fail.
    let catchup_over = scratch.join("catchup-over-limit.json");
    reject_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "catchup",
            "--store", &display(&store),
            "--peer", "did:chio:auditor-kernel",
            "--peer-directory-state", &display(&peer_state),
            "--trusted-issuers", &display(&trusted_issuers),
            "--now-unix-ms", "1766000000500",
            "--treaty", "treaty:auditor-dataco:support-ops",
            "--after-cursor", "0",
            "--limit", "17",
            "--report", &display(&catchup_over),
        ],
        "relay catchup unexpectedly exceeded peer-directory frame bounds",
    )?;

    // Positive catchup, validated and asserted.
    let catchup_report = scratch.join("catchup.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "catchup",
            "--store", &display(&store),
            "--peer", "did:chio:auditor-kernel",
            "--peer-directory-state", &display(&peer_state),
            "--trusted-issuers", &display(&trusted_issuers),
            "--now-unix-ms", "1766000000500",
            "--treaty", "treaty:auditor-dataco:support-ops",
            "--after-cursor", "0",
            "--limit", "16",
            "--report", &display(&catchup_report),
        ],
    )?;
    validate_document(&schema_dir.join("catchup-response.schema.json"), &catchup_report)?;
    assert_catchup_returned_one_frame(&catchup_report)?;
    Ok(())
}

/// The set of auditor-derived relay inputs the orchestration builds.
struct AuditorInputs {
    catchup_batch: PathBuf,
    bad_batch: PathBuf,
    empty_batch: PathBuf,
    transit_policy: PathBuf,
}

/// Build the auditor catchup batch, the bad-action-class variant, the empty
/// variant, and the signed auditor transit policy. The batch/policy mutations
/// mirror the embedded python in the relay script; the policy is then signed by
/// the generator.
fn relay_build_auditor_inputs(
    root: &Path,
    scratch: &ScratchDir,
    pheromone_dir: &Path,
) -> Result<AuditorInputs, XtaskError> {
    let catchup_batch = scratch.join("auditor-catchup-batch.json");
    let bad_batch = scratch.join("auditor-action-class-bad-batch.json");
    let empty_batch = scratch.join("auditor-empty-batch.json");
    let policy_body = scratch.join("auditor-transit-policy-body.json");
    let signed_policy = scratch.join("auditor-transit-policy.json");

    build_auditor_batches(
        &pheromone_dir.join("gossip-batch.json"),
        &catchup_batch,
        &bad_batch,
        &empty_batch,
    )?;
    build_auditor_policy_body(&pheromone_dir.join("transit-policy.json"), &policy_body)?;

    require_cli(
        root,
        &[
            "-p",
            "chio-three-vendor-example",
            "--bin",
            "generate-chio-three-vendor-fixtures",
            "--",
            "--sign-transit-policy",
            &display(&policy_body),
            &display(&signed_policy),
        ],
    )?;

    Ok(AuditorInputs {
        catchup_batch,
        bad_batch,
        empty_batch,
        transit_policy: signed_policy,
    })
}

const AUDITOR_HOP: &str = r#"{
  "from_kernel_id": "did:chio:dataco",
  "to_kernel_id": "did:chio:auditor-kernel",
  "treaty_id": "treaty:auditor-dataco:support-ops",
  "ladder_manifest_id": "ladder:auditor:review:v1",
  "ladder_manifest_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "ladder_manifest_expires_at_unix_ms": 1766000060500,
  "ladder_intersection_id": "intersection:dataco:auditor",
  "ladder_intersection_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "action_class_id": "whisker.pheromone_deposit",
  "emitted_at_unix_ms": 1766000000500
}"#;

fn build_auditor_batches(
    source_batch: &Path,
    catchup_path: &Path,
    bad_path: &Path,
    empty_path: &Path,
) -> Result<(), XtaskError> {
    let mut batch = load_json(source_batch)?;
    set_str(&mut batch, "recipient_kernel_id", "did:chio:auditor-kernel");
    set_str(&mut batch, "treaty_id", "treaty:auditor-dataco:support-ops");
    set_i64(&mut batch, "flushed_at_unix_ms", 1766000000500);
    {
        let frame = batch
            .get_mut("frames")
            .and_then(Value::as_array_mut)
            .and_then(|frames| frames.get_mut(0))
            .ok_or_else(|| invalid("source batch has no frame to mutate"))?;
        set_str(frame, "gossiping_peer_kernel_id", "did:chio:dataco");
        set_str(frame, "treaty_id", "treaty:auditor-dataco:support-ops");
        set_i64(frame, "ts_unix_ms", 1766000000500);
        let hop: Value = serde_json::from_str(AUDITOR_HOP)
            .map_err(|err| XtaskError::Json("<auditor hop literal>".into(), err))?;
        frame
            .get_mut("transit_chain")
            .and_then(|chain| chain.get_mut("hops"))
            .and_then(Value::as_array_mut)
            .ok_or_else(|| invalid("source frame has no transit chain hops"))?
            .push(hop);
    }
    write_json(catchup_path, &batch)?;

    let mut bad = batch.clone();
    if let Some(hop) = bad
        .get_mut("frames")
        .and_then(Value::as_array_mut)
        .and_then(|frames| frames.get_mut(0))
        .and_then(|frame| frame.get_mut("transit_chain"))
        .and_then(|chain| chain.get_mut("hops"))
        .and_then(Value::as_array_mut)
        .and_then(|hops| hops.last_mut())
    {
        set_str(hop, "action_class_id", "whisker.untrusted");
    }
    write_json(bad_path, &bad)?;

    let mut empty = batch.clone();
    if let Some(obj) = empty.as_object_mut() {
        obj.insert("frames".to_string(), Value::Array(Vec::new()));
    }
    write_json(empty_path, &empty)?;
    Ok(())
}

const AUDITOR_LADDER_REF: &str = r#"{
  "ladder_manifest_id": "ladder:auditor:review:v1",
  "ladder_manifest_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "ladder_manifest_expires_at_unix_ms": 1766000060500,
  "ladder_intersection_id": "intersection:dataco:auditor",
  "ladder_intersection_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
}"#;

/// Build the auditor transit-policy body, recomputing the runtime and scarcity
/// policy hashes exactly as the embedded python did (drop the hash fields,
/// canonicalize with sorted keys and tight separators, sha256).
fn build_auditor_policy_body(source_policy: &Path, out_path: &Path) -> Result<(), XtaskError> {
    let envelope = load_json(source_policy)?;
    let mut body = envelope
        .get("body")
        .cloned()
        .ok_or_else(|| invalid("source transit policy has no body"))?;
    set_value(
        &mut body,
        "accepted_hubs",
        Value::Array(vec![
            Value::String("did:chio:buyer-kernel".into()),
            Value::String("did:chio:dataco".into()),
        ]),
    );
    set_i64(&mut body, "max_hops", 3);
    set_value(
        &mut body,
        "allowed_egress_treaties",
        Value::Array(
            [
                "treaty:buyer-llamaworks:support-ops",
                "treaty:buyer-dataco:support-ops",
                "treaty:buyer-payswift:support-ops",
                "treaty:auditor-dataco:support-ops",
            ]
            .iter()
            .map(|s| Value::String((*s).into()))
            .collect(),
        ),
    );
    let ladder_ref: Value = serde_json::from_str(AUDITOR_LADDER_REF)
        .map_err(|err| XtaskError::Json("<auditor ladder ref literal>".into(), err))?;
    body.get_mut("pinned_ladder_refs")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid("transit policy body has no pinned_ladder_refs"))?
        .push(ladder_ref);

    let runtime_hash = runtime_policy_hash(&body);
    if let Some(admission) = body.get_mut("admission") {
        if let Some(roots) = admission
            .get_mut("observationCostVerifierRoots")
            .and_then(Value::as_array_mut)
        {
            for root in roots.iter_mut() {
                set_str(root, "runtimePolicySha256", &runtime_hash);
            }
        }
        if let Some(policies) = admission
            .get_mut("scarcityPolicies")
            .and_then(Value::as_array_mut)
        {
            for policy in policies.iter_mut() {
                set_str(policy, "runtimePolicySha256", &runtime_hash);
                let scarcity_hash = scarcity_policy_hash(policy);
                set_str(policy, "policySha256", &scarcity_hash);
            }
        }
    }
    write_json(out_path, &body)
}

/// Canonical sha256 over a JSON value with sorted keys and tight separators
/// (matches `json.dumps(value, sort_keys=True, separators=(",", ":"))`).
fn canonical_sha256(value: &Value) -> String {
    use sha2::{Digest, Sha256};
    let canonical = canonical_json(value);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Render a JSON value with object keys sorted and no insignificant whitespace.
fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let body: Vec<String> = keys
                .into_iter()
                .map(|key| {
                    let rendered = canonical_json(&map[key]);
                    format!("{}:{}", json_string(key), rendered)
                })
                .collect();
            format!("{{{}}}", body.join(","))
        }
        Value::Array(items) => {
            let body: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", body.join(","))
        }
        other => other.to_string(),
    }
}

fn json_string(raw: &str) -> String {
    Value::String(raw.to_string()).to_string()
}

fn runtime_policy_hash(body: &Value) -> String {
    let mut material = body.clone();
    if let Some(admission) = material.get_mut("admission") {
        if let Some(policies) = admission
            .get_mut("scarcityPolicies")
            .and_then(Value::as_array_mut)
        {
            for policy in policies.iter_mut() {
                remove_key(policy, "runtimePolicySha256");
                remove_key(policy, "policySha256");
            }
        }
        if let Some(roots) = admission
            .get_mut("observationCostVerifierRoots")
            .and_then(Value::as_array_mut)
        {
            for root in roots.iter_mut() {
                remove_key(root, "runtimePolicySha256");
                remove_key(root, "issuerSignature");
            }
        }
    }
    canonical_sha256(&material)
}

fn scarcity_policy_hash(policy: &Value) -> String {
    let mut material = policy.clone();
    remove_key(&mut material, "policySha256");
    canonical_sha256(&material)
}

// -- small JSON mutators ---------------------------------------------------

fn set_str(value: &mut Value, key: &str, new: &str) {
    if let Some(obj) = value.as_object_mut() {
        obj.insert(key.to_string(), Value::String(new.to_string()));
    }
}

fn set_i64(value: &mut Value, key: &str, new: i64) {
    if let Some(obj) = value.as_object_mut() {
        obj.insert(key.to_string(), Value::Number(new.into()));
    }
}

fn set_value(value: &mut Value, key: &str, new: Value) {
    if let Some(obj) = value.as_object_mut() {
        obj.insert(key.to_string(), new);
    }
}

fn remove_key(value: &mut Value, key: &str) {
    if let Some(obj) = value.as_object_mut() {
        obj.remove(key);
    }
}

fn write_json(path: &Path, value: &Value) -> Result<(), XtaskError> {
    let pretty = serde_json::to_string_pretty(value)
        .map_err(|err| XtaskError::Json(display(path), err))?;
    fs::write(path, format!("{pretty}\n")).map_err(|err| XtaskError::Io(display(path), err))
}

fn write_signing_key(path: &Path) -> Result<(), XtaskError> {
    let key = serde_json::json!({
        "kernelId": "did:chio:dataco",
        "seedHex": "01".repeat(32),
    });
    write_json(path, &key)
}

fn cmp_files(left: &Path, right: &Path) -> Result<(), XtaskError> {
    let left_bytes = fs::read(left).map_err(|err| XtaskError::Io(display(left), err))?;
    let right_bytes = fs::read(right).map_err(|err| XtaskError::Io(display(right), err))?;
    if left_bytes != right_bytes {
        return Err(XtaskError::Validation(format!(
            "fixture drift: {} != {}",
            display(left),
            display(right)
        )));
    }
    Ok(())
}

fn assert_detail_contains(report: &Path, needle: &str, message: &str) -> Result<(), XtaskError> {
    let value = load_json(report)?;
    if str_field(&value, "detail").map(|d| d.contains(needle)).unwrap_or(false) {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

fn assert_catchup_returned_one_frame(report: &Path) -> Result<(), XtaskError> {
    let value = load_json(report)?;
    let frames = value.get("frames").and_then(Value::as_array).map(|f| f.len());
    let next_cursor = str_field(&value, "nextCursor");
    if frames == Some(1) && next_cursor != Some("0") {
        Ok(())
    } else {
        Err(invalid("catchup did not return the queued frame"))
    }
}

fn to_owned(tail: &[&str]) -> Vec<String> {
    tail.iter().map(|s| (*s).to_string()).collect()
}

// -- Recursion-only / dashboard / sre-metrics facets -----------------------

fn handle_relay_ops(
    root: &Path,
    manifest: &Manifest,
    facet: &Facet,
    mode: Mode,
) -> Result<(), XtaskError> {
    run_cargo_tests(root, facet)?;
    if mode == Mode::NegativeOnly {
        run_cargo_test(
            root,
            &to_owned(&[
                "-p",
                "chio-pheromone-relay",
                "signed_relay_request_verifies_payload_hash_sender_and_replay_nonce",
            ]),
        )?;
        return Ok(());
    }
    run_recursion(root, manifest, facet)
}

fn handle_directory_lifecycle(
    root: &Path,
    manifest: &Manifest,
    facet: &Facet,
    mode: Mode,
) -> Result<(), XtaskError> {
    run_cargo_tests(root, facet)?;
    if mode == Mode::NegativeOnly {
        return Ok(());
    }
    run_recursion(root, manifest, facet)
}

fn handle_relay_observability(
    root: &Path,
    manifest: &Manifest,
    facet: &Facet,
    mode: Mode,
) -> Result<(), XtaskError> {
    run_cargo_tests(root, facet)?;
    if facet.sre_metrics_registry {
        run_sre_metrics(root)?;
    }
    if facet.needs_dashboard_npm {
        run_dashboard_test_and_build(root, &[])?;
    }
    if mode == Mode::NegativeOnly {
        return Ok(());
    }
    run_recursion(root, manifest, facet)
}

/// The alert routing/handoff/delivery facets: cargo tests, optional
/// sre-metrics, npm test/build, then recurse. The dashboard `npm test`
/// arguments differ per facet, so they are encoded here by facet name.
fn handle_alert_with_npm(
    root: &Path,
    manifest: &Manifest,
    facet: &Facet,
    mode: Mode,
) -> Result<(), XtaskError> {
    run_cargo_tests(root, facet)?;
    if facet.sre_metrics_registry {
        run_sre_metrics(root)?;
    }
    if mode == Mode::NegativeOnly {
        return Ok(());
    }
    if facet.needs_dashboard_npm {
        run_dashboard_test_and_build(root, dashboard_test_args(&facet.name))?;
    }
    run_recursion(root, manifest, facet)
}

fn dashboard_test_args(facet_name: &str) -> &'static [&'static str] {
    match facet_name {
        "relay-alert-delivery" => &["--", "RelayAlertDeliverySummary", "RelayAlertRoutingSummary"],
        "relay-alert-handoff" => &["--", "RelayAlertRoutingSummary"],
        _ => &[],
    }
}

/// The assurance facet runs cargo tests then its dashboard build after
/// recursion (the script order). npm test args are the assurance-specific set.
fn handle_alert_assurance(
    root: &Path,
    manifest: &Manifest,
    facet: &Facet,
    mode: Mode,
) -> Result<(), XtaskError> {
    run_cargo_tests(root, facet)?;
    if mode == Mode::NegativeOnly {
        return Ok(());
    }
    run_recursion(root, manifest, facet)?;
    if facet.needs_dashboard_npm {
        run_dashboard_test_and_build(root, &["--", "RelayAlertAssuranceSummary", "api", "App"])?;
    }
    Ok(())
}

/// The export/archive/archive-package chain: cargo tests, then (mode == All)
/// recurse one level up the chain (`--schema-only`).
fn handle_archive_chain(
    root: &Path,
    manifest: &Manifest,
    facet: &Facet,
    mode: Mode,
) -> Result<(), XtaskError> {
    run_cargo_tests(root, facet)?;
    if mode == Mode::NegativeOnly {
        return Ok(());
    }
    run_recursion(root, manifest, facet)
}

/// Generic facets (`archive-hardening`, `external-retention`) run their cargo
/// tests in both `all` and `negative-only`, with no recursion.
fn handle_generic(root: &Path, facet: &Facet) -> Result<(), XtaskError> {
    run_cargo_tests(root, facet)
}
