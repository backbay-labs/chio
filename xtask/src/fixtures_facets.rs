// Per-facet imperative handlers, pre-schema guards, and metadata assertions.
// Included into `fixtures.rs` via `include!` so the handlers share the module's
// private helpers while keeping runtime handlers focused.

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

/// Reserved hook for facet-specific checks that run before schema validation.
pub(crate) fn pre_schema_guard(_root: &Path, _facet: &Facet) -> Result<(), XtaskError> {
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
    // The cost-commitment statement must bind back to the deposit's subject
    // namespace/class and treaty scope, and carry the verifier identity the
    // scarcity policy later pins. The commitment is the load-bearing tie between
    // the deposit and the scarcity economics.
    let statement = commitment
        .get("statement")
        .ok_or_else(|| invalid("cost commitment fixture must carry a statement"))?;
    for field in ["subjectClassNamespace", "subjectClass", "treatyId", "verifierId"] {
        if statement.get(field).is_none() {
            return Err(invalid(&format!("cost commitment statement missing {field}")));
        }
    }
    if str_field(statement, "subjectClassNamespace") != str_field(&deposit, "subject_class_namespace")
    {
        return Err(invalid(
            "cost commitment namespace does not bind deposit subject namespace",
        ));
    }
    if str_field(statement, "subjectClass") != str_field(&deposit, "subject_class") {
        return Err(invalid("cost commitment class does not bind deposit subject class"));
    }
    let statement_treaty = str_field(statement, "treatyId")
        .ok_or_else(|| invalid("cost commitment statement has no treatyId"))?;
    let treaty_scope = deposit
        .get("treaty_scope")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("deposit fixture has no treaty_scope"))?;
    if !treaty_scope.iter().any(|t| t.as_str() == Some(statement_treaty)) {
        return Err(invalid(
            "cost commitment treaty scope does not bind deposit treaty scope",
        ));
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
    let frames = batch
        .get("frames")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("batch fixture has no frames array"))?;
    if frames.len() != 1 {
        return Err(invalid("batch fixture must carry one relayed frame"));
    }
    // The single frame must exercise a two-hop downstream transit chain: the
    // first hop on the origin treaty, the last hop on the frame treaty, and the
    // frame treaty distinct from the first-hop treaty (a relay, not direct
    // gossip). Both hop treaties must be admitted in the deposit treaty scope.
    let frame = &frames[0];
    let hops = frame
        .get("transit_chain")
        .and_then(|c| c.get("hops"))
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("frame has no transit chain hops"))?;
    if hops.len() != 2 {
        return Err(invalid("fixture must carry a two-hop transit chain"));
    }
    let frame_treaty = str_field(frame, "treaty_id");
    let first_hop_treaty = str_field(&hops[0], "treaty_id");
    let last_hop_treaty = str_field(&hops[hops.len() - 1], "treaty_id");
    if frame_treaty == first_hop_treaty {
        return Err(invalid(
            "fixture must exercise downstream treaty relay, not direct gossip",
        ));
    }
    let frame_treaty = frame_treaty
        .ok_or_else(|| invalid("frame has no treaty_id"))?;
    if !treaty_scope.iter().any(|t| t.as_str() == Some(frame_treaty)) {
        return Err(invalid(
            "frame treaty must be admitted in deposit treaty scope for scoped economics",
        ));
    }
    let first_hop_treaty =
        first_hop_treaty.ok_or_else(|| invalid("first transit hop has no treaty_id"))?;
    if !treaty_scope.iter().any(|t| t.as_str() == Some(first_hop_treaty)) {
        return Err(invalid("first transit hop must use the origin treaty"));
    }
    if last_hop_treaty != Some(frame_treaty) {
        return Err(invalid("last transit hop must match the frame treaty"));
    }
    // The transit policy must cap the fixture at two hops and carry exactly one
    // scarcity policy whose hashes bind the cost-commitment statement.
    let policy_body = policy_envelope
        .get("body")
        .ok_or_else(|| invalid("transit policy envelope has no body"))?;
    if policy_body.get("max_hops").and_then(Value::as_i64) != Some(2) {
        return Err(invalid("transit policy must cap the fixture at two hops"));
    }
    let scarcity_policies = policy_body
        .get("admission")
        .and_then(|a| a.get("scarcityPolicies"))
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("transit policy admission has no scarcityPolicies"))?;
    if scarcity_policies.len() != 1 {
        return Err(invalid("transit policy must carry one scarcity policy fixture"));
    }
    let scarcity = &scarcity_policies[0];
    if str_field(scarcity, "schema") != Some("chio.pheromone-scarcity-policy.v1") {
        return Err(invalid("scarcity policy fixture has wrong schema"));
    }
    if scarcity.get("newcomerHorizonEpochs").and_then(Value::as_i64) != Some(8) {
        return Err(invalid(
            "scarcity policy fixture must preserve the eight-epoch default",
        ));
    }
    for field in ["runtimePolicySha256", "policySha256"] {
        if !is_canonical_sha256(str_field(scarcity, field)) {
            return Err(invalid(&format!(
                "scarcity policy fixture missing canonical {field}"
            )));
        }
    }
    if scarcity.get("activePeersEpoch") != scarcity.get("reputationEpoch") {
        return Err(invalid(
            "scarcity policy fixture must carry explicit active peer epoch",
        ));
    }
    if str_field(scarcity, "observationCostVerification") != Some("required") {
        return Err(invalid(
            "scarcity policy fixture must require verified cost commitments",
        ));
    }
    if str_field(scarcity, "verifierId") != str_field(statement, "verifierId") {
        return Err(invalid(
            "scarcity policy verifier must bind the cost commitment verifier",
        ));
    }
    if str_field(scarcity, "policySha256") != str_field(statement, "scarcityPolicySha256") {
        return Err(invalid(
            "scarcity policy hash must bind the cost commitment statement",
        ));
    }
    if str_field(scarcity, "runtimePolicySha256") != str_field(statement, "runtimePolicySha256") {
        return Err(invalid(
            "runtime policy hash must bind the cost commitment statement",
        ));
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
    // The runtime policy admission must bind the verifier-owned recipient and
    // authenticated sender, carry admitted passport material, and pin exactly one
    // scarcity policy with the canonical runtime/scarcity hashes.
    let admission = policy_envelope
        .get("body")
        .and_then(|b| b.get("admission"))
        .ok_or_else(|| invalid("runtime policy body has no admission"))?;
    if str_field(admission, "recipientKernelId") != Some("did:chio:dataco") {
        return Err(invalid("runtime policy recipient is not verifier-owned"));
    }
    if str_field(admission, "authenticatedSenderKernelId") != Some("did:chio:buyer-kernel") {
        return Err(invalid("runtime policy authenticated sender is not verifier-owned"));
    }
    if admission
        .get("passports")
        .and_then(Value::as_array)
        .map(|p| p.is_empty())
        .unwrap_or(true)
    {
        return Err(invalid("runtime policy must carry admitted passport material"));
    }
    let scarcity_policies = admission
        .get("scarcityPolicies")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("runtime policy admission has no scarcityPolicies"))?;
    if scarcity_policies.len() != 1 {
        return Err(invalid(
            "runtime policy must carry explicit scarcity policy material",
        ));
    }
    let scarcity = &scarcity_policies[0];
    if str_field(scarcity, "schema") != Some("chio.pheromone-scarcity-policy.v1") {
        return Err(invalid("runtime scarcity policy schema mismatch"));
    }
    if scarcity.get("newcomerHorizonEpochs").and_then(Value::as_i64) != Some(8) {
        return Err(invalid(
            "runtime scarcity policy default horizon is not explicit",
        ));
    }
    for field in ["runtimePolicySha256", "policySha256"] {
        if !is_canonical_sha256(str_field(scarcity, field)) {
            return Err(invalid(&format!(
                "runtime scarcity policy missing canonical {field}"
            )));
        }
    }
    if scarcity.get("activePeersEpoch") != scarcity.get("reputationEpoch") {
        return Err(invalid(
            "runtime scarcity policy active peer epoch must be explicit",
        ));
    }
    if str_field(&receive, "schema") != Some("chio.pheromone.receive-report.v1")
        || receive.get("accepted") != Some(&Value::Bool(true))
    {
        return Err(invalid("committed receive report must be accepted"));
    }
    if str_field(&receive, "batchOutcome") != Some("accepted") {
        return Err(invalid("committed receive report must carry accepted batch outcome"));
    }
    if receive.get("acceptedFrameCount").and_then(Value::as_i64) != Some(1)
        || receive.get("rejectedFrameCount").and_then(Value::as_i64) != Some(0)
    {
        return Err(invalid("committed receive report must carry frame outcome counts"));
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
    // The routing profile must declare the notification_route label and carry no
    // dynamic URL targets or inline secret material in its routes.
    let profile = load_json(&fixture_dir.join("relay-alert-routing-profile.json"))?;
    let declares_notification_route = profile
        .get("allowedLabelNames")
        .and_then(Value::as_array)
        .map(|names| names.iter().any(|n| n.as_str() == Some("notification_route")))
        .unwrap_or(false);
    if !declares_notification_route {
        return Err(invalid("routing profile does not declare notification_route label"));
    }
    if let Some(routes) = profile.get("routes").and_then(Value::as_array) {
        for route in routes {
            if str_field(route, "targetRef")
                .map(|t| t.contains("://"))
                .unwrap_or(false)
            {
                return Err(invalid("routing profile contains dynamic URL target"));
            }
            if json_contains_secret_marker(route) {
                return Err(invalid(
                    "routing profile route may contain inline secret material",
                ));
            }
        }
    }

    let alert_report = load_json(&fixture_dir.join("relay-alert-report.json"))?;
    if alert_report.get("accepted") != Some(&Value::Bool(false))
        || str_field(&alert_report, "code") != Some("alerts_firing")
    {
        return Err(invalid("degraded alert report must remain firing"));
    }
    let alerts = alert_report
        .get("alerts")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("degraded alert report has no alerts array"))?;
    // The critical dead-letter alert must remain visible (firing/critical) and the
    // stale-lease alert must exercise capped suppression.
    let dead_letter = alerts
        .iter()
        .find(|a| str_field(a, "code") == Some("dead_letters_present"));
    match dead_letter {
        Some(alert)
            if str_field(alert, "state") == Some("firing")
                && str_field(alert, "severity") == Some("critical") => {}
        _ => return Err(invalid("critical dead-letter alert must remain visible")),
    }
    let stale_lease = alerts
        .iter()
        .find(|a| str_field(a, "code") == Some("stale_leases_present"));
    match stale_lease {
        Some(alert) if str_field(alert, "state") == Some("suppressed") => {}
        _ => return Err(invalid("stale lease alert should exercise capped suppression")),
    }
    // No alert may carry a label outside the bounded set, nor a value that leaks
    // unbounded identifiers (DIDs, treaties, long hex, nonces, cursors, outboxes).
    let allowed_labels = ["notification_route", "opsgenie", "service", "severity"];
    for alert in alerts {
        if let Some(labels) = alert.get("labels").and_then(Value::as_object) {
            for name in labels.keys() {
                if !allowed_labels.contains(&name.as_str()) {
                    return Err(invalid(&format!(
                        "alert has unbounded label: {name}"
                    )));
                }
            }
            for value in labels.values() {
                if let Some(text) = value.as_str() {
                    if value_leaks_unbounded_label(text) {
                        return Err(invalid("alert leaks unbounded label value"));
                    }
                }
            }
        }
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
/// and a `cmp` of the five fixtures against the checked package copies.
fn handle_transit(root: &Path, facet: &Facet, mode: Mode) -> Result<(), XtaskError> {
    run_cargo_tests(root, facet)?;
    if mode == Mode::NegativeOnly {
        return Ok(());
    }
    let scratch = ScratchDir::new("transit")?;
    let out_dir = scratch.join("pheromone");
    let out_arg = display(&out_dir);
    let proof_package = root
        .join("examples/chio-3vendor/fixtures")
        .join("buyer-auditor-proof-package.json");
    let proof_package_arg = display(&proof_package);
    require_cli(
        root,
        &[
            "-p",
            "chio-three-vendor-example",
            "--bin",
            "generate-chio-three-vendor-fixtures",
            "--",
            "--pheromone-package",
            &proof_package_arg,
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
/// fixtures from the checked package and the receive/query CLI orchestration, then recurse into
/// `transit` (full).
fn handle_runtime(
    root: &Path,
    manifest: &Manifest,
    facet: &Facet,
    mode: Mode,
) -> Result<(), XtaskError> {
    if mode == Mode::NegativeOnly {
        // Negative-only runs the targeted rejection tests, not the full suite,
        // then the CLI receive/query orchestration and its replay /
        // wrong-recipient CLI negatives. The original shell gate's `negative-only`
        // branch exited after the rejection tests, but its trailing
        // `if negative-only: exit 0` (placed AFTER the replay / wrong-recipient
        // negatives) shows those CLI negatives were intended to be part of the
        // negative path; restore them here rather than skip them.
        for tail in RUNTIME_NEGATIVE_TESTS {
            run_cargo_test(root, &to_owned(tail))?;
        }
        let scratch = ScratchDir::new("runtime-negative")?;
        let fixture_dir = root.join(&facet.fixture_dir);
        return runtime_receive_query_flow(root, &fixture_dir, &scratch);
    }
    run_cargo_tests(root, facet)?;

    let scratch = ScratchDir::new("runtime")?;
    let out_dir = scratch.join("pheromone");
    let out_arg = display(&out_dir);
    let proof_package = root
        .join("examples/chio-3vendor/fixtures")
        .join("buyer-auditor-proof-package.json");
    let proof_package_arg = display(&proof_package);
    require_cli(
        root,
        &[
            "-p",
            "chio-three-vendor-example",
            "--bin",
            "generate-chio-three-vendor-fixtures",
            "--",
            "--pheromone-package",
            &proof_package_arg,
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

    // The CLI receive -> query persisted-state flow and its replay /
    // wrong-recipient negatives.
    runtime_receive_query_flow(root, &fixture_dir, &scratch)?;

    run_recursion(root, manifest, facet)
}

/// Port of the `check-chio-pheromone-runtime.sh` CLI flow: receive the committed
/// gossip batch into a fresh store, query the store and verify the persisted
/// passport history is reflected in the concentration ratio, then confirm the
/// replayed-nonce and wrong-recipient batches are rejected with the expected
/// per-frame codes.
fn runtime_receive_query_flow(
    root: &Path,
    fixture_dir: &Path,
    scratch: &ScratchDir,
) -> Result<(), XtaskError> {
    let root_fixtures = root.join("examples/chio-3vendor/fixtures");
    let transit_policy = fixture_dir.join("transit-policy.json");
    let proof_package = root_fixtures.join("buyer-auditor-proof-package.json");
    let trust_bundle = root_fixtures.join("verifier-trust-bundle.json");
    let context = root_fixtures.join("verification-context.json");
    let gossip_batch = fixture_dir.join("gossip-batch.json");
    let peer_weights = fixture_dir.join("peer-weights.json");

    let store = scratch.join("runtime.sqlite3");
    let receive_report = scratch.join("receive-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "receive",
            "--batch", &display(&gossip_batch),
            "--transit-policy", &display(&transit_policy),
            "--proof-package", &display(&proof_package),
            "--trust-bundle", &display(&trust_bundle),
            "--context", &display(&context),
            "--store", &display(&store),
            "--report", &display(&receive_report),
        ],
    )?;
    runtime_assert_receive(&receive_report)?;

    let query_report = scratch.join("query-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "query",
            "--store", &display(&store),
            "--subject-class", "support.prompt_injection",
            "--namespace", "dev.chio.support",
            "--reputation-epoch", "42",
            "--peer-weights", &display(&peer_weights),
            "--report", &display(&query_report),
        ],
    )?;
    runtime_assert_query_persisted(&query_report, &transit_policy, &peer_weights)?;

    // Negative: re-receiving the same batch into the same store must be rejected
    // with replay_window_exceeded.
    let replay_report = scratch.join("replay-report.json");
    reject_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "receive",
            "--batch", &display(&gossip_batch),
            "--transit-policy", &display(&transit_policy),
            "--proof-package", &display(&proof_package),
            "--trust-bundle", &display(&trust_bundle),
            "--context", &display(&context),
            "--store", &display(&store),
            "--report", &display(&replay_report),
        ],
        "replayed nonce was accepted",
    )?;
    runtime_assert_frame_code(&replay_report, "replay_window_exceeded")?;

    // Negative: a batch addressed to the wrong recipient must be rejected with
    // batch_recipient_mismatch.
    let wrong_batch = scratch.join("wrong-recipient-batch.json");
    let mut batch = load_json(&gossip_batch)?;
    set_str(&mut batch, "recipient_kernel_id", "did:chio:wrong-recipient");
    write_json(&wrong_batch, &batch)?;
    let wrong_store = scratch.join("wrong-recipient.sqlite3");
    let wrong_report = scratch.join("wrong-recipient-report.json");
    reject_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "receive",
            "--batch", &display(&wrong_batch),
            "--transit-policy", &display(&transit_policy),
            "--proof-package", &display(&proof_package),
            "--trust-bundle", &display(&trust_bundle),
            "--context", &display(&context),
            "--store", &display(&wrong_store),
            "--report", &display(&wrong_report),
        ],
        "wrong recipient batch was accepted",
    )?;
    runtime_assert_frame_code(&wrong_report, "batch_recipient_mismatch")
}

/// Assert the CLI receive report accepted the fixture with the expected batch
/// outcome and frame counts.
fn runtime_assert_receive(report: &Path) -> Result<(), XtaskError> {
    let value = load_json(report)?;
    if value.get("accepted") != Some(&Value::Bool(true)) {
        return Err(invalid("CLI receive did not accept the fixture"));
    }
    if str_field(&value, "batchOutcome") != Some("accepted") {
        return Err(invalid("CLI receive report did not carry accepted batch outcome"));
    }
    if value.get("acceptedFrameCount").and_then(Value::as_i64) != Some(1)
        || value.get("rejectedFrameCount").and_then(Value::as_i64) != Some(0)
    {
        return Err(invalid("CLI receive report did not carry frame outcome counts"));
    }
    Ok(())
}

/// Assert the CLI query accepted the stored fixture and that its concentration
/// ratio reflects the persisted passport history (the newcomer discount derived
/// from the policy passport's firstSeenEpoch and the scarcity horizon). A query
/// that read persisted admission state reproduces `weight * discount`; a query
/// over an empty store could not.
fn runtime_assert_query_persisted(
    query_report: &Path,
    transit_policy: &Path,
    peer_weights: &Path,
) -> Result<(), XtaskError> {
    let report = load_json(query_report)?;
    if report.get("accepted") != Some(&Value::Bool(true)) {
        return Err(invalid("CLI query did not accept the stored fixture"));
    }
    let concentration = report
        .get("concentration")
        .ok_or_else(|| invalid("CLI query report has no concentration"))?;
    let total = concentration
        .get("total_strength")
        .and_then(Value::as_f64)
        .ok_or_else(|| invalid("CLI query report concentration has no usable total_strength"))?;
    let unweighted = concentration
        .get("unweighted_total_strength")
        .and_then(Value::as_f64)
        .ok_or_else(|| {
            invalid("CLI query report concentration has no usable unweighted_total_strength")
        })?;

    // When the persisted history yields strength, the weighted/unweighted ratio
    // must equal the policy weight scaled by the newcomer discount; this is only
    // reproducible if the query read the receive-persisted passport admission.
    if unweighted > 0.0 {
        let policy = load_json(transit_policy)?;
        let admission = policy
            .get("body")
            .and_then(|b| b.get("admission"))
            .ok_or_else(|| invalid("transit policy body has no admission"))?;
        let passport = admission
            .get("passports")
            .and_then(Value::as_array)
            .and_then(|p| p.first())
            .ok_or_else(|| invalid("transit policy admission has no passports"))?;
        let first_seen = passport
            .get("firstSeenEpoch")
            .and_then(Value::as_i64)
            .ok_or_else(|| invalid("passport has no firstSeenEpoch"))?;
        let horizon = admission
            .get("scarcityPolicies")
            .and_then(Value::as_array)
            .and_then(|p| p.first())
            .and_then(|p| p.get("newcomerHorizonEpochs"))
            .and_then(Value::as_i64)
            .unwrap_or(8);
        let weights = load_json(peer_weights)?;
        let epoch = weights
            .get("reputationEpoch")
            .and_then(Value::as_i64)
            .ok_or_else(|| invalid("peer weights has no reputationEpoch"))?;
        let weight = weights
            .get("weights")
            .and_then(Value::as_array)
            .and_then(|w| w.first())
            .and_then(|w| w.get("weight"))
            .and_then(Value::as_f64)
            .ok_or_else(|| invalid("peer weights has no first weight"))?;
        let discount = (((epoch - first_seen + 1) as f64) / (horizon as f64)).min(1.0);
        let expected_ratio = weight * discount;
        let actual_ratio = total / unweighted;
        if (actual_ratio - expected_ratio).abs() > 0.000_001 {
            return Err(invalid(&format!(
                "CLI query ratio {actual_ratio} did not use persisted passport history {expected_ratio}"
            )));
        }
    }
    Ok(())
}

/// Assert a rejected receive report carries the expected per-frame failure code.
fn runtime_assert_frame_code(report: &Path, expected: &str) -> Result<(), XtaskError> {
    let value = load_json(report)?;
    let present = value
        .get("frames")
        .and_then(Value::as_array)
        .map(|frames| {
            frames
                .iter()
                .any(|frame| frame.get("code").and_then(Value::as_str) == Some(expected))
        })
        .unwrap_or(false);
    if present {
        Ok(())
    } else {
        Err(invalid(&format!("receive report missing frame code {expected}")))
    }
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
/// variant, and the signed auditor transit policy. The policy is then signed by
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
/// policy hashes by dropping the hash fields, canonicalizing with sorted keys
/// and tight separators, then hashing with sha256.
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
    // The lint (local-dev + production) and tick CLI orchestration, including
    // the production `relay_profile_denied` assertion, runs in both `all` and
    // `negative-only`.
    relay_ops_lint_orchestration(root, facet)?;
    run_cargo_tests(root, facet)?;
    relay_ops_tick(root, facet)?;
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

/// The relay-ops `pheromone relay lint` flow: lint the committed peer directory
/// under local-dev and under production, asserting the production profile
/// rejects the raw directory with `relay_profile_denied`.
fn relay_ops_lint_orchestration(root: &Path, facet: &Facet) -> Result<(), XtaskError> {
    let scratch = ScratchDir::new("relay-ops-lint")?;
    let fixture_dir = root.join(&facet.fixture_dir);
    let schema_dir = root.join("spec/schemas/chio-pheromone/v1");
    let peer_directory = fixture_dir.join("peer-directory.json");

    let lint = scratch.join("lint.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "lint",
            "--peer-directory", &display(&peer_directory),
            "--profile", "local-dev",
            "--report", &display(&lint),
        ],
    )?;
    validate_document(&schema_dir.join("relay-health-report.schema.json"), &lint)?;

    let lint_production = scratch.join("lint-production.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "lint",
            "--peer-directory", &display(&peer_directory),
            "--profile", "production",
            "--report", &display(&lint_production),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-health-report.schema.json"),
        &lint_production,
    )?;
    let production = load_json(&lint_production)?;
    if production.get("accepted") != Some(&Value::Bool(false))
        || str_field(&production, "code") != Some("relay_profile_denied")
    {
        return Err(invalid("production lint did not reject raw peer directory"));
    }
    Ok(())
}

/// The relay-ops `pheromone relay tick` step: tick the leased batches against the
/// committed peer directory, validating the emitted tick report.
fn relay_ops_tick(root: &Path, facet: &Facet) -> Result<(), XtaskError> {
    let scratch = ScratchDir::new("relay-ops-tick")?;
    let fixture_dir = root.join(&facet.fixture_dir);
    let schema_dir = root.join("spec/schemas/chio-pheromone/v1");
    let peer_directory = fixture_dir.join("peer-directory.json");

    let signing_key = scratch.join("relay-signing-key.json");
    write_signing_key(&signing_key)?;
    let store = scratch.join("relay.sqlite3");
    let tick = scratch.join("tick.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "tick",
            "--store", &display(&store),
            "--peer-directory", &display(&peer_directory),
            "--now-unix-ms", "1766000000500",
            "--max-batches", "4",
            "--signing-key", &display(&signing_key),
            "--report", &display(&tick),
        ],
    )?;
    validate_document(&schema_dir.join("relay-tick-report.schema.json"), &tick)
}

fn handle_directory_lifecycle(
    root: &Path,
    manifest: &Manifest,
    facet: &Facet,
    mode: Mode,
) -> Result<(), XtaskError> {
    run_cargo_tests(root, facet)?;
    // The inspect/promote/lint orchestration (with its rollback, version-floor,
    // and removed-peer negatives) runs in both `all` and `negative-only`, since
    // the negatives are part of it. Only `all` performs the relay-ops recursion.
    directory_lifecycle_orchestration(root, facet)?;
    if mode == Mode::NegativeOnly {
        return Ok(());
    }
    run_recursion(root, manifest, facet)
}

/// Port of the `check-chio-pheromone-directory-lifecycle.sh` CLI flow: inspect
/// active state, promote a first candidate, reject a rolled-back candidate,
/// promote the proper candidate (asserting the version-2 floor and the
/// quarantined removed peer), lint the promoted state and the supervisor
/// profile, and confirm a removed peer cannot catch up.
fn directory_lifecycle_orchestration(root: &Path, facet: &Facet) -> Result<(), XtaskError> {
    let scratch = ScratchDir::new("directory-lifecycle")?;
    let fixture_dir = root.join(&facet.fixture_dir);
    let schema_dir = root.join("spec/schemas/chio-pheromone/v1");

    let state_fixture = fixture_dir.join("peer-directory-state.json");
    let bundle = fixture_dir.join("peer-directory-bundle.json");
    let candidate = fixture_dir.join("peer-directory-candidate.json");
    let trusted_issuers = fixture_dir.join("trusted-peer-directory-issuers.json");
    let supervisor_profile = fixture_dir.join("relay-supervisor-profile.json");

    // Inspect the committed active state.
    let inspect_report = scratch.join("inspect-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "directory", "inspect",
            "--state", &display(&state_fixture),
            "--report", &display(&inspect_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("peer-directory-rotation-report.schema.json"),
        &inspect_report,
    )?;

    // First promotion: the bundle candidate into a fresh working state file.
    let working_state = scratch.join("peer-directory-state.json");
    let first_report = scratch.join("first-rotation-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "directory", "promote",
            "--state", &display(&working_state),
            "--candidate", &display(&bundle),
            "--trusted-issuers", &display(&trusted_issuers),
            "--profile", "production",
            "--now-unix-ms", "1766000000500",
            "--report", &display(&first_report),
        ],
    )?;
    validate_document(&schema_dir.join("peer-directory-state.schema.json"), &working_state)?;
    validate_document(
        &schema_dir.join("peer-directory-rotation-report.schema.json"),
        &first_report,
    )?;

    // Negative: a candidate whose previousVersionSha256 is wrong must be
    // rejected with peer_directory_rollback.
    let bad_candidate = scratch.join("bad-candidate.json");
    let mut candidate_value = load_json(&candidate)?;
    if let Some(body) = candidate_value.get_mut("body") {
        set_str(body, "previousVersionSha256", &"d".repeat(64));
    } else {
        return Err(invalid("peer-directory candidate has no body to mutate"));
    }
    write_json(&bad_candidate, &candidate_value)?;
    let rejected_report = scratch.join("rejected-rotation-report.json");
    reject_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "directory", "promote",
            "--state", &display(&working_state),
            "--candidate", &display(&bad_candidate),
            "--trusted-issuers", &display(&trusted_issuers),
            "--profile", "production",
            "--now-unix-ms", "1766000000500",
            "--report", &display(&rejected_report),
        ],
        "bad peer-directory candidate was unexpectedly promoted",
    )?;
    validate_document(&schema_dir.join("peer-directory-state.schema.json"), &working_state)?;
    validate_document(
        &schema_dir.join("peer-directory-rotation-report.schema.json"),
        &rejected_report,
    )?;
    let rejected = load_json(&rejected_report)?;
    if rejected.get("accepted") != Some(&Value::Bool(false))
        || str_field(&rejected, "code") != Some("peer_directory_rollback")
    {
        return Err(invalid("bad candidate did not fail with peer_directory_rollback"));
    }

    // Second promotion: the proper candidate, advancing to the version-2 floor.
    let second_report = scratch.join("second-rotation-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "directory", "promote",
            "--state", &display(&working_state),
            "--candidate", &display(&candidate),
            "--trusted-issuers", &display(&trusted_issuers),
            "--profile", "production",
            "--now-unix-ms", "1766000000500",
            "--report", &display(&second_report),
        ],
    )?;
    validate_document(&schema_dir.join("peer-directory-state.schema.json"), &working_state)?;
    validate_document(
        &schema_dir.join("peer-directory-rotation-report.schema.json"),
        &second_report,
    )?;
    directory_assert_promoted(&working_state, &second_report)?;

    // Lint the promoted state.
    let lint_state = scratch.join("lint-state.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "lint",
            "--peer-directory-state", &display(&working_state),
            "--profile", "production",
            "--trusted-issuers", &display(&trusted_issuers),
            "--report", &display(&lint_state),
        ],
    )?;
    validate_document(&schema_dir.join("relay-health-report.schema.json"), &lint_state)?;

    // Lint the supervisor profile.
    let supervisor_report = scratch.join("supervisor-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "supervisor", "lint",
            "--profile", &display(&supervisor_profile),
            "--report", &display(&supervisor_report),
        ],
    )?;
    validate_document(&schema_dir.join("relay-drill-report.schema.json"), &supervisor_report)?;

    // Negative: the quarantined buyer peer must not be able to catch up.
    let removed_catchup = scratch.join("removed-peer-catchup.json");
    let store = scratch.join("relay.sqlite3");
    reject_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "catchup",
            "--store", &display(&store),
            "--peer", "did:chio:buyer-kernel",
            "--peer-directory-state", &display(&working_state),
            "--profile", "production",
            "--trusted-issuers", &display(&trusted_issuers),
            "--now-unix-ms", "1766000000500",
            "--treaty", "treaty:buyer-dataco:support-ops",
            "--after-cursor", "start",
            "--limit", "1",
            "--report", &display(&removed_catchup),
        ],
        "removed peer catch-up unexpectedly succeeded",
    )?;
    Ok(())
}

/// Assert the second promotion advanced to the version-2 floor, was accepted,
/// and quarantined the removed buyer peer (the script's final python block).
fn directory_assert_promoted(state: &Path, report: &Path) -> Result<(), XtaskError> {
    let state_value = load_json(state)?;
    let report_value = load_json(report)?;
    let version_floor = state_value.get("versionFloor").and_then(Value::as_i64);
    let active_version = state_value
        .get("active")
        .and_then(|a| a.get("version"))
        .and_then(Value::as_i64);
    if version_floor != Some(2) || active_version != Some(2) {
        return Err(invalid("promoted state did not advance to version 2"));
    }
    if report_value.get("accepted") != Some(&Value::Bool(true))
        || report_value.get("promotedVersion").and_then(Value::as_i64) != Some(2)
    {
        return Err(invalid("second promotion report was not accepted"));
    }
    let quarantined = state_value
        .get("active")
        .and_then(|a| a.get("removedPeerIds"))
        .and_then(Value::as_array)
        .map(|ids| ids.iter().any(|id| id.as_str() == Some("did:chio:buyer-kernel")))
        .unwrap_or(false);
    if !quarantined {
        return Err(invalid("removed peer was not quarantined"));
    }
    Ok(())
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
        // Parity with the script's `--negative-only` tail: the degraded
        // observability fixture must carry the dead-letter and stale-lease
        // recommendations before the gate exits.
        return observability_assert_degraded_recommendations(&root.join(&facet.fixture_dir));
    }
    run_recursion(root, manifest, facet)
}

/// Assert the degraded relay observability fixture carries the
/// `dead_letters_present` and `stale_leases_present` recommendations.
fn observability_assert_degraded_recommendations(fixture_dir: &Path) -> Result<(), XtaskError> {
    let report = load_json(&fixture_dir.join("relay-observability-degraded-report.json"))?;
    let codes: std::collections::BTreeSet<&str> = report
        .get("recommendations")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("code").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    for required in ["dead_letters_present", "stale_leases_present"] {
        if !codes.contains(required) {
            return Err(invalid(&format!(
                "degraded relay observability fixture missing recommendation {required}"
            )));
        }
    }
    Ok(())
}

/// The export/archive/archive-package chain: each facet's artifact
/// create-and-verify CLI orchestration (with the negatives the script drove),
/// then the cargo tests, then (mode == All) recurse one level up the chain
/// (`--schema-only`). The orchestration + negatives run in both `all` and
/// `negative-only`; only `all` recurses.
fn handle_archive_chain(
    root: &Path,
    manifest: &Manifest,
    facet: &Facet,
    mode: Mode,
) -> Result<(), XtaskError> {
    match facet.name.as_str() {
        "relay-alert-assurance-export" => assurance_export_orchestration(root, facet)?,
        "relay-alert-assurance-archive" => assurance_archive_orchestration(root, facet)?,
        "relay-alert-assurance-archive-package" => {
            assurance_archive_package_orchestration(root, facet)?
        }
        other => {
            return Err(invalid(&format!(
                "archive chain has no orchestration for facet {other}"
            )));
        }
    }
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
