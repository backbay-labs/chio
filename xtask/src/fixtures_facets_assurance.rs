// Assurance artifact create-and-verify CLI orchestration for the
// export / archive / archive-package facets, mirroring
// `scripts/check-chio-pheromone-relay-alert-assurance-{export,archive,archive-package}.sh`.
// Included into `fixtures.rs` via `include!` so it shares
// that module's private helpers.
//
// Each flow drives the real `chio pheromone relay alert assurance ...` CLI to
// produce signed bundles / packages from the committed fixtures, validates the
// emitted artifacts against their schemas, asserts the report contents the
// script's python block asserted, and exercises the JSON-mutation negatives the
// script drove (untrusted exporter / packager, tampered bundle, dynamic handoff
// URL). The tar-membership negatives (path traversal, symlink, hardlink,
// casefold collision, ...) remain covered by the `alert_assurance_archive_package`
// integration suite the manifest runs and by the negative-corpus metadata
// assertion; they are not rebuilt here.

/// The export/archive/package scripts all anchor at this evaluation time.
const ASSURANCE_ARTIFACT_NOW_UNIX_MS: &str = "1766000100000";

/// Run `chio pheromone relay alert assurance export` from the committed
/// assurance fixtures into a fresh bundle directory. Shared by the export,
/// archive, and archive-package flows (each starts by producing a bundle).
fn assurance_run_export(
    root: &Path,
    assurance_dir: &Path,
    out_bundle: &Path,
    report: &Path,
) -> Result<(), XtaskError> {
    fs::create_dir_all(out_bundle).map_err(|err| XtaskError::Io(display(out_bundle), err))?;
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "export",
            "--package", &display(&assurance_dir.join("relay-alert-assurance-package.json")),
            "--alert-report", &display(&assurance_dir.join("relay-alert-report.json")),
            "--trend-report", &display(&assurance_dir.join("relay-trend-report.json")),
            "--handoff-report", &display(&assurance_dir.join("relay-alert-handoff-report.json")),
            "--normalization-report",
            &display(&assurance_dir.join("relay-alert-normalization-report.json")),
            "--delivery-report", &display(&assurance_dir.join("relay-alert-delivery-report.json")),
            "--acknowledgement-report",
            &display(&assurance_dir.join("relay-alert-acknowledgement-report.json")),
            "--drift-report",
            &display(&assurance_dir.join("relay-alert-delivery-drift-report.json")),
            "--review-packet",
            &display(&assurance_dir.join("relay-alert-route-review-packet.json")),
            "--retention-profile",
            &display(&assurance_dir.join("relay-alert-assurance-retention-profile.json")),
            "--signing-key",
            &display(&assurance_dir.join("relay-alert-assurance-export-signing-key.json")),
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--out-dir", &display(out_bundle),
            "--report", &display(report),
        ],
    )
}

// -- export ----------------------------------------------------------------

/// Port of `check-chio-pheromone-relay-alert-assurance-export.sh`: export a
/// signed bundle, then verify / replay / retention-plan / recovery-drill it,
/// assert the report contents, and exercise the untrusted-exporter and
/// tampered-bundle negatives (which pin signature_invalid / body_hash_mismatch).
fn assurance_export_orchestration(root: &Path, facet: &Facet) -> Result<(), XtaskError> {
    let scratch = ScratchDir::new("assurance-export")?;
    let assurance_dir = root.join(&facet.fixture_dir);
    let schema_dir = root.join("spec/schemas/chio-pheromone/v1");
    let trusted_exporters = assurance_dir.join("relay-alert-assurance-trusted-exporters.json");
    let retention_profile = assurance_dir.join("relay-alert-assurance-retention-profile.json");

    let bundle = scratch.join("export-bundle");
    let export_report = scratch.join("relay-alert-assurance-export-report.json");
    assurance_run_export(root, &assurance_dir, &bundle, &export_report)?;
    validate_document(
        &schema_dir.join("relay-alert-assurance-export-manifest.schema.json"),
        &bundle.join("manifest.json"),
    )?;
    validate_document(
        &schema_dir.join("relay-alert-assurance-export-report.schema.json"),
        &export_report,
    )?;

    let verify_report = scratch.join("relay-alert-assurance-export-verify-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "verify",
            "--bundle-dir", &display(&bundle),
            "--trusted-exporters", &display(&trusted_exporters),
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--report", &display(&verify_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-assurance-export-report.schema.json"),
        &verify_report,
    )?;

    let replay_report = scratch.join("relay-alert-assurance-replay-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "replay",
            "--bundle-dir", &display(&bundle),
            "--trusted-exporters", &display(&trusted_exporters),
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--report", &display(&replay_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-assurance-replay-report.schema.json"),
        &replay_report,
    )?;

    let retention_report = scratch.join("relay-alert-assurance-retention-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "retention", "plan",
            "--bundle-root", &display(&bundle),
            "--retention-profile", &display(&retention_profile),
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--report", &display(&retention_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-assurance-retention-report.schema.json"),
        &retention_report,
    )?;

    let drill_report = scratch.join("relay-alert-assurance-recovery-drill-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "recovery-drill",
            "--bundle-dir", &display(&bundle),
            "--trusted-exporters", &display(&trusted_exporters),
            "--case", "all",
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--report", &display(&drill_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-assurance-recovery-drill-report.schema.json"),
        &drill_report,
    )?;

    assurance_export_assert(&verify_report, &replay_report, &retention_report, &drill_report)?;

    // Negative: an untrusted exporter (mutated public key) must fail with
    // signature_invalid.
    let untrusted_exporters = scratch.join("untrusted-exporters.json");
    assurance_mutate_first_public_key(&trusted_exporters, "exporters", &untrusted_exporters)?;
    let untrusted_report = scratch.join("untrusted-report.json");
    reject_cli_with_marker(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "verify",
            "--bundle-dir", &display(&bundle),
            "--trusted-exporters", &display(&untrusted_exporters),
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--report", &display(&untrusted_report),
        ],
        "signature_invalid",
        "untrusted exporter verify did not fail with signature_invalid",
    )?;

    // Negative: a tampered bundle (a trailing newline appended to a report) must
    // fail with body_hash_mismatch.
    let tampered = scratch.join("tampered-bundle");
    copy_tree(&bundle, &tampered)?;
    let target = tampered.join("reports").join("relay-alert-report.json");
    assurance_append_newline(&target)?;
    let tampered_report = scratch.join("tampered-report.json");
    reject_cli_with_marker(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "verify",
            "--bundle-dir", &display(&tampered),
            "--trusted-exporters", &display(&trusted_exporters),
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--report", &display(&tampered_report),
        ],
        "body_hash_mismatch",
        "tampered bundle verify did not fail with body_hash_mismatch",
    )
}

/// The export script's generated-report assertions: verify accepted; replay
/// reproduces the source package hash; retention blocks pruning the assurance
/// package; the recovery drill exercised the bad-export-signature case.
fn assurance_export_assert(
    verify_report: &Path,
    replay_report: &Path,
    retention_report: &Path,
    drill_report: &Path,
) -> Result<(), XtaskError> {
    let verify = load_json(verify_report)?;
    if verify.get("accepted") != Some(&Value::Bool(true)) {
        return Err(invalid("generated export verify report must be accepted"));
    }
    let replay = load_json(replay_report)?;
    if replay.get("accepted") != Some(&Value::Bool(true))
        || str_field(&replay, "sourcePackageSha256") != str_field(&replay, "replayedPackageSha256")
    {
        return Err(invalid("generated replay report must reproduce source package hash"));
    }
    let retention = load_json(retention_report)?;
    let blocks_package = retention
        .get("entries")
        .and_then(Value::as_array)
        .map(|entries| {
            entries.iter().any(|entry| {
                str_field(entry, "state") == Some("blocked")
                    && str_field(entry, "artifactRole") == Some("assurance_package")
            })
        })
        .unwrap_or(false);
    if !blocks_package {
        return Err(invalid("retention report must block assurance package pruning"));
    }
    let drill = load_json(drill_report)?;
    let has_bad_signature = drill
        .get("drills")
        .and_then(Value::as_array)
        .map(|drills| {
            drills
                .iter()
                .any(|d| str_field(d, "caseId") == Some("bad_export_signature"))
        })
        .unwrap_or(false);
    if !has_bad_signature {
        return Err(invalid("recovery drill report missing bad export signature case"));
    }
    Ok(())
}

// -- archive ---------------------------------------------------------------

/// Port of `check-chio-pheromone-relay-alert-assurance-archive.sh`: export a
/// bundle, plan its archive lifecycle, review closeout, assert the report
/// contents, and exercise the untrusted-exporter and missing-file archive
/// negatives, pinning their expected codes against the committed expectedCode
/// fixtures.
fn assurance_archive_orchestration(root: &Path, facet: &Facet) -> Result<(), XtaskError> {
    let scratch = ScratchDir::new("assurance-archive")?;
    let assurance_dir = root.join(&facet.fixture_dir);
    let schema_dir = root.join("spec/schemas/chio-pheromone/v1");
    let trusted_exporters = assurance_dir.join("relay-alert-assurance-trusted-exporters.json");
    let archive_profile = assurance_dir.join("relay-alert-assurance-archive-profile.json");
    let closeout_profile = assurance_dir.join("relay-alert-assurance-closeout-profile.json");
    let retention_profile = assurance_dir.join("relay-alert-assurance-retention-profile.json");

    let bundle = scratch.join("export-bundle");
    let export_report = scratch.join("relay-alert-assurance-export-report.json");
    assurance_run_export(root, &assurance_dir, &bundle, &export_report)?;

    let archive_report = scratch.join("relay-alert-assurance-archive-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "archive", "plan",
            "--bundle-root", &display(&bundle),
            "--trusted-exporters", &display(&trusted_exporters),
            "--archive-profile", &display(&archive_profile),
            "--retention-profile", &display(&retention_profile),
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--report", &display(&archive_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-assurance-archive-report.schema.json"),
        &archive_report,
    )?;

    let closeout_report = scratch.join("relay-alert-assurance-closeout-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "closeout", "review",
            "--bundle-root", &display(&bundle),
            "--trusted-exporters", &display(&trusted_exporters),
            "--closeout-profile", &display(&closeout_profile),
            "--retention-profile", &display(&retention_profile),
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--report", &display(&closeout_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-assurance-closeout-report.schema.json"),
        &closeout_report,
    )?;

    assurance_archive_assert(&archive_report, &closeout_report)?;

    // Negative: untrusted exporter archive plan yields signature_invalid.
    let untrusted_exporters = scratch.join("untrusted-exporters.json");
    assurance_mutate_first_public_key(&trusted_exporters, "exporters", &untrusted_exporters)?;
    let untrusted_archive = scratch.join("untrusted-archive-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "archive", "plan",
            "--bundle-root", &display(&bundle),
            "--trusted-exporters", &display(&untrusted_exporters),
            "--archive-profile", &display(&archive_profile),
            "--retention-profile", &display(&retention_profile),
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--report", &display(&untrusted_archive),
        ],
    )?;

    // Negative: a bundle missing a report yields bundle_read_failed.
    let missing_bundle = scratch.join("missing-file-bundle");
    copy_tree(&bundle, &missing_bundle)?;
    let removed = missing_bundle.join("reports").join("relay-alert-report.json");
    fs::remove_file(&removed).map_err(|err| XtaskError::Io(display(&removed), err))?;
    let missing_archive = scratch.join("missing-file-archive-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "archive", "plan",
            "--bundle-root", &display(&missing_bundle),
            "--trusted-exporters", &display(&trusted_exporters),
            "--archive-profile", &display(&archive_profile),
            "--retention-profile", &display(&retention_profile),
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--report", &display(&missing_archive),
        ],
    )?;

    assurance_archive_negative_codes(&untrusted_archive, &missing_archive, &closeout_report)
}

/// The archive script's generated-report assertions: archive accepted with one
/// ready bundle whose trusted exporter is verified; closeout blocked by the
/// legal hold.
fn assurance_archive_assert(
    archive_report: &Path,
    closeout_report: &Path,
) -> Result<(), XtaskError> {
    let archive = load_json(archive_report)?;
    if archive.get("accepted") != Some(&Value::Bool(true))
        || archive.get("archiveReadyCount").and_then(Value::as_i64) != Some(1)
    {
        return Err(invalid("archive report must accept the verified export bundle"));
    }
    let exporter_verified = archive
        .get("reviews")
        .and_then(Value::as_array)
        .and_then(|reviews| reviews.first())
        .and_then(|review| review.get("trustedExporterVerified"))
        == Some(&Value::Bool(true));
    if !exporter_verified {
        return Err(invalid(
            "archive report must verify trusted exporter before retention claims",
        ));
    }
    let closeout = load_json(closeout_report)?;
    if closeout.get("accepted") != Some(&Value::Bool(false)) {
        return Err(invalid("closeout report must remain blocked while legal hold is present"));
    }
    if first_review_code(&closeout) != Some("legal_hold_blocked".to_string()) {
        return Err(invalid("closeout report must expose legal hold blocker"));
    }
    Ok(())
}

/// The archive script's negative-case codes: the untrusted-exporter,
/// missing-file, and legal-hold reviews must carry the expected first-review
/// codes (and the wrong-expected-code detector must not collapse them).
fn assurance_archive_negative_codes(
    untrusted: &Path,
    missing: &Path,
    closeout: &Path,
) -> Result<(), XtaskError> {
    let untrusted_code = first_review_code(&load_json(untrusted)?);
    let missing_code = first_review_code(&load_json(missing)?);
    let closeout_code = first_review_code(&load_json(closeout)?);
    if untrusted_code.as_deref() != Some("signature_invalid") {
        return Err(invalid(&format!(
            "untrusted_exporter expected signature_invalid, got {untrusted_code:?}"
        )));
    }
    if missing_code.as_deref() != Some("bundle_read_failed") {
        return Err(invalid(&format!(
            "missing_file expected bundle_read_failed, got {missing_code:?}"
        )));
    }
    if closeout_code.as_deref() != Some("legal_hold_blocked") {
        return Err(invalid(&format!(
            "legal_hold_closeout expected legal_hold_blocked, got {closeout_code:?}"
        )));
    }
    if untrusted_code.as_deref() == Some("body_hash_mismatch") {
        return Err(invalid("wrong expected code detector did not trip"));
    }
    Ok(())
}

// -- archive-package -------------------------------------------------------

/// Port of `check-chio-pheromone-relay-alert-assurance-archive-package.sh`:
/// export a bundle, plan archive + closeout (with the legal hold relaxed),
/// create a signed archive package, verify and extract it, build the physical-
/// archive and retention-handoff evidence the script derives, review both, and
/// exercise the untrusted-packager and dynamic-retention-handoff-URL negatives.
/// The tar-membership negatives remain covered by the integration suite.
fn assurance_archive_package_orchestration(root: &Path, facet: &Facet) -> Result<(), XtaskError> {
    let scratch = ScratchDir::new("assurance-archive-package")?;
    let assurance_dir = root.join(&facet.fixture_dir);
    let schema_dir = root.join("spec/schemas/chio-pheromone/v1");
    let trusted_exporters = assurance_dir.join("relay-alert-assurance-trusted-exporters.json");
    let trusted_packagers = assurance_dir.join("relay-alert-assurance-trusted-archive-packagers.json");
    let archive_profile = assurance_dir.join("relay-alert-assurance-archive-profile.json");
    let retention_profile = assurance_dir.join("relay-alert-assurance-retention-profile.json");
    let signing_key = assurance_dir.join("relay-alert-assurance-export-signing-key.json");
    let handoff_profile = assurance_dir.join("relay-alert-assurance-retention-handoff-profile.json");

    // The script relaxes the legal hold so closeout accepts (a package needs an
    // accepted closeout).
    let closeout_profile = scratch.join("package-closeout-profile.json");
    let mut closeout_value =
        load_json(&assurance_dir.join("relay-alert-assurance-closeout-profile.json"))?;
    set_value(&mut closeout_value, "blockLegalHold", Value::Bool(false));
    write_json(&closeout_profile, &closeout_value)?;

    let bundle = scratch.join("export-bundle");
    let export_report = scratch.join("relay-alert-assurance-export-report.json");
    assurance_run_export(root, &assurance_dir, &bundle, &export_report)?;

    let archive_report = scratch.join("relay-alert-assurance-archive-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "archive", "plan",
            "--bundle-root", &display(&bundle),
            "--trusted-exporters", &display(&trusted_exporters),
            "--archive-profile", &display(&archive_profile),
            "--retention-profile", &display(&retention_profile),
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--report", &display(&archive_report),
        ],
    )?;

    let closeout_report = scratch.join("relay-alert-assurance-closeout-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "closeout", "review",
            "--bundle-root", &display(&bundle),
            "--trusted-exporters", &display(&trusted_exporters),
            "--closeout-profile", &display(&closeout_profile),
            "--retention-profile", &display(&retention_profile),
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--report", &display(&closeout_report),
        ],
    )?;

    let package = scratch.join("relay-alert-assurance-archive-package.tar.gz");
    let package_report = scratch.join("relay-alert-assurance-archive-package-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "archive", "package", "create",
            "--bundle-root", &display(&bundle),
            "--trusted-exporters", &display(&trusted_exporters),
            "--archive-report", &display(&archive_report),
            "--closeout-report", &display(&closeout_report),
            "--signing-key", &display(&signing_key),
            "--package-id", "relay-alert-assurance-archive-package-001",
            "--packager-key-id", "default",
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--out", &display(&package),
            "--report", &display(&package_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-assurance-archive-package-report.schema.json"),
        &package_report,
    )?;

    let verify_report = scratch.join("relay-alert-assurance-archive-package-verify-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "archive", "package", "verify",
            "--package", &display(&package),
            "--trusted-packagers", &display(&trusted_packagers),
            "--trusted-exporters", &display(&trusted_exporters),
            "--archive-report", &display(&archive_report),
            "--closeout-report", &display(&closeout_report),
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--report", &display(&verify_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-assurance-archive-package-report.schema.json"),
        &verify_report,
    )?;

    let extracted = scratch.join("extracted-package");
    let extraction_report = scratch.join("relay-alert-assurance-archive-extraction-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "archive", "package", "extract",
            "--package", &display(&package),
            "--trusted-packagers", &display(&trusted_packagers),
            "--trusted-exporters", &display(&trusted_exporters),
            "--archive-report", &display(&archive_report),
            "--closeout-report", &display(&closeout_report),
            "--out-dir", &display(&extracted),
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--report", &display(&extraction_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-assurance-archive-extraction-report.schema.json"),
        &extraction_report,
    )?;

    assurance_package_assert(&archive_report, &closeout_report, &verify_report, &extraction_report)?;

    // Build the physical-archive and retention-handoff evidence the script
    // derives from the package report, then review both.
    let physical_evidence = scratch.join("relay-alert-assurance-physical-archive-evidence.json");
    let handoff_evidence = scratch.join("relay-alert-assurance-retention-handoff-evidence.json");
    assurance_build_package_evidence(
        &package_report,
        &handoff_profile,
        &physical_evidence,
        &handoff_evidence,
    )?;
    validate_document(
        &schema_dir.join("relay-alert-assurance-physical-archive-evidence.schema.json"),
        &physical_evidence,
    )?;
    validate_document(
        &schema_dir.join("relay-alert-assurance-retention-handoff-evidence.schema.json"),
        &handoff_evidence,
    )?;

    let physical_drill = scratch.join("relay-alert-assurance-physical-archive-drill-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "archive", "physical-drill", "review",
            "--evidence", &display(&physical_evidence),
            "--package-report", &display(&package_report),
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--report", &display(&physical_drill),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-assurance-physical-archive-drill-report.schema.json"),
        &physical_drill,
    )?;

    let handoff_report = scratch.join("relay-alert-assurance-retention-handoff-report.json");
    require_cli(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "retention", "handoff", "review",
            "--evidence", &display(&handoff_evidence),
            "--profile", &display(&handoff_profile),
            "--package-report", &display(&package_report),
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--report", &display(&handoff_report),
        ],
    )?;
    validate_document(
        &schema_dir.join("relay-alert-assurance-retention-handoff-report.schema.json"),
        &handoff_report,
    )?;

    // Negative: an untrusted packager (mutated public key) must fail with
    // signature_invalid.
    let untrusted_packagers = scratch.join("untrusted-packagers.json");
    assurance_mutate_first_public_key(&trusted_packagers, "packagers", &untrusted_packagers)?;
    let untrusted_package_report = scratch.join("untrusted-package-report.json");
    reject_cli_with_marker(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "archive", "package", "verify",
            "--package", &display(&package),
            "--trusted-packagers", &display(&untrusted_packagers),
            "--trusted-exporters", &display(&trusted_exporters),
            "--archive-report", &display(&archive_report),
            "--closeout-report", &display(&closeout_report),
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--report", &display(&untrusted_package_report),
        ],
        "signature_invalid",
        "untrusted packager verify did not fail with signature_invalid",
    )?;

    // Negative: a retention-handoff evidence with a dynamic (URL) target alias
    // must fail with archive_package_invalid.
    let bad_handoff = scratch.join("bad-handoff-evidence.json");
    let mut bad_value = load_json(&handoff_evidence)?;
    set_str(&mut bad_value, "targetSystemAlias", "https://records.example/upload");
    write_json(&bad_handoff, &bad_value)?;
    let bad_handoff_report = scratch.join("bad-handoff-report.json");
    reject_cli_with_marker(
        root,
        &[
            "-p", "chio-cli", "--bin", "chio", "--",
            "pheromone", "relay", "alert", "assurance", "retention", "handoff", "review",
            "--evidence", &display(&bad_handoff),
            "--profile", &display(&handoff_profile),
            "--package-report", &display(&package_report),
            "--now-unix-ms", ASSURANCE_ARTIFACT_NOW_UNIX_MS,
            "--report", &display(&bad_handoff_report),
        ],
        "archive_package_invalid",
        "dynamic retention handoff URL did not fail with archive_package_invalid",
    )
}

/// The archive-package script's generated-report assertions: archive and
/// closeout accepted, package verify accepted with nested exporters verified,
/// extraction accepted.
fn assurance_package_assert(
    archive_report: &Path,
    closeout_report: &Path,
    verify_report: &Path,
    extraction_report: &Path,
) -> Result<(), XtaskError> {
    if load_json(archive_report)?.get("accepted") != Some(&Value::Bool(true)) {
        return Err(invalid("archive report must be accepted"));
    }
    if load_json(closeout_report)?.get("accepted") != Some(&Value::Bool(true)) {
        return Err(invalid("package closeout report must be accepted"));
    }
    let verify = load_json(verify_report)?;
    if verify.get("accepted") != Some(&Value::Bool(true)) {
        return Err(invalid("package verify report must verify nested exporters"));
    }
    // A verified report omits the boolean (skip_serializing_if = is_true); only a
    // present-and-false value signals a nested-exporter verification failure.
    if verify.get("nestedExporterVerified") == Some(&Value::Bool(false)) {
        return Err(invalid("package verify report must verify nested exporters"));
    }
    if load_json(extraction_report)?.get("accepted") != Some(&Value::Bool(true)) {
        return Err(invalid("archive extraction report must be accepted"));
    }
    Ok(())
}

/// Build the physical-archive and retention-handoff evidence the archive-package
/// script derives from the package report (canonical-hash binding the package
/// report, sampled member count, media/target aliases).
fn assurance_build_package_evidence(
    package_report: &Path,
    handoff_profile: &Path,
    physical_out: &Path,
    handoff_out: &Path,
) -> Result<(), XtaskError> {
    let report = load_json(package_report)?;
    let report_hash = canonical_sha256(&report);
    let local_kernel = str_field(&report, "localKernelId")
        .ok_or_else(|| invalid("package report has no localKernelId"))?;
    let package_id = str_field(&report, "packageId")
        .ok_or_else(|| invalid("package report has no packageId"))?;
    let manifest_hash = str_field(&report, "packageManifestSha256")
        .ok_or_else(|| invalid("package report has no packageManifestSha256"))?;
    let member_count = report
        .get("packageMemberCount")
        .and_then(Value::as_i64)
        .unwrap_or(0)
        .max(1);

    let physical = serde_json::json!({
        "schema": "chio.pheromone.relay-alert-assurance-physical-archive-evidence.v1",
        "localKernelId": local_kernel,
        "evidenceId": "physical-archive-evidence-001",
        "packageId": package_id,
        "packageReportSha256": report_hash,
        "packageManifestSha256": manifest_hash,
        "observedAtUnixMs": 1_766_000_100_000_i64,
        "sampledMemberCount": member_count,
        "mediaAlias": "operator_vault_a",
        "claims": ["operator_readback_sampled"],
    });
    write_json(physical_out, &physical)?;

    let profile = load_json(handoff_profile)?;
    let target_alias = profile
        .get("allowedSystemAliases")
        .and_then(Value::as_array)
        .and_then(|aliases| aliases.first())
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("retention handoff profile has no allowedSystemAliases"))?;
    let handoff = serde_json::json!({
        "schema": "chio.pheromone.relay-alert-assurance-retention-handoff-evidence.v1",
        "localKernelId": local_kernel,
        "evidenceId": "retention-handoff-evidence-001",
        "packageId": package_id,
        "packageReportSha256": report_hash,
        "targetSystemAlias": target_alias,
        "observedAtUnixMs": 1_766_000_100_000_i64,
        "claims": ["ready_for_operator_managed_handoff"],
    });
    write_json(handoff_out, &handoff)
}

// -- shared mutation / fs helpers ------------------------------------------

/// Read a trusted-exporters / trusted-packagers document, replace the first
/// entry's `publicKey` with 64 zeros (the scripts' python mutation), and write
/// the untrusted copy.
fn assurance_mutate_first_public_key(
    source: &Path,
    array_key: &str,
    out: &Path,
) -> Result<(), XtaskError> {
    let mut value = load_json(source)?;
    let entry = value
        .get_mut(array_key)
        .and_then(Value::as_array_mut)
        .and_then(|entries| entries.first_mut())
        .ok_or_else(|| invalid(&format!("trusted document has no {array_key} entry")))?;
    set_str(entry, "publicKey", &"0".repeat(64));
    write_json(out, &value)
}

/// Append a single newline byte to a file (the export script's bundle tamper).
fn assurance_append_newline(path: &Path) -> Result<(), XtaskError> {
    let mut bytes = fs::read(path).map_err(|err| XtaskError::Io(display(path), err))?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|err| XtaskError::Io(display(path), err))
}

/// Recursively copy a directory tree (the scripts' `cp -R`).
fn copy_tree(src: &Path, dst: &Path) -> Result<(), XtaskError> {
    fs::create_dir_all(dst).map_err(|err| XtaskError::Io(display(dst), err))?;
    let entries = fs::read_dir(src).map_err(|err| XtaskError::Io(display(src), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display(src), err))?;
        let file_type = entry
            .file_type()
            .map_err(|err| XtaskError::Io(display(&entry.path()), err))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            fs::copy(&from, &to).map_err(|err| XtaskError::Io(display(&to), err))?;
        }
    }
    Ok(())
}

/// Read a review report's first `reviews[].code`.
fn first_review_code(report: &Value) -> Option<String> {
    report
        .get("reviews")
        .and_then(Value::as_array)
        .and_then(|reviews| reviews.first())
        .and_then(|review| review.get("code"))
        .and_then(Value::as_str)
        .map(|s| s.to_string())
}
