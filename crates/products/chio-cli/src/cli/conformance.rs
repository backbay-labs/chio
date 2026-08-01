// Conformance subcommand handlers for the `chio` CLI.

use super::*;

/// Dispatch entry-point for `chio conformance run`.
pub(crate) fn cmd_conformance_run(
    peer: &str,
    report: Option<&str>,
    scenario: Option<&str>,
    output: Option<&Path>,
    peer_binary: Option<&Path>,
) -> Result<(), CliError> {
    // Reject unknown `--report` values before running the harness so callers
    // don't wait through a full live run before receiving the error.
    let json_report = parse_report_format(report)?;

    let mut options = chio_conformance::default_run_options();
    options.peers = parse_peer_selection(peer)?;
    if let Some(binary) = peer_binary {
        if options.peers.len() != 1 {
            return Err(CliError::cli_other_error(
                "--peer-binary requires --peer to select exactly one language".to_string(),
            ));
        }
        options
            .peer_binaries
            .push((options.peers[0], binary.to_path_buf()));
    }

    let summary = chio_conformance::run_conformance_harness(&options).map_err(|error| {
        CliError::provider_error(format!("conformance harness failed: {error}"))
    })?;

    let scenarios = chio_conformance::load_scenarios_from_dir(&options.scenarios_dir)
        .map_err(|error| CliError::cli_io_error(format!("failed to load scenarios: {error}")))?;
    let mut results = chio_conformance::load_results_from_dir(&summary.results_dir)
        .map_err(|error| CliError::cli_io_error(format!("failed to load peer results: {error}")))?;
    if let Some(filter) = scenario {
        results.retain(|result| result.scenario_id == filter);
    }

    if json_report {
        write_json_report(&summary, &scenarios, &results, scenario, output)
    } else {
        write_human_report(&summary, &results, scenario, output)
    }
}

/// Validate `--report` early so users do not wait through a live harness run
/// before learning they typed an invalid value. Returns whether the report
/// should be JSON-shaped.
pub(crate) fn parse_report_format(report: Option<&str>) -> Result<bool, CliError> {
    match report {
        None => Ok(false),
        Some(value) => {
            if value.eq_ignore_ascii_case("json") {
                Ok(true)
            } else if value.eq_ignore_ascii_case("human") {
                Ok(false)
            } else {
                Err(CliError::cli_other_error(format!(
                    "unsupported --report value `{value}`; expected `json` or `human`",
                )))
            }
        }
    }
}

pub(crate) fn parse_peer_selection(
    peer: &str,
) -> Result<Vec<chio_conformance::PeerTarget>, CliError> {
    match peer {
        "all" => Ok(vec![
            chio_conformance::PeerTarget::Js,
            chio_conformance::PeerTarget::Python,
            chio_conformance::PeerTarget::Go,
            chio_conformance::PeerTarget::Cpp,
        ]),
        "js" => Ok(vec![chio_conformance::PeerTarget::Js]),
        "python" => Ok(vec![chio_conformance::PeerTarget::Python]),
        "go" => Ok(vec![chio_conformance::PeerTarget::Go]),
        "cpp" => Ok(vec![chio_conformance::PeerTarget::Cpp]),
        other => Err(CliError::cli_other_error(format!(
            "unsupported --peer value `{other}`; expected one of js, python, go, cpp, all",
        ))),
    }
}

pub(crate) fn write_json_report(
    summary: &chio_conformance::ConformanceRunSummary,
    scenarios: &[chio_conformance::ScenarioDescriptor],
    results: &[chio_conformance::ScenarioResult],
    scenario_filter: Option<&str>,
    output: Option<&Path>,
) -> Result<(), CliError> {
    let envelope = serde_json::json!({
        "schemaVersion": "chio-conformance-run/v1",
        "listen": summary.listen.to_string(),
        "resultsDir": summary.results_dir.display().to_string(),
        "reportOutput": summary.report_output.display().to_string(),
        "peerResultFiles": summary
            .peer_result_files
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>(),
        "scenarioFilter": scenario_filter,
        "scenarioCount": scenarios.len(),
        "results": results,
    });

    let rendered = serde_json::to_string_pretty(&envelope).map_err(|error| {
        CliError::cli_other_error(format!("failed to serialise conformance report: {error}"))
    })?;

    if let Some(path) = output {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    CliError::cli_io_error(format!(
                        "failed to create report parent directory `{}`: {error}",
                        parent.display(),
                    ))
                })?;
            }
        }
        fs::write(path, &rendered).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to write report to `{}`: {error}",
                path.display(),
            ))
        })?;
    } else {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{rendered}").map_err(|error| {
            CliError::cli_io_error(format!("failed to write report to stdout: {error}"))
        })?;
    }
    Ok(())
}

pub(crate) fn write_human_report(
    summary: &chio_conformance::ConformanceRunSummary,
    results: &[chio_conformance::ScenarioResult],
    scenario_filter: Option<&str>,
    output: Option<&Path>,
) -> Result<(), CliError> {
    let mut buffer = String::new();
    buffer.push_str(&format!("listen: {}\n", summary.listen));
    buffer.push_str(&format!("results: {}\n", summary.results_dir.display()));
    buffer.push_str(&format!("report:  {}\n", summary.report_output.display()));
    for peer_result in &summary.peer_result_files {
        buffer.push_str(&format!("peer:    {}\n", peer_result.display()));
    }
    if let Some(filter) = scenario_filter {
        buffer.push_str(&format!("scenario filter: {filter}\n"));
    }
    buffer.push_str(&format!("\nscenarios reported: {}\n", results.len()));
    for result in results {
        buffer.push_str(&format!(
            "  - {} [{}] peer={} status={} duration_ms={}\n",
            result.scenario_id,
            result.category.heading(),
            result.peer,
            result.status.label(),
            result.duration_ms,
        ));
    }

    if let Some(path) = output {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    CliError::cli_io_error(format!(
                        "failed to create report parent directory `{}`: {error}",
                        parent.display(),
                    ))
                })?;
            }
        }
        fs::write(path, &buffer).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to write report to `{}`: {error}",
                path.display(),
            ))
        })?;
    } else {
        let mut stdout = std::io::stdout().lock();
        write!(stdout, "{buffer}").map_err(|error| {
            CliError::cli_io_error(format!("failed to write report to stdout: {error}"))
        })?;
    }
    Ok(())
}

/// HTTP timeout for peer-binary downloads. Without a timeout a stalled mirror
/// can hang the CLI indefinitely.
pub(crate) const FETCH_PEERS_HTTP_TIMEOUT_SECS: u64 = 120;

/// Resolve the path to `peers.lock.toml`, honouring the `--lockfile`
/// override first and falling back to the layered runtime resolver.
pub(crate) fn resolve_peers_lock_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    chio_conformance::default_peers_lock_path()
}

/// Dispatch entry-point for `chio conformance fetch-peers`.
///
/// `--check` validates the lockfile without touching the network. Without
/// `--check`, each published entry is downloaded, sha256-verified, and
/// extracted under `out/`. The `language` filter restricts the loop to
/// entries matching that adapter. Entries flagged `published = false` are
/// skipped in mixed selections; selecting only unpublished entries fails
/// unless `allow_unpublished_only` is set for an explicit pre-release gate.
pub(crate) fn cmd_conformance_fetch_peers(
    check: bool,
    out: &Path,
    language: Option<&str>,
    allow_unpublished_only: bool,
    lockfile: Option<&Path>,
) -> Result<(), CliError> {
    if allow_unpublished_only && !check {
        return Err(CliError::cli_other_error(
            "--allow-unpublished-only is only valid with --check; downloads still require at least one published peer".to_string(),
        ));
    }

    let lock_path = resolve_peers_lock_path(lockfile);
    let lock = chio_conformance::PeersLock::load(&lock_path).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to load peers lockfile `{}`: {error}",
            lock_path.display(),
        ))
    })?;
    lock.validate().map_err(|error| {
        CliError::cli_other_error(format!("peers lockfile is invalid: {error}"))
    })?;

    if let Some(filter) = language {
        if !chio_conformance::SUPPORTED_LANGUAGES.contains(&filter) {
            return Err(CliError::cli_other_error(format!(
                "unsupported --language value `{filter}`; expected one of {:?}",
                chio_conformance::SUPPORTED_LANGUAGES,
            )));
        }
    }

    let entries: Vec<&chio_conformance::PeerEntry> = match language {
        Some(value) => lock.entries_for_language(value),
        None => lock.peers.iter().collect(),
    };
    let (published_entries, skipped_entries) =
        chio_conformance::PeersLock::partition_by_published(&entries);
    ensure_fetch_peer_selection_has_published(
        &entries,
        &published_entries,
        language,
        allow_unpublished_only,
    )?;

    if check {
        let mut stdout = std::io::stdout().lock();
        writeln!(
            stdout,
            "peers.lock.toml: {} (schema {})",
            lock_path.display(),
            lock.schema,
        )
        .map_err(|error| {
            CliError::cli_io_error(format!("failed to write check summary: {error}"))
        })?;
        writeln!(
            stdout,
            "validated {} entries ({} published, {} skipped) (filter: {})",
            entries.len(),
            published_entries.len(),
            skipped_entries.len(),
            language.unwrap_or("<none>"),
        )
        .map_err(|error| {
            CliError::cli_io_error(format!("failed to write check summary: {error}"))
        })?;
        for entry in &entries {
            let marker = if entry.published {
                ""
            } else {
                " (unpublished, will skip)"
            };
            writeln!(
                stdout,
                "  - {} {} -> {}{}",
                entry.language, entry.target, entry.url, marker,
            )
            .map_err(|error| {
                CliError::cli_io_error(format!("failed to write check entry: {error}"))
            })?;
        }
        return Ok(());
    }

    fs::create_dir_all(out).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to create output dir `{}`: {error}",
            out.display(),
        ))
    })?;

    // Bound the HTTP client timeout so a stalled release-asset mirror
    // cannot hang the CLI indefinitely.
    // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: user-initiated conformance peer
    // binary downloads are lockfile URL fetches verified by sha256, outside
    // substrate tool egress.
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(
            FETCH_PEERS_HTTP_TIMEOUT_SECS,
        ))
        .build()
        .map_err(|error| {
            CliError::cli_other_error(format!("failed to build http client: {error}"))
        })?;

    {
        let mut stdout = std::io::stdout().lock();
        for entry in &skipped_entries {
            writeln!(
                stdout,
                "skipping unpublished peer `{} / {}`: lockfile entry has `published = false` (no real binary uploaded yet)",
                entry.language, entry.target,
            )
            .map_err(|error| {
                CliError::cli_io_error(format!("failed to write skip line: {error}"))
            })?;
        }
    }

    for entry in &published_entries {
        download_and_verify(&client, entry, out)?;
    }
    Ok(())
}

fn ensure_fetch_peer_selection_has_published(
    entries: &[&chio_conformance::PeerEntry],
    published_entries: &[&chio_conformance::PeerEntry],
    language: Option<&str>,
    allow_unpublished_only: bool,
) -> Result<(), CliError> {
    let filter = language.unwrap_or("<none>");
    if entries.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "peers lockfile has no entries matching language filter `{filter}`",
        )));
    }
    if published_entries.is_empty() {
        if allow_unpublished_only {
            return Ok(());
        }
        return Err(CliError::cli_other_error(format!(
            "peers lockfile has no published entries for language filter `{filter}`; every selected peer would be skipped (use --allow-unpublished-only only for pre-release lockfile checks)",
        )));
    }
    Ok(())
}

pub(crate) fn download_and_verify(
    client: &reqwest::blocking::Client,
    entry: &chio_conformance::PeerEntry,
    out: &Path,
) -> Result<(), CliError> {
    // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: conformance peer binary
    // download is verified by sha256, outside substrate tool egress.
    let response = client.get(&entry.url).send().map_err(|error| {
        CliError::provider_error(format!(
            "failed to GET `{}` ({}): {error}",
            entry.url, entry.language,
        ))
    })?;
    if !response.status().is_success() {
        return Err(CliError::provider_error(format!(
            "non-success status {} fetching `{}`",
            response.status(),
            entry.url,
        )));
    }
    let bytes = response.bytes().map_err(|error| {
        CliError::provider_error(format!("failed to read body of `{}`: {error}", entry.url,))
    })?;
    let actual = chio_conformance::sha256_hex(&bytes);
    if actual != entry.sha256 {
        return Err(CliError::provider_error(format!(
            "sha256 mismatch for `{}`: expected {}, got {}",
            entry.url, entry.sha256, actual,
        )));
    }

    // Derive a deterministic filename from the URL's last path segment.
    let filename = entry.url.rsplit('/').next().unwrap_or("peer.bin");
    // Bundles land under `<out>/<language>-<target>/` so consumers find
    // the extracted binary at a stable path.
    let extract_dir = out.join(format!("{}-{}", entry.language, entry.target));
    fs::create_dir_all(&extract_dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to create `{}`: {error}",
            extract_dir.display(),
        ))
    })?;
    let archive_path = extract_dir.join(filename);
    fs::write(&archive_path, &bytes).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to write `{}`: {error}",
            archive_path.display(),
        ))
    })?;

    extract_archive(&archive_path, &extract_dir, &entry.url)?;
    validate_extracted_peer_binary(entry, &extract_dir)?;
    Ok(())
}

/// Extract `.tar.gz` (or `.tgz`) bundles into the per-target directory.
/// `.zip` and unknown archive formats are rejected so `fetch-peers` cannot
/// succeed without an executable peer artifact installed.
pub(crate) fn extract_archive(
    archive: &Path,
    dest: &Path,
    source_url: &str,
) -> Result<(), CliError> {
    let lower = archive
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        let entries = crate::archive::read_tar_gz_file(
            archive,
            "Chio conformance archive",
            crate::archive::SafeArchiveLimits {
                max_compressed_bytes: 128 * 1024 * 1024,
                max_member_bytes: 128 * 1024 * 1024,
                max_total_bytes: 512 * 1024 * 1024,
                max_member_count: 4096,
                max_decompression_ratio: 200,
            },
        )?;
        crate::archive::replace_entries_in_existing_dir(
            dest,
            "Chio conformance archive",
            &entries,
        )?;
        Ok(())
    } else if lower.ends_with(".zip") {
        Err(CliError::cli_other_error(format!(
            "zip archives are unsupported for conformance peer bundles (got `{}` from `{source_url}`)",
            archive.display(),
        )))
    } else {
        Err(CliError::cli_other_error(format!(
            "unsupported archive format for conformance peer bundle `{}` from `{source_url}`; expected .tar.gz or .tgz",
            archive.display(),
        )))
    }
}

pub(crate) fn validate_extracted_peer_binary(
    entry: &chio_conformance::PeerEntry,
    extract_dir: &Path,
) -> Result<(), CliError> {
    let binary = Path::new(&entry.binary);
    if binary.is_absolute()
        || binary
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(CliError::cli_other_error(format!(
            "conformance peer binary path `{}` must be a relative path inside the archive",
            entry.binary
        )));
    }
    let binary_path = extract_dir.join(binary);
    let metadata = fs::metadata(&binary_path).map_err(|error| {
        CliError::cli_other_error(format!(
            "conformance peer bundle `{}` for {} / {} did not install declared binary `{}`: {error}",
            entry.url, entry.language, entry.target, entry.binary
        ))
    })?;
    if !metadata.is_file() {
        return Err(CliError::cli_other_error(format!(
            "conformance peer declared binary `{}` is not a regular file",
            binary_path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(CliError::cli_other_error(format!(
                "conformance peer declared binary `{}` is not executable",
                binary_path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod conformance_error_tests {
    use super::*;

    fn assert_registry_error(
        err: CliError,
        expected_code: &str,
        expected_domain: &str,
        expected_message: &str,
    ) {
        match err {
            CliError::Chio(chio) => {
                assert_eq!(chio.code().as_str(), expected_code);
                assert_eq!(chio.domain().as_str(), expected_domain);
                assert!(
                    chio.to_string().contains(expected_message),
                    "message: {chio}",
                );
            }
            other => panic!("expected registry-backed error, got {other:?}"),
        }
    }

    fn assert_cli_error(err: CliError, expected_message: &str) {
        assert_registry_error(err, "urn:chio:error:cli:other", "cli", expected_message);
    }

    fn sample_summary() -> chio_conformance::ConformanceRunSummary {
        chio_conformance::ConformanceRunSummary {
            listen: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            results_dir: PathBuf::from("results"),
            report_output: PathBuf::from("report.md"),
            peer_result_files: vec![PathBuf::from("peer.json")],
        }
    }

    fn write_test_tar_gz(path: &Path, entries: &[(&str, &[u8])]) {
        write_test_tar_gz_with_modes(path, &[], entries);
    }

    fn write_test_tar_gz_with_modes(path: &Path, directories: &[&str], entries: &[(&str, &[u8])]) {
        let file = fs::File::create(path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for name in directories {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            builder
                .append_data(&mut header, *name, std::io::empty())
                .unwrap();
        }
        for (name, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(u64::try_from(bytes.len()).unwrap());
            header.set_mode(if name.ends_with("peer") { 0o755 } else { 0o600 });
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            builder
                .append_data(&mut header, *name, std::io::Cursor::new(*bytes))
                .unwrap();
        }
        builder.finish().unwrap();
        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();
    }

    fn peer_entry(binary: &str) -> chio_conformance::PeerEntry {
        chio_conformance::PeerEntry {
            language: "python".to_string(),
            url: "https://example.invalid/peer.tar.gz".to_string(),
            sha256: "0".repeat(64),
            target: "x86_64-unknown-linux-gnu".to_string(),
            binary: binary.to_string(),
            published: true,
        }
    }

    #[test]
    fn invalid_report_format_uses_cli_registry_domain() {
        let err = match parse_report_format(Some("xml")) {
            Ok(value) => panic!("expected invalid report format to fail, got {value}"),
            Err(err) => err,
        };
        assert_cli_error(err, "unsupported --report value");
    }

    #[test]
    fn invalid_peer_selection_uses_cli_registry_domain() {
        let err = match parse_peer_selection("ruby") {
            Ok(value) => panic!("expected invalid peer selection to fail, got {value:?}"),
            Err(err) => err,
        };
        assert_cli_error(err, "unsupported --peer value");
    }

    #[test]
    fn conformance_archive_hardening_extracts_regular_nested_file() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("peer.tar.gz");
        let dest = temp.path().join("extract");
        fs::create_dir_all(&dest).unwrap();
        write_test_tar_gz_with_modes(&archive, &["bin"], &[("bin/peer", b"peer-binary")]);

        extract_archive(&archive, &dest, "https://example.invalid/peer.tar.gz").unwrap();

        assert_eq!(fs::read(dest.join("bin/peer")).unwrap(), b"peer-binary");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(dest.join("bin/peer"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
        }
    }

    #[test]
    fn conformance_archive_hardening_requires_declared_binary() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("peer.tar.gz");
        let dest = temp.path().join("extract");
        fs::create_dir_all(&dest).unwrap();
        write_test_tar_gz_with_modes(&archive, &["bin"], &[("bin/other", b"peer-binary")]);

        extract_archive(&archive, &dest, "https://example.invalid/peer.tar.gz").unwrap();
        let err = match validate_extracted_peer_binary(&peer_entry("bin/peer"), &dest) {
            Ok(()) => panic!("expected missing declared binary to fail"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("did not install declared binary `bin/peer`"),
            "{err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn conformance_archive_hardening_requires_executable_declared_binary() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("peer.tar.gz");
        let dest = temp.path().join("extract");
        fs::create_dir_all(&dest).unwrap();
        write_test_tar_gz(&archive, &[("bin/nonexec", b"peer-binary")]);

        extract_archive(&archive, &dest, "https://example.invalid/peer.tar.gz").unwrap();
        let err = match validate_extracted_peer_binary(&peer_entry("bin/nonexec"), &dest) {
            Ok(()) => panic!("expected non-executable declared binary to fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("is not executable"), "{err}");
    }

    #[test]
    fn conformance_archive_hardening_rejects_escape_binary_path() {
        let temp = tempfile::tempdir().unwrap();
        let dest = temp.path().join("extract");
        fs::create_dir_all(&dest).unwrap();
        let err = match validate_extracted_peer_binary(&peer_entry("../peer"), &dest) {
            Ok(()) => panic!("expected escaping binary path to fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("must be a relative path"), "{err}");
    }

    #[test]
    fn conformance_archive_hardening_refreshes_existing_file() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("peer.tar.gz");
        let dest = temp.path().join("extract");
        fs::create_dir_all(dest.join("bin")).unwrap();
        fs::write(dest.join("bin/peer"), b"old-peer").unwrap();
        write_test_tar_gz(&archive, &[("bin/peer", b"new-peer")]);

        extract_archive(&archive, &dest, "https://example.invalid/peer.tar.gz").unwrap();

        assert_eq!(fs::read(dest.join("bin/peer")).unwrap(), b"new-peer");
    }

    #[test]
    fn conformance_archive_hardening_rejects_backslash_member() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("peer.tar.gz");
        let dest = temp.path().join("extract");
        fs::create_dir_all(&dest).unwrap();
        write_test_tar_gz(&archive, &[("bad\\path", b"owned")]);

        let err = match extract_archive(&archive, &dest, "https://example.invalid/peer.tar.gz") {
            Ok(()) => panic!("expected backslash archive to fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("not portable"), "{err}");
        assert!(!temp.path().join("escape").exists());
    }

    #[test]
    fn conformance_archive_hardening_rejects_zip_bundle() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("peer.zip");
        let dest = temp.path().join("extract");
        fs::create_dir_all(&dest).unwrap();
        fs::write(&archive, b"not-a-real-zip").unwrap();

        let err = match extract_archive(&archive, &dest, "https://example.invalid/peer.zip") {
            Ok(()) => panic!("expected zip archive to fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("zip archives are unsupported"));
    }

    #[test]
    fn conformance_archive_hardening_rejects_unknown_bundle_format() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("peer.bin");
        let dest = temp.path().join("extract");
        fs::create_dir_all(&dest).unwrap();
        fs::write(&archive, b"raw-binary").unwrap();

        let err = match extract_archive(&archive, &dest, "https://example.invalid/peer.bin") {
            Ok(()) => panic!("expected unknown archive to fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("unsupported archive format"));
    }

    #[test]
    fn conformance_archive_hardening_rejects_symlink_member() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("peer.tar.gz");
        let file = fs::File::create(&archive).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name("../escape").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "bin/peer", std::io::empty())
            .unwrap();
        builder.finish().unwrap();
        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();
        let dest = temp.path().join("extract");
        fs::create_dir_all(&dest).unwrap();

        let err = match extract_archive(&archive, &dest, "https://example.invalid/peer.tar.gz") {
            Ok(()) => panic!("expected symlink archive to fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("non-regular"), "{err}");
    }

    #[test]
    fn json_report_parent_write_failure_uses_cli_io_domain() {
        let temp = match tempfile::tempdir() {
            Ok(temp) => temp,
            Err(error) => panic!("failed to create temp dir: {error}"),
        };
        let blocked_parent = temp.path().join("blocked-parent");
        if let Err(error) = fs::write(&blocked_parent, b"not a directory") {
            panic!("failed to create blocked parent fixture: {error}");
        }
        let output = blocked_parent.join("report.json");

        let err = match write_json_report(&sample_summary(), &[], &[], None, Some(&output)) {
            Ok(()) => panic!("expected blocked report parent to fail"),
            Err(err) => err,
        };

        assert_registry_error(
            err,
            "urn:chio:error:cli:io",
            "cli",
            "failed to create report parent directory",
        );
    }
}
