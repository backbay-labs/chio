// Conformance subcommand handlers for the `chio` CLI.

/// Dispatch entry-point for `chio conformance run`.
fn cmd_conformance_run(
    peer: &str,
    report: Option<&str>,
    scenario: Option<&str>,
    output: Option<&Path>,
) -> Result<(), CliError> {
    // Reject unknown `--report` values before running the harness so callers
    // don't wait through a full live run before receiving the error.
    let json_report = parse_report_format(report)?;

    let mut options = chio_conformance::default_run_options();
    options.peers = parse_peer_selection(peer)?;

    let summary = chio_conformance::run_conformance_harness(&options).map_err(|error| {
        CliError::Other(format!("conformance harness failed: {error}"))
    })?;

    let scenarios = chio_conformance::load_scenarios_from_dir(&options.scenarios_dir).map_err(
        |error| CliError::Other(format!("failed to load scenarios: {error}")),
    )?;
    let mut results = chio_conformance::load_results_from_dir(&summary.results_dir).map_err(
        |error| CliError::Other(format!("failed to load peer results: {error}")),
    )?;
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
fn parse_report_format(report: Option<&str>) -> Result<bool, CliError> {
    match report {
        None => Ok(false),
        Some(value) => {
            if value.eq_ignore_ascii_case("json") {
                Ok(true)
            } else if value.eq_ignore_ascii_case("human") {
                Ok(false)
            } else {
                Err(CliError::Other(format!(
                    "unsupported --report value `{value}`; expected `json` or `human`",
                )))
            }
        }
    }
}

fn parse_peer_selection(peer: &str) -> Result<Vec<chio_conformance::PeerTarget>, CliError> {
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
        other => Err(CliError::Other(format!(
            "unsupported --peer value `{other}`; expected one of js, python, go, cpp, all",
        ))),
    }
}

fn write_json_report(
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
        CliError::Other(format!("failed to serialise conformance report: {error}"))
    })?;

    if let Some(path) = output {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    CliError::Other(format!(
                        "failed to create report parent directory `{}`: {error}",
                        parent.display(),
                    ))
                })?;
            }
        }
        fs::write(path, &rendered).map_err(|error| {
            CliError::Other(format!(
                "failed to write report to `{}`: {error}",
                path.display(),
            ))
        })?;
    } else {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{rendered}").map_err(|error| {
            CliError::Other(format!("failed to write report to stdout: {error}"))
        })?;
    }
    Ok(())
}

fn write_human_report(
    summary: &chio_conformance::ConformanceRunSummary,
    results: &[chio_conformance::ScenarioResult],
    scenario_filter: Option<&str>,
    output: Option<&Path>,
) -> Result<(), CliError> {
    let mut buffer = String::new();
    buffer.push_str(&format!("listen: {}\n", summary.listen));
    buffer.push_str(&format!(
        "results: {}\n",
        summary.results_dir.display()
    ));
    buffer.push_str(&format!(
        "report:  {}\n",
        summary.report_output.display()
    ));
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
                    CliError::Other(format!(
                        "failed to create report parent directory `{}`: {error}",
                        parent.display(),
                    ))
                })?;
            }
        }
        fs::write(path, &buffer).map_err(|error| {
            CliError::Other(format!(
                "failed to write report to `{}`: {error}",
                path.display(),
            ))
        })?;
    } else {
        let mut stdout = std::io::stdout().lock();
        write!(stdout, "{buffer}").map_err(|error| {
            CliError::Other(format!("failed to write report to stdout: {error}"))
        })?;
    }
    Ok(())
}

/// HTTP timeout for peer-binary downloads. Without a timeout a stalled mirror
/// can hang the CLI indefinitely.
const FETCH_PEERS_HTTP_TIMEOUT_SECS: u64 = 120;

/// Resolve the path to `peers.lock.toml`, honouring the `--lockfile`
/// override first and falling back to the layered runtime resolver.
fn resolve_peers_lock_path(explicit: Option<&Path>) -> PathBuf {
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
/// skipped with a clear message.
fn cmd_conformance_fetch_peers(
    check: bool,
    out: &Path,
    language: Option<&str>,
    lockfile: Option<&Path>,
) -> Result<(), CliError> {
    let lock_path = resolve_peers_lock_path(lockfile);
    let lock = chio_conformance::PeersLock::load(&lock_path).map_err(|error| {
        CliError::Other(format!(
            "failed to load peers lockfile `{}`: {error}",
            lock_path.display(),
        ))
    })?;
    lock.validate().map_err(|error| {
        CliError::Other(format!("peers lockfile is invalid: {error}"))
    })?;

    if let Some(filter) = language {
        if !chio_conformance::SUPPORTED_LANGUAGES.contains(&filter) {
            return Err(CliError::Other(format!(
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

    if check {
        let mut stdout = std::io::stdout().lock();
        writeln!(
            stdout,
            "peers.lock.toml: {} (schema {})",
            lock_path.display(),
            lock.schema,
        )
        .map_err(|error| {
            CliError::Other(format!("failed to write check summary: {error}"))
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
            CliError::Other(format!("failed to write check summary: {error}"))
        })?;
        for entry in &entries {
            let marker = if entry.published { "" } else { " (unpublished, will skip)" };
            writeln!(
                stdout,
                "  - {} {} -> {}{}",
                entry.language, entry.target, entry.url, marker,
            )
            .map_err(|error| {
                CliError::Other(format!("failed to write check entry: {error}"))
            })?;
        }
        return Ok(());
    }

    fs::create_dir_all(out).map_err(|error| {
        CliError::Other(format!(
            "failed to create output dir `{}`: {error}",
            out.display(),
        ))
    })?;

    // Bound the HTTP client timeout so a stalled release-asset mirror
    // cannot hang the CLI indefinitely.
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(FETCH_PEERS_HTTP_TIMEOUT_SECS))
        .build()
        .map_err(|error| {
            CliError::Other(format!("failed to build http client: {error}"))
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
                CliError::Other(format!("failed to write skip line: {error}"))
            })?;
        }
    }

    for entry in &published_entries {
        download_and_verify(&client, entry, out)?;
    }
    Ok(())
}

fn download_and_verify(
    client: &reqwest::blocking::Client,
    entry: &chio_conformance::PeerEntry,
    out: &Path,
) -> Result<(), CliError> {
    let response = client.get(&entry.url).send().map_err(|error| {
        CliError::Other(format!(
            "failed to GET `{}` ({}): {error}",
            entry.url, entry.language,
        ))
    })?;
    if !response.status().is_success() {
        return Err(CliError::Other(format!(
            "non-success status {} fetching `{}`",
            response.status(),
            entry.url,
        )));
    }
    let bytes = response.bytes().map_err(|error| {
        CliError::Other(format!(
            "failed to read body of `{}`: {error}",
            entry.url,
        ))
    })?;
    let actual = chio_conformance::sha256_hex(&bytes);
    if actual != entry.sha256 {
        return Err(CliError::Other(format!(
            "sha256 mismatch for `{}`: expected {}, got {}",
            entry.url, entry.sha256, actual,
        )));
    }

    // Derive a deterministic filename from the URL's last path segment.
    let filename = entry
        .url
        .rsplit('/')
        .next()
        .unwrap_or("peer.bin");
    // Bundles land under `<out>/<language>-<target>/` so consumers find
    // the extracted binary at a stable path.
    let extract_dir = out.join(format!("{}-{}", entry.language, entry.target));
    fs::create_dir_all(&extract_dir).map_err(|error| {
        CliError::Other(format!(
            "failed to create `{}`: {error}",
            extract_dir.display(),
        ))
    })?;
    let archive_path = extract_dir.join(filename);
    fs::write(&archive_path, &bytes).map_err(|error| {
        CliError::Other(format!(
            "failed to write `{}`: {error}",
            archive_path.display(),
        ))
    })?;

    extract_archive(&archive_path, &extract_dir, &entry.url)?;
    Ok(())
}

/// Extract `.tar.gz` (or `.tgz`) bundles into the per-target directory.
/// `.zip` is recognised by extension but not yet implemented; unknown archive
/// formats are preserved on disk with a warning rather than failing fatally.
fn extract_archive(archive: &Path, dest: &Path, source_url: &str) -> Result<(), CliError> {
    let lower = archive
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        let archive_file = fs::File::open(archive).map_err(|error| {
            CliError::Other(format!(
                "failed to open archive `{}`: {error}",
                archive.display(),
            ))
        })?;
        let decompressed = flate2::read::GzDecoder::new(archive_file);
        let mut tar = tar::Archive::new(decompressed);
        tar.unpack(dest).map_err(|error| {
            CliError::Other(format!(
                "failed to extract `{}` into `{}`: {error}",
                archive.display(),
                dest.display(),
            ))
        })?;
        Ok(())
    } else if lower.ends_with(".zip") {
        Err(CliError::Other(format!(
            "zip archives are not yet supported (got `{}` from `{source_url}`)",
            archive.display(),
        )))
    } else {
        // Unknown archive format: leave the bundle on disk but warn so the
        // operator can extract it manually rather than silently shipping a
        // half-installed peer.
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "note: bundle `{}` is not a recognised archive format; downloaded bytes are preserved unchanged",
            archive.display(),
        );
        Ok(())
    }
}
