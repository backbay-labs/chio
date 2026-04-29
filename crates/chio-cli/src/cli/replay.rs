// Replay subcommand handler for the `chio` CLI.

/// Dispatch entry-point for `chio replay`.
fn cmd_replay(args: &ReplayArgs) -> Result<(), CliError> {
    if let Some(ReplaySubcommand::Traffic(traffic)) = args.command.as_ref() {
        return cmd_replay_traffic(traffic);
    }

    // Legacy surface requires the positional `log` path.
    let Some(log) = args.log.as_ref() else {
        return Err(CliError::Other(
            "chio replay requires a positional <log> path or the `traffic` sub-subcommand"
                .to_string(),
        ));
    };

    if args.bless {
        return cmd_replay_bless(args, log);
    }

    cmd_replay_legacy(args, log)
}

/// Legacy `chio replay <log>` arm. Builds a [`ReplayReport`], renders it
/// (single-line JSON when `--json` is set, short human summary otherwise),
/// and on divergence returns through [`finish_replay_failure`] so the binary
/// exits with the canonical 0/10/20/30/40/50 code.
fn cmd_replay_legacy(args: &ReplayArgs, log: &Path) -> Result<(), CliError> {
    if args.from_tee && args.tenant_pubkey.is_none() {
        return finish_replay_failure(
            EXIT_BAD_TENANT_SIG,
            "chio replay --from-tee requires --tenant-pubkey".to_string(),
        );
    }
    if !args.from_tee && args.trusted_kernel_pubkey.is_none() {
        return finish_replay_failure(
            EXIT_BAD_SIGNATURE,
            "chio replay receipt logs require --trusted-kernel-pubkey".to_string(),
        );
    }

    let tenant_pubkey = match args.tenant_pubkey.as_deref() {
        Some(path) => Some(load_tenant_pubkey(path).map_err(|e| {
            CliError::Other(format!("failed to load tenant pubkey: {e}"))
        })?),
        None => None,
    };
    let trusted_kernel_key = match args.trusted_kernel_pubkey.as_deref() {
        Some(path) => Some(load_trusted_kernel_pubkey(path).map_err(|e| {
            CliError::Other(format!("failed to load trusted kernel pubkey: {e}"))
        })?),
        None => None,
    };

    let report = run_legacy_replay(
        log,
        args.expect_root.as_deref(),
        args.from_tee,
        tenant_pubkey.as_ref(),
        trusted_kernel_key.as_ref(),
    )?;

    let mut stdout = std::io::stdout().lock();
    if args.json {
        render_json(&mut stdout, &report)
            .map_err(|e| CliError::Other(format!("write stdout: {e}")))?;
    } else {
        render_replay_human(&mut stdout, &report)
            .map_err(|e| CliError::Other(format!("write stdout: {e}")))?;
    }

    if report.exit_code == 0 {
        return Ok(());
    }
    let detail = report
        .first_divergence
        .as_ref()
        .and_then(|d| d.detail.clone())
        .unwrap_or_else(|| "replay diverged".to_string());
    finish_replay_failure(
        report.exit_code,
        format!("chio replay: {detail}"),
    )
}

/// Run the legacy receipt-log replay pipeline against `log` and produce a
/// [`ReplayReport`]. The pipeline is fail-closed and stops at the first
/// divergence; subsequent receipts are not folded into the synthetic root.
fn run_legacy_replay(
    log: &Path,
    expect_root: Option<&str>,
    from_tee: bool,
    tenant_pubkey: Option<&[u8; 32]>,
    trusted_kernel_key: Option<&chio_core::PublicKey>,
) -> Result<ReplayReport, CliError> {
    let log_path = log.display().to_string();
    let expected_root = expect_root.map(|s| s.to_string());

    if from_tee {
        let Some(tenant_pubkey) = tenant_pubkey else {
            return Err(CliError::Other(
                "chio replay --from-tee requires --tenant-pubkey".to_string(),
            ));
        };
        return run_legacy_replay_from_tee(log, &log_path, expected_root, tenant_pubkey);
    }

    let reader = ReceiptLogReader::open(log).map_err(|e| {
        CliError::Other(format!(
            "failed to open receipt log {}: {e}",
            log.display()
        ))
    })?;
    let iter = match reader.iter() {
        Ok(it) => it,
        Err(ReadError::MalformedJson { line, detail, .. }) => {
            // The reader buffers the whole file before yielding, so a malformed
            // line surfaces here at iter()-creation time. `receipt_index` is
            // pinned to 0 (the iter never started); the real position lives in
            // the `line` field of `detail`.
            let divergence = Divergence {
                kind: DivergenceKind::ParseError,
                receipt_index: 0,
                receipt_id: None,
                json_pointer: None,
                byte_offset: None,
                expected: None,
                observed: None,
                detail: Some(format!("malformed JSON at line {line}: {detail}")),
            };
            return Ok(ReplayReport::diverged(
                log_path,
                0,
                MerkleAccumulator::new().finalize_hex(),
                expected_root,
                divergence,
                exit_code_for(DivergenceKind::ParseError),
            ));
        }
        Err(ReadError::Empty(p)) => {
            return Err(CliError::Other(format!(
                "empty receipt log: {}",
                p.display(),
            )));
        }
        Err(ReadError::Io(e)) => {
            return Err(CliError::Other(format!(
                "io error while reading receipt log: {e}",
            )));
        }
    };

    let mut acc = MerkleAccumulator::new();
    let mut receipts_checked: usize = 0;

    for (index, item) in iter.enumerate() {
        let value = match item {
            Ok(v) => v,
            Err(ReadError::MalformedJson { line, detail, .. }) => {
                let divergence = Divergence {
                    kind: DivergenceKind::ParseError,
                    receipt_index: index,
                    receipt_id: None,
                    json_pointer: None,
                    byte_offset: None,
                    expected: None,
                    observed: None,
                    detail: Some(format!("malformed JSON at line {line}: {detail}")),
                };
                return Ok(ReplayReport::diverged(
                    log_path,
                    receipts_checked,
                    acc.finalize_hex(),
                    expected_root,
                    divergence,
                    exit_code_for(DivergenceKind::ParseError),
                ));
            }
            Err(ReadError::Empty(p)) => {
                return Err(CliError::Other(format!(
                    "empty receipt log: {}",
                    p.display(),
                )));
            }
            Err(ReadError::Io(e)) => {
                return Err(CliError::Other(format!(
                    "io error while reading receipt log: {e}",
                )));
            }
        };

        if let Err(err) = check_receipt_schema(&value) {
            let divergence = match err {
                ReceiptGateError::SchemaMismatch { observed } => Divergence {
                    kind: DivergenceKind::SchemaMismatch,
                    receipt_index: index,
                    receipt_id: receipt_id_from_value(&value),
                    json_pointer: Some("/schema_version".to_string()),
                    byte_offset: None,
                    expected: Some(SUPPORTED_RECEIPT_SCHEMA.to_string()),
                    observed: Some(observed),
                    detail: Some(
                        "receipt schema_version is unsupported by this build"
                            .to_string(),
                    ),
                },
                ReceiptGateError::RedactionMismatch { .. } => {
                    return Err(CliError::Other(
                        "schema gate produced a redaction error".to_string(),
                    ));
                }
            };
            return Ok(ReplayReport::diverged(
                log_path,
                receipts_checked,
                acc.finalize_hex(),
                expected_root,
                divergence,
                exit_code_for(DivergenceKind::SchemaMismatch),
            ));
        }

        if let Err(err) = check_receipt_redaction(&value) {
            let divergence = match err {
                ReceiptGateError::RedactionMismatch { observed } => Divergence {
                    kind: DivergenceKind::RedactionMismatch,
                    receipt_index: index,
                    receipt_id: receipt_id_from_value(&value),
                    json_pointer: Some("/metadata/redaction_pass_id".to_string()),
                    byte_offset: None,
                    expected: Some(SUPPORTED_RECEIPT_REDACTION_PASS_ID.to_string()),
                    observed: Some(observed),
                    detail: Some(
                        "receipt redaction_pass_id is unavailable in this build"
                            .to_string(),
                    ),
                },
                ReceiptGateError::SchemaMismatch { .. } => {
                    return Err(CliError::Other(
                        "redaction gate produced a schema error".to_string(),
                    ));
                }
            };
            return Ok(ReplayReport::diverged(
                log_path,
                receipts_checked,
                acc.finalize_hex(),
                expected_root,
                divergence,
                exit_code_for(DivergenceKind::RedactionMismatch),
            ));
        }

        let receipt: chio_core::receipt::ChioReceipt = match serde_json::from_value(value.clone())
        {
            Ok(r) => r,
            Err(error) => {
                let divergence = Divergence {
                    kind: DivergenceKind::ParseError,
                    receipt_index: index,
                    receipt_id: receipt_id_from_value(&value),
                    json_pointer: None,
                    byte_offset: None,
                    expected: None,
                    observed: None,
                    detail: Some(format!("malformed receipt JSON: {error}")),
                };
                return Ok(ReplayReport::diverged(
                    log_path,
                    receipts_checked,
                    acc.finalize_hex(),
                    expected_root,
                    divergence,
                    exit_code_for(DivergenceKind::ParseError),
                ));
            }
        };

        let outcome = verify_receipt(&value, trusted_kernel_key);
        if !outcome.ok {
            let signer = if outcome.signer_key_hex.is_empty() {
                "unknown".to_string()
            } else {
                format!("ed25519:{}", outcome.signer_key_hex)
            };
            let error = outcome.error.unwrap_or_else(|| "unknown error".to_string());
            let divergence = Divergence {
                kind: DivergenceKind::SignatureMismatch,
                receipt_index: index,
                receipt_id: Some(receipt.id.clone()),
                json_pointer: None,
                byte_offset: None,
                expected: None,
                observed: None,
                detail: Some(format!("signer={signer} {error}")),
            };
            return Ok(ReplayReport::diverged(
                log_path,
                receipts_checked,
                acc.finalize_hex(),
                expected_root,
                divergence,
                exit_code_for(DivergenceKind::SignatureMismatch),
            ));
        }

        match rederive_verdict(&receipt) {
            Ok(_) => {}
            Err(VerdictError::Drift {
                receipt_id,
                stored,
                current,
            }) => {
                let divergence = Divergence {
                    kind: DivergenceKind::VerdictDrift,
                    receipt_index: index,
                    receipt_id: Some(receipt_id),
                    json_pointer: Some("/decision/verdict".to_string()),
                    byte_offset: None,
                    expected: Some(stored),
                    observed: Some(current),
                    detail: Some("stored verdict differs from current build".to_string()),
                };
                return Ok(ReplayReport::diverged(
                    log_path,
                    receipts_checked,
                    acc.finalize_hex(),
                    expected_root,
                    divergence,
                    exit_code_for(DivergenceKind::VerdictDrift),
                ));
            }
            Err(VerdictError::EvalFailed { receipt_id, detail }) => {
                let divergence = Divergence {
                    kind: DivergenceKind::VerdictDrift,
                    receipt_index: index,
                    receipt_id: Some(receipt_id),
                    json_pointer: Some("/decision/verdict".to_string()),
                    byte_offset: None,
                    expected: Some("rederived verdict".to_string()),
                    observed: Some("unavailable".to_string()),
                    detail: Some(detail),
                };
                return Ok(ReplayReport::diverged(
                    log_path,
                    receipts_checked,
                    acc.finalize_hex(),
                    expected_root,
                    divergence,
                    exit_code_for(DivergenceKind::VerdictDrift),
                ));
            }
            Err(other) => {
                return Err(CliError::Other(format!("verdict re-derive failed: {other}")));
            }
        }

        let canonical = chio_core::canonical::canonical_json_bytes(&receipt).map_err(|e| {
            CliError::Other(format!("canonicalize receipt {}: {e}", receipt.id))
        })?;
        acc.append(&canonical);
        receipts_checked = receipts_checked.saturating_add(1);
    }

    let computed_root = acc.finalize_hex();
    if let Some(expected) = expected_root.as_deref() {
        if !expected.eq_ignore_ascii_case(&computed_root) {
            let divergence = Divergence {
                kind: DivergenceKind::MerkleMismatch,
                receipt_index: receipts_checked,
                receipt_id: None,
                json_pointer: None,
                byte_offset: None,
                expected: Some(expected.to_string()),
                observed: Some(computed_root.clone()),
                detail: Some("recomputed root does not match --expect-root".to_string()),
            };
            return Ok(ReplayReport::diverged(
                log_path,
                receipts_checked,
                computed_root,
                expected_root,
                divergence,
                exit_code_for(DivergenceKind::MerkleMismatch),
            ));
        }
    }

    Ok(ReplayReport::clean(
        log_path,
        receipts_checked,
        computed_root,
        expected_root,
    ))
}

/// `--from-tee` arm. Reads `<log>` as an NDJSON capture of
/// `chio-tee-frame.v1` frames, runs `validate_frame` on each, and folds
/// canonical frame bytes into the synthetic root. Verdict drift (exit 10)
/// under `--from-tee` is out of scope for this surface; only the four
/// non-drift divergence shapes (parse / schema / redaction / signature)
/// can fire here.
fn run_legacy_replay_from_tee(
    log: &Path,
    log_path: &str,
    expected_root: Option<String>,
    tenant_pubkey: &[u8; 32],
) -> Result<ReplayReport, CliError> {
    let iter = open_ndjson(log).map_err(|e| {
        CliError::Other(format!(
            "failed to open tee capture {}: {e}",
            log.display()
        ))
    })?;

    let mut acc = MerkleAccumulator::new();
    let mut receipts_checked: usize = 0;

    for (index, item) in iter.enumerate() {
        match item {
            Ok(record) => {
                if let Err(err) =
                    validate_frame(&record.frame, "chio-tee-frame.v1", Some(tenant_pubkey))
                {
                    let kind = match err.exit_code() {
                        EXIT_BAD_TENANT_SIG => DivergenceKind::SignatureMismatch,
                        EXIT_REDACTION_MISMATCH => DivergenceKind::RedactionMismatch,
                        _ => DivergenceKind::SchemaMismatch,
                    };
                    let divergence = Divergence {
                        kind,
                        receipt_index: index,
                        receipt_id: Some(record.frame.event_id.clone()),
                        json_pointer: None,
                        byte_offset: None,
                        expected: None,
                        observed: None,
                        detail: Some(err.to_string()),
                    };
                    return Ok(ReplayReport::diverged(
                        log_path.to_string(),
                        receipts_checked,
                        acc.finalize_hex(),
                        expected_root,
                        divergence,
                        exit_code_for(kind),
                    ));
                }
                let canonical =
                    chio_core::canonical::canonical_json_bytes(&record.frame).map_err(|e| {
                        CliError::Other(format!(
                            "canonicalize frame at line {}: {e}",
                            record.line,
                        ))
                    })?;
                acc.append(&canonical);
                receipts_checked = receipts_checked.saturating_add(1);
            }
            Err(err) => {
                let divergence = Divergence {
                    kind: DivergenceKind::ParseError,
                    receipt_index: index,
                    receipt_id: None,
                    json_pointer: None,
                    byte_offset: None,
                    expected: None,
                    observed: None,
                    detail: Some(err.to_string()),
                };
                return Ok(ReplayReport::diverged(
                    log_path.to_string(),
                    receipts_checked,
                    acc.finalize_hex(),
                    expected_root,
                    divergence,
                    exit_code_for(DivergenceKind::ParseError),
                ));
            }
        }
    }

    if receipts_checked == 0 {
        let divergence = Divergence {
            kind: DivergenceKind::ParseError,
            receipt_index: 0,
            receipt_id: None,
            json_pointer: None,
            byte_offset: None,
            expected: Some("at least one chio-tee-frame.v1 frame".to_string()),
            observed: Some("0 frames".to_string()),
            detail: Some("empty TEE capture cannot be replayed as clean evidence".to_string()),
        };
        return Ok(ReplayReport::diverged(
            log_path.to_string(),
            receipts_checked,
            acc.finalize_hex(),
            expected_root,
            divergence,
            exit_code_for(DivergenceKind::ParseError),
        ));
    }

    let computed_root = acc.finalize_hex();
    if let Some(expected) = expected_root.as_deref() {
        if !expected.eq_ignore_ascii_case(&computed_root) {
            let divergence = Divergence {
                kind: DivergenceKind::MerkleMismatch,
                receipt_index: receipts_checked,
                receipt_id: None,
                json_pointer: None,
                byte_offset: None,
                expected: Some(expected.to_string()),
                observed: Some(computed_root.clone()),
                detail: Some("recomputed root does not match --expect-root".to_string()),
            };
            return Ok(ReplayReport::diverged(
                log_path.to_string(),
                receipts_checked,
                computed_root,
                expected_root,
                divergence,
                exit_code_for(DivergenceKind::MerkleMismatch),
            ));
        }
    }

    Ok(ReplayReport::clean(
        log_path.to_string(),
        receipts_checked,
        computed_root,
        expected_root,
    ))
}

/// Best-effort attribution of a receipt id from the raw value, used for
/// error reports when the receipt could not be deserialized.
fn receipt_id_from_value(value: &serde_json::Value) -> Option<String> {
    value.get("id").and_then(|v| v.as_str()).map(str::to_string)
}

/// Render `report` as a short human-readable summary on `writer`.
fn render_replay_human<W: std::io::Write>(
    writer: &mut W,
    report: &ReplayReport,
) -> std::io::Result<()> {
    writeln!(
        writer,
        "chio replay: {} receipts, root={}",
        report.receipts_checked, report.computed_root,
    )?;
    if let Some(expected) = report.expected_root.as_deref() {
        writeln!(writer, "  expected_root={expected}")?;
    }
    if let Some(divergence) = report.first_divergence.as_ref() {
        writeln!(
            writer,
            "  first_divergence: kind={:?} index={} exit={}",
            divergence.kind, divergence.receipt_index, report.exit_code,
        )?;
        if let Some(detail) = divergence.detail.as_deref() {
            writeln!(writer, "    detail: {detail}")?;
        }
    } else {
        writeln!(writer, "  ok")?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_parser_tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn replay_parses_log_argument() {
        let cli = Cli::try_parse_from(["chio", "replay", "./receipts/"]).unwrap();
        match cli.command {
            Commands::Replay(args) => {
                assert_eq!(args.log.as_deref(), Some(Path::new("./receipts/")));
                assert!(!args.from_tee);
                assert!(args.expect_root.is_none());
                assert!(!args.json);
                assert!(!args.bless);
                assert!(args.into.is_none());
                assert!(args.command.is_none());
            }
            _ => panic!("expected replay subcommand"),
        }
    }

    #[test]
    fn replay_parses_expect_root_flag() {
        let cli = Cli::try_parse_from([
            "chio",
            "replay",
            "./receipts/",
            "--expect-root",
            "7af9deadbeef",
        ])
        .unwrap();
        match cli.command {
            Commands::Replay(args) => {
                assert_eq!(args.expect_root.as_deref(), Some("7af9deadbeef"));
            }
            _ => panic!("expected replay subcommand"),
        }
    }

    #[test]
    fn replay_parses_from_tee_and_json_flags() {
        let cli = Cli::try_parse_from([
            "chio",
            "replay",
            "capture.ndjson",
            "--from-tee",
            "--json",
        ])
        .unwrap();
        match cli.command {
            Commands::Replay(args) => {
                assert!(args.from_tee);
                assert!(args.json);
            }
            _ => panic!("expected replay subcommand"),
        }
    }

    #[test]
    fn replay_parses_bless_flag() {
        let cli =
            Cli::try_parse_from(["chio", "replay", "./receipts/", "--bless"]).unwrap();
        match cli.command {
            Commands::Replay(args) => {
                assert!(args.bless);
            }
            _ => panic!("expected replay subcommand"),
        }
    }

    #[test]
    fn replay_parses_bless_into_flag() {
        let cli = Cli::try_parse_from([
            "chio",
            "replay",
            "capture.ndjson",
            "--bless",
            "--into",
            "tests/replay/goldens/family/name",
        ])
        .unwrap();
        match cli.command {
            Commands::Replay(args) => {
                assert!(args.bless);
                assert_eq!(
                    args.into.as_deref(),
                    Some(Path::new("tests/replay/goldens/family/name"))
                );
            }
            _ => panic!("expected replay subcommand"),
        }
    }

    #[test]
    fn replay_parses_traffic_subcommand() {
        let cli = Cli::try_parse_from([
            "chio",
            "replay",
            "traffic",
            "--from",
            "capture.ndjson",
        ])
        .unwrap();
        match cli.command {
            Commands::Replay(args) => {
                assert!(args.log.is_none(), "positional <log> absent under traffic");
                match args.command.as_ref() {
                    Some(ReplaySubcommand::Traffic(t)) => {
                        assert_eq!(t.from, PathBuf::from("capture.ndjson"));
                        assert_eq!(t.schema, "chio-tee-frame.v1");
                        assert!(t.tenant_pubkey.is_none());
                        assert!(!t.json);
                    }
                    _ => panic!("expected traffic sub-subcommand"),
                }
            }
            _ => panic!("expected replay subcommand"),
        }
    }

    #[test]
    fn replay_parses_traffic_full_flag_set() {
        let cli = Cli::try_parse_from([
            "chio",
            "replay",
            "traffic",
            "--from",
            "capture.ndjson",
            "--schema",
            "chio-tee-frame.v1",
            "--tenant-pubkey",
            "/etc/chio/tenant.pub",
            "--json",
        ])
        .unwrap();
        match cli.command {
            Commands::Replay(args) => match args.command.as_ref() {
                Some(ReplaySubcommand::Traffic(t)) => {
                    assert_eq!(t.from, PathBuf::from("capture.ndjson"));
                    assert_eq!(t.schema, "chio-tee-frame.v1");
                    assert_eq!(
                        t.tenant_pubkey.as_deref(),
                        Some(Path::new("/etc/chio/tenant.pub"))
                    );
                    assert!(t.json);
                    assert!(t.against.is_none());
                    assert!(t.run_id.is_none());
                }
                _ => panic!("expected traffic sub-subcommand"),
            },
            _ => panic!("expected replay subcommand"),
        }
    }

    #[test]
    fn replay_parses_traffic_against_and_run_id_flags() {
        let cli = Cli::try_parse_from([
            "chio",
            "replay",
            "traffic",
            "--from",
            "capture.ndjson",
            "--against",
            "path:/etc/chio/policy.yaml",
            "--run-id",
            "ci-2026-04-25",
        ])
        .unwrap();
        match cli.command {
            Commands::Replay(args) => match args.command.as_ref() {
                Some(ReplaySubcommand::Traffic(t)) => {
                    assert_eq!(t.against.as_deref(), Some("path:/etc/chio/policy.yaml"));
                    assert_eq!(t.run_id.as_deref(), Some("ci-2026-04-25"));
                }
                _ => panic!("expected traffic sub-subcommand"),
            },
            _ => panic!("expected replay subcommand"),
        }
    }
}
