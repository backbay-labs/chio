// `chio replay traffic` dispatcher.
//
// Composes the NDJSON frame iterator with the validators in `replay/validate.rs`
// (schema-version gate, tenant-sig verifier, M01 invocation validator) and emits
// per-frame output. When `--against` is supplied, routes to the re-execution
// path in `replay/execute.rs`.

/// Dispatch `chio replay traffic` against the supplied [`TrafficArgs`].
///
/// Per-frame pipeline: NDJSON parse, schema-version gate, optional tenant-sig
/// verify, M01 invocation validate. When `--against` is supplied, routes
/// through [`run_traffic_replay`] instead.
fn cmd_replay_traffic(args: &TrafficArgs) -> Result<(), CliError> {
    if let Some(against_str) = args.against.as_deref() {
        return cmd_replay_traffic_with_against(args, against_str);
    }
    let pubkey = match args.tenant_pubkey.as_deref() {
        Some(path) => Some(load_tenant_pubkey(path).map_err(|e| {
            CliError::Other(format!("failed to load tenant pubkey: {e}"))
        })?),
        None => None,
    };

    let iter = open_ndjson(&args.from).map_err(|e| {
        CliError::Other(format!(
            "failed to open ndjson capture {}: {e}",
            args.from.display()
        ))
    })?;

    let mut total: u64 = 0;
    let mut passes: u64 = 0;
    let mut first_error: Option<(u64, String, i32)> = None;

    let mut stdout = std::io::stdout().lock();
    if !args.json {
        writeln!(
            stdout,
            "chio replay traffic: validating {} (schema={})",
            args.from.display(),
            args.schema,
        )
        .map_err(|e| CliError::Other(format!("write stdout: {e}")))?;
    }

    for record in iter {
        total = total.saturating_add(1);
        match record {
            Ok(record) => {
                match validate_frame(&record.frame, &args.schema, pubkey.as_ref()) {
                    Ok(()) => {
                        passes = passes.saturating_add(1);
                        if !args.json {
                            writeln!(
                                stdout,
                                "  line {:>4}: ok ({})",
                                record.line, record.frame.event_id,
                            )
                            .map_err(|e| {
                                CliError::Other(format!("write stdout: {e}"))
                            })?;
                        }
                    }
                    Err(err) => {
                        let exit = err.exit_code();
                        let msg = err.to_string();
                        if first_error.is_none() {
                            first_error = Some((record.line, msg.clone(), exit));
                        }
                        if !args.json {
                            writeln!(
                                stdout,
                                "  line {:>4}: FAIL exit={exit} {msg}",
                                record.line,
                            )
                            .map_err(|e| {
                                CliError::Other(format!("write stdout: {e}"))
                            })?;
                        }
                    }
                }
            }
            Err(err) => {
                let line = err.line();
                let msg = err.to_string();
                // NDJSON parse / IO errors map to exit code 30.
                if first_error.is_none() {
                    first_error = Some((line, msg.clone(), EXIT_PARSE_ERROR));
                }
                if !args.json {
                    writeln!(
                        stdout,
                        "  line {:>4}: FAIL exit={EXIT_PARSE_ERROR} {msg}",
                        line,
                    )
                    .map_err(|e| CliError::Other(format!("write stdout: {e}")))?;
                }
            }
        }
    }

    if total == 0 {
        first_error = Some((
            0,
            "empty capture cannot be replayed as clean evidence".to_string(),
            EXIT_PARSE_ERROR,
        ));
    }

    if args.json {
        // Flat JSON object so CI scripts can grep "ok" / "fail".
        let payload = serde_json::json!({
            "schema": args.schema,
            "from": args.from.display().to_string(),
            "total": total,
            "passes": passes,
            "ok": first_error.is_none(),
            "first_error": first_error.as_ref().map(|(line, msg, exit)| {
                serde_json::json!({
                    "line": line,
                    "message": msg,
                    "exit_code": exit,
                })
            }),
        });
        let serialized = serde_json::to_string(&payload)
            .map_err(|e| CliError::Other(format!("serialize report: {e}")))?;
        writeln!(stdout, "{serialized}")
            .map_err(|e| CliError::Other(format!("write stdout: {e}")))?;
    } else {
        writeln!(
            stdout,
            "chio replay traffic: {passes}/{total} frames passed",
        )
        .map_err(|e| CliError::Other(format!("write stdout: {e}")))?;
    }

    if let Some((line, msg, exit)) = first_error {
        return finish_replay_failure(
            exit,
            format!("chio replay traffic: validation failed on line {line}: {msg}"),
        );
    }
    Ok(())
}

/// Canonical exit code: parse error (NDJSON unreadable or structurally
/// invalid).
const EXIT_PARSE_ERROR: i32 = 30;

/// Re-execution arm of `chio replay traffic --against`.
///
/// Parses `against_str` into a [`PolicyRef`], runs [`run_traffic_replay`],
/// and renders a human or `--json` diff report.
fn cmd_replay_traffic_with_against(
    args: &TrafficArgs,
    against_str: &str,
) -> Result<(), CliError> {
    let against = PolicyRef::parse(against_str)
        .map_err(|e| CliError::Other(format!("--against parse failed: {e}")))?;
    let report = match run_traffic_replay(args, &against) {
        Ok(report) => report,
        Err(ExecuteError::MissingTenantPubkey) => {
            return finish_replay_failure(
                EXIT_BAD_TENANT_SIG,
                "chio replay traffic --against requires --tenant-pubkey"
                    .to_string(),
            );
        }
        Err(err) => {
            return Err(CliError::Other(format!(
                "chio replay traffic --against: {err}"
            )));
        }
    };
    let diff = build_traffic_diff_report(&report);

    let mut stdout = std::io::stdout().lock();
    if args.json {
        render_traffic_diff_json(&mut stdout, &diff)
            .map_err(|e| CliError::Other(format!("write stdout: {e}")))?;
    } else {
        render_traffic_diff_human(&mut stdout, &diff)
            .map_err(|e| CliError::Other(format!("write stdout: {e}")))?;
    }

    if !diff.ok() {
        let exit = traffic_diff_exit_code(&diff);
        return finish_replay_failure(
            exit,
            format!(
                "chio replay traffic --against: report has drift/errors ({} drift, {} error)",
                diff.drifts, diff.errors,
            ),
        );
    }
    Ok(())
}

fn traffic_diff_exit_code(diff: &TrafficReplayDiffReport) -> i32 {
    if let Some(error) = diff.error_outcomes.first() {
        let detail = error.error.as_str();
        if detail.contains("ndjson parse error")
            || detail.contains("ndjson io error")
            || detail.contains("empty capture")
        {
            return EXIT_PARSE_ERROR;
        }
        if detail.contains("redaction") {
            return EXIT_REDACTION_MISMATCH;
        }
        if detail.contains("schema") || detail.contains("invocation") {
            return EXIT_SCHEMA_MISMATCH;
        }
        return EXIT_BAD_TENANT_SIG;
    }
    if diff.drifts > 0 {
        return EXIT_VERDICT_DRIFT;
    }
    0
}

#[cfg(not(test))]
fn finish_replay_failure(code: i32, _message: String) -> Result<(), CliError> {
    std::process::exit(code);
}

#[cfg(test)]
fn finish_replay_failure(_code: i32, message: String) -> Result<(), CliError> {
    Err(CliError::Other(message))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_traffic_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signing_keypair() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn canonical_invocation() -> serde_json::Value {
        use chio_tool_call_fabric::{
            Principal, ProviderId, ProvenanceStamp, ToolInvocation,
        };
        use std::time::SystemTime;
        let invocation = ToolInvocation {
            provider: ProviderId::OpenAi,
            tool_name: "search".to_string(),
            arguments: br#"{"q":"hello"}"#.to_vec(),
            provenance: ProvenanceStamp {
                provider: ProviderId::OpenAi,
                request_id: "req_abc".to_string(),
                api_version: "2025-10-01".to_string(),
                principal: Principal::OpenAiOrg {
                    org_id: "org_42".to_string(),
                },
                received_at: SystemTime::UNIX_EPOCH,
            },
        };
        let bytes = chio_core::canonical::canonical_json_bytes(&invocation).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn signed_frame(kp: &SigningKey) -> chio_tee_frame::Frame {
        use base64::Engine;
        let mut frame = chio_tee_frame::Frame {
            schema_version: chio_tee_frame::SCHEMA_VERSION.to_string(),
            event_id: "01H7ZZZZZZZZZZZZZZZZZZZZZZ".to_string(),
            ts: "2026-04-25T18:02:11.418Z".to_string(),
            tee_id: "tee-prod-1".to_string(),
            upstream: chio_tee_frame::Upstream {
                system: chio_tee_frame::UpstreamSystem::Openai,
                operation: "responses.create".to_string(),
                api_version: "2025-10-01".to_string(),
            },
            invocation: canonical_invocation(),
            provenance: chio_tee_frame::Provenance {
                otel: chio_tee_frame::Otel {
                    trace_id: "0".repeat(32),
                    span_id: "0".repeat(16),
                },
                supply_chain: None,
            },
            request_blob_sha256: "a".repeat(64),
            response_blob_sha256: "b".repeat(64),
            redaction_pass_id: "m06-redactors@1.4.0+default".to_string(),
            verdict: chio_tee_frame::Verdict::Allow,
            deny_reason: None,
            would_have_blocked: false,
            tenant_sig: format!("ed25519:{}", "A".repeat(86)),
        };
        let payload = signing_payload(&frame).unwrap();
        let sig = kp.sign(&payload);
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        frame.tenant_sig = format!("ed25519:{encoded}");
        frame
    }

    #[test]
    fn full_pipeline_passes_on_signed_frame() {
        let kp = signing_keypair();
        let frame = signed_frame(&kp);
        let dir = tempfile::tempdir().unwrap();
        let ndjson_path = dir.path().join("capture.ndjson");
        let line = serde_json::to_string(&frame).unwrap();
        std::fs::write(&ndjson_path, format!("{line}\n")).unwrap();

        let pk_path = dir.path().join("tenant.pub");
        std::fs::write(&pk_path, kp.verifying_key().to_bytes()).unwrap();

        let args = TrafficArgs {
            from: ndjson_path,
            schema: "chio-tee-frame.v1".to_string(),
            tenant_pubkey: Some(pk_path),
            json: true,
            against: None,
            run_id: None,
        };
        cmd_replay_traffic(&args).unwrap();
    }

    #[test]
    fn pipeline_surfaces_first_failure_when_signature_tampered() {
        let kp = signing_keypair();
        let mut frame = signed_frame(&kp);
        frame.tee_id = "tee-prod-2".to_string();
        let dir = tempfile::tempdir().unwrap();
        let ndjson_path = dir.path().join("capture.ndjson");
        let line = serde_json::to_string(&frame).unwrap();
        std::fs::write(&ndjson_path, format!("{line}\n")).unwrap();

        let pk_path = dir.path().join("tenant.pub");
        std::fs::write(&pk_path, kp.verifying_key().to_bytes()).unwrap();

        let args = TrafficArgs {
            from: ndjson_path,
            schema: "chio-tee-frame.v1".to_string(),
            tenant_pubkey: Some(pk_path),
            json: true,
            against: None,
            run_id: None,
        };
        let err = cmd_replay_traffic(&args).unwrap_err();
        match err {
            CliError::Other(msg) => {
                assert!(
                    msg.contains("tenant signature verification failed"),
                    "msg: {msg}"
                );
            }
            other => panic!("expected CliError::Other, got {other:?}"),
        }
    }

    #[test]
    fn pipeline_skips_signature_when_pubkey_absent() {
        let kp = signing_keypair();
        let frame = signed_frame(&kp);
        let dir = tempfile::tempdir().unwrap();
        let ndjson_path = dir.path().join("capture.ndjson");
        let line = serde_json::to_string(&frame).unwrap();
        std::fs::write(&ndjson_path, format!("{line}\n")).unwrap();

        let args = TrafficArgs {
            from: ndjson_path,
            schema: "chio-tee-frame.v1".to_string(),
            tenant_pubkey: None,
            json: true,
            against: None,
            run_id: None,
        };
        cmd_replay_traffic(&args).unwrap();
    }

    #[test]
    fn pipeline_surfaces_parse_error_for_malformed_line() {
        let dir = tempfile::tempdir().unwrap();
        let ndjson_path = dir.path().join("capture.ndjson");
        std::fs::write(&ndjson_path, "{not valid json\n").unwrap();

        let args = TrafficArgs {
            from: ndjson_path,
            schema: "chio-tee-frame.v1".to_string(),
            tenant_pubkey: None,
            json: true,
            against: None,
            run_id: None,
        };
        let err = cmd_replay_traffic(&args).unwrap_err();
        match err {
            CliError::Other(msg) => assert!(msg.contains("ndjson"), "msg: {msg}"),
            other => panic!("expected CliError::Other, got {other:?}"),
        }
    }

    #[test]
    fn exit_parse_error_constant_matches_m04_registry() {
        assert_eq!(EXIT_PARSE_ERROR, 30);
    }
}
