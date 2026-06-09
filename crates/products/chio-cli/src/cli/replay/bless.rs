// `chio replay --bless --into <fixture-dir>` dispatcher.

use super::*;

pub(crate) fn cmd_replay_bless(args: &ReplayArgs, log: &Path) -> Result<(), CliError> {
    let into = args.into.as_ref().ok_or_else(|| {
        CliError::cli_other_error("chio replay --bless requires --into <fixture-dir>".to_string())
    })?;
    let Some(tenant_pubkey_path) = args.tenant_pubkey.as_deref() else {
        return finish_replay_failure(
            EXIT_BAD_TENANT_SIG,
            "chio replay --bless requires --tenant-pubkey".to_string(),
        );
    };

    require_replay_bless_capability()?;
    let scenario = validate_replay_bless_into_path(into)?;
    let tenant_pubkey = load_tenant_pubkey(tenant_pubkey_path)
        .map_err(|error| CliError::cli_other_error(format!("failed to load tenant pubkey: {error}")))?;

    let iter = open_ndjson(log).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to open TEE capture {}: {error}",
            log.display()
        ))
    })?;
    let mut frames = Vec::new();
    for record in iter {
        let record = record.map_err(|error| {
            CliError::replay_mismatch_error(format!(
                "failed to parse TEE capture {}: {error}",
                log.display()
            ))
        })?;
        if let Err(err) = validate_frame(&record.frame, "chio-tee-frame.v1", Some(&tenant_pubkey)) {
            return finish_replay_failure(
                err.exit_code(),
                format!(
                    "chio replay --bless: validation failed on line {}: {err}",
                    record.line,
                ),
            );
        }
        frames.push(record.frame);
    }

    let summary = chio_replay_corpus::write_fixture(into, frames)
        .map_err(map_replay_fixture_error)?;

    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "chio replay bless: wrote {}/{} to {}",
        scenario.family,
        scenario.name,
        summary.dir.display(),
    )
    .map_err(|error| CliError::cli_io_error(format!("write stdout: {error}")))?;
    writeln!(
        stdout,
        "  frames:        {} input, {} after dedupe",
        summary.frames_in, summary.frames_after_dedupe,
    )
    .map_err(|error| CliError::cli_io_error(format!("write stdout: {error}")))?;
    writeln!(stdout, "  receipts:      {}", summary.receipt_count)
        .map_err(|error| CliError::cli_io_error(format!("write stdout: {error}")))?;
    writeln!(stdout, "  root:          {}", summary.root_hex)
        .map_err(|error| CliError::cli_io_error(format!("write stdout: {error}")))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_bless_tests {
    use super::*;
    use base64::Engine;
    use chio_tee_frame::{Frame, FrameInputs, Otel, Provenance, Upstream, UpstreamSystem, Verdict};
    use chio_tool_call_fabric::{Principal, ProvenanceStamp, ProviderId, ToolInvocation};
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::{Mutex, OnceLock};
    use std::time::SystemTime;

    fn replay_bless_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct ReplayBlessEnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for ReplayBlessEnvGuard {
        fn drop(&mut self) {
            std::env::remove_var(REPLAY_BLESS_CAPABILITY_ENV);
        }
    }

    fn set_replay_bless_capability() -> ReplayBlessEnvGuard {
        let lock = replay_bless_env_lock().lock().unwrap();
        std::env::set_var(REPLAY_BLESS_CAPABILITY_ENV, REPLAY_BLESS_CAPABILITY);
        ReplayBlessEnvGuard { _lock: lock }
    }

    fn signing_keypair() -> SigningKey {
        SigningKey::from_bytes(&[19u8; 32])
    }

    fn canonical_invocation() -> serde_json::Value {
        let invocation = ToolInvocation {
            provider: ProviderId::OpenAi,
            tool_name: "send".to_string(),
            arguments: br#"{"email":"alice@example.com"}"#.to_vec(),
            provenance: ProvenanceStamp {
                provider: ProviderId::OpenAi,
                request_id: "req_bless_1".to_string(),
                api_version: "2025-10-01".to_string(),
                principal: Principal::OpenAiOrg {
                    org_id: "org_chio_demo".to_string(),
                },
                received_at: SystemTime::UNIX_EPOCH,
            },
        };
        let bytes = chio_core::canonical::canonical_json_bytes(&invocation).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn signed_frame(keypair: &SigningKey) -> Frame {
        let mut frame = Frame::build(FrameInputs {
            event_id: "01H7ZZZZZZZZZZZZZZZZZZZZZA".to_string(),
            ts: "2026-04-25T18:02:11.418Z".to_string(),
            tee_id: "tee-test-1".to_string(),
            upstream: Upstream {
                system: UpstreamSystem::Openai,
                operation: "responses.create".to_string(),
                api_version: "2025-10-01".to_string(),
            },
            invocation: canonical_invocation(),
            provenance: Provenance {
                otel: Otel {
                    trace_id: "0".repeat(32),
                    span_id: "0".repeat(16),
                },
                supply_chain: None,
            },
            request_blob_sha256: "a".repeat(64),
            response_blob_sha256: "b".repeat(64),
            redaction_pass_id: chio_replay_corpus::DEFAULT_REDACTION_PASS_ID.to_string(),
            verdict: Verdict::Allow,
            deny_reason: None,
            would_have_blocked: false,
            tenant_sig: format!(
                "ed25519:{}",
                base64::engine::general_purpose::STANDARD.encode([0u8; 64])
            ),
        })
        .unwrap();
        let payload = signing_payload(&frame).unwrap();
        let sig = keypair.sign(&payload);
        frame.tenant_sig = format!(
            "ed25519:{}",
            base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
        );
        frame
    }

    fn frame_json(keypair: &SigningKey) -> String {
        let frame = signed_frame(keypair);
        serde_json::to_string(&frame).unwrap()
    }

    #[test]
    fn bless_dispatch_writes_fixture_when_capability_is_present() {
        let _env_guard = set_replay_bless_capability();
        let tmp = tempfile::TempDir::new().unwrap();
        let keypair = signing_keypair();
        let pubkey = tmp.path().join("tenant.pub");
        fs::write(&pubkey, keypair.verifying_key().to_bytes()).unwrap();
        let capture = tmp.path().join("capture.ndjson");
        fs::write(&capture, format!("{}\n", frame_json(&keypair))).unwrap();
        let into = tmp.path().join("family").join("name");

        let args = ReplayArgs {
            log: Some(capture.clone()),
            from_tee: false,
            tenant_pubkey: Some(pubkey),
            trusted_kernel_pubkey: None,
            expect_root: None,
            json: false,
            bless: true,
            into: Some(into.clone()),
            command: None,
        };

        cmd_replay_bless(&args, &capture).unwrap();

        assert!(into.join(chio_replay_corpus::RECEIPTS_FILENAME).is_file());
        let receipts =
            fs::read_to_string(into.join(chio_replay_corpus::RECEIPTS_FILENAME)).unwrap();
        assert!(!receipts.contains("tenant_sig"));
        assert!(!receipts.contains("alice@example.com"));
    }

    #[test]
    fn bless_dispatch_requires_tenant_pubkey() {
        let _env_guard = set_replay_bless_capability();
        let tmp = tempfile::TempDir::new().unwrap();
        let keypair = signing_keypair();
        let capture = tmp.path().join("capture.ndjson");
        fs::write(&capture, format!("{}\n", frame_json(&keypair))).unwrap();
        let into = tmp.path().join("family").join("name");

        let args = ReplayArgs {
            log: Some(capture.clone()),
            from_tee: false,
            tenant_pubkey: None,
            trusted_kernel_pubkey: None,
            expect_root: None,
            json: false,
            bless: true,
            into: Some(into),
            command: None,
        };

        let err = cmd_replay_bless(&args, &capture).unwrap_err();

        assert!(err
            .to_string()
            .contains("chio replay --bless requires --tenant-pubkey"));
    }
}
