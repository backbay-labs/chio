use std::error::Error;

use super::cli_entrypoint_support::{fixture_path, parse_cli, render_error_json};
use super::*;

#[test]
fn chio_attest_buyer_packet_surface_parses() {
    let cli = parse_cli([
        "chio",
        "attest",
        "buyer",
        "packet",
        "--run-output",
        "runtime-output",
        "--out",
        "buyer-packet.json",
    ])
    .unwrap();

    match cli.command {
        Commands::Attest {
            command:
                ChioAttestCommands::Buyer {
                    command: ChioBuyerCommands::Packet { run_output, out },
                },
        } => {
            assert_eq!(run_output, std::path::PathBuf::from("runtime-output"));
            assert_eq!(out, std::path::PathBuf::from("buyer-packet.json"));
        }
        _ => panic!("expected chio attest buyer packet surface"),
    }
}

#[test]
fn chio_attest_buyer_public_outputs_use_chio_error_and_schema_boundary(
) -> Result<(), Box<dyn Error>> {
    let tempdir = tempfile::tempdir()?;
    let missing_run_output = tempdir.path().join("missing-run-output");
    let package_out = tempdir.path().join("buyer-review-package.json");

    let error = cmd_chio_attest_buyer_package(&missing_run_output, &package_out)
        .expect_err("missing public buyer run output must fail");
    let rendered = render_error_json(&error)?;
    let rendered_text = rendered.to_string();
    assert!(
        rendered_text.contains("Chio buyer run output"),
        "public buyer error should describe the Chio buyer boundary: {rendered_text}"
    );

    let report_path = tempdir.path().join("buyer-review-report.json");
    let explanation_out = tempdir.path().join("buyer-explanation.json");
    std::fs::write(
        &report_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": chio_attest_buyer::CHIO_ATTEST_BUYER_ATTESTATION_REVIEW_REPORT_SCHEMA,
            "packageId": "buyer-review:packet-1",
            "packetId": "packet-1",
            "accepted": true,
            "checks": []
        }))?,
    )?;

    cmd_chio_attest_buyer_explain(&report_path, "json", &explanation_out)?;
    let explanation: serde_json::Value = serde_json::from_slice(&std::fs::read(&explanation_out)?)?;
    assert_eq!(
        explanation["schema"],
        "chio.attest.buyer-attestation-explanation.v1"
    );

    Ok(())
}

#[test]
fn chio_attest_buyer_verify_rejection_uses_transaction_failure_code() -> Result<(), Box<dyn Error>>
{
    let tempdir = tempfile::tempdir()?;
    let package_path = tempdir.path().join("buyer-review-package.json");
    let trust_bundle_path = tempdir.path().join("trust-bundle.json");
    let context_path = tempdir.path().join("verification-context.json");
    let report_path = tempdir.path().join("buyer-review-report.json");

    std::fs::write(
        &package_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": chio_attest_buyer::CHIO_ATTEST_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA,
            "packageId": "buyer-review:transaction-code",
            "packetId": "buyer-packet:transaction-code",
            "buyerId": "did:chio:buyer",
            "generatedAtUnixMs": 1_766_000_000_000_u64,
            "artifacts": []
        }))?,
    )?;
    std::fs::write(&trust_bundle_path, "{}")?;
    std::fs::write(&context_path, "{}")?;

    let error = cmd_chio_attest_buyer_verify(
        &package_path,
        &trust_bundle_path,
        &context_path,
        &report_path,
    )
    .expect_err("missing buyer review artifacts must reject");
    let rendered = render_error_json(&error)?;
    assert_eq!(
        rendered["code"],
        "urn:chio:error:transaction:buyer-review-rejected"
    );
    assert!(rendered["message"]
        .as_str()
        .expect("buyer review rejection message")
        .contains("chio_attest_buyer_review_missing_artifact_role"));

    Ok(())
}

#[test]
fn chio_attest_buyer_verify_packet_surface_parses() {
    let cli = parse_cli([
        "chio",
        "attest",
        "buyer",
        "verify-packet",
        "--packet",
        "packet.json",
        "--lineage-statement",
        "lineage.json",
        "--continuation",
        "continuation.json",
        "--admission-report",
        "admission.json",
        "--bilateral-invocation",
        "bilateral.json",
        "--report",
        "report.json",
    ])
    .unwrap();

    match cli.command {
        Commands::Attest {
            command:
                ChioAttestCommands::Buyer {
                    command:
                        ChioBuyerCommands::VerifyPacket {
                            packet,
                            lineage_statement,
                            continuation,
                            admission_report,
                            bilateral_invocation,
                            report,
                        },
                },
        } => {
            assert_eq!(packet, std::path::PathBuf::from("packet.json"));
            assert_eq!(lineage_statement, std::path::PathBuf::from("lineage.json"));
            assert_eq!(continuation, std::path::PathBuf::from("continuation.json"));
            assert_eq!(admission_report, std::path::PathBuf::from("admission.json"));
            assert_eq!(
                bilateral_invocation,
                std::path::PathBuf::from("bilateral.json")
            );
            assert_eq!(report, std::path::PathBuf::from("report.json"));
        }
        _ => panic!("expected chio attest buyer verify-packet surface"),
    }
}

#[test]
fn chio_attest_supply_chain_verify_surface_parses() {
    let cli = parse_cli([
        "chio",
        "attest",
        "supply-chain",
        "verify",
        "--artifact",
        "chio.tar.gz",
        "--bundle",
        "chio.tar.gz.bundle",
        "--issuer-san-regex",
        "https://github.com/chio/.+",
        "--issuer-oidc",
        "https://token.actions.githubusercontent.com",
        "--report",
        "supply-chain-report.json",
    ])
    .unwrap();

    match cli.command {
        Commands::Attest {
            command:
                ChioAttestCommands::SupplyChain {
                    command:
                        ChioSupplyChainCommands::Verify {
                            artifact,
                            bundle,
                            issuer_san_regex,
                            issuer_oidc,
                            report,
                        },
                },
        } => {
            assert_eq!(artifact, std::path::PathBuf::from("chio.tar.gz"));
            assert_eq!(bundle, std::path::PathBuf::from("chio.tar.gz.bundle"));
            assert_eq!(issuer_san_regex, "https://github.com/chio/.+");
            assert_eq!(issuer_oidc, "https://token.actions.githubusercontent.com");
            assert_eq!(
                report,
                Some(std::path::PathBuf::from("supply-chain-report.json"))
            );
        }
        _ => panic!("expected chio attest supply-chain verify surface"),
    }
}

#[test]
fn chio_attest_runtime_quote_verify_surface_parses() {
    let cli = parse_cli([
            "chio",
            "attest",
            "runtime-quote",
            "verify",
            "--kernel-public-key",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--receipt-root",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--report-data",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--tee-kind",
            "intel-tdx",
            "--quote",
            "quote.bin",
            "--collateral",
            "collateral.json",
            "--report",
            "runtime-quote-report.json",
        ])
        .unwrap();

    match cli.command {
        Commands::Attest {
            command:
                ChioAttestCommands::RuntimeQuote {
                    command:
                        ChioRuntimeQuoteCommands::Verify {
                            kernel_public_key,
                            receipt_root,
                            report_data,
                            tee_kind,
                            quote,
                            collateral,
                            report,
                        },
                },
        } => {
            assert_eq!(
                kernel_public_key,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            );
            assert_eq!(
                receipt_root,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            );
            assert_eq!(report_data.as_deref().map(str::len), Some(128));
            assert_eq!(tee_kind.as_deref(), Some("intel-tdx"));
            assert_eq!(quote, Some(std::path::PathBuf::from("quote.bin")));
            assert_eq!(
                collateral,
                Some(std::path::PathBuf::from("collateral.json"))
            );
            assert_eq!(
                report,
                Some(std::path::PathBuf::from("runtime-quote-report.json"))
            );
        }
        _ => panic!("expected chio attest runtime-quote verify surface"),
    }
}

#[test]
fn chio_attest_runtime_quote_report_data_only_is_unresolved() {
    let kernel_public_key = chio_core_types::Keypair::from_seed(&[9u8; 32]).public_key();
    let receipt_root = [8u8; 32];
    let report_data = chio_attest_verify::expect_report_data(&kernel_public_key, &receipt_root);

    let error = cmd_chio_attest_runtime_quote_verify(
        &kernel_public_key.to_hex(),
        &hex::encode(receipt_root),
        Some(&hex::encode(report_data)),
        None,
        None,
        None,
        None,
    )
    .err();

    assert!(matches!(
        error,
        Some(CliError::Other(message))
            if message.contains("requires full quote evidence")
    ));
}

#[cfg(not(feature = "tee-quotes"))]
#[test]
fn chio_attest_runtime_quote_default_build_rejects_backend_claims() {
    let tempdir = tempfile::tempdir().unwrap();
    let quote = tempdir.path().join("quote.bin");
    let collateral = tempdir.path().join("collateral.json");
    let report = tempdir.path().join("report.json");
    std::fs::write(&quote, b"not-a-real-quote").unwrap();
    std::fs::write(&collateral, b"{}").unwrap();

    let kernel_public_key = chio_core_types::Keypair::from_seed(&[9u8; 32]).public_key();
    let receipt_root = [8u8; 32];
    let error = cmd_chio_attest_runtime_quote_verify(
        &kernel_public_key.to_hex(),
        &hex::encode(receipt_root),
        None,
        Some("intel-tdx"),
        Some(&quote),
        Some(&collateral),
        Some(&report),
    )
    .err();

    assert!(matches!(
        error,
        Some(CliError::Other(message)) if message.contains("tee-quotes feature")
    ));
    let rendered: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    assert_eq!(rendered["accepted"], false);
    assert_eq!(
        rendered["failureCode"].as_str(),
        Some("tee_quote_feature_disabled")
    );
}

#[test]
fn chio_native_federation_treaty_surface_parses() {
    let cli = parse_cli([
        "chio",
        "federation",
        "treaty",
        "verify-packet",
        "--packet",
        "buyer-packet.json",
        "--lineage-statement",
        "lineage.json",
        "--continuation",
        "continuation.json",
        "--admission-report",
        "admission.json",
        "--bilateral-invocation",
        "bilateral.json",
        "--report",
        "verification.json",
    ])
    .unwrap();

    match cli.command {
        Commands::Federation {
            command:
                ChioFederationCommands::Treaty {
                    command:
                        ChioTreatyCommands::VerifyPacket {
                            packet,
                            lineage_statement,
                            continuation,
                            admission_report,
                            bilateral_invocation,
                            report,
                        },
                },
        } => {
            assert_eq!(packet, std::path::PathBuf::from("buyer-packet.json"));
            assert_eq!(lineage_statement, std::path::PathBuf::from("lineage.json"));
            assert_eq!(continuation, std::path::PathBuf::from("continuation.json"));
            assert_eq!(admission_report, std::path::PathBuf::from("admission.json"));
            assert_eq!(
                bilateral_invocation,
                std::path::PathBuf::from("bilateral.json")
            );
            assert_eq!(report, std::path::PathBuf::from("verification.json"));
        }
        _ => panic!("expected chio federation treaty surface"),
    }
}

#[test]
fn chio_native_runtime_surface_parses() {
    let cli = parse_cli([
        "chio",
        "runtime",
        "sign-trust-input",
        "--body",
        "runtime-trust-input.json",
        "--signing-seed-file",
        "runtime-seed.hex",
        "--out",
        "signed-runtime-trust-input.json",
    ])
    .unwrap();

    match cli.command {
        Commands::Runtime {
            command:
                ChioRuntimeCommands::SignTrustInput {
                    body,
                    signing_seed_file,
                    out,
                },
        } => {
            assert_eq!(body, std::path::PathBuf::from("runtime-trust-input.json"));
            assert_eq!(
                signing_seed_file,
                std::path::PathBuf::from("runtime-seed.hex")
            );
            assert_eq!(
                out,
                std::path::PathBuf::from("signed-runtime-trust-input.json")
            );
        }
        _ => panic!("expected chio runtime surface"),
    }
}

#[test]
fn chio_native_pheromone_surface_parses() {
    let cli = parse_cli([
        "chio",
        "pheromone",
        "query",
        "--store",
        "pheromone.sqlite3",
        "--subject-class",
        "support.ticket",
        "--namespace",
        "support",
        "--reputation-epoch",
        "42",
        "--peer-weights",
        "peer-weights.json",
        "--report",
        "pheromone-query.json",
    ])
    .unwrap();

    match cli.command {
        Commands::Pheromone {
            command:
                ChioPheromoneCommands::Query {
                    store,
                    subject_class,
                    namespace,
                    reputation_epoch,
                    peer_weights,
                    now_unix_ms,
                    report,
                },
        } => {
            assert_eq!(store, std::path::PathBuf::from("pheromone.sqlite3"));
            assert_eq!(subject_class, "support.ticket");
            assert_eq!(namespace, "support");
            assert_eq!(reputation_epoch, 42);
            assert_eq!(peer_weights, std::path::PathBuf::from("peer-weights.json"));
            assert!(now_unix_ms.is_none());
            assert_eq!(report, std::path::PathBuf::from("pheromone-query.json"));
        }
        _ => panic!("expected chio pheromone surface"),
    }
}

#[test]
fn chio_native_surfaces_remain_native_command_variants() {
    let runtime = parse_cli([
        "chio",
        "runtime",
        "sign-trust-input",
        "--body",
        "runtime-trust-input.json",
        "--signing-seed-file",
        "runtime-seed.hex",
        "--out",
        "signed-runtime-trust-input.json",
    ])
    .unwrap()
    .command;
    assert!(matches!(runtime, Commands::Runtime { .. }));

    let pheromone = parse_cli([
        "chio",
        "pheromone",
        "query",
        "--store",
        "pheromone.sqlite3",
        "--subject-class",
        "support.ticket",
        "--namespace",
        "support",
        "--reputation-epoch",
        "42",
        "--peer-weights",
        "peer-weights.json",
        "--report",
        "pheromone-query.json",
    ])
    .unwrap()
    .command;
    assert!(matches!(pheromone, Commands::Pheromone { .. }));

    let federation = parse_cli([
        "chio",
        "federation",
        "treaty",
        "intersect",
        "--treaty-scope",
        "treaty-scope.json",
        "--manifest",
        "ladder.json",
        "--now-unix-ms",
        "1766000000000",
        "--report",
        "intersection.json",
    ])
    .unwrap()
    .command;
    assert!(matches!(federation, Commands::Federation { .. }));

    let attest = parse_cli([
        "chio",
        "attest",
        "buyer",
        "packet",
        "--run-output",
        "runtime-output",
        "--out",
        "buyer-packet.json",
    ])
    .unwrap()
    .command;
    assert!(matches!(attest, Commands::Attest { .. }));
}

#[test]
fn chio_federation_treaty_dispatch_uses_chio_handlers() {
    let treaty_dispatch = include_str!("cli/dispatch/federation.rs");

    assert!(treaty_dispatch.contains("cmd_chio_federation_treaty_intersect("));
    assert!(treaty_dispatch.contains("cmd_chio_federation_treaty_admit("));
    assert!(treaty_dispatch.contains("cmd_chio_federation_treaty_verify_packet("));
    assert!(!treaty_dispatch.contains("cmd_chio_treaty_"));
}

#[test]
fn chio_federation_treaty_handlers_do_not_call_historical_runtime_directly() {
    let treaty_handlers = include_str!("cli/chio/dispatch/treaty.rs");

    assert!(!treaty_handlers.contains("chio_runtime_core::"));
}

#[test]
fn chio_runtime_dispatch_handlers_do_not_call_historical_runtime_directly() {
    let runtime_modules = [
        include_str!("cli/chio/dispatch/runtime.rs"),
        include_str!("cli/chio/dispatch/runtime/admission.rs"),
        include_str!("cli/chio/dispatch/runtime/io.rs"),
        include_str!("cli/chio/dispatch/runtime/loopback.rs"),
        include_str!("cli/chio/dispatch/runtime/ops.rs"),
        include_str!("cli/chio/dispatch/runtime/orchestration.rs"),
        include_str!("cli/chio/dispatch/runtime/signing.rs"),
    ];

    for module in runtime_modules {
        assert!(!module.contains("chio_runtime_core::"));
    }
}

#[test]
fn chio_runtime_active_subject_namespaces_are_chio_native() {
    let runtime_admission = include_str!("cli/chio/dispatch/runtime/admission.rs");
    let chio_namespace = format!("{}.{}", "chio", "runtime");
    let expected_assignment = format!("subject_class_namespace: \"{chio_namespace}\".to_string()");

    assert!(
            runtime_admission.contains(&expected_assignment),
            "active Chio runtime admission dispatch tests must exercise the Chio runtime subject namespace"
        );
}

#[test]
fn chio_federation_authority_dispatch_uses_chio_handlers() {
    let dispatch = include_str!("cli/dispatch/federation.rs");
    let authority_dispatch = dispatch
        .split("fn dispatch_chio_authority_command")
        .nth(1)
        .expect("dispatch_chio_authority_command exists")
        .split("fn dispatch_chio_treaty_command")
        .next()
        .expect("dispatch_chio_authority_command has following function");

    assert!(authority_dispatch.contains("cmd_chio_federation_authority_issue("));
    assert!(authority_dispatch.contains("cmd_chio_federation_authority_checkpoint("));
    assert!(authority_dispatch.contains("cmd_chio_federation_authority_trust_bundle_assemble("));
    assert!(!authority_dispatch.contains("cmd_chio_authority_"));
}

#[test]
fn chio_federation_dispatch_uses_chio_command_types() {
    let dispatch = include_str!("cli/dispatch/federation.rs");
    let authority_dispatch = dispatch
        .split("fn dispatch_chio_authority_command")
        .nth(1)
        .expect("dispatch_chio_authority_command exists")
        .split("fn dispatch_chio_treaty_command")
        .next()
        .expect("dispatch_chio_authority_command has following function");
    let treaty_dispatch = dispatch
        .split("fn dispatch_chio_treaty_command")
        .nth(1)
        .expect("dispatch_chio_treaty_command exists");

    assert!(authority_dispatch.contains("command: ChioAuthorityCommands"));
    assert!(authority_dispatch.contains("ChioAuthorityCommands::"));
    assert!(authority_dispatch.contains("ChioTrustBundleCommands::"));
    assert!(treaty_dispatch.contains("command: ChioTreatyCommands"));
    assert!(treaty_dispatch.contains("ChioTreatyCommands::"));
}

#[test]
fn chio_runtime_signing_dispatch_uses_chio_handlers() {
    let runtime_dispatch = include_str!("cli/dispatch/runtime.rs");

    assert!(runtime_dispatch.contains("cmd_chio_runtime_sign_trust_input("));
    assert!(runtime_dispatch.contains("cmd_chio_runtime_sign_policy("));
    assert!(runtime_dispatch.contains("cmd_chio_runtime_peer_weights_hash("));
    assert!(runtime_dispatch.contains("cmd_chio_runtime_sign_peer_weights("));
    assert!(runtime_dispatch.contains("cmd_chio_runtime_sign_pheromone_query_report("));
}


#[test]
fn chio_runtime_dispatch_uses_chio_command_types() {
    let runtime_dispatch = include_str!("cli/dispatch/runtime.rs");

    assert!(runtime_dispatch.contains("command: ChioRuntimeCommands"));
    assert!(runtime_dispatch.contains("ChioRuntimePolicyCommands::"));
    assert!(runtime_dispatch.contains("ChioRuntimePeerWeightsCommands::"));
    assert!(runtime_dispatch.contains("ChioRuntimePheromoneCommands::"));
    assert!(runtime_dispatch.contains("ChioRuntimeOrchestrateCommands::"));
    assert!(runtime_dispatch.contains("ChioRuntimeOpsCommands::"));
    assert!(runtime_dispatch.contains("ChioRuntimeOpsRetentionCommands::"));
}

#[test]
fn public_chio_runtime_pheromone_query_errors_use_chio_boundary() -> Result<(), Box<dyn Error>> {
    let tempdir = tempfile::tempdir()?;
    let query_report = tempdir.path().join("pheromone-query-report.json");
    let store = tempdir.path().join("runtime-admission-store.json");
    let report = tempdir.path().join("runtime-admission-report.json");
    std::fs::write(&query_report, "{}")?;

    let error = cmd_chio_runtime_admit(
        &fixture_path("runtime-spine/request.json"),
        &fixture_path("runtime-spine/profile.json"),
        &fixture_path("runtime-spine/bundle.json"),
        None,
        None,
        Some(&query_report),
        None,
        None,
        None,
        None,
        &store,
        1_766_000_000_500,
        &report,
    )
    .expect_err("invalid public Chio pheromone query report must fail before admission");
    let rendered = render_error_json(&error)?;
    let rendered_text = rendered.to_string();
    assert!(
        rendered_text.contains("Chio runtime pheromone query report"),
        "public runtime error should describe the Chio query-report boundary: {rendered_text}"
    );

    let runtime_admission = include_str!("cli/chio/dispatch/runtime/admission.rs");
    assert!(!runtime_admission.contains("Chio signed pheromone query report parse"));

    Ok(())
}

#[test]
fn chio_pheromone_core_relay_dispatch_uses_chio_handlers() {
    let pheromone_dispatch = include_str!("cli/dispatch/pheromone.rs");

    let chio_handlers = [
        "cmd_chio_pheromone_relay_lint(",
        "cmd_chio_pheromone_relay_serve(",
        "cmd_chio_pheromone_relay_enqueue(",
        "cmd_chio_pheromone_relay_tick(",
        "cmd_chio_pheromone_relay_catchup(",
        "cmd_chio_pheromone_relay_status(",
        "cmd_chio_pheromone_relay_observe(",
        "cmd_chio_pheromone_relay_metrics(",
        "cmd_chio_pheromone_relay_trend(",
    ];

    for handler in chio_handlers {
        assert!(pheromone_dispatch.contains(handler), "{handler}");
    }
}

#[test]
fn public_chio_pheromone_verified_workflow_errors_use_chio_boundary() -> Result<(), Box<dyn Error>>
{
    let tempdir = tempfile::tempdir()?;
    let proof_package = tempdir.path().join("proof-package.json");
    let store = tempdir.path().join("pheromone.sqlite");
    let report = tempdir.path().join("receive-report.json");
    std::fs::write(&proof_package, "{}")?;

    let error = cmd_chio_pheromone_receive(
        &fixture_path("pheromone/gossip-batch.json"),
        &fixture_path("pheromone/transit-policy.json"),
        &proof_package,
        &fixture_path("verifier-trust-bundle.json"),
        &fixture_path("verification-context.json"),
        &store,
        Some(1_766_000_000_500),
        &report,
    )
    .expect_err("invalid public Chio proof package must fail before receiving");
    let rendered = render_error_json(&error)?;
    let rendered_text = rendered.to_string();
    assert!(
        rendered_text.contains("Chio proof package"),
        "public pheromone error should describe the Chio proof boundary: {rendered_text}"
    );

    let runtime_dispatch = include_str!("cli/chio/dispatch/pheromone/runtime.rs");
    let relay_dispatch = include_str!("cli/chio/dispatch/pheromone/relay.rs");
    for source in [runtime_dispatch, relay_dispatch] {
        assert!(!source.contains("Chio proof package"));
        assert!(!source.contains("Chio verifier trust bundle"));
        assert!(!source.contains("Chio verification context"));
        assert!(!source.contains("Chio package parse"));
        assert!(!source.contains("Chio trust bundle parse"));
        assert!(!source.contains("Chio context parse"));
        assert!(!source.contains("Chio workflow resolver"));
    }

    Ok(())
}

#[test]
fn chio_pheromone_dispatch_uses_chio_command_types() {
    let pheromone_dispatch = include_str!("cli/dispatch/pheromone.rs");

    assert!(pheromone_dispatch.contains("command: ChioPheromoneCommands"));
    assert!(pheromone_dispatch.contains("ChioPheromoneCommands::"));
    assert!(pheromone_dispatch.contains("ChioPheromoneRelayCommands::"));
    assert!(pheromone_dispatch.contains("ChioPheromoneRelayAlertCommands::"));
    assert!(pheromone_dispatch.contains("ChioPheromoneRelayAlertDeliveryCommands::"));
    assert!(pheromone_dispatch.contains("ChioPheromoneRelayAlertAssuranceCommands::"));
    assert!(pheromone_dispatch.contains("ChioPheromoneRelayAlertAssuranceRetentionCommands::"));
    assert!(pheromone_dispatch.contains("ChioPheromoneRelayAlertAssuranceArchiveCommands::"));
    assert!(pheromone_dispatch.contains("ChioPheromoneRelayAlertAssuranceArchivePackageCommands::"));
    assert!(pheromone_dispatch
        .contains("ChioPheromoneRelayAlertAssuranceArchiveRestoreDrillCommands::"));
    assert!(pheromone_dispatch.contains("ChioPheromoneRelayAlertAssuranceCloseoutCommands::"));
    assert!(pheromone_dispatch.contains("ChioPheromoneRelayAlertAssurancePhysicalDrillCommands::"));
    assert!(
        pheromone_dispatch.contains("ChioPheromoneRelayAlertAssuranceRetentionHandoffCommands::")
    );
    assert!(pheromone_dispatch.contains("ChioPheromoneRelayDirectoryCommands::"));
    assert!(pheromone_dispatch.contains("ChioPheromoneRelaySupervisorCommands::"));
}

#[test]
fn chio_pheromone_remaining_relay_dispatch_uses_chio_handlers() {
    let pheromone_dispatch = include_str!("cli/dispatch/pheromone.rs");

    let chio_handlers = [
        "cmd_chio_pheromone_relay_alert_evaluate(",
        "cmd_chio_pheromone_relay_alert_handoff(",
        "cmd_chio_pheromone_relay_alert_normalize(",
        "cmd_chio_pheromone_relay_alert_review(",
        "cmd_chio_pheromone_relay_alert_delivery_import(",
        "cmd_chio_pheromone_relay_alert_delivery_acknowledge(",
        "cmd_chio_pheromone_relay_alert_delivery_drift(",
        "cmd_chio_pheromone_relay_alert_delivery_drift_window(",
        "cmd_chio_pheromone_relay_alert_assurance_package(",
        "cmd_chio_pheromone_relay_alert_assurance_export(",
        "cmd_chio_pheromone_relay_alert_assurance_verify(",
        "cmd_chio_pheromone_relay_alert_assurance_replay(",
        "cmd_chio_pheromone_relay_alert_assurance_retention_plan(",
        "cmd_chio_pheromone_relay_alert_assurance_recovery_drill(",
        "cmd_chio_pheromone_relay_alert_assurance_archive_plan(",
        "cmd_chio_pheromone_relay_alert_assurance_archive_package_create(",
        "cmd_chio_pheromone_relay_alert_assurance_archive_package_verify(",
        "cmd_chio_pheromone_relay_alert_assurance_archive_package_extract(",
        "cmd_chio_pheromone_relay_alert_assurance_archive_restore_drill_review(",
        "cmd_chio_pheromone_relay_alert_assurance_closeout_review(",
        "cmd_chio_pheromone_relay_alert_assurance_physical_drill_review(",
        "cmd_chio_pheromone_relay_alert_assurance_retention_handoff_review(",
        "cmd_chio_pheromone_relay_alert_assurance_retention_external_review(",
        "cmd_chio_pheromone_relay_directory_inspect(",
        "cmd_chio_pheromone_relay_directory_promote(",
        "cmd_chio_pheromone_relay_directory_reject(",
        "cmd_chio_pheromone_relay_supervisor_lint(",
    ];

    for handler in chio_handlers {
        assert!(pheromone_dispatch.contains(handler), "{handler}");
    }
}


#[test]
fn chio_authority_gate_validates_local_signing_keys_schema() {
    let script = include_str!("../../../../scripts/check-chio-authority-issuance.sh");
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let schema_path =
        repo_root.join("spec/schemas/chio-federation/v1/local-signing-keys.schema.json");

    assert!(schema_path.is_file());
    assert!(
            script.contains(
                "validate_schema \"$SCHEMA_DIR/local-signing-keys.schema.json\" \"$tmpdir/input/local-signing-keys.json\""
            ),
            "authority gate must schema-validate local signing keys"
        );
}


#[test]
fn chio_attest_buyer_dispatch_uses_canonical_crate_names() {
    let buyer_dispatch = include_str!("cli/chio/dispatch/buyer.rs");

    assert!(buyer_dispatch.contains("chio_attest_buyer::"));
    assert!(!buyer_dispatch.contains("chio_attest_buyer_core::"));
    assert!(!buyer_dispatch.contains("chio_runtime_core::"));
}
