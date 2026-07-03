use super::cli_entrypoint_support::parse_cli;
use super::*;

#[test]
fn format_json_flag_enables_json_output() {
    let cli = parse_cli(["chio", "--format", "json", "init", "demo"]).unwrap();
    assert!(cli.json_output());
}

#[test]
fn json_shorthand_flag_enables_json_output() {
    let cli = parse_cli(["chio", "--json", "init", "demo"]).unwrap();
    assert!(cli.json_output());
}

#[test]
fn public_chio_command_type_boundaries_are_native() {
    let cli_types = include_str!("cli/types.rs");
    assert!(cli_types.contains("command: ChioRuntimeCommands"));
    assert!(cli_types.contains("command: ChioPheromoneCommands"));
    assert!(cli_types.contains("command: ChioFederationCommands"));
    assert!(cli_types.contains("command: ChioAttestCommands"));
    assert!(
        include_str!("cli/chio/types/runtime.rs").contains("command: ChioRuntimePolicyCommands")
    );
    assert!(include_str!("cli/chio/types/runtime.rs")
        .contains("command: ChioRuntimePeerWeightsCommands"));
    assert!(
        include_str!("cli/chio/types/runtime.rs").contains("command: ChioRuntimePheromoneCommands")
    );
    assert!(include_str!("cli/chio/types/runtime.rs")
        .contains("command: ChioRuntimeOrchestrateCommands"));
    assert!(include_str!("cli/chio/types/runtime.rs").contains("command: ChioRuntimeOpsCommands"));
    assert!(include_str!("cli/chio/types/pheromone/root.rs")
        .contains("command: ChioPheromoneRelayCommands"));
    assert!(include_str!("cli/chio/types/pheromone/relay.rs")
        .contains("command: ChioPheromoneRelayAlertCommands"));
    assert!(
        include_str!("cli/chio/types/authority.rs").contains("command: ChioTrustBundleCommands")
    );
}

#[test]
fn api_protect_subcommand_parses() {
    let cli = parse_cli([
        "chio",
        "api",
        "protect",
        "--upstream",
        "http://127.0.0.1:8080",
    ])
    .unwrap();

    match cli.command {
        Commands::Api {
            command:
                ApiCommands::Protect {
                    upstream,
                    spec,
                    listen,
                    receipt_store,
                },
        } => {
            assert_eq!(upstream, "http://127.0.0.1:8080");
            assert!(spec.is_none());
            assert_eq!(listen, "127.0.0.1:9090");
            assert!(receipt_store.is_none());
        }
        _ => panic!("expected api protect subcommand"),
    }
}

#[test]
fn receipt_flush_subcommand_parses() {
    let cli = parse_cli([
        "chio",
        "--receipt-db",
        "receipts.sqlite3",
        "receipt",
        "flush",
        "--timeout-ms",
        "2500",
    ])
    .unwrap();

    match cli.command {
        Commands::Receipt {
            command: ReceiptCommands::Flush { timeout_ms },
        } => assert_eq!(timeout_ms, 2500),
        _ => panic!("expected receipt flush subcommand"),
    }
}

#[test]
fn receipt_flush_rejects_zero_timeout() {
    let result = parse_cli([
        "chio",
        "--receipt-db",
        "receipts.sqlite3",
        "receipt",
        "flush",
        "--timeout-ms",
        "0",
    ]);

    assert!(result.is_err());
}

#[test]
fn receipt_checkpoint_create_subcommand_parses() {
    let cli = parse_cli([
        "chio",
        "--receipt-db",
        "receipts.sqlite3",
        "receipt",
        "checkpoint",
        "create",
        "--kernel-seed-file",
        "kernel.seed",
        "--max-batch",
        "250",
    ])
    .unwrap();

    match cli.command {
        Commands::Receipt {
            command:
                ReceiptCommands::Checkpoint {
                    command:
                        ReceiptCheckpointCommands::Create {
                            kernel_seed_file,
                            max_batch,
                        },
                },
        } => {
            assert_eq!(kernel_seed_file, PathBuf::from("kernel.seed"));
            assert_eq!(max_batch, 250);
        }
        _ => panic!("expected receipt checkpoint create subcommand"),
    }
}

#[test]
fn receipt_checkpoint_rejects_zero_max_batch() {
    let create = parse_cli([
        "chio",
        "--receipt-db",
        "receipts.sqlite3",
        "receipt",
        "checkpoint",
        "create",
        "--kernel-seed-file",
        "kernel.seed",
        "--max-batch",
        "0",
    ]);
    let status = parse_cli([
        "chio",
        "--receipt-db",
        "receipts.sqlite3",
        "receipt",
        "checkpoint",
        "status",
        "--max-batch",
        "0",
    ]);

    assert!(create.is_err());
    assert!(status.is_err());
}

#[test]
fn write_cli_error_emits_structured_json() {
    let error = CliError::Kernel(chio_kernel::KernelError::OutOfScope {
        tool: "read_file".to_string(),
        server: "fs".to_string(),
    });
    let mut output = Vec::new();

    write_cli_error(&mut output, &error, true).unwrap();

    let rendered: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(rendered["code"], "CHIO-KERNEL-OUT-OF-SCOPE-TOOL");
    assert_eq!(rendered["context"]["tool"], "read_file");
    assert!(rendered["suggested_fix"]
        .as_str()
        .expect("suggested_fix string")
        .contains("Issue a capability"));
}

#[test]
fn write_cli_error_emits_human_report() {
    let error = CliError::cli_other_error("bad inputs".to_string());
    let mut output = Vec::new();

    write_cli_error(&mut output, &error, false).unwrap();

    let rendered = String::from_utf8(output).unwrap();
    assert!(rendered.contains("error [urn:chio:error:cli:other]: bad inputs"));
    assert!(rendered.contains(r#"context: {"domain":"cli""#));
    assert!(rendered.contains("suggested fix: Preserve the original message"));
}

#[test]
fn mcp_wrap_subcommand_parses() {
    let cli = parse_cli([
        "chio",
        "mcp",
        "wrap",
        "--server-id",
        "fs",
        "--",
        "echo",
        "hello",
    ])
    .expect("mcp wrap parses");

    match cli.command {
        Commands::Mcp {
            command: McpCommands::Wrap(args),
        } => {
            assert_eq!(args.server_id, "fs");
            assert_eq!(args.command, vec!["echo".to_string(), "hello".to_string()]);
            assert!(args.emit_config.is_none());
            assert!(!args.print_scopes);
        }
        _ => panic!("expected mcp wrap subcommand"),
    }
}

#[test]
fn chio_native_command_surfaces_parse_representative_operations() {
    let commands: Vec<Vec<&str>> = vec![
        vec![
            "chio",
            "attest",
            "buyer",
            "verify",
            "--package",
            "package.json",
            "--trust-bundle",
            "verifier-trust-bundle.json",
            "--context",
            "verification-context.json",
            "--report",
            "report.json",
        ],
        vec![
            "chio",
            "pheromone",
            "receive",
            "--batch",
            "gossip-batch.json",
            "--transit-policy",
            "transit-policy.json",
            "--proof-package",
            "buyer-auditor-proof-package.json",
            "--trust-bundle",
            "verifier-trust-bundle.json",
            "--context",
            "verification-context.json",
            "--store",
            "pheromone.sqlite3",
            "--now-unix-ms",
            "1766000000500",
            "--report",
            "receive-report.json",
        ],
        vec![
            "chio",
            "pheromone",
            "query",
            "--store",
            "pheromone.sqlite3",
            "--subject-class",
            "support.prompt_injection",
            "--namespace",
            "dev.chio.support",
            "--reputation-epoch",
            "42",
            "--peer-weights",
            "peer-weights.json",
            "--now-unix-ms",
            "1766000000500",
            "--report",
            "query-report.json",
        ],
        vec![
            "chio",
            "pheromone",
            "relay",
            "enqueue",
            "--store",
            "relay.sqlite3",
            "--batch",
            "gossip-batch.json",
            "--transit-policy",
            "transit-policy.json",
            "--trust-bundle",
            "verifier-trust-bundle.json",
            "--peer-directory",
            "peer-directory.json",
            "--now-unix-ms",
            "1766000000500",
            "--report",
            "enqueue-report.json",
        ],
        vec![
            "chio",
            "pheromone",
            "relay",
            "observe",
            "--store",
            "relay.sqlite3",
            "--peer-directory-state",
            "peer-directory-state.json",
            "--profile",
            "production",
            "--trusted-issuers",
            "trusted-issuers.json",
            "--report-dir",
            "relay-reports",
            "--limit",
            "25",
            "--report",
            "relay-observability.json",
        ],
        vec![
            "chio",
            "pheromone",
            "relay",
            "metrics",
            "--store",
            "relay.sqlite3",
            "--format",
            "prometheus",
            "--output",
            "relay-metrics.prom",
        ],
        vec![
            "chio",
            "runtime",
            "admit",
            "--request",
            "request.json",
            "--admission-profile",
            "profile.json",
            "--admission-bundle",
            "bundle.json",
            "--runtime-trust-input",
            "runtime-trust.json",
            "--trusted-verifiers",
            "trusted-verifiers.json",
            "--store",
            "store.json",
            "--now-unix-ms",
            "1800000001000",
            "--report",
            "report.json",
        ],
        vec![
            "chio",
            "runtime",
            "policy",
            "sign",
            "--body",
            "runtime-policy-body.json",
            "--signing-seed-file",
            "verifier.seed",
            "--out",
            "runtime-policy.json",
        ],
        vec![
            "chio",
            "runtime",
            "run-loopback",
            "--scenario",
            "scenario.json",
            "--store-dir",
            "stores",
            "--now-unix-ms",
            "1800000001000",
            "--out-dir",
            "out",
        ],
        vec![
            "chio",
            "runtime",
            "orchestrate",
            "run",
            "--profile",
            "profile.json",
            "--run-contract",
            "run-contract.json",
            "--store",
            "runtime.sqlite3",
            "--evidence-dir",
            "evidence",
            "--now-unix-ms",
            "1800000001000",
            "--report",
            "run-report.json",
        ],
        vec![
            "chio",
            "federation",
            "authority",
            "issue",
            "--profile",
            "authority-profile.json",
            "--request",
            "issuance-request.json",
            "--signing-keys",
            "local-signing-keys.json",
            "--out-dir",
            "issued",
        ],
        vec![
            "chio",
            "federation",
            "treaty",
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
        ],
        vec![
            "chio",
            "attest",
            "buyer",
            "explain",
            "--report",
            "buyer-review-report.json",
            "--format",
            "text",
            "--out",
            "buyer-review.txt",
        ],
    ];

    for args in commands {
        parse_cli(args.clone()).unwrap_or_else(|error| {
            panic!("expected native Chio command to parse: {args:?}: {error}")
        });
    }
}

#[test]
fn chio_native_command_surfaces_preserve_required_arguments() {
    let relay_enqueue = parse_cli([
        "chio",
        "pheromone",
        "relay",
        "enqueue",
        "--store",
        "relay.sqlite3",
        "--peer-directory",
        "peer-directory.json",
        "--report",
        "enqueue-report.json",
    ]);
    let relay_enqueue_error = match relay_enqueue {
        Ok(_) => panic!("relay enqueue must require --batch"),
        Err(error) => error,
    };
    assert_eq!(
        relay_enqueue_error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );

    let buyer_verify = parse_cli([
        "chio",
        "attest",
        "buyer",
        "verify",
        "--package",
        "package.json",
        "--report",
        "report.json",
    ]);
    let buyer_verify_error = match buyer_verify {
        Ok(_) => panic!("buyer verify must require trust inputs"),
        Err(error) => error,
    };
    assert_eq!(
        buyer_verify_error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
}

#[test]
fn chio_runtime_loopback_capability_window_covers_replay_and_wall_clock() {
    let replay_now_unix_ms = 4_102_444_800_000;
    let wall_now_secs = unix_now_ms() / 1000;

    let (issued_at, expires_at) =
        chio_runtime_harness::runtime_loopback_capability_window(replay_now_unix_ms);

    assert!(issued_at <= replay_now_unix_ms / 1000);
    assert!(expires_at > replay_now_unix_ms / 1000);
    assert!(issued_at <= wall_now_secs);
    assert!(expires_at > wall_now_secs);
}

#[test]
fn hidden_chio_attest_verify_shortcut_is_rejected() {
    let error = match parse_cli([
        "chio",
        "attest",
        "verify",
        "--package",
        "proof-package.json",
        "--trust-bundle",
        "trust-bundle.json",
        "--context",
        "context.json",
        "--report",
        "report.json",
    ]) {
        Ok(_) => panic!("hidden chio attest verify shortcut must be rejected"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
}
