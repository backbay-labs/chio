// Chio CLI -- command-line interface for the Chio runtime kernel.
//
// Provides commands for:
//
// - `chio run --policy <path> -- <command> [args...]`
//   Spawn an agent subprocess, set up the length-prefixed transport over
//   stdin/stdout pipes, and run the kernel message loop.
//
// - `chio check --policy <path> --tool <name> --params <json>`
//   Load a policy, create a kernel, and evaluate a single tool call.
//
// - `chio mcp serve --policy <path> --server-id <id> -- <command> [args...]`
//   Wrap an MCP server subprocess with the Chio kernel and expose an
//   MCP-compatible edge over stdio for stock MCP clients.

mod admin;
mod cert;
mod commands {
    pub mod bind;
    pub mod guard_blocklist;
}
mod did;
mod doctor;
mod guard;
mod guards;
mod lineage;
mod market;
mod passport;
mod policies;
mod scaffold;
mod settle;

include!("cli/types.rs");
#[path = "cli/chiodos/types.rs"]
mod chiodos_types;
use chiodos_types::*;
include!("cli/doctor.rs");
include!("cli/dispatch.rs");
#[path = "cli/chiodos/dispatch.rs"]
mod chiodos_dispatch;
use chiodos_dispatch::*;
include!("cli/runtime.rs");
include!("cli/trust_commands.rs");
include!("cli/session.rs");
include!("cli/conformance.rs");
include!("cli/mcp.rs");
include!("cli/replay.rs");
include!("cli/replay/reader.rs");
include!("cli/replay/verify.rs");
include!("cli/replay/merkle.rs");
include!("cli/replay/verdict.rs");
include!("cli/replay/report.rs");
include!("cli/replay/ndjson.rs");
include!("cli/replay/validate.rs");
include!("cli/replay/schema_gate.rs");
include!("cli/replay/policy_ref.rs");
include!("cli/replay/receipt_partition.rs");
include!("cli/replay/execute.rs");
include!("cli/replay/diff.rs");
include!("cli/replay/traffic.rs");
include!("cli/replay/bless/strip.rs");
include!("cli/replay/bless/fixture_layout.rs");
include!("cli/replay/bless.rs");
include!("cli/arena.rs");

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod cli_entrypoint_tests {
    use std::error::Error;

    use clap::{CommandFactory, Parser};

    use super::*;

    #[test]
    fn format_json_flag_enables_json_output() {
        let cli = Cli::try_parse_from(["chio", "--format", "json", "init", "demo"]).unwrap();
        assert!(cli.json_output());
    }

    #[test]
    fn legacy_json_flag_still_enables_json_output() {
        let cli = Cli::try_parse_from(["chio", "--json", "init", "demo"]).unwrap();
        assert!(cli.json_output());
    }

    #[test]
    fn legacy_chiodos_cli_gate_detects_direct_command_after_global_options() {
        assert!(legacy_chiodos_cli_requested([
            "chio", "--format", "json", "chiodos", "help"
        ]));
        assert!(legacy_chiodos_cli_requested([
            "chio",
            "--receipt-db=/tmp/receipts.sqlite3",
            "chiodos",
            "help",
        ]));
        assert!(legacy_chiodos_cli_requested([
            "chio", "--json", "chiodos", "verify"
        ]));
    }

    #[test]
    fn legacy_chiodos_cli_gate_leaves_chio_legacy_attest_path_public() {
        assert!(!legacy_chiodos_cli_requested([
            "chio",
            "attest",
            "legacy",
            "chiodos-v1",
            "verify",
        ]));
        assert!(!legacy_chiodos_cli_requested([
            "chio", "run", "--", "chiodos"
        ]));
        assert!(!legacy_chiodos_cli_requested(["chio", "help"]));
    }

    #[test]
    fn public_chio_runtime_and_pheromone_commands_use_chio_type_boundary() {
        let cli_types = include_str!("cli/types.rs");
        let runtime_types = include_str!("cli/chiodos/types/runtime.rs");
        let pheromone_types = include_str!("cli/chiodos/types/pheromone/root.rs");
        let relay_types = include_str!("cli/chiodos/types/pheromone/relay.rs");
        let alert_types = include_str!("cli/chiodos/types/pheromone/alerts.rs");
        let assurance_types = include_str!("cli/chiodos/types/pheromone/assurance.rs");

        assert!(
            cli_types.contains("command: ChioRuntimeCommands"),
            "public chio runtime command tree must use a Chio-named type boundary"
        );
        assert!(
            !cli_types.contains("command: ChiodosRuntimeCommands"),
            "public chio runtime command tree must not expose the historical Chiodos type"
        );
        assert!(
            runtime_types.contains("command: ChioRuntimePolicyCommands"),
            "public chio runtime policy tree must use a Chio-named type boundary"
        );
        assert!(
            !runtime_types.contains("command: ChiodosRuntimePolicyCommands"),
            "public chio runtime policy tree must not expose the historical Chiodos type"
        );
        assert!(
            runtime_types.contains("command: ChioRuntimePeerWeightsCommands"),
            "public chio runtime peer-weights tree must use a Chio-named type boundary"
        );
        assert!(
            !runtime_types.contains("command: ChiodosRuntimePeerWeightsCommands"),
            "public chio runtime peer-weights tree must not expose the historical Chiodos type"
        );
        assert!(
            runtime_types.contains("command: ChioRuntimePheromoneCommands"),
            "public chio runtime pheromone tree must use a Chio-named type boundary"
        );
        assert!(
            !runtime_types.contains("command: ChiodosRuntimePheromoneCommands"),
            "public chio runtime pheromone tree must not expose the historical Chiodos type"
        );
        assert!(
            runtime_types.contains("command: ChioRuntimeOrchestrateCommands"),
            "public chio runtime orchestration tree must use a Chio-named type boundary"
        );
        assert!(
            !runtime_types.contains("command: ChiodosRuntimeOrchestrateCommands"),
            "public chio runtime orchestration tree must not expose the historical Chiodos type"
        );
        assert!(
            runtime_types.contains("command: ChioRuntimeOpsCommands"),
            "public chio runtime ops tree must use a Chio-named type boundary"
        );
        assert!(
            !runtime_types.contains("command: ChiodosRuntimeOpsCommands"),
            "public chio runtime ops tree must not expose the historical Chiodos type"
        );
        assert!(
            runtime_types.contains("command: ChioRuntimeOpsRetentionCommands"),
            "public chio runtime ops retention tree must use a Chio-named type boundary"
        );
        assert!(
            !runtime_types.contains("command: ChiodosRuntimeOpsRetentionCommands"),
            "public chio runtime ops retention tree must not expose the historical Chiodos type"
        );
        assert!(
            cli_types.contains("command: ChioPheromoneCommands"),
            "public chio pheromone command tree must use a Chio-named type boundary"
        );
        assert!(
            !cli_types.contains("command: ChiodosPheromoneCommands"),
            "public chio pheromone command tree must not expose the historical Chiodos type"
        );
        assert!(
            pheromone_types.contains("command: ChioPheromoneRelayCommands"),
            "public chio pheromone relay tree must use a Chio-named type boundary"
        );
        assert!(
            !pheromone_types.contains("command: ChiodosPheromoneRelayCommands"),
            "public chio pheromone relay tree must not expose the historical Chiodos type"
        );
        assert!(
            relay_types.contains("command: ChioPheromoneRelayAlertCommands"),
            "public chio pheromone relay alert tree must use a Chio-named type boundary"
        );
        assert!(
            !relay_types.contains("command: ChiodosPheromoneRelayAlertCommands"),
            "public chio pheromone relay alert tree must not expose the historical Chiodos type"
        );
        assert!(
            relay_types.contains("command: ChioPheromoneRelayDirectoryCommands"),
            "public chio pheromone relay directory tree must use a Chio-named type boundary"
        );
        assert!(
            !relay_types.contains("command: ChiodosPheromoneRelayDirectoryCommands"),
            "public chio pheromone relay directory tree must not expose the historical Chiodos type"
        );
        assert!(
            relay_types.contains("command: ChioPheromoneRelaySupervisorCommands"),
            "public chio pheromone relay supervisor tree must use a Chio-named type boundary"
        );
        assert!(
            !relay_types.contains("command: ChiodosPheromoneRelaySupervisorCommands"),
            "public chio pheromone relay supervisor tree must not expose the historical Chiodos type"
        );
        assert!(
            alert_types.contains("command: ChioPheromoneRelayAlertDeliveryCommands"),
            "public chio pheromone relay alert delivery tree must use a Chio-named type boundary"
        );
        assert!(
            !alert_types.contains("command: ChiodosPheromoneRelayAlertDeliveryCommands"),
            "public chio pheromone relay alert delivery tree must not expose the historical Chiodos type"
        );
        assert!(
            alert_types.contains("command: ChioPheromoneRelayAlertAssuranceCommands"),
            "public chio pheromone relay alert assurance tree must use a Chio-named type boundary"
        );
        assert!(
            !alert_types.contains("command: ChiodosPheromoneRelayAlertAssuranceCommands"),
            "public chio pheromone relay alert assurance tree must not expose the historical Chiodos type"
        );
        assert!(
            assurance_types
                .contains("command: ChioPheromoneRelayAlertAssuranceRetentionCommands"),
            "public chio pheromone relay alert assurance retention tree must use a Chio-named type boundary"
        );
        assert!(
            !assurance_types
                .contains("command: ChiodosPheromoneRelayAlertAssuranceRetentionCommands"),
            "public chio pheromone relay alert assurance retention tree must not expose the historical Chiodos type"
        );
        assert!(
            assurance_types
                .contains("command: ChioPheromoneRelayAlertAssuranceArchiveCommands"),
            "public chio pheromone relay alert assurance archive tree must use a Chio-named type boundary"
        );
        assert!(
            !assurance_types
                .contains("command: ChiodosPheromoneRelayAlertAssuranceArchiveCommands"),
            "public chio pheromone relay alert assurance archive tree must not expose the historical Chiodos type"
        );
        assert!(
            assurance_types
                .contains("command: ChioPheromoneRelayAlertAssuranceCloseoutCommands"),
            "public chio pheromone relay alert assurance closeout tree must use a Chio-named type boundary"
        );
        assert!(
            !assurance_types
                .contains("command: ChiodosPheromoneRelayAlertAssuranceCloseoutCommands"),
            "public chio pheromone relay alert assurance closeout tree must not expose the historical Chiodos type"
        );
    }

    #[test]
    fn public_chio_federation_commands_use_chio_type_boundary() {
        let cli_types = include_str!("cli/types.rs");
        let authority_types = include_str!("cli/chiodos/types/authority.rs");

        assert!(
            cli_types.contains("command: ChioAuthorityCommands"),
            "public chio federation authority tree must use a Chio-named type boundary"
        );
        assert!(
            !cli_types.contains("command: ChiodosAuthorityCommands"),
            "public chio federation authority tree must not expose the historical Chiodos type"
        );
        assert!(
            cli_types.contains("command: ChioTreatyCommands"),
            "public chio federation treaty tree must use a Chio-named type boundary"
        );
        assert!(
            !cli_types.contains("command: ChiodosTreatyCommands"),
            "public chio federation treaty tree must not expose the historical Chiodos type"
        );
        assert!(
            authority_types.contains("command: ChioTrustBundleCommands"),
            "public chio federation authority trust-bundle tree must use a Chio-named type boundary"
        );
        assert!(
            !authority_types.contains("command: ChiodosTrustBundleCommands"),
            "public chio federation authority trust-bundle tree must not expose the historical Chiodos type"
        );
    }

    #[test]
    fn api_protect_subcommand_parses() {
        let cli = Cli::try_parse_from([
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
        assert!(
            rendered["suggested_fix"]
                .as_str()
                .expect("suggested_fix string")
                .contains("Issue a capability")
        );
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
        let cli = Cli::try_parse_from([
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
    fn chiodos_verify_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "verify",
            "--package",
            "package.json",
            "--trust-bundle",
            "verifier-trust-bundle.json",
            "--context",
            "verification-context.json",
            "--report",
            "report.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Verify {
                        package,
                        trust_bundle,
                        context,
                        report,
                    },
            } => {
                assert_eq!(package, std::path::PathBuf::from("package.json"));
                assert_eq!(
                    trust_bundle,
                    std::path::PathBuf::from("verifier-trust-bundle.json")
                );
                assert_eq!(
                    context,
                    std::path::PathBuf::from("verification-context.json")
                );
                assert_eq!(report, std::path::PathBuf::from("report.json"));
            }
            _ => panic!("expected chiodos verify subcommand"),
        }
    }

    #[test]
    fn chiodos_pheromone_receive_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
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
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Receive {
                                batch,
                                transit_policy,
                                proof_package,
                                trust_bundle,
                                context,
                                store,
                                now_unix_ms,
                                report,
                            },
                    },
            } => {
                assert_eq!(batch, std::path::PathBuf::from("gossip-batch.json"));
                assert_eq!(
                    transit_policy,
                    std::path::PathBuf::from("transit-policy.json")
                );
                assert_eq!(
                    proof_package,
                    std::path::PathBuf::from("buyer-auditor-proof-package.json")
                );
                assert_eq!(
                    trust_bundle,
                    std::path::PathBuf::from("verifier-trust-bundle.json")
                );
                assert_eq!(
                    context,
                    std::path::PathBuf::from("verification-context.json")
                );
                assert_eq!(store, std::path::PathBuf::from("pheromone.sqlite3"));
                assert_eq!(now_unix_ms, Some(1_766_000_000_500));
                assert_eq!(report, std::path::PathBuf::from("receive-report.json"));
            }
            _ => panic!("expected chiodos pheromone receive subcommand"),
        }
    }

    #[test]
    fn chiodos_pheromone_query_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
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
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Query {
                                store,
                                subject_class,
                                namespace,
                                reputation_epoch,
                                peer_weights,
                                now_unix_ms,
                                report,
                            },
                    },
            } => {
                assert_eq!(store, std::path::PathBuf::from("pheromone.sqlite3"));
                assert_eq!(subject_class, "support.prompt_injection");
                assert_eq!(namespace, "dev.chio.support");
                assert_eq!(reputation_epoch, 42);
                assert_eq!(peer_weights, std::path::PathBuf::from("peer-weights.json"));
                assert_eq!(now_unix_ms, Some(1_766_000_000_500));
                assert_eq!(report, std::path::PathBuf::from("query-report.json"));
            }
            _ => panic!("expected chiodos pheromone query subcommand"),
        }
    }

    #[test]
    fn chiodos_pheromone_relay_status_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "status",
            "--store",
            "relay.sqlite3",
            "--report",
            "relay-status.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command: ChiodosPheromoneRelayCommands::Status { store, report },
                            },
                    },
            } => {
                assert_eq!(store, std::path::PathBuf::from("relay.sqlite3"));
                assert_eq!(report, std::path::PathBuf::from("relay-status.json"));
            }
            _ => panic!("expected chiodos pheromone relay status subcommand"),
        }
    }

    #[test]
    fn chiodos_pheromone_relay_enqueue_requires_batch() {
        let result = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "enqueue",
            "--store",
            "relay.sqlite3",
            "--peer-directory",
            "peer-directory.json",
            "--now-unix-ms",
            "1766000000500",
            "--report",
            "enqueue-report.json",
        ]);
        let error = match result {
            Ok(_) => panic!("relay enqueue must require --batch"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn chiodos_pheromone_relay_enqueue_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
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
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Enqueue {
                                        store,
                                        batch,
                                        transit_policy,
                                        trust_bundle,
                                        report,
                                        ..
                                    },
                            },
                    },
            } => {
                assert_eq!(store, std::path::PathBuf::from("relay.sqlite3"));
                assert_eq!(batch, std::path::PathBuf::from("gossip-batch.json"));
                assert_eq!(
                    transit_policy,
                    std::path::PathBuf::from("transit-policy.json")
                );
                assert_eq!(
                    trust_bundle,
                    std::path::PathBuf::from("verifier-trust-bundle.json")
                );
                assert_eq!(report, std::path::PathBuf::from("enqueue-report.json"));
            }
            _ => panic!("expected chiodos pheromone relay enqueue subcommand"),
        }
    }

    #[test]
    fn chiodos_pheromone_relay_catchup_requires_peer_directory_state() {
        let result = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "catchup",
            "--store",
            "relay.sqlite3",
            "--peer",
            "did:chio:buyer-kernel",
            "--treaty",
            "treaty:buyer-dataco:support-ops",
            "--after-cursor",
            "0",
            "--limit",
            "16",
            "--report",
            "catchup-response.json",
        ]);
        let error = match result {
            Ok(_) => panic!("relay catchup must require --peer-directory-state"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn chiodos_pheromone_relay_observe_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
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
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Observe {
                                        store,
                                        peer_directory_state,
                                        profile,
                                        trusted_issuers,
                                        report_dir,
                                        limit,
                                        report,
                                    },
                            },
                    },
            } => {
                assert_eq!(store, std::path::PathBuf::from("relay.sqlite3"));
                assert_eq!(
                    peer_directory_state,
                    std::path::PathBuf::from("peer-directory-state.json")
                );
                assert!(matches!(profile, RelayProfileArg::Production));
                assert_eq!(
                    trusted_issuers,
                    std::path::PathBuf::from("trusted-issuers.json")
                );
                assert_eq!(report_dir, std::path::PathBuf::from("relay-reports"));
                assert_eq!(limit, 25);
                assert_eq!(report, std::path::PathBuf::from("relay-observability.json"));
            }
            _ => panic!("expected chiodos pheromone relay observe subcommand"),
        }
    }

    #[test]
    fn chiodos_pheromone_relay_metrics_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "metrics",
            "--store",
            "relay.sqlite3",
            "--format",
            "prometheus",
            "--output",
            "relay-metrics.prom",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Metrics {
                                        store,
                                        format,
                                        output,
                                    },
                            },
                    },
            } => {
                assert_eq!(store, std::path::PathBuf::from("relay.sqlite3"));
                assert!(matches!(format, RelayMetricsFormatArg::Prometheus));
                assert_eq!(output, std::path::PathBuf::from("relay-metrics.prom"));
            }
            _ => panic!("expected chiodos pheromone relay metrics subcommand"),
        }
    }

    #[test]
    fn chiodos_pheromone_relay_alert_evaluate_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "alert",
            "evaluate",
            "--observability-report",
            "relay-observability.json",
            "--event-dir",
            "relay-events",
            "--routing-profile",
            "alert-routing-profile.json",
            "--suppression-state",
            "alert-suppression-state.json",
            "--now-unix-ms",
            "1766000000500",
            "--report",
            "relay-alert-report.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Alert {
                                        command:
                                            ChiodosPheromoneRelayAlertCommands::Evaluate {
                                                observability_report,
                                                event_dir,
                                                routing_profile,
                                                suppression_state,
                                                now_unix_ms,
                                                report,
                                            },
                                    },
                            },
                    },
            } => {
                assert_eq!(
                    observability_report,
                    std::path::PathBuf::from("relay-observability.json")
                );
                assert_eq!(event_dir, std::path::PathBuf::from("relay-events"));
                assert_eq!(
                    routing_profile,
                    std::path::PathBuf::from("alert-routing-profile.json")
                );
                assert_eq!(
                    suppression_state,
                    std::path::PathBuf::from("alert-suppression-state.json")
                );
                assert_eq!(now_unix_ms, 1_766_000_000_500);
                assert_eq!(report, std::path::PathBuf::from("relay-alert-report.json"));
            }
            _ => panic!("expected chiodos pheromone relay alert evaluate subcommand"),
        }
    }

    #[test]
    fn chiodos_pheromone_relay_trend_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "trend",
            "--reports-dir",
            "relay-reports",
            "--event-dir",
            "relay-events",
            "--routing-profile",
            "alert-routing-profile.json",
            "--since-unix-ms",
            "1765990000000",
            "--until-unix-ms",
            "1766000000500",
            "--report",
            "relay-trend-report.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Trend {
                                        reports_dir,
                                        event_dir,
                                        routing_profile,
                                        since_unix_ms,
                                        until_unix_ms,
                                        report,
                                    },
                            },
                    },
            } => {
                assert_eq!(reports_dir, std::path::PathBuf::from("relay-reports"));
                assert_eq!(event_dir, std::path::PathBuf::from("relay-events"));
                assert_eq!(
                    routing_profile,
                    std::path::PathBuf::from("alert-routing-profile.json")
                );
                assert_eq!(since_unix_ms, 1_765_990_000_000);
                assert_eq!(until_unix_ms, 1_766_000_000_500);
                assert_eq!(report, std::path::PathBuf::from("relay-trend-report.json"));
            }
            _ => panic!("expected chiodos pheromone relay trend subcommand"),
        }
    }

    #[test]
    fn chiodos_pheromone_relay_lint_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "lint",
            "--peer-directory",
            "peer-directory-bundle.json",
            "--profile",
            "production",
            "--trusted-issuers",
            "trusted-issuers.json",
            "--report",
            "lint-report.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Lint {
                                        peer_directory,
                                        peer_directory_state,
                                        profile,
                                        trusted_issuers,
                                        report,
                                    },
                            },
                    },
            } => {
                assert_eq!(
                    peer_directory,
                    Some(std::path::PathBuf::from("peer-directory-bundle.json"))
                );
                assert_eq!(peer_directory_state, None);
                assert!(matches!(profile, RelayProfileArg::Production));
                assert_eq!(
                    trusted_issuers,
                    Some(std::path::PathBuf::from("trusted-issuers.json"))
                );
                assert_eq!(report, std::path::PathBuf::from("lint-report.json"));
            }
            _ => panic!("expected chiodos pheromone relay lint subcommand"),
        }
    }

    #[test]
    fn chiodos_pheromone_relay_directory_promote_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "directory",
            "promote",
            "--state",
            "peer-directory-state.json",
            "--candidate",
            "peer-directory-bundle.json",
            "--trusted-issuers",
            "trusted-issuers.json",
            "--profile",
            "production",
            "--now-unix-ms",
            "1766000000500",
            "--report",
            "rotation-report.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Directory {
                                        command:
                                            ChiodosPheromoneRelayDirectoryCommands::Promote {
                                                state,
                                                candidate,
                                                trusted_issuers,
                                                profile,
                                                now_unix_ms,
                                                report,
                                            },
                                    },
                            },
                    },
            } => {
                assert_eq!(state, std::path::PathBuf::from("peer-directory-state.json"));
                assert_eq!(
                    candidate,
                    std::path::PathBuf::from("peer-directory-bundle.json")
                );
                assert_eq!(
                    trusted_issuers,
                    std::path::PathBuf::from("trusted-issuers.json")
                );
                assert!(matches!(profile, RelayProfileArg::Production));
                assert_eq!(now_unix_ms, Some(1_766_000_000_500));
                assert_eq!(report, std::path::PathBuf::from("rotation-report.json"));
            }
            _ => panic!("expected chiodos pheromone relay directory promote subcommand"),
        }
    }

    #[test]
    fn chiodos_pheromone_relay_supervisor_lint_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "supervisor",
            "lint",
            "--profile",
            "relay-supervisor-profile.json",
            "--report",
            "relay-drill-report.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Supervisor {
                                        command:
                                            ChiodosPheromoneRelaySupervisorCommands::Lint {
                                                profile,
                                                report,
                                            },
                                    },
                            },
                    },
            } => {
                assert_eq!(
                    profile,
                    std::path::PathBuf::from("relay-supervisor-profile.json")
                );
                assert_eq!(report, std::path::PathBuf::from("relay-drill-report.json"));
            }
            _ => panic!("expected chiodos pheromone relay supervisor lint subcommand"),
        }
    }

    #[test]
    fn chiodos_pheromone_relay_tick_requires_signing_key() {
        let result = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "tick",
            "--store",
            "relay.sqlite3",
            "--peer-directory",
            "peer-directory.json",
            "--now-unix-ms",
            "1766000000500",
            "--max-batches",
            "4",
            "--report",
            "tick-report.json",
        ]);
        let error = match result {
            Ok(_) => panic!("relay tick must require --signing-key"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn chiodos_pheromone_relay_tick_report_dir_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "tick",
            "--store",
            "relay.sqlite3",
            "--peer-directory",
            "peer-directory.json",
            "--now-unix-ms",
            "1766000000500",
            "--max-batches",
            "4",
            "--signing-key",
            "relay-signing-key.json",
            "--report",
            "tick-report.json",
            "--report-dir",
            "relay-events",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command: ChiodosPheromoneRelayCommands::Tick { report_dir, .. },
                            },
                    },
            } => assert_eq!(report_dir, Some(std::path::PathBuf::from("relay-events"))),
            _ => panic!("expected chiodos pheromone relay tick subcommand"),
        }
    }

    #[test]
    fn chiodos_verify_requires_trust_bundle() {
        let result = Cli::try_parse_from([
            "chio",
            "chiodos",
            "verify",
            "--package",
            "package.json",
            "--report",
            "report.json",
        ]);
        let error = match result {
            Ok(_) => panic!("chiodos verify must require --trust-bundle"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn chiodos_verify_requires_context() {
        let result = Cli::try_parse_from([
            "chio",
            "chiodos",
            "verify",
            "--package",
            "package.json",
            "--trust-bundle",
            "verifier-trust-bundle.json",
            "--report",
            "report.json",
        ]);
        let error = match result {
            Ok(_) => panic!("chiodos verify must require --context"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn chiodos_runtime_admit_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
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
            "--pheromone-query-report",
            "pheromone-query.json",
            "--runtime-pheromone-policy",
            "runtime-policy.json",
            "--runtime-peer-weights",
            "peer-weights.json",
            "--action-class-id",
            "workflow.destructive.vendor_call",
            "--trust-floor-state",
            "trust-floor.json",
            "--store",
            "store.json",
            "--now-unix-ms",
            "1800000001000",
            "--report",
            "report.json",
        ])
        .unwrap();

        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Runtime {
                        command:
                            ChiodosRuntimeCommands::Admit {
                                request,
                                admission_profile,
                                admission_bundle,
                                runtime_trust_input,
                                trusted_verifiers,
                                pheromone_query_report,
                                runtime_pheromone_policy,
                                runtime_peer_weights,
                                action_class_id,
                                trust_floor_state,
                                store,
                                now_unix_ms,
                                report,
                            },
                    },
            } => {
                assert_eq!(request, std::path::PathBuf::from("request.json"));
                assert_eq!(admission_profile, std::path::PathBuf::from("profile.json"));
                assert_eq!(admission_bundle, std::path::PathBuf::from("bundle.json"));
                assert_eq!(
                    runtime_trust_input,
                    Some(std::path::PathBuf::from("runtime-trust.json"))
                );
                assert_eq!(
                    trusted_verifiers,
                    Some(std::path::PathBuf::from("trusted-verifiers.json"))
                );
                assert_eq!(
                    pheromone_query_report,
                    Some(std::path::PathBuf::from("pheromone-query.json"))
                );
                assert_eq!(
                    runtime_pheromone_policy,
                    Some(std::path::PathBuf::from("runtime-policy.json"))
                );
                assert_eq!(
                    runtime_peer_weights,
                    Some(std::path::PathBuf::from("peer-weights.json"))
                );
                assert_eq!(
                    action_class_id.as_deref(),
                    Some("workflow.destructive.vendor_call")
                );
                assert_eq!(
                    trust_floor_state,
                    Some(std::path::PathBuf::from("trust-floor.json"))
                );
                assert_eq!(store, std::path::PathBuf::from("store.json"));
                assert_eq!(now_unix_ms, 1_800_000_001_000);
                assert_eq!(report, std::path::PathBuf::from("report.json"));
            }
            _ => panic!("expected chiodos runtime admit subcommand"),
        }
    }

    #[test]
    fn chiodos_treaty_verify_packet_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
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
        ])
        .unwrap();

        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Treaty {
                        command:
                            ChiodosTreatyCommands::VerifyPacket {
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
            _ => panic!("expected chiodos treaty verify-packet subcommand"),
        }
    }

    #[test]
    fn chiodos_buyer_verify_and_explain_subcommands_parse() {
        let verify = Cli::try_parse_from([
            "chio",
            "chiodos",
            "buyer",
            "verify",
            "--package",
            "review-package.json",
            "--trust-bundle",
            "trust.json",
            "--context",
            "context.json",
            "--report",
            "buyer-review-report.json",
        ]);
        assert!(verify.is_ok());

        let explain = Cli::try_parse_from([
            "chio",
            "chiodos",
            "buyer",
            "explain",
            "--report",
            "buyer-review-report.json",
            "--format",
            "text",
            "--out",
            "buyer-review.txt",
        ]);
        assert!(explain.is_ok());
    }

    #[test]
    fn chiodos_runtime_policy_sign_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "runtime",
            "policy",
            "sign",
            "--body",
            "runtime-policy-body.json",
            "--signing-seed-file",
            "verifier.seed",
            "--out",
            "runtime-policy.json",
        ])
        .unwrap();

        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Runtime {
                        command:
                            ChiodosRuntimeCommands::Policy {
                                command:
                                    ChiodosRuntimePolicyCommands::Sign {
                                        body,
                                        signing_seed_file,
                                        out,
                                    },
                            },
                    },
            } => {
                assert_eq!(body, std::path::PathBuf::from("runtime-policy-body.json"));
                assert_eq!(signing_seed_file, std::path::PathBuf::from("verifier.seed"));
                assert_eq!(out, std::path::PathBuf::from("runtime-policy.json"));
            }
            _ => panic!("expected chiodos runtime policy sign subcommand"),
        }
    }

    #[test]
    fn chiodos_runtime_pheromone_evaluate_subcommand_parses() {
        let sign = Cli::try_parse_from([
            "chio",
            "chiodos",
            "runtime",
            "pheromone",
            "sign-query-report",
            "--body",
            "pheromone-query-body.json",
            "--signing-seed-file",
            "verifier.seed",
            "--out",
            "pheromone-query.signed.json",
        ]);
        assert!(sign.is_ok());

        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "runtime",
            "pheromone",
            "evaluate",
            "--admission-bundle",
            "bundle.json",
            "--runtime-trust-input",
            "runtime-trust.json",
            "--trusted-verifiers",
            "trusted-verifiers.json",
            "--pheromone-query-report",
            "pheromone-query.json",
            "--runtime-pheromone-policy",
            "runtime-policy.json",
            "--runtime-peer-weights",
            "peer-weights.json",
            "--action-class-id",
            "workflow.destructive.vendor_call",
            "--now-unix-ms",
            "1800000001000",
            "--report",
            "decision.json",
        ])
        .unwrap();

        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Runtime {
                        command:
                            ChiodosRuntimeCommands::Pheromone {
                                command:
                                    ChiodosRuntimePheromoneCommands::Evaluate {
                                        admission_bundle,
                                        runtime_trust_input,
                                        trusted_verifiers,
                                        pheromone_query_report,
                                        runtime_pheromone_policy,
                                        runtime_peer_weights,
                                        action_class_id,
                                        now_unix_ms,
                                        report,
                                    },
                            },
                    },
            } => {
                assert_eq!(admission_bundle, std::path::PathBuf::from("bundle.json"));
                assert_eq!(
                    runtime_trust_input,
                    std::path::PathBuf::from("runtime-trust.json")
                );
                assert_eq!(
                    trusted_verifiers,
                    std::path::PathBuf::from("trusted-verifiers.json")
                );
                assert_eq!(
                    pheromone_query_report,
                    std::path::PathBuf::from("pheromone-query.json")
                );
                assert_eq!(
                    runtime_pheromone_policy,
                    std::path::PathBuf::from("runtime-policy.json")
                );
                assert_eq!(
                    runtime_peer_weights,
                    std::path::PathBuf::from("peer-weights.json")
                );
                assert_eq!(
                    action_class_id.as_deref(),
                    Some("workflow.destructive.vendor_call")
                );
                assert_eq!(now_unix_ms, 1_800_000_001_000);
                assert_eq!(report, std::path::PathBuf::from("decision.json"));
            }
            _ => panic!("expected chiodos runtime pheromone evaluate subcommand"),
        }
    }

    #[test]
    fn chiodos_runtime_sign_trust_input_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "runtime",
            "sign-trust-input",
            "--body",
            "runtime-trust-body.json",
            "--signing-seed-file",
            "verifier.seed",
            "--out",
            "runtime-trust.json",
        ])
        .unwrap();

        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Runtime {
                        command:
                            ChiodosRuntimeCommands::SignTrustInput {
                                body,
                                signing_seed_file,
                                out,
                            },
                    },
            } => {
                assert_eq!(body, std::path::PathBuf::from("runtime-trust-body.json"));
                assert_eq!(signing_seed_file, std::path::PathBuf::from("verifier.seed"));
                assert_eq!(out, std::path::PathBuf::from("runtime-trust.json"));
            }
            _ => panic!("expected chiodos runtime sign-trust-input subcommand"),
        }
    }

    #[test]
    fn chiodos_runtime_run_loopback_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
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
        ])
        .unwrap();

        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Runtime {
                        command:
                            ChiodosRuntimeCommands::RunLoopback {
                                scenario,
                                store_dir,
                                now_unix_ms,
                                out_dir,
                            },
                    },
            } => {
                assert_eq!(scenario, std::path::PathBuf::from("scenario.json"));
                assert_eq!(store_dir, std::path::PathBuf::from("stores"));
                assert_eq!(now_unix_ms, 1_800_000_001_000);
                assert_eq!(out_dir, std::path::PathBuf::from("out"));
            }
            _ => panic!("expected chiodos runtime run-loopback subcommand"),
        }
    }

    #[test]
    fn chiodos_runtime_orchestrate_run_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
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
        ])
        .unwrap();

        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Runtime {
                        command:
                            ChiodosRuntimeCommands::Orchestrate {
                                command:
                                    ChiodosRuntimeOrchestrateCommands::Run {
                                        profile,
                                        run_contract,
                                        store,
                                        evidence_dir,
                                        now_unix_ms,
                                        report,
                                    },
                            },
                    },
            } => {
                assert_eq!(profile, std::path::PathBuf::from("profile.json"));
                assert_eq!(run_contract, std::path::PathBuf::from("run-contract.json"));
                assert_eq!(store, std::path::PathBuf::from("runtime.sqlite3"));
                assert_eq!(evidence_dir, std::path::PathBuf::from("evidence"));
                assert_eq!(now_unix_ms, 1_800_000_001_000);
                assert_eq!(report, std::path::PathBuf::from("run-report.json"));
            }
            _ => panic!("expected chiodos runtime orchestrate run subcommand"),
        }
    }

    #[test]
    fn chiodos_runtime_ops_tick_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "runtime",
            "ops",
            "tick",
            "--supervisor-profile",
            "supervisor.json",
            "--store",
            "runtime.sqlite3",
            "--evidence-root",
            "evidence",
            "--owner-id",
            "operator-a",
            "--now-unix-ms",
            "1800000001000",
            "--max-runs",
            "2",
            "--report",
            "tick-report.json",
        ])
        .unwrap();

        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Runtime {
                        command:
                            ChiodosRuntimeCommands::Ops {
                                command:
                                    ChiodosRuntimeOpsCommands::Tick {
                                        supervisor_profile,
                                        store,
                                        evidence_root,
                                        owner_id,
                                        now_unix_ms,
                                        max_runs,
                                        report,
                                    },
                            },
                    },
            } => {
                assert_eq!(
                    supervisor_profile,
                    std::path::PathBuf::from("supervisor.json")
                );
                assert_eq!(store, std::path::PathBuf::from("runtime.sqlite3"));
                assert_eq!(evidence_root, std::path::PathBuf::from("evidence"));
                assert_eq!(owner_id, "operator-a");
                assert_eq!(now_unix_ms, 1_800_000_001_000);
                assert_eq!(max_runs, 2);
                assert_eq!(report, std::path::PathBuf::from("tick-report.json"));
            }
            _ => panic!("expected chiodos runtime ops tick subcommand"),
        }
    }

    #[test]
    fn chiodos_authority_issue_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
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
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Authority {
                        command:
                            ChiodosAuthorityCommands::Issue {
                                profile,
                                request,
                                signing_keys,
                                out_dir,
                            },
                    },
            } => {
                assert_eq!(profile, std::path::PathBuf::from("authority-profile.json"));
                assert_eq!(request, std::path::PathBuf::from("issuance-request.json"));
                assert_eq!(
                    signing_keys,
                    std::path::PathBuf::from("local-signing-keys.json")
                );
                assert_eq!(out_dir, std::path::PathBuf::from("issued"));
            }
            _ => panic!("expected chiodos authority issue subcommand"),
        }
    }

    #[test]
    fn chiodos_pheromone_relay_alert_handoff_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "alert",
            "handoff",
            "--alert-report",
            "relay-alert-report.json",
            "--trend-report",
            "relay-trend-report.json",
            "--routing-profile",
            "relay-alert-routing-profile.json",
            "--handoff-profile",
            "relay-alert-handoff-profile.json",
            "--now-unix-ms",
            "1766000060000",
            "--report",
            "relay-alert-handoff-report.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Alert {
                                        command:
                                            ChiodosPheromoneRelayAlertCommands::Handoff {
                                                alert_report,
                                                trend_report,
                                                routing_profile,
                                                handoff_profile,
                                                now_unix_ms,
                                                report,
                                            },
                                    },
                            },
                    },
            } => {
                assert_eq!(
                    alert_report,
                    std::path::PathBuf::from("relay-alert-report.json")
                );
                assert_eq!(
                    trend_report,
                    std::path::PathBuf::from("relay-trend-report.json")
                );
                assert_eq!(
                    routing_profile,
                    std::path::PathBuf::from("relay-alert-routing-profile.json")
                );
                assert_eq!(
                    handoff_profile,
                    std::path::PathBuf::from("relay-alert-handoff-profile.json")
                );
                assert_eq!(now_unix_ms, 1_766_000_060_000);
                assert_eq!(
                    report,
                    std::path::PathBuf::from("relay-alert-handoff-report.json")
                );
            }
            _ => panic!("expected chiodos pheromone relay alert handoff subcommand"),
        }
    }

    #[test]
    fn chiodos_pheromone_relay_alert_delivery_subcommands_parse() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "alert",
            "delivery",
            "import",
            "--handoff-report",
            "relay-alert-handoff-report.json",
            "--delivery-profile",
            "relay-alert-delivery-profile.json",
            "--evidence-dir",
            "delivery-evidence",
            "--now-unix-ms",
            "1766000060000",
            "--report",
            "relay-alert-delivery-report.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Alert {
                                        command:
                                            ChiodosPheromoneRelayAlertCommands::Delivery {
                                                command:
                                                    ChiodosPheromoneRelayAlertDeliveryCommands::Import {
                                                        handoff_report,
                                                        delivery_profile,
                                                        evidence_dir,
                                                        now_unix_ms,
                                                        report,
                                                    },
                                            },
                                    },
                            },
                    },
            } => {
                assert_eq!(
                    handoff_report,
                    std::path::PathBuf::from("relay-alert-handoff-report.json")
                );
                assert_eq!(
                    delivery_profile,
                    std::path::PathBuf::from("relay-alert-delivery-profile.json")
                );
                assert_eq!(evidence_dir, std::path::PathBuf::from("delivery-evidence"));
                assert_eq!(now_unix_ms, 1_766_000_060_000);
                assert_eq!(
                    report,
                    std::path::PathBuf::from("relay-alert-delivery-report.json")
                );
            }
            _ => panic!("expected chiodos pheromone relay alert delivery import subcommand"),
        }

        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "alert",
            "delivery",
            "acknowledge",
            "--handoff-report",
            "relay-alert-handoff-report.json",
            "--delivery-report",
            "relay-alert-delivery-report.json",
            "--delivery-profile",
            "relay-alert-delivery-profile.json",
            "--now-unix-ms",
            "1766000060000",
            "--report",
            "relay-alert-acknowledgement-report.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Alert {
                                        command:
                                            ChiodosPheromoneRelayAlertCommands::Delivery {
                                                command:
                                                    ChiodosPheromoneRelayAlertDeliveryCommands::Acknowledge {
                                                        delivery_report,
                                                        report,
                                                        ..
                                                    },
                                            },
                                    },
                            },
                    },
            } => {
                assert_eq!(
                    delivery_report,
                    std::path::PathBuf::from("relay-alert-delivery-report.json")
                );
                assert_eq!(
                    report,
                    std::path::PathBuf::from("relay-alert-acknowledgement-report.json")
                );
            }
            _ => panic!("expected chiodos pheromone relay alert delivery acknowledge subcommand"),
        }

        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "alert",
            "delivery",
            "drift",
            "--handoff-reports-dir",
            "handoff-reports",
            "--delivery-reports-dir",
            "delivery-reports",
            "--delivery-profile",
            "relay-alert-delivery-profile.json",
            "--since-unix-ms",
            "1765999900000",
            "--until-unix-ms",
            "1766000060000",
            "--report",
            "relay-alert-handoff-drift-report.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Alert {
                                        command:
                                            ChiodosPheromoneRelayAlertCommands::Delivery {
                                                command:
                                                    ChiodosPheromoneRelayAlertDeliveryCommands::Drift {
                                                        handoff_reports_dir,
                                                        delivery_reports_dir,
                                                        since_unix_ms,
                                                        until_unix_ms,
                                                        report,
                                                        ..
                                                    },
                                            },
                                    },
                            },
                    },
            } => {
                assert_eq!(
                    handoff_reports_dir,
                    std::path::PathBuf::from("handoff-reports")
                );
                assert_eq!(
                    delivery_reports_dir,
                    std::path::PathBuf::from("delivery-reports")
                );
                assert_eq!(since_unix_ms, 1_765_999_900_000);
                assert_eq!(until_unix_ms, 1_766_000_060_000);
                assert_eq!(
                    report,
                    std::path::PathBuf::from("relay-alert-handoff-drift-report.json")
                );
            }
            _ => panic!("expected chiodos pheromone relay alert delivery drift subcommand"),
        }
    }

    #[test]
    fn chiodos_pheromone_relay_alert_assurance_subcommands_parse() {
        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "alert",
            "normalize",
            "--profile",
            "relay-alert-normalization-profile.json",
            "--input-dir",
            "downstream-alerts",
            "--now-unix-ms",
            "1766000070000",
            "--out-dir",
            "normalized-delivery",
            "--report",
            "relay-alert-normalization-report.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Alert {
                                        command:
                                            ChiodosPheromoneRelayAlertCommands::Normalize {
                                                profile,
                                                input_dir,
                                                now_unix_ms,
                                                out_dir,
                                                report,
                                            },
                                    },
                            },
                    },
            } => {
                assert_eq!(
                    profile,
                    std::path::PathBuf::from("relay-alert-normalization-profile.json")
                );
                assert_eq!(input_dir, std::path::PathBuf::from("downstream-alerts"));
                assert_eq!(now_unix_ms, 1_766_000_070_000);
                assert_eq!(out_dir, std::path::PathBuf::from("normalized-delivery"));
                assert_eq!(
                    report,
                    std::path::PathBuf::from("relay-alert-normalization-report.json")
                );
            }
            _ => panic!("expected chiodos pheromone relay alert normalize subcommand"),
        }

        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "alert",
            "delivery",
            "drift-window",
            "--handoff-reports-dir",
            "handoff-reports",
            "--delivery-reports-dir",
            "delivery-reports",
            "--delivery-profile",
            "relay-alert-delivery-profile.json",
            "--since-unix-ms",
            "1765999900000",
            "--until-unix-ms",
            "1766000090000",
            "--report",
            "relay-alert-delivery-drift-report-v2.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Alert {
                                        command:
                                            ChiodosPheromoneRelayAlertCommands::Delivery {
                                                command:
                                                    ChiodosPheromoneRelayAlertDeliveryCommands::DriftWindow {
                                                        handoff_reports_dir,
                                                        delivery_reports_dir,
                                                        until_unix_ms,
                                                        report,
                                                        ..
                                                    },
                                            },
                                    },
                            },
                    },
            } => {
                assert_eq!(
                    handoff_reports_dir,
                    std::path::PathBuf::from("handoff-reports")
                );
                assert_eq!(
                    delivery_reports_dir,
                    std::path::PathBuf::from("delivery-reports")
                );
                assert_eq!(until_unix_ms, 1_766_000_090_000);
                assert_eq!(
                    report,
                    std::path::PathBuf::from("relay-alert-delivery-drift-report-v2.json")
                );
            }
            _ => panic!("expected chiodos pheromone relay alert delivery drift-window subcommand"),
        }

        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "alert",
            "review",
            "--handoff-report",
            "relay-alert-handoff-report.json",
            "--delivery-report",
            "relay-alert-delivery-report.json",
            "--acknowledgement-report",
            "relay-alert-acknowledgement-report.json",
            "--drift-report",
            "relay-alert-delivery-drift-report-v2.json",
            "--route-owner-profile",
            "relay-alert-route-owner-profile.json",
            "--now-unix-ms",
            "1766000090000",
            "--report",
            "relay-alert-route-review-packet.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Alert {
                                        command:
                                            ChiodosPheromoneRelayAlertCommands::Review {
                                                route_owner_profile,
                                                report,
                                                ..
                                            },
                                    },
                            },
                    },
            } => {
                assert_eq!(
                    route_owner_profile,
                    std::path::PathBuf::from("relay-alert-route-owner-profile.json")
                );
                assert_eq!(
                    report,
                    std::path::PathBuf::from("relay-alert-route-review-packet.json")
                );
            }
            _ => panic!("expected chiodos pheromone relay alert review subcommand"),
        }

        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "alert",
            "assurance",
            "package",
            "--alert-report",
            "relay-alert-report.json",
            "--trend-report",
            "relay-trend-report.json",
            "--handoff-report",
            "relay-alert-handoff-report.json",
            "--normalization-report",
            "relay-alert-normalization-report.json",
            "--delivery-report",
            "relay-alert-delivery-report.json",
            "--acknowledgement-report",
            "relay-alert-acknowledgement-report.json",
            "--drift-report",
            "relay-alert-delivery-drift-report-v2.json",
            "--review-packet",
            "relay-alert-route-review-packet.json",
            "--now-unix-ms",
            "1766000090000",
            "--report",
            "relay-alert-assurance-package.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Alert {
                                        command:
                                            ChiodosPheromoneRelayAlertCommands::Assurance {
                                                command:
                                                    ChiodosPheromoneRelayAlertAssuranceCommands::Package {
                                                        normalization_report,
                                                        review_packet,
                                                        report,
                                                        ..
                                                    },
                                            },
                                    },
                            },
                    },
            } => {
                assert_eq!(
                    normalization_report,
                    std::path::PathBuf::from("relay-alert-normalization-report.json")
                );
                assert_eq!(
                    review_packet,
                    std::path::PathBuf::from("relay-alert-route-review-packet.json")
                );
                assert_eq!(
                    report,
                    std::path::PathBuf::from("relay-alert-assurance-package.json")
                );
            }
            _ => panic!("expected chiodos pheromone relay alert assurance package subcommand"),
        }

        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "alert",
            "assurance",
            "export",
            "--package",
            "relay-alert-assurance-package.json",
            "--alert-report",
            "relay-alert-report.json",
            "--trend-report",
            "relay-trend-report.json",
            "--handoff-report",
            "relay-alert-handoff-report.json",
            "--normalization-report",
            "relay-alert-normalization-report.json",
            "--delivery-report",
            "relay-alert-delivery-report.json",
            "--acknowledgement-report",
            "relay-alert-acknowledgement-report.json",
            "--drift-report",
            "relay-alert-delivery-drift-report-v2.json",
            "--review-packet",
            "relay-alert-route-review-packet.json",
            "--retention-profile",
            "relay-alert-assurance-retention-profile.json",
            "--signing-key",
            "relay-export-signing-key.json",
            "--now-unix-ms",
            "1766000100000",
            "--out-dir",
            "export-bundle",
            "--report",
            "relay-alert-assurance-export-report.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Alert {
                                        command:
                                            ChiodosPheromoneRelayAlertCommands::Assurance {
                                                command:
                                                    ChiodosPheromoneRelayAlertAssuranceCommands::Export {
                                                        package,
                                                        out_dir,
                                                        report,
                                                        ..
                                                    },
                                            },
                                    },
                            },
                    },
            } => {
                assert_eq!(
                    package,
                    std::path::PathBuf::from("relay-alert-assurance-package.json")
                );
                assert_eq!(out_dir, std::path::PathBuf::from("export-bundle"));
                assert_eq!(
                    report,
                    std::path::PathBuf::from("relay-alert-assurance-export-report.json")
                );
            }
            _ => panic!("expected chiodos pheromone relay alert assurance export subcommand"),
        }

        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "alert",
            "assurance",
            "replay",
            "--bundle-dir",
            "export-bundle",
            "--trusted-exporters",
            "trusted-exporters.json",
            "--now-unix-ms",
            "1766000100000",
            "--report",
            "relay-alert-assurance-replay-report.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Alert {
                                        command:
                                            ChiodosPheromoneRelayAlertCommands::Assurance {
                                                command:
                                                    ChiodosPheromoneRelayAlertAssuranceCommands::Replay {
                                                        bundle_dir,
                                                        trusted_exporters,
                                                        report,
                                                        ..
                                                    },
                                            },
                                    },
                            },
                    },
            } => {
                assert_eq!(bundle_dir, std::path::PathBuf::from("export-bundle"));
                assert_eq!(
                    trusted_exporters,
                    std::path::PathBuf::from("trusted-exporters.json")
                );
                assert_eq!(
                    report,
                    std::path::PathBuf::from("relay-alert-assurance-replay-report.json")
                );
            }
            _ => panic!("expected chiodos pheromone relay alert assurance replay subcommand"),
        }

        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "alert",
            "assurance",
            "retention",
            "plan",
            "--bundle-root",
            "exports",
            "--retention-profile",
            "relay-alert-assurance-retention-profile.json",
            "--now-unix-ms",
            "1766000100000",
            "--report",
            "relay-alert-assurance-retention-report.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Alert {
                                        command:
                                            ChiodosPheromoneRelayAlertCommands::Assurance {
                                                command:
                                                    ChiodosPheromoneRelayAlertAssuranceCommands::Retention {
                                                        command:
                                                            ChiodosPheromoneRelayAlertAssuranceRetentionCommands::Plan {
                                                                bundle_root,
                                                                report,
                                                                ..
                                                            },
                                                    },
                                            },
                                    },
                            },
                    },
            } => {
                assert_eq!(bundle_root, std::path::PathBuf::from("exports"));
                assert_eq!(
                    report,
                    std::path::PathBuf::from("relay-alert-assurance-retention-report.json")
                );
            }
            _ => panic!(
                "expected chiodos pheromone relay alert assurance retention plan subcommand"
            ),
        }

        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "alert",
            "assurance",
            "archive",
            "plan",
            "--bundle-root",
            "exports",
            "--trusted-exporters",
            "trusted-exporters.json",
            "--archive-profile",
            "relay-alert-assurance-archive-profile.json",
            "--retention-profile",
            "relay-alert-assurance-retention-profile.json",
            "--now-unix-ms",
            "1766000100000",
            "--report",
            "relay-alert-assurance-archive-report.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Alert {
                                        command:
                                            ChiodosPheromoneRelayAlertCommands::Assurance {
                                                command:
                                                    ChiodosPheromoneRelayAlertAssuranceCommands::Archive {
                                                        command:
                                                            ChiodosPheromoneRelayAlertAssuranceArchiveCommands::Plan {
                                                                bundle_root,
                                                                trusted_exporters,
                                                                archive_profile,
                                                                report,
                                                                ..
                                                            },
                                                    },
                                            },
                                    },
                            },
                    },
            } => {
                assert_eq!(bundle_root, std::path::PathBuf::from("exports"));
                assert_eq!(
                    trusted_exporters,
                    std::path::PathBuf::from("trusted-exporters.json")
                );
                assert_eq!(
                    archive_profile,
                    std::path::PathBuf::from("relay-alert-assurance-archive-profile.json")
                );
                assert_eq!(
                    report,
                    std::path::PathBuf::from("relay-alert-assurance-archive-report.json")
                );
            }
            _ => panic!("expected chiodos pheromone relay alert assurance archive plan subcommand"),
        }

        let cli = Cli::try_parse_from([
            "chio",
            "chiodos",
            "pheromone",
            "relay",
            "alert",
            "assurance",
            "closeout",
            "review",
            "--bundle-root",
            "exports",
            "--trusted-exporters",
            "trusted-exporters.json",
            "--closeout-profile",
            "relay-alert-assurance-closeout-profile.json",
            "--retention-profile",
            "relay-alert-assurance-retention-profile.json",
            "--now-unix-ms",
            "1766000100000",
            "--report",
            "relay-alert-assurance-closeout-report.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Chiodos {
                command:
                    ChiodosCommands::Pheromone {
                        command:
                            ChiodosPheromoneCommands::Relay {
                                command:
                                    ChiodosPheromoneRelayCommands::Alert {
                                        command:
                                            ChiodosPheromoneRelayAlertCommands::Assurance {
                                                command:
                                                    ChiodosPheromoneRelayAlertAssuranceCommands::Closeout {
                                                        command:
                                                            ChiodosPheromoneRelayAlertAssuranceCloseoutCommands::Review {
                                                                closeout_profile,
                                                                report,
                                                                ..
                                                            },
                                                    },
                                            },
                                    },
                            },
                    },
            } => {
                assert_eq!(
                    closeout_profile,
                    std::path::PathBuf::from("relay-alert-assurance-closeout-profile.json")
                );
                assert_eq!(
                    report,
                    std::path::PathBuf::from("relay-alert-assurance-closeout-report.json")
                );
            }
            _ => {
                panic!("expected chiodos pheromone relay alert assurance closeout review subcommand")
            }
        }
    }

    #[test]
    fn mcp_wrap_emit_config_flag_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "mcp",
            "wrap",
            "--emit-config",
            "cursor",
            "--",
            "echo",
        ])
        .expect("mcp wrap emit-config parses");

        match cli.command {
            Commands::Mcp {
                command: McpCommands::Wrap(args),
            } => {
                assert_eq!(args.emit_config, Some(IdeTarget::Cursor));
            }
            _ => panic!("expected mcp wrap subcommand"),
        }
    }

    #[test]
    fn write_cli_error_emits_capability_registry_report() -> Result<(), Box<dyn Error>> {
        let rendered = render_error_json(&CliError::capability_scope_error(
            "capability does not grant tool access",
        ))?;

        assert_eq!(rendered["code"], "urn:chio:error:capability:scope-exceeded");
        assert_eq!(rendered["context"]["domain"], "capability");
        assert!(
            rendered["suggested_fix"]
                .as_str()
                .is_some_and(|fix| fix.contains("Issue a capability"))
        );

        Ok(())
    }

    #[test]
    fn write_cli_error_emits_policy_registry_report() -> Result<(), Box<dyn Error>> {
        let rendered = render_error_json(&CliError::policy_constraint_error(
            "invalid governed autonomy tier",
        ))?;

        assert_eq!(rendered["code"], "urn:chio:error:policy:constraint-invalid");
        assert_eq!(rendered["context"]["domain"], "policy");
        assert!(
            rendered["suggested_fix"]
                .as_str()
                .is_some_and(|fix| fix.contains("constraint"))
        );

        Ok(())
    }

    #[test]
    fn write_cli_error_emits_transport_registry_report() -> Result<(), Box<dyn Error>> {
        let rendered = render_error_json(&CliError::transport_shape_error(
            "OID4VP request URL must include a host",
        ))?;

        assert_eq!(
            rendered["code"],
            "urn:chio:error:transport:invalid-request-shape"
        );
        assert_eq!(rendered["context"]["domain"], "transport");
        assert!(
            rendered["suggested_fix"]
                .as_str()
                .is_some_and(|fix| fix.contains("request shape"))
        );

        Ok(())
    }

    #[test]
    fn chiodos_runtime_loopback_capability_window_covers_replay_and_wall_clock() {
        let replay_now_unix_ms = 4_102_444_800_000;
        let wall_now_secs = unix_now_ms() / 1000;

        let (issued_at, expires_at) =
            chio_chiodos_runtime_harness::runtime_loopback_capability_window(replay_now_unix_ms);

        assert!(issued_at <= replay_now_unix_ms / 1000);
        assert!(expires_at > replay_now_unix_ms / 1000);
        assert!(issued_at <= wall_now_secs);
        assert!(expires_at > wall_now_secs);
    }

    #[test]
    fn hidden_chio_attest_verify_shortcut_is_rejected() {
        let error = match Cli::try_parse_from([
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

    #[test]
    fn chio_attest_legacy_chiodos_v1_verify_surface_parses() {
        let cli = Cli::try_parse_from([
            "chio",
            "attest",
            "legacy",
            "chiodos-v1",
            "verify",
            "--package",
            "proof-package.json",
            "--trust-bundle",
            "trust-bundle.json",
            "--context",
            "context.json",
            "--report",
            "report.json",
        ])
        .unwrap();

        match cli.command {
            Commands::Attest {
                command:
                    ChioAttestCommands::Legacy {
                        command:
                            ChioAttestLegacyCommands::ChiodosV1 {
                                command:
                                    ChioAttestLegacyChiodosV1Commands::Verify {
                                        package,
                                        trust_bundle,
                                        context,
                                        report,
                                    },
                            },
                    },
            } => {
                assert_eq!(package, std::path::PathBuf::from("proof-package.json"));
                assert_eq!(trust_bundle, std::path::PathBuf::from("trust-bundle.json"));
                assert_eq!(context, std::path::PathBuf::from("context.json"));
                assert_eq!(report, std::path::PathBuf::from("report.json"));
            }
            _ => panic!("expected chio attest legacy chiodos-v1 verify surface"),
        }
    }

    #[test]
    fn legacy_chiodos_surface_is_hidden_from_root_help() {
        let mut command = Cli::command();
        let help = command.render_long_help().to_string();
        assert!(!help.contains("chiodos"));

        let legacy = Cli::try_parse_from([
            "chio",
            "chiodos",
            "verify",
            "--package",
            "proof-package.json",
            "--trust-bundle",
            "trust-bundle.json",
            "--context",
            "context.json",
            "--report",
            "report.json",
        ])
        .unwrap();
        assert!(matches!(
            legacy.command,
            Commands::Chiodos {
                command: ChiodosCommands::Verify { .. }
            }
        ));
    }

    fn rendered_help(args: &[&str]) -> String {
        let error = match Cli::try_parse_from(args) {
            Ok(_) => panic!("help exits before parsing command values"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
        error.to_string()
    }

    #[test]
    fn public_chio_help_uses_chio_names_outside_legacy_attest() {
        let public_help = [
            rendered_help(&["chio", "federation", "authority", "issue", "--help"]),
            rendered_help(&["chio", "runtime", "--help"]),
            rendered_help(&["chio", "pheromone", "receive", "--help"]),
            rendered_help(&["chio", "pheromone", "relay", "serve", "--help"]),
        ]
        .join("\n");

        assert!(
            !public_help.contains("Chiodos"),
            "normal public Chio help must not describe inputs as Chiodos material"
        );
        assert!(
            !public_help.contains("chiodos"),
            "normal public Chio help must not expose chiodos wording"
        );

        let legacy_help =
            rendered_help(&["chio", "attest", "legacy", "chiodos-v1", "verify", "--help"]);
        assert!(legacy_help.contains("Chiodos"));
        assert!(legacy_help.contains("chiodos-v1"));
    }

    #[test]
    fn chio_attest_buyer_packet_surface_parses() {
        let cli = Cli::try_parse_from([
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
    fn chio_attest_buyer_public_outputs_use_chio_error_and_schema_boundary()
    -> Result<(), Box<dyn Error>> {
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
        assert!(
            !rendered_text.contains("Chiodos"),
            "public buyer error should not expose historical Chiodos wording: {rendered_text}"
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
        let explanation: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&explanation_out)?)?;
        assert_eq!(
            explanation["schema"],
            "chio.attest.buyer-attestation-explanation.v1"
        );
        assert!(
            !explanation.to_string().contains("chio.chiodos."),
            "public buyer explanation must emit a Chio-native schema id"
        );

        Ok(())
    }

    #[test]
    fn chio_attest_buyer_verify_packet_surface_parses() {
        let cli = Cli::try_parse_from([
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
        let cli = Cli::try_parse_from([
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
        let cli = Cli::try_parse_from([
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
        let cli = Cli::try_parse_from([
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
                            ChiodosTreatyCommands::VerifyPacket {
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
        let cli = Cli::try_parse_from([
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
                    ChiodosRuntimeCommands::SignTrustInput {
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
        let cli = Cli::try_parse_from([
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
                    ChiodosPheromoneCommands::Query {
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
        let runtime = Cli::try_parse_from([
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

        let pheromone = Cli::try_parse_from([
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

        let federation = Cli::try_parse_from([
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

        let attest = Cli::try_parse_from([
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

        let legacy = Cli::try_parse_from([
            "chio",
            "attest",
            "legacy",
            "chiodos-v1",
            "verify",
            "--package",
            "proof-package.json",
            "--trust-bundle",
            "trust-bundle.json",
            "--context",
            "context.json",
            "--report",
            "report.json",
        ])
        .unwrap()
        .command;
        assert!(matches!(
            legacy,
            Commands::Attest {
                command: ChioAttestCommands::Legacy { .. }
            }
        ));
    }

    #[test]
    fn chio_federation_treaty_dispatch_uses_chio_handlers() {
        let dispatch = include_str!("cli/dispatch.rs");
        let treaty_dispatch = dispatch
            .split("fn dispatch_chio_treaty_command")
            .nth(1)
            .expect("dispatch_chio_treaty_command exists")
            .split("fn dispatch_chio_attest_command")
            .next()
            .expect("dispatch_chio_treaty_command has following function");

        assert!(treaty_dispatch.contains("cmd_chio_federation_treaty_intersect("));
        assert!(treaty_dispatch.contains("cmd_chio_federation_treaty_admit("));
        assert!(treaty_dispatch.contains("cmd_chio_federation_treaty_verify_packet("));
        assert!(!treaty_dispatch.contains("cmd_chiodos_treaty_"));
    }

    #[test]
    fn chio_federation_treaty_handlers_do_not_call_historical_runtime_directly() {
        let treaty_handlers = include_str!("cli/chiodos/dispatch/treaty.rs");

        assert!(!treaty_handlers.contains("chio_chiodos_runtime::"));
    }

    #[test]
    fn chio_runtime_dispatch_handlers_do_not_call_historical_runtime_directly() {
        let runtime_modules = [
            include_str!("cli/chiodos/dispatch/runtime.rs"),
            include_str!("cli/chiodos/dispatch/runtime/admission.rs"),
            include_str!("cli/chiodos/dispatch/runtime/io.rs"),
            include_str!("cli/chiodos/dispatch/runtime/loopback.rs"),
            include_str!("cli/chiodos/dispatch/runtime/ops.rs"),
            include_str!("cli/chiodos/dispatch/runtime/orchestration.rs"),
            include_str!("cli/chiodos/dispatch/runtime/signing.rs"),
        ];

        for module in runtime_modules {
            assert!(!module.contains("chio_chiodos_runtime::"));
        }
    }

    #[test]
    fn chio_runtime_active_subject_namespaces_are_chio_native() {
        let runtime_admission = include_str!("cli/chiodos/dispatch/runtime/admission.rs");
        let historical_namespace = format!("{}.{}", "chiodos", "runtime");
        let chio_namespace = format!("{}.{}", "chio", "runtime");
        let expected_assignment =
            format!("subject_class_namespace: \"{chio_namespace}\".to_string()");

        assert!(
            !runtime_admission.contains(&historical_namespace),
            "active Chio runtime admission dispatch tests must not use historical runtime subject namespaces"
        );
        assert!(
            runtime_admission.contains(&expected_assignment),
            "active Chio runtime admission dispatch tests must exercise the Chio runtime subject namespace"
        );
    }

    #[test]
    fn chio_federation_authority_dispatch_uses_chio_handlers() {
        let dispatch = include_str!("cli/dispatch.rs");
        let authority_dispatch = dispatch
            .split("fn dispatch_chio_authority_command")
            .nth(1)
            .expect("dispatch_chio_authority_command exists")
            .split("fn dispatch_chio_treaty_command")
            .next()
            .expect("dispatch_chio_authority_command has following function");

        assert!(authority_dispatch.contains("cmd_chio_federation_authority_issue("));
        assert!(authority_dispatch.contains("cmd_chio_federation_authority_checkpoint("));
        assert!(
            authority_dispatch.contains("cmd_chio_federation_authority_trust_bundle_assemble(")
        );
        assert!(!authority_dispatch.contains("cmd_chiodos_authority_"));
    }

    #[test]
    fn chio_federation_dispatch_uses_chio_command_types() {
        let dispatch = include_str!("cli/dispatch.rs");
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
            .expect("dispatch_chio_treaty_command exists")
            .split("fn dispatch_chio_attest_command")
            .next()
            .expect("dispatch_chio_treaty_command has following function");

        assert!(authority_dispatch.contains("command: ChioAuthorityCommands"));
        assert!(authority_dispatch.contains("ChioAuthorityCommands::"));
        assert!(authority_dispatch.contains("ChioTrustBundleCommands::"));
        assert!(!authority_dispatch.contains("ChiodosAuthorityCommands"));
        assert!(!authority_dispatch.contains("ChiodosTrustBundleCommands::"));
        assert!(treaty_dispatch.contains("command: ChioTreatyCommands"));
        assert!(treaty_dispatch.contains("ChioTreatyCommands::"));
        assert!(!treaty_dispatch.contains("ChiodosTreatyCommands"));
    }

    #[test]
    fn chio_runtime_signing_dispatch_uses_chio_handlers() {
        let dispatch = include_str!("cli/dispatch.rs");
        let runtime_dispatch = dispatch
            .split("fn dispatch_chio_runtime_command")
            .nth(1)
            .expect("dispatch_chio_runtime_command exists")
            .split("fn dispatch_chio_pheromone_command")
            .next()
            .expect("dispatch_chio_runtime_command has following function");

        assert!(runtime_dispatch.contains("cmd_chio_runtime_sign_trust_input("));
        assert!(runtime_dispatch.contains("cmd_chio_runtime_sign_policy("));
        assert!(runtime_dispatch.contains("cmd_chio_runtime_peer_weights_hash("));
        assert!(runtime_dispatch.contains("cmd_chio_runtime_sign_peer_weights("));
        assert!(runtime_dispatch.contains("cmd_chio_runtime_sign_pheromone_query_report("));
        assert!(!runtime_dispatch.contains("cmd_chiodos_runtime_sign_trust_input("));
        assert!(!runtime_dispatch.contains("cmd_chiodos_runtime_sign_policy("));
        assert!(!runtime_dispatch.contains("cmd_chiodos_runtime_peer_weights_hash("));
        assert!(!runtime_dispatch.contains("cmd_chiodos_runtime_sign_peer_weights("));
        assert!(!runtime_dispatch.contains("cmd_chiodos_runtime_sign_pheromone_query_report("));
    }

    #[test]
    fn chio_runtime_dispatch_uses_only_chio_handlers() {
        let dispatch = include_str!("cli/dispatch.rs");
        let runtime_dispatch = dispatch
            .split("fn dispatch_chio_runtime_command")
            .nth(1)
            .expect("dispatch_chio_runtime_command exists")
            .split("fn dispatch_chio_pheromone_command")
            .next()
            .expect("dispatch_chio_runtime_command has following function");

        assert!(!runtime_dispatch.contains("cmd_chiodos_runtime_"));
    }

    #[test]
    fn chio_runtime_dispatch_uses_chio_command_types() {
        let dispatch = include_str!("cli/dispatch.rs");
        let runtime_dispatch = dispatch
            .split("fn dispatch_chio_runtime_command")
            .nth(1)
            .expect("dispatch_chio_runtime_command exists")
            .split("fn dispatch_chio_pheromone_command")
            .next()
            .expect("dispatch_chio_runtime_command has following function");

        assert!(runtime_dispatch.contains("command: ChioRuntimeCommands"));
        assert!(runtime_dispatch.contains("ChioRuntimePolicyCommands::"));
        assert!(runtime_dispatch.contains("ChioRuntimePeerWeightsCommands::"));
        assert!(runtime_dispatch.contains("ChioRuntimePheromoneCommands::"));
        assert!(runtime_dispatch.contains("ChioRuntimeOrchestrateCommands::"));
        assert!(runtime_dispatch.contains("ChioRuntimeOpsCommands::"));
        assert!(runtime_dispatch.contains("ChioRuntimeOpsRetentionCommands::"));
        assert!(!runtime_dispatch.contains("ChiodosRuntimeCommands"));
        assert!(!runtime_dispatch.contains("ChiodosRuntimePolicyCommands::"));
        assert!(!runtime_dispatch.contains("ChiodosRuntimePeerWeightsCommands::"));
        assert!(!runtime_dispatch.contains("ChiodosRuntimePheromoneCommands::"));
        assert!(!runtime_dispatch.contains("ChiodosRuntimeOrchestrateCommands::"));
        assert!(!runtime_dispatch.contains("ChiodosRuntimeOpsCommands::"));
        assert!(!runtime_dispatch.contains("ChiodosRuntimeOpsRetentionCommands::"));
    }

    #[test]
    fn public_chio_runtime_pheromone_query_errors_use_chio_boundary()
    -> Result<(), Box<dyn Error>> {
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
        assert!(
            !rendered_text.contains("Chiodos"),
            "public runtime error should not expose historical Chiodos wording: {rendered_text}"
        );

        let runtime_admission = include_str!("cli/chiodos/dispatch/runtime/admission.rs");
        assert!(!runtime_admission.contains("Chiodos signed pheromone query report parse"));

        Ok(())
    }

    #[test]
    fn chio_pheromone_core_relay_dispatch_uses_chio_handlers() {
        let dispatch = include_str!("cli/dispatch.rs");
        let pheromone_dispatch = dispatch
            .split("fn dispatch_chio_pheromone_command")
            .nth(1)
            .expect("dispatch_chio_pheromone_command exists")
            .split("fn cmd_chio_attest_supply_chain_verify")
            .next()
            .expect("dispatch_chio_pheromone_command has following function");

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
        let chiodos_handlers = [
            "cmd_chiodos_pheromone_relay_lint(",
            "cmd_chiodos_pheromone_relay_serve(",
            "cmd_chiodos_pheromone_relay_enqueue(",
            "cmd_chiodos_pheromone_relay_tick(",
            "cmd_chiodos_pheromone_relay_catchup(",
            "cmd_chiodos_pheromone_relay_status(",
            "cmd_chiodos_pheromone_relay_observe(",
            "cmd_chiodos_pheromone_relay_metrics(",
            "cmd_chiodos_pheromone_relay_trend(",
        ];

        for handler in chio_handlers {
            assert!(pheromone_dispatch.contains(handler), "{handler}");
        }
        for handler in chiodos_handlers {
            assert!(!pheromone_dispatch.contains(handler), "{handler}");
        }
    }

    #[test]
    fn public_chio_pheromone_verified_workflow_errors_use_chio_boundary()
    -> Result<(), Box<dyn Error>> {
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
        assert!(
            !rendered_text.contains("Chiodos"),
            "public pheromone error should not expose historical Chiodos wording: {rendered_text}"
        );

        let runtime_dispatch = include_str!("cli/chiodos/dispatch/pheromone/runtime.rs");
        let relay_dispatch = include_str!("cli/chiodos/dispatch/pheromone/relay.rs");
        for source in [runtime_dispatch, relay_dispatch] {
            assert!(!source.contains("Chiodos proof package"));
            assert!(!source.contains("Chiodos verifier trust bundle"));
            assert!(!source.contains("Chiodos verification context"));
            assert!(!source.contains("Chiodos package parse"));
            assert!(!source.contains("Chiodos trust bundle parse"));
            assert!(!source.contains("Chiodos context parse"));
            assert!(!source.contains("Chiodos workflow resolver"));
        }

        Ok(())
    }

    #[test]
    fn chio_pheromone_dispatch_uses_chio_command_types() {
        let dispatch = include_str!("cli/dispatch.rs");
        let pheromone_dispatch = dispatch
            .split("fn dispatch_chio_pheromone_command")
            .nth(1)
            .expect("dispatch_chio_pheromone_command exists")
            .split("fn cmd_chio_attest_supply_chain_verify")
            .next()
            .expect("dispatch_chio_pheromone_command has following function");

        assert!(pheromone_dispatch.contains("command: ChioPheromoneCommands"));
        assert!(pheromone_dispatch.contains("ChioPheromoneCommands::"));
        assert!(pheromone_dispatch.contains("ChioPheromoneRelayCommands::"));
        assert!(pheromone_dispatch.contains("ChioPheromoneRelayAlertCommands::"));
        assert!(pheromone_dispatch.contains("ChioPheromoneRelayAlertDeliveryCommands::"));
        assert!(pheromone_dispatch.contains("ChioPheromoneRelayAlertAssuranceCommands::"));
        assert!(pheromone_dispatch.contains("ChioPheromoneRelayAlertAssuranceRetentionCommands::"));
        assert!(pheromone_dispatch.contains("ChioPheromoneRelayAlertAssuranceArchiveCommands::"));
        assert!(pheromone_dispatch.contains("ChioPheromoneRelayAlertAssuranceCloseoutCommands::"));
        assert!(pheromone_dispatch.contains("ChioPheromoneRelayDirectoryCommands::"));
        assert!(pheromone_dispatch.contains("ChioPheromoneRelaySupervisorCommands::"));
        assert!(!pheromone_dispatch.contains("ChiodosPheromoneCommands"));
        assert!(!pheromone_dispatch.contains("ChiodosPheromoneRelayCommands::"));
        assert!(!pheromone_dispatch.contains("ChiodosPheromoneRelayAlertCommands::"));
        assert!(!pheromone_dispatch.contains("ChiodosPheromoneRelayAlertDeliveryCommands::"));
        assert!(!pheromone_dispatch.contains("ChiodosPheromoneRelayAlertAssuranceCommands::"));
        assert!(!pheromone_dispatch.contains("ChiodosPheromoneRelayAlertAssuranceRetentionCommands::"));
        assert!(!pheromone_dispatch.contains("ChiodosPheromoneRelayAlertAssuranceArchiveCommands::"));
        assert!(!pheromone_dispatch.contains("ChiodosPheromoneRelayAlertAssuranceCloseoutCommands::"));
        assert!(!pheromone_dispatch.contains("ChiodosPheromoneRelayDirectoryCommands::"));
        assert!(!pheromone_dispatch.contains("ChiodosPheromoneRelaySupervisorCommands::"));
    }

    #[test]
    fn chio_pheromone_remaining_relay_dispatch_uses_chio_handlers() {
        let dispatch = include_str!("cli/dispatch.rs");
        let pheromone_dispatch = dispatch
            .split("fn dispatch_chio_pheromone_command")
            .nth(1)
            .expect("dispatch_chio_pheromone_command exists")
            .split("fn cmd_chio_attest_supply_chain_verify")
            .next()
            .expect("dispatch_chio_pheromone_command has following function");

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
            "cmd_chio_pheromone_relay_alert_assurance_closeout_review(",
            "cmd_chio_pheromone_relay_directory_inspect(",
            "cmd_chio_pheromone_relay_directory_promote(",
            "cmd_chio_pheromone_relay_directory_reject(",
            "cmd_chio_pheromone_relay_supervisor_lint(",
        ];
        let chiodos_handlers = [
            "cmd_chiodos_pheromone_relay_alert_evaluate(",
            "cmd_chiodos_pheromone_relay_alert_handoff(",
            "cmd_chiodos_pheromone_relay_alert_normalize(",
            "cmd_chiodos_pheromone_relay_alert_review(",
            "cmd_chiodos_pheromone_relay_alert_delivery_import(",
            "cmd_chiodos_pheromone_relay_alert_delivery_acknowledge(",
            "cmd_chiodos_pheromone_relay_alert_delivery_drift(",
            "cmd_chiodos_pheromone_relay_alert_delivery_drift_window(",
            "cmd_chiodos_pheromone_relay_alert_assurance_package(",
            "cmd_chiodos_pheromone_relay_alert_assurance_export(",
            "cmd_chiodos_pheromone_relay_alert_assurance_verify(",
            "cmd_chiodos_pheromone_relay_alert_assurance_replay(",
            "cmd_chiodos_pheromone_relay_alert_assurance_retention_plan(",
            "cmd_chiodos_pheromone_relay_alert_assurance_recovery_drill(",
            "cmd_chiodos_pheromone_relay_alert_assurance_archive_plan(",
            "cmd_chiodos_pheromone_relay_alert_assurance_closeout_review(",
            "cmd_chiodos_pheromone_relay_directory_inspect(",
            "cmd_chiodos_pheromone_relay_directory_promote(",
            "cmd_chiodos_pheromone_relay_directory_reject(",
            "cmd_chiodos_pheromone_relay_supervisor_lint(",
        ];

        for handler in chio_handlers {
            assert!(pheromone_dispatch.contains(handler), "{handler}");
        }
        for handler in chiodos_handlers {
            assert!(!pheromone_dispatch.contains(handler), "{handler}");
        }
    }

    #[test]
    fn chio_pheromone_relay_gate_scripts_use_chio_filters() {
        let scripts = [
            include_str!("../../../scripts/check-chio-pheromone-relay-alert-assurance-archive.sh"),
            include_str!("../../../scripts/check-chio-pheromone-relay-alert-assurance-export.sh"),
            include_str!("../../../scripts/check-chio-pheromone-relay-alert-assurance.sh"),
            include_str!("../../../scripts/check-chio-pheromone-relay-alert-delivery.sh"),
            include_str!("../../../scripts/check-chio-pheromone-relay-alert-handoff.sh"),
            include_str!("../../../scripts/check-chio-pheromone-relay-alert-routing.sh"),
            include_str!("../../../scripts/check-chio-pheromone-relay-observability.sh"),
            include_str!("../../../scripts/check-chio-pheromone-relay-ops.sh"),
        ];
        let legacy_cli_filter = [
            "cargo test -p chio-cli --bin chio ",
            "chiodos",
            "_pheromone",
        ]
        .concat();
        let legacy_gate_ref = ["scripts/check-", "chiodos", "-pheromone"].concat();
        let legacy_ok_message = ["OK ", "Chiodos", " relay"].concat();
        for script in scripts {
            assert!(!script.contains(&legacy_cli_filter));
            assert!(!script.contains(&legacy_gate_ref));
            assert!(!script.contains(&legacy_ok_message));
        }
    }

    #[test]
    fn chio_gate_scripts_use_chio_authority_entrypoints() {
        let scripts = [
            include_str!("../../../scripts/check-chio-pheromone-transit.sh"),
            include_str!("../../../scripts/check-chio-pheromone-runtime.sh"),
        ];
        let legacy_authority_gate = ["scripts/check-", "chiodos", "-authority-issuance.sh"].concat();
        for script in scripts {
            assert!(!script.contains(&legacy_authority_gate));
        }
    }

    #[test]
    fn chio_pheromone_gates_use_chio_fixture_root() {
        let scripts = [
            include_str!("../../../scripts/check-chio-authority-issuance.sh"),
            include_str!("../../../scripts/check-chio-pheromone-directory-lifecycle.sh"),
            include_str!("../../../scripts/check-chio-pheromone-relay-alert-assurance-archive.sh"),
            include_str!("../../../scripts/check-chio-pheromone-relay-alert-assurance-export.sh"),
            include_str!("../../../scripts/check-chio-pheromone-relay-alert-assurance.sh"),
            include_str!("../../../scripts/check-chio-pheromone-relay-alert-delivery.sh"),
            include_str!("../../../scripts/check-chio-pheromone-relay-alert-handoff.sh"),
            include_str!("../../../scripts/check-chio-pheromone-relay-alert-routing.sh"),
            include_str!("../../../scripts/check-chio-pheromone-relay-observability.sh"),
            include_str!("../../../scripts/check-chio-pheromone-relay-ops.sh"),
            include_str!("../../../scripts/check-chio-pheromone-relay.sh"),
            include_str!("../../../scripts/check-chio-pheromone-runtime.sh"),
            include_str!("../../../scripts/check-chio-pheromone-transit.sh"),
        ];
        let workflows = [
            include_str!("../../../.github/workflows/chio-pheromone-directory-lifecycle.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-relay.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-relay-alert-assurance-archive.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-relay-alert-assurance-export.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-relay-alert-assurance.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-relay-alert-delivery.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-relay-alert-handoff.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-relay-alert-routing.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-relay-observability.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-relay-ops.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-runtime.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-transit.yml"),
        ];
        let legacy_fixture_root = ["examples/", "chiodos", "-3vendor"].concat();
        let chio_fixture_root = ["examples/", "chio", "-3vendor/fixtures"].concat();
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");

        assert!(repo_root.join(chio_fixture_root).is_dir());
        for script in scripts {
            assert!(!script.contains(&legacy_fixture_root));
        }
        for workflow in workflows {
            assert!(!workflow.contains(&legacy_fixture_root));
        }
    }

    #[test]
    fn chio_authority_gate_validates_local_signing_keys_schema() {
        let script = include_str!("../../../scripts/check-chio-authority-issuance.sh");
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
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
    fn chio_pheromone_workflows_watch_chio_named_docs_and_specs() {
        let workflows = [
            include_str!("../../../.github/workflows/chio-pheromone-directory-lifecycle.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-relay.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-relay-alert-assurance-archive.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-relay-alert-assurance-export.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-relay-alert-assurance.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-relay-alert-delivery.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-relay-alert-handoff.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-relay-alert-routing.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-relay-observability.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-relay-ops.yml"),
            include_str!("../../../.github/workflows/chio-pheromone-transit.yml"),
        ];
        let legacy_spec_path = ["spec/", "CHIODOS", "_PHEROMONE.md"].concat();
        let legacy_runbook_path =
            ["docs/release/", "CHIODOS", "_PHEROMONE_RELAY_RUNBOOK.md"].concat();
        let legacy_operator_docs_path =
            ["docs/release/", "chiodos", "-pheromone-relay/"].concat();
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let legacy_directory_workflow = repo_root.join(
            [
                ".github/workflows/",
                "chiodos",
                "-pheromone-directory-lifecycle.yml",
            ]
            .concat(),
        );
        let legacy_operator_docs_dir =
            repo_root.join(["docs/release/", "chiodos", "-pheromone-relay"].concat());
        assert!(!legacy_directory_workflow.exists());
        assert!(!legacy_operator_docs_dir.exists());
        for workflow in workflows {
            assert!(!workflow.contains(&legacy_spec_path));
            assert!(!workflow.contains(&legacy_runbook_path));
            assert!(!workflow.contains(&legacy_operator_docs_path));
        }
    }

    #[test]
    fn chio_attest_legacy_dispatch_uses_chio_handler() {
        let dispatch = include_str!("cli/dispatch.rs");
        let attest_dispatch = dispatch
            .split("fn dispatch_chio_attest_command")
            .nth(1)
            .expect("dispatch_chio_attest_command exists")
            .split("fn dispatch_chio_buyer_command")
            .next()
            .expect("dispatch_chio_attest_command has following function");

        assert!(attest_dispatch.contains("cmd_chio_attest_legacy_chiodos_v1_verify("));
        assert!(!attest_dispatch.contains("cmd_chiodos_verify("));
    }

    #[test]
    fn chio_attest_buyer_dispatch_owns_legacy_replay_boundary() {
        let buyer_dispatch = include_str!("cli/chiodos/dispatch/buyer.rs");

        assert!(buyer_dispatch.contains("chio_attest_buyer::"));
        assert!(!buyer_dispatch.contains("chio_chiodos::"));
        assert!(!buyer_dispatch.contains("chio_chiodos_runtime::"));
    }

    fn render_error_json(error: &CliError) -> Result<serde_json::Value, Box<dyn Error>> {
        let mut output = Vec::new();
        write_cli_error(&mut output, error, true)?;
        Ok(serde_json::from_slice(&output)?)
    }

    fn fixture_path(relative: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("examples/chio-3vendor/fixtures")
            .join(relative)
    }
}
