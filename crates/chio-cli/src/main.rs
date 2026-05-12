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
include!("cli/doctor.rs");
include!("cli/dispatch.rs");
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

    use clap::Parser;

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
                assert_eq!(trusted_issuers, std::path::PathBuf::from("trusted-issuers.json"));
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
                assert_eq!(
                    state,
                    std::path::PathBuf::from("peer-directory-state.json")
                );
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
        assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
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
                                command:
                                    ChiodosPheromoneRelayCommands::Tick {
                                        report_dir, ..
                                    },
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
        assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
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
        assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
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

        assert_eq!(
            rendered["code"],
            "urn:chio:error:capability:scope-exceeded"
        );
        assert_eq!(rendered["context"]["domain"], "capability");
        assert!(rendered["suggested_fix"]
            .as_str()
            .is_some_and(|fix| fix.contains("Issue a capability")));

        Ok(())
    }

    #[test]
    fn write_cli_error_emits_policy_registry_report() -> Result<(), Box<dyn Error>> {
        let rendered = render_error_json(&CliError::policy_constraint_error(
            "invalid governed autonomy tier",
        ))?;

        assert_eq!(rendered["code"], "urn:chio:error:policy:constraint-invalid");
        assert_eq!(rendered["context"]["domain"], "policy");
        assert!(rendered["suggested_fix"]
            .as_str()
            .is_some_and(|fix| fix.contains("constraint")));

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
        assert!(rendered["suggested_fix"]
            .as_str()
            .is_some_and(|fix| fix.contains("request shape")));

        Ok(())
    }

    fn render_error_json(error: &CliError) -> Result<serde_json::Value, Box<dyn Error>> {
        let mut output = Vec::new();
        write_cli_error(&mut output, error, true)?;
        Ok(serde_json::from_slice(&output)?)
    }
}
