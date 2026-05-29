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
mod archive;
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

// Shared imports for the CLI module tree. These live at the crate root so the
// `cli/*` submodules (which each begin with `use super::*;`) inherit them,
// matching the single coherent `#[path] mod` strategy. The `pub use`
// re-exports keep `crate::CliError`, `crate::policy`, and the sibling
// control-plane modules reachable from the standalone `src/*.rs` command
// modules.
pub use chio_control_plane::{
    CliError, authority_public_key_from_seed_file, build_kernel, certify, configure_budget_store,
    configure_capability_authority, configure_receipt_store, configure_revocation_store,
    enterprise_federation, evidence_export, federation_policy, issuance,
    issue_default_capabilities, load_or_create_authority_keypair, passport_verifier, policy,
    reputation, require_control_token, rotate_authority_keypair, scim_lifecycle, trust_control,
};
pub use chio_mcp_remote as remote_mcp;

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::{Parser, Subcommand};
use serde::de::DeserializeOwned;
use tracing::{debug, error, info, warn};

use chio_api_protect::{ProtectConfig, ProtectProxy};
use chio_core::appraisal::{
    RuntimeAttestationAppraisalImportRequest, RuntimeAttestationAppraisalRequest,
    RuntimeAttestationAppraisalResultExportRequest, RuntimeAttestationImportedAppraisalPolicy,
    SignedRuntimeAttestationAppraisalResult,
};
use chio_core::capability::{
    ChioScope, GovernedAutonomyTier, MonetaryAmount, RuntimeAssuranceTier,
    RuntimeAttestationEvidence,
};
use chio_core::crypto::Keypair;
use chio_core::message::{AgentMessage, KernelMessage, ToolCallError, ToolCallResult};
use chio_core::session::{
    OperationContext, OperationTerminalState, RequestId, SessionId, SessionOperation,
    ToolCallOperation,
};
use chio_kernel::transport::{ChioTransport, TransportError};
use chio_kernel::{
    ChioKernel, RevocationStore, SessionOperationResponse, ToolCallOutput,
    ToolCallRequest as KernelToolCallRequest, ToolCallStream,
};
use chio_mcp_adapter::{AdaptedMcpServer, ChioMcpEdge, McpAdapterConfig, McpEdgeConfig};

use crate::policy::load_policy;

#[path = "cli/types.rs"]
mod types_cli;
pub(crate) use types_cli::*;
#[path = "cli/chio/types.rs"]
mod chio_types;
use chio_types::{
    ChioAuthorityCommands, ChioPheromoneCommands, ChioPheromoneRelayAlertAssuranceArchiveCommands,
    ChioPheromoneRelayAlertAssuranceArchivePackageCommands,
    ChioPheromoneRelayAlertAssuranceArchiveRestoreDrillCommands,
    ChioPheromoneRelayAlertAssuranceCloseoutCommands, ChioPheromoneRelayAlertAssuranceCommands,
    ChioPheromoneRelayAlertAssurancePhysicalDrillCommands,
    ChioPheromoneRelayAlertAssuranceRetentionCommands,
    ChioPheromoneRelayAlertAssuranceRetentionHandoffCommands, ChioPheromoneRelayAlertCommands,
    ChioPheromoneRelayAlertDeliveryCommands, ChioPheromoneRelayCommands,
    ChioPheromoneRelayDirectoryCommands, ChioPheromoneRelaySupervisorCommands,
    ChioRuntimeCommands, ChioRuntimeOpsCommands, ChioRuntimeOpsRetentionCommands,
    ChioRuntimeOrchestrateCommands, ChioRuntimePeerWeightsCommands, ChioRuntimePheromoneCommands,
    ChioRuntimePolicyCommands, ChioTreatyCommands, ChioTrustBundleCommands,
};
#[path = "cli/doctor.rs"]
mod doctor_cli;
pub(crate) use doctor_cli::*;
#[path = "cli/dispatch.rs"]
mod dispatch_cli;
#[cfg(test)]
pub(crate) use dispatch_cli::{cmd_chio_attest_runtime_quote_verify, write_cli_error};
#[path = "cli/chio/dispatch.rs"]
mod chio_dispatch;
use chio_dispatch::*;

fn main() {
    dispatch_cli::run();
}
#[path = "cli/runtime.rs"]
mod runtime_cli;
pub(crate) use runtime_cli::*;
#[path = "cli/trust_commands.rs"]
mod trust_commands_cli;
pub(crate) use trust_commands_cli::*;
#[path = "cli/session.rs"]
mod session_cli;
pub(crate) use session_cli::*;
#[path = "cli/conformance.rs"]
mod conformance_cli;
pub(crate) use conformance_cli::*;
#[path = "cli/mcp.rs"]
mod mcp_cli;
pub(crate) use mcp_cli::*;
#[path = "cli/replay.rs"]
mod replay_cli;
pub(crate) use replay_cli::{cmd_replay, load_trusted_kernel_pubkey};
#[path = "cli/arena.rs"]
mod arena_cli;
pub(crate) use arena_cli::{cmd_arena_evolve, cmd_arena_replay, cmd_arena_run};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod cli_entrypoint_tests {
    use std::error::Error;

    use clap::Parser;

    use super::*;

    /// Parse a `chio` argv into [`Cli`] on a thread with an 8 MiB stack.
    ///
    /// The release binary parses argv on the process main thread, whose
    /// default stack is 8 MiB. The libtest harness runs each `#[test]` on a
    /// worker thread with a ~2 MiB default stack, and the monomorphised clap
    /// parser for the 24-variant `Commands` enum needs more than that to
    /// build, overflowing the worker stack with a SIGABRT. Driving the parse
    /// through an explicit 8 MiB worker mirrors the production main-thread
    /// stack so the tests exercise the same parser the binary does without
    /// changing the CLI surface.
    ///
    /// Accepts any iterator of string-likes and collects to owned `Vec<String>`
    /// so borrowed argv (slices, cloned vecs) can move across the thread.
    fn parse_cli<I, S>(argv: I) -> clap::error::Result<Cli>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let argv: Vec<String> = argv.into_iter().map(Into::into).collect();
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(move || Cli::try_parse_from(argv))
            .expect("spawn 8 MiB parse thread")
            .join()
            .expect("parse thread must not panic")
    }

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



    fn retired_surface_name() -> String {
        ["chio", "dos"].concat()
    }

    fn assert_no_retired_surface_name(label: &str, text: &str) {
        let lowered = text.to_ascii_lowercase();
        let retired = retired_surface_name();
        assert!(
            !lowered.contains(&retired),
            "{label} must not expose the retired public surface name"
        );
    }

    #[test]
    fn public_chio_command_type_boundaries_are_native() {
        let sources = [
            ("root cli types", include_str!("cli/types.rs")),
            ("runtime types", include_str!("cli/chio/types/runtime.rs")),
            (
                "pheromone root types",
                include_str!("cli/chio/types/pheromone/root.rs"),
            ),
            (
                "pheromone relay types",
                include_str!("cli/chio/types/pheromone/relay.rs"),
            ),
            (
                "pheromone alert types",
                include_str!("cli/chio/types/pheromone/alerts.rs"),
            ),
            (
                "pheromone assurance types",
                include_str!("cli/chio/types/pheromone/assurance.rs"),
            ),
            ("authority types", include_str!("cli/chio/types/authority.rs")),
            ("treaty types", include_str!("cli/chio/types/treaty.rs")),
        ];
        for (label, source) in sources {
            assert_no_retired_surface_name(label, source);
        }

        let cli_types = include_str!("cli/types.rs");
        assert!(cli_types.contains("command: ChioRuntimeCommands"));
        assert!(cli_types.contains("command: ChioPheromoneCommands"));
        assert!(cli_types.contains("command: ChioFederationCommands"));
        assert!(cli_types.contains("command: ChioAttestCommands"));
        assert!(include_str!("cli/chio/types/runtime.rs")
            .contains("command: ChioRuntimePolicyCommands"));
        assert!(include_str!("cli/chio/types/runtime.rs")
            .contains("command: ChioRuntimePeerWeightsCommands"));
        assert!(include_str!("cli/chio/types/runtime.rs")
            .contains("command: ChioRuntimePheromoneCommands"));
        assert!(include_str!("cli/chio/types/runtime.rs")
            .contains("command: ChioRuntimeOrchestrateCommands"));
        assert!(include_str!("cli/chio/types/runtime.rs")
            .contains("command: ChioRuntimeOpsCommands"));
        assert!(include_str!("cli/chio/types/pheromone/root.rs")
            .contains("command: ChioPheromoneRelayCommands"));
        assert!(include_str!("cli/chio/types/pheromone/relay.rs")
            .contains("command: ChioPheromoneRelayAlertCommands"));
        assert!(include_str!("cli/chio/types/authority.rs")
            .contains("command: ChioTrustBundleCommands"));
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
                command:
                    ReceiptCommands::Flush {
                        timeout_ms,
                    },
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



    fn rendered_help(args: &[&str]) -> String {
        let error = match parse_cli(args.iter().copied()) {
            Ok(_) => panic!("help exits before parsing command values"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
        error.to_string()
    }

    #[test]
    fn public_chio_help_uses_native_surface_names() {
        let public_help = [
            rendered_help(&["chio", "federation", "authority", "issue", "--help"]),
            rendered_help(&["chio", "runtime", "--help"]),
            rendered_help(&["chio", "pheromone", "receive", "--help"]),
            rendered_help(&["chio", "pheromone", "relay", "serve", "--help"]),
        ]
        .join("\n");

        assert_no_retired_surface_name("public help", &public_help);
    }

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
        assert_no_retired_surface_name("buyer error", &rendered_text);

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
        let retired_schema_prefix = ["chio", "chio", ""].join(".");
        assert!(
            !explanation.to_string().contains(&retired_schema_prefix),
            "public buyer explanation must emit a Chio-native schema id"
        );

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
        assert!(matches!(attest, Commands::Attest { .. }));    }

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
        let expected_assignment =
            format!("subject_class_namespace: \"{chio_namespace}\".to_string()");

        assert_no_retired_surface_name("runtime admission dispatch", runtime_admission);
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
        assert!(!authority_dispatch.contains("cmd_chio_authority_"));
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
        assert!(treaty_dispatch.contains("command: ChioTreatyCommands"));
        assert!(treaty_dispatch.contains("ChioTreatyCommands::"));
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
    }

    #[test]
    fn chio_runtime_dispatch_uses_only_native_names() {
        let dispatch = include_str!("cli/dispatch.rs");
        let runtime_dispatch = dispatch
            .split("fn dispatch_chio_runtime_command")
            .nth(1)
            .expect("dispatch_chio_runtime_command exists")
            .split("fn dispatch_chio_pheromone_command")
            .next()
            .expect("dispatch_chio_runtime_command has following function");

        assert_no_retired_surface_name("runtime dispatch", runtime_dispatch);
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
        assert_no_retired_surface_name("runtime error", &rendered_text);

        let runtime_admission = include_str!("cli/chio/dispatch/runtime/admission.rs");
        assert!(!runtime_admission.contains("Chio signed pheromone query report parse"));

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

        for handler in chio_handlers {
            assert!(pheromone_dispatch.contains(handler), "{handler}");
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
        assert_no_retired_surface_name("pheromone error", &rendered_text);

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
        assert!(pheromone_dispatch.contains("ChioPheromoneRelayAlertAssuranceArchivePackageCommands::"));
        assert!(pheromone_dispatch.contains("ChioPheromoneRelayAlertAssuranceArchiveRestoreDrillCommands::"));
        assert!(pheromone_dispatch.contains("ChioPheromoneRelayAlertAssuranceCloseoutCommands::"));
        assert!(pheromone_dispatch.contains("ChioPheromoneRelayAlertAssurancePhysicalDrillCommands::"));
        assert!(pheromone_dispatch.contains("ChioPheromoneRelayAlertAssuranceRetentionHandoffCommands::"));
        assert!(pheromone_dispatch.contains("ChioPheromoneRelayDirectoryCommands::"));
        assert!(pheromone_dispatch.contains("ChioPheromoneRelaySupervisorCommands::"));
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
        let retired = retired_surface_name();
        for script in scripts {
            assert!(!script.to_ascii_lowercase().contains(&retired));
        }
    }

    #[test]
    fn chio_gate_scripts_use_chio_authority_entrypoints() {
        let scripts = [
            include_str!("../../../scripts/check-chio-pheromone-transit.sh"),
            include_str!("../../../scripts/check-chio-pheromone-runtime.sh"),
        ];
        let retired_authority_gate = ["scripts/check-", &retired_surface_name(), "-authority-issuance.sh"].concat();
        for script in scripts {
            assert!(!script.contains(&retired_authority_gate));
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
        let retired_fixture_root = ["examples/", &retired_surface_name(), "-3vendor"].concat();
        let chio_fixture_root = ["examples/", "chio", "-3vendor/fixtures"].concat();
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");

        assert!(repo_root.join(chio_fixture_root).is_dir());
        for script in scripts {
            assert!(!script.contains(&retired_fixture_root));
        }
        for workflow in workflows {
            assert!(!workflow.contains(&retired_fixture_root));
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
        let retired = retired_surface_name();
        let retired_spec_path = ["spec/", &retired.to_ascii_uppercase(), "_PHEROMONE.md"].concat();
        let retired_runbook_path = [
            "docs/release/",
            &retired.to_ascii_uppercase(),
            "_PHEROMONE_RELAY_RUNBOOK.md",
        ]
        .concat();
        let retired_operator_docs_path = ["docs/release/", &retired, "-pheromone-relay/"].concat();
        for workflow in workflows {
            assert!(!workflow.contains(&retired_spec_path));
            assert!(!workflow.contains(&retired_runbook_path));
            assert!(!workflow.contains(&retired_operator_docs_path));
        }
    }


    #[test]
    fn chio_attest_buyer_dispatch_uses_canonical_crate_names() {
        let buyer_dispatch = include_str!("cli/chio/dispatch/buyer.rs");

        assert!(buyer_dispatch.contains("chio_attest_buyer::"));
        assert!(!buyer_dispatch.contains("chio_attest_buyer_core::"));
        assert!(!buyer_dispatch.contains("chio_runtime_core::"));
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
