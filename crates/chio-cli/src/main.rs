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
                        report,
                    },
            } => {
                assert_eq!(package, std::path::PathBuf::from("package.json"));
                assert_eq!(
                    trust_bundle,
                    std::path::PathBuf::from("verifier-trust-bundle.json")
                );
                assert_eq!(report, std::path::PathBuf::from("report.json"));
            }
            _ => panic!("expected chiodos verify subcommand"),
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
