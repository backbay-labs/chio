//! `clap` derive surface for `cargo xtask`.
//!
//! Noun-group parents (gen/check/qualify/verify/fuzz/mutants/release/
//! supply-chain/tools) carry the leaf subcommands. The flat leaf spellings
//! (validate-scenarios, freeze-vectors, codegen, errors, snippets,
//! eval-receipt-regen) remain as top-level aliases; the dispatch in `main.rs`
//! routes each leaf to its handler.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

/// Workspace task runner. Run `cargo xtask <command> --help` for details.
#[derive(Parser, Debug)]
#[command(name = "xtask", about = "Chio workspace task runner", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Target language for `gen codegen`.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "lower")]
pub enum Lang {
    Rust,
    Ts,
    Go,
    Python,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Artifact generation (codegen, errors, snippets, eval-receipt, vectors).
    Gen {
        #[command(subcommand)]
        command: GenCommand,
    },
    /// Verification gates.
    Check {
        #[command(subcommand)]
        command: CheckCommand,
    },
    /// Release / profile qualification gates.
    Qualify {
        #[command(subcommand)]
        command: QualifyCommand,
    },
    /// Formal-method / coverage gates.
    Verify {
        #[command(subcommand)]
        command: VerifyCommand,
    },
    /// Fuzzing orchestration.
    Fuzz {
        #[command(subcommand)]
        command: FuzzCommand,
    },
    /// Mutation-testing gates.
    Mutants {
        #[command(subcommand)]
        command: MutantsCommand,
    },
    /// Release steps.
    Release {
        #[command(subcommand)]
        command: ReleaseCommand,
    },
    /// Supply-chain checks.
    #[command(name = "supply-chain")]
    SupplyChain {
        #[command(subcommand)]
        command: SupplyChainCommand,
    },
    /// Tool-version management.
    Tools {
        #[command(subcommand)]
        command: ToolsCommand,
    },

    // -- Flat leaf aliases that forward to the noun-group handlers. --
    /// (alias) Validate conformance scenarios against their `$schema`.
    #[command(name = "validate-scenarios")]
    ValidateScenarios,
    /// (alias) Freeze the bindings vector manifest. `--check` gates drift.
    #[command(name = "freeze-vectors")]
    FreezeVectors {
        /// Compare against the on-disk manifest and exit non-zero on drift.
        #[arg(long)]
        check: bool,
    },
    /// (alias) Regenerate the eval-report golden vector. `--check` gates drift.
    #[command(name = "eval-receipt-regen")]
    EvalReceiptRegen {
        #[arg(long)]
        check: bool,
    },
    /// (alias) Schema-derived bindings codegen. Forwards to `gen codegen`.
    Codegen(CodegenArgs),
    /// (alias) `errors regen`. Forwards to `gen errors`.
    Errors {
        #[command(subcommand)]
        command: ErrorsCompat,
    },
    /// (alias) `snippets regen`. Forwards to `gen snippets`.
    Snippets {
        #[command(subcommand)]
        command: SnippetsCompat,
    },
}

/// Shared positional/flag shape for `codegen` (used by both the back-compat
/// `Codegen` leaf and `gen codegen`). Accepts BOTH `codegen rust` (positional)
/// and `codegen --lang rust` (flag); exactly one must be supplied.
#[derive(clap::Args, Debug)]
pub struct CodegenArgs {
    /// Language as a positional (e.g. `codegen rust`).
    #[arg(value_enum)]
    pub lang_positional: Option<Lang>,
    /// Language as a flag (e.g. `codegen --lang rust`).
    #[arg(long = "lang", value_enum)]
    pub lang_flag: Option<Lang>,
    /// Render to memory and exit non-zero on byte drift.
    #[arg(long)]
    pub check: bool,
}

#[derive(Subcommand, Debug)]
pub enum GenCommand {
    /// Schema-derived bindings codegen.
    Codegen(CodegenArgs),
    /// Regenerate the error registry Rust output.
    Errors {
        #[arg(long)]
        check: bool,
    },
    /// Regenerate editor snippet files.
    Snippets {
        #[arg(long)]
        check: bool,
    },
    /// Regenerate the eval-report golden vector.
    EvalReceipt {
        #[arg(long)]
        check: bool,
    },
    /// Freeze the bindings vector manifest.
    FreezeVectors {
        #[arg(long)]
        check: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum CheckCommand {
    /// Assert every `crates/chio-*` path literal in config resolves on disk.
    #[command(name = "crate-paths")]
    CratePaths,
    /// Run a fixture-and-schema gate by facet name.
    Fixtures {
        /// Facet name. Pheromone facets are in ci-gates/pheromone.toml; the
        /// The `runtime-*` facets are in ci-gates/runtime.toml.
        facet: String,
        /// Schema/metadata validation only; skip cargo tests and orchestration.
        #[arg(long, conflicts_with = "negative_only")]
        schema_only: bool,
        /// Negative-corpus path only.
        #[arg(long)]
        negative_only: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ErrorsCompat {
    /// Regenerate the error registry Rust output.
    Regen {
        #[arg(long)]
        check: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum SnippetsCompat {
    /// Regenerate editor snippet files.
    Regen {
        #[arg(long)]
        check: bool,
    },
}

// A noun group with no implemented leaves yet. Each enum carries a single
// hidden reserved variant so the `Subcommand` derive has a variant to generate
// and the parent shows in `--help`; invoking a reserved leaf is a fail-closed
// error handled in `main.rs`. The reserved variant is hidden from `--help` so
// the tree advertises only implemented surface.
macro_rules! pending_group {
    ($name:ident) => {
        #[derive(Subcommand, Debug)]
        pub enum $name {
            #[command(name = "__pending", hide = true)]
            Pending,
        }
    };
}

/// Qualification leaves. `bounded-chio` asserts the bounded release matrix
/// contract.
#[derive(Subcommand, Debug)]
pub enum QualifyCommand {
    /// Assert the bounded Chio release qualification matrix contract.
    #[command(name = "bounded-chio")]
    BoundedChio,
}

#[derive(Subcommand, Debug)]
pub enum VerifyCommand {
    /// Assemble and verify the public Proof Room launch acceptance package.
    #[command(name = "launch-acceptance")]
    LaunchAcceptance(LaunchAcceptanceArgs),
}

#[derive(clap::Args, Debug)]
pub struct LaunchAcceptanceArgs {
    /// Output directory for the assembled public bundle.
    #[arg(long, default_value = "target/proof-room/public-bundle")]
    pub out: PathBuf,
    /// Validate and assemble metadata only; skip expensive verifier corpus runs.
    #[arg(long)]
    pub schema_only: bool,
}

pending_group!(FuzzCommand);
pending_group!(MutantsCommand);
pending_group!(ReleaseCommand);
pending_group!(SupplyChainCommand);
pending_group!(ToolsCommand);

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Parse `args` and return the (required-by-the-test) subcommand. Panics
    /// if parsing fails or yields no subcommand, so callers can match on the
    /// `Command` variant directly. The bare-invocation case is exercised by
    /// `no_subcommand_parses_to_none`, which inspects the `Option` instead.
    fn parse(args: &[&str]) -> Command {
        match Cli::try_parse_from(args) {
            Ok(cli) => match cli.command {
                Some(command) => command,
                None => panic!("expected `{args:?}` to carry a subcommand"),
            },
            Err(err) => panic!("expected `{args:?}` to parse, got: {err}"),
        }
    }

    #[test]
    fn flat_alias_validate_scenarios_parses() {
        assert!(matches!(
            parse(&["xtask", "validate-scenarios"]),
            Command::ValidateScenarios
        ));
    }

    #[test]
    fn flat_alias_freeze_vectors_check_parses() {
        assert!(matches!(
            parse(&["xtask", "freeze-vectors", "--check"]),
            Command::FreezeVectors { check: true }
        ));
        assert!(matches!(
            parse(&["xtask", "freeze-vectors"]),
            Command::FreezeVectors { check: false }
        ));
    }

    #[test]
    fn flat_alias_eval_receipt_regen_check_parses() {
        assert!(matches!(
            parse(&["xtask", "eval-receipt-regen", "--check"]),
            Command::EvalReceiptRegen { check: true }
        ));
    }

    #[test]
    fn flat_alias_codegen_positional_and_flag_parse() {
        match parse(&["xtask", "codegen", "rust", "--check"]) {
            Command::Codegen(args) => {
                assert_eq!(args.lang_positional, Some(Lang::Rust));
                assert_eq!(args.lang_flag, None);
                assert!(args.check);
            }
            other => panic!("expected Codegen, got {other:?}"),
        }
        match parse(&["xtask", "codegen", "--lang", "python", "--check"]) {
            Command::Codegen(args) => {
                assert_eq!(args.lang_positional, None);
                assert_eq!(args.lang_flag, Some(Lang::Python));
                assert!(args.check);
            }
            other => panic!("expected Codegen, got {other:?}"),
        }
    }

    #[test]
    fn flat_alias_errors_and_snippets_regen_parse() {
        assert!(matches!(
            parse(&["xtask", "errors", "regen", "--check"]),
            Command::Errors {
                command: ErrorsCompat::Regen { check: true }
            }
        ));
        assert!(matches!(
            parse(&["xtask", "snippets", "regen", "--check"]),
            Command::Snippets {
                command: SnippetsCompat::Regen { check: true }
            }
        ));
    }

    #[test]
    fn new_check_crate_paths_parses() {
        assert!(matches!(
            parse(&["xtask", "check", "crate-paths"]),
            Command::Check {
                command: CheckCommand::CratePaths
            }
        ));
    }

    #[test]
    fn check_fixtures_parses_with_facet() {
        match parse(&["xtask", "check", "fixtures", "relay-observability"]) {
            Command::Check {
                command:
                    CheckCommand::Fixtures {
                        facet,
                        schema_only,
                        negative_only,
                    },
            } => {
                assert_eq!(facet, "relay-observability");
                assert!(!schema_only && !negative_only);
            }
            other => panic!("expected check fixtures, got {other:?}"),
        }
    }

    #[test]
    fn check_fixtures_schema_only_parses() {
        match parse(&["xtask", "check", "fixtures", "relay", "--schema-only"]) {
            Command::Check {
                command:
                    CheckCommand::Fixtures {
                        facet,
                        schema_only,
                        negative_only,
                    },
            } => {
                assert_eq!(facet, "relay");
                assert!(schema_only);
                assert!(!negative_only);
            }
            other => panic!("expected check fixtures, got {other:?}"),
        }
    }

    #[test]
    fn check_fixtures_schema_only_and_negative_only_conflict() {
        match Cli::try_parse_from([
            "xtask",
            "check",
            "fixtures",
            "relay",
            "--schema-only",
            "--negative-only",
        ]) {
            Ok(_) => panic!("conflicting flags parsed"),
            Err(err) => assert_eq!(
                err.kind(),
                clap::error::ErrorKind::ArgumentConflict,
                "got: {err}"
            ),
        }
    }

    #[test]
    fn check_fixtures_requires_a_facet() {
        // Fail-closed: a bare `check fixtures` with no facet is a parse error.
        match Cli::try_parse_from(["xtask", "check", "fixtures"]) {
            Ok(_) => panic!("missing facet parsed"),
            Err(err) => assert_eq!(
                err.kind(),
                clap::error::ErrorKind::MissingRequiredArgument,
                "got: {err}"
            ),
        }
    }

    #[test]
    fn qualify_bounded_chio_parses() {
        assert!(matches!(
            parse(&["xtask", "qualify", "bounded-chio"]),
            Command::Qualify {
                command: QualifyCommand::BoundedChio
            }
        ));
    }

    #[test]
    fn verify_launch_acceptance_parses() {
        match parse(&[
            "xtask",
            "verify",
            "launch-acceptance",
            "--schema-only",
            "--out",
            "target/proof-room/public-bundle",
        ]) {
            Command::Verify {
                command: VerifyCommand::LaunchAcceptance(args),
            } => {
                assert!(args.schema_only);
                assert_eq!(args.out, PathBuf::from("target/proof-room/public-bundle"));
            }
            other => panic!("expected verify launch-acceptance, got {other:?}"),
        }
    }

    #[test]
    fn qualify_unknown_profile_is_a_parse_error() {
        // Fail-closed: an unknown qualification profile never parses to a no-op.
        match Cli::try_parse_from(["xtask", "qualify", "not-a-profile"]) {
            Ok(cli) => panic!("unknown qualify profile parsed: {:?}", cli.command),
            Err(err) => assert_eq!(
                err.kind(),
                clap::error::ErrorKind::InvalidSubcommand,
                "got: {err}"
            ),
        }
    }

    #[test]
    fn new_gen_codegen_parses() {
        match parse(&["xtask", "gen", "codegen", "--lang", "ts"]) {
            Command::Gen {
                command: GenCommand::Codegen(args),
            } => assert_eq!(args.lang_flag, Some(Lang::Ts)),
            other => panic!("expected gen codegen, got {other:?}"),
        }
    }

    #[test]
    fn unknown_subcommand_is_a_parse_error() {
        // Fail-closed: an unknown subcommand never parses, so it can never
        // dispatch to a no-op. clap reports it as an error.
        match Cli::try_parse_from(["xtask", "definitely-not-a-command"]) {
            Ok(cli) => panic!("unknown subcommand parsed: {:?}", cli.command),
            Err(err) => assert_eq!(
                err.kind(),
                clap::error::ErrorKind::InvalidSubcommand,
                "got: {err}"
            ),
        }
    }

    #[test]
    fn no_subcommand_parses_to_none() {
        // Bare `cargo xtask` parses with no subcommand; `main.rs` then prints
        // the help tree and exits 0.
        match Cli::try_parse_from(["xtask"]) {
            Ok(cli) => assert!(cli.command.is_none(), "got: {:?}", cli.command),
            Err(err) => panic!("bare invocation must parse, got: {err}"),
        }
    }
}
