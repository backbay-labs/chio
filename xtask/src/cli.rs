//! `clap` derive surface for `cargo xtask`.
//!
//! Mirrors the six historical subcommands as aliased leaf variants and
//! introduces the noun-group parents (gen/check/qualify/verify/fuzz/mutants/
//! release/supply-chain/tools) as parents whose children are unimplemented for
//! now. Every historical invocation string keeps working through
//! `#[command(alias = "...")]`; the dispatch in `main.rs` routes each leaf to the
//! handler that already exists.

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
    /// Release / profile qualification gates (parents only for now).
    Qualify {
        #[command(subcommand)]
        command: QualifyCommand,
    },
    /// Formal-method / coverage gates (parents only for now).
    Verify {
        #[command(subcommand)]
        command: VerifyCommand,
    },
    /// Fuzzing orchestration (parents only for now).
    Fuzz {
        #[command(subcommand)]
        command: FuzzCommand,
    },
    /// Mutation-testing gates (parents only for now).
    Mutants {
        #[command(subcommand)]
        command: MutantsCommand,
    },
    /// Release steps (parents only for now).
    Release {
        #[command(subcommand)]
        command: ReleaseCommand,
    },
    /// Supply-chain checks (parents only for now).
    #[command(name = "supply-chain")]
    SupplyChain {
        #[command(subcommand)]
        command: SupplyChainCommand,
    },
    /// Tool-version management (parents only for now).
    Tools {
        #[command(subcommand)]
        command: ToolsCommand,
    },

    // -- Back-compat leaf aliases for the six historical subcommands. --
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
        /// six `runtime-*` facets are in ci-gates/runtime.toml.
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

// Noun-group children: parents introduced now, leaves land in Phase 3. Each
// enum carries a single hidden reserved variant so the derive compiles and the
// parent shows in `--help`; invoking a reserved leaf is a fail-closed error
// handled in `main.rs`.
/// Reserved leaf for a noun group whose real leaves land in Phase 3.
/// Hidden from `--help` so the tree advertises only implemented surface, but
/// present so the `Subcommand` derive has a variant to generate.
macro_rules! pending_group {
    ($name:ident) => {
        #[derive(Subcommand, Debug)]
        pub enum $name {
            #[command(name = "__pending", hide = true)]
            Pending,
        }
    };
}

pending_group!(QualifyCommand);
pending_group!(VerifyCommand);
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
    fn historical_validate_scenarios_parses() {
        assert!(matches!(
            parse(&["xtask", "validate-scenarios"]),
            Command::ValidateScenarios
        ));
    }

    #[test]
    fn historical_freeze_vectors_check_parses() {
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
    fn historical_eval_receipt_regen_check_parses() {
        assert!(matches!(
            parse(&["xtask", "eval-receipt-regen", "--check"]),
            Command::EvalReceiptRegen { check: true }
        ));
    }

    #[test]
    fn historical_codegen_positional_and_flag_parse() {
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
    fn historical_errors_and_snippets_regen_parse() {
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
        // the help tree and exits 0, matching the historical hand-rolled CLI.
        match Cli::try_parse_from(["xtask"]) {
            Ok(cli) => assert!(cli.command.is_none(), "got: {:?}", cli.command),
            Err(err) => panic!("bare invocation must parse, got: {err}"),
        }
    }
}
