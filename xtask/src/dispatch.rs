//! Translation layer between the parsed clap command tree and the existing
//! handler functions.

use crate::cli::{
    self, CheckCommand, CodegenArgs, ErrorsCompat, GenCommand, Lang, QualifyCommand,
    SnippetsCompat, VerifyCommand,
};
use crate::fixtures;
use crate::launch_acceptance;
use crate::qualify;
use crate::XtaskError;
use crate::{crate_paths, eval_receipt_regen};
use crate::{errors_regen, freeze_vectors, run_codegen, run_snippets, validate_scenarios};

/// Translate the parsed clap command into a handler call. A flat leaf alias and
/// its `gen ...`/`check ...`/`qualify ...` equivalent route to the same handler.
/// Noun-group reserved leaves fail closed.
pub(crate) fn dispatch(command: cli::Command) -> Result<(), XtaskError> {
    match command {
        // -- gen group --
        cli::Command::Gen { command } => match command {
            GenCommand::Codegen(args) => run_codegen(codegen_argv(&args)?),
            GenCommand::Errors { check } => errors_regen(check_argv(check)),
            GenCommand::Snippets { check } => run_snippets(snippets_regen_argv(check)),
            GenCommand::EvalReceipt { check } => eval_receipt_regen::run(check_argv(check)),
            GenCommand::FreezeVectors { check } => freeze_vectors(check_argv(check)),
        },
        // -- check group --
        cli::Command::Check { command } => match command {
            CheckCommand::CratePaths => crate_paths::run(Vec::new()),
            CheckCommand::Fixtures {
                facet,
                schema_only,
                negative_only,
            } => fixtures::run(
                &facet,
                fixtures::Mode::from_flags(schema_only, negative_only)?,
            ),
        },
        // -- qualify group --
        cli::Command::Qualify { command } => match command {
            QualifyCommand::BoundedChio => qualify::run("bounded-chio"),
        },
        // -- verify group --
        cli::Command::Verify { command } => match command {
            VerifyCommand::LaunchAcceptance(args) => launch_acceptance::run(&args),
        },
        // -- noun-group parents with no implemented leaves (fail closed) --
        cli::Command::Fuzz { .. }
        | cli::Command::Mutants { .. }
        | cli::Command::Release { .. }
        | cli::Command::SupplyChain { .. }
        | cli::Command::Tools { .. } => Err(XtaskError::Usage(
            "this command group has no implemented subcommands yet".into(),
        )),
        // -- flat leaf aliases (same handlers as the noun-group leaves) --
        cli::Command::ValidateScenarios => validate_scenarios(Vec::new()),
        cli::Command::FreezeVectors { check } => freeze_vectors(check_argv(check)),
        cli::Command::EvalReceiptRegen { check } => eval_receipt_regen::run(check_argv(check)),
        cli::Command::Codegen(args) => run_codegen(codegen_argv(&args)?),
        cli::Command::Errors { command } => match command {
            ErrorsCompat::Regen { check } => errors_regen(check_argv(check)),
        },
        cli::Command::Snippets { command } => match command {
            SnippetsCompat::Regen { check } => run_snippets(snippets_regen_argv(check)),
        },
    }
}

/// Build the `Vec<String>` argv that `run_codegen` parses. Accepts exactly one
/// language selector: the positional form (the `codegen rust` spelling stamped
/// into generated headers) or the `--lang` flag form. Supplying both is rejected
/// so a stray flag cannot silently override the positional argument.
pub(crate) fn codegen_argv(args: &CodegenArgs) -> Result<Vec<String>, XtaskError> {
    let mut out = Vec::new();
    match (args.lang_positional, args.lang_flag) {
        (Some(positional), Some(flag)) => {
            return Err(XtaskError::Usage(format!(
                "codegen language given twice: positional `{}` and --lang `{}`",
                lang_str(positional),
                lang_str(flag)
            )));
        }
        (Some(lang), None) => out.push(lang_str(lang).to_string()),
        (None, Some(lang)) => {
            out.push("--lang".to_string());
            out.push(lang_str(lang).to_string());
        }
        (None, None) => {}
    }
    if args.check {
        out.push("--check".to_string());
    }
    Ok(out)
}

fn lang_str(lang: Lang) -> &'static str {
    match lang {
        Lang::Rust => "rust",
        Lang::Ts => "ts",
        Lang::Go => "go",
        Lang::Python => "python",
    }
}

/// Argv for a bare `[--check]` leaf (freeze-vectors / eval-receipt / errors-body).
fn check_argv(check: bool) -> Vec<String> {
    if check {
        vec!["--check".to_string()]
    } else {
        Vec::new()
    }
}

/// `run_snippets` expects `["regen", maybe "--check"]` (its `run` reads the
/// `regen` subcommand first). Rebuild that exact argv.
fn snippets_regen_argv(check: bool) -> Vec<String> {
    let mut out = vec!["regen".to_string()];
    if check {
        out.push("--check".to_string());
    }
    out
}
