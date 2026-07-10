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
pub(crate) fn parse_cli<I, S>(argv: I) -> clap::error::Result<Cli>
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

pub(crate) fn render_error_json(error: &CliError) -> Result<serde_json::Value, Box<dyn Error>> {
    let mut output = Vec::new();
    write_cli_error(&mut output, error, true)?;
    Ok(serde_json::from_slice(&output)?)
}

pub(crate) fn fixture_path(relative: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("examples/chio-3vendor/fixtures")
        .join(relative)
}
