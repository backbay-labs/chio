//! `chio-lsp` binary entry point.
//!
//! Speaks LSP over stdio. Editor extensions (VSCode, Zed) spawn
//! this binary directly or via the `chio lsp` subcommand.

#[tokio::main]
async fn main() {
    chio_lsp::server::run_stdio().await;
}
