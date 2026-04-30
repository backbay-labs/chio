//! Zed editor extension for Chio.
//!
//! Spawns the `chio-lsp` binary via Zed's LSP adapter API and wires
//! diagnostics through to the editor. The actual extension surface
//! (the `zed::Extension` impl, the `language_server_command` callback)
//! only compiles for the `wasm32` target that Zed loads at runtime.
//!
//! On host targets the crate compiles to a plain rlib so the workspace
//! gate (`cargo build -p zed-chio` and `cargo test -p zed-chio --test
//! integration`) can exercise the manifest and LSP-binary contract
//! without a Zed runtime.

#![deny(clippy::unwrap_used, clippy::expect_used)]

/// The binary name the extension spawns. Zed resolves this on `PATH`
/// when the user has not pinned an explicit path. Editors and the
/// `editors/README.md` LSP-binary contract document agree on this
/// literal.
pub const CHIO_LSP_BINARY: &str = "chio-lsp";

/// Language ID the extension contributes. Matches the
/// `[languages.chio]` block in `extension.toml`.
pub const CHIO_LANGUAGE_ID: &str = "Chio";

/// Settings key the extension reads to allow users to override the
/// `chio-lsp` binary path. Mirrors the VSCode extension's
/// `chio.lsp.path` setting so the two editors share documentation.
pub const SETTINGS_PATH_KEY: &str = "lsp.path";

/// Settings key for extra arguments forwarded to `chio-lsp` on spawn.
pub const SETTINGS_ARGS_KEY: &str = "lsp.args";

/// Returns the default command-line invocation for the language
/// server. The wasm-side extension entrypoint composes this same
/// invocation through Zed's `Command` type; the host-side helper is
/// kept separate so the integration test can pin the contract.
#[must_use]
pub fn default_lsp_command() -> (String, Vec<String>) {
    (CHIO_LSP_BINARY.to_string(), Vec::new())
}

#[cfg(target_arch = "wasm32")]
mod wasm_extension {
    use zed_extension_api::{self as zed, Command, LanguageServerId, Result, Worktree};

    use super::CHIO_LSP_BINARY;

    struct ChioExtension;

    impl zed::Extension for ChioExtension {
        fn new() -> Self {
            Self
        }

        fn language_server_command(
            &mut self,
            _id: &LanguageServerId,
            _worktree: &Worktree,
        ) -> Result<Command> {
            Ok(Command {
                command: CHIO_LSP_BINARY.to_string(),
                args: Vec::new(),
                env: Vec::new(),
            })
        }
    }

    zed::register_extension!(ChioExtension);
}
