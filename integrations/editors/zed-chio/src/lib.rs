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

/// Compose the LSP invocation for a single launch from the default
/// binary plus any user overrides discovered in Zed's `LspSettings`.
///
/// `override_path` corresponds to `lsp.<server>.binary.path`; an empty
/// or `None` value falls back to [`CHIO_LSP_BINARY`] so the default
/// `PATH` lookup still works. `override_args` correspond to
/// `lsp.<server>.binary.arguments` and replace the empty default. The
/// helper lives outside the wasm extension block so the host-side
/// integration test can exercise the override contract without booting
/// Zed's wasm runtime.
#[must_use]
pub fn lsp_command_with_overrides(
    override_path: Option<&str>,
    override_args: Option<Vec<String>>,
) -> (String, Vec<String>) {
    let command = match override_path {
        Some(p) if !p.trim().is_empty() => p.to_string(),
        _ => CHIO_LSP_BINARY.to_string(),
    };
    let args = override_args.unwrap_or_default();
    (command, args)
}

#[cfg(target_arch = "wasm32")]
mod wasm_extension {
    use zed_extension_api::{
        self as zed, settings::LspSettings, Command, LanguageServerId, Result, Worktree,
    };

    use super::lsp_command_with_overrides;

    struct ChioExtension;

    impl zed::Extension for ChioExtension {
        fn new() -> Self {
            Self
        }

        fn language_server_command(
            &mut self,
            id: &LanguageServerId,
            worktree: &Worktree,
        ) -> Result<Command> {
            // Read user-configured overrides for this language server
            // (the `lsp.<id>.binary.{path,arguments,env}` block) and
            // fall back to the bare `chio-lsp` invocation when the
            // user has not customised it. Without this lookup the
            // documented `lsp.path` / `lsp.args` knobs in the README
            // are unreachable and non-default installs cannot launch.
            let settings = LspSettings::for_worktree(id.as_ref(), worktree).ok();
            let binary = settings.as_ref().and_then(|s| s.binary.as_ref());

            let override_path = binary.and_then(|b| b.path.as_deref());
            let override_args = binary.and_then(|b| b.arguments.clone());
            let env: Vec<(String, String)> = binary
                .and_then(|b| b.env.as_ref())
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default();

            let (command, args) = lsp_command_with_overrides(override_path, override_args);
            Ok(Command { command, args, env })
        }
    }

    zed::register_extension!(ChioExtension);
}
