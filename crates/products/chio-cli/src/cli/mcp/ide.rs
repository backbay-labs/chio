// IDE config emit targets for `chio mcp wrap`.
//
// The four supported IDEs each have their own configuration shape; we
// model the target as a `clap::ValueEnum` so the CLI surface is
// `--emit-config <target>` and each target pins a schema version.
//
// Pinned schema versions:
//
// - Cursor `~/.cursor/mcp.json`           schema: cursor.mcp/2024-12
// - Claude Desktop `claude_desktop_config.json` schema: anthropic.mcp/2024-12
// - Continue                              schema: continue.mcpServers/2025-01
// - Zed                                   schema: zed.context_servers/2025-02

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub(crate) enum IdeTarget {
    Cursor,
    ClaudeDesktop,
    Continue,
    Zed,
}

impl IdeTarget {
    pub(crate) fn schema_version(self) -> &'static str {
        match self {
            IdeTarget::Cursor => "cursor.mcp/2024-12",
            IdeTarget::ClaudeDesktop => "anthropic.mcp/2024-12",
            IdeTarget::Continue => "continue.mcpServers/2025-01",
            IdeTarget::Zed => "zed.context_servers/2025-02",
        }
    }
}
