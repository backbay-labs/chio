# Migrating from MCP to Chio

This guide adds Chio protection to an existing MCP server in about five
minutes. It covers the most common setup: a local MCP tool server
(filesystem, git, shell) invoked by a coding agent (Claude Code,
Cursor, a custom CLI).

You'll end with:

- The same MCP client UX you have today.
- A policy-enforced sidecar between the client and the tool server.
- Signed receipts for every allow / deny decision.
- Bundled defaults that immediately deny `.env` writes, `.git/**`
  reads, and destructive shell commands.

If you'd rather stay inside Python and skip the CLI, jump to
[Alternate route: embedded Python SDK](#alternate-route-embedded-python-sdk).

## Prerequisites

- An MCP server you can launch locally. The examples use
  `@modelcontextprotocol/server-filesystem`, but any MCP stdio server
  works (see [Servers other than filesystem](#servers-other-than-filesystem)).
- macOS or Linux. Windows works via WSL.
- 5 minutes.

## Step 1: Install `chio`

Use the release binary or build from source:

```bash
# Homebrew release asset
curl -fsSL -o /tmp/chio.rb https://github.com/backbay-labs/chio/releases/latest/download/chio.rb
brew install --formula /tmp/chio.rb

# Or, from a local checkout
cargo install --path crates/chio-cli
chio --version
```

You should see something like:

```
chio 0.1.0
```

## Step 2: Bootstrap or copy the supported starter policy

If this is a fresh project, scaffold one with `chio init`:

```bash
chio init my-chio-project
cd my-chio-project
```

That creates a runnable `policy.yaml`, a sample tool server, and a
demo driver so you can sanity-check your install.

If you already have a project tree, copy the supported coding-agent
starter instead:

```bash
cp examples/policies/canonical-hushspec.yaml ./policy.yaml
```

That file is the canonical HushSpec starting point for coding-agent
stacks: safe file access is allowed, obvious secret paths are denied,
destructive shell commands are blocked, and receipts are on by default.

## Step 3: Wrap your MCP server with `chio mcp serve --policy`

This is the canonical supported path. The Chio CLI spawns your MCP server
as a subprocess, mediates every tool call through the kernel, and
re-exposes a compatible MCP edge over stdio:

```bash
chio mcp serve \
  --policy ./policy.yaml \
  --server-id fs \
  -- npx -y @modelcontextprotocol/server-filesystem .
```

What the flags mean:

| Flag | Purpose |
|------|---------|
| `--policy ./policy.yaml` | File-backed HushSpec starter you can edit in-repo while keeping the wrapped MCP flow unchanged. |
| `--server-id fs` | Chio's internal id for the wrapped server. Used in receipts. Any short string works. |
| `--` | Everything after this is the literal command Chio runs as the MCP subprocess. |

A successful launch prints a structured log line on stderr:

```
INFO chio::cli loaded policy for MCP edge policy_path="/tmp/chio-preset-.../code_agent_preset.yaml" preset="code-agent" server_id="fs" source_policy_hash="..."
INFO chio::cli initialized MCP edge session capability_count=N wrapped_command="npx"
```

Point your MCP client at this process exactly the way you would point
it at the upstream MCP server -- it speaks the same protocol.

If you want the zero-config fallback instead, `chio mcp serve --preset code-agent`
still exists and ships a bundled policy with the same intent.

### Hosted HTTP variant: `chio mcp serve-http`

If you expose the same stack over HTTP instead of stdio, keep the session
contract literal:

- send `initialize` to `POST /mcp` without `MCP-Session-Id`
- wait for the SSE initialize response and capture `MCP-Session-Id`
- send `notifications/initialized` on `POST /mcp` before `tools/list` or `tools/call`
- use `GET /mcp` for live notifications and replay, with `Last-Event-ID` as the replay cursor
- expect late notifications and task handles to stay scoped to the session that created them, even when a shared hosted owner reuses one upstream subprocess

If your client sends `_meta.modelMetadata` or `_meta.chioModelMetadata`, Chio
preserves that data on the request and receipt path, but the incoming
provenance is treated as `asserted` until a trusted subsystem upgrades it.

## Step 4: Prove one deny, one allow, and one receipt

Run `chio check` against the same file-backed starter policy to confirm the
kernel path is live:

```bash
chio check --policy ./policy.yaml \
  --server fs --tool write_file \
  --params '{"path":"/workspace/project/.env","content":"BAD=1"}'
```

On a deny the command exits non-zero and prints a structured verdict:

```
verdict:    DENY
tool:       write_file
server:     fs
reason:     forbidden_path: path matched **/.env
receipt_id: 0198d2af-...
policy:     0b4a2ef9...
source:     9f1e73c6...
```

A safe command is the reverse:

```bash
chio check --policy ./policy.yaml \
  --server shell --tool run_command \
  --params '{"command":"pwd"}'
# verdict: ALLOW, exit 0
```

End-to-end through your MCP client:

| Operation | Expected outcome |
|-----------|------------------|
| `run_command("pwd")` | Allow. Receipt emitted. |
| `read_file(".env")` | Deny. `forbidden_path`. |
| `read_file(".git/config")` | Deny. `forbidden_path`. |
| `write_file("src/main.py", ...)` | Allow. Receipt emitted. |
| `write_file("package.json", ...)` | Deny. `not_in_writable_root`. |
| `run_command("rm -rf /")` | Deny. `shell_command`. |
| `run_command("git push --force")` | Deny. `shell_command`. |

If you see a different result, double-check that the MCP client is
talking to the `chio mcp serve` process -- not the upstream server
directly.

## Step 5: Next steps

Once the baseline deny list is in place:

1. **Author a custom policy.** The preset is a starting point. Copy
   the starter HushSpec to your repo and edit to taste:

   ```bash
   cp examples/policies/canonical-hushspec.yaml ./policy.yaml
   # edit policy.yaml, then:
   chio mcp serve --policy ./policy.yaml --server-id fs -- npx -y @modelcontextprotocol/server-filesystem .
   ```

2. **Add more guards.** The preset ships with `forbidden_path`,
   `shell_command`, `secret_patterns`, and `patch_integrity`. Other
   guards that plug in cleanly:

   - `path_allowlist` -- allow-list instead of deny-list for reads
     and writes.
   - `egress_allowlist` -- restrict outbound HTTP domains.
   - `tool_access` -- enforce a named allow list for tool names.
   - `computer_use` / `input_injection` -- desktop CUA safety (Phase
     5).

   See `docs/guards/` for the catalogue.

3. **Verify receipts.** Every allow / deny is a signed artefact. Use
   `chio receipt` to query them:

   ```bash
   # Tenant-scoped local read (fails closed unless --tenant or --admin-all is set).
   chio --receipt-db ./receipts.sqlite receipt list --tenant <your-tenant> --limit 20
   # Cross-tenant operator read.
   chio --receipt-db ./receipts.sqlite receipt list --admin-all --limit 20
   chio --receipt-db ./receipts.sqlite receipt verify <receipt-id>
   ```

4. **Enable delegation.** If you have a multi-agent crew, capability
   attenuation lets you hand a junior agent a strictly narrower
   token. See `sdks/python/chio-crewai/README.md`.

## Alternate route: embedded Python SDK

If your coding agent is a Python process, skip the CLI entirely and
embed `chio-code-agent`:

```bash
pip install chio-code-agent chio-sdk-python
```

```python
import asyncio
from chio_code_agent import CodeAgent
from chio_sdk import ChioClient

async def main() -> None:
    async with ChioClient("http://127.0.0.1:9090") as client:
        agent = CodeAgent(chio_client=client, capability_id="cap-123")
        result = await agent.files.read_file("README.md")   # allow
        print(result.result)
        await agent.files.write_file(".env", "BAD=value")   # deny

asyncio.run(main())
```

The Python package enforces the same coding-agent policy intent as the
CLI starter path, but the supported default operator workflow remains the
file-backed HushSpec plus `chio mcp serve`.

## Servers other than filesystem

The `code-agent` preset is designed to wrap any MCP tool server
whose tools fall into the file / shell / git buckets. The preset
allow-list covers:

| Server id | Tools allowed |
|-----------|---------------|
| `fs` | `read_file`, `write_file`, `edit_file`, `list_directory`, `search_files`, `create_directory` |
| `shell` | `run_command` |
| `git` | `status`, `diff`, `log`, `add`, `commit` |

In practice that means the preset drops in cleanly for:

- `@modelcontextprotocol/server-filesystem`
- `@modelcontextprotocol/server-git` (map `git/push` at the shell
  guard; force-push is denied regardless)
- Shell-style MCP servers (map your tool name to `shell/run_command`
  via the `--server-id` flag)

For servers that expose tool names the preset doesn't know, supply
`--policy` with an edited YAML instead of `--preset code-agent`.

## Troubleshooting

### `error: unknown --preset "nope" (known: code-agent)`

Typo in the preset name. `code-agent` is the only bundled preset
today. Use a custom `--policy` path for anything else.

### The upstream MCP server exits immediately

`chio mcp serve` shells out exactly as written -- the first token is
the executable, the rest are argv. If you'd normally write
`npx @modelcontextprotocol/server-filesystem .` make sure the `--`
separator is in place:

```bash
chio mcp serve --preset code-agent -- npx @modelcontextprotocol/server-filesystem .
```

### The client hangs on startup

Check stderr. On a typical `stderr` the Chio CLI prints:

```
INFO chio::cli loaded policy for MCP edge ...
INFO chio::cli initialized MCP edge session ...
```

If only the first line prints, the wrapped MCP server failed to
initialize. Run that command standalone to see its own error output.

### A known-safe file is still denied

The preset enforces writes to be under `src/`, `tests/`, or `docs/`
by default. A write to a top-level `package.json` produces:

```
DENY: not_in_writable_root
```

To permit broader writes, switch to a custom policy whose
`path_allowlist.write` matches your layout.

## What's NOT migrated by this guide

Not every MCP feature lands on day one. Known gaps:

- **Streaming responses.** `chio mcp serve` supports streaming chunks
  but the bundled preset does not yet throttle them. Heavy streamers
  (log tailers, large-file readers) should move to the HTTP edge
  (`chio mcp serve-http`) which exposes backpressure controls.
- **Resource / prompt endpoints.** The preset only maps tool calls.
  MCP resources (`resources/list`, `resources/read`) and prompts
  (`prompts/get`) are wrapped but use default-allow through the
  upstream server. Add `resource_grants` / `prompt_grants` to a
  custom policy to enforce scoping.
- **Sampling.** `completions/` is proxied unchanged. If you need
  nested sampling governance, enable `allow_sampling_tool_use` in the
  policy's `kernel:` section and author a matching scope.
- **Remote MCP.** This guide covers stdio edges. For remote MCP
  (Streamable HTTP with OAuth2 / OIDC), use `chio mcp serve-http`;
  the `--preset` flag is a stdio-only convenience today.
- **Pre-existing receipts.** Moving to Chio does not retroactively
  attest past tool calls; receipts start at the first call through
  the edge.
- **Non-coding workloads.** The `code-agent` preset is tuned for
  developer-style workloads. For CUA (computer use) agents, data
  agents, or e-commerce flows, start from a custom policy.
- **Authorization beyond capability tokens.** The preset runs with
  kernel-minted default capabilities; integrating an external
  authority, issuing time-bounded child tokens, or wiring DPoP
  nonces requires explicit policy and client changes (see
  `docs/DPOP_INTEGRATION_GUIDE.md`, `sdks/python/chio-sdk-python`).
- **Windows stdio.** Tested on macOS and Linux. Windows works via
  WSL; native Windows stdio is untested.

None of these are blockers for the five-minute flow. Come back when
you need them.
