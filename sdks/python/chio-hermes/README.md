# chio-hermes

Hermes Agent plugin for the [Chio](https://github.com/backbay-labs/chio)
protocol. Routes Hermes file/shell/git tools through a capability-scoped
Chio sidecar so every call is policy-checked, signed, and audited.

There are two ways to bring Chio into a Hermes session. Pick one; do
not stack them.

- **Path A (zero-code, MCP-server style):** run
  `chio mcp serve --preset code-agent -- <upstream-mcp-server-argv>` and
  paste the resulting `mcp_servers.chio` block into
  `~/.hermes/config.yaml`. No Python dependency.
- **Path B (this package):** install Hermes, then `pip install
  chio-hermes` into the same Python environment, enable `chio` under
  `plugins.enabled`, and Chio's `CodeAgent` tool surface becomes part
  of the Hermes tool registry.

## Install

`hermes-agent` is not on PyPI. Install Hermes first via the upstream
curl-installer, then `pip install chio-hermes` into the same Python:

```bash
# 1. Install Hermes (one of the two)
curl -LsSf https://hermes.nousresearch.com/install.sh | sh
# or
pip install --upgrade git+https://github.com/NousResearch/hermes-agent.git

# 2. Install the Chio plugin
pip install chio-hermes

# 3. Enable the plugin in ~/.hermes/config.yaml
#    plugins:
#      enabled:
#        - chio
```

`hermes setup` will then prompt for `CHIO_SIDECAR_URL` and
`CHIO_CAPABILITY_ID` (the capability id is masked at the prompt).

## Path A: zero-code MCP wrapping

Skip this package entirely. Wrap any upstream MCP server with the Chio
edge:

```yaml
# ~/.hermes/config.yaml
mcp_servers:
  chio:
    command:
      - chio
      - mcp
      - serve
      - --preset
      - code-agent
      - --server-id
      - fs
      - --
      - npx
      - -y
      - "@modelcontextprotocol/server-filesystem"
      - /workspace
```

The `--server-id` MUST match an identifier the bundled `code-agent`
preset grants capabilities to (`fs`, `shell`, or `git`). Using any
other id (e.g. `filesystem`) fails closed because no grant matches.

Chio gates each `tools/call` through the `code-agent` policy preset
(byte-identical to the policy used by `chio-code-agent` and this
plugin). See `docs/integrations/HERMES.md` for the full Path A
walkthrough including shell and git server entries.

## Path B quickstart

After installing Hermes, this plugin, and minting a capability:

```bash
hermes chio issue \
    --tool-server fs --tool-server shell --tool-server git \
    --subject 0xabcdef... \
    --ttl 3600

export CHIO_SIDECAR_URL="http://127.0.0.1:9090"
export CHIO_CAPABILITY_ID="cap-..."   # printed by `hermes chio issue`

hermes chat -t chio,hermes-cli
```

The `chio` toolset is opt-in. Add `chio` to the `toolsets:` list in
`~/.hermes/config.yaml`, or pass `-t chio,hermes-cli` per-invocation,
or the 12 `chio_*` tools will not surface in the session even with
`plugins.enabled: [chio]` set.

Inside the session, `chio_file_read`, `chio_shell_run`, `chio_git_*`
and the rest of the 12 `chio_*` tools are available. `/chio status`
shows the configured sidecar, masked capability id, and recent
receipts.

> **Sidecar quickstart (chio v0.2+):** the plugin expects a Chio
> sidecar at `CHIO_SIDECAR_URL` exposing `/v1/capabilities/*`. With
> chio v0.2 you can run one in a single line:
>
> ```bash
> chio start --listen 127.0.0.1:9090 --print-config
> ```
>
> `chio start` is a friendly zero-config alias for `chio api protect`
> with the SDK path aliases (`POST /v1/capabilities`,
> `POST /v1/evaluate`, `POST /v1/capabilities/validate`,
> `POST /v1/receipts/verify`) mounted. For chio < 0.2, the plugin
> stays in degraded-but-safe mode: `chio_sidecar_unreachable` envelopes
> surface for `status: allowed` paths, but every client-side guard
> (path filters, env sanitization, `--no-verify` rejection, output
> capping) still fires. See
> [docs/integrations/HERMES.md](../../../docs/integrations/HERMES.md)
> for the full deployment matrix.

## What the bundled default policy denies

The plugin reuses the `chio_code_agent` default policy unchanged:

- **Allows:** reading files under the cwd; writing under `src/`,
  `tests/`, `docs/`; safe shell commands; read-only `git` subcommands
  (`status`, `diff`, `log`); `git add` and `git commit`.
- **Denies:** `.env` / `.env.*`, `.git/**`, `.ssh/**`,
  `.aws/credentials`, `*.pem`, `*.key`, `id_rsa`, `id_ed25519`.
- **Denies outright:** `rm -rf /`, `chmod 777`, `curl | sh`, `sudo`,
  `git push --force`, `git reset --hard origin`, `mkfs.*`,
  `dd if=... of=/dev/...`.
- **Approval-required (held in the sidecar HITL queue):** `rm -rf
  <subdir>`, `mv`, `cp -r`, `git reset --hard`, `git clean -fd`. The
  `chio_shell_run` schema does NOT expose an `approved` field, so the
  model cannot self-approve. As of v0.2 the plugin POSTs the held call
  to the sidecar (`POST /approvals/submit`) and returns a
  `chio_requires_approval` envelope carrying an `approval_id`. Resolve
  it with `/chio approve <id>` (or `/chio deny <id>`) inside the
  Hermes session, or `hermes chio approvals respond <id>
  --approve|--deny [--reason TEXT]` from another shell. After the
  approval lands, the LLM has to retry the original tool call;
  auto-resume of held calls is v0.3 work.

Custom policies load from `CHIO_POLICY_FILE` (path to YAML); if unset
the bundled `DEFAULT_POLICY` is used.

## Capability lifecycle

The plugin ships a `hermes chio` CLI subcommand:

```bash
hermes chio issue --tool-server fs --subject 0x... --ttl 3600
hermes chio list
hermes chio revoke <capability-id> --reason "rotated"
hermes chio approvals list
hermes chio approvals respond <approval-id> --approve --reason "ok-by-operator"
hermes chio approvals respond <approval-id> --deny
```

`issue` calls `ChioClient.create_capability(...)` and writes the
returned capability id into a per-profile JSON cache at
`~/.hermes/profiles/<active>/chio-capabilities.json`. `list` reads
that cache. `revoke` shells out to `chio trust revoke
--capability-id <id>` and marks the local cache entry revoked.
`approvals list` and `approvals respond` drive the sidecar HITL
channel via the operator-respond shortcut on
`POST /approvals/{id}/operator-respond`.

For an in-session view, use `/chio status`, `/chio receipts [N]`,
`/chio policy`, `/chio approvals`, `/chio approve <id> [reason]`, or
`/chio deny <id> [reason]`.

## Receipts caveat

The plugin appends one canonical-JSON line per Chio receipt to
`<hermes-home>/logs/chio-receipts.jsonl` (profile-aware). This file is
a **user-side convenience for the Hermes session, not the canonical
audit store.**

The verifiable, tamper-evident copy lives in the sidecar's receipts
database. To get long-term storage, run the sidecar with
`--receipts-db <path>.sqlite`; replay it via `chio replay` (see
`docs/replay-cli.md`). Operators who care about audit MUST configure
`--receipts-db`.

## Failure modes

Each handler returns canonical JSON. Common shapes:

| Case | `error` field |
|------|---------------|
| Allow | (none, `status: "allowed"`) |
| Local policy deny | `denied` (with `guard`) |
| Sidecar deny | `denied` (with `guard` from receipt) |
| Sidecar unreachable | `chio_sidecar_unreachable` |
| Capability expired | `chio_capability_expired` |
| `CHIO_CAPABILITY_ID` unset | `chio_not_configured` |
| Executor I/O error | `chio_executor_error` |
| Other | `chio_error` |

`pre_tool_call` denials surface to the model via Hermes's native block
path; the plugin does not inject extra system messages.

## Relation to `chio mcp serve --preset code-agent`

`chio mcp serve --preset code-agent` is the same policy wrapping an
arbitrary MCP server over stdio (Path A above). `chio-hermes` is the
Python-embedded flavour that lives inside the Hermes process (Path B).
The two paths use byte-identical policies, so they deny the same set
of operations. Pick whichever fits your integration surface; do not
stack both, or every tool call will be policy-checked twice.

## Environment variables

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `CHIO_SIDECAR_URL` | yes | `http://127.0.0.1:9090` | Sidecar HTTP endpoint. Not secret. |
| `CHIO_CAPABILITY_ID` | yes | (none) | Capability id from `hermes chio issue`. Without this the handlers return `chio_not_configured`. Long-lived bearer secret; store in `~/.hermes/.env` with mode `0600`. |
| `CHIO_POLICY_FILE` | no | (bundled `DEFAULT_POLICY`) | Path to a YAML policy. Not secret. |
| `CHIO_WORKSPACE_ROOT` | no | current working directory | Constrains every `chio_file_*`, `chio_git_*`, and `chio_shell_run` operation to a single resolved root; paths that resolve outside are rejected with `PermissionError`. Not secret. |
| `CHIO_SHELL_TIMEOUT` | no | `60` (seconds) | Per-subprocess wall-clock timeout for `chio_shell_run`, `chio_file_edit`, and `chio_git_*` (each invocation, not the cumulative budget). Not secret. |
| `CHIO_SUBPROCESS_MAX_BYTES` | no | `1048576` (1 MiB) | Per-stream byte cap for `chio_shell_run` / `chio_git_*` subprocess output. Output past the cap is truncated and the result envelope carries `output_truncated: true`. Not secret. |
| `CHIO_RECEIPT_BUFFER_MAX` | no | `1000` | In-memory recorded-receipt buffer cap (cap on the global FIFO deque exposed via `/chio receipts`, NOT a per-task limit). Not secret. |
| `CHIO_CONTROL_URL` | required for `hermes chio revoke` (when `CHIO_REVOCATION_DB` is unset) | (none) | Forwarded as `--control-url` to `chio trust revoke`. Takes precedence over `CHIO_REVOCATION_DB`. Without this or `CHIO_REVOCATION_DB`, `revoke` exits with `chio_revocation_backend_unconfigured`. Not secret (URL only; auth is the capability bearer). |
| `CHIO_REVOCATION_DB` | required for `hermes chio revoke` (when `CHIO_CONTROL_URL` is unset) | (none) | Filesystem path forwarded as `--revocation-db` to `chio trust revoke`. Used when `CHIO_CONTROL_URL` is not set. Not secret (path only). |

## Configuration precedence

For each setting (sidecar URL, capability id, policy file, etc.):

1. `plugins.entries.chio.*` in `~/.hermes/config.yaml` (lowest).
2. `~/.hermes/.env` env vars (override).
3. In-process env vars at registration time (highest).

This mirrors Hermes's own `~/.hermes/.env` over `config.yaml` model.

## Caveats (upstream Hermes)

Four Hermes 0.13.0 gaps affect entry-point plugins. None block
functionality once worked around.

- `hermes plugins list` does not enumerate entry-point plugins. Trust
  `pip show chio-hermes` and the `[plugins] DEBUG Loading plugin
  'chio'` log line under `HERMES_PLUGINS_DEBUG=1`.
- `hermes plugins enable chio` rejects entry-point names. Edit
  `~/.hermes/config.yaml` directly:

  ```yaml
  plugins:
    enabled:
      - chio
  ```
- `hermes setup` does not read entry-point `plugin.yaml`, so it never
  prompts for `CHIO_SIDECAR_URL` / `CHIO_CAPABILITY_ID`. Export them
  (or write to `~/.hermes/.env` mode `0600`) before `hermes`.
- LLM-driven invocation (`hermes -z "..."`) is unproven (no provider
  key on the dogfood box). Static surface is verified end to end.

See `docs/integrations/HERMES.md` "Known issues" for the file:line
references in upstream `hermes_cli`.

## See also

- `docs/integrations/HERMES.md` -- long-form integration walkthrough.
- `chio-code-agent` -- the underlying tool wrappers.
- `chio mcp serve --preset code-agent` -- Path A wrapping flavour.
