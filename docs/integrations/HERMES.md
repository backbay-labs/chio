# Hermes Integration

Chio (formerly ARC) is a first-class tool surface for the
[Hermes Agent](https://github.com/NousResearch/hermes-agent) the same
way it is for Claude Code, Cursor, Codex, and OpenClaw. Two integration
paths are supported. Path A wires Chio into Hermes as an MCP server
(zero new code, just a config snippet). Path B installs the native
`chio-hermes` Python plugin so policy enforcement runs as a
`pre_tool_call` hook and signed receipts land in a per-session JSONL
log. Pick one; stacking both is supported but doubles receipt volume
and confuses the audit trail.

## 1. Path A: run Chio as an MCP server (zero-code)

`chio mcp serve --preset code-agent` wraps an upstream MCP server, runs
every `tools/call` through the bundled `code-agent` policy, emits a
signed receipt, and forwards the call. The `--` separator marks the
start of the wrapped server's argv (`crates/chio-cli/src/cli/types.rs:1486-1529`;
`command: Vec<String>` is declared with `trailing_var_arg = true,
required = true`).

Add an entry under `mcp_servers` in `~/.hermes/config.yaml`:

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
      - filesystem
      - --
      # Wrapped MCP server argv. Replace with whichever MCP server you
      # want Chio to gate. The reference example wraps the upstream
      # filesystem MCP server (npm install -g
      # @modelcontextprotocol/server-filesystem) restricted to the
      # current directory.
      - npx
      - "-y"
      - "@modelcontextprotocol/server-filesystem"
      - "."
    transport: stdio
```

Verify with `hermes mcp test chio`. The `--preset code-agent` policy
is bundled; for a custom policy use `--policy <path/to/policy.yaml>`
(mutually exclusive with `--preset`, via `conflicts_with = "preset"`).

There is no "hosted MCP edge that ships its own tools" mode today;
Path A always wraps an external MCP server.

## 2. Path B: install the native plugin (`chio-hermes`)

Install Hermes itself first (the curl-installer or
`pip install --upgrade git+https://github.com/NousResearch/hermes-agent.git`).
Then, into the same Python environment:

```bash
pip install chio-hermes
```

Enable the plugin in `~/.hermes/config.yaml`:

```yaml
# ~/.hermes/config.yaml
plugins:
  enabled:
    - chio
```

Required environment variables (`hermes setup` will prompt for them; the
capability id is masked because `requires_env.password` is `true`):

| Variable                  | Required | Description                                                                                                |
| ------------------------- | -------- | ---------------------------------------------------------------------------------------------------------- |
| `CHIO_SIDECAR_URL`        | yes      | URL of the Chio sidecar (default `http://127.0.0.1:9090`).                                                  |
| `CHIO_CAPABILITY_ID`      | yes      | Capability id issued by `hermes chio issue`. Long-lived bearer token; prefer `~/.hermes/.env` mode `0600`. |
| `CHIO_POLICY_FILE`        | no       | Path to a custom policy YAML. Defaults to the bundled `chio-code-agent` policy.                             |
| `CHIO_RECEIPT_BUFFER_MAX` | no       | In-memory recorded-receipt buffer cap (cap on the global FIFO deque exposed via `/chio receipts`, NOT a per-task limit); default `1000`. |

### 2.1 What is wrapped

12 tools are registered under one Hermes toolset (`chio`). All names use
the `chio_` prefix to avoid collision with the bundled Hermes tools
(`read_file`, `write_file`, `patch`, `search_files`, `terminal`).

| Tool name          | What it does                                          |
| ------------------ | ----------------------------------------------------- |
| `chio_file_read`   | Read a file inside the workspace.                     |
| `chio_file_write`  | Write a file inside a writable root.                  |
| `chio_file_edit`   | Apply a unified diff via `patch`.                     |
| `chio_file_list`   | List a directory.                                     |
| `chio_file_search` | Glob the workspace for filenames.                     |
| `chio_shell_run`   | Run a shell command (60 s timeout).                   |
| `chio_git_status`  | `git status`.                                         |
| `chio_git_diff`    | `git diff` (optionally scoped to paths).              |
| `chio_git_log`     | `git log` (default last 20 commits).                  |
| `chio_git_add`     | `git add <paths>`.                                    |
| `chio_git_commit`  | `git commit -m <message>`.                            |
| `chio_git_run`     | Arbitrary `git <command>` (gated by policy).          |

Default policy: safe file reads are allowed, writes to `.env`,
`.git/**`, and `.ssh/**` are denied, `git push --force` is denied,
`rm -rf /` is denied. Full policy lives in
`sdks/python/chio-code-agent/src/chio_code_agent/default_policy.yaml`;
see the `chio-code-agent` README for the rationale behind each rule.

### 2.2 Capability lifecycle

```bash
# Mint a capability scoped to file/shell/git tool servers.
hermes chio issue \
    --tool-server fs \
    --tool-server shell \
    --tool-server git \
    --subject <hex-ed25519-pubkey> \
    --ttl 3600

# List locally-cached capabilities.
hermes chio list

# Revoke a capability (shells out to `chio trust revoke`).
hermes chio revoke cap-aaaa11112222 --reason "rotation"
```

`hermes chio issue` calls `ChioClient.create_capability` and writes the
returned `CapabilityToken` into
`~/.hermes/profiles/<active>/chio-capabilities.json`. `hermes chio list`
reads only the local cache; `chio-sdk-python` has no list RPC today.
`hermes chio revoke` invokes
`chio trust revoke --capability-id <id>` (`crates/chio-cli/src/cli/types.rs:1897-1902`)
and updates the cache.

There is no `hermes chio status` subcommand by design; use the
in-session `/chio status` slash command, or `hermes -c "/chio status"`
from a script.

### 2.3 In-session slash commands

| Slash command       | What it shows                                                                  |
| ------------------- | ------------------------------------------------------------------------------ |
| `/chio`             | Alias for `/chio status`.                                                       |
| `/chio status`      | Sidecar URL, capability id (last 8 chars), policy hash, buffer / denial counts. |
| `/chio receipts [N]`| The last N receipts (default 5, max 50).                                        |
| `/chio policy`      | Allowed-tool list and forbidden-path patterns from the active policy.           |

### 2.4 Receipts

Two side-effect surfaces hold receipts:

1. An in-memory FIFO deque of recorded receipts, capped at
   `CHIO_RECEIPT_BUFFER_MAX` (default 1000). The cap applies to the
   global recorded-receipt buffer, not a per-task quota; the pending
   per-task queue used by lifecycle hooks is unbounded between
   `on_session_start` / `on_session_end`. Surfaces via `/chio receipts`.
2. An append-only JSONL log at
   `<get_hermes_home()>/logs/chio-receipts.jsonl`. One canonical-JSON
   line per receipt. Profile-aware: `hermes profile switch work`
   redirects the log path automatically.

> The JSONL log is a user-side convenience for the Hermes session,
> NOT the canonical audit store. The kernel-signed copy lives in the
> sidecar's receipts database (`chio` started with
> `--receipts-db <path>.sqlite`) and is the verifiable source of truth,
> replayable via `chio replay`. See `docs/replay-cli.md`. Operators who
> care about tamper-evident long-term storage MUST run the sidecar with
> `--receipts-db`.

Hermes invokes parallel tools inside one `delegate_task` with the same
`task_id`; receipts are therefore keyed by `task_id` alone and ordered
by handler-completion time, not by Hermes dispatch order.

### 2.5 Failure modes

Every error path returns canonical JSON (sorted keys, no whitespace) so
Hermes's tool-output parser can route it consistently:

| Case                          | Envelope                                                                                                                       |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Allow                         | `{"receipt_id":"rcpt-...","result":"<value>","status":"allowed","tool_name":"...","tool_server":"..."}`                          |
| Local policy deny             | `{"error":"denied","guard":"ForbiddenPathGuard","reason":"path .env is forbidden","receipt_id":null}`                            |
| Sidecar deny                  | `{"error":"denied","guard":"<from receipt>","reason":"<from receipt>","receipt_id":"rcpt-..."}`                                  |
| Sidecar unreachable           | `{"error":"chio_sidecar_unreachable","message":"Failed to connect to Chio sidecar at http://127.0.0.1:9090"}`                    |
| Capability expired            | `{"error":"chio_capability_expired","guard":"ExpiredCapabilityGuard","message":"capability cap-... has expired; run hermes chio issue","receipt_id":"rcpt-..."}` |
| Configuration missing         | `{"error":"chio_not_configured","message":"set CHIO_CAPABILITY_ID before invoking Chio tools"}`                                  |
| Generic exception             | `{"error":"chio_error","message":"<exception text>"}`                                                                           |
| Executor I/O error after allow| `{"error":"chio_executor_error","message":"<text>","receipt_id":"rcpt-..."}`                                                    |

### 2.6 Configuration precedence

Config sources resolve in this order; later wins:

1. `plugins.entries.chio.*` from `~/.hermes/config.yaml` (lowest).
2. Variables in `~/.hermes/.env` (recommended for secrets, mode `0600`).
3. In-process environment (highest).

Custom policies load via
`compile_policy(open(CHIO_POLICY_FILE).read())`, the only loader
exported from `chio_code_agent` today.

### 2.7 Custom policy

Point `CHIO_POLICY_FILE` at a YAML file in the same shape as
`sdks/python/chio-code-agent/src/chio_code_agent/default_policy.yaml`.
The plugin reloads the policy on every `register(ctx)`, which Hermes
calls on `hermes plugins reload`.

### 2.8 Known issues (upstream Hermes)

Four `hermes-agent` 0.13.0 gaps affect entry-point plugins; fixes
belong in upstream `hermes_cli`.

| Symptom                                          | Root cause                                                                                                                                            | Workaround                                                                                                                  |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `hermes plugins list` does not show `chio`       | `_discover_all_plugins` (`hermes_cli/plugins_cmd.py:710`) walks user/bundled directories only; never calls `_scan_entry_points`.                       | Trust `pip show chio-hermes` and the `[plugins] DEBUG Loading plugin 'chio'` line under `HERMES_PLUGINS_DEBUG=1`.            |
| `hermes plugins enable chio` fails               | `_plugin_exists` (`hermes_cli/plugins_cmd.py:684`) only matches user/bundled directory names; rejects entry-point plugin names.                        | Edit `~/.hermes/config.yaml` directly to set `plugins.enabled: ["chio"]`.                                                    |
| `hermes setup` does not prompt for `CHIO_*` env  | `_missing_requires_env_names` (`hermes_cli/plugins_cmd.py:194, 1336`) is only consulted by the install pipeline for git/directory plugins; pip plugins skip it. | Export `CHIO_SIDECAR_URL` and `CHIO_CAPABILITY_ID` manually, or write them to `~/.hermes/.env` (mode `0600`).                |
| `hermes -z "..."` (LLM-driven dispatch) unproven | No provider API key on the dogfood box; the `-z` path hung. Static surface verified end to end.                                                       | Provide an LLM provider key and retry.                                                                                       |

The first three are fixable upstream by teaching
`_discover_all_plugins` / `_plugin_exists` /
`_missing_requires_env_names` to consult the entry-point manifest
cache that `_scan_entry_points` already populates.

## 3. Path A vs Path B: when to pick which

| Concern                                        | Path A (MCP wrap) | Path B (native plugin) |
| ---------------------------------------------- | ----------------- | ---------------------- |
| Install                                        | YAML edit only    | `pip install chio-hermes` + env vars |
| Tool naming                                    | Inherits from wrapped MCP server | `chio_*` (no collision) |
| Receipt surface                                | Sidecar-side only | Sidecar + per-session JSONL + `/chio receipts` |
| Denial UX                                      | MCP-style error | Pre-tool-call block message in chat |
| Per-tool granularity                           | Whatever the wrapped MCP server exposes | 12 fixed tools (file/shell/git) |
| Sidecar requirement                            | Always (`chio mcp serve` is the sidecar) | Always (HTTP sidecar) |
| Suitable for in-session policy customisation   | `--policy <file>` flag at startup | `CHIO_POLICY_FILE` env var |
| Stack both?                                    | Discouraged. | Discouraged. |

## 4. Troubleshooting

| Symptom                                        | First check                                                            |
| ---------------------------------------------- | ---------------------------------------------------------------------- |
| `chio_not_configured`                          | `printenv CHIO_SIDECAR_URL CHIO_CAPABILITY_ID` (or run `hermes setup`).|
| `chio_sidecar_unreachable`                     | `curl http://127.0.0.1:9090/chio/health`. Is the sidecar running?      |
| `chio_capability_expired`                      | `hermes chio issue` to mint a new one; export the new id.              |
| Plugin missing from `hermes plugins list`      | `pip show chio-hermes`; same Python interpreter as Hermes?             |
| JSONL log empty                                | `ls -la $(hermes profile path)/logs/`; check `HERMES_HOME` override.   |
| Hermes session killed by hook exception        | Should never happen; the `post_tool_call` hook swallows JSONL writer failures. File a bug. |

## 5. Relation to other Chio adapters

`chio-hermes` joins the family of framework adapters that lift Chio's
async client into a host runtime:

* `chio-langchain` -- LangChain `BaseTool` wrappers.
* `chio-llamaindex` -- LlamaIndex tool wrappers.
* `chio-crewai` -- CrewAI `BaseTool` wrappers.
* `chio-code-agent` -- the shared `CodeAgent` toolset (file/shell/git)
  that `chio-hermes` re-uses underneath.
* `chio-fastapi`, `chio-asgi`, `chio-django` -- HTTP-side enforcement.

All adapters share the `chio-sdk-python` core client and the canonical
JSON / signed-receipt contract, so swapping host frameworks does not
move the trust boundary.

## 6. Future work

Tracked separately, not blocking v0.1.0:

* Path C: ACP (`agent-client-protocol`) bridge between Chio and Hermes.
* Streamable HTTP variant of the Chio MCP edge for Hermes
  (`chio mcp serve-http`).
* Keychain-backed credential store for `CHIO_CAPABILITY_ID`.
* Native `hermes chio verify <receipt-id>` that calls into `chio-replay`.
