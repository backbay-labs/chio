# chio-hermes

The 0.1.2 candidate provides a restricted Hermes CLI launcher for Chio's
kernel-mediated MCP execution gateway. The program acceptance status is
**unresolved**, not production qualified. See [ACCEPTANCE.md](ACCEPTANCE.md)
for actual versions, observations, failures, and remaining gates.

The legacy native plugin is retained for compatibility and diagnosis. Its
id-only Python SDK calls deliberately cannot authorize execution. Its hook
now rejects tools outside the twelve registered Chio names, including forged
`chio_*` names, and rejects missing configuration. A loaded hook can prevent
calls on the pinned host, but host callback exceptions and plugin load failure
leave native tools executable. Do not use that mode as a protected boundary.

## Candidate supported mode

`chio-hermes-restricted` launches the pinned Hermes CLI with only `mcp-chio`.
It creates a fresh isolated profile and empty local working directory, disables
user/project plugins and shell hooks, disables dynamic tool search, and exposes
only the exact tool names in an operator-prepared Chio gateway configuration.
The tested initial workflow is external file reading, writing, and editing.
Native shell, local file operations, native/custom network tools, browser,
MCP servers other than Chio, delegation, background jobs, and scheduled jobs
are unavailable in this mode. It does not accept arbitrary Hermes CLI flags.

The real resource lives behind the kernel in a separate resource service. The
Hermes process must receive no protected resource mount or Docker socket. The
stdio gateway owns the agent authentication token, trusted signer pins,
retained kernel session, and durable operation journal. Each effect is sent
through kernel `tools/call`; the launcher never authorizes a local executor.
Gateway configuration and journals must be outside the protected resource's
write scope. The launcher itself is not an OS sandbox.

## Installation and launch

This candidate has not yet passed public installation or release acceptance.
Use a reviewed wheel artifact and the matching packed `@chio/bridge` artifact,
not an unpinned public `chio` installer. The current source qualification pins
Hermes `175054c14b54404663d8614a178280cffe6062eb` (v0.20.5, 2026.8.19), Python
3.11.3, and Chio gateway 0.3.0. The acceptance record identifies tested artifact
hashes and whether each run used source or a packed installation.

1. Install the pinned upstream Hermes revision into a dedicated installation
   and Python environment. Keep that installation's `.env` absent. Hermes
   loads and may rewrite `install/.env` despite an isolated `HERMES_HOME`.
   The launcher checks the inspected dispatch/configuration file hashes and
   refuses a different host contract. Machine-managed Hermes configuration
   requires separate qualification and is refused by this candidate.
2. Install the reviewed `chio_hermes-0.1.2` wheel in an isolated environment.
   Install its dependencies from the reviewed wheelhouse. Local qualification
   builds used `chio-sdk-python==0.1.0`, `chio-code-agent==0.1.0`, and
   `chio-adapter-base==0.2.0`; version strings alone do not identify those
   source-built artifacts. Their hashes are recorded in the evidence.
3. Install the compatible packed bridge and kernel artifacts. Run
   `chio-prepare-gateway` with a private operator request to establish a
   retained kernel session, signer/subject/capability binding, a unique
   session identity, a durable journal, and an exact resource tool allowlist.
   Keep the administrative credential separate from the gateway agent token.
4. Put the model provider credential in an explicitly named environment
   variable and the task in a query file. Invoke:

```bash
chio-hermes-restricted \
  --host-python /opt/hermes/venv/bin/python \
  --host-root /opt/hermes/pinned-source \
  --node /opt/node/bin/node \
  --gateway-script /opt/chio-bridge/dist/gateway.js \
  --gateway-config /private/operator/hermes-gateway.json \
  --state-dir /private/operator/runs/hermes-unique-run \
  --query-file /private/operator/task.txt \
  --model gpt-4.1 \
  --model-base-url https://api.openai.com/v1 \
  --model-key-env OPENAI_API_KEY
```

The paths above are explicit installation locations, not assumed private
sibling checkouts. The state directory must not already exist. The launcher
stores `launch.json` with configuration and gateway script hashes and exact
command arguments; it does not copy the gateway token or provider credential
into the profile. The supplied environment must contain the named model
credential. The gateway configuration is private (mode `0600`); the gateway
journal is private (mode `0700`).

## Recovery, upgrade, and removal

A normal completed operation has a verified outcome in the gateway journal.
An error after dispatch can mean an unknown external outcome. Stop the session
and preserve the gateway journal, resource observations, host logs, and kernel
receipt data. Do not silently retry, delete a stale gateway lock, replace its
journal, or give an uncertain operation a new identity. Use resource-side
reconciliation before the trusted operator restores admission. A missing or
malformed gateway configuration leaves protected tools unavailable.

This candidate is one-shot. Automatic resume, restart continuation, interactive
slash commands, and background sessions are not exposed by the launcher.
Their I07 acceptance remains open. A new independent run needs a fresh
operator-prepared session and new state directory; it must not substitute for
recovery of an unknown previous outcome.

For upgrades, retain the prior artifacts and evidence, install the new version
into a separate environment, and rerun the host gates. A new host contract
requires new source inspection and qualification. Do not widen toolsets to fix
an installation error. For removal, stop the host and gateway, revoke/expire
the kernel session authority, retain required audit records, then uninstall
the isolated plugin/bridge installations. No normal Hermes profile is modified
by this launcher.

## Validation

```bash
uv sync --extra dev
uv run --extra dev pytest -q
uv run --extra dev ruff check src tests scripts
```

Four legacy sidecar tests are opt-in and remain unresolved in a default unit
run. Explicit `CHIO_INTEGRATION=1` fails if no binary is available. These tests
call Python handlers, not a real Hermes session, and their historical allow
expectations conflict with the now fail-closed id-only SDK. Do not count them
or `MockChioClient` tests as host acceptance.

`scripts/probe_host_boundary.py` drives an actual pinned Hermes CLI process
using a local deterministic model fixture. It records independent effect
markers, configured tools, returned tool results, and raw host logs in an
isolated profile. It reproduces the legacy native bypass, loaded-hook denial,
callback exception, malformed hook response, plugin load failure, and static
native-tool exclusion. The fixture replaces inference only; it does not
qualify real-model useful work or substitute for real-kernel testing.
