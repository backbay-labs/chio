# Restricted MCP session credentials

This candidate closes two demonstrated required-agent integration gaps: a
host-readable gateway config contained the static operator bearer, and an
agent-writable adapter journal could lose an unknown-outcome fence. It does not
by itself qualify any host's complete operating-system or resource boundary.

## Operator preparation

The selected mode requires a static operator bearer, a different admin bearer,
`--session-db`, durable admission, and `--shared-hosted-owner`. Keep both operator
bearers and the operator preparation input outside the agent's readable paths.
The agent receives only the exchanged credential and its public binding.

1. The operator initializes `/mcp` with the static bearer and retains the returned
   `MCP-Session-Id`. Finish `notifications/initialized`, inspect
   `chio/execution-context`, and inspect `tools/list` without invoking tools.
2. Send `POST /admin/sessions/{sessionId}/credential` with the distinct admin
   bearer and JSON `{"ttlSeconds":300,"allowedTools":["read_text_file","write_file"]}`.
   The TTL must be 1 through 3600 seconds. The server clamps it to the earliest
   retained capability expiry. Tool names must be explicit, present in the real
   owner inventory, and covered by a retained invocation grant.
3. Validate the response against the retained session, caller, capabilities,
   resource owner, selected tools, and expected expiry. It contains `schema`
   (`chio.mcp.session-credential.v1`), `bearerToken`, `sessionId`, `subjectKey`,
   `capabilityIds`, `serverId`, `endpointPath` (`/mcp`), `allowedTools`, `issuedAt`,
   and `expiresAt` (Unix seconds).
4. Use the exchanged bearer with the exact session header. Recheck
   `chio/execution-context`: `result.sessionCredential` contains the same public
   binding, excluding `bearerToken`. Only this bearer belongs in the host-facing
   configuration. The response is authenticated by the selected transport; it
   is not a separately signed client-verifiable artifact. The persisted owner
   record is signed with the durable kernel key and contains only a token hash.

The credential cannot initialize another session, use another session, access
admin APIs, or invoke resource, prompt, delegation, or logging methods. Supported
POST methods are `tools/list`, `tools/call`, `chio/execution-context`, `ping`, and
`notifications/cancelled`. Every tool call must carry an explicit stable
`params._meta.chioRequestId`. Calls outside the selected exact tool names are
rejected before submission to the kernel; the tool catalog is filtered. GET
subscriptions are disabled because shared upstream notifications can contain
unrelated data. DELETE can close only the retained session.

Kernel capability validation, revocation, guards, approval requirements, and
aggregate grant budgets continue to apply. Exchanging or rotating a credential
never issues a capability or resets its budget.

## Owner recovery boundary

Before dispatch, the owner records a signed pending call in an immediate SQLite
transaction. A completed response can release this pending fence only after the
owner verifies the intended kernel signer, capability, caller, resource, tool,
parameters, stable request ID, durable admission terminal state, and raw output
hash. Denial, error, unknown outcome, missing response, or persistence failure
leaves the session fenced against subsequent protected calls. Configuration or
journal tampering in an agent process cannot erase this owner record.

An exact completed retry receives the persisted response with its current
JSON-RPC correlation ID. A changed request under an existing stable ID is
rejected. Pending calls and completed response history survive restart. Loss of
the retained session or credential store denies the old credential; no new
session or capability is minted automatically.

The operator can inspect `GET /admin/sessions/{sessionId}/credential/status` and
revoke via `POST /admin/sessions/{sessionId}/credential/revoke`. Revocation waits
for an admitted request stream to release ownership; queued requests must
reauthenticate before dispatch. Revocation and credential rotation retain the
call fence and history. A safe automatic unfencing procedure is not delivered
in this candidate. Preserve the record, inspect kernel receipts and the actual
resource independently, and revoke uncertain authority. A new operator-issued
session is an explicit new authority decision, never an implicit retry of an
unknown external effect.

## Reproduction

Run `cargo test -p chio-mcp-remote --lib`, then build `chio-cli` and copy the
binary to an immutable test artifact. With the separately qualified filesystem
resource image locally available:

```sh
python3 scripts/acceptance/session-credentials.py \
  --binary /absolute/immutable/chio \
  --image sha256:RESOURCE_IMAGE_DIGEST \
  --runtime /absolute/new-private-runtime \
  --evidence /absolute/new-evidence-directory
```

The script creates its own Docker volume, private operator tokens, kernel
process, and databases. It leaves the volume and state for inspection and stops
only its own kernel. Its MCP relay delays one real filesystem tool response to
exercise a lost response after the independent observer sees the actual write.
Raw evidence contains no operator or exchanged bearer secrets. This is a shared
kernel qualification, separate from each real host's I01 through I08 acceptance.
