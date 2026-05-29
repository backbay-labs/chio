# Progressive Chio Tutorial

This tutorial takes the shortest honest path from "what is Chio?" to "I made a
governed call and I understand how delegation continues from here."

It reuses the phase `309` demo stack so the same local deployment can back the
tutorial, the SDK examples, and the receipt viewer.

## 1. Chio Concepts

Chio sits between an agent client and the tools it wants to call.

- Policies define what can be issued.
- Capabilities bind those permissions to a subject and a TTL.
- The hosted edge mediates tool calls and issues receipts.
- The trust service stores receipts, revocations, lineage, and query APIs.
- Delegation narrows or continues authority rather than minting unbounded new
  power.

For the local demo, the trust service and hosted edge are separate processes:

- `chio trust serve` owns receipt, revocation, and authority state
- `chio mcp serve-http` exposes an MCP endpoint and asks the trust service to
  issue and record governed capabilities

## 2. Start The Demo Stack

From the repo root:

```bash
docker compose -f examples/docker/compose.yaml up --build
```

That publishes three defaults used throughout the rest of this tutorial:

- hosted edge: `http://127.0.0.1:8931`
- trust service and receipt viewer: `http://127.0.0.1:8940`
- auth token: `demo-token`

If you prefer to run the processes directly instead of Docker, phase `309`
already qualified the equivalent `chio trust serve` plus
`chio mcp serve-http --control-url ...` topology.

## 3. Write A Policy

Chio policies describe what the hosted edge may issue when a session starts.
The demo policy is intentionally small:

```yaml
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5

capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
```

This means:

- session capabilities may last up to five minutes
- the hosted edge may issue tool-call authority
- the tool permissions are rooted in the trust service rather than trusted
  implicitly at the client

You can save this as `tutorial-policy.yaml` or reuse
[examples/docker/policy.yaml](../../examples/docker/policy.yaml).

## 4. Wrap A Tool

The upstream demo tool is a tiny MCP server that exposes `echo_text`:
[examples/docker/mock_mcp_server.py](../../examples/docker/mock_mcp_server.py).

To put Chio in front of it without Docker:

```bash
chio \
  --control-url http://127.0.0.1:8940 \
  --control-token demo-token \
  mcp serve-http \
  --policy tutorial-policy.yaml \
  --server-id tutorial-echo \
  --server-name "Tutorial Echo" \
  --listen 127.0.0.1:8931 \
  --auth-token demo-token \
  -- \
  python3 examples/docker/mock_mcp_server.py
```

At this point the upstream tool is no longer called directly. Clients connect
to the Chio hosted edge, Chio issues the session capability, and every governed
call produces a receipt.

## 5. Execute A Governed Call

The fastest end-to-end check is the host-side smoke client:

```bash
python3 examples/docker/smoke_client.py
```

The output includes:

- `sessionId`
- `capabilityId`
- the tool inventory returned by the hosted edge
- the governed tool result
- `receiptId`
- the receipt viewer URL

That single run proves the whole chain:

1. session initialization
2. capability issuance
3. governed tool execution
4. receipt persistence

## 6. Read A Receipt

The smoke client already resolves the receipt, but it helps to see the raw
query shape as well:

```bash
curl \
  -H "Authorization: Bearer demo-token" \
  "http://127.0.0.1:8940/v1/receipts/query?capabilityId=<capability-id>&limit=10"
```

You can also inspect the viewer directly at:

```text
http://127.0.0.1:8940/?token=demo-token
```

The receipt detail view shows the decision, timestamp, and delegation-chain
projection for the selected governed call.

If you need the capability attached to a hosted session, query the hosted edge:

```bash
curl \
  -H "Authorization: Bearer demo-token" \
  "http://127.0.0.1:8931/admin/sessions/<session-id>/trust"
```

That response is what the framework examples use before querying the trust
service for receipts.

## 7. Delegate A Capability

The concrete public delegation lane in the current CLI is the federated
continuation workflow. The local hosted-session demo above gives you the mental
model; the child-capability continuation happens with a signed delegation
policy plus a federated issue step that binds the new local authority to an
upstream capability ID.

The relevant commands are:

```bash
chio trust federated-delegation-policy-create \
  --output delegation-policy.json \
  --signing-seed-file authority-seed.txt \
  --issuer local-org \
  --partner remote-org \
  --verifier https://trust.example.com \
  --capability-policy examples/policies/federated-parent.yaml \
  --parent-capability-id cap-upstream \
  --expires-at 1900000000

chio \
  --control-url https://trust.example.com \
  --control-token <service-token> \
  trust federated-issue \
  --presentation-response response.json \
  --challenge challenge.json \
  --capability-policy examples/policies/federated-child.yaml \
  --delegation-policy delegation-policy.json \
  --upstream-capability-id cap-upstream
```

What this does:

- the delegation policy narrows and signs what may continue downstream
- `--upstream-capability-id` binds the child issuance to a real parent
- the trust service records a delegation anchor so lineage and receipts can
  explain where the child authority came from

For a fuller walkthrough of the federated inputs, see
[docs/AGENT_PASSPORT_GUIDE.md](../reference/AGENT_PASSPORT_GUIDE.md).

## 8. Run The Framework Examples

With the demo stack still running, the framework examples all target the same
defaults:

- [examples/anthropic-sdk/README.md](../../examples/anthropic-sdk/README.md)
- [examples/langchain/README.md](../../examples/langchain/README.md)
- [examples/openai-compatible/README.md](../../examples/openai-compatible/README.md)

They all:

- initialize a hosted Chio session
- list tools through the official Chio SDK
- perform a governed `echo_text` call
- resolve the resulting receipt through the trust service

That is the stable baseline for integrating Chio into higher-level agent
frameworks.
