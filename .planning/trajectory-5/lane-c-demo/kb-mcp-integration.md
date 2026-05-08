# KB MCP Integration via `chio mcp serve` and `mcp-remote`

This document specifies how the demo wraps the local Chio Knowledge
Base MCP gateway (HTTP at `http://localhost:8111/mcp/`, per
`ops/knowledge-base/README.md` line 11) using `chio mcp serve
--policy` (per `crates/chio-cli/src/cli/types.rs:993`).

**Wave 3 rework (review finding 2):** the original Wave 1 plan tried
to invoke `chio mcp serve --policy ... -- chio-kb-mcp` as if the KB
MCP exposed a stdio MCP server binary. It does not. The KB MCP is
HTTP-only at `:8111/mcp/`. `chio mcp serve` is a stdio wrapper
(`crates/chio-cli/src/cli/types.rs:1032-1034`, `command: Vec<String>`
with `trailing_var_arg = true`). Resolution path: use `mcp-remote`
as the stdio<->HTTP bridge.

`ops/knowledge-base/README.md:136-151` already canonicalizes this
pattern for Claude Desktop:

```json
{ "command": "npx", "args": ["mcp-remote", "http://localhost:8111/mcp/"] }
```

The demo composes the same shape under `chio mcp serve`:

```sh
chio mcp serve --policy examples/chiodome-bilateral/policies/refund-policy.yaml \
  -- npx -y mcp-remote http://localhost:8111/mcp/
```

The bounded claim narrows accordingly: this composition validates
`chio mcp serve` plus the `mcp-remote` stdio bridge, NOT direct
HTTP MCP wrapping by `chio mcp serve` itself. Direct HTTP-upstream
wrapping is out of scope for release work; v0.2 may add it.

The KB MCP stack is the productization layup the Productization
Champion called out in `debate/05-productization-sdk-champion.md`
section 1.5. Lane C consumes it as the demo's user-facing surface so
that every receipt the demo emits is a receipt the project's own
internal agents could plausibly produce in the future.

## What `chio mcp serve --policy` already does

From `crates/chio-cli/src/cli/types.rs:993-1035`:

- Wraps a stdio MCP server subprocess.
- Gates each `tools/call` through the manifest scaffold and the
  configured policy (or the bundled `code-agent` preset).
- Exposes a secured MCP edge over stdio.

Existing presets:

- `code-agent` - safe-file-reads / `.env` deny / `.git/**` deny /
  `.ssh/**` deny / `git push --force` deny.

Lane C does NOT extend the preset list. It writes one bespoke policy
YAML for the refund scenario.

## Topology in the demo

Each kernel runs its own `chio mcp serve` instance. Each instance
wraps an `mcp-remote` stdio subprocess (`npx -y mcp-remote
http://localhost:8111/mcp/`) which itself proxies to the HTTP KB
MCP gateway. The two `chio mcp serve` instances are connected
through the federation handshake (Lane C C1).

```
+--------------------+        +--------------------+
| Org A's chio mcp   | <----> | Org B's chio mcp   |
|   serve --policy   | refund |   serve --policy   |
| (stdio interface)  |  call  | (stdio interface)  |
+---------+----------+        +---------+----------+
          |                             |
          | wraps                       | wraps
          v                             v
+--------------------+        +--------------------+
| npx mcp-remote     |        | npx mcp-remote     |
| (stdio<->HTTP)     |        | (stdio<->HTTP)     |
+---------+----------+        +---------+----------+
          |                             |
          v                             v
     Org A's kernel              Org B's kernel
     (chio-kernel)               (chio-kernel)
                                       |
                                       v
                        +---------------------------+
                        | KB MCP gateway (HTTP)     |
                        |   ops/knowledge-base/     |
                        |   :8111/mcp/              |
                        |   chio_kb tools           |
                        +---------------------------+
```

In the simplest configuration the demo runs both `chio mcp serve`
instances against the same KB MCP gateway (one stack); the
federation cosign happens at the kernel layer; the KB MCP is the
shared back-end the refund tool reads from. This keeps the demo to
one Docker stack.

For a more faithful two-org topology, Org B can run its own KB MCP
instance, but this is optional and out of scope for the W2-W3
deliverable; the bounded-claim language in `release-bar.md`
acknowledges the shared back-end.

**Pre-requisites for the smoke**: `npx` is available (Node.js 18+).
The `mcp-remote` package is fetched on demand by `npx -y` so no
explicit install is required, but air-gapped CI runners should
pre-warm the npm cache.

## Policy file shape

The Lane C demo uses the canonical Chio HushSpec policy format
(`examples/policies/canonical-hushspec.yaml` and the family of
`examples/policies/hushspec-*.yaml` files). The Wave 1 plan
proposed a non-HushSpec schema with keys like `version`,
`policy_id`, `default_decision`, `allow_rules`, and conditions
`amount_minor_max` / `co_sign_required` / `receipt_v2_required`.
That schema is fictional - none of those keys exist in
`crates/chio-policy`. review finding 5b rejected it.

The HushSpec-shaped policy at
`examples/chiodome-bilateral/policies/refund-policy.yaml`:

```yaml
hushspec: "0.1.0"
name: chiodome-bilateral-refund
description: |
  Lane C demo policy. Allows the synthetic `refund.execute` tool;
  denies KB MCP write tools as belt-and-braces. The amount cap is
  NOT enforced here (HushSpec does not have an amount cap
  primitive); it is enforced by the example-local
  chiodos-ladder intersection logic per
  `spec/CHIODOS_LADDER.md` §5.2 `partition_fallback.blast_radius_cap`,
  which is what the demo exercises in the over-cap deny scenario.

rules:
  tool_access:
    enabled: true
    default: block
    allow:
      - refund.execute
      - kb_search
      - kb_query
  forbidden_paths:
    enabled: true
    paths:
      - .env
      - .git/**
      - .ssh/**
```

The cap (25000 minor units, matching `CHIODOS_LADDER §5.2`) is
enforced by the example's chiodos-ladder pinned-intersection logic
in `examples/chiodome-bilateral/src/ladder.rs` (per review finding 5a).
The smoke's over-cap deny scenario fails the ladder intersection
check before reaching the kernel; the bilateral envelope's
`policy_evaluation_summary.server_b_verdict.verdict` carries
`deny` as a result.

This is option (a) from review finding 5b: the deny path is
ladder-driven, not policy-YAML-driven. The HushSpec policy YAML's
job is to gate which MCP tools the kernel will dispatch at all; the
amount cap and other ladder-shaped invariants live in
`ladder-intersection.json`.

## MCP tool registration

The KB MCP gateway exposes tools `kb_search`, `kb_query`,
`kb_add_episode`, etc. (per `ops/knowledge-base/README.md` lines
40-44). For the demo's refund flow we register one additional tool
on each kernel via `NativeChioServiceBuilder` (per
`docs/start-here/NATIVE_ADOPTION_GUIDE.md`):

- `refund.execute(amount_minor: u64, customer_id: string,
  reason: string) -> RefundOutcome` - registered on Org B's
  kernel; Org A's kernel only proxies the call.

`refund.execute` is a synthetic stub for the demo. Its
implementation:

- Accepts the args.
- Optionally calls `kb_search` against the KB MCP gateway to look
  up the customer record (this is the dogfooding step - the demo
  agent literally retrieves from the KB MCP, exercising the wrapped
  edge).
- Returns a synthetic outcome.

The `refund.execute` tool name and shape are constants in
`examples/chiodome-bilateral/src/refund_tool.rs`; the `chio mcp
serve --policy` allow rule above references this name verbatim.

## Receipt emission

Each `tools/call` produces one v2 `ChioReceipt`
(`crates/chio-core/src/receipt/v2.rs`). Lane B's enforcement is
what makes this real: with the warn-and-downgrade in place, a v2
negotiation could silently produce a v1 body and the bilateral
envelope's subject digest fails section 7 step 7.

Receipts are persisted via a custom sink wired in release work-C3.3:

```rust
// examples/chiodome-bilateral/src/receipt_sink.rs

pub struct FixtureReceiptSink {
    fixtures_dir: PathBuf,
}

impl ReceiptSink for FixtureReceiptSink {
    fn record(&self, receipt: &ChioReceiptV2) -> Result<(), SinkError> {
        let bytes = canonical_json_bytes(receipt)?;
        let path = self.fixtures_dir.join(format!("{}.json", receipt.receipt_id));
        std::fs::write(path, bytes)?;
        Ok(())
    }
}
```

Receipts written:

- One per `kb_search` call (the dogfooding step within
  `refund.execute`).
- One per `refund.execute` call (the outer tool call).
- Both kernels' receipts (Org A's local view, Org B's local view).

The bilateral envelope's `subject.digest.sha256` references Org B's
authoritative receipt body; Org A's receipt body is committed
separately for explain-time chain walking.

## The example's smoke flow

`examples/chiodome-bilateral/smoke.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# 0. Ensure KB MCP stack is up (operator's responsibility, but smoke
#    can fail closed if the port is not listening).
nc -z 127.0.0.1 8111 || {
    echo "KB MCP not running. Run: make kb-up"
    exit 2
}

# 1. Reset fixtures.
rm -rf fixtures/{handshake,receipts,auditor-view}
mkdir -p fixtures/handshake fixtures/receipts fixtures/auditor-view

# 2. Run the orchestrator binary.
cargo run -p chiodome-bilateral -- \
    --policy policies/refund-policy.yaml \
    --kb-mcp-url http://localhost:8111/mcp/ \
    --fixtures-dir fixtures \
    --scenario happy-path

# 3. Run the deny scenario.
cargo run -p chiodome-bilateral -- \
    --policy policies/refund-policy.yaml \
    --kb-mcp-url http://localhost:8111/mcp/ \
    --fixtures-dir fixtures \
    --scenario over-cap-deny

# 4. Verify the produced fixtures with chio receipt explain.
for receipt in fixtures/receipts/*.json; do
    chio receipt explain "fixture" --input-file "$receipt" \
        --depth 8 --fanout-limit 32 > /dev/null
done

# 5. Verify bilateral envelope.
chio receipt explain "fixture" \
    --input-file fixtures/bilateral-cosign-invocation.json > /dev/null

# 6. Optional selective-disclosure auditor view (only if compiled with --features bbs-stub).
if cargo run -p chiodome-bilateral --features bbs-stub -- --print-selective-disclosure-status \
   2>/dev/null | grep -q enabled; then
    cargo run -p chiodome-bilateral --features bbs-stub -- \
        --policy policies/refund-policy.yaml \
        --fixtures-dir fixtures \
        --scenario auditor-view
fi

echo "smoke OK"
```

The smoke is the artifact CI runs. If Lane B regresses any of the
three negative conformance fixtures, the smoke goes red because the
expected receipt v2 / lease / anchor invariants no longer hold.

## Where the example lives

`examples/chiodome-bilateral/` (proposed) joins the existing
flagship examples (`agent-commerce-network`,
`internet-of-agents-incident-network`,
`internet-of-agents-web3-network`). It is referenced from
`examples/EXAMPLE_SURFACE_MATRIX.md` as

> Flagship: `trust serve`, MCP edge, bilateral cosign, anchor
> inclusion, selective disclosure (gated). Demonstrates the
> Chiodome v0.1 cross-kernel refund slice end-to-end.

## Bounded-claim discipline (KB MCP integration)

What the KB MCP integration claims:

- The demo is a real `chio mcp serve --policy` invocation wrapping
  a real `mcp-remote` stdio bridge that proxies to the real HTTP
  MCP server at `ops/knowledge-base/` (`:8111/mcp/`).
- Each tool call emits a receipt produced by the production kernel
  hot path.
- The policy YAML is a real-shape Chio HushSpec policy file
  (matches the canonical `examples/policies/canonical-hushspec.yaml`
  family).

What the KB MCP integration does NOT claim:

- The demo does NOT validate direct HTTP-upstream MCP wrapping by
  `chio mcp serve`. It uses the `mcp-remote` stdio bridge as the
  shim. Direct HTTP wrapping is out of scope for v0.1.0.
- It is NOT a multi-tenant deployment. Both kernels run locally.
- It is NOT a benchmark of `chio mcp serve` performance under load.
  The demo runs serially, two-three calls per scenario.
- It is NOT a security audit of the KB MCP itself. The KB MCP is
  retrieval support; receipts are scoped to the wrapped edge.
- It is NOT a recommendation that production agents wrap the KB MCP
  in `chio mcp serve` as their daily workflow. It is a
  proof-of-composition.
- The amount cap for the refund scenario is NOT a HushSpec policy
  primitive. It lives in the example-local chiodos-ladder
  intersection logic. Verifiers reading the HushSpec YAML alone
  will not see the cap; the cap is in `ladder-intersection.json`.
