# Lane C - End-to-End Demo Architecture

This document maps the Chiodome v0.1 cross-org refund demo onto the
existing Chio crates. Every box is an existing crate or an existing
function unless explicitly marked NEW.

## End-to-end flow

```
                  +-----------------------+
                  |   Org A user / agent  |
                  +-----------+-----------+
                              |
                              | tools/call("refund.execute", { amount_minor: 5000, ... })
                              v
                  +-----------+-----------+
                  | chio mcp serve --policy
                  |   (Org A wrapped MCP edge)
                  |   chio-cli/cli/types.rs:993 (Mcp::Serve)
                  |   chio-mcp-adapter
                  +-----------+-----------+
                              |
                              | dispatch_tool_call_with_cost (async)  <-- release work-B0.x
                              v
                  +-----------+-----------+
                  |    Kernel A           |
                  |    chio-kernel        |
                  | (verify_capability_full
                  |  on the hot path)     |  <-- release work-B1.x
                  +-----------+-----------+
                              |
                              | issue local v2 receipt (artifact #1)  <-- release work-B2.x
                              | route across federation peer
                              v
                  +-----------+-----------+
                  |  chio-federation       |
                  |   trust_establishment  |
                  |   FederationPeer pin   |
                  +-----------+-----------+
                              |
                              | bilateral cosign request
                              v
                  +-----------+-----------+
                  |    Kernel B           |
                  |    chio-kernel        |
                  | (verify_capability_full|
                  |  on the hot path)     |  <-- release work-B1.x
                  +-----------+-----------+
                              |
                              | execute refund tool (KB MCP-backed)
                              | issue local v2 receipt (artifact #2)  <-- release work-B2.x
                              v
                  +-----------+-----------+
                  | DualSignedReceipt      |
                  |   chio-federation/     |
                  |   bilateral.rs:93      |
                  | (rewired by Lane B B4  |
                  |  to verify against     |
                  |  spec §6 DSSE PAE)     |
                  +-----------+-----------+
                              |
                              | DSSE Statement (artifacts #3 + #4 emitted as one envelope)
                              v
                  +-----------+-----------+
                  | bilateral_dsse         |
                  | (Lane B B4 owns module |
                  |  + envelope/PAE types) |
                  | chio.bilateral-cosign- |
                  | invocation.v1 envelope |
                  | spec §6 PAE            |
                  | (Lane C extends with   |
                  |  predicate helper +    |
                  |  §7 partial local verifier subset)  |
                  +-----------+-----------+
                              |
                              | feed receipt body to anchor batch
                              v
                  +-----------+-----------+
                  | chio-anchor            |
                  | Web3CheckpointStatement|
                  |   lib.rs:138           |
                  | build_anchor_inclusion_|
                  |   proof lib.rs:178     |
                  | (ASYNC ONLY when       |
                  |  public-witness req.)  |  <-- release work-B3.x
                  +-----------+-----------+
                              |
                              | settle batch
                              v
                  +-----------+-----------+
                  | chio-settle            |
                  | LocalDevnetDeployment  |
                  |   config.rs:393        |
                  | + evm.rs               |
                  | (NO live web3)         |
                  +-----------+-----------+
                              |
                              | inclusion proof (artifact #5)
                              v
                  +-----------+-----------+
                  |  fixtures/             |
                  | examples/chiodome-     |
                  | bilateral/fixtures/    |
                  +-----------+-----------+
                              |
                              | optional auditor view (bbs-stub feature only)
                              v
                  +-----------+-----------+
                  | chio-federation (NEW) |
                  | bbs-2023 / bls12-381   |
                  | spec §6.1 + §6.2       |
                  | projection             |
                  | spec §8 envelope       |
                  | (artifact #6)          |
                  +-----------+-----------+
                              |
                              v
                  +-----------+-----------+
                  | chio receipt explain   |
                  | chio-cli types.rs:2660 |
                  | trust_commands.rs:2629 |
                  | walks the chain        |
                  +-----------------------+
```

## Crates touched

The following table enumerates every crate the demo touches, the role it
plays, and whether the demo introduces new code in it.

| Crate | Role | New code? |
|---|---|---|
| `chio-kernel` | Kernel A and Kernel B; v2 receipt issuance; capability verification | No - consumes Lane B B0/B1/B2/B3 enforcement |
| `chio-federation` | Trust handshake; bilateral cosigning; DSSE envelope | Lane B B4 introduces `bilateral_dsse.rs` (envelope, signing, PAE); Lane C extends with `predicate_from_kernel_state` helper, `CapabilityVerifier` trait, and `verify_envelope` partial local verifier subset |
| `chio-credit` | `CreditBondArtifact` minting for `capability_lease_ref` | No - consumes existing schema |
| `chio-anchor` | `Web3CheckpointStatement` + inclusion proof | No - consumes existing functions; Lane B B3 enforces async-only |
| `chio-settle` | `LocalDevnetDeployment` for the on-chain leg | No - consumes existing config |
| `chio-mcp-adapter` | `chio mcp serve --policy` proxy to KB MCP via `mcp-remote` stdio bridge | No - consumes existing adapter |
| `chio-cli` | `Mcp::Serve` and `Receipt::Explain` commands | Yes - extended explain path; new snapshot tests |
| C5 selective disclosure | Future work outside current closure | No current implementation; `c5-selective-disclosure-status.toml` records v0.2 deferral for compatibility |
| `chio-conformance` | Lane B-owned negative conformance fixtures | No - Lane B owns this; Lane C cites it |
| `examples/chiodome-bilateral` | The demo example crate | Yes - NEW example crate |

**New code surface, total:**

- The `bilateral_dsse.rs` module is owned by Lane B B4 (envelope,
  signing, PAE function). Lane C adds a Lane-C-side predicate helper
  and the §7 verifier inside the same module (or as a sibling
  module if the file grows).
- No current C5 workspace member or feature is claimed in this branch.
  Selective disclosure is deferred to v0.2 unless a future branch adds the
  implementation and fixture evidence required by the gate.
- One new example crate (`examples/chiodome-bilateral`) including
  an example-local minimal `chiodos-ladder` primitive (review finding 5a).
- One snapshot-test file in `chio-cli/tests/`.
- A handful of doc updates and CI workflow files.

That is the entire production-source impact of Lane C. The signing
hot path itself is Lane B B4's responsibility; Lane C's role is to
drive the demo orchestrator and ship the §7 verifier.

## Data flow detail

### Receipt v1/v2 path (artifacts #1 and #2)

Each kernel emits a v2 receipt for its side of the call. Per
`crates/chio-kernel/src/kernel/mod.rs:1574-1591`
(`kernel_receipt_version_for_remote`) the legacy path warns and
downgrades to v1; Lane B `release work-B2.x` replaces this with a hard
reject when negotiation is v2. Lane C asserts the demo runs in
v2-only mode.

Receipts are persisted via the receipt sink wired in release work-C3.3 to
`examples/chiodome-bilateral/fixtures/receipts/<id>.json`.

### Predicate body and DualSignedReceipt (artifact #3)

After Lane B B4 lands, the in-toto Statement carrying the §5
predicate body IS the cross-org signing surface. The legacy
`CoSigningBody` type at `crates/chio-federation/src/bilateral.rs:41`
is retained as a fixture-only signer (used by B4's negative
conformance test to prove the production verifier rejects legacy
preimages) and as the historical wire body of
`DualSignedReceipt::body` (which B4 re-anchors so its `verify`
method validates against PAE bytes of the Statement).

The artefact #3 captured into demo fixtures is the `DualSignedReceipt`
shape (kept for backward compatibility with `chio receipt explain`
chain walking). Its signatures and verification path are spec-§6
conformant after B4 because the underlying signing scheme has been
rebaked.

### DSSE Statement (artifact #4)

The `bilateral_dsse.rs` module (introduced by Lane B B4; extended
by Lane C release work-C2.x with the verifier and predicate helper) wraps
the cross-org cosign in the in-toto Statement / DSSE envelope
shape from `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` section 6.

The mapping:

| Spec §5 predicate field | Source |
|---|---|
| `invocation_id` | UUIDv4 from kernel B; or canonical-JSON SHA-256 of the underlying receipt body |
| `tool_server_a` | from `FederationPeer` pin |
| `tool_server_b` | from `FederationPeer` pin |
| `tool_name` | `refund.execute` |
| `tool_args_hash.value` | SHA-256 of canonical-JSON tool args |
| `capability_lease_ref` | from the minted `CreditBondArtifact` |
| `policy_evaluation_summary.server_a_verdict` | Kernel A's policy verdict |
| `policy_evaluation_summary.server_b_verdict` | Kernel B's policy verdict |
| `governance_receipt_ref` | the workflow receipt id (mode `receipt_backed`) |
| `consistency_model` | `totally-ordered` |
| `consistency_anchor` | `chio-anchor` |
| `cross_org_visibility` | `treaty_only` (per CHIODOS_LADDER §5.2) |
| `co_sign` | `bilateral_required` |
| `timestamp_unix_ms` | Kernel B wall-clock at canonicalisation |

`subject[0].digest.sha256` is the SHA-256 of the canonical-JSON
`ChioReceipt` body that both kernels signed. Spec section 7 step 7
requires this to be re-derivable; the demo persists the receipt body
to `fixtures/receipts/` so it is always resolvable.

### Anchor inclusion proof (artifact #5)

`crates/chio-anchor/src/lib.rs:178` `build_anchor_inclusion_proof`
takes the receipt + checkpoint + chain anchor and returns an
`AnchorInclusionProof`. The demo runs against
`LocalDevnetDeployment` (no live RPC).

For the spec section 7 step 16 reconciliation, the demo's
`consistency_anchor = "chio-anchor"` and the verifier resolves the
inclusion proof from the same fixture directory.

Lane B's anchor-batch async-only enforcement is what makes this real:
without it, the demo could be silently using the sync path and the
"public witness" claim is false.

### Selective disclosure envelope (C5 deferred)

C5 is deferred to v0.2 outside current closure. The current architecture does
not claim that `crates/chio-federation` emits a selective-disclosure envelope, does not
claim a `bbs-stub` feature, and does not claim auditor-view proof fixtures.

The normative spec currently points to a `chio-zk-receipts` crate behind a
default-off `zk` feature. A future C5 implementation must either follow that
shape or land a protocol-owner-approved spec update before changing the
machine-readable marker to evidence-complete.

## Lane B primitives the demo MUST exercise

The demo is the canary for three Lane B enforcements. If any one is
missing or silently bypassed, the demo's correctness claim collapses
in a specific, observable way:

1. **Capability v2 single-entry verifier** (Lane B item:
   single-entry `verify_capability_full`).
   Demo exercise: spec section 7 step 14 re-runs lease expiry; the
   adversarial fixture intentionally sets `expires_at` to a value
   already past the pinned epoch; verification MUST emit
   `capability.lease_expired_or_unknown`. If `verify_capability_full_without_budget_admit`
   is still callable, the kernel may admit a stale lease and the
   adversarial fixture passes (which is the failure mode).

2. **Receipt v2 fail-closed** (Lane B `release work-B2.x`: hard-reject
   downgrade at `chio-kernel/src/kernel/mod.rs:1574-1591`,
   `kernel_receipt_version_for_remote`). Demo exercise: both
   kernels negotiate `chio.capability.v2`; the adversarial fixture
   pretends to negotiate v2 then sends a v1 body. The kernel MUST
   refuse. The demo asserts the refusal is observable at the call
   site, not buried in a warn log.

3. **Anchor-batch async-only when public witness required** (Lane B
   item: gate `crates/chio-anchor/src/batch.rs:208-258`). Demo
   exercise: with `require_public_witness=true`, the sync path MUST
   be uncallable. The demo's anchor leg sets the flag and verifies
   the async path is taken; the negative conformance fixture in
   `crates/chio-conformance/tests/` removes the gate and the demo
   smoke fails.

The cross-link is:

```
Lane B negative conformance fixture <==> Lane C smoke step
- conformance/tests/capability_v2_negative.rs <==> demo/scenario "stale lease"
- conformance/tests/receipt_v2_negative.rs    <==> demo/scenario "v2-then-v1 attack"
- conformance/tests/anchor_witness_negative.rs <==> demo/scenario "anchor under witness"
```

If Lane B removes any of these enforcements, the corresponding demo
scenario fails to produce its expected error code, and the smoke job
goes red. That is the forcing function.

## Boundaries (what is NOT in the diagram)

- No `OR` / negation in the auditor predicate. Spec §7.3 freezes
  v0.1 at AND-only.
- No three-vendor topology. The demo is two kernels.
- No live web3 RPC. `LocalDevnetDeployment` only.
- No transparency-log artefact. Bounded-claim discipline.
- No ladder-amendment in flight. Pinned at handshake.
- No cross-trust pheromone gossip. Out of scope per Vision Strategist.
- No new chiodos primitive beyond what the demo consumes. Synthesis
  forbids new normative drafts.
