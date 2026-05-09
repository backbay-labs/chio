# Trajectory 5 - Lane C - One Forcing Demo

## What this lane is

Trj5 Lane C is a single end-to-end demo that composes the Chio primitives
that already exist in the tree into one cross-org transaction. From
`.planning/trajectory-5/debate/00-SYNTHESIS.md` lines 115-132, Lane C is:

> Two-kernel cross-org bilateral cosigned invocation using existing
> `crates/chio-federation/src/bilateral.rs` (`CoSigningBody`,
> `DualSignedReceipt`). Per `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md`
> section 6. ... Output: a `v0.1.0-bounded-chiodome` honest release tag
> under v3.18 bounded-claim discipline.

That quotation is historical synthesis input, not current release truth. The
current #620 branch records a canary plan and release boundary; it does not tag,
ship, or authorize `v0.1.0-bounded-chiodome`.

Concretely it is the slice the Vision Strategist named "Chiodome v0.1
Cross-Kernel Refund" (`debate/06-vision-strategist-chiodome.md` section 2):
two kernels, one cosigned invocation, one bonded settlement, one
selective-disclosure auditor view. That last phrase is historical strategy
input only; C5 selective disclosure is future work outside current closure.

## Why Lane C is the forcing function for Lanes A and B

Lane A (Realize the floor) and Lane B (Wire the spec hot path) are the
substrate hardening lanes. Lane C is the lane that proves they are
load-bearing. From `00-SYNTHESIS.md` lines 173-175:

> If Lane C breaks, Lanes A and B aren't real either.

The synthesis is explicit about which Lane B primitives the demo
**validates**. Every one of these is an enforcement that Lane B is
landing in the kernel hot path; the demo is the canary that proves the
enforcement is actually wired:

1. **Capability v2 single-entry verifier** - the bilateral invocation
   carries a `capability_lease_ref`
   (`spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` section 5,
   `capability_lease_ref` object). If `verify_capability_full` is not
   the only path on the kernel hot path, the demo cannot rely on
   `capability.lease_expired_or_unknown` failing closed when the lease
   is yanked mid-flight. Lane B item `verify_capability_full` becomes
   the only production path. Demo exercises the negative.
2. **Receipt v2 fail-closed under negotiated v2** - the dual-signed
   receipt body is the underlying `ChioReceipt`; Lane B `release work-B2.x`
   replaces the warn-and-downgrade at
   `crates/chio-kernel/src/kernel/mod.rs:1574-1591`
   (`kernel_receipt_version_for_remote`) with a hard reject. The
   demo presents two kernels both negotiated to receipt v2; if the
   kernel silently downgrades one side, the bilateral envelope's
   `subject.digest.sha256` test fails (spec section 7 step 7). Demo
   proves v2 negotiated => v2 emitted.
3. **Anchor-batch async-only when public witness required** - the
   demo's settlement step lands a `Web3CheckpointStatement`
   (`crates/chio-anchor/src/lib.rs:138`) under
   `consistency_model = "totally-ordered"`. Spec section 7 step 16
   requires `consistency_anchor in {"chio-anchor","hash-chain"}`
   and reconciliable. With `require_public_witness=true` the
   sync path at `crates/chio-anchor/src/batch.rs:208-258` is
   forbidden; Lane B gates this. Demo asserts the gate.

Lane A is independent: it is the floor work (mutation kill, threat
coverage, Kani harnesses, TLA+ rewrites, Lean refinement). Lane C does
not consume Lane A directly, but Lane A's evidence quality is what
makes the bounded canary credible. If the floor banner still reads 31%
kill, the bounded-claim language has to
acknowledge it (release-bar.md).

The forcing function relationship is therefore:

```
Lane B     ----enforces----> kernel hot path
Lane B     ----validated by-> Lane C demo
Lane A     ----back-fills----> evidence under the demo's release banner
```

If Lane C cannot compose the existing primitives end-to-end, then
either (a) the primitives never composed (and the project's
"governance ladder + selective disclosure + cross-kernel cosigning"
positioning is unfalsifiable), or (b) Lane B failed to enforce on the
hot path and a downgrade silently happened. Either is the same trj4
pattern repeating, dressed differently.

## Scope - one demo, one example crate, five current artifacts

The demo lives at `examples/chiodome-bilateral/` (proposed). One CLI
walk-through. For the same refund the planned example emits, in order:

1. The local kernel A receipt (v2)
2. The local kernel B receipt (v2)
3. The `DualSignedReceipt` (`crates/chio-federation/src/bilateral.rs:93`)
4. The `chio.bilateral-cosign-invocation.v1` DSSE Statement
   (`spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` section 6)
5. The `Web3CheckpointStatement` from `chio-anchor` plus inclusion proof

C5 selective disclosure is not part of the current canary artifact set. It is
future work outside the closure matrix.

The current branch does not claim those fixtures exist. When implemented, each
non-deferred artifact must be committed to `examples/chiodome-bilateral/fixtures/`
as canonical JSON produced by source, not hand-written as planning evidence.
Each must be inspectable through `chio receipt explain`
(`crates/chio-cli/src/cli/types.rs:2660`,
`trust_commands.rs:2629`). Each appears in a `chio mcp serve --policy`
log line when the demo runs through the `ops/knowledge-base/` MCP
gateway at `:8111/mcp/`.

## Out of scope (explicit, mirrors synthesis)

- New normative spec drafts. The DSSE adapter wraps existing
  `CoSigningBody` semantics; spec text already exists in
  `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md`.
- Web3 live activation. Demo runs against the
  `LocalDevnetDeployment` plus mock RPC
  (`crates/chio-settle/src/config.rs:393`). The bounded label says so.
- Three-vendor walk-through. That is `docs/research/CHIODOS_3VENDOR_FIXTURE.md`
  research; Lane C is two kernels.
- Pheromone deposits. Out of scope per
  `debate/06-vision-strategist-chiodome.md` section 5.
- Ladder amendment lifecycle (`spec/CHIODOS_LADDER.md` section 8).
  Handshake-pinned manifest only.
- Mock receipts. Receipts MUST be produced by the production kernel
  through its real call sites; fixtures are captured outputs, not
  hand-written templates.

## Dependencies on Lanes A and B

| Need | Lane | Item | Lane B ticket | Trj5 ref |
|---|---|---|---|---|
| `verify_capability_full` is the only hot-path verifier | B | Single-entry verifier | release work-B1.6 | synthesis lines 100-103 |
| Receipt v2 fails closed when negotiated | B | Receipt v2 hot path | release work-B2.5 | synthesis lines 104-107 |
| Anchor-batch async only when witness required | B | Anchor-batch enforcement | release work-B3.5 | synthesis lines 108-111 |
| `ToolServerConnection` -> `async_trait` | B | Architectural prerequisite | release work-B0.5 | synthesis lines 96-100 |
| DSSE-conformant bilateral signing | B | Sub-lane B4 (added W3 per review finding 1) | bilateral DSSE signing item | `lane-b-wiring/dsse-bilateral-signing.md` |
| Mutation kill banner credible | A | Realize the floor | n/a | synthesis lines 76-89 |
| Real threat-coverage evidence | A | `audits/evidence/threats/*.json` | n/a | synthesis lines 78-82 |

Lane C scaffolding (C1.1, C1.2, C1.4) starts in W3 alongside
in-progress Lane B work so the smoke runs continuously against
partial enforcement (R1 §6.2 §10, review finding 10). The full demo
canary remains blocked until the four Lane B negative conformance fixtures
(B1.6, B2.5, B3.5, B4.5) exist in
`crates/chio-conformance/tests/`. The continuous CI workflow
`chiodome-demo-continuous.yml` is what keeps the forcing-function
honest between W3 start and W4-W5 close.

## Week-by-week timeline (~4-5 weeks; 1 week buffer for B4 ladder slip)

The five-week target assumes a single engineer plus reviewer, with
Lane B's four primitives (B0/B1/B2/B3/B4) wired by W4. Lane C
scaffolding starts in W3 alongside in-progress Lane B work to
make the forcing-function continuous (R1 §6.2 §10, review finding 10).
If Lane B slips beyond W4, Lane C slips with it.

| Week | Sub-lane | Deliverable | Forcing function |
|---|---|---|---|
| W3 | C1 (architecture, scaffolding) | Demo flow doc + scenario script + fixture skeleton in `examples/chiodome-bilateral/`; trust-establishment handshake between two in-process kernels; example-local chiodos-ladder primitive; refund tool registration | Picks up Lane B's `verify_capability_full` signature and `ToolServerConnection` async migration; if either changes, C1 surfaces it immediately |
| W4 | C2 (cosign verifier) | Consume Lane B B4's `bilateral_dsse.rs` envelope; ship the §7 partial local verifier subset with the 16-case negative fixture set; capability lease binding via `chio-credit`; anchor inclusion proof emission; orchestrator wiring | Lane B B4's signing surface is exercised end-to-end; lease-expiration enforcement (B1) gets exercised under both happy and deny path; receipt-v2 fail-closed (B2) drives subject digest validity; anchor-batch async-only (B3) drives §7 step 16 |
| W4 | C3 (KB MCP) | `chio mcp serve --policy ... -- npx -y mcp-remote http://localhost:8111/mcp/` wraps the HTTP KB MCP via the stdio bridge; HushSpec policy YAML; receipts written to `examples/chiodome-bilateral/fixtures/` per call; cross-org refund + over-cap deny scenario | Validates Lane B's receipt-v2-on-the-hot-path enforcement (B2.5); validates the chiodos-ladder cap (over-cap deny) |
| W4 | C4 (receipt explain) | `chio receipt explain` walks the bilateral chain (parent -> step -> dual-signed -> envelope -> anchor); doc page; snapshot tests | T1.6 (`audits/T1.6-chio-explain.md`) reopened row in trj4 closes |
| W5 | C5 selective-disclosure boundary | Deferred to v0.2 outside current closure. Future work must follow `c5-selective-disclosure-status.toml` and the normative spec before any auditor-view proof claim. | Prevents product, zk, BBS+, BBS, or proof claims without evidence |
| W5 | C6 packaging boundary | #620 records release-truth boundaries only. Tagging, release notes, tarballs, and required checks belong to a later packaging owner after merged-source evidence exists. | Prevents planning docs from becoming release claims |

## Acceptance

Lane C canary assurance moves out of partial status when all of:

1. `examples/chiodome-bilateral/smoke.sh` returns 0 in CI on
   `make ci-demo`. The smoke runs the full bilateral path end-to-end,
   produces the five current artifacts. C5 is not one of those artifacts,
   and verifies them.
2. Each of the produced artifacts is committed under
   `examples/chiodome-bilateral/fixtures/<scenario>/` as canonical
   JSON produced by the production kernel. Receipts are NOT mocked.
   The CI workflow asserts that fixtures were regenerated by the
   smoke run in the same workflow execution (mtime check;
   release work-C6.2 acceptance).
3. `chio receipt explain` succeeds on every fixture, returns the
   expected `decision`, `parents`, and (for v2 receipts) the
   `signature_ok` flag, and surfaces `policy.verdict_disagreement`
   on the deny fixture.
4. `release-bar.md` remains a release-truth boundary, not release notes.
5. Lane B's four negative conformance fixtures (B1.6, B2.5, B3.5,
   B4.x) all reference the demo's `examples/chiodome-bilateral/`
   paths in their per-test fixtures, so removing the Lane B
   enforcement breaks Lane C's smoke as a second-order effect.
6. The continuous CI workflow `chiodome-demo-continuous.yml`
   (release work-C6.3) has been green for 7 consecutive nights before the
   canary can move out of partial status.

When all six are met on an integrated branch, the legacy-named
`SHIP-BAR-TRACKER.md` Claim C can move out of PARTIAL. Until then, it stays
PARTIAL with the missing condition called out in the per-week summary.

If condition 6 is not met, the demo is decoupled from the substrate
it is supposed to validate, and Lane C's forcing-function purpose
has been quietly defeated. That is the trj4 pattern; do not
recreate it.

## Files

- `PLAN.md` - sub-lanes C1..C6 with scope, acceptance, evidence, deps
- planning docs - concrete tickets `release work-C1.x..C6.x`
- `architecture.md` - end-to-end flow with crate map
- `bilateral-cosign-flow.md` - DSSE adapter design over `CoSigningBody`
- `kb-mcp-integration.md` - `chio mcp serve --policy` wrapping the
  local KB MCP stack
- `selective-disclosure.md` - C5 deferral and future evidence boundary
- `c5-selective-disclosure-status.toml` - machine-readable C5 status marker for
  legacy checker compatibility
- `release-bar.md` - release-truth boundary for future packaging
