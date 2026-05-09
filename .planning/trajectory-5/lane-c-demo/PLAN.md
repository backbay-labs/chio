# Lane C Demo - Sub-Lane Plan

This document decomposes Lane C into six sub-lanes (C1..C6). Each sub-lane
has scope, acceptance, evidence, dependency on Lanes A/B, and a week
range. Tickets implementing each sub-lane are in planning docs.

The single guiding principle from `00-SYNTHESIS.md` lines 173-175:
the demo composes existing primitives. New code is rare, narrow, and
named. Where future code appears, it must be bounded by an existing spec
section and an existing crate's API surface. This planning branch does not
itself create a release claim.

---

## C1. Demo architecture and scenario script

### Scope

- One scenario: cross-org `refund.execute` per
  `debate/06-vision-strategist-chiodome.md` section 2.
- Two `chio-federation` peers (Org A, Org B) bound by
  `crates/chio-federation/src/trust_establishment.rs`
  (`FEDERATION_HANDSHAKE_SCHEMA`, `FederationPeer`).
- Action class: `refund.execute` (analogue of
  `spec/CHIODOS_LADDER.md` section 5.2 `settle.rollback`,
  `mode = receipt_backed`, `consistency_model = totally-ordered`,
  `consistency_anchor = chio-anchor`, `co_sign = bilateral_required`).
  No new spec section; uses the existing financial ladder.
- Pinned ladder intersection: domain `financial`, exactly one action
  class, no amendment lifecycle (`spec/CHIODOS_LADDER.md` section 8
  is out of scope per Vision Strategist concession).
- Two-kernel topology: in-process by default
  (`InProcessCoSigner` at `crates/chio-federation/src/bilateral.rs:216`).
  Optional split-process via mTLS-backed transport stub deferred to C6
  unless trivially included.
- `examples/chiodome-bilateral/` is the Cargo crate that runs the
  scenario; one binary, one `smoke.sh`, one `README.md`.

### Acceptance

- `examples/chiodome-bilateral/orchestrate.rs` constructs both kernels,
  runs the handshake, pins the ladder intersection artefact (in
  memory; written to fixtures), and executes one refund.
- The fixtures directory is empty after scenario reset and populated
  with the five current artifacts after a successful run. C5 selective
  disclosure is not one of those artifacts and stays outside current closure.
- Reviewer can read the scenario in `examples/chiodome-bilateral/README.md`
  and reproduce it with `./smoke.sh` from a clean checkout.

### Evidence

- `examples/chiodome-bilateral/fixtures/handshake/` containing the
  signed `FederationKernelHandshake` from each side.
- `examples/chiodome-bilateral/fixtures/ladder-intersection.json` -
  the co-pinned intersection per
  `spec/CHIODOS_LADDER.md` section 6.1 `chio.chiodos-ladder-intersection.v1`.
- Smoke run logged to `examples/chiodome-bilateral/fixtures/run.log`.

### Lane A/B dependencies

- Depends on `verify_capability_full` (Lane B `release work-B1.x`). C1 builds
  against the current verifier signature; if Lane B's surgery lands
  first the example just compiles.
- Depends on Lane B's `ToolServerConnection` -> `async_trait`
  migration (`release work-B0.5`) so the refund tool can register normally
  on both kernels without manual sync-wrapping at the example layer.

### Week range

Per R1 §6.2 §10 and review finding 10, Lane C scaffolding (C1.1, C1.2,
C1.4) starts in W3 alongside in-progress Lane B work so the
forcing-function smoke runs continuously against Lane B partial
enforcement; full demo (C2-C6) waits for Lane B B0/B1/B2/B3/B4 to
land. W3 start, full close W4-W5.

---

## C2. Bilateral cosigned invocation flow (consumes Lane B B4)

### Scope

**Wave 3 rework (review finding 1):** the W1 plan's Option-A
two-signature design was rejected. The DSSE-conformant signing
primitive (envelope, PAE, signing surface) is now Lane B sub-lane
B4 (`lane-b-wiring/dsse-bilateral-signing.md`,
`bilateral DSSE signing item-B4.6` plus `bilateral DSSE signing item` Evidence Gate close).
Lane C C2 simplifies from "ship a
two-signature adapter" to "consume B4 and ship the §7 verifier".

- Lane B B4 owns `crates/chio-federation/src/bilateral_dsse.rs`
  which provides:
  - `BilateralCoSignInvocationStatement` struct serialising to the
    in-toto Statement shape with
    `predicateType = "chio.bilateral-cosign-invocation.v1"` (not the
    proposed in-toto URI; spec section 3 mandates the chio-namespaced
    fallback until WG acceptance).
  - `DsseEnvelope` plus the PAE function and signing helpers.
  - The kernel-side cross-org dispatch hot path that emits the
    envelope as the production signing surface.
- Lane C C2 EXTENDS the same module with:
  - `predicate_from_kernel_state` helper for demo orchestration.
  - `CapabilityVerifier` trait + `ReceiptStore` re-export so the §7
    verifier does not pull in `chio-kernel` directly (architecture
    cut option B in `bilateral-cosign-flow.md`).
  - `verify_envelope(envelope, peer_pin_set, pinned_epoch)` that
    runs verification algorithm steps 1-17 from
    `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` section 7.
  - Error type extensions for the spec section 7.1 codes (e.g.
    `PredicateSchemaInvalid`, `SubjectDigestMismatch`,
    `CapabilityLeaseExpiredOrUnknown`).
- `chio-credit` `CREDIT_BOND_ARTIFACT_SCHEMA`
  (`crates/chio-credit/src/lib.rs:32`) is wired in: the demo mints a
  budget bond, the bond's `bond_id` becomes the predicate's
  `capability_lease_ref.lease_id`, and `expires_at` populates
  `capability_lease_ref.expires_at_unix_ms`.

### Acceptance

- Round-trip: produce envelope -> verify envelope -> implemented verifier subset
  pass against happy-path fixture.
- Negative conformance: each spec section 7.1 error code is exercised
  in `crates/chio-federation/tests/bilateral_dsse_negative.rs` (16
  tests, one per error code).
- Demo emits `chio.bilateral-cosign-invocation.v1` envelope as
  artifact #4 in the six-artifact list.

### Evidence

- `examples/chiodome-bilateral/fixtures/bilateral-cosign-invocation.json`
  - the DSSE envelope.
- `examples/chiodome-bilateral/fixtures/credit-bond.json` - the
  `CreditBondArtifact` referenced via `lease_id`.
- Negative-test files committed under `crates/chio-federation/tests/`.

### Lane A/B dependencies

- Hard dep on Lane B `bilateral DSSE signing item` (DSSE-conformant signing surface;
  the gating B4 negative conformance fixture, analogous to the
  B1.6/B2.5/B3.5 gating pattern).
- Hard dep on Lane B `release work-B1.6` (lease-expiry enforcement; the §7
  verifier step 14 only fails closed if the capability path
  enforces).
- Hard dep on Lane B `release work-B2.5` (receipt v2 fail-closed; §7 step 7
  subject digest depends on a real v2 body).
- Hard dep on Lane B `release work-B3.5` (anchor-batch async-only; §7 step 16).

### Week range

W4-W5 (after Lane B B0/B1/B2/B3/B4 close).

---

## C3. KB MCP integration via `chio mcp serve` over `mcp-remote`

### Scope

- The user-facing surface for the demo is `chio mcp serve --policy`
  per `crates/chio-cli/src/cli/types.rs:993` wrapping the
  `mcp-remote` stdio bridge (per
  `ops/knowledge-base/README.md:136-151`) which proxies to the HTTP
  KB MCP at `:8111/mcp/` (review finding 2). `chio mcp serve` itself
  only wraps stdio MCP servers; the bridge is what bridges to HTTP.
- One HushSpec-shaped policy YAML at
  `examples/chiodome-bilateral/policies/refund-policy.yaml`
  (matches `examples/policies/canonical-hushspec.yaml` family).
  The amount cap lives in the example-local chiodos-ladder
  intersection (per review finding 5b option a, `partition_fallback.blast_radius_cap`),
  not in the policy YAML.
- Each KB MCP tool call emits a `ChioReceipt` v2 through the kernel's
  hot path (Lane B's enforcement is what makes this real, not
  optional). Receipts persist to
  `examples/chiodome-bilateral/fixtures/receipts/`.
- Cross-org call: Org A's `chio mcp serve` instance forwards the
  refund call to Org B's instance; Org B executes against its KB MCP
  stand-in (or the real KB MCP if the demo uses a KB-resident refund
  tool name); the bilateral cosign envelope wraps the result.

### Acceptance

- `chio mcp serve --policy examples/chiodome-bilateral/policies/refund-policy.yaml
  -- npx -y mcp-remote http://localhost:8111/mcp/`
  starts cleanly and proxies to the local KB MCP.
- A `refund.execute` call against the proxied stack returns a v2
  receipt and a co-signed envelope.
- Smoke script asserts the over-cap refund (`amount_minor = 100000`)
  is rejected by the example-local chiodos-ladder intersection,
  producing a deny verdict in the bilateral envelope's
  `policy_evaluation_summary.server_b_verdict.verdict`. The §7
  verifier surfaces `joint_disposition = deny`.

### Evidence

- `examples/chiodome-bilateral/fixtures/policy-deny.json` - a denied
  refund's receipt with the explicit verdict + reason.
- `examples/chiodome-bilateral/fixtures/receipts/<id>.json` per call.

### Lane A/B dependencies

- Hard dep on Lane B's receipt-v2 fail-closed behavior: if the kernel
  silently downgrades, the bilateral envelope's
  `subject.digest.sha256` test fails non-deterministically.
- Soft dep on Lane A: KB-MCP receipts surfaced into the bounded
  release rely on the threat-coverage and mutation-kill banner having
  real numbers.

### Week range

W2-W3.

---

## C4. Receipt explain UX

### Scope

- `chio receipt explain` (`crates/chio-cli/src/cli/types.rs:2660`,
  `crates/chio-cli/src/cli/trust_commands.rs:2629`) is taught to walk
  the bilateral chain end-to-end:
  - Parent receipts (kernel A's local v2 + kernel B's local v2)
  - The `DualSignedReceipt`
  - The DSSE bilateral envelope (decoded; lists tool_server_a/b,
    co_sign mode, joint_disposition)
  - The anchor inclusion proof (`build_anchor_inclusion_proof` at
    `crates/chio-anchor/src/lib.rs:178`)
- Documentation page at `docs/guides/EXPLAIN_A_DENIAL.md` is updated
  (or written) to walk a denied refund: the policy verdict
  disagreement (`policy.verdict_disagreement`) shows in the explain
  output; the operator can trace which side denied.
- Closes `audits/T1.6-chio-explain.md` reopened row from trj4 by
  attaching the demo's denied-receipt fixture as the canonical
  example.

### Acceptance

- `chio receipt explain <happy-path-receipt-id>
  --input-file examples/chiodome-bilateral/fixtures/receipts/<id>.json`
  prints the joined view (parent IDs, anchor inclusion summary,
  bilateral envelope summary).
- Same command on the deny fixture surfaces the denying kernel,
  policy ID, rationale code, and `repair_hint`.
- A snapshot test in `crates/chio-cli/tests/explain_bilateral.rs`
  pins the rendered output.

### Evidence

- `docs/guides/EXPLAIN_A_DENIAL.md` includes a copy-pasteable example
  block citing the demo fixture filenames.
- T1.6 audit row references this doc.

### Lane A/B dependencies

- Soft dep on Lane B (the explain output's signature_ok line is only
  meaningful when the receipt is real; Lane B's enforcement is what
  ensures the receipt was produced through the hot path).

### Week range

W3.

---

## C5. Selective disclosure auditor view (future work outside closure)

### Scope

- C5 is deferred to v0.2 in this branch. The current canary plan does not
  implement, ship, claim, or close a selective-disclosure auditor view.
- The normative spec currently names `crates/chio-zk-receipts/` behind a
  default-off `zk` feature. This branch does not provide that crate or feature.
- `crates/chio-federation/` exists as a federation crate, but its current
  `Cargo.toml` does not define `bbs-stub` and does not assemble BBS+/AnonCreds
  dependencies.
- The machine-readable boundary is
  `.planning/trajectory-5/lane-c-demo/c5-selective-disclosure-status.toml`.
  Deferred status may still appear as PARTIAL under the legacy checker, but that
  compatibility output is not a current closure row.

### Acceptance

- `scripts/check-bounded-ship-bar.sh` may report C5 as PARTIAL while the marker
  records `status = "deferred_to_v0_2"` until Worker A updates checker behavior.
- If a future branch changes C5 to `evidence_complete`, the gate fails unless
  the implementation crate, feature, proof fixture, negative fixture, and
  `release_claim_allowed = "yes"` are all present.
- Release-facing docs carry no product, zk, BBS+, BBS, or proof claim for C5
  while the marker is deferred.

### Evidence

- `.planning/trajectory-5/lane-c-demo/c5-selective-disclosure-status.toml`
  records the current deferral for compatibility.
- Future C5 evidence is outside the current closure contract.

### Lane A/B dependencies

- None for the current canary because C5 is deferred. A future C5 branch needs
  protocol-owner coordination if it diverges from the spec's `chio-zk-receipts`
  and `zk` feature naming.

### Week range

W4.

---

## C6. v0.1.0-bounded-chiodome packaging boundary

### Scope

- This branch does not tag, publish release notes, require a CI check, produce a
  signed tarball, or update root release audit truth.
- `release-bar.md` is a release-truth boundary for future release editing, not
  a GitHub release body.
- #618 packaging remains last and must regenerate any release artifacts from
  merged `main` after Lane B, regenerated Lane A evidence, and Lane C canary
  evidence are settled. C5 status is not a packaging precondition for the
  current five-artifact canary.

### Acceptance

- No release claim is made by #620.
- Future packaging remains blocked until the assurance checker sees complete
  canary evidence and package metadata from merged source.

### Evidence

- `release-bar.md` records the current non-claim boundary.
- `scripts/check-bounded-ship-bar.sh` reports the current evidence state under
  its legacy compatibility name.

### Lane A/B dependencies

- Hard dep on Lane B's negative conformance fixtures being
  green before any future package claim. If they are red, the package claim is
  not bounded.
- Hard dep on Lane A's mutation banner reading the real number; the
  bounded-claim language in `release-bar.md` quotes the banner
  verbatim.

### Week range

W4.

---

## Cross-cutting

### Effort summary

| Sub-lane | Effort | Risk |
|---|---|---|
| C1 architecture | M+L (4 tickets, includes new chiodos-ladder primitive) | Medium (review finding 5a: ladder primitive is new code) |
| C2 cosign | L+L (6 tickets; consumes Lane B B4 for signing surface) | Medium (depends on B4 close; verifier work + architecture cut) |
| C3 KB MCP | M+L (4 tickets; uses mcp-remote stdio bridge) | Low-Medium (review finding 2 resolved via bridge; HushSpec YAML simpler than fictional schema) |
| C4 receipt explain | L+S (2 tickets; bumped per review finding 9) | Low (extends existing explain function; bilateral chain walk is the new work) |
| C5 selective-disclosure boundary | Future work outside current closure | Deferred to v0.2 unless real implementation and fixtures land |
| C6 packaging boundary | XS now; future release owner scope | Blocked until integrated evidence exists |

### Forcing-function gates between Lanes

Lane C scaffolding (C1.1, C1.2, C1.4) starts in W3 alongside
in-progress Lane B work (R1 §6.2). Continuous CI workflow
`chiodome-demo-continuous.yml` (release work-C6.3, review finding 10) runs the
smoke nightly on `main` and on every push to Lane B paths so
partial-enforcement bugs surface continuously, not at the worst
possible time. Lane C will not package at C6 if Lane B's four negative
conformance fixtures (B1.6, B2.5, B3.5, B4.x) are not green or if
the continuous workflow has not been green for 7 consecutive
nights.

### What we don't do

- Refactor `chio-kernel/src/kernel/mod.rs` beyond what Lane B does
  for `ToolServerConnection`. Out of scope per `00-SYNTHESIS.md`
  lines 96-100.
- Add a transparency log. Bounded-claim discipline says no.
- Promote v2.71 Web3 live activation. Bounded-claim discipline says
  no; spec already pins the demo to `LocalDevnetDeployment`.
- Add OR / negation / nested predicates to selective disclosure;
  spec section 7.3 freezes v0.1 at AND-only with eight-clause
  ceiling.
- Wrap the KB MCP HTTP server directly. `chio mcp serve` is
  stdio-only; the demo uses `mcp-remote` as the bridge.
- Bolt a second signature on `DualSignedReceipt` to pretend §6
  conformance. Lane B B4 is the structural fix; Lane C consumes
  the spec-conformant signing surface that B4 produces.
