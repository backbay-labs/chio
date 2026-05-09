# Lane C - Tickets

Concrete tickets `release work-C1.x..C6.x`. Each entry has title, scope, files
touched, effort (S/M/L), depends-on (cross-lane deps explicit),
acceptance.

Every ticket closes under the release work Evidence Gate trio (per
`.planning/trajectory-5/templates/EVIDENCE-GATE.md`): enforced call
site + spec MUST citation + signed negative conformance test that
fails when wiring is removed. Cross-lane dependencies cite literal
Lane B ticket IDs (`release work-B0.5`, `release work-B1.6`, `release work-B2.5`,
`release work-B3.5`, `bilateral DSSE signing item`), not aliases.

Acceptance for Lane C tickets follows the Lane B/C variant of the
TICKET-TEMPLATE (`templates/TICKET-TEMPLATE.md` §2.1): enforced call
site, spec MUST citation, negative conformance test path, audit-doc
evidence reference, banner update where applicable.

Effort: S = under 1 day; M = 1-3 days; L = 3-6 days.

Cross-lane dependencies (literal Lane B ticket IDs as of W3):

| Was alias | Maps to (Lane B ticket) | What it provides |
|---|---|---|
| `LB-CAP` | `release work-B1.6` | Single-entry capability verifier negative conformance fixture (gating artifact) |
| `LB-RV2` | `release work-B2.5` | Receipt-v2 fail-closed negative conformance fixture (gating artifact) |
| `LB-AB`  | `release work-B3.5` | Anchor-batch async-only negative conformance fixture (gating artifact) |
| `LB-AT`  | `release work-B0.5` | Dispatch-hop collapse (gating artifact for `async_trait` migration) |

Plus the new sub-lane added by review finding 1:

| Lane B ticket | What it provides |
|---|---|
| `bilateral DSSE signing item` | DSSE-conformant bilateral signing primitive (envelope, PAE, signing surface in `crates/chio-federation/src/bilateral_dsse.rs`). Lane C consumes this; the §7 verifier extends the same module. The full B4 sub-lane is `bilateral DSSE signing item-B4.6` plus `bilateral DSSE signing item` Evidence Gate close; B4.5 is the gating negative conformance fixture (parallel to B1.6/B2.5/B3.5). |

If Lane B's tickets renumber during execution, the cross-reference
table above is the source of truth. Lane C tickets cite the literal
IDs current at W3 close.

---

## C1 - Architecture and scenario

### release work-C1.1 - Scaffold `examples/chiodome-bilateral/`

- **Scope:** New Rust example crate with `Cargo.toml`, `src/main.rs`,
  `README.md`, `smoke.sh`, `policies/`, `fixtures/.gitkeep`. Set up
  the example-local chiodos-ladder primitive skeleton (per R4
  Finding 5a; full implementation in release work-C1.3).
- **Files:** `examples/chiodome-bilateral/{Cargo.toml,src/main.rs,
  README.md,smoke.sh,policies/.gitkeep,fixtures/.gitkeep}`.
- **Effort:** S
- **Depends on:** none
- **Owner-class:** demo-eng

#### Acceptance

1. **Production wiring**: example crate compiles and the stub
   binary runs.
   - Enforced call site: `examples/chiodome-bilateral/src/main.rs`
2. **Spec MUST**: scaffolding ticket; defers spec citation to C2.x
   and C3.x.
3. **Negative conformance test**: not applicable (scaffolding).
4. **Audit-doc evidence**: `.planning/trajectory-5/audits/lane-c-demo.md`
   `### release work-C1.1` records the example crate path and stub-run output.
5. **Banner update**: not applicable.

### release work-C1.2 - Two-kernel handshake harness

- **Scope:** Construct two `chio-kernel` instances in-process, run
  the federation handshake from
  `crates/chio-federation/src/trust_establishment.rs`. Persist the
  signed handshake bodies to fixtures.
- **Files:** `examples/chiodome-bilateral/src/handshake.rs`;
  `examples/chiodome-bilateral/fixtures/handshake/{org-a.json,org-b.json}`.
- **Effort:** M
- **Depends on:** release work-C1.1, release work-B0.5 (so the kernels can register
  their refund tools without ad-hoc sync wrappers).
- **Owner-class:** demo-eng

#### Acceptance

1. **Production wiring**: handshake harness drives
   `chio_federation::trust_establishment` directly.
   - Enforced call site:
     `examples/chiodome-bilateral/src/handshake.rs` plus
     `crates/chio-federation/src/trust_establishment.rs:47`
     (`FEDERATION_HANDSHAKE_SCHEMA`).
2. **Spec MUST**: "kernels MUST exchange a signed
   `FederationKernelHandshake` body before any cross-org dispatch".
   - Citation: `spec/PROTOCOL.md` (handshake section; exact lines
     to be filled in by W1 audit-doc owner).
3. **Negative conformance test**:
   `crates/chio-conformance/tests/c_bilateral_handshake_unverified_rejected.rs`
   - Imports `chio_federation::trust_establishment` directly.
   - Asserts the kernel refuses cross-org dispatch when handshake
     verification fails.
4. **Audit-doc evidence**: handshake fixtures captured by smoke run.
5. **Banner update**: not applicable.

### release work-C1.3 - Example-local chiodos-ladder primitive + intersection

- **Scope:** Implement a minimal example-local `chio.chiodos-ladder.v1`
  manifest type in `examples/chiodome-bilateral/src/ladder.rs` per
  `spec/CHIODOS_LADDER.md` §2-6.1. Build the manifest for each side
  (domain `financial`, one action class `refund.execute` shaped like
  `settle.rollback` from §5.2), and emit the
  `chio.chiodos-ladder-intersection.v1` artefact per §6.1. The
  `partition_fallback.blast_radius_cap.amount_minor` field is what
  enforces the demo's 25000-unit cap (per review finding 5b option a -
  the cap is ladder-driven, not policy-YAML-driven).
  **This is NEW Rust code** (review finding 5a): the codebase has no
  prior chiodos-ladder primitive. The example-local version is
  sufficient for v0.1; a production `chio-chiodos-ladder` crate is
  deferred to trj6.
- **Files:** `examples/chiodome-bilateral/src/ladder.rs`;
  `examples/chiodome-bilateral/fixtures/ladder-intersection.json`.
- **Effort:** L
- **Depends on:** release work-C1.2
- **Owner-class:** demo-eng

#### Acceptance

1. **Production wiring**: `ladder.rs` exposes a `LadderManifest`
   type, an `intersection` function, and validates against the
   spec's JSON Schema as a `&str` constant.
   - Enforced call site:
     `examples/chiodome-bilateral/src/ladder.rs`
2. **Spec MUST**: "Producers MUST emit a
   `chio.chiodos-ladder-intersection.v1` artefact when two ladders
   are pinned at handshake".
   - Citation: `spec/CHIODOS_LADDER.md` §6.1 (exact lines to be
     filled in by audit-doc owner).
3. **Negative conformance test**:
   `crates/chio-conformance/tests/c_ladder_intersection_over_cap_rejected.rs`
   - Imports the example crate's `ladder` module.
   - Asserts an over-cap refund (amount_minor > 25000) fails
     ladder intersection check.
4. **Audit-doc evidence**: `ladder-intersection.json` is captured
   by smoke run.
5. **Banner update**: bounded-claim language in `release-bar.md`
   notes "the chiodos-ladder primitive used in the demo is an
   example-local minimal implementation; production ladder primitive
   deferred to trj6".

### release work-C1.4 - Refund tool registration on both kernels

- **Scope:** A `refund.execute` tool implementation registered on
  both kernels via the standard `ToolServerConnection` path. Sync
  semantics: the tool is a stub returning `{ "amount_minor": ...,
  "customer_id": ... }`.
- **Files:** `examples/chiodome-bilateral/src/refund_tool.rs`.
- **Effort:** M
- **Depends on:** release work-C1.1, release work-B0.5
- **Owner-class:** demo-eng

#### Acceptance

1. **Production wiring**: tool registers on both kernels via
   `chio_kernel::runtime::ToolServerConnection`
   (`crates/chio-kernel/src/runtime.rs:254`, post-B0 async).
   - Enforced call site:
     `examples/chiodome-bilateral/src/refund_tool.rs`
2. **Spec MUST**: "Production kernels MUST route every governed
   capability decision through `verify_capability_full`" (the
   refund tool is governed).
   - Citation: `spec/PROTOCOL.md` §5.4 lines 408-418 (post-B1.4
     amend).
3. **Negative conformance test**: covered by release work-B1.6.
4. **Audit-doc evidence**: tool registration confirmed by
   `tools/list` log captured during smoke run.
5. **Banner update**: not applicable.

---

## C2 - Bilateral cosigned invocation flow (consumes Lane B B4)

### release work-C2.1 - Capability verifier trait + receipt-store wiring

- **Scope:** Add `CapabilityVerifier` trait in `chio-federation`
  (per the architecture cut in `bilateral-cosign-flow.md` "Architecture
  cut for cross-crate calls" - option B). The trait wraps Lane B's
  `verify_capability_full` so the §7 verifier in `chio-federation`
  does not pull in `chio-kernel` directly. Wire the existing
  `ReceiptStore` trait re-export
  (`crates/chio-kernel/src/lib.rs:396-397`) into the verifier
  signature.
- **Files:** `crates/chio-federation/src/bilateral_dsse.rs`
  (extends Lane B B4's module);
  `crates/chio-federation/src/lib.rs` (re-export trait).
- **Effort:** M
- **Depends on:** bilateral DSSE signing item (B4.2 introduces the bilateral_dsse.rs
  module; Lane C extends it), bilateral DSSE signing item (gating B4 negative
  conformance fixture)
- **Owner-class:** federation-eng

#### Acceptance

1. **Production wiring**: trait defined; demo's kernel impl wires
   `verify_capability_full` (B1).
   - Enforced call site:
     `crates/chio-federation/src/bilateral_dsse.rs` (trait def);
     `examples/chiodome-bilateral/src/orchestrate.rs` (impl wires
     `chio_kernel::Kernel::verify_capability_full_hosted`).
2. **Spec MUST**: covered by §7 step 14 (release work-C2.4); this ticket
   provides the architectural seam.
3. **Negative conformance test**: covered by release work-C2.5 (one of the
   16 negative-fixture cases asserts `capability.lease_expired_or_unknown`
   when the trait's impl rejects).
4. **Audit-doc evidence**: trait visible in
   `cargo doc -p chio-federation` output.
5. **Banner update**: not applicable.

### release work-C2.2 - Predicate body schema validation + helper

- **Scope:** Lane C extends Lane B B4's module with
  `predicate_from_kernel_state`, the helper that constructs
  `BilateralCoSignInvocationPredicate` from kernel A and kernel B
  state during demo orchestration. Validate the predicate body
  against `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §5 JSON
  Schema (bundled as a `&str` constant, originally introduced by B4).
- **Files:** `crates/chio-federation/src/bilateral_dsse.rs`
  (extends B4's module).
- **Effort:** M
- **Depends on:** release work-C2.1, bilateral DSSE signing item (B4.2 introduces the bilateral_dsse.rs module that this ticket extends), bilateral DSSE signing item (gating B4 negative conformance fixture)
- **Owner-class:** federation-eng

#### Acceptance

1. **Production wiring**: helper + schema validation function
   exposed; called by demo.
   - Enforced call site:
     `crates/chio-federation/src/bilateral_dsse.rs::predicate_from_kernel_state`
2. **Spec MUST**: "Verifiers MUST reject predicates whose body
   does not validate against the §5 JSON Schema".
   - Citation: `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §7
     step 5 (lines to be filled in by audit-doc owner).
3. **Negative conformance test**:
   `crates/chio-federation/tests/bilateral_dsse_negative.rs`
   `predicate_schema_invalid_rejected` (one of the 16 cases).
4. **Audit-doc evidence**: schema-validation negative test passes;
   schema constant matches spec verbatim.
5. **Banner update**: not applicable.

### release work-C2.3 - Capability lease binding via `chio-credit`

- **Scope:** Mint a `CreditBondArtifact`
  (`crates/chio-credit/src/lib.rs:766`) inside the demo flow; bind
  `bond_id` -> `capability_lease_ref.lease_id` and `expires_at` ->
  `capability_lease_ref.expires_at_unix_ms`. Persist the bond as
  fixture. (Was C2.6 in W1.)
- **Files:** `examples/chiodome-bilateral/src/credit.rs`;
  `examples/chiodome-bilateral/fixtures/credit-bond.json`.
- **Effort:** M
- **Depends on:** release work-C2.2, release work-B1.6
- **Owner-class:** demo-eng

#### Acceptance

1. **Production wiring**: bond minted via existing
   `chio-credit::CreditBondArtifact` API.
   - Enforced call site:
     `examples/chiodome-bilateral/src/credit.rs`
2. **Spec MUST**: "predicate
   `capability_lease_ref.lease_id` MUST match a live capability
   lease at pinned_epoch".
   - Citation: `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §5
     (`capability_lease_ref` object).
3. **Negative conformance test**:
   `crates/chio-conformance/tests/c_bilateral_lease_expired_rejected.rs`
   - Imports the demo's bond mint plus `chio-federation::verify_envelope`.
   - Asserts §7 step 14 returns
     `capability.lease_expired_or_unknown` for an expired bond.
   - Depends on Lane B `release work-B1.6` so the kernel-side verifier
     fails closed.
4. **Audit-doc evidence**: `credit-bond.json` fixture; negative test
   pass.
5. **Banner update**: not applicable.

### release work-C2.4 - partial local verifier subset + spec-7.1 negative fixture set

- **Scope:** Implement spec section 7 verification algorithm steps
  1-17 in order, returning the spec section 7.1 error code on
  failure. Ship the 16-case negative fixture set in one PR.
  (Merges W1's C2.4 and C2.5.)
- **Files:** `crates/chio-federation/src/bilateral_dsse.rs`
  (verifier extends B4's module);
  `crates/chio-federation/tests/bilateral_dsse_negative.rs`;
  `crates/chio-federation/tests/fixtures/bilateral_dsse/<code>.json`.
- **Effort:** L
- **Depends on:** release work-C2.1, release work-C2.2, release work-B1.6, release work-B2.5,
  release work-B3.5, bilateral DSSE signing item
- **Owner-class:** federation-eng

#### Acceptance

1. **Production wiring**: `verify_envelope` callable from demo
   orchestrator and from `chio receipt explain` for bilateral chains.
   - Enforced call site:
     `crates/chio-federation/src/bilateral_dsse.rs::verify_envelope`
2. **Spec MUST**: "Receivers MUST run the section 7 verification
   algorithm in order and reject on the first failing step with
   the §7.1 error code".
   - Citation: `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §7
     (steps 1-17) and §7.1 (error code table).
3. **Negative conformance test**:
   `crates/chio-federation/tests/bilateral_dsse_negative.rs` plus
   `crates/chio-conformance/tests/c_bilateral_verifier_steps.rs`
   that drives the federation verifier from a chio-conformance
   harness so the test exercises the same code path the demo does.
   - One `#[test]` per §7.1 error code (16 cases).
   - Each case fails when the matching production check is reverted.
4. **Audit-doc evidence**: 16/16 negative tests green; reverts
   recorded in audit doc.
5. **Banner update**: not applicable.

### release work-C2.5 - Anchor inclusion proof emission

- **Scope:** Construct the `KernelCheckpoint`,
  `SignedWeb3IdentityBinding`, and call
  `crates/chio-anchor/src/lib.rs:178`
  `build_anchor_inclusion_proof` to emit artifact #5. Use
  `LocalDevnetDeployment` for the chain anchor field. (R4 Step gap
  7a: this was previously hand-waved into release work-C4.2.)
- **Files:** `examples/chiodome-bilateral/src/anchor.rs`;
  `examples/chiodome-bilateral/fixtures/anchor-inclusion.json`.
- **Effort:** M
- **Depends on:** release work-C2.4, release work-B3.5
- **Owner-class:** demo-eng

#### Acceptance

1. **Production wiring**: `anchor.rs` calls
   `chio_anchor::build_anchor_inclusion_proof` directly.
   - Enforced call site: `examples/chiodome-bilateral/src/anchor.rs`
2. **Spec MUST**: "consistency_anchor MUST be reconcilable to a
   real inclusion proof when consistency_model is totally-ordered".
   - Citation: `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §7
     step 16.
3. **Negative conformance test**:
   `crates/chio-conformance/tests/c_anchor_inclusion_missing_witness_rejected.rs`
   - Asserts spec §7 step 16 fails when binding is absent.
4. **Audit-doc evidence**: `anchor-inclusion.json` validates under
   `validate_anchor_inclusion_proof` and `verify_anchor_inclusion_proof`.
5. **Banner update**: not applicable.

### release work-C2.6 - Wire the cosign flow into the orchestrator

- **Scope:** Connect the refund tool call to the cosign emission:
  Org A invokes, Org B executes, both kernels sign the PAE
  (per the two-keypair signing protocol in
  `bilateral-cosign-flow.md`), the DSSE Statement is emitted as
  artifact #4, the underlying receipts as #1 and #2, the
  `DualSignedReceipt` shape (rewired by B4) as #3.
- **Files:** `examples/chiodome-bilateral/src/orchestrate.rs`;
  `examples/chiodome-bilateral/fixtures/bilateral-cosign-invocation.json`.
- **Effort:** L
- **Depends on:** release work-C2.4, release work-C2.3, release work-C2.5, release work-C1.4
- **Owner-class:** demo-eng

#### Acceptance

1. **Production wiring**: orchestrator drives the production
   federation hot path; envelope emission is kernel-driven (B4).
   - Enforced call site:
     `examples/chiodome-bilateral/src/orchestrate.rs`
2. **Spec MUST**: covered by release work-C2.4 (the verifier) plus
   bilateral DSSE signing item (the production hot-path emission) and bilateral DSSE signing item (the
   gating negative conformance fixture for the signing surface).
3. **Negative conformance test**:
   `crates/chio-conformance/tests/c_bilateral_orchestrate_unsigned_fails.rs`
   asserts the orchestrator path produces a verifier-acceptable
   envelope and FAILS when B4's signing wiring is reverted.
4. **Audit-doc evidence**: happy-path and deny-path fixtures
   captured by smoke run.
5. **Banner update**: not applicable.

---

## C3 - KB MCP integration via `chio mcp serve` + `mcp-remote` bridge

### release work-C3.1 - HushSpec policy YAML for refund flow

- **Scope:** Author
  `examples/chiodome-bilateral/policies/refund-policy.yaml` in
  the canonical Chio HushSpec format (matches
  `examples/policies/canonical-hushspec.yaml` family). The amount
  cap is NOT a HushSpec primitive (per review finding 5b); it lives in
  the example-local chiodos-ladder intersection logic and is
  enforced upstream of the kernel by release work-C1.3.
- **Files:** `examples/chiodome-bilateral/policies/refund-policy.yaml`.
- **Effort:** S
- **Depends on:** release work-C1.3
- **Owner-class:** demo-eng

#### Acceptance

1. **Production wiring**: `chio check --policy <yaml>` returns
   success against the chio-policy crate.
   - Enforced call site: validated via
     `crates/chio-policy/src/evaluate/`
     (canonical HushSpec parser).
2. **Spec MUST**: "MCP tool dispatch MUST be policy-gated".
   - Citation: `spec/PROTOCOL.md` (HushSpec section; lines to be
     filled in by audit-doc owner).
3. **Negative conformance test**: covered by release work-C3.4 (deny scenario).
4. **Audit-doc evidence**: `chio check` exit code recorded.
5. **Banner update**: not applicable.

### release work-C3.2 - `chio mcp serve` over `mcp-remote` stdio bridge

- **Scope:** Validate `chio mcp serve --policy
  examples/chiodome-bilateral/policies/refund-policy.yaml --
  npx -y mcp-remote http://localhost:8111/mcp/` spawns the
  `mcp-remote` stdio bridge as the wrapped command, which proxies
  to the HTTP KB MCP at `:8111/mcp/`. Capture stdout in fixture.
  Pre-requisite: `npx` (Node.js 18+) on the smoke's PATH; smoke
  fails closed with a clear error if absent.
- **Files:** `examples/chiodome-bilateral/smoke.sh`
  (extends with the serve invocation).
- **Effort:** M
- **Depends on:** release work-C3.1; pre-existing `mcp-remote` shim
  documented at `ops/knowledge-base/README.md:136-151`.
- **Owner-class:** demo-eng

#### Acceptance

1. **Production wiring**: `chio mcp serve` invocation succeeds;
   `tools/list` over the wrapped edge returns at least the KB
   tools (`kb_search`, `kb_query`).
   - Enforced call site: `examples/chiodome-bilateral/smoke.sh`
2. **Spec MUST**: "MCP edge MUST gate `tools/call` through the
   policy".
   - Citation: `spec/PROTOCOL.md` (HushSpec/MCP edge section).
3. **Negative conformance test**:
   `crates/chio-conformance/tests/c_mcp_edge_unpoliced_call_blocked.rs`
   asserts a `tools/call` blocked by the policy returns the
   expected error variant.
4. **Audit-doc evidence**: `tools/list` output committed as
   fixture; `chio mcp serve` start log committed.
5. **Banner update**: bounded-claim text in `kb-mcp-integration.md`
   notes the demo uses `mcp-remote` as stdio bridge, not direct
   HTTP wrapping.

### release work-C3.3 - Receipt persistence sink

- **Scope:** Wire the kernel's receipt sink to write each tool
  call's receipt as canonical JSON to
  `examples/chiodome-bilateral/fixtures/receipts/<id>.json`. Lane
  B `release work-B2.5` is what makes v2 actually emit when negotiated; this
  ticket's smoke fails red if v1 leaks through.
- **Files:** `examples/chiodome-bilateral/src/receipt_sink.rs`.
- **Effort:** S
- **Depends on:** release work-B2.5
- **Owner-class:** demo-eng

#### Acceptance

1. **Production wiring**: sink implements `chio_kernel::ReceiptSink`
   (or equivalent trait) and writes captured v2 receipts.
   - Enforced call site:
     `examples/chiodome-bilateral/src/receipt_sink.rs`
2. **Spec MUST**: "Receivers MUST mint receipt v2 when negotiation
   selects `chio.capability.v2`".
   - Citation: `spec/PROTOCOL.md` §6 lines 714-741 (post-B2.4
     amend).
3. **Negative conformance test**: covered by release work-B2.5.
4. **Audit-doc evidence**: per-call receipt fixtures with
   `signature_ok = true`.
5. **Banner update**: not applicable.

### release work-C3.4 - Cross-org refund call + adversarial deny fixture

- **Scope:** Org A's kernel invokes the proxied refund through Org
  A's `chio mcp serve` instance; Org B's kernel handles the proxied
  call through its own `chio mcp serve`. The bilateral cosign flow
  from release work-C2.6 wraps the result. Includes the adversarial
  over-cap fixture: `amount_minor = 100000` is rejected by Org B's
  ladder intersection; the bilateral envelope's
  `policy_evaluation_summary.server_b_verdict.verdict = deny`;
  `joint_disposition = deny`. (Merges W1's C3.4 and C3.5.)
- **Files:** `examples/chiodome-bilateral/src/orchestrate.rs`;
  `examples/chiodome-bilateral/fixtures/policy-deny.json`.
- **Effort:** L
- **Depends on:** release work-C2.6, release work-C3.2, release work-C3.3
- **Owner-class:** demo-eng

#### Acceptance

1. **Production wiring**: end-to-end smoke produces all six
   artifacts; deny scenario produces the deny envelope fixture.
   - Enforced call site:
     `examples/chiodome-bilateral/src/orchestrate.rs`
2. **Spec MUST**: "joint_disposition MUST resolve to deny when
   either side returns a deny verdict".
   - Citation: `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §7
     step 13.
3. **Negative conformance test**: covered by release work-C2.4 cases for
   verdict disagreement; smoke regression covered by release work-C6.2.
4. **Audit-doc evidence**: six-artifact smoke output for happy and
   deny scenarios.
5. **Banner update**: not applicable.

---

## C4 - Receipt explain

### release work-C4.1 - Extend `chio receipt explain` for bilateral chains

- **Scope:** Update
  `crates/chio-cli/src/cli/trust_commands.rs:2629`
  (`explain_receipt_value`) so that when the input file is a
  `DualSignedReceipt` or a `chio.bilateral-cosign-invocation.v1`
  envelope, the rendered output:
  - decodes the DSSE envelope (Base64, in-toto Statement parse)
  - lists the cosign summary (`tool_server_a/b`, `co_sign` mode,
    `joint_disposition`)
  - walks parent receipts (kernel A v2, kernel B v2,
    `DualSignedReceipt`)
  - surfaces `policy.verdict_disagreement` as a top-level
    diagnostic when present
  - shows the anchor inclusion summary
    (`Web3CheckpointStatement.checkpoint_seq`, `merkle_root`) when
    a child reference resolvable via
    `crates/chio-anchor/src/lib.rs::build_anchor_inclusion_proof`
    is available.
  Effort bumped from M to L per review finding 9 (the bilateral chain
  walk is closer to a tree-renderer than a flat JSON formatter).
- **Files:** `crates/chio-cli/src/cli/trust_commands.rs`;
  `examples/chiodome-bilateral/src/anchor.rs` (data exposure).
- **Effort:** L
- **Depends on:** release work-C2.6, release work-C2.5, release work-B3.5
- **Owner-class:** demo-eng

#### Acceptance

1. **Production wiring**: `chio receipt explain` covers all five
   bilateral artifact types.
   - Enforced call site:
     `crates/chio-cli/src/cli/trust_commands.rs:2629` (post-extend).
2. **Spec MUST**: "Implementations MUST provide a structured
   explain output for cosigned chains".
   - Citation: `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §11
     (debugging, lines to be filled in by audit-doc owner).
3. **Negative conformance test**:
   `crates/chio-cli/tests/explain_bilateral.rs` snapshot test pins
   rendered JSON for happy and deny fixtures; assertion on
   `policy.verdict_disagreement` surfacing.
4. **Audit-doc evidence**: snapshot JSON committed; T1.6 audit row
   references this work.
5. **Banner update**: doc page (release work-C4.2) cites the new behavior.

### release work-C4.2 - `EXPLAIN_A_DENIAL.md` doc + T1.6 close

- **Scope:** Author or update `docs/guides/EXPLAIN_A_DENIAL.md` to
  walk a denied refund through `chio receipt explain`. Cite the
  demo fixtures by exact path. Close `audits/T1.6-chio-explain.md`
  reopened row from trj4. (Merges W1's C4.3 and C4.4 since C4.3
  was a snapshot test that now lives inside C4.1's acceptance.)
- **Files:** `docs/guides/EXPLAIN_A_DENIAL.md`;
  `audits/T1.6-chio-explain.md`.
- **Effort:** S
- **Depends on:** release work-C4.1
- **Owner-class:** demo-eng

#### Acceptance

1. **Production wiring**: doc renders in the docs site; T1.6 row
   references this doc as the resolution evidence.
   - Enforced call site: `docs/guides/EXPLAIN_A_DENIAL.md`.
2. **Spec MUST**: not applicable (doc).
3. **Negative conformance test**: not applicable.
4. **Audit-doc evidence**: T1.6 row carries `caught >= 1` once
   the snapshot tests in release work-C4.1 land green.
5. **Banner update**: README references the EXPLAIN guide.

---

## C5 - Selective disclosure (future work outside closure)

**Scope guard (review finding 6):** C5 is deferred to v0.2 in #620. The current
branch records the release-truth boundary and does not implement or claim
selective-disclosure, zk, BBS+, BBS, or auditor-view proof support. C5 is not a
current closure row.

### release work-C5.1 - C5 deferral marker + dep-tree boundary

- **Scope:** Keep C5 out of release and closure claims unless a future implementation branch
  adds the crate, feature, dependencies, and fixtures required by the gate.
- **Files:** `.planning/trajectory-5/lane-c-demo/c5-selective-disclosure-status.toml`;
  `selective-disclosure.md`; `release-bar.md`;
  `scripts/check-bounded-ship-bar.sh`.
- **Effort:** XS
- **Depends on:** none (independent of Lane B/A)
- **Owner-class:** planning/release-truth

#### Acceptance

1. **Production wiring**: no production wiring claim in #620.
2. **Spec MUST**: marker records the current mismatch between the spec's
   `chio-zk-receipts` / `zk` shape and the current branch state.
3. **Negative conformance test**: `scripts/tests/check-bounded-ship-bar.test.sh`
   proves a false `evidence_complete` marker fails the gate.
4. **Audit-doc evidence**: legacy checker diagnostic output may report C5 as
   PARTIAL, but that output is compatibility metadata only.
5. **Banner update**: `release-bar.md` forbids C5 proof claims while deferred.

---

## C6 - Packaging boundary

### release work-C6.1 - Release-truth boundary

- **Scope:** Keep `release-bar.md` as release-truth boundary prose, not release
  notes. It records what future packaging must prove before any
  `v0.1.0-bounded-chiodome` claim exists.
- **Files:** `.planning/trajectory-5/lane-c-demo/release-bar.md`.
- **Effort:** XS
- **Depends on:** C5 marker boundary
- **Owner-class:** planning/release-truth

#### Acceptance

1. **Production wiring**: no tag, release note, tarball, or release audit row
   is claimed by #620.
   - Enforced call site: `release-bar.md` forbidden-claims section.
2. **Spec MUST**: not applicable.
3. **Negative conformance test**: not applicable.
4. **Audit-doc evidence**: `scripts/check-bounded-ship-bar.sh --diagnostic`
   reports partial rows rather than ready/release status.
5. **Banner update**: README states the branch does not tag or authorize the
   package.

### release work-C6.2 - `chio-demo-smoke` PR-gating CI workflow

- **Scope:** Add `.github/workflows/chio-demo-smoke.yml` that runs
  `examples/chiodome-bilateral/smoke.sh` on every PR; gate on green.
  Acceptance includes the mock-receipt detection assertion (R4
  Finding 12): the workflow MUST verify every fixture under
  `examples/chiodome-bilateral/fixtures/` was produced by the smoke
  run in the same workflow run (mtime check or
  delete-fixtures-then-regenerate pattern).
- **Files:** `.github/workflows/chio-demo-smoke.yml`.
- **Effort:** S
- **Depends on:** release work-C3.4
- **Owner-class:** sre-eng

#### Acceptance

1. **Production wiring**: workflow appears as a required check on
   `main`.
   - Enforced call site:
     `.github/workflows/chio-demo-smoke.yml`
2. **Spec MUST**: not applicable (CI infra).
3. **Negative conformance test**: workflow itself fails red if any
   fixture is hand-edited (mtime check) or if the smoke produces
   fewer than the expected non-deferred artifacts.
4. **Audit-doc evidence**: workflow run URL captured.
5. **Banner update**: README references the demo path and CI gate.

### release work-C6.3 - Continuous chiodome demo workflow (forcing function)

- **Scope:** Add `.github/workflows/chiodome-demo-continuous.yml`
  that runs the smoke nightly on `main` AND on every push to any
  Lane B branch (path filters: `crates/chio-kernel/**`,
  `crates/chio-anchor/**`, `crates/chio-federation/**`,
  `crates/chio-conformance/**`). Failures open an issue with the
  matching commit SHA. (review finding 10 and R1 §6.2 §10: the
  forcing-function CI hook is non-negotiable; without it Lane B
  partial-enforcement bugs the demo would catch get caught at the
  worst possible time, the day before tag.)
- **Files:** `.github/workflows/chiodome-demo-continuous.yml`.
- **Effort:** S
- **Depends on:** release work-C6.2
- **Owner-class:** sre-eng

#### Acceptance

1. **Production wiring**: workflow runs nightly; failures open
   issue with commit SHA.
   - Enforced call site:
     `.github/workflows/chiodome-demo-continuous.yml`
2. **Spec MUST**: not applicable (CI infra).
3. **Negative conformance test**: workflow itself goes red when
   any of the four Lane B negative conformance fixtures regress.
4. **Audit-doc evidence**: seven-night evidence is a future packaging
   prerequisite, not a #620 claim.
5. **Banner update**: README references the continuous gate.

### release work-C6.4 - Diff-stable fixture tarball

- **Scope:** Build a tarball
  `chiodome-bilateral-fixtures-v0.1.0.tar.gz` from the demo's
  `fixtures/` directory. Add a `tools/diff-stable.py` (or Rust
  binary) under the example crate that compares two fixture
  directories modulo allowed-varying fields (timestamps, UUIDs,
  signing nonces). Smoke step 5 calls this tool. (review finding 11:
  byte-identical reproducibility is impractical; "diff-stable
  modulo allow-list of varying fields" is the rule.)
- **Files:** `examples/chiodome-bilateral/scripts/build-tarball.sh`;
  `examples/chiodome-bilateral/tools/diff-stable.py`.
- **Effort:** S
- **Depends on:** release work-C6.2
- **Owner-class:** sre-eng

#### Acceptance

1. **Production wiring**: tarball regenerable via `./smoke.sh &&
   build-tarball.sh`; `diff-stable` returns 0 on two consecutive
   runs.
   - Enforced call site:
     `examples/chiodome-bilateral/scripts/build-tarball.sh`
2. **Spec MUST**: not applicable.
3. **Negative conformance test**: `diff-stable` returns non-zero
   if a non-allow-listed field varies between two runs.
4. **Audit-doc evidence**: two consecutive run hashes recorded.
5. **Banner update**: not applicable.

### release work-C6.5 - Future tag boundary

- **Scope:** #620 does not sign-tag or publish. Future packaging remains blocked
  unless Lane B negative conformance fixtures (B1.6, B2.5, B3.5, B4.5), Lane C
  canary evidence, Lane A evidence, package metadata, and C5 status are all
  evidenced from merged source.
- **Files:** none in tree (operational).
- **Effort:** XS in #620; future packaging owner scope later.
- **Depends on:** release work-C6.1..4 + release work-B1.6, release work-B2.5, release work-B3.5,
  bilateral DSSE signing item + Lane A's mutation banner reading the real number.
- **Owner-class:** release owner

#### Acceptance

1. **Production wiring**: branch records no tag or release artifact claim.
   - Enforced call site: `release-bar.md` forbidden-claims section.
2. **Spec MUST**: not applicable.
3. **Negative conformance test**: not applicable.
4. **Audit-doc evidence**: future tag SHA + release URL must be recorded by a
   packaging owner, not #620.
5. **Banner update**: no tag banner is added by #620.

---

## Ticket count

- C1: 4 (release work-C1.1 .. C1.4)
- C2: 6 (release work-C2.1 .. C2.6) - merged W1's C2.4+C2.5 into one L
  ticket; absorbed C2.6 into C2.3; added C2.5 anchor inclusion per
  R4 Step gap 7a
- C3: 4 (release work-C3.1 .. C3.4) - merged W1's C3.4+C3.5 into one L
  ticket
- C4: 2 (release work-C4.1, C4.2) - merged W1's C4.3 snapshot test into
  C4.1 acceptance; merged W1's C4.4 doc with T1.6 close
- C5: 1 current boundary ticket; implementation deferred to v0.2.
- C6: 5 boundary/planning tickets; tag/release publication is future packaging
  owner scope after integrated evidence exists.

**Total: 24 tickets** (within the 22-26 final target after R1 §11.7
merge guidance). The list is fine-grained where each ticket maps
to one composable primitive and one fixture, and merged where two
adjacent S-tickets shared scope without losing audit granularity.
Reviewers may merge further at execution time.
