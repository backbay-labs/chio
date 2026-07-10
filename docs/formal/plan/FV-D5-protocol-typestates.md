# FV-D5: Machine-readable protocol state machines with generated typestates

Status: Proposed (2026-07-09)
Theme: D - Widen the verified frontier
Effort: M
Depends on: none
Feeds: [FV-B1](FV-B1-drop-guard-model.md) (state tables as future TLA model input), [FV-C1](FV-C1-receipt-trace-validation.md) (trace vocabulary), [FV-C5](FV-C5-proof-coverage-map.md) (coverage rows per machine)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G4: one source of truth instead of prose-plus-code duplication), `crates/tooling/chio-spec-codegen/src/lib.rs`, `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md`

## Summary

Chio's protocol flows have lifecycle semantics scattered across normative prose (`spec/PROTOCOL.md`, `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md` section 7), hand-written Rust sequencing, and step-numbered conformance tests - three copies with no machine link. This document proposes state tables as data (`spec/statemachines/*.toml`: states, messages, guards, transitions, terminal states) as the single source, and extends `chio-spec-codegen` (following its existing committed-generated-artifact and drift-check pattern exactly) to emit three artifacts per machine: a Rust typestate module in which illegal sequences are unrepresentable at compile time, conformance-test skeletons asserting that runtime edges reject out-of-order messages from dynamic peers, and a generated documentation appendix table. The pilot machine is the bilateral co-signing flow (`BilateralCoSigningProtocol` in `chio-federation`), chosen over the receipt/session lifecycle after reading both. Wire-level semantics are unchanged and `spec/PROTOCOL.md` normative text is NOT modified in this wave: the tables encode what the spec already says, and the generated appendix lives beside the spec, not inside it.

## Motivation and evidence

- The step numbering already exists; only the machine-readability is missing. `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md` defines a numbered verification algorithm (section 7, L384) with a closed error-code alphabet (section 7.1, L438), and `crates/tooling/chio-conformance/tests/c2_bilateral_invocation_partial_verifier.rs` carries a step-by-step tamper table in its module doc (L8-23: steps 7 through 15, each mapped to the exact 7.1 code a mutation must produce). That table is a state machine transcribed by hand into a comment. When the spec gains a step, nothing forces the test table, the verifier, or any SDK to follow.
- Ordering bugs are currently caught only at runtime, only where a test exists. The kernel holds the co-signing seam as a trait object (`crates/kernel/chio-kernel/src/kernel/kernel_struct.rs` L220); the compiler currently permits calling verify-shaped functions on artifacts that were never co-signed, because every stage is the same Rust type. Typestates make the illegal call absent rather than rejected.
- The codegen pattern to copy is proven in-tree, three times. `chio-spec-codegen` already runs a schemas-to-Rust pass (typify over `spec/schemas/chio-wire/v1/**/*.schema.json` into `crates/chio-core-types/src/_generated/chio_wire_v1.rs`), an error-registry pass (`errors_pass.rs`, `codegen_error_codes`), and a threat-model stub pass - each with the canonical `// DO NOT EDIT` header, deterministic output (lexicographic file order plus prettyplease), a committed snapshot, and `cargo xtask codegen --check` drift detection; `_generated_check.rs` fails the build on a missing header, and `.github/workflows/spec-drift.yml` (L141-160) verifies the regeneration-command headers. A statemachines pass is a fourth pass through the same machinery, not new infrastructure.
- This is the G4 medicine applied forward: instead of de-duplicating prose and code after they drift, put the table in one file and generate the other copies.

## Current state

- `spec/PROTOCOL.md` (3455 lines, sampled selectively this session) names several lifecycle semantics without a machine-readable form: the commerce order event log is "a monotonic state-transition ledger" whose verifier rejects "skipped states, backwards state transitions" (~L1108-1115); anchor batches carry a `WitnessState` lifecycle Pending -> Witnessed -> Stale (L1292-1300); the hosted session flow requires `initialize` before `notifications/initialized` before ready-state dependence (L238-245, with normative details in `spec/WIRE_PROTOCOL.md`); section 5.5 (L658) anchors the verified-core boundary this plan does not touch.
- Bilateral co-signing surface (`crates/trust/chio-federation/src/bilateral.rs`, read this session): `CoSigningBody` (L48), `CoSigningRequest`/`CoSigningResponse` (L207/L237), DSSE variants (L249/L276), `DualSignedReceipt` with strict both-signatures verification (L100, L126, L153), the `BilateralCoSigningProtocol` trait the kernel calls after local signing (module doc L9), producer helpers `co_sign_with_origin` (L457) and `co_sign_with_origin_full` (L562), and an end-to-end fixture `execute_local_bilateral_invocation_fixture` (L668) whose own comments are step-numbered ("Step 1" L672, "Step 2: partial local verifier (subset of section 7)" L699).
- `chio-spec-codegen` (`crates/tooling/chio-spec-codegen/`, read this session): library passes as described above; CLI in `src/main.rs` with `--errors-only` and `--threat-model` modes; ARCHITECTURE.md documents the pass layout.
- No `spec/statemachines/` directory exists.

## Design

### State tables as data

`spec/statemachines/<machine>.toml`, schema `chio.statemachine.v1`:

```toml
schema   = "chio.statemachine.v1"
machine  = "bilateral_cosign"
crate    = "chio-federation"                  # owning crate for the generated module
doc_refs = ["spec/CHIO_BILATERAL_COSIGN_INVOCATION.md#7-verification-algorithm"]

states   = ["Drafted", "LocallySigned", "CoSigned", "Verified", "Rejected"]
initial  = "Drafted"
terminal = ["Verified", "Rejected"]

[[transitions]]
from    = "Drafted"
to      = "LocallySigned"
message = "sign_local"                        # producer-side action
guards  = ["receipt_signature_valid"]         # runtime guard names (fail-closed: guard false -> error, not transition)

[[transitions]]
from    = "LocallySigned"
to      = "CoSigned"
message = "co_sign_response"                  # CoSigningResponse accepted
guards  = ["peer_id_matches_request", "signature_over_cosigning_body_valid"]

[[transitions]]
from    = "CoSigned"
to      = "Verified"
message = "verify_pinned"
guards  = ["both_signatures_valid", "peers_pinned"]   # spec 7 steps 8, 11, 12

[[transitions]]
from    = "CoSigned"
to      = "Rejected"
message = "verify_pinned_failure"
guards  = []                                  # every 7.1 error code maps here; codes listed in codes = [...]
```

Loader rules (fail-closed, matching house style): unknown states in a transition reject at load; unreachable states reject; a non-terminal state with no outgoing transitions rejects; duplicate (from, message) pairs reject; guard names must be unique per edge. The loader is a library function so `chio-spec-validate` can also call it.

### Generated artifact (a): Rust typestate module

Per machine, `crates/<owning-crate>/src/_generated/<machine>_typestate.rs` behind feature `typestate` in the owning crate. Zero-sized state types, transition methods consuming `self`, illegal transitions simply absent. Sketch of the pilot output (abridged; real output carries the DO NOT EDIT header and doc comments citing the table row):

```rust
// DO NOT EDIT - generated by chio-spec-codegen statemachines pass
// from spec/statemachines/bilateral_cosign.toml

pub struct Drafted;
pub struct LocallySigned;
pub struct CoSigned;
pub struct Verified;

pub struct BilateralCoSign<S> {
    body: CoSigningBody,
    evidence: StageEvidence,
    _state: core::marker::PhantomData<S>,
}

impl BilateralCoSign<Drafted> {
    pub fn sign_local(self, kp: &Keypair)
        -> Result<BilateralCoSign<LocallySigned>, BilateralCoSigningError> { /* guard: receipt_signature_valid */ }
}

impl BilateralCoSign<LocallySigned> {
    pub fn co_sign_response(self, resp: CoSigningResponse)
        -> Result<BilateralCoSign<CoSigned>, BilateralCoSigningError> { /* guards: peer id, signature */ }
}

impl BilateralCoSign<CoSigned> {
    pub fn verify_pinned(self, peers: &ExpectedBilateralPeers<'_>)
        -> Result<BilateralCoSign<Verified>, BilateralCoSigningError> { /* spec 7 steps 8, 11, 12 */ }
}

// No method exists from Drafted to CoSigned, or from Verified to anything:
// out-of-order calls are compile errors, not runtime denials.
```

Guards from the table become the runtime `Result` inside each method (a guard failure is an `Err`, never a silent state change), because guards depend on data the type system cannot see; the TYPE layer encodes only ordering. Method bodies delegate to the existing hand-written functions (`co_sign_with_origin`, `DualSignedReceipt::verify_pinned`), so the generated module adds sequencing, not new crypto.

### Generated artifact (b): conformance-test skeletons

Compile-time typestates protect in-process callers; a remote peer can still SEND messages out of order. For each non-edge in the table (every (state, message) pair with no transition), the pass emits a test skeleton into `crates/tooling/chio-conformance/tests/_generated/<machine>_ordering.rs`: drive the runtime surface to `state`, deliver `message`, assert the surface rejects with an error (exact code filled in by hand where 7.1 names one; the skeleton asserts rejection and carries a TODO-coded assertion otherwise). The generated file is committed and drift-checked like every other generated file; hand-completed assertions live in a companion non-generated file so regeneration never destroys work (the skeleton emits `include!`-able case lists, following the threat-model stub pass's convention of stubs-plus-hand-tests).

### Generated artifact (c): documentation appendix

`docs/reference/generated/STATE_MACHINES.md`: one table per machine (states, transitions, guards, terminal states, spec references). Explicitly NOT a `spec/PROTOCOL.md` edit: PROTOCOL.md is normative and wire-level semantics are unchanged in this wave; the appendix is derived documentation, and each table cites the normative section it transcribes. If a table and the spec disagree, the spec wins and the table is the bug - stated in the file header.

### Pilot selection: bilateral co-signing, and why not receipt/session

Compared after reading both:

- Bilateral co-signing: small closed alphabet (4-5 states, ~6 messages); an existing trait seam consumed by the kernel (`kernel_struct.rs` L220) giving phase 2 a concrete adoption point; a step-numbered normative algorithm (section 7) and an existing step-tamper conformance test (c2, L8-23) to validate the generated skeletons against; both producer and verifier ordering worth protecting.
- Receipt/session lifecycle: the hosted session flow (initialize -> initialized -> ready, PROTOCOL.md L238-245) spans HTTP/SSE transport with session storage side effects, and its normative text lives across two spec files; the commerce order event log is verifier-side data validation (already rejecting skipped/backwards transitions) rather than SDK call-sequencing, so typestates add less there. Both are better as phase-4 machines once the pass exists; `WitnessState` (Pending/Witnessed/Stale, L1292-1300) is the recommended second machine because it is three states and already enum-shaped.

## Implementation plan

1. Schema plus pilot machine plus generated Rust behind a feature. Files to add: `spec/statemachines/bilateral_cosign.toml`; `crates/tooling/chio-spec-codegen/src/statemachines_pass.rs` (loader, validation, Rust emitter); `crates/trust/chio-federation/src/_generated/bilateral_cosign_typestate.rs` (committed output) plus the `typestate` feature and `mod _generated;` wiring in `crates/trust/chio-federation/src/lib.rs` and `Cargo.toml`. Files to modify: `crates/tooling/chio-spec-codegen/src/main.rs` (a `--statemachines` mode alongside `--errors-only`), the xtask codegen entry so `cargo xtask codegen rust` and `--check` cover the new pass.
2. Adopt in one SDK-core path. Modify the kernel's bilateral call path (the post-sign co-signing hop behind `kernel_struct.rs` L220) to route through `BilateralCoSign<S>` when the `typestate` feature is on, with the feature default-on for the kernel once green; the hand-rolled sequence remains as the erased fallback for `dyn` call sites. Files: `crates/kernel/chio-kernel/src/kernel/kernel_struct.rs` call path modules, `crates/trust/chio-federation/src/bilateral.rs` (additive constructors only; no existing signature changes).
3. Conformance skeleton generation. Files to add: skeleton emitter in `statemachines_pass.rs`; `crates/tooling/chio-conformance/tests/_generated/bilateral_cosign_ordering.rs` (committed); hand-completed companion `crates/tooling/chio-conformance/tests/bilateral_cosign_ordering_impl.rs` wiring the non-edges to real drivers, reusing the c2 fixture setup. Cross-check: every c2 tamper-table row (L8-23) must correspond to either a guard failure or a non-edge in the table; discrepancies are table bugs to fix before merge.
4. Additional machines plus the docs appendix. Files: `spec/statemachines/anchor_witness_state.toml` (second machine), `docs/reference/generated/STATE_MACHINES.md` emitter and committed output; candidate third machine: the commerce order event log's transition relation (verifier-side table only, no typestate emission for data-validation machines - the pass gains a `emit = ["docs", "conformance"]` selector).

## CI and gating changes

- `cargo xtask codegen --check` (already run by CI) gains the statemachines pass, so drift between any table and its committed outputs fails PR-time - identical mechanism to `chio_wire_v1.rs`.
- `.github/workflows/spec-drift.yml`: add the new generated files to the regeneration-header checks (the L141-160 list pattern) and add `spec/statemachines/**` to the workflow's path triggers.
- `_generated_check.rs`-style header enforcement extends to the new `_generated/` directories in `chio-federation` and `chio-conformance` (add or reuse the header-scan test per crate).
- Conformance ordering tests ride `cargo test --workspace`. No formal-lane gating changes: this plan produces code and tests, not proofs.

## Acceptance criteria

- [ ] `chio.statemachine.v1` loader rejects (with tests): unknown states, unreachable states, dead non-terminal states, duplicate (from, message) edges.
- [ ] The pilot table round-trips: regeneration is byte-identical (determinism), and `--check` fails on a hand-edit to any generated file.
- [ ] The generated typestate module compiles with illegal transitions absent, demonstrated by `compile_fail` doctests (at least: Drafted-to-CoSigned skip, double-verify on a terminal state).
- [ ] One kernel/SDK-core path constructs and consumes `BilateralCoSign<S>` end-to-end under the `typestate` feature, with no wire bytes changed (existing c2 and bilateral tests all pass unmodified).
- [ ] Generated ordering skeletons cover every non-edge; the hand-completed suite maps each c2 tamper row to a table guard or non-edge, with any mismatch resolved in the table.
- [ ] `docs/reference/generated/STATE_MACHINES.md` exists, is drift-checked, and `spec/PROTOCOL.md` has zero diffs in this wave.
- [ ] A second machine (`WitnessState`) lands through the same pass with no emitter changes (proves the pass is table-driven, not pilot-shaped).

## Risks and mitigations

- Generated-code churn polluting diffs. Mitigation: committed-snapshot plus `--check` drift gate, deterministic emission (sorted tables, prettyplease), and one file per machine so a table edit touches exactly one generated file.
- Typestate ergonomics at async call sites: consuming `self` across `.await` points is fine, but trait objects cannot be generic over the state parameter, and the kernel seam is `dyn BilateralCoSigningProtocol`. Mitigation: the generated module includes an erased `BilateralCoSignDyn` wrapper carrying the state as a runtime enum with fail-closed transition checks - dynamic call sites get runtime enforcement, static call sites get compile-time enforcement, both from the same table.
- Table wrong, spec right: encoding the machine incorrectly would generate confidently wrong tests. Mitigation: phase 3's cross-check against the independently written c2 tamper table; `doc_refs` on every table; the appendix header's "spec wins" rule.
- Guard explosion: pushing data-dependent conditions into the type layer would bloat states. Mitigation: the design rule is explicit - types encode ordering only, guards stay runtime `Result`s - enforced by the schema having no conditional-state construct.
- Cross-language SDKs (Python/TS/Go) do not get typestates from this wave. Mitigation: the table is language-neutral by construction; the four-language codegen pipeline (`xtask/codegen-tools.lock.toml`) can grow emitters later; runtime ordering conformance tests protect dynamic implementations meanwhile.

## Open questions

- Feature naming and defaulting: `typestate` default-on for in-repo consumers immediately, or after one release of soak? (Proposal: off for one release, then default-on for the kernel path.)
- Should the fixture `execute_local_bilateral_invocation_fixture` (bilateral.rs L668) be rewritten over the typestate API in phase 2, or kept as an independent hand-rolled cross-check? (Proposal: keep independent; two encodings of the sequence that must agree are worth more than one.)
- Does the DSSE signature-slice profile need its own machine, or is it a parameterization of the pilot table? Decide when transcribing section 7 fully.
- Where does the erased dynamic wrapper's state enum live for serde purposes (peers may need to persist mid-flow state)? Out of scope for the pilot; flag for the session-lifecycle machine.

## Manifest and registry updates

- `formal/proof-manifest.toml`: no changes. This plan generates code and tests, not proof artifacts; nothing here may be described as verified.
- `formal/assumptions.toml`, `formal/theorem-inventory.json`, `docs/reference/CLAIM_REGISTRY.md`: no changes. If release prose ever claims "illegal protocol sequences fail at compile time", that claim is scoped to Rust in-process callers with the `typestate` feature and must not be added to the registry without that scope.
- `formal/MAPPING.md`: no changes now. Follow-up hook: once [FV-B1](FV-B1-drop-guard-model.md)-style TLA models are derived from these tables (the tables are already states/messages/transitions), each table gains a MAPPING row tying it to its model; the `doc_refs` field is designed to make that row mechanical.
- `fuzz/target-map.toml`: no changes (no new fuzz target); if a statemachine-table fuzzer is ever added, it registers per [FV-E4](FV-E4-fuzz-plumbing-repair.md).
