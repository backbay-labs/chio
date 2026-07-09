# FV-C1: Receipt trace validation against the TLA+ specs

- Status: Proposed (2026-07-09)
- Theme: C - Turn verification into product surface
- Effort: M
- Depends on: existing TLA+ specs (formal/tla/, formal/apalache/); becomes richer after [FV-B1](FV-B1-drop-guard-model.md) adds the PostAdmissionDropGuard model
- Feeds: customer-facing trust tooling (`chio trust trace-verify`), [FV-E2](FV-E2-counterexample-regression-pipeline.md), [FV-C5](FV-C5-proof-coverage-map.md)
- Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G5), [FV-B1](FV-B1-drop-guard-model.md), [FV-E3](FV-E3-pr-formal-smoke-tier.md), [FV-B4](FV-B4-loom-registry-and-dst.md)

## Summary

The Apalache lane model-checks revocation propagation and kernel transition safety, but nothing ever confronts those specs with what the kernel actually emitted. This plan adds trace validation in the style of MongoDB's eXtreme modelling work: read a receipt log, project each receipt onto spec actions through an explicit abstraction function, emit the projected trace as ITF JSON, and have Apalache check that the observed trace is a behavior of the spec and that the spec invariants hold along it. Phase 1 validates conformance-suite logs against RevocationPropagation; phase 2 makes that a nightly gate; phase 3 ships `chio trust trace-verify` so relying parties can run the same check against their own logs. A divergence is triaged as exporter-bug, spec-bug, or kernel-bug, and each class has a concrete owner and template.

## Motivation and evidence

- G5 in [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md): proof lanes are never adversarially measured. The TLA+ specs are the sharpest instance - they are checked against themselves, never against the implementation's observable output.
- The specs are load-bearing, not documentation. The RETIRED-SQLITE-CROSS-ROW assumption discharge cites the `MonotoneLog` invariant and the `ReceiptBeforeAllow` Apalache spec directly (formal/proof-manifest.toml `discharged_assumptions`, formal/assumptions.toml `retired_assumptions`). If the spec's `Evaluate` action drifts from what `crates/kernel/chio-kernel/src/receipt_store.rs` records, that discharge is vacuous and nothing currently notices.
- formal/MAPPING.md ties invariant names to Rust call sites, but scripts/check-mapping.sh enforces name presence by grep, not semantic correspondence. Trace validation is the cheapest mechanism that tests the correspondence itself.
- The decode problem is already solved once: the fuzz lane parses NDJSON receipt logs line by line into `ChioReceipt` and verifies signatures (crates/kernel/chio-kernel-core/src/fuzz.rs:85-102, entry `fuzz_receipt_log_replay` at line 77) [v]. The exporter reuses that approach.
- Receipts are signed decisions in an append-only Merkle-committed log [v], so a validated trace is also a product story: the same spec the vendor model-checks can be replayed by a customer over logs they hold. That is Theme C in one sentence.

Prior art cited by name only: MongoDB eXtreme modelling (trace checking of production logs against TLA+ specs).

## Current state

- Specs and named actions, verified this session:
  - formal/tla/RevocationPropagation.tla: actions `Attenuate(a, c)` (L148), `Revoke(a, c)` (L161), `Propagate(m)` (L176), `Evaluate(a, c)` (L192), `PropagateAny` (L213); state variables `state, depth, rev_epoch, receipt_log, pending, clock` (L91-105); receipt record shape `[cap, verdict, t, seen_epoch]` (L83); safety invariants `NoAllowAfterRevoke` (L269), `MonotoneLog` (L281), `AttenuationPreserving` (L293), `RevocationFreshness` (L311); liveness `RevocationEventuallySeen` (L374).
  - formal/apalache/: MonotoneLogApalache.tla, ReceiptBeforeAllow.tla, RevocationCutCompleteness.tla, KernelTransitionCancelSafe.tla, plus MC*.cfg configs and a `_negative_tests` directory.
- Apalache 0.50.1 is the pinned checker; its native counterexample/trace format is ITF JSON [v].
- The conformance replay fixture corpus holds 50 fixtures under tests/replay/fixtures (formal/diff-tests/tests/anchored_root.rs:18, L125), and the anchored-root diff test already replays them deterministically.
- Counterexample triage templates exist: formal/issue-templates/property-counterexample.md and liveness-counterexample.md.
- There is no trace exporter, no TraceCheck module, and no CI step relating logs to specs.

## Design

### Exporter home: tooling crate, not xtask

Two candidate homes were weighed:

1. An xtask leaf (`cargo xtask check receipt-trace`). Cheap to add (xtask/src/cli.rs already has the `check` noun group, L153-170), but xtask is a dev-only workspace runner that is never shipped, and phase 3 needs the identical decode + map + emit logic linked into the chio-cli product binary.
2. A dedicated crate `crates/tooling/chio-trace-validate`. One implementation serves the fixture tests, the nightly lane, and the `chio trust trace-verify` product command.

Recommendation: the tooling crate. An xtask alias can wrap it later; the reverse migration (xtask leaf into product surface) would strand the logic.

### Input decode

NDJSON receipt logs, one canonical-JSON receipt per line, decoded as `ChioReceipt` exactly as `drive_ndjson_log` does (crates/kernel/chio-kernel-core/src/fuzz.rs:85-102). One deliberate difference: the fuzz driver skips undecodable lines because its goal is coverage; trace mode fails closed on the first undecodable or signature-invalid line, because a silently skipped receipt weakens the trace. An `--allow-skip` flag exists for exploratory runs and prints a skip count; the default is strict.

### Abstraction function

Per spec, an explicit, versioned Rust module maps receipts to spec steps. For RevocationPropagation the projection table is:

| TLA+ variable / field | Receipt-log projection | Notes |
|---|---|---|
| `ProcSet` index `a` | issuing authority (kernel key id), interned in first-seen order | PROCS derived from trace |
| `CapSet` index `c` | capability id named by the receipt, interned | CAPS derived from trace |
| `receipt_log[a][i].cap` | interned capability id | |
| `receipt_log[a][i].verdict` | receipt verdict, `allow` or `deny` | matches spec alphabet (L75) |
| `receipt_log[a][i].t` | monotonic receipt sequence number | spec maps `clock` to "kernel monotonic receipt counter" (L29) |
| `receipt_log[a][i].seen_epoch` | revocation epoch the kernel had observed at issuance | 0 means none observed |
| `rev_epoch[a][c]` | revocation-observation events reconstructed from the log | |
| `state[a][c]`, `depth[a][c]` | attenuation/revocation lifecycle events where the log carries them | unconstrained otherwise |
| `pending` | unobservable (internal propagation) | left existentially unconstrained |
| `clock` | receipt sequence counter | |

Two rules make this sound rather than hopeful:

- Partial observability: variables the log cannot witness (`pending`, and `state`/`depth` where no event is logged) are left unconstrained; the TraceCheck module constrains only projected variables per step. This is the standard trace-validation treatment and avoids inventing state.
- Crypto verdicts project to booleans. A receipt participates in the trace only after its signature verifies; "signature valid" then projects to plain membership in `receipt_log`. The projection is justified by the upstream lanes that own crypto: the P4 receipt lane and ASSUME-ED25519 / ASSUME-SHA256 (formal/assumptions.toml:19-20). The exporter re-verifies before projecting, so the boolean never launders an unverified receipt.

### Output and checking

- The exporter emits ITF JSON, Apalache's native trace format [v], one state per projected step.
- A per-spec TraceCheck module template, first instance `formal/tla/trace/TraceCheckRevocationPropagation.tla`: EXTENDS the spec, loads the trace, defines `TraceNext == Next /\ (projected variables follow trace entry i+1)`, and asserts the spec's `SafetyInv` along the constrained behavior, with a completion check that the full trace was consumed (checked at `--length` equal to the trace length). This is the standard Apalache trace-validation pattern.
- `scripts/check-receipt-trace.sh` drives exporter plus `apalache-mc` per spec, exits nonzero on divergence, and prints the first divergent step with both states: the projected receipt-log step and the spec state it failed to extend.

Exporter output sketch (ITF, one projected state per step; unprojected variables omitted per the partial-observability rule):

```json
{
  "#meta": { "format": "ITF", "source": "chio-trace-validate 0.1",
             "spec": "RevocationPropagation", "log_sha256": "..." },
  "vars": ["receipt_log", "rev_epoch", "clock"],
  "states": [
    { "#meta": { "index": 0 }, "clock": 1,
      "rev_epoch": { "#map": [] }, "receipt_log": { "#map": [] } },
    { "#meta": { "index": 1 }, "clock": 2,
      "rev_epoch": { "#map": [] },
      "receipt_log": { "#map": [[1, [{ "cap": 3, "verdict": "allow",
                                        "t": 1, "seen_epoch": 0 }]]] } }
  ]
}
```

TraceCheck module skeleton (per-spec template, instantiated per trace run):

```tla
---- MODULE TraceCheckRevocationPropagation ----
EXTENDS RevocationPropagation
VARIABLE step
TraceInit == Init /\ step = 0
TraceNext ==
    /\ Next
    /\ step' = step + 1
    /\ ProjectedVarsMatch(step + 1)  \* only projected variables constrained
TraceSafety == SafetyInv             \* checked at --length = Len(trace)
================================================
```

### Divergence triage flow

Every divergence is classified before any fix lands, reusing formal/issue-templates/property-counterexample.md:

1. Exporter-bug (most likely): the abstraction function mis-projected a field. Detect by replaying the divergent step against the hand-written fixture traces; fix the mapping module and add the log as a fixture.
2. Spec-bug: the kernel behavior is intended but the spec forbids it. Fix the spec, update the corresponding formal/MAPPING.md row, and record the trace as a negative-turned-positive fixture.
3. Kernel-bug: the spec is right and the log shows a real violation (an allow after locally observed revocation would violate `NoAllowAfterRevoke`). This is a security finding; the receipt log itself is the evidence artifact. Escalate outside the formal lane.

### FV-B1 hook

The exporter keeps a spec-keyed registry of abstraction functions. When FV-B1 lands the PostAdmissionDropGuard model, adding `src/map/drop_guard.rs` and `formal/tla/trace/TraceCheckPostAdmissionDropGuard.tla` is additive; drop/cancel receipts then get trace-checked with no changes to the phase-2 lane shape.

## Implementation plan

1. Phase 1 - exporter and RevocationPropagation mapping over conformance logs.
   - Add `crates/tooling/chio-trace-validate/Cargo.toml`, `src/main.rs`, `src/decode.rs` (strict NDJSON decode), `src/intern.rs` (authority/capability interning), `src/map/mod.rs`, `src/map/revocation.rs` (the table above), `src/itf.rs` (ITF JSON writer).
   - Add `formal/tla/trace/TraceCheckRevocationPropagation.tla` and hand-written fixture logs under `formal/tla/trace/fixtures/` - at minimum one log that must pass and one containing an allow-after-revoke receipt that must diverge at a known step index.
   - Add `scripts/check-receipt-trace.sh`.
   - Modify the workspace `Cargo.toml` members list.
2. Phase 2 - nightly CI validation of conformance-run traces.
   - Modify the conformance harness (crates/tooling/chio-conformance) to persist receipt logs from a run.
   - Modify the nightly formal workflow to run `scripts/check-receipt-trace.sh` over those logs.
   - Modify `scripts/generate-proof-report.sh` and `scripts/check-proof-report.sh` so target/formal/proof-report.json records a `trace_validation` section (specs checked, trace lengths, action-coverage counters, result) [v: proof-report plumbing already records gate results, tool versions, artifact hashes].
3. Phase 3 - `chio trust trace-verify` product subcommand.
   - Add `crates/products/chio-cli/src/cli/trust/trace_verify.rs`; modify `crates/products/chio-cli/src/cli/trust_commands.rs` to include it (the trust family already hosts receipt/credit/liability/underwriting/runtime_attestation modules).
   - UX sketch: `chio trust trace-verify --log receipts.ndjson --spec revocation-propagation [--format json|text]`. Pass output: one line naming the spec, trace length, and the invariants that held. Fail output: first divergent step index, the projected step, the spec state it could not extend, and the failed conjunct; exit code 1. Missing `apalache-mc` fails closed with an install pointer.

## CI and gating changes

- Phase 1: exporter fixture tests run in the normal PR `cargo test` surface (cheap, no Apalache).
- Phase 2: nightly formal lane gains the trace-validation step; `scripts/check-proof-report.sh` asserts the `trace_validation` section is present and passing for release qualification. No PR-time Apalache run here - a single-fixture trace check is a candidate for the [FV-E3](FV-E3-pr-formal-smoke-tier.md) smoke tier, decided there.
- Divergences in nightly open an issue from formal/issue-templates/property-counterexample.md with the ITF trace attached, feeding the [FV-E2](FV-E2-counterexample-regression-pipeline.md) counterexample-regression pipeline.

## Acceptance criteria

- [ ] `chio-trace-validate` decodes the 50-fixture replay corpus and emits ITF JSON deterministically (byte-identical across two runs).
- [ ] The known-good fixture log validates against TraceCheckRevocationPropagation with all four safety invariants.
- [ ] The allow-after-revoke fixture log diverges at exactly the documented step, and the tool prints both states.
- [ ] Strict mode fails closed on an undecodable line and on an invalid signature.
- [ ] Nightly CI validates conformance-run traces and records the result in target/formal/proof-report.json.
- [ ] Action-coverage counters are reported, and the nightly lane fails if conformance logs project zero `Revoke` steps (vacuity guard).
- [ ] `chio trust trace-verify` runs the full flow locally against a customer-supplied log with no network access.
- [ ] Divergence triage doc section exists and the issue template link is wired into the tool's failure output.

## Risks and mitigations

- Abstraction-function bugs are the dominant risk: a wrong projection can both mask real violations and manufacture false ones. Mitigations: hand-written fixture traces in both directions (must-pass and must-diverge) gate every exporter change; the triage flow defaults to suspecting the exporter first; the mapping table lives next to the spec's own code-mapping comment (formal/tla/RevocationPropagation.tla:25-29) and both are updated in the same PR.
- Vacuous passes: a log with no revocation activity satisfies `NoAllowAfterRevoke` trivially. Mitigation: action-coverage counters with a nightly floor (at least one projected `Revoke` and one post-revocation `Evaluate`).
- Trace-length cost: Apalache checking cost grows with `--length`. Mitigation: chunk long logs into windows (default 500 steps) with carried state; window boundaries are recorded in the report. Formal soundness of chunking is an open question below.
- Interning overflow and log heterogeneity: derive PROCS/CAPS from the trace, fail closed above a sanity cap instead of silently truncating.
- Tool drift: pin Apalache 0.50.1 as the existing lanes do; version and artifact hashes are already recorded by the proof-report scripts [v].
- Customer log privacy: trace-verify is local-only; nothing uploads.

## Open questions

- Should phase 3 bundle a pinned Apalache distribution with chio-cli, or document it as an external prerequisite? (Supply-chain review needed either way.)
- The conformance suite uses a fixed clock (anchored_root.rs pins FIXED_CLOCK_EPOCH_MS, L19); does deterministic sequencing make the `MonotoneLog` projection trivially satisfied, and do we need jittered fixtures to make that check meaningful?
- Is window chunking sound for `NoAllowAfterRevoke` given `seen_epoch` is per-receipt (likely yes, since the invariant is per-entry), and how do we state that argument in the doc for `MonotoneLog` (needs cross-window ordering carried)?
- Should deny reasons project to distinguish revocation denies from scope denies, sharpening the `Evaluate` mapping?
- Should trace-verify also accept the Proof Room export bundle format as input, not just raw NDJSON?

## Manifest and registry updates

- formal/proof-manifest.toml: add `./scripts/check-receipt-trace.sh` to `gate_commands` at phase 2; add a `notes` entry stating that TLA+ specs used to discharge assumptions (MonotoneLog, ReceiptBeforeAllow) are trace-validated nightly.
- formal/MAPPING.md: new "Trace validation" section, one row per (spec, abstraction function) pair, e.g. `TraceCheckRevocationPropagation` -> `crates/tooling/chio-trace-validate/src/map/revocation.rs`, with the assumption-discharge column citing ASSUME-ED25519/ASSUME-SHA256 for the crypto-boolean projection.
- formal/theorem-inventory.json: not applicable (no Lean artifacts in this plan).
- formal/assumptions.toml: no new assumptions; the projection consumes existing ones.
- docs/reference/CLAIM_REGISTRY.md: propose claim `TRACE-VALIDATED` (approved_with_scope): "Chio's shipped TLA+ models are trace-validated against conformance receipt logs on every nightly run; customer logs can be checked with `chio trust trace-verify`." Evidence classes: `runtime_qualification`, `differential_test`. Blanket "the kernel is model-checked" phrasing stays disallowed.
