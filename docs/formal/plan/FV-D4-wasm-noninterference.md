# FV-D4: Non-interference at the wasm guard boundary, plus structure-aware module fuzzing

Status: Proposed (2026-07-09)
Theme: D - Widen the verified frontier
Effort: M-L
Depends on: none (fuzz registration mechanics follow [FV-E4](FV-E4-fuzz-plumbing-repair.md))
Feeds: [FV-E4](FV-E4-fuzz-plumbing-repair.md) (one more target through the repaired plumbing), [FV-C5](FV-C5-proof-coverage-map.md) (guard-boundary coverage row)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G6), `crates/guards/chio-wasm-guards/src/`, `formal/lean4/Chio/Chio/Core/Protocol.lean`

## Summary

Guest wasm is the only Turing-complete attacker-supplied input the kernel's decision pipeline consumes, and today its influence on the verdict is constrained by code comments and eight fuzz seed classes, not by a stated theorem. This document does two things. Part 1 models the host-call boundary in Lean (`Chio/Guards/WasmBoundary.lean`): host decision inputs, the guest-visible projection (the declared `GuardRequest` fields), and a typed guest-output channel, with three theorems - guest-output confinement (the evaluation outcome depends on guest bytes only through the typed verdict channel, and malformed output collapses to deny), no-allow-amplification (guest output can never flip `core_authorized = false` into an allow, extending the existing `guardPipeline_allow_requires_core_authorized`), and resource-exhaustion fail-closure (fuel and memory exhaustion map to deny/error, never allow). Every model arm is grounded in dispatch code read and line-cited this session. Part 2 adds a structure-aware fuzz target (`wasm_guard_smith`) that uses wasm-smith to generate valid-but-arbitrary guard-shaped modules and asserts no-panic, fail-closed verdicts, and enforced resource limits. We are explicit about scope: this is a boundary model plus fail-closed theorems over Chio's own dispatch code; full information-flow verification of wasmtime is out of scope and the engine becomes a named trust dependency.

## Motivation and evidence

- The fail-closed story currently lives in comments and match arms. Verified this session in `crates/guards/chio-wasm-guards/src/runtime/wasmtime_backend.rs`: the verdict decode maps `VERDICT_ALLOW`/`VERDICT_DENY` and fails closed on ANY other return value (`evaluate`, L685-708, "Unexpected return value -- fail closed"); fuel exhaustion becomes `WasmGuardError::FuelExhausted` (L663-678); and in `crates/guards/chio-wasm-guards/src/runtime/guard.rs` the `Guard` impl denies on malformed host-side action extraction (L331-339) and on any inner wasm execution error ("Fail closed: any error during WASM execution denies", L399-413). None of this is stated once, centrally, as a property; a refactor of any one match arm silently weakens the boundary.
- One deliberate exception exists and must be modeled, not hidden: advisory guards return allow on deny AND on error (guard.rs L381-388, L408-412). Any theorem that ignores the advisory flag would be false; any prose that omits it would be dishonest.
- The pipeline-level theorems stop one layer too early. `guardPipeline_deny_dominates`, `guardPipeline_error_dominates`, `guardPipeline_allow_requires_core_authorized` (`formal/lean4/Chio/Chio/Proofs/Protocol.lean` L146, L151, L156) constrain the fold over `GuardResult`s (`Core/Protocol.lean` L101-111), but nothing connects "what a malicious guest can emit" to "which `GuardResult` the pipeline sees". FV-D4 is exactly that connecting layer.
- The fuzz surface is good but structure-blind at the execution stage. `fuzz/fuzz_targets/wasm_guard_escape.rs` seeds cover eight escape classes (undeclared_imports, oversize_memory, fuel_exhaustion, table_grow_abuse, deep_recursion, host_reentry, malformed_component, signed_but_malicious); `wit_host_call_boundary.rs` covers `GuardRequest`/`GuestDenyResponse` serde. Raw-byte mutation of wasm rarely survives validation long enough to explore post-validation behavior; wasm-smith generates modules that validate by construction, which is where the interesting evaluate-path behavior lives.

## Current state

Runtime dispatch (all read this session):

- `WasmtimeBackend::evaluate` (`runtime/wasmtime_backend.rs` L567-723): fresh `Store` per evaluation with a memory limiter (L579-582), fuel set from the loaded limit (L583-585), request serialized and written into guest memory, guest `evaluate(ptr, len) -> i32` invoked, result decoded per the L685-708 match. The guest-visible input is exactly the serialized `GuardRequest` (`abi.rs` L29) plus the host functions.
- Deny-reason readback: `read_structured_deny_reason` (L747-784) - every error path returns `None` ("fail closed with no reason rather than crashing"); a malformed `GuestDenyResponse` (`abi.rs` L133) degrades to a plain-string attempt and then to no reason; the verdict remains deny throughout.
- Host state and limits: `WasmHostState::with_memory_limit` (`host.rs` L98) with `trap_on_grow_failure(true)` (L120) so `memory.grow` beyond the cap traps (doc, L96-98). Host imports are the small log/config/time/blob set registered in `host.rs`.
- Kernel-facing mapping: `WasmGuard::evaluate` (`runtime/guard.rs` L329-415): malformed action extraction denies before any wasm runs (L331-339); a load-layer error propagates as `Err(KernelError)` to the pipeline (L352-358), where the pipeline's error-dominates theorem takes over; verdicts map allow->allow, deny->deny, inner error->deny, each with the advisory carve-out.
- The ABI verdict channel is an `i32` return code (`VERDICT_ALLOW = 0`, `VERDICT_DENY = 1`, `abi.rs` L15-18); `fuzz.rs` correctly notes `GuardVerdict` itself never crosses the boundary as serialized data.

Fuzzing: `fuzz/target-map.toml` entries `[targets.wit_host_call_boundary]` (L174) and `[targets.wasm_guard_escape]` (L184), both triggered by `crates/guards/chio-wasm-guards/**`; the file header (L8-10) requires lockstep with `.clusterfuzzlite/build.sh` and `fuzz/oss-fuzz/build.sh`. [FV-E4](FV-E4-fuzz-plumbing-repair.md) owns that checklist and the G6 leak repairs.

Formal: nothing under `formal/` mentions the wasm boundary; `proof-manifest.toml` `excluded_surfaces` (L145-151) does not name the wasm engine at all, which is a registry gap this plan closes.

## Design

### Part 1: the boundary model (`formal/lean4/Chio/Chio/Guards/WasmBoundary.lean`)

Types:

```
structure HostInputs where            -- what the host already decided
  coreAuthorized : Bool
  advisory : Bool

structure GuestVisible where          -- projection of GuardRequest (abi.rs L29)
  toolName : String
  agentId : String
  actionType : Option String          -- "malformed_arguments" is host-derived
  -- arguments elided: opaque to the model, irrelevant to the theorems

inductive GuestOutput where           -- the ONLY channel guest bytes influence
  | verdictAllow
  | verdictDeny (reason : Option String)   -- None models malformed/absent GuestDenyResponse
  | verdictUnknown (code : Int)            -- any i32 outside {0, 1}
  | trap
  | fuelExhausted
  | memoryExhausted                        -- grow-beyond-cap trap (host.rs L120)
```

Interpretation, mirroring guard.rs L368-413 and wasmtime_backend.rs L663-708 arm for arm:

```
def interpret (h : HostInputs) : GuestOutput -> GuardResult
  | .verdictAllow      => .allow
  | .verdictDeny _     => if h.advisory then .allow else .deny
  | .verdictUnknown _  => if h.advisory then .allow else .deny   -- Err(Trap) -> error path -> deny
  | .trap | .fuelExhausted | .memoryExhausted =>
      if h.advisory then .allow else .deny
```

The arm-by-arm citation table below is the model's grounding contract; it lands verbatim in the Lean file header and is what phase 3's tripwire tests pin (all locations verified this session):

| `GuestOutput` constructor | Producing Rust arm | Consuming Rust arm | Decision (blocking) |
| --- | --- | --- | --- |
| `verdictAllow` | `wasmtime_backend.rs` L686 (`VERDICT_ALLOW`) | `guard.rs` L369-377 | allow |
| `verdictDeny (some r)` | L687-701 (structured or offset-64K reason) | `guard.rs` L378-397 | deny |
| `verdictDeny none` | `read_structured_deny_reason` error paths, L747-784 | `guard.rs` L378-397 (default reason string) | deny |
| `verdictUnknown c` | L702-707 (`Err(Trap)`, "fail closed") | `guard.rs` L399-413 | deny |
| `trap` | L676 (`WasmGuardError::Trap`) | `guard.rs` L399-413 | deny |
| `fuelExhausted` | L663-678 (`WasmGuardError::FuelExhausted`) | `guard.rs` L399-413 | deny |
| `memoryExhausted` | `host.rs` L120 (`trap_on_grow_failure(true)`) via the trap path | `guard.rs` L399-413 | deny |
| (host-side malformed action extraction; no wasm runs) | n/a | `guard.rs` L331-339 | deny |

(The load-layer `Err(KernelError)` path, guard.rs L352-358, is modeled at the pipeline level as `GuardResult.error`, where `guardPipeline_error_dominates` already applies; the model comment cites the split.)

Theorems:

(a) `guest_output_confinement`: the guard's contribution to the pipeline is `interpret h o` - a total function of the typed output alone - so for any two guest executions with equal typed outputs, the decisions are equal: `o1 = o2 -> interpret h o1 = interpret h o2` stated over the full evaluation composition, plus the collapse lemma `interpret h (.verdictDeny none) = interpret h (.verdictDeny (some r))` and, for blocking guards, `interpret { h with advisory := false } (.verdictUnknown c) = .deny`. The modeling claim being made (and documented in the file header): the Rust dispatch constructs its `GuardDecision` from the decoded i32 and error class only, verified at the cited match arms; guest memory, logs, and the deny-reason string affect telemetry, never the decision (`read_structured_deny_reason` returns into the reason field only, L747-784).

(b) `no_allow_amplification`: for ALL `h` and `o` (advisory included), `guardPipelineAllows false (gs ++ [interpret h o] ++ gs') = false`. This is a corollary of `guardPipeline_allow_requires_core_authorized` (Proofs/Protocol.lean L156) instantiated at the wasm-interpreted result: since `guardPipelineAllows` conjoins `coreAuthorized` (Core/Protocol.lean L110-111), no guest output, including in advisory mode, can convert an unauthorized call into an allow. Stated and proved here so the wasm-specific claim has its own inventory row.

(c) `resource_exhaustion_fail_closed`: for blocking guards, `interpret h .fuelExhausted = .deny` and `interpret h .memoryExhausted = .deny` and `interpret h .trap = .deny`; never `.allow`. Grounded at wasmtime_backend.rs L663-678 (fuel), host.rs L96-120 (memory trap), guard.rs L399-413 (both land in the deny arm). The advisory-mode complement `interpret { advisory := true } _ = .allow` is stated as its own named lemma `advisory_mode_is_nonblocking_by_design` so the carve-out is a theorem, not a footnote.

Honesty boundary (stated in the file header, mirroring the chio-anchor harness discipline): this model proves properties of Chio's dispatch logic given that wasmtime delivers the i32/trap/fuel semantics it documents. Compiler bugs, JIT miscompiles, or sandbox escapes inside wasmtime are NOT covered; they become the registered engine assumption below, with the escape-class fuzzing plus the new wasm-smith target as the empirical layer against exactly that residual.

### Part 2: structure-aware fuzzing (`wasm_guard_smith`)

New target driving `WasmtimeBackend::load_module` then `evaluate` with wasm-smith-generated inputs:

- Generation: `wasm_smith::Module` from the fuzzer's `Unstructured`, configured toward guard shape: exported linear memory, an exported `evaluate (i32, i32) -> i32` (via wasm-smith's export-forcing configuration where the pinned version supports it; otherwise a deterministic post-generation splice that renames or appends a conforming export - the splice must re-validate with wasmparser before use so the "valid by construction" property is preserved). A byte of the input selects core-module vs component encoding to also exercise `ComponentBackend`.
- Assertions per iteration (this target asserts semantics, unlike the existing no-panic-only targets): (1) no panic/abort anywhere; (2) if `load_module` accepts and `evaluate` returns `Ok(verdict)`, the verdict is exactly `Allow` or `Deny` (type-total by construction, asserted anyway as a tripwire); (3) any `Err` is one of the named `WasmGuardError` variants; (4) `last_fuel_consumed() <= fuel_limit`; (5) with a small memory cap configured, no successful evaluation reports guest memory beyond the cap; (6) fail-closed mapping: interpreting the outcome with `advisory = false` through a local copy of the guard.rs mapping never yields allow unless the guest returned `VERDICT_ALLOW`.
- Registration follows the [FV-E4](FV-E4-fuzz-plumbing-repair.md) checklist verbatim (target-map entry, both build scripts, seed corpus, owners); this doc defers those mechanics and only fixes the target's name, crate (`chio-wasm-guards`), triggers (`crates/guards/chio-wasm-guards/**`, `spec/schemas/wasm-guard/**`), and the wasm-smith/arbitrary dependency additions to the standalone fuzz workspace.

## Implementation plan

1. Model skeleton. Add `formal/lean4/Chio/Chio/Guards/WasmBoundary.lean` (types, `interpret`, theorems (a)-(c), `advisory_mode_is_nonblocking_by_design`, header with the arm-by-arm Rust citation table); add to `formal/lean4/Chio/Chio.lean` and `proof-manifest.toml` `root_modules`.
2. Pipeline hookup. Extend `formal/lean4/Chio/Chio/Proofs/Protocol.lean` (or the new file) with `no_allow_amplification` stated against `guardPipelineAllows`; no changes to existing theorem statements.
3. Rust-side tripwires. Add `#[test]`s in `crates/guards/chio-wasm-guards/src/runtime/guard.rs` tests (or `wasmtime_backend_tests.rs`) that pin the arm-for-arm mapping the model cites: unknown verdict code denies (blocking), fuel exhaustion denies (blocking), advisory allows on error; each test comment names the Lean theorem it grounds. These keep model-code drift visible PR-time without any Lean toolchain (the G1-era stopgap).
4. Fuzz target. Add `fuzz/fuzz_targets/wasm_guard_smith.rs` plus a `fuzz_wasm_guard_smith` entry point in `crates/guards/chio-wasm-guards/src/fuzz.rs` (keeping the target file thin like the existing two); add wasm-smith to the fuzz workspace `fuzz/Cargo.toml`; seed corpus `fuzz/corpus/wasm_guard_smith/` bootstrapped from a handful of generated-and-minimized modules.
5. Plumbing registration. `fuzz/target-map.toml` entry plus `.clusterfuzzlite/build.sh` and `fuzz/oss-fuzz/build.sh` additions, executed via the [FV-E4](FV-E4-fuzz-plumbing-repair.md) checklist (single change set, per the target-map header rule at L8-10).
6. Assumption registration. Add the wasm engine row to `formal/assumptions.toml` and mirror in `excluded_surfaces`/notes (see Manifest section); update `formal/MAPPING.md` if any new named property is grep-enforced.

## CI and gating changes

- Lean additions ride `./scripts/check-formal-proofs.sh` (existing gate command). No new workflow.
- The new fuzz target enters `cflite_pr.yml` changed-target sampling automatically via its target-map `triggers` (that is the mechanism the map exists for) and the nightly rotation via `cflite_batch.yml`; ClusterFuzzLite and oss-fuzz build lists are updated in the same change set per the lockstep rule.
- The Rust tripwire tests ride `cargo test --workspace` (PR-time, cheap).
- No gating promotion is proposed here; if the smith target proves high-signal, [FV-E5](FV-E5-lane-ratchets.md) owns any ratchet.

## Acceptance criteria

- [ ] `WasmBoundary.lean` is root-imported, sorry-free, and its header contains the arm-by-arm citation table mapping every `GuestOutput` constructor to a verified Rust match arm (file plus line at time of landing).
- [ ] Theorems (a), (b), (c) plus the advisory lemma are proved and inventory-registered.
- [ ] The advisory carve-out is stated as a theorem and mentioned in the doc/prose wherever fail-closure is claimed (no unqualified "wasm guards fail closed" claim survives review).
- [ ] Rust tripwire tests exist for: unknown verdict code, fuel exhaustion, memory-grow trap, malformed `GuestDenyResponse` (deny retained, reason None), advisory-error-allows; each names its Lean counterpart.
- [ ] `wasm_guard_smith` runs locally (10^5 iterations without panic), asserts all six per-iteration properties, and is registered in target-map plus both build scripts in one change set.
- [ ] The wasm engine trust dependency is registered (assumptions.toml row landed, or the explicit decision to fold it into ASSUME-SUBPROCESS-ISOLATION recorded with rationale).
- [ ] At least one deliberately broken mapping variant (flip the unknown-verdict arm to allow in a test-only copy) is shown to be caught by the tripwire tests (falsifiability).

## Risks and mitigations

- Model-code drift: the Lean `interpret` is a manual mirror of two match statements. Mitigation: the phase-3 tripwire tests are the PR-time bond between them; [FV-A4](FV-A4-mirror-drift-hashes.md)-style hash pinning of the two Rust functions can be added if drift recurs.
- wasm-smith cannot force the exact export shape in the pinned version. Mitigation: the splice-then-revalidate fallback is specified up front; if neither works, the target degrades to config-forced exported functions with random names plus a host-side export probe, still asserting no-panic and limits.
- Fuzz iteration cost: instantiating wasmtime per input is expensive. Mitigation: reuse the process-wide engine exactly as `fuzz.rs` already does (OnceLock engine, L48-66); cap generated module size via wasm-smith config; accept a lower exec/s for a higher-value target.
- The advisory mode is a standing soft spot: a misconfigured advisory=true on a load-bearing guard nullifies (c). Mitigation: out of scope for the model, but flagged to policy review; the named lemma makes the risk searchable.
- Reentry and host-import abuse (two of the eight escape classes) are only lightly touched by the model, which treats host imports as opaque. Mitigation: they remain covered by `wasm_guard_escape` seeds; the model header lists them as empirically-covered-only.

## Open questions

- Register the engine as a NEW assumption id (proposed `ASSUME-WASM-ENGINE`, class `audited_platform`: "wasmtime enforces its documented fuel, memory-limiter, and trap semantics for guest code") or widen ASSUME-SUBPROCESS-ISOLATION? The guards run in-process, so reusing the subprocess assumption would be a stretch; new id proposed, decision at phase 6.
- Should `GuestVisible` grow the full `GuardRequest` field list now, or stay minimal until a confidentiality-style theorem (host state NOT in the projection never influences guest-visible bytes) is attempted? Minimal now; the confidentiality direction is real non-interference and is deliberately deferred.
- Component-model path: `ComponentBackend`'s typed WIT verdict decode should eventually get the same arm-by-arm citation treatment; this plan cites the core-module backend it verified and leaves the component table as a named follow-up in the file header.

## Manifest and registry updates

- `formal/proof-manifest.toml`: `root_modules` += `formal/lean4/Chio/Chio/Guards/WasmBoundary.lean`; `excluded_surfaces` += an explicit wasmtime-internals line; note added pointing P3's guard-pipeline row at the new boundary theorems.
- `formal/assumptions.toml`: add `ASSUME-WASM-ENGINE` (or the recorded fold-in decision), mapped to P3.
- `formal/theorem-inventory.json`: rows for (a), (b), (c), and the advisory lemma; `mapsTo: ["P3"]` (fail-closed evaluation is the property family these serve).
- `formal/MAPPING.md`: no TLA/Kani rows; add informational Lean cross-references only if the file's conventions call for them.
- `docs/reference/CLAIM_REGISTRY.md`: no new claim id; any future "guest code cannot influence authorization beyond its typed verdict" release claim must cite theorem (a)/(b) plus the advisory lemma and the engine assumption.
- `fuzz/target-map.toml`: new `[targets.wasm_guard_smith]` entry (crate, path, triggers, seeds, notes), in lockstep with both build scripts per [FV-E4](FV-E4-fuzz-plumbing-repair.md).
