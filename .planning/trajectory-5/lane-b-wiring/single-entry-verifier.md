# B1: Single-entry Verifier Design

This document is the deep dive for sub-lane B1. It captures the current call graph, the target call graph, the migration sequence, the deletion plan, and the negative conformance test that proves only one production entry exists.

## Current call graph (as of release work kickoff)

`chio_kernel_core` exposes five capability-verifier entry points (`crates/chio-kernel-core/src/capability_verify.rs`):

| Entry point | Line | Production hot-path? | Subset checks performed |
|---|---|---|---|
| `verify_capability` | (line ~100, thin wrapper) | No | issuer + signature only |
| `verify_capability_with_floor` | line 148 | Indirectly (called by all others) | + crypto-floor + time + W1.2 budget admit |
| `verify_capability_with_negotiated_floor` | line ~245 | No | adds W1.3 schema-ceiling |
| `verify_capability_with_floor_and_trust_root` | line 327 | No | adds single-trust-root chain-binding (W1.1 partial) |
| `verify_capability_with_floor_and_resolver` | line 352 | No | adds resolver-driven chain-binding (full W1.1) |
| `verify_capability_full` | line 400 | YES | + W1.3 ceiling + W1.1 binding + signature/floor/time + W1.2 budget admit |

Inside `chio-kernel`, four hosted call sites currently hit different shapes:

| Caller | Line | Calls | Defect |
|---|---|---|---|
| `validate_capability_for_resource_or_prompt` | `crates/chio-kernel/src/kernel/mod.rs:2452` | `self.verify_capability_signature` (kernel-local helper, line 4005) | Skips W1.2 budget admit, W1.3 schema ceiling. |
| `evaluate_planner_step_*` | `crates/chio-kernel/src/kernel/mod.rs:2706` | `self.verify_capability_signature` | Same defect. |
| `evaluate_tool_call_blocking` (hosted dispatch) | `crates/chio-kernel/src/kernel/mod.rs:2898-2911` | `self.verify_capability_full_without_budget_admit` (line 4035) | Calls full verifier but with `NoopBudgetRegistry` at line 4045 - bypasses budget admit. |
| nested-flow dispatch | `crates/chio-kernel/src/kernel/mod.rs:3403-3416` | `self.verify_capability_full_without_budget_admit` | Same defect. |

The kernel-local helpers themselves:

- `verify_capability_signature` at `crates/chio-kernel/src/kernel/mod.rs:4005-4033`: trusted-issuer check + `cap.verify_signature_with_floor` + v2 chain-binding only. No W1.2 budget admit; no W1.3 schema ceiling. This is the legacy entry point.
- `verify_capability_full_without_budget_admit` at `crates/chio-kernel/src/kernel/mod.rs:4035-4058`: calls `chio_kernel_core::verify_capability_full` but with `let mut budgets = chio_kernel_core::NoopBudgetRegistry;` at line 4045. The signature is "full" but the runtime substitutes the no-op registry - so W1.2 sibling-sum admit never runs from this path.

The synthesis (line 28) is precise: "`verify_capability_full_without_budget_admit` and the legacy `verify_capability_signature` are still callable from `crates/chio-kernel/src/kernel/mod.rs:4005` and `:4035-4047`, defeating the T1.0 capability-negotiation Evidence Gate."

## Target call graph

After Lane B1, exactly one kernel-local thin wrapper exists:

```
ChioKernel::verify_capability_full_hosted(&self, cap, remote_kernel_id, agent_id, now) ->
    chio_kernel_core::verify_capability_full(
        cap, &self.trusted_issuer_keys(), &FixedClock::new(now),
        capability_crypto_floor(self.capability_crypto_floor),
        &self.capability_negotiation_for_remote(remote_kernel_id, now)?,
        &self.capability_trust_root_resolver_snapshot(),
        &mut *self.budget_registry.lock(),
    )
```

The four hosted call sites all route through this wrapper. `verify_capability_signature` and `verify_capability_full_without_budget_admit` are deleted from `crates/chio-kernel/src/kernel/mod.rs`.

The `chio_kernel_core` crate retains all five public entry points (`verify_capability`, `_with_floor`, `_with_negotiated_floor`, `_with_floor_and_trust_root`, `_with_floor_and_resolver`, `_full`) because they remain useful for auditor-facing isolation tests and for portable callers who construct their own `BudgetRegistry`. Only `verify_capability_full` is allowed in `chio-kernel`'s production code.

## Migration sequence

1. **release work-B1.1**: add `ChioKernel::verify_capability_full_hosted`. Place at the same `impl` block where the deleted helpers live (current `mod.rs:4005-4058`). The new method's body uses the kernel's actual `budget_registry` (held under a `Mutex`/`RwLock` already; signature and lifetime details determined at PR time).
2. **release work-B1.2**: migrate the four call sites in lockstep. The migrations:
   - `mod.rs:2452`: replace
     ```
     self.verify_capability_signature(capability)
         .map_err(|_| KernelError::InvalidSignature)?;
     ```
     with
     ```
     self.verify_capability_full_hosted(capability, None, agent_id, current_unix_timestamp())?;
     ```
     The `None` for `remote_kernel_id` reflects the resource/prompt path's no-federation-context; the agent-id check (line 2457 `check_subject_binding`) stays as-is after the wrapper.
   - `mod.rs:2706`: same pattern. Note that this is a per-step verdict path; the wrapper return value is mapped to the StepVerdict shape with the structured reason.
   - `mod.rs:2898-2911`: replace `verify_capability_full_without_budget_admit` with the new wrapper. The acceptance criterion is that the **actual** kernel registry is mutated, not a noop. The Round-3 codex P2 ordering note at `mod.rs:4080-4087` ("admit deferred until after time/revocation/subject/scope/guards") is preserved by structuring the wrapper to expose two phases: a verify-only phase (signature + chain-binding + ceiling + time) and an admit phase (budget). The wrapper is split into `verify_capability_full_hosted_pre_admit` and `verify_capability_full_hosted_admit`. Implementation detail in B1.1 PR.
   - `mod.rs:3403-3416`: same as 2898-2911.
3. **release work-B1.3**: delete the two helper bodies (`mod.rs:4005-4058`).
4. **release work-B1.4**: spec edit (PROTOCOL.md line 408 SHOULD -> MUST).
5. **release work-B1.5**: gate script `scripts/check-verify-capability-full.sh`.
6. **release work-B1.6**: negative conformance fixture.

## Deletion plan

After B1.3, the following symbols are unreachable from `chio-kernel`'s public API:

- `ChioKernel::verify_capability_signature` - was `fn(&self, cap) -> Result<(), String>`. Removed.
- `ChioKernel::verify_capability_full_without_budget_admit` - was `fn(&self, cap, remote_kernel_id, now) -> Result<(), String>`. Removed.

The `chio_kernel_core::verify_capability_with_floor` etc remain reachable for tests and external callers but are forbidden from production code by the gate script.

## Negative conformance fixture

Path: `crates/chio-conformance/tests/verify_full_is_only_production_entry.rs`.

The fixture must EXERCISE THE PRODUCTION HOT PATH and must FAIL when the wiring is removed. The trj4 erratum's failure mode (synthesis lines 9-13) was tests that passed without exercising production code. This fixture explicitly defends against that.

**Fixture structure**:

1. Build a real `ChioKernel` via the same `make_kernel` pattern as `crates/chio-conformance/tests/v2_receipt_kernel_round_trip.rs:92-115` (real `Keypair`, real `SqliteReceiptStore`, real `EchoToolServer`).
2. Construct a real `BudgetRegistry` and inject it via a hook so the fixture can OBSERVE registry mutations. Either:
   - Provide a wrapper `CountingBudgetRegistry` that delegates to the kernel's real registry but counts `try_admit_share` calls, OR
   - Use the existing kernel registry and read its admitted-share state via a `pub(crate)` accessor (B1.6 ticket adds the accessor under `#[cfg(test)]` if needed).
3. Mint a real v2 capability token via `chio-core-types::capability::sign_capability_v2` with a non-trivial sibling split (parent at 5000bps, child at 4000bps). Verify token by hand first (independent fixture-time check).
4. Call `ChioKernel::evaluate_tool_call_blocking` with the request. Assert the verdict is Allow.
5. **Critical assertion**: `CountingBudgetRegistry::try_admit_share` was called exactly once with the child's share. If the kernel routes through `verify_capability_full_without_budget_admit` (the deleted helper) the count is 0 because the noop registry was substituted - the test FAILS in that revert scenario.
6. Assertion 2: the partial-entry symbol names are NOT importable from `chio_kernel`. Try `use chio_kernel::verify_capability_signature;` - this should fail at fixture compile time. Encode this as a `compiletest_rs` or as a `#[test]` that invokes `cargo build` against a small inline test crate; B1.6 picks the simpler approach (likely a `trybuild` test).

**Reverse-test (the part that proves the fixture is real)**: in the B1.6 PR description, intentionally revert B1.2 on a draft branch and run this fixture; record that it FAILS with the structured reason "verify_capability_full was not invoked; production path used a partial verifier". This satisfies the Evidence Gate close bar.

## Why this design satisfies the Evidence Gate

- **Enforced call site**: the four sites at `mod.rs:2452`, `:2706`, `:2898`, `:3403` route exclusively through `verify_capability_full_hosted` -> `chio_kernel_core::verify_capability_full`. The two partial helpers are deleted.
- **Spec MUST citation**: PROTOCOL.md line 408 SHOULD -> MUST per B1.4.
- **Signed negative conformance test**: the fixture exercises the production hot path through `evaluate_tool_call_blocking`, observes the actual `BudgetRegistry::try_admit_share` count, and FAILS when the wiring is removed.

The lint script (`scripts/check-verify-capability-full.sh`) is a defense-in-depth: it prevents future PRs from re-introducing the partial entry from a production module. The fixture is the runtime guarantee; the lint is the static guarantee.
