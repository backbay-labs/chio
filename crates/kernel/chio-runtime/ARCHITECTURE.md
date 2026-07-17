# chio-runtime architecture

## Overview

`chio-runtime` is a stability facade, not an implementation. `chio-runtime-core`
implements live runtime admission, trust-floor tracking, orchestration
planning, evidence and proof handling, and provider health for
kernel-mediated cross-vendor and swarm workflows; `chio-runtime` forwards
every call to it. `chio-kernel` is the trusted computing base and owns the
`RuntimeAdmissionHook` extension point; `chio-runtime`'s
`ChioRuntimeAdmissionHook<S>` implements that trait so a configured hook can
be registered with the kernel's admission pipeline. The crate itself performs
no I/O and holds no state beyond hook configuration; every store operation
and file/database access happens inside `chio-runtime-core`.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public facade: 60 `pub type` aliases onto `chio_runtime_core` types, 33 owned `CHIO_RUNTIME_*` schema constants, `ChioRuntimeAdmissionHook<S>`, `ChioRuntimeError`, `ChioRuntimeAdmissionInput`, and 76 wrapped parse / validate / sign / generate / hash functions. |
| `src/stores.rs` | `ChioRuntimeAdmissionStore` and `ChioRuntimeTrustFloorStore` traits; five store backends (`InMemoryRuntimeAdmissionStore`, `JsonRuntimeAdmissionStore`, `JsonRuntimeTrustFloorStateStore`, `LayeredRuntimeAdmissionStore`, `SqliteRuntimeOrchestrationStore`); the crate-private `RuntimeCoreAdmissionStoreAdapter` that lets a Chio store satisfy `chio_runtime_core::RuntimeAdmissionStore`. |

## Call boundary

Every public function, with two exceptions, follows the same shape: call the
same-named `chio_runtime_core` function, then pass the result through
`wrap_runtime`, which maps `Err(chio_runtime_core::ChioRuntimeError)` into
`ChioRuntimeError { code, source }` and preserves `source.code()` as the
public `code()`. `unwrap_runtime` runs the reverse conversion at the point
where `chio-runtime-core` calls back into a Chio-owned store through
`RuntimeCoreAdmissionStoreAdapter`.

`validate_runtime_orchestration_evidence_binding` and
`validate_runtime_orchestration_evidence_integrity` bypass the wrapper and
return `RuntimeOrchestrationEvidenceFailure` directly; `runtime_orchestration_evidence_is_fresh`
is infallible and returns `bool`.

`runtime_provider_bindings_from_json` adds a step `chio-runtime-core`'s own
parser does not perform: after `serde_json` deserialization it calls
`validate_runtime_provider_bindings`, so a well-formed but semantically
invalid payload (for example two bindings sharing a `providerId`) is
rejected before it reaches the caller.

Admission hook evaluation rebuilds the core hook on every call.
`ChioRuntimeAdmissionHook::evaluate` and `::release_reserved` both call a
private `core_hook()` that clones the current configuration (trust input,
pheromone policy and peer weights, swarm witness keys, fixed clock) into a
fresh `chio_runtime_core::ChioRuntimeAdmissionHook` wrapping a
`RuntimeCoreAdmissionStoreAdapter` that borrows `self.store`, then delegates
to it.

## Invariants and failure modes

- `#![forbid(unsafe_code)]` at the crate root.
- No wildcard re-export of `chio_runtime_core` and no direct re-export of its
  schema constants (`tests/runtime_boundary.rs`, `tests/public_surface.rs`).
- `ChioRuntimeAdmissionHook<S>` is bounded by the Chio-owned
  `ChioRuntimeAdmissionStore`, never by `chio_runtime_core`'s store traits.
- `ChioRuntimeTrustFloorStore` has a blanket impl for any
  `T: ChioRuntimeAdmissionStore + ?Sized`, so every admission store is usable
  wherever a trust-floor store is required.
- `LayeredRuntimeAdmissionStore` routes its three trust-floor methods to a
  separate `&dyn ChioRuntimeTrustFloorStore` and every other method to a
  `&dyn ChioRuntimeAdmissionStore`, so admission-bundle and trust-floor state
  can live in different backends.
- `JsonRuntimeAdmissionStore` and `SqliteRuntimeOrchestrationStore` share one
  `ChioRuntimeAdmissionStore` implementation via the
  `impl_chio_runtime_admission_store_for_inner!` macro.
- `SqliteRuntimeOrchestrationStore` is the fullest backend: beyond the
  `ChioRuntimeAdmissionStore` surface it records run and step state and
  evidence artifacts, reports status, recovery drills, and scheduler ticks,
  and grants fenced run leases (`acquire_run_lease`, `heartbeat_run_lease`).
- All five store wrapper types implement `Debug`
  (`runtime_public_store_wrappers_are_debuggable` in `tests/runtime_boundary.rs`);
  `JsonRuntimeTrustFloorStateStore`, `LayeredRuntimeAdmissionStore`, and
  `SqliteRuntimeOrchestrationStore` use a hand-written `finish_non_exhaustive`
  impl that omits the wrapped internals.

## Dependencies

- `chio-runtime-core` - the implementation this crate wraps: admission,
  trust-floor, orchestration, pheromone policy, evidence, provider health,
  and retention logic, plus the concrete store backends.
- `chio-core-types` - `crypto::Keypair` for `sign_runtime_admission_report`;
  `PublicKey` for `ChioRuntimeAdmissionHook::with_swarm_witness_keys`.
- `chio-kernel` - defines `RuntimeAdmissionHook`, `RuntimeAdmissionContext`,
  and `RuntimeAdmissionDecision`; `ChioRuntimeAdmissionHook<S>` implements
  `RuntimeAdmissionHook` so the kernel can call into this crate as an
  admission-hook plugin.
- `chio-swarm-authority` - `SwarmAuthorityBundle`, stored and returned by the
  admission stores for swarm continuation admission.
- `chio-weights` - `card::ModelCard`, accepted by
  `generate_runtime_provider_health_report_with_model_cards` and
  `generate_runtime_provider_health_report_with_model_card_evidence`.
- `serde` / `serde_json` - the `Serialize` bound on store insert helpers and
  JSON (de)serialization throughout.

## Extension points

- Implement `ChioRuntimeAdmissionStore` to back admission bundles, treaty and
  swarm continuations, destructive leases, and trust-floor entries with a
  custom backend; `ChioRuntimeTrustFloorStore` comes for free through the
  blanket impl.
- Wrap any `ChioRuntimeAdmissionStore` in `ChioRuntimeAdmissionHook::new` and
  register the hook with `chio-kernel` as a `RuntimeAdmissionHook`
  implementation.
