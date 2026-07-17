# chio-runtime

`chio-runtime` is Chio's runtime admission and orchestration boundary: the
public facade over `chio-runtime-core`, which implements live runtime
admission for kernel-mediated cross-vendor and swarm workflows. It forwards
every call to `chio-runtime-core`, converts its errors into a locally owned
`ChioRuntimeError`, and owns its own schema constants and store traits so the
public API can hold still while the implementation crate changes underneath
it.

Depend on `chio-runtime`, not `chio-runtime-core`, for the stable surface.
`chio-runtime-core` is the implementation; `chio-kernel` is the trusted
computing base whose `RuntimeAdmissionHook` extension point this crate's
`ChioRuntimeAdmissionHook<S>` implements.

## Responsibilities

- Re-export a curated `chio-runtime-core` surface as 60 explicit `pub type`
  aliases, with no wildcard re-export (`tests/runtime_boundary.rs` enforces
  this).
- Own 33 `CHIO_RUNTIME_*` schema constants as locally declared string
  literals rather than re-exports, decoupling the public wire-schema names
  from `chio-runtime-core`'s internal schema module (`tests/public_surface.rs`
  enforces this).
- Convert every `chio-runtime-core` error into `ChioRuntimeError` so callers
  never observe a `chio_runtime_core::ChioRuntimeError`.
- Own `ChioRuntimeAdmissionStore` and `ChioRuntimeTrustFloorStore`, the store
  traits callers implement, and adapt them into `chio-runtime-core`'s store
  traits through a private adapter.
- Implement `chio_kernel::RuntimeAdmissionHook` for `ChioRuntimeAdmissionHook<S>`
  so a configured hook can be registered with the kernel's admission
  pipeline.
- Ship five store backends: in-memory, JSON-file, SQLite-backed
  orchestration storage, and a layered combinator that splits
  admission-bundle and trust-floor storage across two backends.
- Revalidate provider bindings on parse: `runtime_provider_bindings_from_json`
  calls `validate_runtime_provider_bindings` after deserializing, rejecting
  duplicates the underlying core parser alone would accept.

## Public API

Re-exported from `chio-runtime-core` as `pub type` aliases (see `src/lib.rs`
for the complete list):

- Admission - `RuntimeAdmissionProfile`, `RuntimeAdmissionBundle`,
  `RuntimeAdmissionCheck`, `RuntimeAdmissionReport`, `SignedRuntimeAdmissionReport`.
- Trust floor - `RuntimeTrustFloorEntry`, `RuntimeTrustFloorState`,
  `RuntimeVerifierTrustBundleV4`, `SignedRuntimeVerifierTrustBundle`,
  `RuntimeTrustedVerifierKey`, `RuntimeTrustedVerifierKeysDocument`.
- Pheromone and peer weights - `RuntimePheromoneAdvisory`,
  `RuntimePheromonePolicy`, `RuntimePheromonePolicyDecision`,
  `RuntimePheromonePolicyRule`, `RuntimePeerWeight`, `RuntimePeerWeights`, and
  their `Signed*` counterparts.
- Orchestration - `RuntimeOrchestrationProfile`, `RuntimeRunContract`,
  `RuntimeOrchestrationPlan`, `RuntimeOrchestrationPlannedStep`,
  `RuntimeOrchestrationRunReport`, `RuntimeOrchestrationResumePlan`,
  `RuntimeOrchestrationStatusReport`, `RuntimeOrchestrationStepState`.
- Evidence and proof - `RuntimeEvidenceManifest`, `RuntimeEvidenceManifestEntry`,
  `RuntimeStepEvidence`, `RuntimeWorkflowRunReport`, `RuntimeOrchestrationEvidence`,
  `RuntimeOrchestrationEvidenceFailure`, `RuntimeProofRegenerationInput`,
  `RuntimeProofRegenerationReport`, `RuntimeProofParityReport`,
  `RuntimeProofParityMismatch`, `RuntimeProofDriftReport`, `RuntimeProofArtifactDrift`.
- Provider, ops and recovery - `RuntimeProviderBinding`,
  `RuntimeProviderBindingsDocument`, `RuntimeProviderHealthCheck`,
  `RuntimeProviderHealthReport`, `RuntimeProviderLoadedWeightsEvidence`,
  `WeightsBindingMode`, `RuntimeOpsStatusReport`, `RuntimeRecoveryDrillReport`,
  `RuntimeSchedulerTickReport`, `RuntimeEvidenceSinkHealthReport`.
- Retention - `RuntimeArtifactRetentionProfile`, `RuntimeArtifactRetentionPlan`,
  `RuntimeArtifactRetentionAction`.
- Supervisor and swarm - `RuntimeSupervisorProfile`, `RuntimeRunLease`,
  `SwarmAuthorityBundle` (from `chio-swarm-authority`), `TreatyRuntimeArtifactRecord`.

Owned in this crate:

- `ChioRuntimeError` - wraps the `chio-runtime-core` error; `code()` returns
  a stable `&'static str` failure code.
- `ChioRuntimeAdmissionHook<S: ChioRuntimeAdmissionStore>` - implements
  `chio_kernel::RuntimeAdmissionHook`; configure with `with_runtime_trust_input`,
  `with_pheromone_query_report`, `with_runtime_pheromone_policy`,
  `with_swarm_witness_keys`, `with_fixed_now_unix_ms`.
- `ChioRuntimeAdmissionInput` - input struct for `evaluate_runtime_admission`.
- `stores::{ChioRuntimeAdmissionStore, ChioRuntimeTrustFloorStore}` plus five
  backends: `InMemoryRuntimeAdmissionStore`, `JsonRuntimeAdmissionStore`,
  `JsonRuntimeTrustFloorStateStore`, `LayeredRuntimeAdmissionStore`,
  `SqliteRuntimeOrchestrationStore`.
- 76 `runtime_*_from_json` / `runtime_*_json` / `validate_runtime_*` /
  `generate_runtime_*` / `*_sha256` free functions, each wrapping the
  matching `chio-runtime-core` call.

## Usage

```rust
use chio_runtime::{
    ChioRuntimeAdmissionHook, InMemoryRuntimeAdmissionStore, RuntimeAdmissionProfile,
    CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA,
};

let store = InMemoryRuntimeAdmissionStore::new();
let hook = ChioRuntimeAdmissionHook::new(
    RuntimeAdmissionProfile {
        schema: CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
        profile_id: "profile-1".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
    },
    store,
);
// `hook` implements `chio_kernel::RuntimeAdmissionHook` and registers with
// the kernel's admission pipeline.
```

## Testing

`cargo test -p chio-runtime`

`tests/runtime_boundary.rs` loads swarm-authority fixtures from the repo-root
`fixtures/proof-room/swarm-authority/` directory via `include_str!`.

## See also

- `chio-runtime-core` - the implementation this crate wraps; not part of the
  stable public API.
- `chio-kernel` - the trusted computing base; defines the `RuntimeAdmissionHook`
  extension point this crate's `ChioRuntimeAdmissionHook<S>` implements.
- `chio-swarm-authority` - supplies `SwarmAuthorityBundle`, stored and served
  by the admission stores.
- `chio-weights` - supplies `card::ModelCard`, accepted by the
  model-card-aware provider health report generators.
