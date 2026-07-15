# chio-runtime-core architecture

## Overview

`chio-runtime-core` sits inside the kernel's trust boundary, not at its edge. `ChioRuntimeAdmissionHook` implements `chio_kernel::RuntimeAdmissionHook`, so `chio-kernel` calls into this crate synchronously during tool-call dispatch, after capability, budget, and guard checks pass but before the call actually dispatches, and the hook's decision gates whether it proceeds. The crate has no transport and no async runtime: the kernel supplies the request, the wall clock (`now_unix_ms` on every call), and, through a `RuntimeAdmissionStore`, storage. Every artifact (admission bundle, treaty scope, buyer attestation packet, orchestration report, ...) is a `serde`-derived struct carrying its own `schema` string, and every admission or verification function returns a structured report (`accepted: bool`, `failure_code: Option<String>`, `checks: Vec<String>`) instead of throwing, so a rejection is itself an auditable, receipt-embeddable artifact.

## Diagram

```mermaid
flowchart TD
  subgraph kernel_sg["chio-kernel (trust boundary)"]
    kernel["Tool-call dispatch"]
  end

  subgraph hook_sg["chio-runtime-core admission hook"]
    hook["ChioRuntimeAdmissionHook.evaluate"]
    binding["RuntimeRequestBinding"]
    swarm["Swarm authority resolve and verify"]
    treaty["Treaty scope and cross-boundary admission"]
    core["evaluate_runtime_admission"]
    pheromone["Pheromone policy decision"]
    lease["Destructive lease reserve"]
    decision{"accepted"}
  end

  subgraph store_sg["RuntimeAdmissionStore (consumer trait)"]
    store["memory / json / sqlite backends"]
  end

  subgraph ext_sg["External crates and caller inputs"]
    keys["Trusted verifier and swarm witness keys"]
    swarmdep["chio-swarm-authority"]
    fed["chio-federation bilateral DSSE"]
  end

  kernel -->|"after capability, budget, guard"| hook
  hook -->|"build binding"| binding
  binding -->|"chioSwarm ref"| swarm
  binding -->|"chioTreaty ref"| treaty
  binding --> core
  swarm --> core
  treaty --> core
  swarmdep --> swarm
  fed --> treaty
  keys -->|"verify trust input"| core
  core -->|"profile, bundle, trust floor"| store
  core -->|"policy and peer weights"| pheromone
  core -->|"destructive bundle"| lease
  lease --> store
  core --> decision
  decision -->|"yes"| allow["allow plus chio_runtime receipt"]
  decision -->|"no"| deny["deny plus release reserved"]
  allow -->|"consume continuations"| store
  deny -->|"release reservations"| store
```

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Declares the modules and re-exports the public surface. `#![forbid(unsafe_code)]`. |
| `src/types.rs` | Every wire artifact as a `serde` struct: admission profile/bundle/report, verifier trust bundle, pheromone policy/advisory, treaty scope, ladder intersection, buyer attestation packet/review, orchestration profile/plan/run report, provider bindings, ops status. |
| `src/schema.rs` | `CHIO_RUNTIME_*_SCHEMA` / `CHIO_FEDERATION_*_SCHEMA` / `CHIO_ATTEST_*_SCHEMA` constants (with back-compat aliases) and `CHIO_RUNTIME_FAILURE_CODES`, the failure-code registry. |
| `src/error.rs` | `ChioRuntimeError`: `Rejected { code, detail }` plus store/IO/JSON/canonicalization variants. |
| `src/hash.rs` | Canonical-JSON SHA-256 helpers for every hashed artifact type. |
| `src/admission.rs` | `evaluate_runtime_admission`: the admission state machine (profile freshness, bundle lookup, runtime-trust-input verification and trust-floor transition, pheromone-policy evaluation, destructive-lease reservation). |
| `src/admission_hook.rs` (+ `admission_hook/`) | `ChioRuntimeAdmissionHook`. Submodules: `dsse` (bilateral DSSE treaty binding), `metadata` (denial metadata), `request` (`RuntimeRequestBinding` from `ToolCallRequest`), `store_artifacts` (typed artifact loads by hash), `swarm_authority` / `swarm_ref` (swarm delegation evidence), `treaty_evidence` / `treaty_ref` (treaty evidence resolution). |
| `src/buyer.rs` (+ `buyer/`) | Buyer-attestation packet and review-package verification. Submodules: `packet` (packet-to-treaty-evidence binding), `proof_package` (proof-package and lineage-bundle checks), `review_hydration` (parses the 14 required review artifacts), `review_package` (the full review pipeline), `runtime_report` (binds runtime run/proof-regeneration reports), `strict_dsse` (treaty-bound strict-DSSE signer verification), `helpers`. |
| `src/treaty.rs` | Federation data model and validators: treaty scope, governance ladder manifest, ladder intersection (`compute_ladder_intersection`), cross-boundary admission (`evaluate_cross_boundary_admission`), receipt lineage statement/bundle, bilateral invocation. |
| `src/orchestration.rs` | Loads and cross-validates a run's evidence directory (workflow run report, proof regeneration report, evidence manifest, verifier report) against a `RuntimeRunContract`. |
| `src/ops.rs` | Builds orchestration plans and generates operational reports: evidence-sink health, provider health (model-card and loaded-weights binding via `chio_weights` / `chio_kernel::weights_binding`), proof-drift, artifact-retention plans. |
| `src/pheromone_policy.rs` | Evaluates a signed pheromone policy, peer weights, and query report into an allow/deny/escalate `RuntimePheromonePolicyDecision`. |
| `src/serde_io.rs` | `*_from_json` / `*_json` parse-and-serialize pairs; serializers validate before emitting. |
| `src/validation.rs` (+ `validation/`) | Fail-closed structural validators split by domain: `common` (shared hash/label/non-empty checks), `evidence` (workflow/step/manifest/sink-health), `ops` (supervisor/lease/scheduler/retention/provider/ops-status), `orchestration` (profile/contract/plan/run-report/resume/status), `proof` (drift, regeneration input/report/artifacts; parity delegated to `chio-runtime-proof-parity`). |
| `src/store/` | `RuntimeAdmissionStore` trait plus implementations: `memory` (in-process `Mutex<BTreeMap>`), `json` (single JSON file, validated on every write), `trust_floor` (JSON-file trust-floor-only store), `traits::LayeredRuntimeAdmissionStore` (composes a separate admission store and trust-floor store). |
| `src/store/sqlite/` | `SqliteRuntimeOrchestrationStore`: WAL-mode SQLite backing both `RuntimeAdmissionStore` and the orchestration surface (runs, step states, leases, scheduler ticks, recovery drills, evidence artifacts, treaty artifacts, swarm authority bundles, provider/evidence-sink health), split across `admission_replay`, `runs_steps`, `leases_scheduler`, `evidence_artifacts`, `treaty_artifacts`, `swarm_authority_bundles`, `trust_floors`, `health_summaries`, `schema_migrations`. |

## Admission lifecycle

1. The kernel evaluates a `ToolCallRequest` and calls `ChioRuntimeAdmissionHook::evaluate`.
2. The hook reads the `chioAdmission` context (required once any Chio runtime context is present) and the optional `chioSwarm` / `chioTreaty` context, builds a `RuntimeRequestBinding`, and, if a bundle hash was pinned in the request, checks it against the store.
3. If a swarm reference is present, the hook resolves and verifies the referenced `SwarmAuthorityBundle` (delegation witness chain, route-plan and route-metadata match, revocation epoch, budget pool) and marks its continuation for consumption.
4. If a treaty reference is present, the hook resolves treaty scope and ladder intersection from the store, optionally verifies cross-kernel continuation, receipt-lineage bundle, bilateral invocation, and bilateral DSSE evidence, calls `evaluate_cross_boundary_admission`, and marks the treaty continuation for consumption.
5. `evaluate_runtime_admission` runs the core checks: profile schema and freshness, bundle presence and schema, runtime-trust-input verification and trust-floor transition, host-kernel match, request-binding match, pheromone-policy evaluation, and, for destructive bundles, lease reservation gated on a governance receipt.
6. On rejection the hook releases whatever it already reserved (destructive lease, swarm continuation, treaty continuation) before returning `deny`; on acceptance it consumes the continuations and returns `allow` with receipt metadata under the `chio_runtime` key.
7. If the kernel denies or cleans up the call before dispatch, it calls `release_reserved` with that receipt metadata to release the destructive lease and any treaty/swarm continuation; a failure discovered after dispatch deliberately skips `release_reserved` and leaves reservations in place, fail-closed, since a side effect may already have run.

## Boundaries

- No transport and no async runtime: the crate is synchronous, plain Rust plus SQLite (`rusqlite`, bundled); the kernel owns HTTP/stdio and calls in.
- No wall-clock reads for correctness: every evaluation takes `now_unix_ms` from the caller.
- No key management: signature verification consumes `PublicKey`s the caller already resolved as trusted (trusted verifier keys, treaty participant keys, swarm witness keys); this crate does not look up or rotate keys.

## Invariants and failure modes

- `#![forbid(unsafe_code)]`, and the workspace's `unwrap_used = "deny"` / `expect_used = "deny"` clippy lints hold with no crate-level overrides; there is no `unwrap`, `expect`, or `unsafe` in `src/`.
- Destructive admission bundles must carry both a `lease_id` and a `governance_receipt_id`; the destructive lease is reserved (single-consume, replay-rejected) before a report is returned accepted.
- Runtime trust-floor entries only move forward: reusing a version requires an identical bundle hash, advancing a version requires `previous_hash_sha256` to chain from the currently persisted floor hash, and version zero is rejected both when a runtime trust input is validated (`runtime_trust_version_zero`) and when a trust-floor entry reaches any store (`runtime_trust_floor_version_zero`).
- Pheromone-policy evaluation is all-or-nothing: supplying only one of policy or peer weights is rejected, and once both are supplied a runtime trust input and a signed query report become mandatory too; a destructive bundle additionally requires policy, peer weights, and query report to be present at all (`runtime_pheromone_required_for_destructive`).
- The `RuntimeAdmissionStore` trait's default `consume_treaty_continuation` / `consume_swarm_continuation` reject with an unsupported-store error; every bundled store overrides them as single-consume, replay-rejected operations.
- Buyer-attestation review is fail-closed across the 14-artifact chain: a hash mismatch anywhere (packet, lineage statement/bundle, continuation, admission report, bilateral invocation/DSSE, workflow receipt, proof package, verifier report, proof-regeneration report/input, evidence manifest) rejects with a specific `chio_buyer_review_*` code, and the trust-context-free entry point (`verify_buyer_attestation_review_package`) always terminates in a `chio_buyer_review_strict_dsse_signer_mismatch` rejection once it reaches the trust-bundle-dependent checks; only `verify_buyer_attestation_review_package_with_trust` can accept.
- Evidence paths are always validated as safe relative paths (`validate_relative_evidence_path`): no absolute paths, `.`/`..` segments, backslashes, or repeated separators, shared by evidence-manifest validation, orchestration evidence loading, proof-drift artifact paths, and SQLite evidence-artifact recording.
- The SQLite store opens with WAL journaling and `synchronous = FULL`, and enforces the same replay and uniqueness invariants as the in-memory and JSON stores via `INSERT OR IGNORE` and primary keys rather than duplicating validation logic.

## Dependencies

Internal: `chio-attest-buyer-core` (verifier-report, proof-package, and trust-bundle parsing for buyer review), `chio-core-types` (canonical JSON, hashing, signing envelopes, `PublicKey`), `chio-federation` (`bilateral_dsse` / `bilateral_verifier`), `chio-kernel` (`RuntimeAdmissionHook` trait, `ToolCallRequest`, `KernelError`, `weights_binding` evaluation), `chio-runtime-proof-parity` (`RuntimeProofParityReport` / `RuntimeProofParityMismatch` and their validator), `chio-swarm-authority` (`SwarmAuthorityBundle`, `verify_swarm_authority_bundle`), `chio-weights` (`ModelCard`). Dev-only: `chio-attest-loopback` (buyer-review test fixtures), `base64` / `chrono` / `tempfile` (test support). External: `rusqlite` (bundled SQLite, the orchestration store), `serde` / `serde_json` (every artifact), `thiserror` (`ChioRuntimeError`). No dependency is aliased; every `chio-*` Cargo dependency name matches the crate name used in source.

## Extension points

- `RuntimeAdmissionStore` (and `RuntimeTrustFloorStore`) is the trait a caller implements to plug in a different persistence backend; `LayeredRuntimeAdmissionStore` composes an admission store with a separate trust-floor store when they should not share a backend.
- `ChioRuntimeAdmissionHook<S>` is generic over any `S: RuntimeAdmissionStore + Send + Sync`, making it the extension point for wiring a custom store into `chio_kernel::RuntimeAdmissionHook`.
