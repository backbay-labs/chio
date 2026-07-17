# chio-runtime-harness architecture

## Overview

`chio-runtime-harness` is a tooling crate, not a production kernel component. It
replays a scenario file through the same primitives a deployment uses (the
`chio-runtime-core` admission evaluator, a live `chio-kernel` instance, and the
`chio-attest-buyer-core` proof verifier) so a hand-maintained fixture proof package
can be checked against what the current code actually produces. It forbids
`unsafe` (`#![forbid(unsafe_code)]`) and does real, temporary file I/O rather than
running in-memory only.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public entry points (`run_runtime_loopback_scenario[_with_static_artifacts]`), `RuntimeLoopbackError`, module wiring. |
| `src/scenario.rs` | `RuntimeLoopbackScenario` / `RuntimeLoopbackStep` deserialization and single-step-vs-`steps` normalization. |
| `src/admission_loop.rs` | Per-step admission evaluation against a `JsonRuntimeAdmissionStore`, admission-report evidence, and dispatch into `kernel.rs` on acceptance. |
| `src/kernel.rs` | Builds and drives one disposable `ChioKernel` per step: capability signing, policy-input signing, federation peer pinning, and the live tool-call evaluation that produces a signed `ChioReceipt`. |
| `src/treaty.rs` | Builds and persists cross-kernel treaty scope, ladder intersection, continuation, receipt lineage, and bilateral DSSE artifacts for federated steps. |
| `src/buyer_closure.rs` | Rebuilds the buyer-side federation closure (cross-boundary admission, lineage, bilateral invocation, strict DSSE) for the qualifying destructive/governed step. |
| `src/proof_assembly.rs` | Top-level orchestration: assembles the live `ChioProofPackage`, verifies it, writes all evidence artifacts, and computes final acceptance. |
| `src/proof_parity.rs` | Field-by-field structural comparison between the static baseline package/report and the live-regenerated package. |
| `src/evidence_io.rs` | Safe relative-path validation, content-addressed JSON artifact writes, canonical-JSON hashing, and the public `runtime_loopback_capability_window`. |

## Scenario replay

1. `scenario.rs` parses and normalizes the scenario into `(run_id, Vec<RuntimeLoopbackStep>)`;
   a scenario carries either one top-level step or an explicit `steps` list, never both.
2. `lib.rs` opens a `JsonRuntimeAdmissionStore` at `store_dir/admission-store.json`.
3. `admission_loop.rs` evaluates each step in order through `evaluate_runtime_admission`,
   writing an admission-report artifact per step, and stops at the first rejection.
4. Each accepted step is dispatched through a fresh `ChioKernel` (`kernel.rs`). A step with
   an `origin_kernel_id` also gets a treaty context (`treaty.rs`), which is fed into the
   kernel's own runtime admission hook and retained for buyer closure.
5. `proof_assembly.rs` builds a `ChioProofPackage` from the captured live receipts, splices
   in a buyer closure (`buyer_closure.rs`) for the first destructive step that carries a
   governance receipt and a treaty context, and verifies the package with
   `chio_attest_buyer_core::report::verify_package_report`.
6. `proof_parity.rs` diffs the live package against the static baseline package and verifier
   report across proof claims, workflow and step semantics, tool receipt targets and
   semantics, bilateral DSSE predicate semantics, lease scope, governance-receipt presence,
   and destructive flags.
7. `proof_assembly.rs` writes every artifact as evidence JSON under `out_dir`
   (`evidence_io.rs`), then the run returns `Ok(())` only if the workflow run report itself
   accepted.

## Invariants and failure modes

- Scenario `runId` must be non-empty and unpadded; top-level single-step fields and an
  explicit `steps` list are mutually exclusive; both scenario structs deny unknown fields.
- Evidence relative paths must be plain and safe: no absolute path, no `\`, no `:`, no `//`,
  no `.`/`..` segment. Every write is content-addressed by the SHA-256 of the exact bytes
  written, including the trailing newline (`evidence_io.rs`).
- `kernel.rs` verifies a step's `server_id` / `tool_name` / `host_kernel_id` against
  `chio_attest_loopback::runtime_vendor_binding` and its recomputed argument hash against the
  request's declared `tool_args_sha256` before dispatch; kernel dispatch requires
  `Verdict::Allow`.
- `buyer_closure.rs` and `treaty.rs` each recompute the bilateral invocation binding hash
  after the lineage statement back-fill and reject if it drifted from the pre-backfill hash.
- `evaluate_cross_boundary_admission` must accept the buyer closure; rejection fails the run
  closed with its failure code.
- The final proof package must reproduce the exact live receipt hashes captured during
  execution, checked both after the baseline build and again after the buyer-closure splice.
- Workflow step count must exactly match both the admission-hash count and the admission-id
  count (`validate_step_admission_binding_counts`).
- Overall acceptance requires the live verifier report to accept and every compared parity
  field to match; the buyer-closure treaty-binding delta is the one tolerated difference. Any
  other mismatch fails closed with `runtime_proof_semantic_parity_mismatch`.
- The loopback kernel always installs durable (temp-file) SQLite receipt and revocation
  stores (`allow_ephemeral_receipt_log: false`, `allow_ephemeral_revocation_store: false`):
  the kernel dispatches fail-closed against ephemeral revocation state, so an isolated
  proof-regeneration kernel needs a durable store of its own even though it is temporary.

## Dependencies

`chio-kernel` supplies the live `ChioKernel`, `ToolServerConnection`, and tool-call
evaluation this crate drives. `chio-runtime-core` supplies the admission evaluator, treaty
and evidence types, and the `CHIO_RUNTIME_*` / `CHIO_FEDERATION_*` schema constants.
`chio-federation` supplies bilateral DSSE signing and trust establishment.
`chio-attest-buyer-core` supplies proof-package assembly and verification;
`chio-attest-loopback` supplies fixture signing keys, fixture baselines, and package
construction from live receipts. `chio-core` / `chio-core-types` supply canonical JSON
hashing, keypairs, capability tokens, and receipt signing. `chio-store-sqlite` supplies the
temporary receipt and revocation stores. No dependency is package-aliased. `tokio` runs one
current-thread executor per step to call the async kernel evaluation synchronously;
`async-trait` backs the stub `ToolServerConnection` implementation; `thiserror` backs
`RuntimeLoopbackError`.
