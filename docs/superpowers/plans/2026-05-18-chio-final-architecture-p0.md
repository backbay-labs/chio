# Chio Final Architecture P0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the first P0 final-architecture gap by making live pheromone runtime policy loading schema-first and fail-closed when scarcity policy material is absent or implicit.

**Architecture:** Live receiver admission must validate the transit policy document against the Chio pheromone JSON schema before serde conversion. The runtime policy path must require explicit `scarcityPolicies` and explicit `newcomerHorizonEpochs`; compatibility defaults are allowed only for non-live historical verification paths.

**Tech Stack:** Rust, serde, serde_json, jsonschema, chio-pheromone, chio-pheromone-runtime, chio-spec-validate, shell schema gates.

---

## Current Gap Ranking

### P0

- Live runtime policy parsing still accepts missing `scarcityPolicies` through serde defaulting.
- `PheromoneScarcityPolicy` still has a Rust-side default for `newcomerHorizonEpochs`.
- Runtime policy parsing does not validate against `spec/schemas/chio-pheromone/v1/transit-policy.schema.json` before serde.
- Scarcity policy selection is not yet receiver-owned active-window selection with deterministic `windowId` recomputation.
- Observation-cost commitment verification is still field binding, not signed statement plus RFC 6962 inclusion proof.
- `spec/schemas/chio-pheromone/v1/scarcity-policy.schema.json` is untracked and absent from `spec/schemas/MANIFEST.sha256`.

### P1

- Chio-native CLI paths currently normalize into `ChioCommands`.
- Public `chio` remains visible as a normal compatibility command.
- Buyer ownership remains in `chio-runtime-core`.

### P2

- Chio-native artifact IDs and registry `artifactKind` values are only partially cut over.
- Script and fixture roots remain Chio-named except for compatibility cases.

### P3

- Final crate/module convergence has not yet split `chio-runtime-core` into `chio-attest-buyer` and Chio-native runtime ownership.

---

### Task 1: Add Runtime Schema-First Red Tests

**Files:**
- Modify: `crates/chio-pheromone-runtime/tests/runtime_receiver.rs`

- [x] **Step 1: Add failing tests**

Add tests that remove `admission.scarcityPolicies`, remove `newcomerHorizonEpochs`, and add an unknown admission field in the fixture transit policy, then assert `runtime_policy_from_json` rejects each document before live receive.

- [x] **Step 2: Verify red**

Run:

```bash
cargo test -p chio-pheromone-runtime runtime_policy_loader_rejects --test runtime_receiver
```

Expected: fail because the loader currently accepts missing policy defaults and does not run JSON schema validation first.

### Task 2: Implement Schema-First Runtime Policy Loading

**Files:**
- Modify: `crates/chio-pheromone-runtime/Cargo.toml`
- Modify: `crates/chio-pheromone-runtime/src/lib.rs`
- Modify: `crates/chio-pheromone/src/lib.rs`

- [x] **Step 1: Remove implicit serde defaults**

Remove the serde default from `PheromoneAdmissionPolicyDocument.scarcity_policies` and from `PheromoneScarcityPolicy.newcomer_horizon_epochs`.

- [x] **Step 2: Validate JSON schema before serde**

Embed `spec/schemas/chio-pheromone/v1/transit-policy.schema.json` in the runtime crate and validate the full JSON document before removing `admission` and deserializing Rust types.

- [x] **Step 3: Add explicit live admission guard**

Reject an empty `scarcityPolicies` list with `scarcity_policy_missing` for the live runtime policy path.

- [x] **Step 4: Verify green**

Run:

```bash
cargo test -p chio-pheromone-runtime runtime_policy_loader_rejects --test runtime_receiver
```

Expected: pass.

### Task 3: Manifest and Focused Gates

**Files:**
- Modify: `spec/schemas/MANIFEST.sha256`
- Modify: `scripts/check-chio-pheromone-runtime.sh`

- [x] **Step 1: Add schema manifest coverage**

Regenerate or patch the manifest hash entry for `spec/schemas/chio-pheromone/v1/scarcity-policy.schema.json` and update the runtime gate to fail when a required schema is not tracked by the manifest.

- [x] **Step 2: Verify focused gates**

Run:

```bash
cargo test -p chio-pheromone-runtime --test runtime_receiver
bash scripts/check-chio-pheromone-runtime.sh --schema-only
git diff --check
```

Expected: pass, except any unrelated pre-existing failures must be recorded instead of hidden.
