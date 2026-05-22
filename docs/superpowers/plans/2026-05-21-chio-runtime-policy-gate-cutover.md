# Chio Runtime Policy Gate Cutover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the runtime policy gate to a Chio-named script and workflow with Chio-native runtime schema fixtures.

**Architecture:** The active gate must be `scripts/check-chio-runtime-policy.sh`. It validates Chio runtime peer weights, pheromone policy, policy decisions, and trust-floor state against `spec/schemas/chio-runtime/v1`, runs focused runtime policy and trust-floor tests, and chains through the Chio runtime-spine gate. The old Chio script and workflow remain only as manual compatibility entrypoints.

**Tech Stack:** Bash gate scripts, GitHub Actions workflow YAML, Chio runtime JSON schemas, Cargo test filters.

---

### Task 1: Add Red Drift Checks

**Files:**
- Create: `scripts/check-chio-runtime-policy.sh`
- Modify: `scripts/check-chio-runtime-policy.sh`
- Create: `.github/workflows/chio-runtime-policy.yml`
- Modify: `.github/workflows/chio-runtime-policy.yml`

- [x] **Step 1: Prove the Chio runtime policy gate is missing**

Run:

```bash
test -x scripts/check-chio-runtime-policy.sh
```

Expected: fail because the active Chio-named runtime policy gate does not exist.

- [x] **Step 2: Prove the old runtime policy path still owns implementation**

Run:

```bash
if rg -n 'chio\.chio\.runtime|spec/schemas/chio|check-chio-runtime-policy|check-chio-runtime-spine|chio_runtime' scripts/check-chio-runtime-policy.sh .github/workflows/chio-runtime-policy.yml; then
  echo "legacy runtime policy gate still owns Chio implementation" >&2
  exit 1
fi
```

Expected: fail because the old script and active workflow still point at Chio runtime schemas, Chio schema IDs, and Chio gate names.

### Task 2: Add Chio-Owned Runtime Policy Gate

**Files:**
- Create: `scripts/check-chio-runtime-policy.sh`

- [x] **Step 1: Implement mode parsing**

Support:

```text
--schema-only
--negative-only
```

Default mode runs schema checks, focused runtime policy tests, focused CLI ownership tests, and the Chio runtime-spine gate.

- [x] **Step 2: Validate Chio-native runtime policy documents**

Use `spec/schemas/chio-runtime/v1` and inline schema fixtures with these IDs:

```text
chio.runtime.peer-weights.v1
chio.runtime.pheromone-policy.v1
chio.runtime.pheromone-policy-decision.v1
chio.runtime.trust-floor-state.v1
```

The policy rule namespace must be `chio.runtime`, not `chio.runtime`.

- [x] **Step 3: Add zero-match-safe focused test runner**

Use a local `run_cargo_test_filter` helper that fails if cargo returns no nonzero passed test result for a filtered command.

- [x] **Step 4: Run focused runtime and CLI tests**

Run:

```bash
cargo test -p chio-runtime-core chio_native_runtime_policy_material_emits_chio_decision --test runtime_pheromone_policy
cargo test -p chio-runtime-core runtime_trust_floor --test runtime_trust
cargo test -p chio-cli --bin chio_runtime
```

- [x] **Step 5: Chain through the Chio runtime-spine gate**

Default mode must call:

```bash
bash "$repo_root/scripts/check-chio-runtime-spine.sh"
```

### Task 3: Convert The Old Script To A Wrapper

**Files:**
- Modify: `scripts/check-chio-runtime-policy.sh`

- [x] **Step 1: Replace old implementation with delegation**

Make the file:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$repo_root/scripts/check-chio-runtime-policy.sh" "$@"
```

### Task 4: Rename The Workflow

**Files:**
- Create: `.github/workflows/chio-runtime-policy.yml`
- Modify: `.github/workflows/chio-runtime-policy.yml`

- [x] **Step 1: Add active Chio workflow**

Create a Chio-named workflow that watches Chio runtime schemas, Chio runtime scripts, runtime crates, CLI, kernel, registry, and manifest. Invoke:

```bash
bash scripts/check-chio-runtime-policy.sh
```

- [x] **Step 2: Disable the old workflow as active CI**

Make the old workflow manual-only and delegate to the Chio-named gate. It should not run on pull requests or pushes.

### Task 5: Verify

**Files:**
- All files above

- [x] **Step 1: Run focused gates**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-policy.sh --schema-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-policy.sh --negative-only
```

- [x] **Step 2: Run compatibility wrapper check**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-policy.sh --schema-only
```

- [x] **Step 3: Run default workflow-equivalent gate**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-policy.sh
```

- [x] **Step 4: Run drift and hygiene checks**

Run:

```bash
test -x scripts/check-chio-runtime-policy.sh
if rg -n 'chio\.chio\.runtime|spec/schemas/chio|check-chio-runtime-policy|check-chio-runtime-spine|chio_runtime' scripts/check-chio-runtime-policy.sh; then
  echo "Chio runtime policy gate still points at Chio runtime implementation paths" >&2
  exit 1
fi
if rg -n 'pull_request:|push:' .github/workflows/chio-runtime-policy.yml; then
  echo "legacy runtime policy workflow is still active on PR or push" >&2
  exit 1
fi
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo fmt --all -- --check
git diff --check
rg -n $'\xE2\x80\x94|\xE2\x80\x93' docs/superpowers/plans/2026-05-21-chio-runtime-policy-gate-cutover.md scripts/check-chio-runtime-policy.sh scripts/check-chio-runtime-policy.sh .github/workflows/chio-runtime-policy.yml .github/workflows/chio-runtime-policy.yml
```

Expected: all pass, except the dash scan exits 1 with no output.
