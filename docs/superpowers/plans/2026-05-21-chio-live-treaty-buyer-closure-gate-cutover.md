# Chio Live Treaty Buyer Closure Gate Cutover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the live treaty buyer closure gate to a Chio-named script and workflow while preserving explicit historical proof verification.

**Architecture:** The active gate must be `scripts/check-chio-live-treaty-buyer-closure.sh` and must call Chio-owned gates for schema, proof, buyer, and negative coverage. The old Chio script may remain only as a compatibility wrapper that delegates to the Chio gate and emits no artifacts of its own. The active workflow should watch Chio fixture/schema/script paths and invoke the Chio gate.

**Tech Stack:** Bash gate scripts, GitHub Actions workflow YAML, Cargo test filters, existing Chio treaty-buyer and runtime-spine gates.

---

### Task 1: Add Red Drift Checks

**Files:**
- Modify: `scripts/check-chio-live-treaty-buyer-closure.sh`
- Modify: `scripts/check-chio-live-treaty-buyer-closure.sh`
- Create: `.github/workflows/chio-live-treaty-buyer-closure.yml`
- Modify: `.github/workflows/chio-live-treaty-buyer-closure.yml`

- [x] **Step 1: Prove the Chio gate is missing**

Run:

```bash
test -x scripts/check-chio-live-treaty-buyer-closure.sh
```

Expected: fail because the active Chio-named live treaty buyer gate does not exist.

- [x] **Step 2: Prove the old gate still owns implementation**

Run:

```bash
if rg -n 'check-chio-(treaty-buyer-hero-loop|runtime-spine)' scripts/check-chio-live-treaty-buyer-closure.sh; then
  echo "legacy live treaty buyer closure gate still owns Chio implementation" >&2
  exit 1
fi
```

Expected: fail because the old script directly calls Chio-era gate scripts.

### Task 2: Add Chio-Owned Live Closure Gate

**Files:**
- Create: `scripts/check-chio-live-treaty-buyer-closure.sh`

- [x] **Step 1: Implement mode parsing**

Support the same focused modes as the historical gate:

```text
--schema-only
--negative-only
--runtime-only
--dsse-only
--lineage-only
--proof-only
--buyer-only
```

- [x] **Step 2: Route schema and buyer modes through Chio gates**

Use:

```bash
bash "$repo_root/scripts/check-chio-treaty-buyer-hero-loop.sh" --schema-only
bash "$repo_root/scripts/check-chio-treaty-buyer-hero-loop.sh" --packet-only
bash "$repo_root/scripts/check-chio-treaty-buyer-hero-loop.sh" --negative-only
```

- [x] **Step 3: Route proof mode through direct Chio gates**

Use:

```bash
bash "$repo_root/scripts/check-chio-treaty-buyer-hero-loop.sh" --packet-only
cargo test -p chio-runtime-core runtime_workflow_report --test runtime_admission
cargo test -p chio-runtime-core runtime_proof_regeneration --test runtime_admission
```

The runtime tests still live in the historical runtime crate while the crate split continues, but the shell gate must not call the old Chio runtime-spine script.

### Task 3: Convert The Old Script To A Wrapper

**Files:**
- Modify: `scripts/check-chio-live-treaty-buyer-closure.sh`

- [x] **Step 1: Replace old implementation with delegation**

Make the file:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$repo_root/scripts/check-chio-live-treaty-buyer-closure.sh" "$@"
```

### Task 4: Rename The Workflow

**Files:**
- Create: `.github/workflows/chio-live-treaty-buyer-closure.yml`
- Modify: `.github/workflows/chio-live-treaty-buyer-closure.yml`

- [x] **Step 1: Add active Chio workflow**

Create a Chio-named workflow that watches Chio fixture/schema/script paths and invokes:

```bash
bash scripts/check-chio-live-treaty-buyer-closure.sh
```

- [x] **Step 2: Disable the old workflow as active CI**

Make the old workflow manual-only and delegate to the Chio-named gate. It should not run on pull requests or pushes.

### Task 5: Verify

**Files:**
- All files above

- [x] **Step 1: Run focused gates**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-live-treaty-buyer-closure.sh --schema-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-live-treaty-buyer-closure.sh --buyer-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-live-treaty-buyer-closure.sh --proof-only
```

- [x] **Step 2: Run compatibility wrapper check**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-live-treaty-buyer-closure.sh --schema-only
```

- [x] **Step 3: Run drift and hygiene checks**

Run:

```bash
test -x scripts/check-chio-live-treaty-buyer-closure.sh
if rg -n 'check-chio-(treaty-buyer-hero-loop|runtime-spine)' scripts/check-chio-live-treaty-buyer-closure.sh scripts/check-chio-live-treaty-buyer-closure.sh; then
  echo "live treaty buyer closure gate still delegates to Chio gate implementation" >&2
  exit 1
fi
if rg -n 'pull_request:|push:' .github/workflows/chio-live-treaty-buyer-closure.yml; then
  echo "legacy live treaty buyer workflow is still active on PR or push" >&2
  exit 1
fi
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo fmt --all -- --check
git diff --check
rg -n $'\xE2\x80\x94|\xE2\x80\x93' docs/superpowers/plans/2026-05-21-chio-live-treaty-buyer-closure-gate-cutover.md scripts/check-chio-live-treaty-buyer-closure.sh scripts/check-chio-live-treaty-buyer-closure.sh .github/workflows/chio-live-treaty-buyer-closure.yml .github/workflows/chio-live-treaty-buyer-closure.yml
```

Expected: all pass, except the dash scan exits 1 with no output.
