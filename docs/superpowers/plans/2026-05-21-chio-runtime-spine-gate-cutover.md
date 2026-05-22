# Chio Runtime Spine Gate Cutover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the runtime-spine closure gate to a Chio-named script and workflow while preserving explicit historical proof verification.

**Architecture:** The active gate must be `scripts/check-chio-runtime-spine.sh`. It must validate Chio runtime fixtures and schemas, run Chio-native admission checks, exercise the live runtime loopback through Chio-owned closure logic, and retain only explicit legacy proof verification for historical `chio-attest-v1` proof packages. The old Chio script may remain only as a compatibility wrapper that delegates to the Chio gate. The old workflow must be manual-only.

**Tech Stack:** Bash gate scripts, GitHub Actions workflow YAML, Chio runtime fixtures, Chio runtime schemas, Cargo test filters.

---

### Task 1: Add Red Drift Checks

**Files:**
- Create: `scripts/check-chio-runtime-spine.sh`
- Modify: `scripts/check-chio-runtime-spine.sh`
- Create: `.github/workflows/chio-runtime-spine.yml`
- Modify: `.github/workflows/chio-runtime-spine.yml`

- [x] **Step 1: Prove the Chio runtime-spine gate is missing**

Run:

```bash
test -x scripts/check-chio-runtime-spine.sh
```

Expected: fail because the active Chio-named runtime-spine gate does not exist.

- [x] **Step 2: Prove the old runtime-spine path still owns implementation**

Run:

```bash
if rg -n 'examples/chio-3vendor|spec/schemas/chio|check-chio-runtime-spine' scripts/check-chio-runtime-spine.sh .github/workflows/chio-runtime-spine.yml; then
  echo "legacy runtime-spine gate still owns Chio implementation" >&2
  exit 1
fi
```

Expected: fail because the old script and active workflow still point at Chio fixtures, schemas, and script naming.

### Task 2: Add Chio-Owned Runtime Spine Gate

**Files:**
- Create: `scripts/check-chio-runtime-spine.sh`

- [x] **Step 1: Implement mode parsing**

Support:

```text
--schema-only
--negative-only
```

Default mode runs schema, runtime crate tests, kernel runtime tests, positive runtime-spine checks, and negative admission checks.

- [x] **Step 2: Validate Chio runtime-spine fixtures**

Route schema mode through:

```bash
bash "$repo_root/scripts/check-chio-runtime-spine-fixtures.sh"
```

- [x] **Step 3: Add Chio-native admission checks**

Use `examples/chio-3vendor/fixtures/runtime-spine` and `spec/schemas/chio-runtime/v1`. The positive admission report must use schema `chio.runtime.admission-report.v1` and metadata key `chio_runtime`.

- [x] **Step 4: Exercise live runtime loopback through Chio-owned closure logic**

Use:

```bash
bash "$repo_root/scripts/check-chio-treaty-buyer-hero-loop.sh" --packet-only
```

The packet gate already runs `chio runtime run-loopback`, validates Chio runtime and buyer schemas, explicitly verifies historical `chio-attest-v1` proof packages, and rejects pending proof-regeneration markers.

- [x] **Step 5: Keep negative admission coverage**

Preserve destructive lease replay and request binding mismatch checks, validating failure reports against Chio runtime admission report schemas.

### Task 3: Convert The Old Script To A Wrapper

**Files:**
- Modify: `scripts/check-chio-runtime-spine.sh`

- [x] **Step 1: Replace old implementation with delegation**

Make the file:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$repo_root/scripts/check-chio-runtime-spine.sh" "$@"
```

### Task 4: Rename The Workflow

**Files:**
- Create: `.github/workflows/chio-runtime-spine.yml`
- Modify: `.github/workflows/chio-runtime-spine.yml`

- [x] **Step 1: Add active Chio workflow**

Create a Chio-named workflow that watches Chio runtime fixtures, Chio runtime schemas, Chio attest and federation schemas, runtime crates, and the new Chio script. Invoke:

```bash
bash scripts/check-chio-runtime-spine.sh
```

- [x] **Step 2: Disable the old workflow as active CI**

Make the old workflow manual-only and delegate to the Chio-named gate. It should not run on pull requests or pushes.

### Task 5: Verify

**Files:**
- All files above

- [x] **Step 1: Run focused gates**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-spine.sh --schema-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-spine.sh --negative-only
```

- [x] **Step 2: Run compatibility wrapper check**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-spine.sh --schema-only
```

- [x] **Step 3: Run drift and hygiene checks**

Run:

```bash
test -x scripts/check-chio-runtime-spine.sh
if rg -n 'examples/chio-3vendor|spec/schemas/chio-runtime/v1|check-chio-runtime-spine' scripts/check-chio-runtime-spine.sh; then
  echo "Chio runtime-spine gate still points at Chio runtime implementation paths" >&2
  exit 1
fi
if rg -n 'pull_request:|push:' .github/workflows/chio-runtime-spine.yml; then
  echo "legacy runtime-spine workflow is still active on PR or push" >&2
  exit 1
fi
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo fmt --all -- --check
git diff --check
rg -n $'\xE2\x80\x94|\xE2\x80\x93' docs/superpowers/plans/2026-05-21-chio-runtime-spine-gate-cutover.md scripts/check-chio-runtime-spine.sh scripts/check-chio-runtime-spine.sh .github/workflows/chio-runtime-spine.yml .github/workflows/chio-runtime-spine.yml
```

Expected: all pass, except the dash scan exits 1 with no output.
