# Chio Treaty Buyer Legacy Wrapper Cutover Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert `scripts/check-chio-treaty-buyer-hero-loop.sh` from a second implementation into a compatibility wrapper over the Chio-owned treaty buyer gate.

**Architecture:** `scripts/check-chio-treaty-buyer-hero-loop.sh` is the active executable gate. The Chio-named script may remain only as a stable compatibility entrypoint that delegates every mode to the Chio script.

**Tech Stack:** Bash gate scripts, Cargo-backed Chio treaty buyer validation, shell drift checks.

---

### Task 1: Add Red Drift Checks

**Files:**
- Modify: `scripts/check-chio-treaty-buyer-hero-loop.sh`

- [x] **Step 1: Prove the legacy script still owns implementation**

Run:

```bash
if rg -n 'check-chio-runtime-spine|schema_dir=|fixture_dir=|run_strict_dsse_negative_tests|run_runtime_spine_with_artifacts' scripts/check-chio-treaty-buyer-hero-loop.sh; then
  echo "legacy treaty buyer gate still owns implementation" >&2
  exit 1
fi
```

Expected: fail because the old script still validates schemas, owns runtime-spine artifact plumbing, and calls the old Chio runtime-spine gate.

### Task 2: Convert The Old Script To A Wrapper

**Files:**
- Modify: `scripts/check-chio-treaty-buyer-hero-loop.sh`

- [x] **Step 1: Replace old implementation with delegation**

Make the file:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$repo_root/scripts/check-chio-treaty-buyer-hero-loop.sh" "$@"
```

### Task 3: Verify

**Files:**
- `scripts/check-chio-treaty-buyer-hero-loop.sh`
- `scripts/check-chio-treaty-buyer-hero-loop.sh`

- [x] **Step 1: Run wrapper compatibility check**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-treaty-buyer-hero-loop.sh --schema-only
```

- [x] **Step 2: Run drift and hygiene checks**

Run:

```bash
bash -n scripts/check-chio-treaty-buyer-hero-loop.sh scripts/check-chio-treaty-buyer-hero-loop.sh
if rg -n 'check-chio-runtime-spine|schema_dir=|fixture_dir=|run_strict_dsse_negative_tests|run_runtime_spine_with_artifacts' scripts/check-chio-treaty-buyer-hero-loop.sh; then
  echo "legacy treaty buyer gate still owns implementation" >&2
  exit 1
fi
git diff --check -- scripts/check-chio-treaty-buyer-hero-loop.sh docs/superpowers/plans/2026-05-21-chio-treaty-buyer-legacy-wrapper-cutover.md
rg -n $'\xE2\x80\x94|\xE2\x80\x93' scripts/check-chio-treaty-buyer-hero-loop.sh docs/superpowers/plans/2026-05-21-chio-treaty-buyer-legacy-wrapper-cutover.md
```

Expected: all pass, except the dash scan exits 1 with no output.
