# Chio Runtime Orchestration Gate Cutover Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move runtime orchestration validation to `scripts/check-chio-runtime-orchestration.sh` and a Chio-named workflow.

**Architecture:** The active gate must use Chio runtime schemas and public `chio runtime orchestrate ...` commands. The Chiodos-named script and workflow may remain only as compatibility wrappers. Legacy Chiodos schema references are allowed only for `runtime-orchestration-negative-fixture-corpus.schema.json` until that schema has a Chio-runtime replacement.

**Tech Stack:** Bash gate scripts, Chio runtime schemas, Chio CLI runtime orchestration commands, Cargo test filters, GitHub Actions workflow YAML.

---

### Task 1: Add Red Drift Checks

**Files:**
- Create: `scripts/check-chio-runtime-orchestration.sh`
- Modify: `scripts/check-chiodos-runtime-orchestration.sh`
- Create: `.github/workflows/chio-runtime-orchestration.yml`
- Modify: `.github/workflows/chiodos-runtime-orchestration.yml`

- [x] **Step 1: Prove the Chio runtime orchestration gate is missing**

Run:

```bash
test -x scripts/check-chio-runtime-orchestration.sh
```

Expected: fail because the Chio-named runtime orchestration gate does not exist.

- [x] **Step 2: Prove the old runtime orchestration path still owns active implementation**

Run:

```bash
if rg -n 'spec/schemas/chiodos/v1|chio\\.chiodos\\.runtime-|chiodos_runtime_orchestrate|scripts/check-chiodos-runtime-orchestration.sh' scripts/check-chiodos-runtime-orchestration.sh .github/workflows/chiodos-runtime-orchestration.yml; then
  echo "legacy runtime orchestration gate still owns active implementation" >&2
  exit 1
fi
```

Expected: fail because the old script owns Chiodos runtime schemas and the old workflow is active.

### Task 2: Add Chio-Owned Runtime Orchestration Gate

**Files:**
- Create: `scripts/check-chio-runtime-orchestration.sh`

- [x] **Step 1: Implement Chio runtime fixture schemas**

Use Chio runtime schema values such as:

```text
chio.runtime.orchestration-profile.v1
chio.runtime.run-contract.v1
chio.runtime.workflow-run-report.v1
chio.runtime.evidence-manifest.v1
```

- [x] **Step 2: Validate against Chio runtime schema files**

Use `spec/schemas/chio-runtime/v1` for profile, run contract, workflow report, step evidence, proof regeneration, evidence manifest, orchestration reports, resume plan, and proof drift report artifacts.

- [x] **Step 3: Preserve the legacy-only negative corpus exception**

Use `spec/schemas/chiodos/v1/runtime-orchestration-negative-fixture-corpus.schema.json` only for the local negative corpus fixture.

### Task 3: Convert Old Entrypoints To Compatibility Wrappers

**Files:**
- Modify: `scripts/check-chiodos-runtime-orchestration.sh`
- Create: `.github/workflows/chio-runtime-orchestration.yml`
- Modify: `.github/workflows/chiodos-runtime-orchestration.yml`

- [x] **Step 1: Replace old script implementation with delegation**

Make the old script delegate to `scripts/check-chio-runtime-orchestration.sh`.

- [x] **Step 2: Add active Chio workflow**

Create a Chio-named workflow that invokes:

```bash
bash scripts/check-chio-runtime-orchestration.sh
```

- [x] **Step 3: Disable old workflow as active CI**

Make the old workflow manual-only and delegate to the Chio script.

### Task 4: Verify

**Files:**
- All files above

- [x] **Step 1: Run focused modes**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-orchestration.sh --schema-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-orchestration.sh --negative-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-orchestration.sh --drift-only
```

- [x] **Step 2: Run wrapper and default gates**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chiodos-runtime-orchestration.sh --schema-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-orchestration.sh
```

- [x] **Step 3: Run drift and hygiene checks**

Run:

```bash
bash -n scripts/check-chio-runtime-orchestration.sh scripts/check-chiodos-runtime-orchestration.sh
test -x scripts/check-chio-runtime-orchestration.sh
if rg -n 'chio\\.chiodos\\.runtime-(orchestration-profile|run-contract|workflow-run-report|step-evidence|proof-regeneration-report|evidence-manifest|orchestration-plan|orchestration-run-report|orchestration-status-report|orchestration-resume-plan|proof-drift-report)|chiodos_runtime_orchestrate|check-chiodos-runtime-orchestration' scripts/check-chio-runtime-orchestration.sh; then
  echo "Chio runtime orchestration gate still points at Chiodos runtime implementation paths" >&2
  exit 1
fi
if rg -n 'pull_request:|push:' .github/workflows/chiodos-runtime-orchestration.yml; then
  echo "legacy runtime orchestration workflow is still active on PR or push" >&2
  exit 1
fi
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo fmt --all -- --check
git diff --check
rg -n $'\xE2\x80\x94|\xE2\x80\x93' docs/superpowers/plans/2026-05-21-chio-runtime-orchestration-gate-cutover.md scripts/check-chio-runtime-orchestration.sh scripts/check-chiodos-runtime-orchestration.sh .github/workflows/chio-runtime-orchestration.yml .github/workflows/chiodos-runtime-orchestration.yml
```

Expected: all pass, except the dash scan exits 1 with no output.
