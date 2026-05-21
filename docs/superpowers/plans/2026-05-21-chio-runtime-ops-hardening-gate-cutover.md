# Chio Runtime Ops Hardening Gate Cutover Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move runtime ops hardening validation to `scripts/check-chio-runtime-ops-hardening.sh` and a Chio-named workflow.

**Architecture:** The active gate must use Chio runtime schemas and public `chio runtime ops ...` commands. The Chiodos-named script and workflow may remain only as compatibility wrappers. Legacy Chiodos schema references are allowed only for runtime ops negative-corpus and failure-code registry schemas until those schemas have Chio-runtime replacements.

**Tech Stack:** Bash gate scripts, Chio runtime schemas, Chio CLI runtime ops commands, Cargo test filters, GitHub Actions workflow YAML.

---

### Task 1: Add Red Drift Checks

**Files:**
- Create: `scripts/check-chio-runtime-ops-hardening.sh`
- Modify: `scripts/check-chiodos-runtime-ops-hardening.sh`
- Create: `.github/workflows/chio-runtime-ops-hardening.yml`
- Modify: `.github/workflows/chiodos-runtime-ops-hardening.yml`

- [x] **Step 1: Prove the Chio runtime ops gate is missing**

Run:

```bash
test -x scripts/check-chio-runtime-ops-hardening.sh
```

Expected: fail because the Chio-named runtime ops gate does not exist.

- [x] **Step 2: Prove the old runtime ops path still owns active implementation**

Run:

```bash
if rg -n 'spec/schemas/chiodos/v1|chio\\.chiodos\\.runtime-|chiodos_runtime_ops|scripts/check-chiodos-runtime-ops-hardening.sh' scripts/check-chiodos-runtime-ops-hardening.sh .github/workflows/chiodos-runtime-ops-hardening.yml; then
  echo "legacy runtime ops gate still owns active implementation" >&2
  exit 1
fi
```

Expected: fail because the old script owns Chiodos runtime schemas and the old workflow is active.

### Task 2: Add Chio-Owned Runtime Ops Gate

**Files:**
- Create: `scripts/check-chio-runtime-ops-hardening.sh`

- [x] **Step 1: Implement Chio runtime fixture schemas**

Use Chio runtime schema values such as:

```text
chio.runtime.supervisor-profile.v1
chio.runtime.provider-bindings.v1
chio.runtime.artifact-retention-profile.v1
chio.runtime.evidence-manifest.v1
```

- [x] **Step 2: Validate against Chio runtime schema files**

Use `spec/schemas/chio-runtime/v1` for supervisor, provider, retention, report, tick, recovery, evidence, and provider-health artifacts.

- [x] **Step 3: Preserve legacy-only schema exceptions**

Use `spec/schemas/chiodos/v1` only for:

```text
runtime-ops-negative-fixture-corpus.schema.json
runtime-failure-code-registry.schema.json
```

### Task 3: Convert Old Entrypoints To Compatibility Wrappers

**Files:**
- Modify: `scripts/check-chiodos-runtime-ops-hardening.sh`
- Create: `.github/workflows/chio-runtime-ops-hardening.yml`
- Modify: `.github/workflows/chiodos-runtime-ops-hardening.yml`

- [x] **Step 1: Replace old script implementation with delegation**

Make the old script delegate to `scripts/check-chio-runtime-ops-hardening.sh`.

- [x] **Step 2: Add active Chio workflow**

Create a Chio-named workflow that invokes:

```bash
bash scripts/check-chio-runtime-ops-hardening.sh
```

- [x] **Step 3: Disable old workflow as active CI**

Make the old workflow manual-only and delegate to the Chio script.

### Task 4: Verify

**Files:**
- All files above

- [x] **Step 1: Run focused modes**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-ops-hardening.sh --schema-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-ops-hardening.sh --negative-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-ops-hardening.sh --failure-codes-only
```

- [x] **Step 2: Run wrapper and default gates**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chiodos-runtime-ops-hardening.sh --schema-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-ops-hardening.sh
```

- [x] **Step 3: Run drift and hygiene checks**

Run:

```bash
bash -n scripts/check-chio-runtime-ops-hardening.sh scripts/check-chiodos-runtime-ops-hardening.sh
test -x scripts/check-chio-runtime-ops-hardening.sh
if rg -n 'chio\\.chiodos\\.runtime-(supervisor-profile|provider-bindings|artifact-retention|evidence-manifest|scheduler|ops-status|recovery-drill)|chiodos_runtime_ops|check-chiodos-runtime-ops-hardening' scripts/check-chio-runtime-ops-hardening.sh; then
  echo "Chio runtime ops gate still points at Chiodos runtime implementation paths" >&2
  exit 1
fi
if rg -n 'pull_request:|push:' .github/workflows/chiodos-runtime-ops-hardening.yml; then
  echo "legacy runtime ops workflow is still active on PR or push" >&2
  exit 1
fi
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo fmt --all -- --check
git diff --check
rg -n $'\xE2\x80\x94|\xE2\x80\x93' docs/superpowers/plans/2026-05-21-chio-runtime-ops-hardening-gate-cutover.md scripts/check-chio-runtime-ops-hardening.sh scripts/check-chiodos-runtime-ops-hardening.sh .github/workflows/chio-runtime-ops-hardening.yml .github/workflows/chiodos-runtime-ops-hardening.yml
```

Expected: all pass, except the dash scan exits 1 with no output.
