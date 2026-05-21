# Chio Treaty Buyer Gate Ownership Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the active Chio treaty buyer gate from delegating to `check-chiodos-treaty-buyer-hero-loop.sh`.

**Architecture:** Active Chio gates must own Chio fixture validation, direct Chio CLI runtime execution, and buyer packet verification. Historical signed proof packages may still contain Chiodos workflow identifiers when those bytes are part of old signed evidence. That compatibility path must be explicit through `chio attest legacy chiodos-v1 verify`, not hidden behind a Chiodos gate script.

**Tech Stack:** Bash gate script, `chio-cli`, `chio-spec-validate`, Chio runtime fixture schemas, Chio attest buyer schemas, legacy Chiodos proof-package schema.

---

### Task 1: Add The Red Gate

**Files:**
- Modify: `scripts/check-chio-treaty-buyer-hero-loop.sh`

- [x] **Step 1: Prove active delegation exists**

Run:

```bash
if rg -n 'check-chiodos' scripts/check-chio-treaty-buyer-hero-loop.sh; then
  echo "active Chio treaty buyer gate delegates to Chiodos script" >&2
  exit 1
fi
```

Expected: fail because the active Chio script calls `check-chiodos-treaty-buyer-hero-loop.sh`.

### Task 2: Make The Chio Gate Own Runtime Artifacts

**Files:**
- Modify: `scripts/check-chio-treaty-buyer-hero-loop.sh`

- [x] **Step 1: Keep schema-only Chio-native**

Validate `examples/chio-3vendor/fixtures/runtime-spine` through `scripts/check-chio-runtime-spine-fixtures.sh` and validate the Chio treaty runtime negative fixture corpus directly.

- [x] **Step 2: Generate runtime loopback artifacts directly**

Copy the Chio runtime-spine scenario to a temporary directory, add executable step arguments, widen the test lease window, and run:

```bash
cargo run -p chio-cli --bin chio -- runtime run-loopback ...
```

Temporary executable arguments may preserve `wf-chiodos-refund-001` while the current loopback proof-parity assembler still compares against historical proof-package bytes. Do not write those temporary compatibility values back into Chio fixtures.

### Task 3: Make Packet And Explain Modes Direct

**Files:**
- Modify: `scripts/check-chio-treaty-buyer-hero-loop.sh`

- [x] **Step 1: Validate produced artifacts**

Validate direct loopback outputs against Chio runtime schemas, Chio attest buyer schemas, Chio federation lineage schemas, and the legacy Chiodos proof-package schema.

- [x] **Step 2: Run explicit CLI checks**

Use direct CLI commands for:

```bash
chio attest legacy chiodos-v1 verify
chio attest buyer packet
chio attest buyer verify
chio attest buyer explain
```

The legacy verifier is allowed because it is the explicit historical proof-package boundary.

### Task 4: Preserve Negative Coverage

**Files:**
- Modify: `scripts/check-chio-treaty-buyer-hero-loop.sh`

- [x] **Step 1: Run the strict buyer review regressions directly**

Run the strict DSSE and live material buyer review tests directly from the Chio gate instead of delegating to the Chiodos script.

### Task 5: Verify

**Files:**
- All files above

- [x] **Step 1: Run focused gates**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-treaty-buyer-hero-loop.sh --schema-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-treaty-buyer-hero-loop.sh --packet-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-treaty-buyer-hero-loop.sh --explain-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-treaty-buyer-hero-loop.sh --negative-only
```

- [x] **Step 2: Run hygiene checks**

Run:

```bash
if rg -n 'check-chiodos' scripts/check-chio-treaty-buyer-hero-loop.sh; then
  echo "active Chio treaty buyer gate delegates to Chiodos script" >&2
  exit 1
fi
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo fmt --all -- --check
git diff --check
rg -n $'\xE2\x80\x94|\xE2\x80\x93' docs/superpowers/plans/2026-05-21-chio-treaty-buyer-gate-ownership.md scripts/check-chio-treaty-buyer-hero-loop.sh
```

Expected: all pass, except the dash scan exits 1 with no output.
