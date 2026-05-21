# Chio Three Vendor Workflow Wrapper Cutover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the three-vendor fixture generator use the Chio workflow proof,
trust-bundle, and verification-context facade types required by
`VerifiedChioWorkflowResolver`.

**Architecture:** Runtime workflow verification must cross the public
`chio-pheromone-runtime` Chio wrapper boundary. Historical proof-package,
trust-bundle, and context values may be used to preserve signed fixture
compatibility, but active generator code should adapt them through Chio facade
parsers before constructing the verified resolver.

**Tech Stack:** Rust example generator and pheromone runtime negative gate.

---

### Task 1: Three Vendor Workflow Resolver Boundary

**Files:**
- Modify: `examples/chiodos-3vendor/src/main.rs`
- Modify: `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`

- [x] **Step 1: Capture failing gate**

Run: `bash scripts/check-chio-pheromone-runtime.sh --negative-only`

Observed: `generate-chio-three-vendor-fixtures` fails to compile because it
passes historical proof, trust-bundle, and context values directly to
`VerifiedChioWorkflowResolver::from_verified_package`.

- [x] **Step 2: Convert generator through Chio wrappers**

Serialize the existing package, trust bundle, and context using existing fixture
helpers, parse them through the Chio workflow wrapper types, and pass those
wrappers to `VerifiedChioWorkflowResolver::from_verified_package`.

- [x] **Step 3: Run green**

Run: `bash scripts/check-chio-pheromone-runtime.sh --negative-only`

- [x] **Step 4: Verify hygiene**

Run `cargo fmt --all -- --check`, `git diff --check`, and touched-file unicode
dash scans.
