# V1 Foundation Landing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stabilize and prepare the v1-only protocol strategy and authoritative receipt-boundary foundation for review without starting adapter implementation.

**Architecture:** Split the work into a docs-only PR #652 lane and a code foundation lane. Keep Chio-owned schema/runtime surfaces v1-only, make receipt-kind semantics authoritative, and ensure exports/read models cannot turn trace or advisory observations into authorization claims.

**Tech Stack:** Rust workspace, SQLite receipt store, SIEM exporters, generated Rust/Python/TypeScript/Go schemas, GitHub Actions, Markdown research docs.

---

### Task 1: PR #652 Docs V1-Only Translation Review

**Files:**
- Modify: `/Users/connor/.codex/worktrees/3398/arc-pr652-v1/docs/research/protocol-strategy/00-overview-v2.md`
- Modify: `/Users/connor/.codex/worktrees/3398/arc-pr652-v1/docs/research/protocol-strategy/18-decision-packet.md`
- Modify: `/Users/connor/.codex/worktrees/3398/arc-pr652-v1/docs/adr/ADR-0010-current-v1-receipt-kind-trace-semantics.md`
- Modify: `/Users/connor/.codex/worktrees/3398/arc-pr652-v1/docs/adr/ADR-0012-current-v1-manifest-event-actions.md`
- Modify: `/Users/connor/.codex/worktrees/3398/arc-pr652-v1/docs/adr/README.md`

- [ ] **Step 1: Scan normative docs for stale Chio-owned pre-release version language**

Run:

```bash
rg -n "Receipt v3|receipt v3|Manifest v2|manifest v2|maxReceiptSchema|maxManifestSchema|ACCEPTS_.*_V[2-9]|chio\\.receipt\\.v[2-9]|chio\\.manifest\\.v[2-9]" docs/adr docs/research/protocol-strategy/00-overview-v2.md docs/research/protocol-strategy/18-decision-packet.md
```

Expected: no matches except historical file paths if explicitly described as historical.

- [ ] **Step 2: Verify links after renamed ADR and research files**

Run:

```bash
rg -n "ADR-0010-receipt-v3-trace-semantics|ADR-0012-manifest-v2-event-actions|15-receipt-schema-v3" docs
```

Expected: no matches.

- [ ] **Step 3: Run docs hygiene**

Run:

```bash
git diff --check
rg -n $'[\u2013\u2014]' docs/research/protocol-strategy docs/adr docs/superpowers/plans
```

Expected: `git diff --check` exits 0, dash scan exits 1 with no output.

### Task 2: Code Foundation Semantic Review

**Files:**
- Review: `/Users/connor/.codex/worktrees/3398/arc/crates/chio-core-types/src/receipt.rs`
- Review: `/Users/connor/.codex/worktrees/3398/arc/crates/chio-core-types/src/capability.rs`
- Review: `/Users/connor/.codex/worktrees/3398/arc/crates/chio-acp-proxy/src/kernel_signer.rs`
- Review: `/Users/connor/.codex/worktrees/3398/arc/crates/chio-acp-proxy/src/interceptor.rs`
- Review: `/Users/connor/.codex/worktrees/3398/arc/crates/chio-kernel/src/evidence_export.rs`
- Review: `/Users/connor/.codex/worktrees/3398/arc/crates/chio-siem/src/`

- [ ] **Step 1: Verify receipt-kind validation and display semantics**

Run:

```bash
cargo test -p chio-core-types receipt_semantics --lib
cargo test -p chio-core-types trace_and_advisory_semantics_cannot_authorize --lib
cargo test -p chio-siem trace_observation_allow --lib
```

Expected: all tests pass.

- [ ] **Step 2: Verify ACP receipt-washing protections**

Run:

```bash
cargo test -p chio-acp-proxy kernel_receipt_signer_propagates_capability_metadata_into_receipts --lib
cargo test -p chio-acp-proxy interceptor_clears_capability_context_after_terminal_status_updates --lib
```

Expected: all tests pass.

- [ ] **Step 3: Verify read-boundary fail-closed behavior**

Run:

```bash
cargo test -p chio-store-sqlite evidence_export --lib
cargo test -p chio-cli evidence_export
cargo test -p chio-cli receipt_query
```

Expected: all tests pass.

### Task 3: Schema, SDK, And CI Guard Review

**Files:**
- Review: `/Users/connor/.codex/worktrees/3398/arc/scripts/check-chio-owned-v1-only.sh`
- Review: `/Users/connor/.codex/worktrees/3398/arc/.github/workflows/spec-drift.yml`
- Review: `/Users/connor/.codex/worktrees/3398/arc/spec/schemas/chio-wire/v1/receipt/lineage_statement.schema.json`
- Review: `/Users/connor/.codex/worktrees/3398/arc/crates/chio-core-types/src/_generated/chio_wire_v1.rs`
- Review: `/Users/connor/.codex/worktrees/3398/arc/sdks/python/chio-sdk-python/src/chio_sdk/_generated/`
- Review: `/Users/connor/.codex/worktrees/3398/arc/sdks/typescript/packages/conformance/src/_generated/index.ts`
- Review: `/Users/connor/.codex/worktrees/3398/arc/sdks/go/chio-go-http/types.go`

- [ ] **Step 1: Run v1-only and codegen guards**

Run:

```bash
bash scripts/check-chio-owned-v1-only.sh
cargo xtask codegen --lang rust --check
cargo xtask codegen --lang python --check
cargo xtask codegen --lang ts --check
cargo xtask codegen --lang go --check
```

Expected: all commands pass.

- [ ] **Step 2: Inspect guard allowlist boundaries**

Run:

```bash
sed -n '1,220p' scripts/check-chio-owned-v1-only.sh
sed -n '1,120p' .github/workflows/spec-drift.yml
```

Expected: the guard excludes external standards and explicit future negative fixtures, but blocks Chio-owned runtime/schema/generated v2+ remnants.

### Task 4: Final Integration Verification

**Files:**
- No new files expected beyond fixes from Tasks 1-3.

- [ ] **Step 1: Run focused crate validation**

Run:

```bash
cargo fmt --all -- --check
cargo test -p chio-core-types --lib
cargo test -p chio-kernel-core --lib
cargo test -p chio-acp-proxy --lib
cargo test -p chio-siem --lib
cargo check -p chio-cli
git diff --check
```

Expected: all commands pass.

- [ ] **Step 2: Produce landing summary**

Report:

```text
Docs branch: list changed PR #652 files and hygiene results.
Code branch: list changed foundation areas and focused validation results.
Known blockers: GitHub Actions billing/spending limit and any full-workspace validation not run.
Next safe execution: stage/commit/push docs PR #652 first, then v1 code branch, then PR #661 bench lane if still separate.
```
