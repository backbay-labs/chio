# Chio Universal Security Kernel: Execution Roadmap

> Historical internal planning note. `v2.x` labels in this document are
> pre-release implementation milestones, not Chio-owned protocol, schema, SDK,
> or runtime versions. Current protocol posture is v1-only; use
> `spec/PROTOCOL.md`, `spec/README.md`, and
> `docs/release/RELEASE_CANDIDATE.md` for the live boundary.

> **Date**: April 2026
> **Synthesized from**: 35 protocol docs, 13 guard docs, 8 research agents,
> 6 review agents, 3 critique cycles, and the priority adjustments in
> `docs/protocols/REVIEW-FINDINGS-AND-NEXT-STEPS.md`.
>
> **Canonical type contract**: `docs/protocols/ADR-TYPE-EVOLUTION.md`
> **Historical priority note**: This document was the source of truth for the
> milestone program it records. It does not override the current v1-only
> protocol posture.

---

## How to Read This Document

Each phase contains numbered stories. Each story has:
- **What**: concise description
- **Files**: source files to create or modify
- **Refs**: design docs that inform the implementation
- **Acceptance**: what "done" looks like

Phases are ordered by dependency. Within a phase, stories can generally
be parallelized unless noted. Some phases can overlap with others where
there are no hard dependencies.

Phase headers marked `[SHIPPED <sha>]` are complete on the implementation
branch. Headers marked `[PARTIAL <sha>]` shipped the core feature but have one
or more follow-up gaps noted in the phase body. Headers with no marker are
unstarted or in-flight.

---

## Shipment Status (2026-04-16)

**73 of 73 numbered phases shipped** on the implementation branch. The entire roadmap was executed end-to-end. Every phase group is complete: Phase 0 (DX), Phase 1 (structural security), Phase 2 (types), Phase 3 (content safety + HITL), Phase 4 (code agent), Phase 5 (guard absorption), Phase 6 (framework SDKs), Phase 7 (data guards), Phase 8 (code exec), Phase 9 (service mesh), Phase 10 (orchestration), Phase 11 (content/streaming/iac), Phase 12 (observability), Phase 13 (external guards), Phase 14 (portable kernel), Phase 15 (compliance), Phase 16 (economics), Phase 17 (workflow orchestrators), Phase 18 (memory), Phase 19 (regulatory), Phase 20 (capstone). Plus adjacent
TEE attested-checkpoint-binding scope work (`ed2614f`) that is not a numbered
roadmap phase.

| Phase group | Shipped | In flight | Pending |
|---|---|---|---|
| 0 (DX) | 0.1, 0.2, 0.3, 0.4, 0.5 | -- | -- |
| 1 (Structural security) | 1.1, 1.2, 1.3, 1.4, 1.5 | -- | -- |
| 2 (Types) | 2.1, 2.2, 2.3, 2.4 | -- | -- |
| 3 (Content safety / HITL) | 3.1, 3.2, 3.3, 3.4, 3.5, 3.6 | -- | -- |
| 4 (Code agent) | 4.1, 4.2, 4.3 | -- | -- |
| 5 (Guard absorption) | 5.1, 5.2, 5.3, 5.4, 5.5, 5.6 | -- | -- |
| 6 (Framework SDKs) | 6.1, 6.2, 6.3, 6.4 | -- | -- |
| 7 (Data guards) | 7.1, 7.2, 7.3, 7.4 | -- | -- |
| 8 (Code exec) | 8.1, 8.2 | -- | -- |
| 9 (Service mesh) | 9.1, 9.2 | -- | -- |
| 10 (Orchestration) | 10.1, 10.2, 10.3 | -- | -- |
| 11 (Content / streaming / IaC) | 11.1, 11.2, 11.3 | -- | -- |
| 12 (Observability) | 12.1, 12.2, 12.3 | -- | -- |
| 13 (External guards) | 13.1, 13.2, 13.3 | -- | -- |
| 14 (Portable kernel) | 14.1, 14.2, 14.3 | -- | -- |
| 15 (Compliance) | 15.1, 15.2, 15.3, 15.4, 15.5 | -- | -- |
| 16 (Economics) | 16.1, 16.2 | -- | -- |
| 17 (Workflow orchestrators) | 17.1, 17.2, 17.3, 17.4, 17.5, 17.6 | -- | -- |
| 18 (Memory) | 18.1, 18.2 | -- | -- |
| 19 (Regulatory) | 19.1, 19.2, 19.3 | -- | -- |
| 20 (Capstone) | 20.1, 20.2, 20.3, 20.4 | -- | -- |

All phase groups in the table above are fully shipped.

---

## Phase 0: Developer Experience Foundation

> **Goal**: External developers can install, try, and test Chio without
> compiling Rust or cloning the repo.
> **Depends on**: Nothing. Unblocks everything.
> **Refs**: `docs/protocols/DX-AND-ADOPTION-ROADMAP.md`

### 0.1 Publish Python SDKs to PyPI [SHIPPED 9eeea0f]

**What**: Publish `chio-sdk-python`, `chio-fastapi`, `chio-asgi`, `chio-django`,
`chio-langchain` to PyPI. Set up CI to publish on git tag.

**Files**:
- `sdks/python/chio-sdk-python/pyproject.toml` (add PyPI metadata, classifiers)
- `sdks/python/chio-fastapi/pyproject.toml`
- `sdks/python/chio-asgi/pyproject.toml`
- `sdks/python/chio-django/pyproject.toml`
- `sdks/python/chio-langchain/pyproject.toml`
- `.github/workflows/publish-python.yml` (new: CI publish on tag)

**Refs**: `docs/protocols/DX-AND-ADOPTION-ROADMAP.md` section 1

**Acceptance**: `pip install chio-sdk-python` works from a clean venv.

### 0.2 Publish TypeScript SDKs to npm [SHIPPED 9eeea0f]

**What**: Publish `@chio-protocol/node-http`, `@chio-protocol/express`,
`@chio-protocol/fastify`, `@chio-protocol/elysia` to npm.

**Files**:
- `sdks/typescript/packages/*/package.json` (add npm metadata)
- `.github/workflows/publish-typescript.yml` (new)

**Refs**: `docs/protocols/DX-AND-ADOPTION-ROADMAP.md` section 1

**Acceptance**: `npm install @chio-protocol/node-http` works.

### 0.3 MockChioClient for Testing [SHIPPED 788f69c]

**What**: Ship test fixtures so developers can write unit tests without
a running sidecar.

**Files**:
- `sdks/python/chio-sdk-python/src/chio_sdk/testing.py` (new: `MockChioClient`, `allow_all()`, `deny_all()`, `with_policy()`)
- `sdks/python/chio-sdk-python/tests/test_mock_client.py` (new)
- `sdks/typescript/packages/node-http/src/testing.ts` (new)

**Refs**: `docs/protocols/DX-AND-ADOPTION-ROADMAP.md` section 2

**Acceptance**: A pytest test using `MockChioClient` passes without any
sidecar process running.

### 0.4 Pre-Built Binary Distribution [SHIPPED c9650f9]

**What**: Distribute the Chio sidecar as pre-built binaries so developers
don't need the Rust toolchain.

**Files**:
- `.github/workflows/release-binaries.yml` (new: cross-compile for linux-x86_64, linux-aarch64, darwin-x86_64, darwin-aarch64, windows-x86_64)
- `Homebrew/chio.rb.tmpl` release formula template (new)
- `Dockerfile.sidecar` (public image, no GHCR auth required)

**Refs**: `docs/protocols/DX-AND-ADOPTION-ROADMAP.md` section 3

**Acceptance**: `brew install chio` or `docker run ghcr.io/backbay-labs/chio-sidecar:latest` works without Rust installed.

### 0.5 Error Message Improvements [SHIPPED 224a05c]

**What**: `ChioDeniedError` includes what was denied, what scope was needed
vs granted, which guard denied, and a next-steps suggestion.

**Files**:
- `sdks/python/chio-sdk-python/src/chio_sdk/errors.py`
- `crates/chio-http-core/src/verdict.rs` (enrich Deny variant)

**Refs**: `docs/protocols/DX-AND-ADOPTION-ROADMAP.md` section 6

**Acceptance**: A denied tool call prints a message that tells the
developer exactly what scope to request.

---

## Phase 1: Structural Security Fixes

> **Goal**: Close the three architectural gaps the red team found.
> **Depends on**: Nothing (can run parallel to Phase 0).
> **Refs**: `docs/protocols/STRUCTURAL-SECURITY-FIXES.md`

### 1.1 Execution Nonces (TOCTOU Fix) [SHIPPED f6d42a3]

**What**: Kernel issues a short-lived `ExecutionNonce` with each allow
verdict. Tool servers validate the nonce before executing. Closes the
window between evaluate() and execution.

**Files**:
- `crates/chio-kernel/src/execution_nonce.rs` (new: `ExecutionNonce`, `ExecutionNonceStore`)
- `crates/chio-kernel/src/kernel/mod.rs` (issue nonce in evaluate response)
- `crates/chio-http-core/src/verdict.rs` (add nonce to allow verdict)
- `crates/chio-core-types/src/lib.rs` (ExecutionNonce type)

**Refs**: `docs/protocols/STRUCTURAL-SECURITY-FIXES.md` section 1

**Acceptance**: A tool call presented >30s after evaluation is rejected.
A tool call with a replayed nonce is rejected.

### 1.2 Trust Level Taxonomy [SHIPPED 27488eb]

**What**: Define three trust levels (Mediated, Verified, Advisory).
Record trust level on every receipt. Document which integration pattern
provides which trust level.

**Files**:
- `crates/chio-core-types/src/capability.rs` (add `TrustLevel` enum)
- `crates/chio-kernel/src/kernel/mod.rs` (record trust level on receipts)
- `docs/protocols/STRUCTURAL-SECURITY-FIXES.md` (already designed)

**Refs**: `docs/protocols/STRUCTURAL-SECURITY-FIXES.md` section 2

**Acceptance**: Receipts from mediated evaluations are distinguishable
from advisory ones. Operators can filter receipts by trust level.

### 1.3 WASM Guard Module Signing [SHIPPED 3e258a3]

**What**: Require Ed25519 signatures on `.wasm` guard binaries. Verify
at load time. Reject unsigned modules unless explicitly opted out.

**Files**:
- `crates/chio-wasm-guards/src/manifest.rs` (add signature field)
- `crates/chio-wasm-guards/src/runtime.rs` (verify before compilation)
- `crates/chio-cli/src/guards/sign.rs` (new: `chio guard sign` command)

**Refs**: `docs/protocols/STRUCTURAL-SECURITY-FIXES.md` section 4

**Acceptance**: Loading an unsigned WASM guard fails with a clear error.
`chio guard sign` produces a signed module that loads successfully.

### 1.4 Emergency Kill Switch [SHIPPED 225193d]

**What**: `kernel.emergency_stop()` revokes all active capabilities,
rejects all new evaluate() calls. `kernel.emergency_resume()` re-enables.
Exposed via authenticated HTTP API.

**Files**:
- `crates/chio-kernel/src/kernel/mod.rs` (add `AtomicBool` emergency flag, check in evaluate path)
- `crates/chio-http-core/src/routes.rs` (add `/emergency-stop` and `/emergency-resume` endpoints)

**Refs**: `docs/protocols/STRUCTURAL-SECURITY-FIXES.md` section 5

**Acceptance**: After `POST /emergency-stop`, all evaluate() calls return
Deny. After `POST /emergency-resume`, normal operation resumes.

### 1.5 Multi-Tenant Receipt Isolation [SHIPPED 2ccf02f]

**What**: Add `tenant_id` to receipts. Enforce query isolation at the
store level. Tenant derived from auth context, not caller choice.

**Current state**: `tenant_id` exists in session/enterprise identity
context (`chio-core-types/src/session.rs`) but NOT on receipts
(`chio-core-types/src/receipt.rs`) or in the receipt store. This story
is untouched -- the file paths below point at files that need modification,
not files that already have this feature.

**Files**:
- `crates/chio-store-sqlite/src/receipt_store.rs` (modify: add tenant_id column, WHERE clause)
- `crates/chio-core-types/src/receipt.rs` (modify: add tenant_id field)
- `crates/chio-kernel/src/kernel/mod.rs` (modify: populate tenant_id from session)

**Refs**: `docs/protocols/STRUCTURAL-SECURITY-FIXES.md` section 6

**Acceptance**: Receipts from tenant A are invisible to tenant B queries.

---

## Phase 2: Core Type Evolution

> **Goal**: Add the new ToolAction variants and Constraint variants needed
> by all downstream phases. This is the foundation that guards, framework
> integrations, and data layer work all depend on.
> **Current state**: ToolAction in `chio-guards/src/action.rs` and Constraint
> in `chio-core-types/src/capability.rs` are still the pre-ADR shapes. None
> of the new variants (DatabaseQuery, CodeExecution, BrowserAction,
> ModelConstraint, TableAllowlist, etc.) exist in code yet. Plan-level
> evaluation types do not exist. This phase is untouched.
> **Depends on**: Nothing (can run parallel to Phases 0-1).
> **Refs**: `docs/protocols/ADR-TYPE-EVOLUTION.md` (canonical shapes)

### 2.1 New ToolAction Variants [SHIPPED f5a8a58]

**What**: Add `CodeExecution`, `BrowserAction`, `DatabaseQuery`,
`ExternalApiCall`, `MemoryWrite` to the `ToolAction` enum. Update
`extract_action()` to populate them from tool call arguments.

**Files**:
- `crates/chio-guards/src/action.rs` (add variants per ADR-TYPE-EVOLUTION.md section 3)
- `crates/chio-guards/src/action.rs` fn `extract_action()` (add heuristics for new tool names)

**Refs**: `docs/protocols/ADR-TYPE-EVOLUTION.md` section 3

**Acceptance**: `extract_action("sql_query", args)` returns `ToolAction::DatabaseQuery { ... }`.
Existing guards continue to work (Unknown fallback unchanged).

### 2.2 New Constraint Variants [SHIPPED f6a8820]

**What**: Add data layer, communication, financial, model routing, and
memory governance constraints to the `Constraint` enum.

**Files**:
- `crates/chio-core-types/src/capability.rs` (add variants per ADR-TYPE-EVOLUTION.md section 3)
- `crates/chio-kernel/src/kernel/mod.rs` (constraint checking for new variants)

**Refs**: `docs/protocols/ADR-TYPE-EVOLUTION.md` section 3

**Acceptance**: A `ToolGrant` with `TableAllowlist(["users", "orders"])`
compiles, serializes, and is enforced by the kernel.

### 2.3 ModelConstraint Implementation [SHIPPED 0cd2517]

**What**: Kernel evaluates `ModelConstraint` against `model_metadata` on
`ToolCallRequest`. Add `ModelMetadata` and `ModelSafetyTier` types.

**Files**:
- `crates/chio-core-types/src/capability.rs` (ModelMetadata, ModelSafetyTier, ModelConstraint)
- `crates/chio-kernel/src/kernel/mod.rs` (constraint evaluation logic)

**Refs**: `docs/protocols/ARCHITECTURAL-EXTENSIONS.md` section 1

**Acceptance**: A tool call with `model_metadata.model_id = "small-uncensored"`
is denied when the grant requires `min_safety_tier: Standard`.

### 2.4 Plan-Level Evaluation [SHIPPED 6e16017]

**What**: New `evaluate_plan()` kernel method and `/evaluate-plan` HTTP
endpoint. Takes a list of planned tool calls, evaluates all against scope
and guards, returns per-step verdicts before any execute.

**Files**:
- `crates/chio-core-types/src/plan.rs` (new: `PlannedToolCall`, `PlanEvaluationRequest`, `PlanEvaluationResponse`, `PlanVerdict`)
- `crates/chio-kernel/src/kernel/mod.rs` (add `evaluate_plan()`)
- `crates/chio-http-core/src/routes.rs` (add `/evaluate-plan` endpoint)

**Refs**: `docs/protocols/ARCHITECTURAL-EXTENSIONS.md` section 2

**Acceptance**: A 3-step plan where step 3 is out-of-scope returns
`plan_verdict: PartiallyDenied` with step 3 flagged, before any tool executes.

---

## Phase 3: Content Safety and Human-in-the-Loop

> **Goal**: Close the two P0 gaps: content plane governance and HITL.
> **Depends on**: Phase 2 (ToolAction variants).
> **Refs**: `docs/guards/06-CONTENT-SAFETY-ABSORPTION.md`,
> `docs/protocols/HUMAN-IN-THE-LOOP-PROTOCOL.md`

### 3.1 PromptInjectionGuard (port from the prior internal guard library) [SHIPPED 3d55e18]

**What**: Port the prior internal guard library's 6-signal prompt injection detector to Chio's
sync Guard trait. Includes text canonicalization and fingerprint dedup.

**Files**:
- `crates/chio-guards/src/prompt_injection.rs` (new)
- `crates/chio-guards/src/text_utils.rs` (new: canonicalization, shared with jailbreak)
- `crates/chio-guards/src/lib.rs` (register)

**Source**: the prior internal guard library
**Refs**: `docs/guards/06-CONTENT-SAFETY-ABSORPTION.md` section 1.2, 5.2

**Acceptance**: Guard detects "ignore previous instructions" patterns and
returns Deny. Existing guards unaffected.

### 3.2 JailbreakGuard (port from the prior internal guard library) [SHIPPED 2da8f19]

**What**: Port the 4-layer jailbreak detector (heuristic, statistical, ML
scoring, optional LLM judge). LLM judge deferred to host function in v2.

**Files**:
- `crates/chio-guards/src/jailbreak.rs` (new)
- `crates/chio-guards/src/jailbreak_detector.rs` (new: ML scoring layer)

**Source**: the prior internal guard library
**Refs**: `docs/guards/06-CONTENT-SAFETY-ABSORPTION.md` section 1.1, 5.1

**Acceptance**: Guard detects multi-layer jailbreak attempts. Configurable
threshold for sensitivity.

### 3.3 Output Sanitizer Completion [SHIPPED 8d0cbb1]

**What**: Complete the partial port of the prior internal guard library's output sanitizer.
Add secret detection, entropy scanning, Luhn validation, allowlist/denylist,
overlap resolution, and full redaction strategy support.

**Files**:
- `crates/chio-guards/src/response_sanitization.rs` (extend existing)
- `crates/chio-guards/src/post_invocation.rs` (extend pipeline)

**Source**: the prior internal guard library
**Refs**: `docs/guards/07-OUTPUT-SANITIZER-ABSORPTION.md`

**Acceptance**: Post-invocation guard redacts SSNs, credit cards (Luhn-validated),
API keys, and high-entropy strings from tool results.

### 3.4 Human-in-the-Loop: Kernel Verdict Extension [SHIPPED c1ac528]

**What**: Add `Verdict::PendingApproval(ApprovalRequest)` to the kernel.
Implement the approval guard, approval store, and resume flow.

**Files**:
- `crates/chio-kernel/src/runtime.rs` (add PendingApproval variant)
- `crates/chio-kernel/src/approval.rs` (new: `ApprovalGuard`, `ApprovalStore`, `BatchApprovalStore`)
- `crates/chio-http-core/src/routes.rs` (add `/approvals/pending`, `/approvals/{id}/respond`, `/approvals/batch`)
- `crates/chio-kernel/src/kernel/mod.rs` (integrate approval guard, resume validation)

**Refs**: `docs/protocols/HUMAN-IN-THE-LOOP-PROTOCOL.md` sections 2-10, 13

**Acceptance**: A tool call requiring approval pauses, sends a webhook,
waits for human response. Approved call executes; denied call records
denial receipt. Replay of consumed approval token is rejected.

### 3.5 HITL Persistence Backend [SHIPPED c1ac528]

**What**: Pending approvals must survive kernel restart. Implement
`ApprovalStore` and `BatchApprovalStore` traits with SQLite backend.
Pending requests are written to durable storage; on restart, the kernel
reloads pending requests and resumes listening for responses.

**Files**:
- `crates/chio-store-sqlite/src/approval_store.rs` (new: `SqliteApprovalStore`)
- `crates/chio-store-sqlite/src/batch_approval_store.rs` (new: `SqliteBatchApprovalStore`)
- `crates/chio-kernel/src/approval.rs` (define `ApprovalStore`, `BatchApprovalStore` traits)

**Refs**: `docs/protocols/HUMAN-IN-THE-LOOP-PROTOCOL.md` sections 10, 13
(specifically: "Pending requests survive in approval store" at the
fail-closed table, and the `ApprovalStore`/`BatchApprovalStore` contracts)

**Acceptance**: Kill the kernel process while an approval is pending.
Restart the kernel. The pending approval is still queryable via
`GET /approvals/pending`. Responding to it resumes tool execution.

### 3.6 Approval Channels [SHIPPED c1ac528]

**What**: Implement `ApprovalChannel` trait and webhook channel. Slack
and dashboard channels follow.

**Files**:
- `crates/chio-kernel/src/approval_channels.rs` (new: trait + WebhookChannel)

**Refs**: `docs/protocols/HUMAN-IN-THE-LOOP-PROTOCOL.md` section 6

**Acceptance**: Webhook fires on pending approval. Response via
`POST /approvals/{id}/respond` resumes execution.

---

## Phase 4: Flagship Integration -- chio-code-agent

> **Goal**: Ship the single fastest onboarding experience. A coding agent
> developer installs one package and gets Chio protecting file/shell/git.
> **Depends on**: Phase 0 (package publishing, test fixtures).
> **Refs**: `docs/protocols/DX-AND-ADOPTION-ROADMAP.md` section 4

### 4.1 chio-code-agent Python Package [SHIPPED e38d41b]

**What**: Wraps file, shell, and git tool calls for coding agents. Ships
with a zero-config default policy. Works with Claude Code, Cursor, or
any MCP-based coding agent.

**Files**:
- `sdks/python/chio-code-agent/pyproject.toml` (new)
- `sdks/python/chio-code-agent/src/chio_code_agent/__init__.py` (new)
- `sdks/python/chio-code-agent/src/chio_code_agent/policy.py` (new: default policy)
- `sdks/python/chio-code-agent/src/chio_code_agent/agent.py` (new: CodeAgent wrapper)
- `sdks/python/chio-code-agent/tests/test_code_agent.py` (new)

**Refs**: `docs/protocols/DX-AND-ADOPTION-ROADMAP.md` sections 4.1-4.5

**Acceptance**: `pip install chio-code-agent` works. A 10-line Python script
demonstrates safe file reads allowed and `.env` writes denied.

### 4.2 MCP Sidecar Wrapper for Coding Agents [SHIPPED e38d41b]

**What**: `chio mcp serve` with the default code-agent policy. One command
wraps any MCP filesystem server with Chio.

**Files**:
- `crates/chio-cli/src/policies/code_agent.yaml` (new: bundled default policy)
- `crates/chio-cli/src/mcp/serve.rs` (add `--preset code-agent` flag)

**Refs**: `docs/protocols/DX-AND-ADOPTION-ROADMAP.md` section 4.4

**Acceptance**: `chio mcp serve --preset code-agent -- npx @modelcontextprotocol/server-filesystem .`
wraps the MCP server with Chio. File reads allowed, `.env` writes denied.

### 4.3 Migration Guide: MCP to Chio [SHIPPED e38d41b]

**What**: Step-by-step guide for adding Chio to existing MCP setups.

**Files**:
- `docs/guides/MIGRATING-FROM-MCP.md` (new)

**Refs**: `docs/protocols/DX-AND-ADOPTION-ROADMAP.md` section 7

**Acceptance**: A developer with an existing MCP server can follow the
guide in <5 minutes and have Chio protecting their tool calls.

---

## Phase 5: Guard Absorption (Remaining)

> **Goal**: Port the remaining 4 guards and 2 subsystems from the prior internal guard library.
> **Depends on**: Phase 2 (ToolAction variants for CUA).
> **Refs**: `docs/guards/08-DESKTOP-CUA-GUARD-ABSORPTION.md`,
> `docs/guards/09-POLICY-ENGINE-ABSORPTION.md`,
> `docs/guards/12-SELECTIVE-ABSORPTION-PLAN.md`

### 5.1 ComputerUseGuard [SHIPPED 8593a9b]

**What**: Port action-type allowlisting with Observe/Guardrail/FailClosed modes.

**Files**:
- `crates/chio-guards/src/computer_use.rs` (new)

**Source**: the prior internal guard library
**Refs**: `docs/guards/08-DESKTOP-CUA-GUARD-ABSORPTION.md` section 1.1

**Acceptance**: BrowserAction::Navigate to a blocked domain returns Deny.
Screenshot actions respect rate limits.

### 5.2 InputInjectionCapabilityGuard [SHIPPED 8593a9b]

**What**: Port input-type restrictions and postcondition probe validation.

**Files**:
- `crates/chio-guards/src/input_injection.rs` (new)

**Source**: the prior internal guard library
**Refs**: `docs/guards/08-DESKTOP-CUA-GUARD-ABSORPTION.md` section 1.2

**Acceptance**: Keyboard input injection denied when input type not in
allowlist. Actions without postcondition probes denied in strict mode.

### 5.3 RemoteDesktopSideChannelGuard [SHIPPED 8593a9b]

**What**: Port per-channel enable/disable with transfer size limits.

**Files**:
- `crates/chio-guards/src/remote_desktop.rs` (new)

**Source**: the prior internal guard library
**Refs**: `docs/guards/08-DESKTOP-CUA-GUARD-ABSORPTION.md` section 1.3

**Acceptance**: Clipboard transfer denied when clipboard channel disabled.
File transfer exceeding size limit denied. Unknown channels denied
(fail-closed).

### 5.4 SpiderSense Embedding Detector [SHIPPED 8593a9b]

**What**: Port cosine similarity anomaly detection. Sync guard using
pre-computed pattern database.

**Files**:
- `crates/chio-guards/src/spider_sense.rs` (new)
- `crates/chio-guards/data/spider_sense_patterns.json` (new: pattern DB)

**Source**: the prior internal guard library
**Refs**: `docs/guards/06-CONTENT-SAFETY-ABSORPTION.md` section 1.3, 4.1

**Acceptance**: Tool call arguments with high cosine similarity to known
threat patterns return Deny. Arguments below the ambiguity threshold
return Allow. Pattern database loads from JSON at guard init.

### 5.5 Policy Engine: Guard Compilation [SHIPPED b595653]

**What**: Port the prior internal guard library's policy-to-guard compiler. HushSpec YAML compiles
to guard instances registered on the kernel. Complete the 5 missing guard
types in the compilation pipeline.

**Files**:
- `crates/chio-policy/src/compiler.rs` (extend: add missing guard types)
- `crates/chio-policy/src/rulesets/` (new: port 7 built-in rulesets from the prior internal guard library)

**Source**: the prior internal guard library
**Refs**: `docs/guards/09-POLICY-ENGINE-ABSORPTION.md` sections 1-6

**Acceptance**: `compile_policy(yaml)` produces a Vec<Box<dyn Guard>>
that includes all 12 guard types.

### 5.6 Custom Guard Registry: WASM Merge [SHIPPED c381458]

**What**: Add policy-driven WASM guard loading. Placeholder resolution for
env vars in guard config. Capability intersection on load.

**Files**:
- `crates/chio-wasm-guards/src/runtime.rs` (add `load_guards_from_policy()`)
- `crates/chio-wasm-guards/src/placeholders.rs` (new: `resolve_placeholders()`)

**Source**: the prior internal guard library
**Refs**: `docs/guards/12-SELECTIVE-ABSORPTION-PLAN.md` section 1

**Acceptance**: A policy YAML with a `custom_guards` section loads a WASM
guard module, resolves `${ENV_VAR}` placeholders in config, and runs the
guard in the pipeline. Capability intersection restricts which host
functions the WASM module can call.

---

## Phase 6: Agent Framework SDKs

> **Goal**: Ship working packages for the top 4 agent frameworks.
> **Depends on**: Phase 0 (publishing, MockChioClient), Phase 2 (type extensions).
> **Refs**: `docs/protocols/AGENT-FRAMEWORK-INTEGRATION.md`

### 6.1 chio-crewai (Highest Priority) [SHIPPED dfcb780]

**What**: `BaseTool` wrapper, per-role capability scoping, delegation
between crews. Published to PyPI.

**Files**:
- `sdks/python/chio-crewai/pyproject.toml` (new)
- `sdks/python/chio-crewai/src/chio_crewai/__init__.py` (new)
- `sdks/python/chio-crewai/src/chio_crewai/tool.py` (new: ChioBaseTool)
- `sdks/python/chio-crewai/src/chio_crewai/crew.py` (new: ChioCrew with scoping)
- `sdks/python/chio-crewai/tests/` (new)

**Refs**: `docs/protocols/AGENT-FRAMEWORK-INTEGRATION.md` section 1

**Acceptance**: A CrewAI crew where the researcher agent can search but not
write, and the writer agent can write but not search.

### 6.2 chio-autogen [SHIPPED 1b8f77e]

**What**: Function registration wrapper, group chat governance, nested
chat delegation.

**Files**:
- `sdks/python/chio-autogen/` (new package)

**Refs**: `docs/protocols/AGENT-FRAMEWORK-INTEGRATION.md` section 2

**Acceptance**: An AutoGen GroupChat where registered functions are
Chio-governed. Nested chat spawns get attenuated capability tokens.

### 6.3 chio-llamaindex [SHIPPED 1dd8361]

**What**: FunctionTool wrapper, QueryEngineTool scoping for RAG pipelines.

**Files**:
- `sdks/python/chio-llamaindex/` (new package)

**Refs**: `docs/protocols/AGENT-FRAMEWORK-INTEGRATION.md` section 3

**Acceptance**: A LlamaIndex `AgentRunner` with `ChioFunctionTool` that
evaluates each tool dispatch through the sidecar. QueryEngineTool
scoped to specific vector collections.

### 6.4 @chio-protocol/ai-sdk (Vercel AI SDK) [SHIPPED 9c973fe]

**What**: `chioTool()` wrapper preserving streaming. Published to npm.

**Files**:
- `sdks/typescript/packages/ai-sdk/` (new package)

**Refs**: `docs/protocols/AGENT-FRAMEWORK-INTEGRATION.md` section 4

**Acceptance**: `chioTool()` wrapping a Vercel AI SDK `tool()` evaluates
via sidecar without breaking `ReadableStream` / SSE streaming.

---

## Phase 7: Data Layer Guards

> **Goal**: Govern SQL queries, vector DB access, and warehouse costs.
> **Depends on**: Phase 2 (Constraint variants, DatabaseQuery ToolAction).
> **Refs**: `docs/guards/10-DATA-LAYER-GUARDS.md`,
> `docs/protocols/DATA-LAYER-INTEGRATION.md`

### 7.1 SqlQueryGuard [SHIPPED b3666a9]

**What**: Parses SQL using `sqlparser-rs`. Checks tables, columns,
operations, predicates, LIMIT clauses. Fail-closed on parse failure.
Blocks DELETE/UPDATE without WHERE.

**Files**:
- `crates/chio-data-guards/Cargo.toml` (new crate, dep on sqlparser)
- `crates/chio-data-guards/src/lib.rs` (new)
- `crates/chio-data-guards/src/sql_guard.rs` (new)
- `crates/chio-data-guards/src/sql_parser.rs` (new: dialect-aware analysis)

**Refs**: `docs/guards/10-DATA-LAYER-GUARDS.md` section 3.1

**Acceptance**: `SELECT * FROM users` denied when `ColumnDenylist` is active.
`DELETE FROM users` denied (no WHERE). `SELECT name FROM users WHERE tenant_id = 'acme' LIMIT 100` allowed.

### 7.2 VectorDbGuard [SHIPPED 102c805]

**What**: Collection/namespace scoping, operation class, top_k limits,
embedding exfiltration protection.

**Files**:
- `crates/chio-data-guards/src/vector_guard.rs` (new)

**Refs**: `docs/guards/10-DATA-LAYER-GUARDS.md` section 3.2

**Acceptance**: Query to collection not in `CollectionAllowlist` denied.
Cross-namespace access denied. Upsert denied when operation class is
ReadOnly. `top_k=500` denied when `MaxRowsReturned=50`.

### 7.3 WarehouseCostGuard [SHIPPED 5a0da48]

**What**: Pre-execution cost estimation via dry-run results in tool
arguments. MaxBytesScanned and MaxCostPerQuery enforcement.

**Files**:
- `crates/chio-data-guards/src/warehouse_cost_guard.rs` (new)
- `crates/chio-metering/src/lib.rs` (add `CostDimension::WarehouseQuery`)

**Refs**: `docs/guards/10-DATA-LAYER-GUARDS.md` section 3.3,
`docs/protocols/DATA-LAYER-INTEGRATION.md` section 5.3

**Acceptance**: Query estimating 50GB scan denied when `MaxBytesScanned=1GB`.
Query estimating $0.25 allowed when `MaxCostPerQuery=$5.00`. Receipt
records `CostDimension::WarehouseQuery` with actual bytes and cost.

### 7.4 QueryResultGuard (Post-Invocation) [PARTIAL d8e4514]

> Shipped as `redact_result` transform and `PostInvocationPipeline` adapter.
> Kernel post-invocation hook wiring is deferred until the kernel exposes
> that surface.


**What**: Row count enforcement, column redaction, PII pattern matching
on query results.

**Files**:
- `crates/chio-data-guards/src/result_guard.rs` (new)

**Refs**: `docs/guards/10-DATA-LAYER-GUARDS.md` section 4

**Acceptance**: Post-invocation guard truncates results exceeding
`MaxRowsReturned`. Columns in `ColumnDenylist` are redacted from results
before returning to the agent.

---

## Phase 8: Code Execution Guards

> **Goal**: Govern sandbox code execution and browser automation.
> **Depends on**: Phase 2 (CodeExecution and BrowserAction ToolAction variants).
> **Refs**: `docs/guards/13-CODE-EXECUTION-GUARDS.md`

### 8.1 CodeExecutionGuard [SHIPPED 8b650e1]

**What**: Language allowlist, network access control, execution time
limits, dangerous module detection (os, subprocess, socket).

**Files**:
- `crates/chio-guards/src/code_execution.rs` (new)

**Refs**: `docs/guards/13-CODE-EXECUTION-GUARDS.md` section 2

**Acceptance**: Code execution with `language=bash` denied when allowlist
is `["python"]`. Code containing `import subprocess` denied by dangerous
module detection. Network access denied when `network_access=false` on
the constraint.

### 8.2 BrowserAutomationGuard [SHIPPED 8b650e1]

**What**: Domain allowlists, action-type restrictions, credential
detection in Type actions.

**Files**:
- `crates/chio-guards/src/browser_automation.rs` (new)

**Refs**: `docs/guards/13-CODE-EXECUTION-GUARDS.md` section 3

**Acceptance**: Browser navigation to a domain not in the allowlist is
denied. A read-only browser session (navigate + screenshot only) denies
click and type actions. Credential patterns in Type action text trigger
Deny.

---

## Phase 9: Networking -- Envoy ext_authz

> **Goal**: One adapter puts Chio into every Envoy-based mesh.
> **Depends on**: Nothing (uses existing sidecar endpoint).
> **Refs**: `docs/protocols/ENVOY-EXT-AUTHZ-INTEGRATION.md`

### 9.1 gRPC ext_authz Adapter [SHIPPED 7f4d0d7]

**What**: Implement `envoy.service.auth.v3.Authorization/Check` as a thin
shim over Chio's `/evaluate` endpoint.

**Files**:
- `crates/chio-envoy-ext-authz/Cargo.toml` (new crate)
- `crates/chio-envoy-ext-authz/src/lib.rs` (new)
- `crates/chio-envoy-ext-authz/src/grpc_service.rs` (new)
- `crates/chio-envoy-ext-authz/proto/` (vendored envoy auth proto)

**Refs**: `docs/protocols/ENVOY-EXT-AUTHZ-INTEGRATION.md` sections 3-4

**Acceptance**: An Envoy sidecar with ext_authz pointing at Chio correctly
allows/denies traffic based on Chio capability evaluation.

### 9.2 Istio Integration Example [SHIPPED 929e4ab]

**What**: Reference `AuthorizationPolicy` + ext_authz provider config.

**Files**:
- `examples/istio-ext-authz/` (new: K8s manifests, README)

**Refs**: `docs/protocols/ENVOY-EXT-AUTHZ-INTEGRATION.md` section 6

**Acceptance**: An Istio mesh with the reference `AuthorizationPolicy`
routes ext_authz checks to the Chio adapter. `x-chio-receipt-id` header
appears on responses passing through the mesh.

---

## Phase 10: Orchestration Integrations

> **Goal**: Ship the top 3 orchestration SDKs.
> **Depends on**: Phase 0 (publishing). **10.3 (chio-langgraph) additionally
> depends on Phase 3 (HITL)** because it maps LangGraph `interrupt()` to
> Chio approval guards (see `LANGGRAPH-INTEGRATION.md` section 3.3).
> 10.1 and 10.2 also reference approval-aware flows but can ship a basic
> version without HITL and add approval support after Phase 3 lands.
> **Refs**: `docs/protocols/TEMPORAL-INTEGRATION.md`,
> `docs/protocols/AWS-LAMBDA-INTEGRATION.md`,
> `docs/protocols/LANGGRAPH-INTEGRATION.md`

### 10.1 chio-temporal (Python) [SHIPPED 811fbb8]

**What**: `ChioActivityInterceptor`, `WorkflowGrant`, receipt aggregation.
Basic version ships without HITL; approval-aware activities added after
Phase 3.

**Files**:
- `sdks/python/chio-temporal/` (new package)

**Refs**: `docs/protocols/TEMPORAL-INTEGRATION.md`

**Acceptance**: A Temporal workflow where each Activity is capability-checked.
Denied activities raise non-retryable `ApplicationError`. WorkflowReceipt
aggregates step receipts on completion.

### 10.2 chio-lambda-extension [SHIPPED 82b69d4]

**What**: Chio kernel as Lambda Extension. Pre-built Layer for arm64/x86_64.

**Files**:
- `sdks/lambda/chio-lambda-extension/` (new: Rust binary)
- `sdks/lambda/chio-lambda-python/` (new: Python client)

**Refs**: `docs/protocols/AWS-LAMBDA-INTEGRATION.md`

**Acceptance**: A Lambda function with the Chio Extension Layer evaluates
tool calls via the extension's localhost:9090. Receipts flushed to
DynamoDB on SHUTDOWN lifecycle event.

### 10.3 chio-langgraph (depends on Phases 0 and 3) [SHIPPED 7c2df6b]

**What**: `chio_node` wrapper, node-level scoping, delegation, approval nodes.
Requires HITL (Phase 3) because `chio_approval_node` maps LangGraph
`interrupt()` to Chio's `Verdict::PendingApproval`.

**Files**:
- `sdks/python/chio-langgraph/` (new package)

**Refs**: `docs/protocols/LANGGRAPH-INTEGRATION.md`

**Acceptance**: A LangGraph state graph with `chio_node` wrappers where
each node operates under a scoped capability. `chio_approval_node` pauses
the graph via `interrupt()`, waits for human approval, and resumes.
Subgraph nodes cannot exceed the parent graph's scope ceiling.

---

## Phase 11: SaaS, Communication, and Streaming

> **Goal**: Govern external-facing agent actions (messages, payments, pages)
> and event-driven agent architectures.
> **Depends on**: Phase 2 (ExternalApiCall ToolAction), Phase 3 (HITL for approvals).
> **Refs**: `docs/protocols/SAAS-COMMUNICATION-INTEGRATION.md`,
> `docs/protocols/EVENT-STREAMING-INTEGRATION.md`

### 11.1 Content-Review Guard [SHIPPED 8b650e1]

**What**: Pre-invocation guard that inspects outbound content (message body,
email text, payment amounts). PII detection, tone/profanity, configurable
per-service.

**Files**:
- `crates/chio-guards/src/content_review.rs` (new)

**Refs**: `docs/protocols/SAAS-COMMUNICATION-INTEGRATION.md` section 6

**Acceptance**: A Slack message tool call with PII in the body is denied.
A Stripe charge above `RequireApprovalAbove` threshold triggers HITL.
Guard evidence includes detected PII categories.

### 11.2 chio-streaming (Kafka Consumer Middleware) [SHIPPED d42eb02]

**What**: `ChioConsumerMiddleware` for Kafka. Consumer-side evaluation,
transactional receipt commit, DLQ governance.

**Files**:
- `sdks/python/chio-streaming/` (new package)

**Refs**: `docs/protocols/EVENT-STREAMING-INTEGRATION.md`

**Acceptance**: A Kafka consumer with `ChioConsumerMiddleware` evaluates
capabilities before processing events. Denied events routed to DLQ with
denial receipt. Offset commit and receipt are transactionally atomic.

### 11.3 IaC Governance (chio-iac) [SHIPPED 4177cad]

**What**: Terraform CLI wrapper with plan/apply two-phase capability.
Pulumi decorators.

**Files**:
- `sdks/python/chio-iac/` (new package)

**Refs**: `docs/protocols/IAC-INTEGRATION.md`

**Acceptance**: `terraform plan` requires `infra:plan` scope.
`terraform apply` requires `infra:apply` scope + plan-review guard.
Resource types outside granted scopes are denied.

---

## Phase 12: SIEM and Observability Completion

> **Goal**: Complete SIEM exporter coverage and add observability bridges.
> **Depends on**: Nothing.
> **Refs**: `docs/guards/11-SIEM-OBSERVABILITY-COMPLETION.md`

### 12.1 Missing SIEM Exporters [SHIPPED 4c8472b]

**What**: Port Datadog, Sumo Logic, webhook, and alerting exporters from
the prior internal guard library.

**Files**:
- `crates/chio-siem/src/exporters/datadog.rs` (new)
- `crates/chio-siem/src/exporters/sumo_logic.rs` (new)
- `crates/chio-siem/src/exporters/webhook.rs` (new)
- `crates/chio-siem/src/alerting.rs` (new)

**Source**: the prior internal guard library
**Refs**: `docs/guards/11-SIEM-OBSERVABILITY-COMPLETION.md` section 2

**Acceptance**: All four exporters implement the `Exporter` trait.
Datadog exporter sends to Datadog Logs API. Webhook exporter delivers
to a configurable URL with retry. Alerting fires PagerDuty/OpsGenie
on high-severity guard denials.

### 12.2 OCSF Receipt Format [SHIPPED dec8378]

**What**: Map Chio receipts to OCSF Authorization event class (3002).

**Files**:
- `crates/chio-siem/src/ocsf.rs` (new)

**Refs**: `docs/guards/11-SIEM-OBSERVABILITY-COMPLETION.md` section 3

**Acceptance**: `OcsfFormatter::format(&receipt)` produces a valid OCSF
3002 event JSON. Ingested by AWS Security Lake without schema errors.

### 12.3 LangSmith / LangFuse Bridge [SHIPPED 5e067c1]

**What**: Push receipts as enriched spans into agent observability platforms.

**Files**:
- `sdks/python/chio-observability/` (new package)

**Refs**: `docs/guards/11-SIEM-OBSERVABILITY-COMPLETION.md` section 5

**Acceptance**: Receipts appear as spans in LangSmith/LangFuse with
tool name, verdict, guard evidence, and cost metadata.

---

## Phase 13: Async Guard Runtime and Threat Intelligence

> **Goal**: External-calling guards with circuit breakers, caching, retry.
> Threat intel and cloud guardrail adapters.
> **Depends on**: Phase 3 (content safety guards as baseline).
> **Refs**: `docs/guards/12-SELECTIVE-ABSORPTION-PLAN.md`,
> `docs/protocols/ARCHITECTURAL-EXTENSIONS.md` section 3

### 13.1 AsyncGuardAdapter Infrastructure [SHIPPED 6104a8c]

**What**: `ExternalGuard` trait, `AsyncGuardAdapter` with circuit breaker,
token bucket, TtlCache, retry with jitter.

**Files**:
- `crates/chio-guards/src/external/mod.rs` (new)
- `crates/chio-guards/src/external/circuit_breaker.rs` (new)
- `crates/chio-guards/src/external/cache.rs` (new)
- `crates/chio-guards/src/external/retry.rs` (new)

**Refs**: `docs/guards/12-SELECTIVE-ABSORPTION-PLAN.md` section 2

**Acceptance**: An `ExternalGuard` impl wrapped in `AsyncGuardAdapter`
with a circuit breaker that opens after 5 failures. When open, the adapter
returns `circuit_open_verdict` (configurable Allow or Deny) without calling
the external service. Cache hit returns cached verdict without API call.

### 13.2 Cloud Guardrail Adapters [SHIPPED bf1bc74]

**What**: `BedrockGuardrailGuard`, `AzureContentSafetyGuard`,
`VertexSafetyGuard` as `ExternalGuard` implementations.

**Files**:
- `crates/chio-guards/src/external/bedrock.rs` (new)
- `crates/chio-guards/src/external/azure_content_safety.rs` (new)
- `crates/chio-guards/src/external/vertex_safety.rs` (new)

**Refs**: `docs/protocols/ARCHITECTURAL-EXTENSIONS.md` section 3

**Acceptance**: Bedrock adapter calls `ApplyGuardrail` API and maps
`GUARDRAIL_INTERVENED` to Deny. Azure adapter calls `text:analyze` and
denies when any category exceeds severity threshold. Cloud provider
verdict captured as `GuardEvidence` in receipt.

### 13.3 Threat Intelligence Guards [SHIPPED bf1bc74]

**What**: VirusTotal, Safe Browsing, Snyk as `ExternalGuard` implementations.

**Files**:
- `crates/chio-guards/src/external/threat_intel/virustotal.rs` (new)
- `crates/chio-guards/src/external/threat_intel/safe_browsing.rs` (new)
- `crates/chio-guards/src/external/threat_intel/snyk.rs` (new)

**Source**: the prior internal guard library
**Refs**: `docs/guards/12-SELECTIVE-ABSORPTION-PLAN.md` section 3

**Acceptance**: Each threat intel guard implements `ExternalGuard`, is
wrapped in `AsyncGuardAdapter` with circuit breaker and cache. VT guard
denies a tool call targeting a known-malicious file hash. Safe Browsing
guard denies navigation to a flagged URL.

---

## Phase 14: Portable Kernel (WASM)

> **Goal**: Chio kernel runs in browsers, edge workers, mobile, and embedded.
> **Depends on**: Phases 1-3 (security fixes, content safety -- the core
> kernel must be stable before extracting a portable subset).
> **Refs**: `docs/protocols/PORTABLE-KERNEL-ARCHITECTURE.md`

### 14.1 chio-kernel-core Extraction [SHIPPED ce43897]

> Portable `#![no_std] + alloc` crate extracted with pure evaluate,
> sign, and verify entry points (`38b230e`). WASM32 cross-compile
> unblocked by the chio-core-types `std`/`no_std + alloc` feature
> split landed as part of `ce43897` (bundled via staging race):
> `cargo build --target wasm32-unknown-unknown -p chio-kernel-core`
> now succeeds on both default and `--no-default-features` paths.


**What**: Extract a `no_std + alloc` kernel core with capability validation,
scope checking, sync guard pipeline, receipt signing. No tokio, rusqlite, ureq.

**Files**:
- `crates/chio-kernel-core/Cargo.toml` (new)
- `crates/chio-kernel-core/src/lib.rs` (new: evaluate, sign_receipt, verify_capability)
- `crates/chio-kernel/Cargo.toml` (depend on chio-kernel-core)
- `crates/chio-kernel/src/kernel/mod.rs` (delegate to core for evaluation)

**Refs**: `docs/protocols/PORTABLE-KERNEL-ARCHITECTURE.md` sections 1-2

**Acceptance**: `cargo build --target wasm32-unknown-unknown -p chio-kernel-core` succeeds.
Binary size < 1MB stripped.

### 14.2 Browser Bindings [SHIPPED 9872b71]

**What**: `wasm-bindgen` bindings for browser-based Chio evaluation.

**Files**:
- `crates/chio-kernel-browser/Cargo.toml` (new)
- `crates/chio-kernel-browser/src/lib.rs` (new)

**Refs**: `docs/protocols/PORTABLE-KERNEL-ARCHITECTURE.md` section 4

**Acceptance**: A browser page loads the WASM module via `wasm-bindgen`.
`evaluate()` returns a verdict in <5ms. Receipt signing works using
Web Crypto for entropy.

### 14.3 Mobile FFI (iOS/Android) [SHIPPED 00b6eb1]

**What**: UniFFI bindings for embedding Chio in mobile apps.

**Files**:
- `crates/chio-kernel-mobile/Cargo.toml` (new)
- `crates/chio-kernel-mobile/src/lib.rs` (new)

**Refs**: `docs/protocols/PORTABLE-KERNEL-ARCHITECTURE.md` section 4

**Acceptance**: A Swift iOS app links the Chio static library via UniFFI.
`evaluate()` and `sign_receipt()` work offline. Receipts sync to a backend
when connectivity returns.

---

## Phase 15: Compliance

> **Goal**: Unblock enterprise procurement with compliance mappings and
> FIPS crypto support.
> **Depends on**: Nothing (documentation + crypto work).
> **Refs**: `docs/protocols/COMPLIANCE-ROADMAP.md`

### 15.1 FIPS Crypto Path [SHIPPED 9c5ca85]

**What**: Add FIPS-capable signing for receipts, capability tokens, and
DPoP proofs. Currently all signing uses Ed25519 via `ed25519-dalek` in
`chio-core-types/src/crypto.rs`. Verifier-side JWT/JWK P-256 handling
exists in `chio-cli` (`jsonwebtoken` crate), but there is no shared core
signing abstraction and no FIPS path for Chio artifact signing.

This requires a cross-crate migration:
1. Define `SigningBackend` trait in `chio-core-types/src/crypto.rs`
2. Implement Ed25519 backend (default, current behavior)
3. Implement P-256/P-384 backend behind `fips` feature flag using `aws-lc-rs`
4. Update `CapabilityToken::sign()`, `ChioReceipt` signing, `DpopProof`
   signing, and `GovernedApprovalToken::sign()` to use the trait
5. Update all verification paths to accept both algorithm families
6. Extend receipt/capability serialization to include algorithm identifier

**Files**:
- `crates/chio-core-types/src/crypto.rs` (add `SigningBackend` trait, algorithm enum)
- `crates/chio-core-types/src/capability.rs` (update `CapabilityToken::sign/verify`)
- `crates/chio-core-types/src/receipt.rs` (update receipt signing)
- `crates/chio-kernel/src/dpop.rs` (update DPoP signing/verification)
- `crates/chio-kernel/src/kernel/mod.rs` (update approval token verification)
- `Cargo.toml` (add aws-lc-rs optional dep behind `fips` feature)

**Refs**: `docs/protocols/COMPLIANCE-ROADMAP.md` section 2

**Acceptance**: `cargo build --features fips` compiles. Receipts signed
with P-256 verify correctly. Capability tokens signed with P-256 are
accepted by the kernel. Existing Ed25519 signatures continue to work
(backward compatible). Algorithm identifier present in serialized artifacts.

### 15.2 NIST AI RMF Mapping [SHIPPED 98252dd]

**What**: Map Chio controls to NIST AI RMF Govern/Map/Measure/Manage functions.

**Files**:
- `docs/compliance/nist-ai-rmf.md` (new)

**Refs**: `docs/protocols/COMPLIANCE-ROADMAP.md` section 4

**Acceptance**: Document maps each NIST AI RMF subcategory to specific
Chio controls (capability tokens, guards, receipts, budgets). Reviewed
by compliance-focused contributor.

### 15.3 PCI DSS v4.0 Mapping [SHIPPED 98252dd]

**What**: Map Chio controls to PCI DSS requirements.

**Files**:
- `docs/compliance/pci-dss-v4.md` (new)

**Refs**: `docs/protocols/COMPLIANCE-ROADMAP.md` section 3

**Acceptance**: All 12 PCI DSS requirement groups mapped. Each requirement
shows Chio controls that satisfy it, gaps requiring additional work, and
customer responsibilities.

### 15.4 ISO 42001 Mapping [SHIPPED 98252dd]

**What**: Map Chio controls to ISO 42001 AI management system clauses.

**Files**:
- `docs/compliance/iso-42001.md` (new)

**Refs**: `docs/protocols/COMPLIANCE-ROADMAP.md` section 5

**Acceptance**: Clause-level mapping covering organizational controls
(Chio provides technical controls, customer provides organizational).
Annex A control mapping included.

### 15.5 OWASP LLM Top 10 Coverage Matrix [SHIPPED 98252dd]

**What**: Document which of the 10 risks Chio addresses, which are gaps,
which are out of scope.

**Files**:
- `docs/compliance/owasp-llm-top-10.md` (new)

**Refs**: `docs/protocols/COMPLIANCE-ROADMAP.md` section 8

**Acceptance**: A markdown document mapping each of the 10 OWASP LLM risks
to Chio controls. Coverage level (strong/partial/out-of-scope) for each.
Reviewed by at least one security-focused contributor.

---

## Phase 16: Economic Layer Developer Guide and Budget Hierarchy

> **Goal**: The 7 economic crates are substantive and now have an overview
> doc (`docs/protocols/ECONOMIC-LAYER-OVERVIEW.md`). This phase adds a
> developer-facing how-to guide and closes the hierarchical budget gap.
> The crates are NOT undocumented -- the overview exists. What is missing
> is a practical guide and the budget tree feature.
> **Depends on**: Nothing.
> **Refs**: `docs/protocols/ECONOMIC-LAYER-OVERVIEW.md`

### 16.1 Economic Layer Developer Guide [SHIPPED f7c738f]

**What**: How-to guide for using metering, budgets, credit, and settlement.

**Files**:
- `docs/guides/ECONOMIC-LAYER.md` (new)

**Refs**: `docs/protocols/ECONOMIC-LAYER-OVERVIEW.md` sections 1-6

**Acceptance**: A developer can follow the guide to set up per-agent
budget limits, track tool call costs, and export billing records.

### 16.2 Hierarchical Budget Governance [SHIPPED 8234a4d]

**What**: Tree-structured budget policies for enterprise fleet management
(department -> team -> agent). **This is product work, not documentation.**

**Files**:
- `crates/chio-metering/src/budget_hierarchy.rs` (new)

**Refs**: `docs/protocols/ECONOMIC-LAYER-OVERVIEW.md` section 7

**Acceptance**: A budget tree where department has $10K/month, team has
$2K/month, agent has $200/month. Agent hitting its limit does not affect
other agents in the team. Team hitting its limit stops all agents in that
team.

---

## Phase 17: Remaining Orchestration and Pipeline Integrations

> **Goal**: Cover the long tail of orchestration and pipeline integrations.
> **Depends on**: Phase 0 (publishing).
> **Refs**: `docs/protocols/PREFECT-INTEGRATION.md`,
> `docs/protocols/DAGSTER-INTEGRATION.md`,
> `docs/protocols/AIRFLOW-INTEGRATION.md`,
> `docs/protocols/RAY-INTEGRATION.md`,
> `docs/protocols/K8S-JOBS-INTEGRATION.md`

### 17.1 chio-prefect [SHIPPED b72dc0d]

**What**: `@chio_task` / `@chio_flow` decorators, Prefect Events integration.

**Files**: `sdks/python/chio-prefect/` (new)
**Refs**: `docs/protocols/PREFECT-INTEGRATION.md`

**Acceptance**: A Prefect flow where each task is capability-checked.
Denied tasks raise `PermissionError`. Receipts emitted as Prefect events.

### 17.2 chio-dagster [SHIPPED ac31e21]

**What**: `@chio_asset` decorator, partition-scoped capabilities, IO Manager.

**Files**: `sdks/python/chio-dagster/` (new)
**Refs**: `docs/protocols/DAGSTER-INTEGRATION.md`

**Acceptance**: A Dagster asset materialization governed by Chio. Partition
key included in capability evaluation context.

### 17.3 chio-airflow [SHIPPED e25d73f]

**What**: `ChioOperator` wrapper, TaskFlow `@chio_task` decorator, DAG listener.

**Files**: `sdks/python/chio-airflow/` (new)
**Refs**: `docs/protocols/AIRFLOW-INTEGRATION.md`

**Acceptance**: An Airflow DAG with `ChioOperator`-wrapped tasks. Denied
tasks fail with `PermissionError`. Receipt IDs pushed to XCom.

### 17.4 chio-ray [SHIPPED 1e290d2]

**What**: `@chio_remote` decorator, `ChioActor` base class with standing grants.

**Files**: `sdks/python/chio-ray/` (new)
**Refs**: `docs/protocols/RAY-INTEGRATION.md`

**Acceptance**: A Ray actor with `@ChioActor.requires("tools:search")` on
methods. Calls outside granted scope are denied.

### 17.5 K8s Job Controller Extension [SHIPPED 6a1cac9]

**What**: Job lifecycle capability grants, receipt aggregation on completion.

**Files**: `sdks/k8s/controller/job_reconciler.go` (new)
**Refs**: `docs/protocols/K8S-JOBS-INTEGRATION.md`

**Acceptance**: A K8s Job with `chio.world/governed: "true"` label gets
a capability grant at creation and release on completion.

### 17.6 Cloud Run / ECS Sidecar Reference Patterns [SHIPPED 8a0b933]

**What**: Reference deployment configs for running Chio sidecar alongside
application containers on Cloud Run, ECS Fargate, and Azure Container Apps.

**Files**:
- `deploy/cloud-run/service.yaml` (new)
- `deploy/ecs/task-definition.json` (new)
- `deploy/azure/container-app.bicep` (new)
- `deploy/sidecar/Dockerfile` (new: Chio sidecar container image)

**Refs**: `docs/protocols/CLOUD-SIDECAR-INTEGRATION.md`

**Acceptance**:
- Cloud Run: `gcloud run services replace deploy/cloud-run/service.yaml`
  deploys a multi-container service with Chio sidecar. Health check on
  `:9090/health` passes. Chio evaluates tool calls from the app container.
- ECS: Task definition at `deploy/ecs/task-definition.json` registers
  successfully. App container depends on sidecar health check.
- Azure: `deploy/azure/container-app.bicep` deploys with Chio sidecar.
  Sidecar starts before app container.

---

## Phase 18: Agent Memory Governance

> **Goal**: Close the cross-session poisoning attack vector.
> **Depends on**: Phase 2 (MemoryWrite ToolAction).
> **Refs**: `docs/protocols/STRUCTURAL-SECURITY-FIXES.md` section 3

### 18.1 Memory Write/Read Guards [SHIPPED 8b650e1]

**What**: Guards for `ToolAction::MemoryWrite` and `ToolAction::MemoryRead`.
Enforce `MemoryStoreAllowlist`, `MaxRetentionTtl`, `MaxMemoryEntries`.

**Files**:
- `crates/chio-guards/src/memory_governance.rs` (new)

**Refs**: `docs/protocols/STRUCTURAL-SECURITY-FIXES.md` section 3

**Acceptance**: An agent writing to a vector DB collection not in its
`MemoryStoreAllowlist` is denied. Writes exceeding `MaxMemoryEntries`
are denied.

### 18.2 Memory Entry Provenance [SHIPPED 0e9ffb5]

**What**: Hash chain of memory writes linked to capability IDs. On read,
verify the write was authorized.

**Files**:
- `crates/chio-kernel/src/memory_provenance.rs` (new)

**Refs**: `docs/protocols/STRUCTURAL-SECURITY-FIXES.md` section 3

**Acceptance**: A memory read returns provenance metadata (which capability
authorized the write, when, receipt ID). Reads of entries with no
provenance are flagged as unverified.

---

## Phase 19: Future Moats (Near-Term)

> **Goal**: Productize and expose the near-term competitive moats. This is
> analytics/productization work, NOT raw-reporting greenfield. The kernel
> already ships `BehavioralFeedReport`, `SignedBehavioralFeed`, and
> `ComplianceReport` in `chio-kernel/src/operator_report.rs`, backed by
> SQLite report queries in `chio-store-sqlite/src/receipt_store/reports.rs`.
> This phase wraps those primitives into user-facing scoring APIs, guard
> integration, and regulatory endpoints.
> **Depends on**: Receipts and metering (already shipped).
> **Refs**: `docs/protocols/FUTURE-MOATS-AND-RESEARCH.md`

### 19.1 Receipt Compliance Scoring [SHIPPED c5c5d06]

**What**: Productize the existing `ComplianceReport` in
`chio-kernel/src/operator_report.rs` into a user-facing `compliance_score()`
API. The raw reporting infrastructure exists; this story adds the scoring
model (0-1000 range, weighted factors) and the CLI/HTTP surface.

**Files**:
- `crates/chio-kernel/src/compliance_score.rs` (new: scoring model on top of existing ComplianceReport)
- `crates/chio-kernel/src/operator_report.rs` (extend: add score computation)
- `crates/chio-http-core/src/routes.rs` (add `/compliance/score` endpoint)

**Refs**: `docs/protocols/FUTURE-MOATS-AND-RESEARCH.md` section 1

**Acceptance**: `chio compliance score --agent <id>` returns a 0-1000 score.
An agent with zero denials in 1000 calls scores above 900. An agent with
a revoked capability scores below 500.

### 19.2 Agent Behavioral Profiling [SHIPPED c5c5d06]

**What**: Productize the existing `BehavioralFeedReport` and
`SignedBehavioralFeed` in `chio-kernel/src/operator_report.rs` into a
guard-integrated anomaly detection system. The raw behavioral reporting
and SQLite queries exist in `chio-store-sqlite/src/receipt_store/reports.rs`.
This story adds EMA baselines, z-score anomaly detection, and integration
with the velocity guard pipeline.

**Files**:
- `crates/chio-guards/src/behavioral_profile.rs` (new: guard that reads from existing behavioral feed)
- `crates/chio-kernel/src/operator_report.rs` (extend: add anomaly scoring on top of existing BehavioralFeedReport)

**Refs**: `docs/protocols/FUTURE-MOATS-AND-RESEARCH.md` section 2

**Acceptance**: An agent that normally makes 10 calls/minute triggers an
advisory signal when it suddenly makes 500. The behavioral guard reads
from `chio-store-sqlite` receipt queries.

### 19.3 Regulatory API [SHIPPED c5c5d06]

**What**: Read-only API over receipt store for regulators. Every response
wrapped in `SignedExportEnvelope`.

**Files**:
- `crates/chio-http-core/src/regulatory_api.rs` (new)

**Refs**: `docs/protocols/FUTURE-MOATS-AND-RESEARCH.md` section 3

**Acceptance**: `GET /regulatory/receipts?agent=<id>&after=<timestamp>`
returns a signed envelope of receipts. The signature verifies against the
kernel's public key.

---

## Phase 20: Future Moats (Medium-Term)

> **Goal**: Build the strongest competitive differentiators.
> **Depends on**: Per-item (see below). NOT gated on WASM kernel for all
> items -- only Agent Passport requires WASM. Insurance and marketplace
> build on the existing economic crates. Cross-kernel federation builds
> on receipts and choreography patterns.
> **Refs**: `docs/protocols/FUTURE-MOATS-AND-RESEARCH.md`

### 20.1 Agent Passport: Trust-Tier Synthesis and WASM Portability (depends on Phases 14, 19.1, 19.2) [SHIPPED 1da2900]

**What**: The core passport system already ships: `AgentPassport` in
`crates/chio-credentials/src/passport.rs`, challenge flows, OID4VCI/VP,
and cross-issuer portfolio evaluation in `crates/chio-credentials/src/cross_issuer.rs`.
CLI passport flows exist in `crates/chio-cli/src/passport.rs`.

This phase adds **trust-tier synthesis** (populating the passport with
compliance scores from 19.1 and behavioral profiles from 19.2) and
**WASM portability** (passport verification in `chio-kernel-core` for
browser/mobile agents). It is NOT creating passport support from scratch.

**Files**:
- `crates/chio-credentials/src/passport.rs` (extend: add trust_tier field from compliance score)
- `crates/chio-credentials/src/trust_tier.rs` (new: synthesize tier from compliance + behavioral data)
- `crates/chio-kernel-core/src/passport_verify.rs` (new: WASM-compatible verification)

**Refs**: `docs/protocols/FUTURE-MOATS-AND-RESEARCH.md` section 4

**Acceptance**: `chio passport generate --agent <id>` includes a `trust_tier`
field computed from compliance score and behavioral profile. A WASM-compiled
kernel verifies the passport and reads the tier.

### 20.2 Agent Insurance Protocol (depends on Phases 16, 19.1, 19.2) [SHIPPED 657ca6d]

**What**: Connect chio-underwriting risk assessment -> chio-market liability
placement -> chio-settle claims payout. Premium pricing from receipt history.

**Files**:
- `crates/chio-underwriting/src/premium.rs` (new: premium pricing from receipt score)
- `crates/chio-market/src/insurance_flow.rs` (new: end-to-end flow)

**Refs**: `docs/protocols/FUTURE-MOATS-AND-RESEARCH.md` section 5,
`docs/protocols/ECONOMIC-LAYER-OVERVIEW.md` section 4

**Acceptance**: An agent with a clean receipt history gets a lower premium
quote than one with denials. A claim filed against a policy with receipt
evidence is processed through the settlement flow.

### 20.3 Cross-Kernel Federation: Bilateral Runtime Co-Signing (depends on Phases 1, 20.1) [SHIPPED e08d856]

**What**: The federation crate already ships signed activation, quorum
governance, open-admission, reputation, and qualification artifacts
(`crates/chio-federation/src/lib.rs`). CLI/control-plane federation-policy
and federated-issue flows are shipped.

This phase adds **bilateral runtime co-signing** (two kernels in different
orgs both sign the same receipt when an agent crosses org boundaries) and
**trust establishment** (mTLS key exchange between kernels). It is NOT
creating federation from scratch.

**Files**:
- `crates/chio-federation/src/bilateral.rs` (new: bilateral receipt co-signing protocol)
- `crates/chio-federation/src/trust_establishment.rs` (new: mTLS key exchange)
- `crates/chio-kernel/src/kernel/mod.rs` (extend: co-sign receipt with remote kernel)

**Refs**: `docs/protocols/FUTURE-MOATS-AND-RESEARCH.md` section 6

**Acceptance**: Agent from Org A calls tool in Org B. Both kernels sign
the receipt (dual signatures). Receipt chain is verifiable by either org.
Trust established via mTLS handshake between kernels.

### 20.4 Capability Marketplace (independent -- builds on shipped chio-listing/chio-market) [SHIPPED e6ee085]

**What**: Tool servers advertise, agents discover and bid. Receipts prove
usage for billing.

**Files**:
- `crates/chio-listing/src/discovery.rs` (extend: search and compare)
- `crates/chio-open-market/src/bidding.rs` (new: bid/ask protocol)

**Acceptance**: A tool server listed via `chio-listing` is discoverable
by agents. Agents can compare prices and bid for access. Receipts serve
as proof of usage for settlement.

**Refs**: `docs/protocols/FUTURE-MOATS-AND-RESEARCH.md` section 7,
`docs/protocols/ECONOMIC-LAYER-OVERVIEW.md` section 5

---

## Dependency Graph

```
Phase 0 (DX Foundation) ──────────────────────────────────────┐
Phase 1 (Structural Security) ────────────────────────────────┤
Phase 2 (Core Type Evolution) ────────────────────────────────┤
                                                              │
               ┌──────────────────────────────────────────────┤
               │                                              │
Phase 3 (Content Safety + HITL) ──── depends on 2             │
Phase 4 (chio-code-agent) ────────── depends on 0              │
Phase 5 (Guard Absorption) ────── depends on 2              │
Phase 6 (Framework SDKs) ───────── depends on 0, 2            │
Phase 7 (Data Layer Guards) ─────── depends on 2              │
Phase 8 (Code Execution Guards) ─── depends on 2              │
Phase 9 (Envoy ext_authz) ───────── depends on nothing        │
Phase 10 (Orchestration) ────────── depends on 0; 10.3 also on 3  │
Phase 11 (SaaS + Streaming) ─────── depends on 2, 3           │
Phase 12 (SIEM) ──────────────────── depends on nothing       │
Phase 13 (Async Guards + Threat) ── depends on 3              │
Phase 14 (WASM Kernel) ──────────── depends on 1, 2, 3        │
Phase 15 (Compliance) ──────────── depends on nothing          │
Phase 16 (Economic Docs + Gaps) ─── depends on nothing         │
Phase 17 (Pipeline Integrations) ── depends on 0              │
Phase 18 (Memory Governance) ─────── depends on 2             │
Phase 19 (Near-Term Moats) ────────── depends on receipts (shipped)  │
Phase 20 (Medium-Term Moats) ──────── per-item (see stories)  │
```

## Parallelization Strategy

These phase groups can execute concurrently:

**Group 1** (immediate, no dependencies):
- Phase 0: DX Foundation
- Phase 1: Structural Security
- Phase 2: Core Type Evolution
- Phase 9: Envoy ext_authz
- Phase 12: SIEM Completion
- Phase 15: Compliance Mappings
- Phase 16: Economic Docs + Gaps
- Phase 19: Near-Term Moats (depends only on shipped receipts/metering)

**Group 2** (after Group 1 core types land):
- Phase 3: Content Safety + HITL
- Phase 4: chio-code-agent
- Phase 5: Guard Absorption
- Phase 6: Framework SDKs
- Phase 7: Data Layer Guards
- Phase 8: Code Execution Guards
- Phase 10: Orchestration

**Group 3** (after Group 2):
- Phase 11: SaaS + Streaming
- Phase 13: Async Guards
- Phase 14: WASM Kernel
- Phase 17: Pipeline Integrations
- Phase 18: Memory Governance

**Group 4** (per-item dependencies, NOT gated on Group 3 as a whole):
- 20.4 Capability Marketplace: independent, can start in Group 1
- 20.2 Agent Insurance: needs 16 (Group 1) + 19.1/19.2 (Group 1) -- can start in Group 2
- 20.1 Agent Passport: needs 14 (Group 3) + 19.1/19.2 (Group 1) -- starts when WASM lands
- 20.3 Cross-Kernel Federation: needs 1 (Group 1) + 20.1 -- starts after passport

---

## Document Index

All design docs produced during this planning cycle, organized by topic:

### Integration Design Docs (`docs/protocols/`)

| Doc | Phase | Topic |
|-----|-------|-------|
| `TEMPORAL-INTEGRATION.md` | 10 | Temporal activity interceptor |
| `AWS-LAMBDA-INTEGRATION.md` | 10 | Lambda Extension model |
| `LANGGRAPH-INTEGRATION.md` | 10 | LangGraph node scoping |
| `PREFECT-INTEGRATION.md` | 17 | Prefect task decorator |
| `DAGSTER-INTEGRATION.md` | 17 | Dagster asset governance |
| `AIRFLOW-INTEGRATION.md` | 17 | Airflow operator wrapper |
| `RAY-INTEGRATION.md` | 17 | Ray actor capabilities |
| `K8S-JOBS-INTEGRATION.md` | 17 | K8s Job lifecycle grants |
| `CLOUD-SIDECAR-INTEGRATION.md` | 17 | Cloud Run/ECS patterns |
| `EVENT-STREAMING-INTEGRATION.md` | 11 | Kafka choreography governance |
| `IAC-INTEGRATION.md` | 11 | Terraform/Pulumi plan/apply |
| `DATA-LAYER-INTEGRATION.md` | 7 | SQL/vector/warehouse |
| `AGENT-FRAMEWORK-INTEGRATION.md` | 6 | CrewAI/AutoGen/LlamaIndex/Vercel |
| `SAAS-COMMUNICATION-INTEGRATION.md` | 11 | Slack/Stripe/PagerDuty |
| `ENVOY-EXT-AUTHZ-INTEGRATION.md` | 9 | Envoy/Istio/Consul |

### Architecture Design Docs (`docs/protocols/`)

| Doc | Phase | Topic |
|-----|-------|-------|
| `PORTABLE-KERNEL-ARCHITECTURE.md` | 14 | WASM/mobile/embedded kernel |
| `ARCHITECTURAL-EXTENSIONS.md` | 2 | Model routing, plan eval, cloud guardrails |
| `STRUCTURAL-SECURITY-FIXES.md` | 1 | TOCTOU, bypass, memory, kill switch |
| `HUMAN-IN-THE-LOOP-PROTOCOL.md` | 3 | Full HITL protocol design |
| `ADR-TYPE-EVOLUTION.md` | 2 | Canonical ToolAction/Constraint shapes |
| `UNIVERSAL-KERNEL-COVERAGE-MAP.md` | All | Master coverage matrix |

### Strategy and Review Docs (`docs/protocols/`)

| Doc | Phase | Topic |
|-----|-------|-------|
| `REVIEW-FINDINGS-AND-NEXT-STEPS.md` | All | Six-review synthesis |
| `DX-AND-ADOPTION-ROADMAP.md` | 0 | Publishing, testing, quickstart |
| `COMPLIANCE-ROADMAP.md` | 15 | FIPS, PCI, NIST, ISO, OWASP |
| `ECONOMIC-LAYER-OVERVIEW.md` | 16 | 7-crate economic layer |
| `FUTURE-MOATS-AND-RESEARCH.md` | 19-20 | Competitive moats |

### Guard Absorption Docs (`docs/guards/`)

| Doc | Phase | Topic |
|-----|-------|-------|
| `06-CONTENT-SAFETY-ABSORPTION.md` | 3 | Jailbreak, prompt injection, SpiderSense |
| `07-OUTPUT-SANITIZER-ABSORPTION.md` | 3 | PII redaction, watermarking |
| `08-DESKTOP-CUA-GUARD-ABSORPTION.md` | 5 | Computer use, input injection, RDP |
| `09-POLICY-ENGINE-ABSORPTION.md` | 5 | Policy compiler, rulesets |
| `10-DATA-LAYER-GUARDS.md` | 7 | SQL, vector, warehouse, graph, cache |
| `11-SIEM-OBSERVABILITY-COMPLETION.md` | 12 | Exporters, OCSF, LangSmith |
| `12-SELECTIVE-ABSORPTION-PLAN.md` | 13 | Async runtime, threat intel, WASM merge |
| `13-CODE-EXECUTION-GUARDS.md` | 8 | Sandbox, browser automation |
