# Colorado SB 24-205 Compliance Mapping

## Metadata

| Field | Value |
|-------|-------|
| Regulation | Colorado Senate Bill 24-205, "Consumer Protections for Artificial Intelligence" |
| Effective Date | February 1, 2026 |
| Chio Profile | Current v1-only pre-release profile |
| Document Date | 2026-03-22 |
| Filing Deadline | June 30, 2026 |
| Maintained by | Chio Protocol Team |

---

## Executive Summary

Chio provides a cryptographically-attested tool invocation infrastructure designed to satisfy the record-keeping, transparency, and accountability requirements of Colorado SB 24-205. Every tool invocation processed by the Chio kernel produces a signed `ChioReceipt` -- a tamper-evident record containing the capability identifier, tool server, tool name, decision (allow or deny), policy hash, and a content hash of the invocation parameters. These receipts are stored in an append-only SQLite log and are committed into Merkle checkpoint batches signed by the kernel's keypair, providing cryptographic tamper evidence without relying on a central authority.

Colorado SB 24-205 imposes obligations on developers and deployers of high-risk AI systems to maintain verifiable records of AI system outputs and to disclose the capabilities and material limitations of deployed AI systems. Chio satisfies the record-keeping obligations through its configurable `RetentionConfig` on `KernelConfig`: operators may set `retention_days` (default 90) and `max_size_bytes` (default 10 GB) to control how long live receipts are retained before they are archived to a separate SQLite file. Archived receipts remain verifiable against stored Merkle checkpoint roots in the archive database -- satisfying the requirement that records remain verifiable after the retention period.

Transparency obligations are satisfied through the `ToolManifest` format: each tool server publishes a signed manifest with human-readable descriptions and parameter schemas for every tool it exposes. The DPoP (Demonstration of Proof-of-Possession) module adds per-invocation cryptographic binding between the invoking agent's keypair and each specific tool call, providing proof of possession for every agent action. Budget accountability for monetary grants is captured in `FinancialReceiptMetadata` attached to every allow or deny receipt involving a monetary `ToolGrant`.

---

## Clause Mapping

| Clause | Requirement Summary | Chio Mechanism | Test File | Test Function |
|--------|---------------------|----------------|-----------|---------------|
| SB 24-205 §6-1-1703(1)(a) | Developer must disclose material limitations and capabilities of AI system | `ToolManifest` with signed `ToolDefinition` per tool including description and parameter schema | `crates/platform/chio-manifest/src/lib.rs` | `sign_and_verify_manifest` |
| SB 24-205 §6-1-1703(1)(b) | AI system must generate records of high-risk AI system outputs | Signed `ChioReceipt` per invocation with decision (allow/deny), policy_hash, capability_id, tool_server, tool_name | `crates/kernel/chio-kernel/src/lib.rs` | `all_calls_produce_verified_receipts` |
| SB 24-205 §6-1-1703(2)(a) | Records of AI system outputs must be retained for a configurable period | `RetentionConfig.retention_days` (default 90) controls time-based rotation; `rotate_if_needed` archives aged receipts to separate SQLite file | `crates/kernel/chio-kernel/tests/retention.rs` | `retention_rotates_at_time_boundary` |
| SB 24-205 §6-1-1703(2)(a) | Records must also rotate based on storage size thresholds | `RetentionConfig.max_size_bytes` (default 10 GB) triggers `rotate_if_needed` when DB exceeds threshold | `crates/kernel/chio-kernel/tests/retention.rs` | `retention_rotates_at_size_boundary` |
| SB 24-205 §6-1-1703(2)(b) | Records must remain verifiable after retention period expires | Archived receipts verify against Merkle checkpoint roots stored in archive DB; `verify_checkpoint_signature` confirms the checkpoint is authentic | `crates/kernel/chio-kernel/tests/retention.rs` | `archived_receipt_verifies_against_checkpoint` |
| SB 24-205 §6-1-1703(2)(b) | Archive must preserve all checkpoint rows alongside receipt batches | Archival logic copies checkpoint rows whose `batch_end_seq` is fully covered by archived receipts (partial-batch exclusion prevents orphaned proofs) | `crates/kernel/chio-kernel/tests/retention.rs` | `archive_preserves_checkpoint_rows` |
| SB 24-205 §6-1-1703(3) | Decision audit trail -- AI system decisions must be attributable and reviewable | `ChioReceipt.decision` field (`Allow`/`Deny`) combined with `policy_hash` and `capability_id` provides a signed, attributable audit record for every decision | `crates/kernel/chio-kernel/src/lib.rs` | `all_calls_produce_verified_receipts` |
| SB 24-205 §6-1-1703(3) | Deny decisions must record attempted action for audit | Deny `ChioReceipt` is signed and stored with the same fields as allow; monetary denial receipts carry `FinancialReceiptMetadata.attempted_cost` | `crates/kernel/chio-kernel/src/lib.rs` | `monetary_denial_receipt_contains_financial_metadata` |
| SB 24-205 §6-1-1703(4) | Tamper-evident record storage -- records must not be silently altered | Merkle-committed receipt batches with signed `KernelCheckpoint` per batch; `build_checkpoint_signature_verifies` confirms Ed25519 signature over canonical JSON of checkpoint body | `crates/kernel/chio-kernel/src/checkpoint.rs` | `build_checkpoint_signature_verifies` |
| SB 24-205 §6-1-1703(4) | Individual receipts must be provably included in the checkpoint | Merkle inclusion proofs via `build_inclusion_proof` allow verifying any single receipt against the stored checkpoint root without re-reading all receipts | `crates/kernel/chio-kernel/src/checkpoint.rs` | `inclusion_proof_verifies_for_leaf_n` |
| SB 24-205 §6-1-1703(5) | Proof of possession -- agent actions must be bound to the acting entity | DPoP (Demonstration of Proof-of-Possession) Ed25519 proof binds `capability_id + tool_server + tool_name + action_hash + nonce` to the agent's registered keypair | `crates/kernel/chio-kernel/tests/dpop.rs` | `dpop_valid_proof_accepted` |
| SB 24-205 §6-1-1703(5) | Cross-invocation replay of agent actions must be prevented | DPoP proof `action_hash` (SHA-256 of canonical invocation arguments) prevents a proof from one invocation being replayed for a different invocation | `crates/kernel/chio-kernel/tests/dpop.rs` | `dpop_wrong_action_hash_rejected` |
| SB 24-205 §6-1-1703(5) | Agent identity binding -- proof must originate from the agent named in the capability | `verify_dpop_proof` checks `proof.body.agent_key == capability.subject` before accepting the proof | `crates/kernel/chio-kernel/tests/dpop.rs` | `dpop_wrong_agent_key_rejected` |
| SB 24-205 §6-1-1703(6) | Budget accountability for AI systems with monetary authority | `FinancialReceiptMetadata` (`cost_charged`, `attempted_cost`, `settlement_status`) is attached to every receipt involving a monetary `ToolGrant`; `max_total_cost` and `max_cost_per_invocation` are enforced atomically via SQLite IMMEDIATE transactions | `crates/kernel/chio-kernel/src/lib.rs` | `monetary_full_pipeline_three_invocations_third_denied` |
| SB 24-205 §6-1-1703(6) | Monetary allow receipts must record actual cost charged | Allow receipts carry `FinancialReceiptMetadata.cost_charged` reflecting the actual cost reported by the tool server (not just the worst-case cap) | `crates/kernel/chio-kernel/src/lib.rs` | `monetary_allow_receipt_contains_financial_metadata` |
| SB 24-205 §6-1-1703(7) | Checkpointing interval -- periodic tamper-evident commits | `checkpoint_batch_size` (default 100) controls how frequently Merkle checkpoints are triggered; checkpoint is automatically triggered after every N receipts | `crates/kernel/chio-kernel/src/lib.rs` | `checkpoint_triggers_at_100_receipts` |

---

## Architecture Overview

```
Agent  -->  Chio Kernel (TCB)  -->  Tool Server
              |
              +-- Validates capability (issuer, expiry, scope, revocation)
              +-- Checks DPoP proof (if dpop_required on ToolGrant)
              +-- Runs guard pipeline (velocity, policy, budget)
              +-- Dispatches tool call
              +-- Signs ChioReceipt (allow or deny)
              +-- Appends to SqliteReceiptStore
              +-- Triggers Merkle checkpoint (every checkpoint_batch_size receipts)
              +-- rotate_if_needed() archives receipts per RetentionConfig
```

All operations above are verified by automated tests. The kernel fails closed -- any error during evaluation results in a signed deny receipt, not a silent pass.

---

## Verification

To confirm that all claims in this document are backed by passing test artifacts, run:

```bash
cargo test --workspace
```

All 113 tests in the workspace must pass. Key tests referenced in this document:

```bash
# Retention tests (COMP-03, COMP-04)
cargo test -p chio-kernel -- retention

# DPoP proof-of-possession tests (SEC-03, SEC-04)
cargo test -p chio-kernel -- dpop

# Checkpoint tamper-evidence tests
cargo test -p chio-kernel -- checkpoint

# Monetary budget enforcement tests
cargo test -p chio-kernel -- monetary

# Manifest transparency tests
cargo test -p chio-manifest -- sign_and_verify_manifest
```

Expected output: all referenced test functions exist and report `ok`.

---

## Regulatory Notes

The clause numbers above (§6-1-1703) reference Colorado SB 24-205 as enacted, effective February 1, 2026. The Colorado AI Act imposes requirements on developers and deployers of high-risk AI systems. Chio operates as infrastructure for the Runtime Kernel layer of an AI agent system and directly satisfies the record-keeping, audit, tamper-evidence, and transparency obligations described above.

Legal review of this mapping against the final enrolled bill text is recommended before filing. Technical claims in the "Clause Mapping" table are verifiable by running `cargo test --workspace`.
