# Session Compliance Certificate

**Status:** Shipped | **Version:** 1.0.0 | **Schema:** `chio.session_compliance_certificate.v1`
Normative spec: `spec/COMPLIANCE-CERTIFICATE.md`

> **Status**: The certificate generation and verification APIs described here
> are implemented in `crates/protocol/chio-acp-proxy/src/compliance.rs`. The normative
> specification for certificate structure, generation algorithm, abort errors,
> and verification modes is `spec/COMPLIANCE-CERTIFICATE.md`. This document
> is retained as a non-normative companion for design rationale, regulatory
> mapping, and integration details.

## 1. Problem Statement

Enterprises deploying Chio-governed agent systems must demonstrate to auditors,
regulators, and internal compliance teams that every agent session operated
within its authorized boundaries. Chio already produces Ed25519-signed receipts
for every tool call and commits them to Merkle-rooted checkpoint batches. However,
reconstructing compliance from individual receipts requires tooling that
understands the full protocol: verifying signatures, replaying scope checks,
summing budget consumption, and confirming chain continuity.

A **Session Compliance Certificate** is a single, self-contained, cryptographically
signed artifact that proves an entire agent session complied with policy. It
composes receipt-level evidence into one auditor-ready document that a third party
can verify without replaying every guard evaluation.

## 2. What a Compliance Certificate Proves

A valid certificate makes six assertions about the session it covers:

1. **Capability validity.** Every tool call presented a capability token that was non-expired, non-revoked, and signed by a recognized Capability Authority at invocation time.
2. **Scope containment.** No capability was exercised outside the tool grants, resource grants, and prompt grants declared in its `ChioScope`.
3. **Budget compliance.** No `ToolGrant` with `max_invocations`, `max_cost_per_invocation`, or `max_total_cost` constraints had those limits exceeded.
4. **Guard passage.** Every `GuardEvidence` entry attached to every receipt has `verdict: true`. No denied guard evaluation was bypassed.
5. **No privilege escalation.** The effective scope never widened beyond what the root capability authority granted. Delegation chains maintained monotonic attenuation.
6. **Receipt chain completeness.** The receipt chain is gap-free, with each receipt hash-linked to its predecessor. No receipts were omitted, replayed, or reordered.

The certificate may also carry supplemental execution-context evidence for
auditors and insurers: model/provider identifiers, policy or prompt bundle
hashes, human-approval references, runtime-attestation summaries, and
redaction metadata describing what evidence was intentionally omitted from the
portable artifact.

## 3. Certificate Structure

### 3.1 Rust Type Definition

```rust
pub const SESSION_COMPLIANCE_CERTIFICATE_SCHEMA: &str =
    "chio.session_compliance_certificate.v1";

/// A signed proof that an entire agent session complied with policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionComplianceCertificate {
    pub body: SessionComplianceCertificateBody,
    /// Ed25519 signature over canonical JSON of `body`.
    pub signature: Signature,
}

/// The body of a compliance certificate (signing input).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionComplianceCertificateBody {
    pub schema: String,
    /// Unique certificate ID (UUIDv7).
    pub certificate_id: String,
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub time_range: CertificateTimeRange,
    /// Number of tool-call receipts in the session.
    pub tool_receipt_count: u64,
    /// Number of child-request receipts in the session.
    pub child_receipt_count: u64,
    /// Total number of receipts committed by this certificate.
    pub total_receipt_count: u64,
    /// Merkle root over the canonical JSON of every receipt in order.
    pub merkle_root: Hash,
    /// SHA-256 hash of the first receipt body (chain anchor).
    pub chain_head: String,
    /// SHA-256 hash of the last receipt body.
    pub chain_tail: String,
    pub scope_summary: ScopeSummary,
    pub budget_summary: Vec<BudgetSummaryEntry>,
    pub guard_summary: GuardSummary,
    /// Capability IDs referenced across all receipts.
    pub capability_ids: Vec<String>,
    pub execution_context: ExecutionContextSummary,
    #[serde(default)]
    pub approval_refs: Vec<ApprovalReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_profile: Option<RedactionProfileSummary>,
    /// Public key of the kernel that signs this certificate.
    pub issuer_key: PublicKey,
    /// Unix timestamp (seconds) when the certificate was issued.
    pub issued_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateTimeRange {
    pub start: u64, // Unix timestamp of the earliest receipt
    pub end: u64,   // Unix timestamp of the latest receipt
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeSummary {
    /// Distinct (server_id, tool_name) pairs invoked.
    pub tools_invoked: Vec<ToolReference>,
    pub resources_accessed: Vec<String>,
    pub prompts_accessed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolReference {
    pub server_id: String,
    pub tool_name: String,
}

/// Budget consumption for one grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetSummaryEntry {
    pub capability_id: String,
    pub grant_index: u32,
    pub tool: ToolReference,
    pub invocations_used: u32,
    pub invocations_limit: Option<u32>,       // None = unlimited
    pub cost_consumed: Option<u64>,            // Minor units (e.g. cents)
    pub cost_limit: Option<u64>,               // Minor units
    /// ISO 4217 currency code. None when the grant uses invocation-count
    /// budgets rather than monetary budgets.
    pub currency: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardSummary {
    pub total_evaluations: u64,
    pub passed: u64,
    pub failed: u64,  // Must be 0 for a compliant certificate
    pub guard_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContextSummary {
    #[serde(default)]
    pub providers: Vec<String>,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub policy_bundle_hashes: Vec<String>,
    #[serde(default)]
    pub prompt_bundle_hashes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<RuntimeAttestationSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeAttestationSummary {
    pub format: String,
    pub measurement_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalReference {
    pub system: String,
    pub reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionProfileSummary {
    pub profile_id: String,
    #[serde(default)]
    pub redacted_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}
```

### 3.2 Serialization

All certificate fields use canonical JSON (RFC 8785 / JCS) for deterministic
hashing and signature verification, consistent with all other Chio signed
artifacts. The signature covers `canonical_json_bytes(&body)`.

## 4. Generation Process

The kernel generates a certificate by walking the complete receipt log for a
session. The algorithm is fail-closed: any anomaly aborts generation and returns
an error rather than issuing a misleading certificate.

### 4.1 Algorithm

```
generate_compliance_certificate(session_id) -> Result<SessionComplianceCertificate>

1.  Load all StoredToolReceipt and StoredChildReceipt records for session_id,
    ordered by sequence number. If empty, return Err(EmptySession).

2.  Initialize accumulators:
      receipt_hashes: Vec<Vec<u8>>, prev_hash: Option<String> = None,
      scope_summary, budget_map, guard_summary, execution_context,
      approval_refs, redaction_profile

3.  For each receipt in sequence order:
      a. Verify Ed25519 signature against embedded kernel_key.
         Fail: Err(InvalidReceiptSignature { receipt_id }).
      b. Verify chain continuity:
         Compute hash = SHA-256(canonical_json_bytes(receipt.body())).
         If prev_hash is Some, assert linkage. Update prev_hash.
      c. Verify capability scope alignment:
         Look up CapabilityToken by receipt.capability_id.
         Confirm (tool_server, tool_name) falls within scope.grants.
         Fail: Err(ScopeViolation { receipt_id }).
      d. Accumulate budget usage from FinancialReceiptMetadata.
         If max_invocations or max_total_cost exceeded: Err(BudgetExceeded).
      e. Verify guard evidence: assert all GuardEvidence.verdict == true.
         False verdict on Allow decision: Err(GuardBypass { receipt_id }).
      f. Append canonical_json_bytes(receipt.body()) to receipt_hashes.
      g. Update scope_summary with observed tools, resources, prompts.
      h. Accumulate execution-context summaries (model/provider IDs, policy or
         prompt bundle hashes, runtime-attestation metadata, approval refs).

4.  Build MerkleTree::from_leaves(&receipt_hashes). Record merkle_root.
5.  Assemble SessionComplianceCertificateBody with all accumulated data.
6.  Sign: keypair.sign_canonical(&body) -> (signature, _bytes).
7.  Return SessionComplianceCertificate { body, signature }.
```

### 4.2 Error Conditions

| Error | Meaning |
|-------|---------|
| `EmptySession` | No receipts found for the session |
| `InvalidReceiptSignature` | A receipt failed Ed25519 verification |
| `ChainDiscontinuity` | Gap or reordering in the receipt hash chain |
| `ScopeViolation` | Tool call fell outside its capability's scope |
| `BudgetExceeded` | Grant invocation or cost limit was exceeded |
| `GuardBypass` | Allow decision issued despite a failed guard |
| `CapabilityExpired` | Receipt references a capability expired at invocation time |
| `DelegationViolation` | Delegation chain failed monotonic attenuation |

Any error means the session is **non-compliant** and no certificate is issued.

## 5. Verification Process

### 5.1 Certificate-Only Verification (Lightweight)

```
verify_compliance_certificate(cert, trusted_kernel_keys) -> Result<()>

1. Verify cert.signature against cert.body using cert.body.issuer_key.
2. Confirm cert.body.issuer_key is in trusted_kernel_keys.
3. Confirm cert.body.schema == "chio.session_compliance_certificate.v1".
4. Confirm cert.body.guard_summary.failed == 0.
5. For each budget_summary entry: assert usage <= limit where limits exist.
6. Confirm time_range.start <= time_range.end and total_receipt_count > 0.
7. Confirm tool_receipt_count + child_receipt_count == total_receipt_count.
```

This trusts the kernel's assertions. Sufficient for routine audit trails where
the kernel itself is in the trusted computing base.

### 5.2 Full Verification (With Receipt Bundle)

```
verify_compliance_certificate_full(cert, receipt_bundle, trusted_kernel_keys) -> Result<()>

1. Perform all lightweight checks from 5.1.
2. Confirm receipt_bundle.tool_receipts.len() == cert.body.tool_receipt_count.
3. Confirm receipt_bundle.child_receipts.len() == cert.body.child_receipt_count.
4. Confirm total receipt count matches cert.body.total_receipt_count.
5. Verify each receipt's Ed25519 signature and kernel_key membership.
6. Rebuild MerkleTree from canonical_json_bytes of each receipt body in
   canonical session order.
7. Assert rebuilt root == cert.body.merkle_root.
8. Verify chain_head/chain_tail match first/last receipt body hashes.
```

Full verification is independent of the issuing kernel and provides non-repudiation.

## 6. Capability Attestation Chaining

### 6.1 Hash Chain Construction

Each receipt carries a `content_hash` (SHA-256 of its canonical JSON body),
computed at creation time. The certificate anchors this chain via `chain_head`
(first receipt hash) and `chain_tail` (last receipt hash).

### 6.2 Integrity Properties

| Property | Detection method |
|----------|-----------------|
| **Gap** (missing receipt) | Sequence number discontinuity during generation |
| **Replay** (duplicate) | Duplicate sequence number or content hash |
| **Reordering** | Timestamp or sequence inversion during ordered walk |
| **Truncation** | Tool/child/total receipt count mismatch between certificate and bundle |
| **Forgery** | Ed25519 signature verification failure |

### 6.3 Merkle Anchoring

The certificate's Merkle root commits the entire ordered receipt set using Chio's
RFC 6962-compatible tree (`MerkleTree::from_leaves`):

- Leaf: `SHA-256(byte(0x00) || canonical_json_bytes(receipt.body()))`
- Node: `SHA-256(byte(0x01) || left || right)`

Where `byte(0x00)` is a single zero byte and `||` denotes byte concatenation.

A verifier holding the certificate and a single receipt can obtain a
`MerkleProof` and confirm inclusion against `merkle_root` without the full bundle.

## 7. Regulatory Mapping

> **Disclaimer**: These mappings illustrate how Chio artifacts can provide
> evidence for regulatory requirements. Regulatory compliance depends on
> deployment context, organizational controls, and legal interpretation.
> Consult legal counsel before relying on Chio artifacts for regulatory claims.

### 7.1 SOC 2

| Control | Certificate evidence |
|---------|---------------------|
| CC6.1 -- Logical access | `capability_ids`, `scope_summary` |
| CC6.3 -- Access enforcement | `guard_summary` (failed == 0) |
| CC7.2 -- Monitoring | `total_receipt_count`, `merkle_root` |
| CC8.1 -- Change management | `budget_summary` |

### 7.2 EU AI Act (Articles 12, 14-15)

| Obligation | Certificate evidence |
|------------|---------------------|
| Art. 12 -- Logging | Full receipt chain via `merkle_root` |
| Art. 14 -- Human oversight | `guard_summary` records all policy gates |
| Art. 15 -- Robustness | `merkle_root` provides tamper evidence |

### 7.3 HIPAA

| Provision | Certificate evidence |
|-----------|---------------------|
| 164.312(b) -- Audit controls | Receipt chain via `merkle_root` |
| 164.312(c) -- Integrity | Ed25519 signatures on certificate and receipts |
| 164.312(d) -- Entity authentication | `agent_id` bound via capability subject |

### 7.4 SEC Rule 17a-4

| Requirement | Certificate evidence |
|-------------|---------------------|
| Non-rewritable records | Merkle-committed, append-only receipt log |
| Indexed and retrievable | `session_id`, `certificate_id`, `time_range` |
| Third-party verification | Section 5.2 verifies against the receipt bundle and trusted keys |

## 8. Integration Points

### 8.1 Kernel API

```rust
impl ChioKernel {
    /// Generate a compliance certificate for a completed session.
    pub async fn generate_compliance_certificate(
        &self,
        session_id: &SessionId,
    ) -> Result<SessionComplianceCertificate, ComplianceCertificateError>;

    /// Verify a certificate against this kernel's trusted key set.
    pub fn verify_compliance_certificate(
        &self,
        cert: &SessionComplianceCertificate,
    ) -> Result<(), ComplianceCertificateError>;
}
```

### 8.2 CLI

```
chio cert generate --session <session-id> [--output <path>]
chio cert verify   --cert <path> [--receipts <path>] [--trusted-keys <path>]
chio cert inspect  --cert <path>
```

### 8.3 SIEM Export

Certificates export as structured events via `EvidenceExportBundle`:

```json
{
  "event_type": "chio.session_compliance_certificate",
  "event_id": "<certificate_id>",
  "session_id": "<session_id>",
  "agent_id": "<agent_id>",
  "timestamp": 1718300000,
  "total_receipt_count": 47,
  "compliant": true,
  "merkle_root": "0x<64 hex chars>",
  "certificate_signature": "<128 hex chars>"
}
```

### 8.4 Web3 Anchoring

The certificate hash (`SHA-256(canonical_json_bytes(certificate.body))`) can be
anchored on-chain via `Web3SettlementDispatchArtifact`, providing a public
timestamped proof independent of the issuing kernel's availability.

## 9. Example Certificate

```json
{
  "body": {
    "schema": "chio.session_compliance_certificate.v1",
    "certificate_id": "019058a3-7b2c-7def-8a00-4e6f8c3d1a2b",
    "session_id": "session-2026-04-13-ab7f",
    "agent_id": "agent-research-assistant-01",
    "time_range": { "start": 1781568000, "end": 1781571600 },
    "tool_receipt_count": 12,
    "child_receipt_count": 3,
    "total_receipt_count": 15,
    "merkle_root": "0x3a7f1c9e8b2d4f6a0e5c7b9d1f3a5c7e9b0d2f4a6c8e0b3d5f7a9c1e3b5d7f",
    "chain_head": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    "chain_tail": "f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e1",
    "scope_summary": {
      "tools_invoked": [
        { "server_id": "pubmed-search", "tool_name": "search_articles" },
        { "server_id": "pubmed-search", "tool_name": "get_abstract" },
        { "server_id": "file-writer", "tool_name": "write_file" }
      ],
      "resources_accessed": ["chio://pubmed-search/config"],
      "prompts_accessed": []
    },
    "budget_summary": [
      {
        "capability_id": "cap-019058a3-1111-7def-8a00-000000000001",
        "grant_index": 0,
        "tool": { "server_id": "pubmed-search", "tool_name": "search_articles" },
        "invocations_used": 8, "invocations_limit": 50,
        "cost_consumed": null, "cost_limit": null, "currency": null
      },
      {
        "capability_id": "cap-019058a3-1111-7def-8a00-000000000001",
        "grant_index": 1,
        "tool": { "server_id": "pubmed-search", "tool_name": "get_abstract" },
        "invocations_used": 3, "invocations_limit": null,
        "cost_consumed": null, "cost_limit": null, "currency": null
      },
      {
        "capability_id": "cap-019058a3-2222-7def-8a00-000000000002",
        "grant_index": 0,
        "tool": { "server_id": "file-writer", "tool_name": "write_file" },
        "invocations_used": 1, "invocations_limit": 5,
        "cost_consumed": 250, "cost_limit": 10000, "currency": "USD"
      }
    ],
    "guard_summary": {
      "total_evaluations": 24, "passed": 24, "failed": 0,
      "guard_names": ["ForbiddenPathGuard", "ContentPolicyGuard"]
    },
    "execution_context": {
      "providers": ["openai"],
      "models": ["gpt-5.2"],
      "policy_bundle_hashes": ["sha256:policy-bundle-001"],
      "prompt_bundle_hashes": ["sha256:prompt-bundle-017"],
      "runtime_attestation": {
        "format": "tee-report-v1",
        "measurement_hash": "sha256:runtime-measurement-abc",
        "verifier": "chio-control-plane"
      }
    },
    "approval_refs": [
      {
        "system": "servicenow",
        "reference": "CHG-10493",
        "approver": "ops-manager",
        "approved_at": 1781567900
      }
    ],
    "redaction_profile": {
      "profile_id": "default-phi-minimized",
      "redacted_fields": ["tool_parameters.patient_name"],
      "rationale": "PII minimized for external audit bundle"
    },
    "capability_ids": [
      "cap-019058a3-1111-7def-8a00-000000000001",
      "cap-019058a3-2222-7def-8a00-000000000002"
    ],
    "issuer_key": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01",
    "issued_at": 1781571605
  },
  "signature": "e3b0c44298fc1c149afbf4c8996fb924...128 hex chars total..."
}
```

This session ran 12 tool calls plus 3 child receipts across two servers,
consumed 8 of 50 search invocations and 1 of 5 file writes ($2.50 of $100.00
USD budget), passed all 24 guard evaluations, carried a recorded change-
approval reference, and completed within one hour. The certificate was signed 5
seconds after the last receipt.
