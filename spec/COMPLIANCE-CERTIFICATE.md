# Chio Compliance Certificate

**Version:** 1.0
**Date:** 2026-04-14
**Status:** Normative

This specification defines the Session Compliance Certificate: a signed
artifact that proves an entire agent session operated within its authorized
boundaries. Implementations MUST follow the generation algorithm, error
semantics, and verification modes described herein.

The design rationale, regulatory mapping, and integration details are in
`docs/protocols/SESSION-COMPLIANCE-CERTIFICATE.md`.

---

## 1. Purpose

Chio runtimes produce Ed25519-signed receipts for every tool invocation and
commit them to Merkle-rooted checkpoint batches. A compliance certificate
composes receipt-level evidence into a single auditor-ready document. A
third party can verify the certificate without replaying every guard
evaluation.

A valid certificate asserts that:

1. Every receipt in the session has a valid Ed25519 signature.
2. The receipt chain is continuous with no gaps, duplicates, or reordering.
3. Every tool invocation fell within its capability's authorized scope.
4. No budget limit (invocation count or monetary) was exceeded.
5. Every required guard produced passing evidence in every receipt.
6. Delegation chains maintained monotonic attenuation (no privilege
   escalation).

---

## 2. Certificate Structure

### 2.1 ComplianceCertificateBody

The unsigned body of a compliance certificate.

| Field | Type | Description |
|-------|------|-------------|
| `schema` | string | Schema identifier. MUST be `"chio.compliance.certificate.v1"`. |
| `session_id` | string | Session ID the certificate covers. |
| `issued_at` | u64 | Unix timestamp (seconds) when the certificate was generated. |
| `receipt_count` | u64 | Number of receipts examined. |
| `first_receipt_at` | u64 | Timestamp of the first receipt in the session. |
| `last_receipt_at` | u64 | Timestamp of the last receipt in the session. |
| `all_signatures_valid` | bool | Whether all receipts passed signature verification. |
| `chain_continuous` | bool | Whether the receipt chain has no gaps. |
| `scope_compliant` | bool | Whether all invocations fell within authorized scope. |
| `budget_compliant` | bool | Whether budget limits were respected. |
| `guards_compliant` | bool | Whether all required guards have evidence in every receipt. |
| `anomalies` | string[] | Summary of any anomalies detected. Empty if fully compliant. |
| `kernel_key` | PublicKey | The kernel public key that signed the session receipts. |

For a certificate to represent full compliance, all boolean fields MUST be
`true` and the `anomalies` array MUST be empty.

### 2.2 ComplianceCertificate

The signed certificate wrapping the body.

| Field | Type | Description |
|-------|------|-------------|
| `body` | ComplianceCertificateBody | The unsigned body. |
| `signer_key` | PublicKey | Public key that signed the certificate. |
| `signature` | Signature | Ed25519 signature over canonical JSON of `body`. |

The signature MUST be computed over `canonical_json_bytes(body)` using
RFC 8785 (JCS) canonical JSON serialization.

### 2.3 Coverage

The certificate body's `kernel_key` field identifies which kernel signed the
session's receipts. Verifiers SHOULD confirm this key belongs to a trusted
kernel in their trust configuration.

The `receipt_count` field, combined with `first_receipt_at` and
`last_receipt_at`, indicates the temporal and volumetric scope of the
certificate. Verifiers can determine which protocol surfaces contributed
signed receipts by examining the session's receipt log.

---

## 3. Generation

The kernel generates a certificate by walking the complete receipt log for a
session. The algorithm is fail-closed: any anomaly MUST abort generation and
return a typed error rather than issuing a misleading certificate.

### 3.1 Algorithm

```
generate_compliance_certificate(session_id, receipts, config, keypair)
  -> Result<ComplianceCertificate, ComplianceCertificateError>

1.  If receipts is empty, return Err(EmptySession(session_id)).

2.  For each receipt in sequence order:
      a. Verify Ed25519 signature.
         Fail: Err(InvalidReceiptSignature { receipt_id }).

3.  Verify chain continuity:
      For each pair of consecutive receipts, confirm
      receipts[i].seq + 1 == receipts[i+1].seq.
      Fail: Err(ChainDiscontinuity { expected, found }).

4.  Verify scope compliance (when authorized_scopes is non-empty):
      For each receipt, confirm the tool_name matches at least one
      authorized scope prefix.
      Fail: Err(ScopeViolation { receipt_id, resource }).

5.  Verify budget compliance (when budget_limit > 0):
      Confirm total invocation count <= budget_limit.
      Fail: Err(BudgetExceeded { used, limit }).

6.  Verify guard evidence (for each required guard):
      For each receipt, confirm the guard name appears in the
      receipt's evidence list.
      Fail: Err(GuardBypass { guard_name, receipt_id }).

7.  Construct ComplianceCertificateBody with all fields set to their
    compliant values.

8.  Sign: keypair.sign(canonical_json_bytes(body)) -> signature.

9.  Return ComplianceCertificate { body, signer_key, signature }.
```

### 3.2 Configuration

The `ComplianceConfig` struct controls generation behavior:

| Field | Type | Description |
|-------|------|-------------|
| `budget_limit` | u64 | Maximum invocations allowed. `0` means unlimited. |
| `required_guards` | string[] | Guard names that MUST appear in every receipt's evidence. |
| `authorized_scopes` | string[] | Resource path prefixes. Empty means all scopes are allowed. |

---

## 4. Abort Errors

Certificate generation MUST abort with one of the following typed errors.
Each error indicates the session is non-compliant and no certificate is
issued.

| Error | Fields | Meaning |
|-------|--------|---------|
| `EmptySession` | `session_id: String` | No receipts found for the session. |
| `InvalidReceiptSignature` | `receipt_id: String` | A receipt failed Ed25519 signature verification. |
| `ChainDiscontinuity` | `expected: u64, found: u64` | Gap or reordering in the receipt sequence. |
| `ScopeViolation` | `receipt_id: String, resource: String` | A tool invocation fell outside authorized scope. |
| `BudgetExceeded` | `used: u64, limit: u64` | The session's invocation count exceeded the budget. |
| `GuardBypass` | `guard_name: String, receipt_id: String` | A required guard has no evidence in a receipt. |

Implementations MAY define additional error variants for serialization and
signing failures, but the six errors above are the normative compliance
abort conditions.

---

## 5. Verification Modes

### 5.1 Lightweight Verification

Lightweight verification trusts the kernel's assertions in the certificate
body. It is sufficient for routine audit trails where the kernel itself is
in the trusted computing base.

```
verify_lightweight(cert) -> CertificateVerificationResult

1. Serialize cert.body to canonical JSON bytes.
2. Verify cert.signature against the bytes using cert.signer_key.
3. Confirm all boolean fields in body are true.
4. Confirm body.anomalies is empty.
5. Return pass/fail with summary.
```

Lightweight verification does not re-verify individual receipt signatures.

### 5.2 Full Bundle Verification

Full bundle verification re-verifies all receipt signatures independently
of the kernel's assertions. It supports non-repudiation when the verifier
resolves each receipt's signing key against a trusted-key set populated
out of band (operator-pinned roots, federation registry, or exported
`KernelKeyDirectory`): a third party with that key set can confirm the
certificate without trusting the issuing kernel.

```
verify_full_bundle(cert, receipts) -> CertificateVerificationResult

1. Perform all lightweight checks from 5.1.
2. For each receipt in the bundle:
     Verify Ed25519 signature.
     Count successes and failures.
3. Confirm all receipt signatures are valid.
4. Return pass/fail with receipt re-verification counts.
```

Full bundle verification reconstructs the cryptographic evidence chain from
the raw receipts rather than trusting the certificate body's summary fields.

### 5.3 Verification Result

| Field | Type | Description |
|-------|------|-------------|
| `certificate_signature_valid` | bool | Whether the certificate signature passed. |
| `body_consistent` | bool | Whether all body fields indicate compliance. |
| `receipts_reverified` | u64 | Number of receipts re-verified (full-bundle only, 0 for lightweight). |
| `receipt_failures` | u64 | Number of receipt signature failures (full-bundle only). |
| `passed` | bool | Overall pass/fail. |
| `summary` | string | Human-readable verification summary. |

---

## 6. CLI

Implementations SHOULD provide the following CLI commands:

### 6.1 Generate

```
chio cert generate --session <session-id> [--output <path>]
```

Walks the receipt log for the given session, runs the generation algorithm
from Section 3, and writes the signed certificate to the output path (or
stdout if omitted).

### 6.2 Verify

```
chio cert verify --cert <path> [--receipts <path>] [--trusted-keys <path>]
```

Performs lightweight verification by default. When `--receipts` is provided,
performs full bundle verification (Section 5.2). When `--trusted-keys` is
provided, additionally confirms the signer key is in the trusted set.

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Verification passed |
| 1 | Verification failed |
| 2 | Input error (file not found, invalid format) |

### 6.3 Inspect

```
chio cert inspect --cert <path>
```

Prints the certificate body fields in human-readable format without
performing cryptographic verification. Useful for debugging and auditing
workflows.

Output includes: session ID, receipt count, time range, compliance boolean
summary, anomaly list, and signer key fingerprint.

---

## 7. Serialization

All certificate fields use canonical JSON (RFC 8785 / JCS) for deterministic
hashing and signature verification. This is consistent with all other Chio
signed artifacts.

The signature covers `canonical_json_bytes(&body)`. Verifiers MUST
re-serialize the body to canonical JSON before checking the signature;
non-canonical JSON serialization will produce verification failures.
