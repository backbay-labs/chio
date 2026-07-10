// DO NOT EDIT - regenerate via 'cargo run -p chio-spec-codegen -- --errors-only'.
//
// Source: spec/errors/registry.yaml
// Tool:   chio-spec-codegen
// Crate:  chio-spec-codegen
//
// Manual edits will be overwritten by the next regeneration.

use crate::{Domain, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorCodeSpec {
    pub urn: &'static str,
    pub domain: Domain,
    pub severity: Severity,
    pub summary: &'static str,
    pub help: &'static str,
    pub string_code: &'static str,
    pub jsonrpc_code: Option<i32>,
    pub since: &'static str,
    pub stability: &'static str,
    pub consumed_by: &'static [&'static str],
}

pub const REGISTRY_SCHEMA: &str = "chio.error-urn-registry.v1";
pub const REGISTRY_VERSION: &str = "0.1.0";
pub const REGISTRY_UPDATED_AT: &str = "2026-06-19";

pub const TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:passport-schema-unsupported",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction passport schema is unsupported by the verifier.",
    help: "Reject the proof bundle and regenerate the passport with a registered transaction passport schema.",
    string_code: "CHIO-TRANSACTION-PASSPORT-SCHEMA-UNSUPPORTED",
    jsonrpc_code: Some(7100),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_PASSPORT_HASH_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:passport-hash-mismatch",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction passport root digest does not match its bound evidence.",
    help: "Reject the proof bundle, rebuild the passport root, and retry with matching evidence graph, claim set, and policy digests.",
    string_code: "CHIO-TRANSACTION-PASSPORT-HASH-MISMATCH",
    jsonrpc_code: Some(7101),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_GRAPH_NOT_CLOSED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:graph-not-closed",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction evidence graph does not close over the required artifact references.",
    help: "Reject the proof bundle and include every required evidence, claim-set, policy, and receipt node in the graph.",
    string_code: "CHIO-TRANSACTION-GRAPH-NOT-CLOSED",
    jsonrpc_code: Some(7102),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_GRAPH_CYCLE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:graph-cycle",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction evidence graph contains a cycle.",
    help: "Reject the proof bundle and emit an acyclic evidence graph whose dependency edges can be topologically verified.",
    string_code: "CHIO-TRANSACTION-GRAPH-CYCLE",
    jsonrpc_code: Some(7103),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_REQUIRED_CLAIM_MISSING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:required-claim-missing",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction verifier policy requires a claim that is not verified.",
    help: "Reject the proof bundle and add verified evidence for the required claim or remove the unsupported requirement.",
    string_code: "CHIO-TRANSACTION-REQUIRED-CLAIM-MISSING",
    jsonrpc_code: Some(7104),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_ARTIFACT_HASH_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:artifact-hash-mismatch",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction proof artifact digest does not match the passport or evidence graph.",
    help: "Reject the proof bundle, regenerate the artifact set, and retry with matching transaction evidence digests.",
    string_code: "CHIO-TRANSACTION-ARTIFACT-HASH-MISMATCH",
    jsonrpc_code: Some(7105),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_IDENTITY_NOT_BOUND: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:identity-not-bound",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction evidence does not bind the required identity or subject.",
    help: "Reject the proof bundle and include identity evidence bound to the transaction passport subject and evidence graph.",
    string_code: "CHIO-TRANSACTION-IDENTITY-NOT-BOUND",
    jsonrpc_code: Some(7106),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_AUTHORIZATION_NOT_BOUND: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:authorization-not-bound",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction evidence does not bind required authorization evidence.",
    help: "Reject the proof bundle and include capability, policy, approval, or guard evidence bound to the governed transaction.",
    string_code: "CHIO-TRANSACTION-AUTHORIZATION-NOT-BOUND",
    jsonrpc_code: Some(7107),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_RECEIPT_UNCHECKPOINTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:receipt-uncheckpointed",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction receipt evidence is not checkpointed or included in the required receipt lineage.",
    help: "Reject the proof bundle and provide checkpointed receipt or inclusion evidence for the transaction receipt.",
    string_code: "CHIO-TRANSACTION-RECEIPT-UNCHECKPOINTED",
    jsonrpc_code: Some(7108),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_RUNTIME_PROOF_REJECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:runtime-proof-rejected",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Runtime proof evidence required by the transaction verifier was rejected.",
    help: "Reject the proof bundle and regenerate runtime security, parity, lease, nonce, revocation, sandbox, ack, and terminal receipt evidence.",
    string_code: "CHIO-TRANSACTION-RUNTIME-PROOF-REJECTED",
    jsonrpc_code: Some(7109),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_BUYER_REVIEW_REJECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:buyer-review-rejected",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Buyer review evidence required by the transaction verifier was rejected.",
    help: "Reject the proof bundle and regenerate buyer review evidence that matches the transaction passport and verifier policy.",
    string_code: "CHIO-TRANSACTION-BUYER-REVIEW-REJECTED",
    jsonrpc_code: Some(7110),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_SETTLEMENT_UNVERIFIED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:settlement-unverified",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Settlement evidence required by the transaction verifier is absent or unverified.",
    help: "Reject the proof bundle and include settlement evidence bound to the transaction order, amount, currency, rail, and receipt lineage.",
    string_code: "CHIO-TRANSACTION-SETTLEMENT-UNVERIFIED",
    jsonrpc_code: Some(7111),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_DISPUTE_UNBOUND: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:dispute-unbound",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Dispute, refund, or remediation evidence is not bound to the transaction.",
    help: "Reject the proof bundle and bind dispute, refund, remediation, and settlement reversal evidence to the transaction passport and receipts.",
    string_code: "CHIO-TRANSACTION-DISPUTE-UNBOUND",
    jsonrpc_code: Some(7112),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_TRANSPARENCY_PREVIEW_NOT_ALLOWED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:transparency-preview-not-allowed",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction transparency evidence is only preview or advisory when verified transparency is required.",
    help: "Reject the proof bundle and provide verified transparency inclusion evidence or remove the transparency claim.",
    string_code: "CHIO-TRANSACTION-TRANSPARENCY-PREVIEW-NOT-ALLOWED",
    jsonrpc_code: Some(7113),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const CAPABILITY_SCOPE_EXCEEDED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:capability:scope-exceeded",
    domain: Domain::Capability,
    severity: Severity::Error,
    summary: "Capability scope does not allow the requested tool, resource, or prompt.",
    help: "Issue a capability that explicitly grants the requested scope, or change the request to fit the granted scope.",
    string_code: "CHIO-KERNEL-OUT-OF-SCOPE-TOOL",
    jsonrpc_code: Some(2100),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-cli", "chio-control-plane"],
};

pub const CAPABILITY_EXPIRED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:capability:expired",
    domain: Domain::Capability,
    severity: Severity::Error,
    summary: "Capability token expired before the kernel evaluated the request.",
    help: "Obtain or issue a fresh time-bounded capability before retrying the operation.",
    string_code: "CHIO-KERNEL-CAPABILITY-EXPIRED",
    jsonrpc_code: Some(2101),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-cli", "chio-control-plane"],
};

pub const CAPABILITY_REVOKED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:capability:revoked",
    domain: Domain::Capability,
    severity: Severity::Error,
    summary: "Capability token was revoked and must not be retried.",
    help: "Resolve the revocation reason and request a newly issued capability.",
    string_code: "CHIO-KERNEL-CAPABILITY-REVOKED",
    jsonrpc_code: Some(2102),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-cli", "chio-control-plane"],
};

pub const CAPABILITY_NOT_YET_VALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:capability:not-yet-valid",
    domain: Domain::Capability,
    severity: Severity::Error,
    summary: "Capability token is not valid at the current evaluation time.",
    help: "Retry after the not-before timestamp or issue a capability with the intended validity window.",
    string_code: "CHIO-KERNEL-CAPABILITY-NOT-YET-VALID",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-cli"],
};

pub const CAPABILITY_SUBJECT_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:capability:subject-mismatch",
    domain: Domain::Capability,
    severity: Severity::Error,
    summary: "Capability subject does not match the requesting actor.",
    help: "Bind the capability to the correct subject DID or use credentials for the subject named by the token.",
    string_code: "CHIO-KERNEL-SUBJECT-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-credentials"],
};

pub const CAPABILITY_SIGNATURE_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:capability:signature-invalid",
    domain: Domain::Capability,
    severity: Severity::Fatal,
    summary: "Capability signature verification failed.",
    help: "Reject the capability, verify issuer trust, and reissue the token with canonical JSON signing.",
    string_code: "CHIO-KERNEL-INVALID-SIGNATURE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-credentials"],
};

pub const POLICY_DECISION_DENIED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:policy:decision-denied",
    domain: Domain::Policy,
    severity: Severity::Error,
    summary: "Policy evaluation denied the requested action.",
    help: "Inspect the policy rule path and update the request or policy inputs before retrying.",
    string_code: "CHIO-CLI-POLICY",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-policy", "chio-cli", "chio-control-plane"],
};

pub const POLICY_COMPILE_FAILED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:policy:compile-failed",
    domain: Domain::Policy,
    severity: Severity::Error,
    summary: "Policy document failed to compile.",
    help: "Fix the policy syntax or schema issue reported by the compiler and reload the policy.",
    string_code: "CHIO-CLI-POLICY",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-policy", "chio-cli"],
};

pub const POLICY_CONSTRAINT_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:policy:constraint-invalid",
    domain: Domain::Policy,
    severity: Severity::Error,
    summary: "Policy constraint was syntactically valid but semantically invalid.",
    help: "Regenerate or edit the constraint so every referenced scope, resource, and operator is supported.",
    string_code: "CHIO-KERNEL-INVALID-CONSTRAINT",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-policy", "chio-kernel"],
};

pub const POLICY_GOVERNANCE_DENIED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:policy:governance-denied",
    domain: Domain::Policy,
    severity: Severity::Error,
    summary: "Governance policy denied a governed transaction.",
    help: "Follow the governance approval path or remove the governed operation from the request.",
    string_code: "CHIO-KERNEL-GOVERNED-TRANSACTION-DENIED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-governance", "chio-kernel"],
};

pub const GUARD_DENIED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:guard:denied",
    domain: Domain::Guard,
    severity: Severity::Error,
    summary: "Guard pipeline denied the request or response.",
    help: "Inspect the guard verdict and adjust the prompt, tool input, policy, or output before retrying.",
    string_code: "CHIO-KERNEL-GUARD-DENIED",
    jsonrpc_code: Some(3100),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-guards", "chio-cli"],
};

pub const GUARD_INPUT_REDACTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:guard:input-redacted",
    domain: Domain::Guard,
    severity: Severity::Warning,
    summary: "Guard redacted sensitive input before it crossed a trust boundary.",
    help: "Review the redaction receipt and provide lower-risk input if the tool requires the removed field.",
    string_code: "CHIO-GUARD-INPUT-REDACTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-data-guards", "chio-guards"],
};

pub const GUARD_OUTPUT_REDACTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:guard:output-redacted",
    domain: Domain::Guard,
    severity: Severity::Warning,
    summary: "Guard redacted sensitive output before it crossed a trust boundary.",
    help: "Review the guard receipt and update the downstream consumer to handle redacted fields.",
    string_code: "CHIO-GUARD-OUTPUT-REDACTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-data-guards", "chio-guards"],
};

pub const GUARD_WASM_TRAP: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:guard:wasm-trap",
    domain: Domain::Guard,
    severity: Severity::Fatal,
    summary: "WASM guard trapped during evaluation.",
    help: "Fail closed, inspect the guard bundle, and republish a guard that completes deterministically.",
    string_code: "CHIO-GUARD-WASM-TRAP",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-wasm-guards", "chio-guard-sdk"],
};

pub const ATTEST_RECEIPT_SIGNING_FAILED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:attest:receipt-signing-failed",
    domain: Domain::Attest,
    severity: Severity::Fatal,
    summary: "Kernel could not sign the receipt for a decision or tool call.",
    help:
        "Treat the operation as failed and repair the signing key, key store, or canonical payload.",
    string_code: "CHIO-KERNEL-RECEIPT-SIGNING-FAILED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-attest-verify"],
};

pub const ATTEST_QUOTE_VERIFICATION_FAILED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:attest:quote-verification-failed",
    domain: Domain::Attest,
    severity: Severity::Fatal,
    summary: "TEE quote verification failed.",
    help: "Reject the attestation and refresh the quote or verifier trust roots before retrying.",
    string_code: "CHIO-ATTEST-QUOTE-VERIFICATION-FAILED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-attest-verify", "chio-tee"],
};

pub const ATTEST_PROVENANCE_MISSING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:attest:provenance-missing",
    domain: Domain::Attest,
    severity: Severity::Error,
    summary: "Required provenance evidence was missing from the receipt context.",
    help: "Regenerate the evidence bundle and include provenance before submitting the operation.",
    string_code: "CHIO-ATTEST-PROVENANCE-MISSING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-attest-verify", "chio-otel-receipt-exporter"],
};

pub const REPLAY_TRACE_NOT_FOUND: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:replay:trace-not-found",
    domain: Domain::Replay,
    severity: Severity::Error,
    summary: "Replay trace could not be found.",
    help: "Check the replay corpus path and regenerate the trace if it was not archived.",
    string_code: "CHIO-REPLAY-TRACE-NOT-FOUND",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-replay-corpus", "chio-cli"],
};

pub const REPLAY_DETERMINISTIC_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:replay:deterministic-mismatch",
    domain: Domain::Replay,
    severity: Severity::Error,
    summary: "Replay produced a deterministic output mismatch.",
    help: "Compare the recorded receipt, model fixture, and guard bundle versions before accepting the replay.",
    string_code: "CHIO-REPLAY-DETERMINISTIC-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-replay-corpus", "chio-conformance"],
};

pub const REPLAY_FIXTURE_DRIFT: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:replay:fixture-drift",
    domain: Domain::Replay,
    severity: Severity::Warning,
    summary: "Replay fixture no longer matches the registry or schema it was recorded against.",
    help: "Regenerate the fixture from the current registry and rerun replay validation.",
    string_code: "CHIO-REPLAY-FIXTURE-DRIFT",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-replay-corpus", "chio-spec-codegen"],
};

pub const PROVIDER_TOOL_SERVER_ERROR: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:provider:tool-server-error",
    domain: Domain::Provider,
    severity: Severity::Error,
    summary: "Tool server returned an adapter or execution error.",
    help: "Retry with bounded backoff only when the provider marks the failure as transient.",
    string_code: "CHIO-KERNEL-TOOL-SERVER",
    jsonrpc_code: Some(5100),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &[
        "chio-kernel",
        "chio-tool-call-fabric",
        "chio-provider-conformance",
    ],
};

pub const PROVIDER_OPENAI: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:provider:openai",
    domain: Domain::Provider,
    severity: Severity::Error,
    summary: "OpenAI provider adapter returned a normalized provider error.",
    help: "Inspect the provider error details and retry only when the adapter marks the failure transient.",
    string_code: "CHIO-PROVIDER-OPENAI",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["deferred-openai-adapter-ticket", "chio-provider-conformance"],
};

pub const PROVIDER_ANTHROPIC: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:provider:anthropic",
    domain: Domain::Provider,
    severity: Severity::Error,
    summary: "Anthropic provider adapter returned a normalized provider error.",
    help: "Inspect the provider error details and retry only when the adapter marks the failure transient.",
    string_code: "CHIO-PROVIDER-ANTHROPIC",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-anthropic-tools-adapter", "chio-provider-conformance"],
};

pub const PROVIDER_BEDROCK: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:provider:bedrock",
    domain: Domain::Provider,
    severity: Severity::Error,
    summary: "Bedrock Converse provider adapter returned a normalized provider error.",
    help: "Inspect the provider error details and retry only when the adapter marks the failure transient.",
    string_code: "CHIO-PROVIDER-BEDROCK",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-bedrock-converse-adapter", "chio-provider-conformance"],
};

pub const MANIFEST_SCHEMA_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:manifest:schema-invalid",
    domain: Domain::Manifest,
    severity: Severity::Error,
    summary: "Manifest did not validate against the expected schema.",
    help: "Fix the manifest shape and rerun schema validation before loading it.",
    string_code: "CHIO-CLI-YAML",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-manifest", "chio-cli", "chio-spec-validate"],
};

pub const MANIFEST_SIGNATURE_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:manifest:signature-invalid",
    domain: Domain::Manifest,
    severity: Severity::Fatal,
    summary: "Manifest signature verification failed.",
    help:
        "Reject the manifest and republish it with the expected signing key and canonical payload.",
    string_code: "CHIO-MANIFEST-SIGNATURE-INVALID",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-manifest", "chio-guard-registry"],
};

pub const MANIFEST_TOOL_NOT_REGISTERED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:manifest:tool-not-registered",
    domain: Domain::Manifest,
    severity: Severity::Error,
    summary: "Requested tool is not registered in the active manifest.",
    help: "Register the tool in the manifest or request a tool that is present.",
    string_code: "CHIO-KERNEL-TOOL-NOT-REGISTERED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-manifest", "chio-kernel"],
};

pub const MANIFEST_RESOURCE_ROOT_DENIED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:manifest:resource-root-denied",
    domain: Domain::Manifest,
    severity: Severity::Error,
    summary: "Requested resource root is not allowed by the manifest.",
    help: "Grant the resource root in the manifest or request a resource under an allowed root.",
    string_code: "CHIO-KERNEL-RESOURCE-ROOT-DENIED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-manifest", "chio-kernel"],
};

pub const KERNEL_INTERNAL_ERROR: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:internal-error",
    domain: Domain::Kernel,
    severity: Severity::Fatal,
    summary: "Kernel hit an internal error while evaluating the request.",
    help: "Retry with bounded backoff only after preserving the receipt and diagnostic context.",
    string_code: "CHIO-KERNEL-INTERNAL",
    jsonrpc_code: Some(6100),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-cli"],
};

pub const KERNEL_SESSION_NOT_INITIALIZED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:session-not-initialized",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Request arrived before the session was initialized.",
    help: "Open a new session and complete initialization before retrying the operation.",
    string_code: "CHIO-KERNEL-UNKNOWN-SESSION",
    jsonrpc_code: Some(1001),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-http-session"],
};

pub const KERNEL_SESSION_ALREADY_EXISTS: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:session-already-exists",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Session creation attempted to reuse an existing session identifier.",
    help: "Choose a new session identifier or attach to the existing session.",
    string_code: "CHIO-KERNEL-SESSION-ALREADY-EXISTS",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-http-session"],
};

pub const KERNEL_REQUEST_INCOMPLETE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:request-incomplete",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Kernel request is missing required fields.",
    help: "Provide every required request field before dispatching the operation.",
    string_code: "CHIO-KERNEL-REQUEST-INCOMPLETE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-core-types"],
};

pub const KERNEL_REQUEST_CANCELLED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:request-cancelled",
    domain: Domain::Kernel,
    severity: Severity::Warning,
    summary: "Kernel request was cancelled before completion.",
    help: "Treat any partial tool output as invalid and retry with a new request if work is still required.",
    string_code: "CHIO-KERNEL-REQUEST-CANCELLED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-tool-call-fabric"],
};

pub const KERNEL_BUDGET_EXHAUSTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:budget-exhausted",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Kernel budget for the requested operation was exhausted.",
    help: "Retry only after replenishing the budget, widening the grant, or reconciling billing state.",
    string_code: "CHIO-KERNEL-BUDGET-EXHAUSTED",
    jsonrpc_code: Some(4100),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-metering", "chio-cli"],
};

pub const TRANSPORT_PROTOCOL_VERSION_UNSUPPORTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:protocol-version-unsupported",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "Peer requested an unsupported protocol version.",
    help: "Negotiate a supported Chio protocol version before retrying.",
    string_code: "CHIO-CLI-TRANSPORT",
    jsonrpc_code: Some(1000),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-http-core", "chio-mcp-edge", "chio-a2a-edge"],
};

pub const TRANSPORT_INVALID_REQUEST_SHAPE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:invalid-request-shape",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "Request payload did not match the expected wire shape.",
    help: "Correct the JSON-RPC or HTTP request shape before retrying.",
    string_code: "CHIO-CLI-JSON",
    jsonrpc_code: Some(1002),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-http-core", "chio-spec-validate"],
};

pub const TRANSPORT_AUTH_MISSING_OR_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:auth-missing-or-invalid",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "Transport authentication was missing, expired, or invalid.",
    help: "Refresh credentials and resend the request with valid transport authentication.",
    string_code: "CHIO-CLI-CREDENTIAL",
    jsonrpc_code: Some(1100),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-http-core", "chio-credentials"],
};

pub const TRANSPORT_HTTP_FAILED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:http-failed",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "HTTP transport failed before the kernel could evaluate the request.",
    help: "Check endpoint reachability, TLS configuration, and response body diagnostics before retrying.",
    string_code: "CHIO-CLI-HTTP",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-http-core", "chio-cli"],
};

pub const TRANSPORT_DPOP_VERIFICATION_FAILED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:dpop-verification-failed",
    domain: Domain::Transport,
    severity: Severity::Fatal,
    summary: "DPoP proof verification failed.",
    help: "Reject the request and require a fresh proof bound to the correct method, URI, and key.",
    string_code: "CHIO-KERNEL-DPOP-VERIFICATION-FAILED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-http-core"],
};

pub const TRANSPORT_UPSTREAM_FAILURE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:upstream-failure",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "Wrapped upstream MCP server returned an error while handling a relayed tool call or listing.",
    help: "Inspect the upstream MCP server response; retry only when the upstream marks the failure transient.",
    string_code: "CHIO-TRANSPORT-UPSTREAM-FAILURE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-cli"],
};

pub const TRANSPORT_METHOD_NOT_FOUND: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:method-not-found",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "JSON-RPC method is not supported by the Chio MCP wrapper.",
    help: "Call a recognized method; the MCP wrapper supports tools/list, tools/call, initialize, ping, and JSON-RPC notifications.",
    string_code: "CHIO-TRANSPORT-METHOD-NOT-FOUND",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-cli"],
};

pub const CLI_IO: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:io",
    domain: Domain::Cli,
    severity: Severity::Error,
    summary: "CLI failed while reading or writing local data.",
    help: "Check the path, permissions, and filesystem state before retrying.",
    string_code: "CHIO-CLI-IO",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-cli", "chio-control-plane"],
};

pub const CLI_JSON: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:json",
    domain: Domain::Cli,
    severity: Severity::Error,
    summary: "CLI failed to parse or render JSON.",
    help: "Fix the JSON payload or output template and rerun the command.",
    string_code: "CHIO-CLI-JSON",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-cli", "chio-control-plane"],
};

pub const CLI_YAML: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:yaml",
    domain: Domain::Cli,
    severity: Severity::Error,
    summary: "CLI failed to parse or render YAML.",
    help: "Fix the YAML document and rerun the command.",
    string_code: "CHIO-CLI-YAML",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-cli", "chio-control-plane"],
};

pub const CLI_SQLITE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:sqlite",
    domain: Domain::Cli,
    severity: Severity::Error,
    summary: "CLI SQLite store operation failed.",
    help: "Check the database path, schema version, and write permissions before retrying.",
    string_code: "CHIO-CLI-SQLITE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-cli", "chio-store-sqlite"],
};

pub const CLI_OTHER: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:other",
    domain: Domain::Cli,
    severity: Severity::Error,
    summary: "CLI returned an uncategorized compatibility error.",
    help: "Preserve the original message and migrate the call site to a specific registry code when touched.",
    string_code: "CHIO-CLI-OTHER",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "deprecated",
    consumed_by: &["chio-cli", "chio-control-plane"],
};

pub const CLI_DOCTOR_TOOLCHAIN_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:doctor-toolchain-mismatch",
    domain: Domain::Cli,
    severity: Severity::Error,
    summary: "chio doctor toolchain probe found a Rust toolchain mismatch.",
    help: "Install the workspace MSRV (or the version pinned in rust-toolchain.toml) and rerun chio doctor.",
    string_code: "CHIO-CLI-DOCTOR-TOOLCHAIN-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-cli"],
};

pub const CLI_DOCTOR_OCI_UNREACHABLE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:doctor-oci-unreachable",
    domain: Domain::Cli,
    severity: Severity::Warning,
    summary: "chio doctor OCI registry reachability probe could not reach the configured registry.",
    help: "Verify the registry URL, network egress, and credentials, or run with CHIO_DOCTOR_SKIP_NETWORK=1 to bypass.",
    string_code: "CHIO-CLI-DOCTOR-OCI-UNREACHABLE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-cli", "chio-guard-registry"],
};

pub const CLI_DOCTOR_COSIGN_STALE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:doctor-cosign-stale",
    domain: Domain::Cli,
    severity: Severity::Warning,
    summary: "chio doctor cosign freshness probe found a stale or unverifiable guard-bundle signature.",
    help: "Re-pull the guard bundle and verify its sigstore signature against the trusted identity set.",
    string_code: "CHIO-CLI-DOCTOR-COSIGN-STALE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-cli", "chio-attest-verify"],
};

pub const CLI_DOCTOR_OTEL_UNRESOLVED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:doctor-otel-unresolved",
    domain: Domain::Cli,
    severity: Severity::Warning,
    summary: "chio doctor OTEL probe could not resolve the OTLP endpoint or kernel runtime metrics.",
    help: "Set OTEL_EXPORTER_OTLP_ENDPOINT and ensure the chio-tower /metrics endpoint exposes chio_kernel_dispatch_inflight.",
    string_code: "CHIO-CLI-DOCTOR-OTEL-UNRESOLVED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-cli"],
};

pub const CLI_DOCTOR_CHIO_YAML_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:doctor-chio-yaml-invalid",
    domain: Domain::Cli,
    severity: Severity::Error,
    summary: "chio doctor schema probe found chio.yaml validation errors.",
    help: "Repair the document at the reported line and column and rerun chio doctor.",
    string_code: "CHIO-CLI-DOCTOR-CHIO-YAML-INVALID",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-cli"],
};

pub const CLI_DOCTOR_PROBE_FAILED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:doctor-probe-failed",
    domain: Domain::Cli,
    severity: Severity::Error,
    summary: "chio doctor reported one or more failing probes.",
    help: "Inspect the per-probe diagnostics, fix the reported issues, and rerun chio doctor.",
    string_code: "CHIO-CLI-DOCTOR-PROBE-FAILED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-cli"],
};

pub const DELEGATION_CHAIN_REVOKED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:delegation:chain-revoked",
    domain: Domain::Delegation,
    severity: Severity::Error,
    summary: "Delegation chain includes a revoked link.",
    help: "Rebuild the chain from non-revoked grants before retrying delegated execution.",
    string_code: "CHIO-KERNEL-DELEGATION-CHAIN-REVOKED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-kernel", "chio-federation"],
};

pub const ADVERSARIAL_ESCAPE_DETECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:adversarial:escape-detected",
    domain: Domain::Adversarial,
    severity: Severity::Fatal,
    summary: "Adversarial suite detected an escape from the intended guard boundary.",
    help: "Fail the run, preserve artifacts, and tighten the guard or sandbox before rerunning.",
    string_code: "CHIO-ADVERSARIAL-ESCAPE-DETECTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-conformance", "chio-guards"],
};

pub const THREAT_COVERAGE_GAP: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:threat:coverage-gap",
    domain: Domain::Threat,
    severity: Severity::Warning,
    summary: "Threat model coverage check found an uncovered failure mode.",
    help: "Add a mapped test, fixture, or documented deferral before closing the coverage finding.",
    string_code: "CHIO-THREAT-COVERAGE-GAP",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-conformance", "chio-spec-validate"],
};

pub const ARENA_REPLAY_DIVERGENCE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:arena:replay-divergence",
    domain: Domain::Arena,
    severity: Severity::Error,
    summary: "Arena replay produced a verdict divergence.",
    help: "Compare the replay receipt, policy, guard bundle, and provider fixture before accepting the run.",
    string_code: "CHIO-ARENA-REPLAY-DIVERGENCE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-replay-corpus", "chio-conformance"],
};

pub const ECONOMY_METERING_UNAVAILABLE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:economy:metering-unavailable",
    domain: Domain::Economy,
    severity: Severity::Error,
    summary: "Metering or balance state was unavailable for an economic decision.",
    help: "Retry after the metering backend or settlement ledger is reachable and current.",
    string_code: "CHIO-ECONOMY-METERING-UNAVAILABLE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-metering", "chio-settle", "chio-credit"],
};

pub const LINEAGE_ANCESTOR_MISSING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:lineage:ancestor-missing",
    domain: Domain::Lineage,
    severity: Severity::Error,
    summary: "Lineage graph references an ancestor that cannot be resolved.",
    help: "Repair the lineage edge or import the missing receipt before accepting the graph.",
    string_code: "CHIO-LINEAGE-ANCESTOR-MISSING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-anchor", "chio-otel-receipt-exporter"],
};

pub const CUSTODY_HARDWARE_KEY_UNAVAILABLE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:hardware-key-unavailable",
    domain: Domain::Custody,
    severity: Severity::Fatal,
    summary: "Required hardware custody key was unavailable.",
    help: "Do not fall back to a software key; restore the custody key path and retry.",
    string_code: "CHIO-CUSTODY-HARDWARE-KEY-UNAVAILABLE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-tee", "chio-attest-verify"],
};

pub const CUSTODY_ASSERTION_REJECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:assertion-rejected",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "WebAuthn assertion failed structural or signature verification.",
    help:
        "Treat the assertion as untrusted; do not retry without a fresh challenge from the issuer.",
    string_code: "CHIO-CUSTODY-ASSERTION-REJECTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-control-plane"],
};

pub const MOBILE_RECEIPT_POST_REJECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:mobile:receipt-post-rejected",
    domain: Domain::Mobile,
    severity: Severity::Error,
    summary: "Hosted oracle rejected a mobile receipt after a successful network POST.",
    help: "Preserve the queued receipt, surface the oracle response, and do not retry until the tenant, signature, or capability binding is repaired.",
    string_code: "CHIO-MOBILE-RECEIPT-POST-REJECTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-kernel-mobile", "chio-custody-hw"],
};

pub const MOBILE_RECEIPT_SCHEMA_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:mobile:receipt-schema-invalid",
    domain: Domain::Mobile,
    severity: Severity::Error,
    summary: "Mobile receipt export did not validate against the audit-log export schema.",
    help: "Keep the receipt in the offline queue and regenerate the export envelope against spec/audit-log/export-schema.v1.json before retrying.",
    string_code: "CHIO-MOBILE-RECEIPT-SCHEMA-INVALID",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-kernel-mobile", "chio-siem"],
};

pub const MOBILE_ORACLE_UNREACHABLE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:mobile:oracle-unreachable",
    domain: Domain::Mobile,
    severity: Severity::Warning,
    summary: "Mobile SDK could not reach the hosted receipt oracle within the retry budget.",
    help: "Keep the receipt in the encrypted offline queue and retry with bounded backoff after connectivity returns.",
    string_code: "CHIO-MOBILE-ORACLE-UNREACHABLE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-kernel-mobile", "chio-control-plane"],
};

pub const CUSTODY_AUDIENCE_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:audience-mismatch",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Capability presented to a different audience than it was minted for.",
    help: "Issue or request a capability whose audience pin matches the verifier identity.",
    string_code: "CHIO-CUSTODY-AUDIENCE-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel"],
};

pub const CUSTODY_REPLAY_DETECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:replay-detected",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "WebAuthn challenge nonce was previously redeemed for this credential.",
    help: "Obtain a fresh challenge from the issuer; replayed assertions are denied fail-closed.",
    string_code: "CHIO-CUSTODY-REPLAY-DETECTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-control-plane"],
};

pub const CUSTODY_CAPABILITY_EXPIRED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:capability-expired",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Passkey capability expired before the verifier evaluated the request.",
    help: "Mint a fresh capability; passkey capabilities are pinned to a five-minute lifetime.",
    string_code: "CHIO-CUSTODY-CAPABILITY-EXPIRED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel"],
};

pub const CUSTODY_CREDENTIAL_REVOKED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:credential-revoked",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "WebAuthn credential bound to this capability has been revoked.",
    help: "Re-enroll the user's authenticator and request a freshly-issued capability.",
    string_code: "CHIO-CUSTODY-CREDENTIAL-REVOKED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel", "chio-revocation-oracle"],
};

pub const CUSTODY_USER_VERIFICATION_REQUIRED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:user-verification-required",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "WebAuthn assertion verified cryptographically but did not report user verification.",
    help: "Re-attempt the ceremony with a user-verifying gesture (PIN, biometric); custody issuance requires UV.",
    string_code: "CHIO-CUSTODY-USER-VERIFICATION-REQUIRED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-control-plane"],
};

pub const CUSTODY_INTERNAL_ENCODING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:internal-encoding",
    domain: Domain::Custody,
    severity: Severity::Fatal,
    summary: "Custody surface failed to canonicalize, encode, or decode an envelope.",
    help: "Treat as an internal error; do not retry until the encoding bug is resolved. No fresh challenge will help.",
    string_code: "CHIO-CUSTODY-INTERNAL-ENCODING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw"],
};

pub const CUSTODY_RATE_LIMITED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:rate-limited",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Capability issuance was denied because the subject exceeded its rate budget.",
    help: "Retry after the rate window elapses; the mint is denied fail-closed before the revocation oracle, nonce store, or signing backend are consulted.",
    string_code: "CHIO-CUSTODY-RATE-LIMITED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw"],
};

pub const CUSTODY_APP_ATTEST_INVALID_CBOR: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:app-attest-invalid-cbor",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Apple App Attest statement failed to decode as valid CBOR or was missing a required field.",
    help: "Reject the attestation; do not retry without a freshly generated App Attest statement from the device.",
    string_code: "CHIO-CUSTODY-APP-ATTEST-INVALID-CBOR",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_APP_ATTEST_INVALID_ROOT: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:app-attest-invalid-root",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Apple App Attest certificate chain did not anchor to the pinned Apple App Attestation root.",
    help: "Reject the attestation; verify the device produced a genuine Apple App Attest statement and that the pinned root is current.",
    string_code: "CHIO-CUSTODY-APP-ATTEST-INVALID-ROOT",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_APP_ATTEST_APP_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:app-attest-app-mismatch",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Apple App Attest app-identifier hash did not match the expected application identity.",
    help: "Reject the attestation; the statement was minted for a different app identifier than the verifier expects.",
    string_code: "CHIO-CUSTODY-APP-ATTEST-APP-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_APP_ATTEST_CHALLENGE_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:app-attest-challenge-mismatch",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Apple App Attest challenge hash did not match the issued challenge.",
    help: "Reject the attestation and reissue a fresh challenge; replayed or mismatched challenges are denied fail-closed.",
    string_code: "CHIO-CUSTODY-APP-ATTEST-CHALLENGE-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_APP_ATTEST_KEY_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:app-attest-key-mismatch",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Apple App Attest key identifier did not match the credential bound to this capability.",
    help: "Reject the attestation; the statement was produced by a different hardware key than the one enrolled.",
    string_code: "CHIO-CUSTODY-APP-ATTEST-KEY-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_APP_ATTEST_CREDENTIAL_KEY_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:app-attest-credential-key-mismatch",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Apple App Attest leaf certificate public key did not match the credential public key in authenticator data (WebAuthn registration step 6).",
    help: "Reject the attestation; the attested hardware key is not bound to the enrolled credential public key and is denied fail-closed.",
    string_code: "CHIO-CUSTODY-APP-ATTEST-CREDENTIAL-KEY-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_APP_ATTEST_COUNTER_ROLLBACK: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:app-attest-counter-rollback",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Apple App Attest assertion counter went backwards relative to the last accepted value.",
    help: "Reject the assertion; a counter rollback indicates replay or a cloned key and is denied fail-closed.",
    string_code: "CHIO-CUSTODY-APP-ATTEST-COUNTER-ROLLBACK",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_APP_ATTEST_CERT_CHAIN_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:app-attest-cert-chain-invalid",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Apple App Attest certificate chain failed signature or structural verification.",
    help: "Reject the attestation; the certificate chain did not verify against the pinned Apple roots.",
    string_code: "CHIO-CUSTODY-APP-ATTEST-CERT-CHAIN-INVALID",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_PLAY_INTEGRITY_INVALID_TOKEN: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:play-integrity-invalid-token",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Google Play Integrity token failed to decode or verify.",
    help: "Reject the attestation; do not retry without a freshly minted Play Integrity token from the device.",
    string_code: "CHIO-CUSTODY-PLAY-INTEGRITY-INVALID-TOKEN",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_PLAY_INTEGRITY_NONCE_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:play-integrity-nonce-mismatch",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Google Play Integrity token nonce did not match the issued challenge.",
    help: "Reject the attestation and reissue a fresh nonce; replayed or mismatched nonces are denied fail-closed.",
    string_code: "CHIO-CUSTODY-PLAY-INTEGRITY-NONCE-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_PLAY_INTEGRITY_APP_REJECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:play-integrity-app-rejected",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Google Play Integrity verdict rejected the application (unrecognized or tampered package).",
    help: "Reject the attestation; the Play Integrity verdict did not recognize the app as a genuine, unmodified install.",
    string_code: "CHIO-CUSTODY-PLAY-INTEGRITY-APP-REJECTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_PLAY_INTEGRITY_DEVICE_REJECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:play-integrity-device-rejected",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Google Play Integrity verdict rejected the device integrity signal.",
    help: "Reject the attestation; the Play Integrity verdict did not attest a trustworthy device.",
    string_code: "CHIO-CUSTODY-PLAY-INTEGRITY-DEVICE-REJECTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const WEIGHTS_MODEL_CARD_MISSING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:weights:model-card-missing",
    domain: Domain::Weights,
    severity: Severity::Error,
    summary: "Model weights or runtime artifact lacks a required model card.",
    help: "Attach the signed model card and verify its hash before running the workload.",
    string_code: "CHIO-WEIGHTS-MODEL-CARD-MISSING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-tee-frame", "chio-attest-verify"],
};

pub const WEIGHTS_CARD_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:weights:card-mismatch",
    domain: Domain::Weights,
    severity: Severity::Error,
    summary: "Provider's loaded weights_hash does not match the signed model card.",
    help: "Re-sign a card whose weights_hash matches the loaded weights blob, or rebind the provider with the correct weights.",
    string_code: "CHIO-WEIGHTS-CARD-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-weights", "chio-kernel", "chio-cli"],
};

pub const WEIGHTS_SCOPE_NOT_SUBSET: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:weights:scope-not-subset",
    domain: Domain::Weights,
    severity: Severity::Error,
    summary: "Requested capability scope set is not a subset of the model card's allowed_capability_set.",
    help: "Bind under a card whose allowed_capability_set covers the requested scope, or narrow the request.",
    string_code: "CHIO-WEIGHTS-SCOPE-NOT-SUBSET",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-weights", "chio-kernel", "chio-cli"],
};

pub const WEIGHTS_TOOL_BANNED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:weights:tool-banned",
    domain: Domain::Weights,
    severity: Severity::Error,
    summary: "Requested tool intersects the model card's banned_tools.",
    help: "The card explicitly forbids the requested tool. Bind under a card that does not list the tool as banned, or remove the tool from the request.",
    string_code: "CHIO-WEIGHTS-TOOL-BANNED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-weights", "chio-kernel", "chio-cli"],
};

pub const WEIGHTS_CARD_EXPIRED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:weights:card-expired",
    domain: Domain::Weights,
    severity: Severity::Error,
    summary: "Model card expired before the verifier evaluated it.",
    help: "Mint a fresh card; cards bind to issued_at / expires_at and the kernel rejects past expiry.",
    string_code: "CHIO-WEIGHTS-CARD-EXPIRED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-weights", "chio-kernel"],
};

pub const WEIGHTS_BUNDLE_REJECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:weights:bundle-rejected",
    domain: Domain::Weights,
    severity: Severity::Error,
    summary: "Cosign bundle for the model card failed cryptographic verification.",
    help: "Treat the card as untrusted; do not rebind without a fresh, correctly-signed cosign bundle.",
    string_code: "CHIO-WEIGHTS-BUNDLE-REJECTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-weights", "chio-kernel", "chio-cli"],
};

pub const WEIGHTS_SCHEMA_REJECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:weights:schema-rejected",
    domain: Domain::Weights,
    severity: Severity::Error,
    summary: "Model card structural validation failed (bad weights_hash, missing required field, or invalid issued_at / expires_at window).",
    help: "Re-mint the card with a valid v1 schema; check weights_hash is 64 lowercase hex chars and expires_at >= issued_at.",
    string_code: "CHIO-WEIGHTS-SCHEMA-REJECTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-weights"],
};

pub const WEIGHTS_INTERNAL_ENCODING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:weights:internal-encoding",
    domain: Domain::Weights,
    severity: Severity::Fatal,
    summary: "Model card surface failed to canonicalize, encode, or decode an envelope.",
    help: "Treat as an internal error; do not retry until the encoding bug is resolved. No fresh challenge will help.",
    string_code: "CHIO-WEIGHTS-INTERNAL-ENCODING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-weights"],
};

pub static ERROR_CODES: &[ErrorCodeSpec] = &[
    TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED,
    TRANSACTION_PASSPORT_HASH_MISMATCH,
    TRANSACTION_GRAPH_NOT_CLOSED,
    TRANSACTION_GRAPH_CYCLE,
    TRANSACTION_REQUIRED_CLAIM_MISSING,
    TRANSACTION_ARTIFACT_HASH_MISMATCH,
    TRANSACTION_IDENTITY_NOT_BOUND,
    TRANSACTION_AUTHORIZATION_NOT_BOUND,
    TRANSACTION_RECEIPT_UNCHECKPOINTED,
    TRANSACTION_RUNTIME_PROOF_REJECTED,
    TRANSACTION_BUYER_REVIEW_REJECTED,
    TRANSACTION_SETTLEMENT_UNVERIFIED,
    TRANSACTION_DISPUTE_UNBOUND,
    TRANSACTION_TRANSPARENCY_PREVIEW_NOT_ALLOWED,
    CAPABILITY_SCOPE_EXCEEDED,
    CAPABILITY_EXPIRED,
    CAPABILITY_REVOKED,
    CAPABILITY_NOT_YET_VALID,
    CAPABILITY_SUBJECT_MISMATCH,
    CAPABILITY_SIGNATURE_INVALID,
    POLICY_DECISION_DENIED,
    POLICY_COMPILE_FAILED,
    POLICY_CONSTRAINT_INVALID,
    POLICY_GOVERNANCE_DENIED,
    GUARD_DENIED,
    GUARD_INPUT_REDACTED,
    GUARD_OUTPUT_REDACTED,
    GUARD_WASM_TRAP,
    ATTEST_RECEIPT_SIGNING_FAILED,
    ATTEST_QUOTE_VERIFICATION_FAILED,
    ATTEST_PROVENANCE_MISSING,
    REPLAY_TRACE_NOT_FOUND,
    REPLAY_DETERMINISTIC_MISMATCH,
    REPLAY_FIXTURE_DRIFT,
    PROVIDER_TOOL_SERVER_ERROR,
    PROVIDER_OPENAI,
    PROVIDER_ANTHROPIC,
    PROVIDER_BEDROCK,
    MANIFEST_SCHEMA_INVALID,
    MANIFEST_SIGNATURE_INVALID,
    MANIFEST_TOOL_NOT_REGISTERED,
    MANIFEST_RESOURCE_ROOT_DENIED,
    KERNEL_INTERNAL_ERROR,
    KERNEL_SESSION_NOT_INITIALIZED,
    KERNEL_SESSION_ALREADY_EXISTS,
    KERNEL_REQUEST_INCOMPLETE,
    KERNEL_REQUEST_CANCELLED,
    KERNEL_BUDGET_EXHAUSTED,
    TRANSPORT_PROTOCOL_VERSION_UNSUPPORTED,
    TRANSPORT_INVALID_REQUEST_SHAPE,
    TRANSPORT_AUTH_MISSING_OR_INVALID,
    TRANSPORT_HTTP_FAILED,
    TRANSPORT_DPOP_VERIFICATION_FAILED,
    TRANSPORT_UPSTREAM_FAILURE,
    TRANSPORT_METHOD_NOT_FOUND,
    CLI_IO,
    CLI_JSON,
    CLI_YAML,
    CLI_SQLITE,
    CLI_OTHER,
    CLI_DOCTOR_TOOLCHAIN_MISMATCH,
    CLI_DOCTOR_OCI_UNREACHABLE,
    CLI_DOCTOR_COSIGN_STALE,
    CLI_DOCTOR_OTEL_UNRESOLVED,
    CLI_DOCTOR_CHIO_YAML_INVALID,
    CLI_DOCTOR_PROBE_FAILED,
    DELEGATION_CHAIN_REVOKED,
    ADVERSARIAL_ESCAPE_DETECTED,
    THREAT_COVERAGE_GAP,
    ARENA_REPLAY_DIVERGENCE,
    ECONOMY_METERING_UNAVAILABLE,
    LINEAGE_ANCESTOR_MISSING,
    CUSTODY_HARDWARE_KEY_UNAVAILABLE,
    CUSTODY_ASSERTION_REJECTED,
    MOBILE_RECEIPT_POST_REJECTED,
    MOBILE_RECEIPT_SCHEMA_INVALID,
    MOBILE_ORACLE_UNREACHABLE,
    CUSTODY_AUDIENCE_MISMATCH,
    CUSTODY_REPLAY_DETECTED,
    CUSTODY_CAPABILITY_EXPIRED,
    CUSTODY_CREDENTIAL_REVOKED,
    CUSTODY_USER_VERIFICATION_REQUIRED,
    CUSTODY_INTERNAL_ENCODING,
    CUSTODY_RATE_LIMITED,
    CUSTODY_APP_ATTEST_INVALID_CBOR,
    CUSTODY_APP_ATTEST_INVALID_ROOT,
    CUSTODY_APP_ATTEST_APP_MISMATCH,
    CUSTODY_APP_ATTEST_CHALLENGE_MISMATCH,
    CUSTODY_APP_ATTEST_KEY_MISMATCH,
    CUSTODY_APP_ATTEST_CREDENTIAL_KEY_MISMATCH,
    CUSTODY_APP_ATTEST_COUNTER_ROLLBACK,
    CUSTODY_APP_ATTEST_CERT_CHAIN_INVALID,
    CUSTODY_PLAY_INTEGRITY_INVALID_TOKEN,
    CUSTODY_PLAY_INTEGRITY_NONCE_MISMATCH,
    CUSTODY_PLAY_INTEGRITY_APP_REJECTED,
    CUSTODY_PLAY_INTEGRITY_DEVICE_REJECTED,
    WEIGHTS_MODEL_CARD_MISSING,
    WEIGHTS_CARD_MISMATCH,
    WEIGHTS_SCOPE_NOT_SUBSET,
    WEIGHTS_TOOL_BANNED,
    WEIGHTS_CARD_EXPIRED,
    WEIGHTS_BUNDLE_REJECTED,
    WEIGHTS_SCHEMA_REJECTED,
    WEIGHTS_INTERNAL_ENCODING,
];

#[must_use]
pub fn lookup_error_code(urn: &str) -> Option<&'static ErrorCodeSpec> {
    ERROR_CODES.iter().find(|entry| entry.urn == urn)
}

#[must_use]
pub fn lookup_string_code(code: &str) -> Option<&'static ErrorCodeSpec> {
    let mut matches = lookup_string_code_matches(code);
    let first = matches.next()?;
    if matches.next().is_some() {
        None
    } else {
        Some(first)
    }
}

pub fn lookup_string_code_matches(code: &str) -> impl Iterator<Item = &'static ErrorCodeSpec> + '_ {
    ERROR_CODES
        .iter()
        .filter(move |entry| entry.string_code == code)
}

#[must_use]
pub fn lookup_jsonrpc_code(code: i32) -> Option<&'static ErrorCodeSpec> {
    ERROR_CODES
        .iter()
        .find(|entry| entry.jsonrpc_code == Some(code))
}
