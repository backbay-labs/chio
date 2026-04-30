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
    pub legacy_string_code: &'static str,
    pub jsonrpc_code: Option<i32>,
    pub since: &'static str,
    pub stability: &'static str,
    pub consumed_by: &'static [&'static str],
}

pub const REGISTRY_SCHEMA: &str = "chio.error-urn-registry.v1";
pub const REGISTRY_VERSION: &str = "0.1.0";
pub const REGISTRY_UPDATED_AT: &str = "2026-04-29";

pub const CAPABILITY_SCOPE_EXCEEDED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:capability:scope-exceeded",
    domain: Domain::Capability,
    severity: Severity::Error,
    summary: "Capability scope does not allow the requested tool, resource, or prompt.",
    help: "Issue a capability that explicitly grants the requested scope, or change the request to fit the granted scope.",
    legacy_string_code: "CHIO-KERNEL-OUT-OF-SCOPE-TOOL",
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
    legacy_string_code: "CHIO-KERNEL-CAPABILITY-EXPIRED",
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
    legacy_string_code: "CHIO-KERNEL-CAPABILITY-REVOKED",
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
    legacy_string_code: "CHIO-KERNEL-CAPABILITY-NOT-YET-VALID",
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
    legacy_string_code: "CHIO-KERNEL-SUBJECT-MISMATCH",
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
    legacy_string_code: "CHIO-KERNEL-INVALID-SIGNATURE",
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
    legacy_string_code: "CHIO-CLI-POLICY",
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
    legacy_string_code: "CHIO-CLI-POLICY",
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
    legacy_string_code: "CHIO-KERNEL-INVALID-CONSTRAINT",
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
    legacy_string_code: "CHIO-KERNEL-GOVERNED-TRANSACTION-DENIED",
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
    legacy_string_code: "CHIO-KERNEL-GUARD-DENIED",
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
    legacy_string_code: "CHIO-GUARD-INPUT-REDACTED",
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
    legacy_string_code: "CHIO-GUARD-OUTPUT-REDACTED",
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
    legacy_string_code: "CHIO-GUARD-WASM-TRAP",
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
    legacy_string_code: "CHIO-KERNEL-RECEIPT-SIGNING-FAILED",
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
    legacy_string_code: "CHIO-ATTEST-QUOTE-VERIFICATION-FAILED",
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
    legacy_string_code: "CHIO-ATTEST-PROVENANCE-MISSING",
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
    legacy_string_code: "CHIO-REPLAY-TRACE-NOT-FOUND",
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
    legacy_string_code: "CHIO-REPLAY-DETERMINISTIC-MISMATCH",
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
    legacy_string_code: "CHIO-REPLAY-FIXTURE-DRIFT",
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
    legacy_string_code: "CHIO-KERNEL-TOOL-SERVER",
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
    legacy_string_code: "CHIO-PROVIDER-OPENAI",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-openai-adapter", "chio-provider-conformance"],
};

pub const PROVIDER_ANTHROPIC: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:provider:anthropic",
    domain: Domain::Provider,
    severity: Severity::Error,
    summary: "Anthropic provider adapter returned a normalized provider error.",
    help: "Inspect the provider error details and retry only when the adapter marks the failure transient.",
    legacy_string_code: "CHIO-PROVIDER-ANTHROPIC",
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
    legacy_string_code: "CHIO-PROVIDER-BEDROCK",
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
    legacy_string_code: "CHIO-CLI-YAML",
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
    legacy_string_code: "CHIO-MANIFEST-SIGNATURE-INVALID",
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
    legacy_string_code: "CHIO-KERNEL-TOOL-NOT-REGISTERED",
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
    legacy_string_code: "CHIO-KERNEL-RESOURCE-ROOT-DENIED",
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
    legacy_string_code: "CHIO-KERNEL-INTERNAL",
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
    legacy_string_code: "CHIO-KERNEL-UNKNOWN-SESSION",
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
    legacy_string_code: "CHIO-KERNEL-SESSION-ALREADY-EXISTS",
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
    legacy_string_code: "CHIO-KERNEL-REQUEST-INCOMPLETE",
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
    legacy_string_code: "CHIO-KERNEL-REQUEST-CANCELLED",
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
    legacy_string_code: "CHIO-KERNEL-BUDGET-EXHAUSTED",
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
    legacy_string_code: "CHIO-CLI-TRANSPORT",
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
    legacy_string_code: "CHIO-CLI-JSON",
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
    legacy_string_code: "CHIO-CLI-CREDENTIAL",
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
    legacy_string_code: "CHIO-CLI-HTTP",
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
    legacy_string_code: "CHIO-KERNEL-DPOP-VERIFICATION-FAILED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-http-core"],
};

pub const CLI_IO: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:io",
    domain: Domain::Cli,
    severity: Severity::Error,
    summary: "CLI failed while reading or writing local data.",
    help: "Check the path, permissions, and filesystem state before retrying.",
    legacy_string_code: "CHIO-CLI-IO",
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
    legacy_string_code: "CHIO-CLI-JSON",
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
    legacy_string_code: "CHIO-CLI-YAML",
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
    legacy_string_code: "CHIO-CLI-SQLITE",
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
    legacy_string_code: "CHIO-CLI-OTHER",
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
    legacy_string_code: "CHIO-CLI-DOCTOR-TOOLCHAIN-MISMATCH",
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
    legacy_string_code: "CHIO-CLI-DOCTOR-OCI-UNREACHABLE",
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
    legacy_string_code: "CHIO-CLI-DOCTOR-COSIGN-STALE",
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
    legacy_string_code: "CHIO-CLI-DOCTOR-OTEL-UNRESOLVED",
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
    legacy_string_code: "CHIO-CLI-DOCTOR-CHIO-YAML-INVALID",
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
    legacy_string_code: "CHIO-CLI-DOCTOR-PROBE-FAILED",
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
    legacy_string_code: "CHIO-KERNEL-DELEGATION-CHAIN-REVOKED",
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
    legacy_string_code: "CHIO-ADVERSARIAL-ESCAPE-DETECTED",
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
    legacy_string_code: "CHIO-THREAT-COVERAGE-GAP",
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
    legacy_string_code: "CHIO-ARENA-REPLAY-DIVERGENCE",
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
    legacy_string_code: "CHIO-ECONOMY-METERING-UNAVAILABLE",
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
    legacy_string_code: "CHIO-LINEAGE-ANCESTOR-MISSING",
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
    legacy_string_code: "CHIO-CUSTODY-HARDWARE-KEY-UNAVAILABLE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-tee", "chio-attest-verify"],
};

pub const WEIGHTS_MODEL_CARD_MISSING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:weights:model-card-missing",
    domain: Domain::Weights,
    severity: Severity::Error,
    summary: "Model weights or runtime artifact lacks a required model card.",
    help: "Attach the signed model card and verify its hash before running the workload.",
    legacy_string_code: "CHIO-WEIGHTS-MODEL-CARD-MISSING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-tee-frame", "chio-attest-verify"],
};

pub static ERROR_CODES: &[ErrorCodeSpec] = &[
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
    WEIGHTS_MODEL_CARD_MISSING,
];

#[must_use]
pub fn lookup_error_code(urn: &str) -> Option<&'static ErrorCodeSpec> {
    ERROR_CODES.iter().find(|entry| entry.urn == urn)
}

#[must_use]
pub fn lookup_legacy_string_code(code: &str) -> Option<&'static ErrorCodeSpec> {
    ERROR_CODES
        .iter()
        .find(|entry| entry.legacy_string_code == code)
}

#[must_use]
pub fn lookup_jsonrpc_code(code: i32) -> Option<&'static ErrorCodeSpec> {
    ERROR_CODES
        .iter()
        .find(|entry| entry.jsonrpc_code == Some(code))
}
