//! Shadow-runner orchestrator for the chio-tee sidecar.
//!
//! [`ShadowRunner`] is the glue that turns the crate's primitives (mode
//! lattice, redactor pass, encrypted spool, signed frame type, NDJSON writer)
//! into a working capture pipeline. It implements [`TrafficTap`] so a host
//! kernel boundary can drive it as a passive observer.
//!
//! Per kernel evaluation the runner, in [`TrafficTap::after_kernel`]:
//!
//! 1. Serializes the request and the kernel response to canonical-JSON bytes.
//! 2. Runs each through the mandatory redactor pass, fail-closed: a redactor
//!    error (or the `--paranoid` zero-match refusal) aborts the capture and
//!    surfaces a `tee.redact_failed`-shaped error instead of persisting.
//! 3. Persists the redacted request/response blobs encrypted under the tenant
//!    key and computes the SHA-256 of each redacted blob.
//! 4. Builds a `chio-tee-frame.v1` frame (ULID `event_id`, RFC3339-ms `ts`,
//!    the observed verdict, blob hashes, redaction pass id), signs it with the
//!    tenant Ed25519 key, and appends it to the run's NDJSON capture file.
//!
//! Mode behaviour follows the [`Mode`] lattice:
//!
//! - [`Mode::VerdictOnly`]: capture only; `would_have_blocked` is always
//!   `false`.
//! - [`Mode::Shadow`]: record the divergence; `would_have_blocked` is
//!   `verdict != allow`; the runner never blocks.
//! - [`Mode::Enforce`]: same capture, but a blocking verdict makes
//!   [`TrafficTap::after_kernel`] return `Err` so the host fails closed.
//!
//! ## Decision-replay scope
//!
//! The verdict the runner records is the kernel's own decision, read from the
//! observed [`ChioReceipt`]. A second, fully independent kernel re-evaluation
//! (re-running the guard/policy pipeline TEE-side over a reconstructed
//! evaluation input) is a deeper integration with the kernel decision crate
//! and is intentionally out of this orchestrator: the tap boundary only sees
//! the request and the signed receipt, not the kernel's trust-root, policy, or
//! guard configuration. The capture-redact-sign pipeline here is complete and
//! ships without that coupling.

use std::io::BufRead;
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::message::AgentMessage;
use chio_core::receipt::{body::ChioReceipt, decision::Decision};
use chio_store_sqlite::{SqliteEncryptedBlobStore, TenantId, TenantKey};

use crate::buffer::RawPayloadBuffer;
use crate::capture::{new_event_id, rfc3339_millis, sign_frame, CaptureError, CaptureWriter};
use crate::frame::{FrameInputs, Otel, Provenance, Upstream, UpstreamSystem, Verdict};
use crate::mode::{Mode, MoteState};
use crate::persist::TeeBlobPersistence;
use crate::redact::{RedactClass, RedactError, RedactPass};
use crate::spool::TeeBlobSpool;
use crate::tap::{TapError, TapResult, TrafficTap};

/// Default `tee_id` used when a deployment does not pin one. Satisfies the
/// frame `tee_id` pattern (3..=64 of `[a-z0-9-]`, no leading/trailing dash).
pub const DEFAULT_TEE_ID: &str = "chio-tee-local";

/// Default upstream API-version label stamped on captured frames when the
/// observation point does not carry one.
const DEFAULT_API_VERSION: &str = "unknown";

/// Errors the runner surfaces to the host through the [`TrafficTap`] hooks.
#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    /// A payload could not be serialized to canonical JSON before redaction.
    #[error("canonical serialization failed: {0}")]
    Canonical(String),
    /// The mandatory redactor pass failed closed (`tee.redact_failed`).
    #[error("tee.redact_failed: {0}")]
    RedactFailed(#[from] RedactError),
    /// Encrypted persistence of a redacted blob failed.
    #[error("encrypted persistence failed: {0}")]
    Persist(String),
    /// Frame construction, signing, or NDJSON append failed.
    #[error("capture frame error: {0}")]
    Capture(#[from] CaptureError),
    /// Enforce mode observed a blocking verdict and rejected the call.
    #[error("enforce: kernel verdict {verdict:?} blocked (reason: {reason})")]
    EnforceBlocked {
        /// The blocking verdict captured into the frame.
        verdict: Verdict,
        /// Namespaced deny reason recorded on the frame.
        reason: String,
    },
}

/// Configuration the runner needs that is not derived from observed traffic.
///
/// Not `Clone`: it holds the tenant at-rest [`TenantKey`], which is
/// zeroize-on-drop and deliberately non-cloneable to keep key custody to a
/// single owner.
#[derive(Debug)]
pub struct RunnerConfig {
    /// Stable per-deployment tee identifier (frame `tee_id`).
    pub tee_id: String,
    /// Tenant the captured blobs are encrypted under.
    pub tenant_id: TenantId,
    /// Tenant at-rest encryption key.
    pub tenant_key: TenantKey,
    /// Redaction classes applied to every captured payload.
    pub redact_classes: RedactClass,
    /// Whether the `--paranoid` zero-match heuristic is armed.
    pub paranoid: bool,
}

impl RunnerConfig {
    /// Construct with the default tee id, full default redaction classes, and
    /// the paranoid heuristic disarmed.
    #[must_use]
    pub fn new(tenant_id: TenantId, tenant_key: TenantKey) -> Self {
        Self {
            tee_id: DEFAULT_TEE_ID.to_string(),
            tenant_id,
            tenant_key,
            redact_classes: RedactClass::default_full(),
            paranoid: false,
        }
    }

    /// Override the tee id (must satisfy the frame `tee_id` pattern).
    #[must_use]
    pub fn with_tee_id(mut self, tee_id: impl Into<String>) -> Self {
        self.tee_id = tee_id.into();
        self
    }

    /// Arm the `--paranoid` zero-match redactor heuristic.
    #[must_use]
    pub fn with_paranoid(mut self, paranoid: bool) -> Self {
        self.paranoid = paranoid;
        self
    }
}

/// One observed kernel evaluation fed to the runner ingest path.
///
/// A host kernel boundary serializes each evaluation it observes as one of
/// these envelopes (one canonical-JSON object per NDJSON line) and pipes the
/// stream to the runner. The runner replays the [`TrafficTap`] hooks over each
/// envelope, producing the signed capture frame stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// The request the kernel evaluated.
    pub request: AgentMessage,
    /// The signed receipt the kernel emitted for `request`.
    pub receipt: ChioReceipt,
}

/// Outcome of draining an observation stream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunSummary {
    /// Observations read from the stream.
    pub observed: u64,
    /// Frames appended to the capture file.
    pub captured: u64,
}

/// The shadow-runner orchestrator.
///
/// Owns the resolved mode cell, the redactor pass, the encrypted spool, the
/// tenant signing key, and the NDJSON capture writer. Cloneable handles share
/// the same mode cell and writer so a fan-out of taps observes one run.
pub struct ShadowRunner {
    config: RunnerConfig,
    mode: MoteState,
    redactor: Arc<RedactPass>,
    spool: Arc<TeeBlobSpool>,
    keypair: Arc<Keypair>,
    writer: Arc<CaptureWriter>,
}

impl ShadowRunner {
    /// Build a runner with an in-memory encrypted blob store. Captures are
    /// still persisted as NDJSON to `${runtime_dir}/captures/<run_id>.ndjson`;
    /// only the encrypted blob store is ephemeral. Useful for hermetic tests
    /// and for deployments that treat the redacted blobs as transient.
    pub fn with_in_memory_store(
        config: RunnerConfig,
        mode: Mode,
        keypair: Keypair,
        runtime_dir: &Path,
        run_id: &str,
    ) -> Result<Self, RunnerError> {
        let store = SqliteEncryptedBlobStore::open_in_memory()
            .map_err(|error| RunnerError::Persist(error.to_string()))?;
        Self::from_store(config, mode, keypair, store, runtime_dir, run_id)
    }

    /// Build a runner over a caller-provided encrypted blob store.
    pub fn from_store(
        config: RunnerConfig,
        mode: Mode,
        keypair: Keypair,
        store: SqliteEncryptedBlobStore,
        runtime_dir: &Path,
        run_id: &str,
    ) -> Result<Self, RunnerError> {
        let spool = TeeBlobSpool::new(TeeBlobPersistence::new(store));
        let writer = CaptureWriter::open(runtime_dir, run_id)?;
        Ok(Self {
            config,
            mode: MoteState::new(mode),
            redactor: Arc::new(RedactPass::with_default()),
            spool: Arc::new(spool),
            keypair: Arc::new(keypair),
            writer: Arc::new(writer),
        })
    }

    /// Shared mode cell, so a SIGUSR1 handler can hot-toggle the live mode.
    #[must_use]
    pub fn mode_state(&self) -> MoteState {
        self.mode.clone()
    }

    /// Current resolved mode.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode.current()
    }

    /// Path of the NDJSON capture file this runner appends to.
    #[must_use]
    pub fn capture_path(&self) -> &Path {
        self.writer.path()
    }

    /// Tenant public key bytes, for downstream `tenant_sig` verification.
    #[must_use]
    pub fn tenant_public_key(&self) -> [u8; 32] {
        *self.keypair.public_key().as_bytes()
    }

    /// Drain an NDJSON stream of [`Observation`] envelopes, driving each one
    /// through the [`TrafficTap`] hooks. Blank lines are skipped. Returns the
    /// observed/captured counts.
    ///
    /// Fail-closed: a malformed line, a tap error (redactor failure, persist
    /// failure), or an enforce-mode block aborts the run and returns `Err`.
    /// Frames already appended before the error remain on disk for audit.
    pub fn run<R: BufRead>(&self, reader: R) -> Result<RunSummary, RunnerError> {
        let mut summary = RunSummary::default();
        for line in reader.lines() {
            let line = line.map_err(|error| RunnerError::Canonical(error.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            let observation: Observation = serde_json::from_str(&line)
                .map_err(|error| RunnerError::Canonical(error.to_string()))?;
            summary.observed += 1;
            self.observe(&observation.request, &observation.receipt)?;
            summary.captured += 1;
        }
        Ok(summary)
    }

    /// Drive one observation through the tap hooks (`before_kernel` then
    /// `after_kernel`), surfacing tap errors as [`RunnerError`].
    fn observe(&self, request: &AgentMessage, receipt: &ChioReceipt) -> Result<(), RunnerError> {
        self.before_kernel(request)
            .map_err(|error| RunnerError::Canonical(error.to_string()))?;
        match self.after_kernel(request, receipt) {
            Ok(()) => Ok(()),
            Err(error) => Err(downcast_runner_error(error)),
        }
    }

    /// Redact `bytes` fail-closed and persist nothing; returns the redacted
    /// bytes the caller will both hash and persist.
    fn redact(&self, bytes: Vec<u8>) -> Result<Vec<u8>, RunnerError> {
        let buffer = RawPayloadBuffer::new(bytes);
        let redacted = self.redactor.redact_or_fail_closed(
            buffer,
            self.config.redact_classes,
            self.config.paranoid,
        )?;
        Ok(redacted.bytes)
    }

    /// Run the full capture pipeline for one observed (request, receipt) pair
    /// and return the appended frame's verdict + would-have-blocked flag.
    fn capture(
        &self,
        request: &AgentMessage,
        receipt: &ChioReceipt,
    ) -> Result<CaptureOutcome, RunnerError> {
        let mode = self.mode.current();

        // 1. Canonicalize both halves to bytes. The request half is the tool
        //    invocation (the receipt's evaluated parameters); the response
        //    half is the full signed receipt.
        let invocation_bytes = canonical_json_bytes(&receipt.action.parameters)
            .map_err(|error| RunnerError::Canonical(error.to_string()))?;
        let response_bytes = canonical_json_bytes(receipt)
            .map_err(|error| RunnerError::Canonical(error.to_string()))?;
        // The request envelope is captured separately so the persisted request
        // blob commits the full message, not just its parameters.
        let request_bytes = canonical_json_bytes(request)
            .map_err(|error| RunnerError::Canonical(error.to_string()))?;

        // 2. Mandatory redactor pass (fail-closed). Every payload that lands in
        //    the capture stream is redacted first: the persisted blobs AND the
        //    frame's inline invocation.
        let redacted_invocation_bytes = self.redact(invocation_bytes)?;
        let redacted_request = self.redact(request_bytes)?;
        let redacted_response = self.redact(response_bytes)?;

        // The redactor replaces matched substrings with bracketed tokens that
        // stay valid inside JSON string values, so the redacted invocation
        // re-parses as a JSON value for the inline `invocation` field. If it
        // somehow does not, fail closed rather than emit a plaintext fallback.
        let redacted_invocation: serde_json::Value =
            serde_json::from_slice(&redacted_invocation_bytes)
                .map_err(|error| RunnerError::Canonical(error.to_string()))?;

        // 3. Persist redacted blobs encrypted, then hash the redacted bytes.
        self.spool
            .persist_traffic(
                &self.config.tenant_id,
                &self.config.tenant_key,
                &redacted_request,
                &redacted_response,
            )
            .map_err(|error| RunnerError::Persist(error.to_string()))?;
        let request_blob_sha256 = sha256_hex(&redacted_request);
        let response_blob_sha256 = sha256_hex(&redacted_response);

        // 4. Derive the verdict from the kernel's observed decision and apply
        //    mode semantics.
        let (verdict, deny_reason) = verdict_from_decision(receipt.decision.as_ref());
        let would_have_blocked = match mode {
            Mode::VerdictOnly => false,
            Mode::Shadow | Mode::Enforce => !matches!(verdict, Verdict::Allow),
        };

        // 5. Build, sign, and append the frame.
        let unix_millis = receipt.timestamp.saturating_mul(1000);
        let inputs = FrameInputs {
            event_id: new_event_id(unix_millis),
            ts: rfc3339_millis(unix_millis),
            tee_id: self.config.tee_id.clone(),
            upstream: self.upstream_for(receipt),
            invocation: redacted_invocation,
            provenance: Provenance {
                otel: Otel {
                    trace_id: "0".repeat(32),
                    span_id: "0".repeat(16),
                },
                supply_chain: None,
            },
            request_blob_sha256,
            response_blob_sha256,
            redaction_pass_id: crate::DEFAULT_REDACTION_PASS_ID.to_string(),
            verdict,
            deny_reason: deny_reason.clone(),
            would_have_blocked,
            tenant_sig: String::new(),
        };
        let frame = sign_frame(inputs, &self.keypair)?;
        self.writer.append(&frame)?;

        Ok(CaptureOutcome {
            mode,
            verdict,
            would_have_blocked,
            deny_reason,
        })
    }

    /// Derive the frame upstream descriptor from the observed receipt. The tee
    /// is upstream-agnostic at the kernel boundary, so the receipt's tool
    /// server/name populate an `mcp` tool-call descriptor; the operation is
    /// normalized to the frame pattern.
    fn upstream_for(&self, receipt: &ChioReceipt) -> Upstream {
        Upstream {
            system: UpstreamSystem::Mcp,
            operation: normalize_operation(&receipt.tool_name),
            api_version: DEFAULT_API_VERSION.to_string(),
        }
    }
}

impl std::fmt::Debug for ShadowRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowRunner")
            .field("tee_id", &self.config.tee_id)
            .field("mode", &self.mode.current())
            .field("capture_path", &self.writer.path())
            .finish()
    }
}

impl TrafficTap for ShadowRunner {
    fn before_kernel(&self, request: &AgentMessage) -> TapResult {
        // Validate the request is canonicalizable before the kernel runs, so a
        // malformed request fails closed at the boundary rather than after the
        // kernel has acted. The captured frame itself is emitted in
        // `after_kernel` once both halves are observed.
        canonical_json_bytes(request)
            .map(|_| ())
            .map_err(|error| -> TapError { Box::new(RunnerError::Canonical(error.to_string())) })
    }

    fn after_kernel(&self, request: &AgentMessage, receipt: &ChioReceipt) -> TapResult {
        let outcome = self
            .capture(request, receipt)
            .map_err(|e| -> TapError { Box::new(e) })?;
        // Enforce mode rejects on a blocking verdict (fail-closed). The frame
        // is already persisted above so the rejection is auditable.
        if matches!(outcome.mode, Mode::Enforce) && outcome.would_have_blocked {
            return Err(Box::new(RunnerError::EnforceBlocked {
                verdict: outcome.verdict,
                reason: outcome
                    .deny_reason
                    .unwrap_or_else(|| "guard:tee.enforce_divergence".to_string()),
            }) as TapError);
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "chio-tee-shadow-runner"
    }
}

/// Recover the concrete [`RunnerError`] from a boxed [`TapError`] produced by
/// [`ShadowRunner`]'s own tap hooks. The runner only ever boxes a
/// `RunnerError`, so the downcast succeeds; the fallback keeps the function
/// total by wrapping any other error text.
fn downcast_runner_error(error: TapError) -> RunnerError {
    match error.downcast::<RunnerError>() {
        Ok(runner_error) => *runner_error,
        Err(other) => RunnerError::Canonical(other.to_string()),
    }
}

/// Result of one capture, used to drive enforce-mode rejection.
struct CaptureOutcome {
    mode: Mode,
    verdict: Verdict,
    would_have_blocked: bool,
    deny_reason: Option<String>,
}

/// Map a kernel [`Decision`] onto a frame [`Verdict`] plus an optional
/// namespaced deny reason. Absent decisions (trace/advisory receipts) are
/// treated as allow; the deny-reason gate requires `None` for allow.
fn verdict_from_decision(decision: Option<&Decision>) -> (Verdict, Option<String>) {
    match decision {
        None | Some(Decision::Allow) => (Verdict::Allow, None),
        Some(Decision::Deny { guard, .. }) => (Verdict::Deny, Some(normalize_deny_reason(guard))),
        Some(Decision::Cancelled { .. }) => {
            (Verdict::Deny, Some("guard:tee.cancelled".to_string()))
        }
        Some(Decision::Incomplete { .. }) => {
            (Verdict::Deny, Some("guard:tee.incomplete".to_string()))
        }
    }
}

/// Coerce a guard label into the frame `deny_reason` pattern
/// (`^[a-z][a-z0-9_]*(:[a-z][a-z0-9_.]*)*$`). Non-conforming labels collapse to
/// a stable `guard:tee.denied` so the frame always validates.
fn normalize_deny_reason(guard: &str) -> String {
    let cleaned = sanitize_identifier(guard);
    if cleaned.is_empty() {
        "guard:tee.denied".to_string()
    } else {
        format!("guard:{cleaned}")
    }
}

/// Coerce a tool name into the frame upstream `operation` pattern
/// (`^[a-z][a-z0-9_.]*$`). Empty/non-conforming names collapse to
/// `tool.call`.
fn normalize_operation(tool_name: &str) -> String {
    let cleaned = sanitize_identifier(tool_name);
    if cleaned.is_empty() {
        "tool.call".to_string()
    } else {
        cleaned
    }
}

/// Lowercase, replace any character outside `[a-z0-9_.]` with `_`, and trim to
/// a leading lowercase letter so the result fits the namespaced-identifier
/// patterns the frame schema enforces.
fn sanitize_identifier(input: &str) -> String {
    let lowered: String = input
        .chars()
        .map(|c| {
            let lc = c.to_ascii_lowercase();
            if lc.is_ascii_lowercase() || lc.is_ascii_digit() || lc == '_' || lc == '.' {
                lc
            } else {
                '_'
            }
        })
        .collect();
    // The pattern requires a leading [a-z]; strip any leading non-letters.
    let trimmed = lowered.trim_start_matches(|c: char| !c.is_ascii_lowercase());
    let mut out = trimmed.to_string();
    out.truncate(120);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    use chio_core::canonical::canonical_json_string;
    use chio_core::capability::{
        scope::ChioScope,
        token::{CapabilityToken, CapabilityTokenBody},
    };
    use chio_core::receipt::{body::ChioReceiptBody, decision::ToolCallAction, kinds::TrustLevel};

    fn keypair() -> Keypair {
        Keypair::from_seed(&[42u8; 32])
    }

    fn capability(kp: &Keypair, id: &str) -> CapabilityToken {
        let body = CapabilityTokenBody {
            id: format!("cap-{id}"),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: ChioScope::default(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        };
        CapabilityToken::sign(body, kp).test_expect("sign capability")
    }

    fn request(kp: &Keypair, id: &str, params: serde_json::Value) -> AgentMessage {
        AgentMessage::ToolCallRequest {
            id: id.to_string(),
            capability_token: Box::new(capability(kp, id)),
            server_id: "srv-1".to_string(),
            tool: "send_email".to_string(),
            params: Box::new(params),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
        }
    }

    fn receipt(
        kp: &Keypair,
        id: &str,
        params: serde_json::Value,
        decision: Decision,
    ) -> ChioReceipt {
        let canonical = canonical_json_string(&params).test_expect("canonical params");
        let parameter_hash = sha256_hex(canonical.as_bytes());
        let action = ToolCallAction {
            parameters: params,
            parameter_hash: parameter_hash.clone(),
        };
        let body = ChioReceiptBody {
            id: format!("rcpt-{id}"),
            timestamp: 1_745_603_731,
            capability_id: format!("cap-{id}"),
            tool_server: "srv-1".to_string(),
            tool_name: "send_email".to_string(),
            action,
            decision: Some(decision),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: parameter_hash,
            policy_hash: "0".repeat(64),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp.public_key(),
            bbs_projection_version: None,
        };
        ChioReceipt::sign(body, kp).test_expect("sign receipt")
    }

    fn config() -> RunnerConfig {
        RunnerConfig::new(
            TenantId::new("tenant-runner-test"),
            TenantKey::from_bytes([9u8; 32]),
        )
        .with_tee_id("tee-runner-test")
    }

    #[test]
    fn verdict_only_capture_writes_allow_frame() {
        let dir = tempfile::tempdir().test_unwrap();
        let runner = ShadowRunner::with_in_memory_store(
            config(),
            Mode::VerdictOnly,
            keypair(),
            dir.path(),
            "run-vo",
        )
        .test_unwrap();
        let kp = keypair();
        let params = serde_json::json!({"to": "alice@example.com"});
        let req = request(&kp, "r1", params.clone());
        let rcpt = receipt(&kp, "r1", params, Decision::Allow);

        runner.before_kernel(&req).test_expect("before ok");
        runner.after_kernel(&req, &rcpt).test_expect("after ok");

        let body = std::fs::read_to_string(runner.capture_path()).test_unwrap();
        let frame: crate::frame::Frame =
            serde_json::from_str(body.lines().next().test_unwrap()).test_unwrap();
        assert!(matches!(frame.verdict, Verdict::Allow));
        assert!(!frame.would_have_blocked);
        // The redactor stripped the email out of the persisted invocation
        // hash path; the frame never carries plaintext payload bytes.
        assert!(!body.contains("alice@example.com"));
    }

    #[test]
    fn shadow_mode_sets_would_have_blocked_on_deny() {
        let dir = tempfile::tempdir().test_unwrap();
        let runner = ShadowRunner::with_in_memory_store(
            config(),
            Mode::Shadow,
            keypair(),
            dir.path(),
            "run-shadow",
        )
        .test_unwrap();
        let kp = keypair();
        let params = serde_json::json!({"cmd": "rm -rf /"});
        let req = request(&kp, "r2", params.clone());
        let rcpt = receipt(
            &kp,
            "r2",
            params,
            Decision::Deny {
                reason: "blocked by policy".to_string(),
                guard: "fs.write".to_string(),
            },
        );

        // Shadow mode records divergence but never blocks.
        runner
            .after_kernel(&req, &rcpt)
            .test_expect("shadow never blocks");

        let body = std::fs::read_to_string(runner.capture_path()).test_unwrap();
        let frame: crate::frame::Frame =
            serde_json::from_str(body.lines().next().test_unwrap()).test_unwrap();
        assert!(matches!(frame.verdict, Verdict::Deny));
        assert!(frame.would_have_blocked);
        assert_eq!(frame.deny_reason.as_deref(), Some("guard:fs.write"));
    }

    #[test]
    fn enforce_mode_rejects_blocking_verdict() {
        let dir = tempfile::tempdir().test_unwrap();
        let runner = ShadowRunner::with_in_memory_store(
            config(),
            Mode::Enforce,
            keypair(),
            dir.path(),
            "run-enforce",
        )
        .test_unwrap();
        let kp = keypair();
        let params = serde_json::json!({"cmd": "exfiltrate"});
        let req = request(&kp, "r3", params.clone());
        let rcpt = receipt(
            &kp,
            "r3",
            params,
            Decision::Deny {
                reason: "blocked".to_string(),
                guard: "egress".to_string(),
            },
        );

        let err = runner.after_kernel(&req, &rcpt).test_unwrap_err();
        assert!(err.to_string().contains("enforce"));
        // The frame is still persisted for audit despite the rejection.
        let body = std::fs::read_to_string(runner.capture_path()).test_unwrap();
        assert_eq!(body.lines().count(), 1);
    }

    #[test]
    fn enforce_mode_allows_clean_verdict() {
        let dir = tempfile::tempdir().test_unwrap();
        let runner = ShadowRunner::with_in_memory_store(
            config(),
            Mode::Enforce,
            keypair(),
            dir.path(),
            "run-enforce-ok",
        )
        .test_unwrap();
        let kp = keypair();
        let params = serde_json::json!({"to": "ops@example.com"});
        let req = request(&kp, "r4", params.clone());
        let rcpt = receipt(&kp, "r4", params, Decision::Allow);
        runner
            .after_kernel(&req, &rcpt)
            .test_expect("clean allow passes enforce");
    }

    #[test]
    fn frames_verify_under_tenant_public_key() {
        let dir = tempfile::tempdir().test_unwrap();
        let runner = ShadowRunner::with_in_memory_store(
            config(),
            Mode::Shadow,
            keypair(),
            dir.path(),
            "run-verify",
        )
        .test_unwrap();
        let kp = keypair();
        let params = serde_json::json!({"q": "select 1"});
        let req = request(&kp, "r5", params.clone());
        let rcpt = receipt(&kp, "r5", params, Decision::Allow);
        runner.after_kernel(&req, &rcpt).test_expect("capture ok");

        let pubkey = runner.tenant_public_key();
        let body = std::fs::read_to_string(runner.capture_path()).test_unwrap();
        for line in body.lines().filter(|l| !l.trim().is_empty()) {
            let frame: crate::frame::Frame = serde_json::from_str(line).test_unwrap();
            crate::frame::validate_signed(&frame, &pubkey).test_expect("frame verifies");
        }
    }

    #[test]
    fn sanitize_identifier_enforces_leading_letter() {
        assert_eq!(sanitize_identifier("Send-Email"), "send_email");
        assert_eq!(sanitize_identifier("123abc"), "abc");
        assert_eq!(normalize_operation(""), "tool.call");
        assert_eq!(normalize_deny_reason("!!!"), "guard:tee.denied");
    }
}
