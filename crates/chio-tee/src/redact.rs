//! Mandatory M06 redactor pass for the tee shadow runner (M10 Phase 1
//! Task 6).
//!
//! The trajectory doc (`.planning/trajectory/10-tee-replay-harness.md`)
//! pins three normative behaviours wired by this module:
//!
//! 1. Every captured payload runs through the `chio:guards/redact@0.1.0`
//!    host call before any frame is buffered (line 21, line 235).
//! 2. The pass is fail-closed: an `Err(_)` from the redactor MUST cause
//!    the tee to refuse persistence and write `tee.redact_failed` to
//!    the receipt log (line 452).
//! 3. Under `--paranoid`, frames whose manifest reports zero matches on
//!    a payload longer than 256 bytes are quarantined as a defensive
//!    heuristic against a misconfigured redactor (line 21, line 566).
//!
//! The wasm host-call wiring (calling into the actual wasm guest via
//! wasmtime) is deferred. T6 wires the **native-Rust placeholder**
//! redactor from `chio-data-guards/redactors/default/` so the M10
//! pipeline integrates fail-closed semantics today; the wasm bridge is
//! mechanical because the native types mirror the WIT records 1:1
//! (default redactor crate docs).

use chio_data_guards_redactors_default::{
    redact_payload as default_redact_payload, RedactClass as DefaultRedactClass,
    RedactedPayload as DefaultRedactedPayload, RedactionManifest as DefaultRedactionManifest,
    RedactionMatch as DefaultRedactionMatch,
};

use crate::buffer::RawPayloadBuffer;

/// Re-export of the default-redactor classes as the canonical tee class
/// type. Mirrors WIT `redact-class`.
pub type RedactClass = DefaultRedactClass;

/// Re-export of the default-redactor manifest match record. Mirrors WIT
/// `redaction-match`.
pub type RedactionMatch = DefaultRedactionMatch;

/// Re-export of the default-redactor manifest. Mirrors WIT
/// `redaction-manifest`.
pub type RedactionManifest = DefaultRedactionManifest;

/// Re-export of the default-redactor output. Mirrors WIT
/// `redacted-payload`.
pub type RedactedPayload = DefaultRedactedPayload;

/// Threshold above which a zero-match manifest under `--paranoid` is
/// treated as redactor misconfiguration. Sourced from the trajectory
/// doc line 21 (>256 bytes).
pub const PARANOID_ZERO_MATCH_THRESHOLD: usize = 256;

/// Trait abstracting the redactor surface so the tee can run against
/// the in-process default crate today and a wasmtime-hosted guest in
/// the future without churn at the call site.
///
/// Implementations MUST keep fail-closed semantics: an `Err(_)` MUST
/// indicate the redactor pass failed and that persistence MUST be
/// refused.
pub trait Redactor: Send + Sync {
    /// Apply the redactor to `payload` under the requested classes.
    fn redact_payload(
        &self,
        payload: &[u8],
        classes: RedactClass,
    ) -> Result<RedactedPayload, RedactorError>;
}

/// Error type a [`Redactor`] returns to the tee.
#[derive(Debug, thiserror::Error)]
pub enum RedactorError {
    /// The redactor refused or failed mid-pass. Tee MUST write
    /// `tee.redact_failed` to the receipt log and refuse persistence.
    #[error("redactor pass failed: {0}")]
    Failed(String),
}

/// In-process [`Redactor`] backed by the default-redactor crate.
///
/// This is the placeholder while the wasm host-call wiring is deferred
/// (see module-level docs). Production deployments will swap this for
/// a wasmtime-driven implementation; the [`RedactPass`] code path is
/// trait-objected so the swap is mechanical.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultRedactor;

impl Redactor for DefaultRedactor {
    fn redact_payload(
        &self,
        payload: &[u8],
        classes: RedactClass,
    ) -> Result<RedactedPayload, RedactorError> {
        default_redact_payload(payload, classes)
            .map_err(|err| RedactorError::Failed(err.to_string()))
    }
}

/// Mandatory redactor pass driver.
///
/// Holds a single `Box<dyn Redactor>` so the tee can swap the backing
/// implementation (default crate today, wasmtime-hosted guest later)
/// without touching call sites.
pub struct RedactPass {
    redactor: Box<dyn Redactor>,
}

impl RedactPass {
    /// Construct from any [`Redactor`] implementation.
    #[must_use]
    pub fn new(redactor: Box<dyn Redactor>) -> Self {
        Self { redactor }
    }

    /// Construct using the in-process default-redactor crate. Equivalent
    /// to `RedactPass::new(Box::new(DefaultRedactor))`.
    #[must_use]
    pub fn with_default() -> Self {
        Self::new(Box::new(DefaultRedactor))
    }

    /// Run the redactor with fail-closed semantics.
    ///
    /// On `Err(_)` from the redactor: returns
    /// [`RedactError::FailClosed`]. The caller MUST write
    /// `tee.redact_failed` to the receipt log and refuse persistence
    /// (trajectory doc line 452).
    ///
    /// On `Ok(_)` with a zero-match manifest, payload length > 256
    /// bytes, and `paranoid == true`: returns
    /// [`RedactError::ParanoidRefusal`] (trajectory doc line 21).
    ///
    /// On `Ok(_)` otherwise: returns the [`RedactedPayload`].
    ///
    /// The plaintext [`RawPayloadBuffer`] is consumed by value and
    /// dropped (zeroized) before this function returns; the redacted
    /// payload is a separate `Vec<u8>` containing only the redactor's
    /// output, which has already had secrets stripped.
    pub fn redact_or_fail_closed(
        &self,
        payload: RawPayloadBuffer,
        classes: RedactClass,
        paranoid: bool,
    ) -> Result<RedactedPayload, RedactError> {
        // Capture length up front; we drop the buffer before returning.
        let payload_len = payload.len();

        // Run the redactor against the borrowed plaintext bytes. The
        // redactor returns an owned, redacted Vec<u8>; we never expose
        // the plaintext past this scope.
        let redacted = self
            .redactor
            .redact_payload(payload.as_slice(), classes)
            .map_err(|err| RedactError::FailClosed(err.to_string()))?;

        // Drop the plaintext buffer explicitly. This is also what would
        // happen at end-of-scope, but the explicit drop documents the
        // zeroize handoff and means subsequent code in this function
        // can NEVER touch plaintext again.
        drop(payload);

        if paranoid
            && redacted.manifest.matches.is_empty()
            && payload_len > PARANOID_ZERO_MATCH_THRESHOLD
        {
            return Err(RedactError::ParanoidRefusal {
                payload_len,
                threshold: PARANOID_ZERO_MATCH_THRESHOLD,
            });
        }

        Ok(redacted)
    }
}

impl std::fmt::Debug for RedactPass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedactPass")
            .field("redactor", &"<dyn Redactor>")
            .finish()
    }
}

/// Failure modes the tee surfaces from [`RedactPass::redact_or_fail_closed`].
///
/// Both variants are fail-closed: the caller MUST refuse persistence and
/// write a `tee.redact_failed` event to the receipt log. They differ
/// only in audit framing; [`RedactError::FailClosed`] reflects an actual
/// redactor error, while [`RedactError::ParanoidRefusal`] reflects the
/// `--paranoid` heuristic refusing a suspiciously empty manifest.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RedactError {
    /// Redactor returned an error. Tee MUST refuse persistence and
    /// emit `tee.redact_failed`.
    #[error("redactor pass failed (fail-closed): {0}")]
    FailClosed(String),

    /// Paranoid heuristic refused: zero matches on a payload larger
    /// than the threshold.
    #[error(
        "paranoid refusal: zero redaction matches on {payload_len}-byte payload \
         (threshold {threshold})"
    )]
    ParanoidRefusal {
        /// Length of the plaintext payload, captured before the buffer
        /// was zeroized.
        payload_len: usize,
        /// Threshold the heuristic enforces (256 bytes by default).
        threshold: usize,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_pass_returns_redacted_bytes() {
        let pass = RedactPass::with_default();
        let payload =
            RawPayloadBuffer::from_slice(b"contact alice@example.com for the receipt please");
        let out = pass
            .redact_or_fail_closed(payload, RedactClass::default_full(), false)
            .unwrap();
        let body = String::from_utf8(out.bytes).unwrap();
        assert!(body.contains("[REDACTED-EMAIL]"));
        assert!(!body.contains("alice@example.com"));
    }

    #[test]
    fn paranoid_does_not_trip_when_matches_present() {
        let pass = RedactPass::with_default();
        // Payload >256 bytes but contains an email so the manifest is
        // non-empty: paranoid heuristic must NOT refuse.
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(b"alice@example.com ");
        bytes.extend(std::iter::repeat_n(b'.', 300));
        let payload = RawPayloadBuffer::new(bytes);
        let out = pass
            .redact_or_fail_closed(payload, RedactClass::default_full(), true)
            .unwrap();
        assert!(!out.manifest.matches.is_empty());
    }
}
