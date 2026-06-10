//! Stable re-redaction under the current default redactor set.

use chio_tee::{RawPayloadBuffer, RedactClass, RedactPass, RedactedPayload, RedactionMatch};

use crate::Result;

/// Stable view of a default re-redaction pass.
///
/// The tee redactor manifest includes elapsed timing, which is useful for
/// telemetry but intentionally unstable for fixture blessing. Corpus
/// normalization keeps the redacted bytes, pass identity, and match list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReredactedPayload {
    /// Post-redaction bytes.
    pub bytes: Vec<u8>,
    /// Redactor pass identity used by the current default set.
    pub pass_id: String,
    /// Stable match records emitted by the default redactor.
    pub matches: Vec<RedactionMatch>,
}

impl From<RedactedPayload> for ReredactedPayload {
    fn from(value: RedactedPayload) -> Self {
        Self {
            bytes: value.bytes,
            pass_id: value.manifest.pass_id,
            matches: value.manifest.matches,
        }
    }
}

/// Re-run the current default redactor set over a payload.
///
/// This uses the same default redactor pass surface as the tee path:
/// `RedactPass::with_default()` and `RedactClass::default_full()`.
pub fn reredact_default(payload: &[u8]) -> Result<ReredactedPayload> {
    let pass = RedactPass::with_default();
    let raw = RawPayloadBuffer::from_slice(payload);
    let redacted = pass.redact_or_fail_closed(raw, RedactClass::default_full(), false)?;
    Ok(redacted.into())
}
