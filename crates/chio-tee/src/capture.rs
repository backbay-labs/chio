//! Capture-frame construction and the append-only NDJSON capture writer.
//!
//! The shadow runner emits one signed `chio-tee-frame.v1` record per kernel
//! evaluation. This module owns the three pieces the runner needs to produce
//! that stream:
//!
//! 1. [`new_event_id`]: a 26-char Crockford base32 ULID for the frame
//!    `event_id` (48-bit millisecond timestamp prefix + 80 bits of entropy).
//! 2. [`rfc3339_millis`]: an RFC3339 UTC timestamp with millisecond precision
//!    and a trailing `Z`, matching the frame `ts` pattern.
//! 3. [`sign_frame`]: fills `tenant_sig` with `ed25519:<base64>` over the
//!    canonical JSON of every other field, exactly as
//!    [`chio_tee_frame::verify_tenant_sig`] re-derives it.
//! 4. [`CaptureWriter`]: an append-only writer that serializes each signed
//!    frame as a single canonical-JSON line under
//!    `${runtime_dir}/captures/<run_id>.ndjson`. This is the stream the
//!    `chio replay --bless` consumer reads back.
//!
//! The output format is pinned by the existing consumer
//! (`crates/chio-cli/src/cli/replay/ndjson.rs`): one `serde_json` frame per
//! line, blank lines tolerated, every non-blank line a valid frame.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine;
use chio_core::crypto::Keypair;

use crate::frame::{canonicalize, signing_payload, Frame, FrameError, FrameInputs};

/// Crockford base32 uppercase alphabet (ULID encoding). Excludes I, L, O, U.
const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Errors surfaced when building or writing capture frames.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// Frame construction, signing payload, or canonicalization failed.
    #[error("frame error: {0}")]
    Frame(#[from] FrameError),
    /// Signing payload derivation failed before the signature could be
    /// computed.
    #[error("signing payload error: {0}")]
    SigningPayload(String),
    /// Filesystem error creating the captures directory or appending a line.
    #[error("io error writing capture {path}: {source}")]
    Io {
        /// Path being written.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Generate a 26-char Crockford base32 ULID.
///
/// The first 48 bits encode `unix_millis` (lexicographically sortable); the
/// remaining 80 bits are filled from a fresh [`Keypair`] seed, which draws
/// from the platform CSPRNG. Using the keypair seed avoids taking a direct
/// `rand`/`getrandom` dependency: the same OS entropy source the signing keys
/// use produces the ULID entropy.
#[must_use]
pub fn new_event_id(unix_millis: u64) -> String {
    let mut entropy = [0u8; 10];
    // The keypair seed is 32 CSPRNG bytes; the low 10 are the ULID entropy.
    let seed = Keypair::generate().seed_hex();
    let seed_bytes = decode_seed_low_bytes(&seed);
    entropy.copy_from_slice(&seed_bytes);
    encode_ulid(unix_millis & 0x0000_FFFF_FFFF_FFFF, entropy)
}

/// Decode the low 10 bytes of a 64-char hex seed. The seed always decodes to
/// 32 bytes, so this never falls back; the explicit zero-fill keeps the
/// function total without an `unwrap`.
fn decode_seed_low_bytes(seed_hex: &str) -> [u8; 10] {
    let mut out = [0u8; 10];
    let bytes = seed_hex.as_bytes();
    // Each byte is two hex chars. Take the final 20 hex chars (10 bytes).
    let start = bytes.len().saturating_sub(20);
    let tail = &bytes[start..];
    for (i, chunk) in tail.chunks(2).enumerate() {
        if i >= out.len() {
            break;
        }
        let hi = hex_val(chunk.first().copied().unwrap_or(b'0'));
        let lo = hex_val(chunk.get(1).copied().unwrap_or(b'0'));
        out[i] = (hi << 4) | lo;
    }
    out
}

fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// Encode a 48-bit timestamp + 80-bit entropy into a 26-char Crockford ULID.
fn encode_ulid(unix_millis: u64, entropy: [u8; 10]) -> String {
    // Assemble the 128-bit value as 16 bytes: 6 timestamp bytes (big-endian)
    // followed by 10 entropy bytes.
    let mut bytes = [0u8; 16];
    bytes[0] = ((unix_millis >> 40) & 0xff) as u8;
    bytes[1] = ((unix_millis >> 32) & 0xff) as u8;
    bytes[2] = ((unix_millis >> 24) & 0xff) as u8;
    bytes[3] = ((unix_millis >> 16) & 0xff) as u8;
    bytes[4] = ((unix_millis >> 8) & 0xff) as u8;
    bytes[5] = (unix_millis & 0xff) as u8;
    bytes[6..16].copy_from_slice(&entropy);

    // 128 bits encode as 26 base32 chars: the first char carries only 2 bits
    // (the top 6 bits are always zero for a valid ULID), the rest carry 5.
    let mut out = [0u8; 26];
    out[0] = CROCKFORD_ALPHABET[((bytes[0] & 0xe0) >> 5) as usize];
    out[1] = CROCKFORD_ALPHABET[(bytes[0] & 0x1f) as usize];

    // Bit cursor over the remaining 120 bits, 5 bits per output char.
    let mut bit_pos = 8usize;
    for slot in out.iter_mut().skip(2) {
        let idx = read_bits(&bytes, bit_pos, 5);
        *slot = CROCKFORD_ALPHABET[idx as usize];
        bit_pos += 5;
    }

    // The output is ASCII from a fixed alphabet, so this is always valid UTF-8.
    String::from_utf8(out.to_vec()).unwrap_or_else(|_| "0".repeat(26))
}

/// Read `count` bits (<= 8) starting at `bit_pos` from a big-endian byte slice.
fn read_bits(bytes: &[u8; 16], bit_pos: usize, count: usize) -> u8 {
    let mut value = 0u16;
    for i in 0..count {
        let abs = bit_pos + i;
        let byte = bytes.get(abs / 8).copied().unwrap_or(0);
        let bit = (byte >> (7 - (abs % 8))) & 1;
        value = (value << 1) | u16::from(bit);
    }
    (value & 0xff) as u8
}

/// Format `unix_millis` as RFC3339 UTC with millisecond precision and a
/// trailing `Z`, e.g. `2026-04-25T18:02:11.418Z`.
///
/// Falls back to the Unix epoch if the millisecond count is out of
/// `chrono`'s representable range (which cannot happen for real wall-clock
/// values; the fallback keeps the function total without an `unwrap`).
#[must_use]
pub fn rfc3339_millis(unix_millis: u64) -> String {
    use chrono::{SecondsFormat, TimeZone, Utc};
    let secs = (unix_millis / 1000) as i64;
    let nanos = ((unix_millis % 1000) * 1_000_000) as u32;
    match Utc.timestamp_opt(secs, nanos) {
        chrono::LocalResult::Single(dt) => dt.to_rfc3339_opts(SecondsFormat::Millis, true),
        _ => "1970-01-01T00:00:00.000Z".to_string(),
    }
}

/// Build and sign a frame from `inputs` using the tenant `keypair`.
///
/// The `tenant_sig` field of `inputs` is ignored; it is overwritten with a
/// fresh `ed25519:<base64>` signature over the canonical JSON of every other
/// field. The returned frame validates against the v1 schema and verifies
/// under the keypair's public key.
pub fn sign_frame(mut inputs: FrameInputs, keypair: &Keypair) -> Result<Frame, CaptureError> {
    // A zero-filled signature of the correct shape so `Frame::build`'s schema
    // validation passes; it is replaced with the real signature below.
    inputs.tenant_sig = format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode([0u8; 64])
    );
    let mut frame = Frame::build(inputs)?;
    let payload =
        signing_payload(&frame).map_err(|e| CaptureError::SigningPayload(e.to_string()))?;
    let signature = keypair.sign(&payload);
    frame.tenant_sig = format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    );
    Ok(frame)
}

/// Append-only NDJSON capture writer.
///
/// Writes one canonical-JSON frame per line to
/// `${runtime_dir}/captures/<run_id>.ndjson`. The file is opened in
/// append mode and each [`CaptureWriter::append`] flushes the line, so a
/// crash mid-run leaves a prefix of well-formed frames rather than a torn
/// final line. Appends are serialized behind a mutex so concurrent taps
/// never interleave bytes on one line.
pub struct CaptureWriter {
    path: PathBuf,
    file: Mutex<File>,
}

impl CaptureWriter {
    /// Open (creating if necessary) the capture file for `run_id` under
    /// `${runtime_dir}/captures/`.
    pub fn open(runtime_dir: &Path, run_id: &str) -> Result<Self, CaptureError> {
        let captures_dir = runtime_dir.join("captures");
        fs::create_dir_all(&captures_dir).map_err(|source| CaptureError::Io {
            path: captures_dir.clone(),
            source,
        })?;
        let path = captures_dir.join(format!("{run_id}.ndjson"));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| CaptureError::Io {
                path: path.clone(),
                source,
            })?;
        Ok(Self {
            path,
            file: Mutex::new(file),
        })
    }

    /// Path of the capture file being written.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Canonicalize, frame-validate, and append `frame` as one NDJSON line.
    pub fn append(&self, frame: &Frame) -> Result<(), CaptureError> {
        let mut line = canonicalize(frame)?;
        line.push(b'\n');
        let mut guard = match self.file.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.write_all(&line).map_err(|source| CaptureError::Io {
            path: self.path.clone(),
            source,
        })?;
        guard.flush().map_err(|source| CaptureError::Io {
            path: self.path.clone(),
            source,
        })?;
        Ok(())
    }
}

impl std::fmt::Debug for CaptureWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureWriter")
            .field("path", &self.path)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{validate_signed, Otel, Provenance, Upstream, UpstreamSystem, Verdict};
    use chio_test_support::prelude::*;

    fn sample_inputs() -> FrameInputs {
        FrameInputs {
            event_id: new_event_id(1_745_603_731_418),
            ts: rfc3339_millis(1_745_603_731_418),
            tee_id: "tee-capture-test".to_string(),
            upstream: Upstream {
                system: UpstreamSystem::Mcp,
                operation: "tool.call".to_string(),
                api_version: "2025-10-01".to_string(),
            },
            invocation: serde_json::json!({"tool": "noop"}),
            provenance: Provenance {
                otel: Otel {
                    trace_id: "0".repeat(32),
                    span_id: "0".repeat(16),
                },
                supply_chain: None,
            },
            request_blob_sha256: "a".repeat(64),
            response_blob_sha256: "b".repeat(64),
            redaction_pass_id: "redactors@1.4.0+default".to_string(),
            verdict: Verdict::Allow,
            deny_reason: None,
            would_have_blocked: false,
            tenant_sig: String::new(),
        }
    }

    #[test]
    fn event_id_is_26_char_crockford() {
        let id = new_event_id(1_745_603_731_418);
        assert_eq!(id.len(), 26);
        for c in id.chars() {
            assert!(
                CROCKFORD_ALPHABET.contains(&(c as u8)),
                "char {c} not in Crockford alphabet"
            );
        }
    }

    #[test]
    fn event_id_timestamp_prefix_is_sortable() {
        let early = new_event_id(1_000_000_000_000);
        let late = new_event_id(2_000_000_000_000);
        // The 48-bit timestamp prefix dominates the first ~10 chars, so a
        // later timestamp sorts strictly after an earlier one.
        assert!(early < late, "{early} should sort before {late}");
    }

    #[test]
    fn rfc3339_has_millis_and_z() {
        let ts = rfc3339_millis(1_745_603_731_418);
        assert_eq!(ts, "2025-04-25T17:55:31.418Z");
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 24);
    }

    #[test]
    fn signed_frame_verifies_under_public_key() {
        let keypair = Keypair::from_seed(&[3u8; 32]);
        let frame = sign_frame(sample_inputs(), &keypair).test_unwrap();
        let pubkey = *keypair.public_key().as_bytes();
        validate_signed(&frame, &pubkey).test_expect("signed frame must verify");
    }

    #[test]
    fn signed_frame_rejects_wrong_key() {
        let keypair = Keypair::from_seed(&[4u8; 32]);
        let frame = sign_frame(sample_inputs(), &keypair).test_unwrap();
        let wrong = Keypair::from_seed(&[5u8; 32]);
        let wrong_pub = *wrong.public_key().as_bytes();
        assert!(validate_signed(&frame, &wrong_pub).is_err());
    }

    #[test]
    fn writer_appends_one_frame_per_line() {
        let dir = tempfile::tempdir().test_unwrap();
        let keypair = Keypair::from_seed(&[6u8; 32]);
        let writer = CaptureWriter::open(dir.path(), "run-test").test_unwrap();
        let frame = sign_frame(sample_inputs(), &keypair).test_unwrap();
        writer.append(&frame).test_unwrap();
        writer.append(&frame).test_unwrap();

        let body = std::fs::read_to_string(writer.path()).test_unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let parsed: Frame = serde_json::from_str(line).test_unwrap();
            assert_eq!(parsed.tee_id, "tee-capture-test");
        }
    }
}
