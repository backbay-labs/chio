//! Assertion helpers for provider conformance replay.

use chio_core::canonical::canonical_json_bytes;
use chio_tool_call_fabric::VerdictResult;
use serde::Serialize;
use thiserror::Error;

/// Assertion failure emitted by the replay harness.
#[derive(Debug, Error)]
pub enum AssertionError {
    /// Canonical JSON encoding failed before byte comparison.
    #[error("{label} failed canonical JSON encoding: {source}")]
    CanonicalJson {
        label: String,
        #[source]
        source: chio_core::Error,
    },
    /// Canonical JSON bytes did not match.
    #[error("{label} canonical JSON bytes differed: expected {expected}, actual {actual}")]
    CanonicalJsonMismatch {
        label: String,
        expected: String,
        actual: String,
    },
    /// Captured and replayed verdicts did not match.
    #[error("{label} verdict differed: expected {expected:?}, actual {actual:?}")]
    VerdictMismatch {
        label: String,
        expected: Box<VerdictResult>,
        actual: Box<VerdictResult>,
    },
}

/// Encode a serializable value as canonical JSON bytes.
pub fn canonical_json_bytes_for<T>(
    label: impl Into<String>,
    value: &T,
) -> Result<Vec<u8>, AssertionError>
where
    T: Serialize,
{
    let label = label.into();
    canonical_json_bytes(value).map_err(|source| AssertionError::CanonicalJson { label, source })
}

/// Assert byte equality after RFC 8785 canonical JSON encoding.
pub fn assert_canonical_json_eq<L, R>(
    label: impl Into<String>,
    expected: &L,
    actual: &R,
) -> Result<(), AssertionError>
where
    L: Serialize,
    R: Serialize,
{
    let label = label.into();
    let expected_bytes = canonical_json_bytes_for(label.clone(), expected)?;
    let actual_bytes = canonical_json_bytes_for(label.clone(), actual)?;
    assert_canonical_bytes_eq(label, &expected_bytes, &actual_bytes)
}

/// Assert canonical JSON byte equality for already encoded values.
pub fn assert_canonical_bytes_eq(
    label: impl Into<String>,
    expected: &[u8],
    actual: &[u8],
) -> Result<(), AssertionError> {
    if expected == actual {
        return Ok(());
    }

    Err(AssertionError::CanonicalJsonMismatch {
        label: label.into(),
        expected: render_bytes(expected),
        actual: render_bytes(actual),
    })
}

/// Assert exact verdict equality.
pub fn assert_verdict_eq(
    label: impl Into<String>,
    expected: &VerdictResult,
    actual: &VerdictResult,
) -> Result<(), AssertionError> {
    if expected == actual {
        return Ok(());
    }

    Err(AssertionError::VerdictMismatch {
        label: label.into(),
        expected: Box::new(expected.clone()),
        actual: Box::new(actual.clone()),
    })
}

fn render_bytes(bytes: &[u8]) -> String {
    const MAX_PREVIEW_BYTES: usize = 240;

    let rendered = String::from_utf8_lossy(bytes);
    if bytes.len() <= MAX_PREVIEW_BYTES {
        return rendered.into_owned();
    }

    let mut preview = rendered.chars().take(MAX_PREVIEW_BYTES).collect::<String>();
    preview.push_str("...");
    preview
}
