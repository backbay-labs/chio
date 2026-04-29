// Line-buffered NDJSON iterator for `chio replay traffic`.
// Yields strongly-typed `chio_tee_frame::Frame` records; malformed lines
// surface as [`NdjsonError`] without panicking. Schema validation and
// signature verification are layered on top in `cli/replay/validate.rs`.

/// Default capacity of the per-line buffer (8 KiB). NDJSON lines are
/// expected to fit comfortably; pathologically long lines cause the
/// underlying `BufReader::read_until` call to grow the buffer.
const DEFAULT_LINE_CAPACITY: usize = 8 * 1024;

/// Errors surfaced by [`FrameIter`] / [`read_frame_line`].
#[derive(Debug, thiserror::Error)]
pub enum NdjsonError {
    /// Underlying `Read` returned an I/O error.
    #[error("ndjson io error on line {line}: {source}")]
    Io {
        line: u64,
        #[source]
        source: std::io::Error,
    },
    /// A non-blank line failed `serde_json::from_slice`.
    #[error("ndjson parse error on line {line}: {message}")]
    Parse { line: u64, message: String },
}

impl NdjsonError {
    /// Line number (1-based) the error refers to.
    pub fn line(&self) -> u64 {
        match self {
            Self::Io { line, .. } | Self::Parse { line, .. } => *line,
        }
    }
}

/// One yielded record from [`FrameIter`].
///
/// `line` is the 1-based line number in the source stream so callers can
/// surface a precise byte offset in the structured replay report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameRecord {
    /// 1-based line number in the source NDJSON stream.
    pub line: u64,
    /// Decoded frame.
    pub frame: chio_tee_frame::Frame,
}

/// Iterator over `chio_tee_frame::Frame` records read from an NDJSON
/// stream. Blank lines (zero-length after trim) are skipped silently;
/// every other line must decode into a typed [`Frame`] or the iterator
/// yields a structured [`NdjsonError`].
///
/// The iterator does NOT validate the schema beyond serde's
/// `deny_unknown_fields` enforcement; full validation is layered on top
/// in [`crate::cli::replay::validate`].
pub struct FrameIter<R: std::io::BufRead> {
    inner: R,
    line: u64,
    buf: Vec<u8>,
    finished: bool,
}

impl<R: std::io::BufRead> FrameIter<R> {
    /// Create a new iterator over `reader`.
    pub fn new(reader: R) -> Self {
        Self {
            inner: reader,
            line: 0,
            buf: Vec::with_capacity(DEFAULT_LINE_CAPACITY),
            finished: false,
        }
    }
}

impl<R: std::io::BufRead> Iterator for FrameIter<R> {
    type Item = Result<FrameRecord, NdjsonError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        loop {
            self.buf.clear();
            self.line = self.line.saturating_add(1);
            let read = match self.inner.read_until(b'\n', &mut self.buf) {
                Ok(n) => n,
                Err(source) => {
                    self.finished = true;
                    return Some(Err(NdjsonError::Io {
                        line: self.line,
                        source,
                    }));
                }
            };
            if read == 0 {
                self.finished = true;
                return None;
            }
            // Strip trailing newline (and CR if present, for tolerance
            // against captures emitted on Windows-style hosts).
            let mut slice = self.buf.as_slice();
            if slice.last() == Some(&b'\n') {
                slice = &slice[..slice.len() - 1];
            }
            if slice.last() == Some(&b'\r') {
                slice = &slice[..slice.len() - 1];
            }
            // Skip blank-line whitespace lines silently.
            if slice.iter().all(|b| b.is_ascii_whitespace()) {
                continue;
            }
            let frame: chio_tee_frame::Frame = match serde_json::from_slice(slice) {
                Ok(f) => f,
                Err(error) => {
                    return Some(Err(NdjsonError::Parse {
                        line: self.line,
                        message: error.to_string(),
                    }));
                }
            };
            return Some(Ok(FrameRecord {
                line: self.line,
                frame,
            }));
        }
    }
}

/// Convenience: open `path` and return a [`FrameIter`] over a
/// `BufReader`. Preserves the same line-numbering and error semantics as
/// [`FrameIter::new`].
pub fn open_ndjson(
    path: &std::path::Path,
) -> Result<FrameIter<std::io::BufReader<std::fs::File>>, std::io::Error> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    Ok(FrameIter::new(reader))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_ndjson_tests {
    use super::*;

    fn good_frame_json() -> String {
        // Mirrors the `good_frame()` helper in chio-tee-frame's test
        // suite. Crockford-base32 ULID, RFC3339 ms-precision timestamp,
        // 64-char lower-hex blob hashes, `Allow` verdict so the
        // deny-reason gate stays clean.
        let frame = chio_tee_frame::Frame {
            schema_version: chio_tee_frame::SCHEMA_VERSION.to_string(),
            event_id: "01H7ZZZZZZZZZZZZZZZZZZZZZZ".to_string(),
            ts: "2026-04-25T18:02:11.418Z".to_string(),
            tee_id: "tee-prod-1".to_string(),
            upstream: chio_tee_frame::Upstream {
                system: chio_tee_frame::UpstreamSystem::Openai,
                operation: "responses.create".to_string(),
                api_version: "2025-10-01".to_string(),
            },
            invocation: serde_json::json!({"tool":"noop"}),
            provenance: chio_tee_frame::Provenance {
                otel: chio_tee_frame::Otel {
                    trace_id: "0".repeat(32),
                    span_id: "0".repeat(16),
                },
                supply_chain: None,
            },
            request_blob_sha256: "a".repeat(64),
            response_blob_sha256: "b".repeat(64),
            redaction_pass_id: "m06-redactors@1.4.0+default".to_string(),
            verdict: chio_tee_frame::Verdict::Allow,
            deny_reason: None,
            would_have_blocked: false,
            tenant_sig: format!("ed25519:{}", "A".repeat(86)),
        };
        serde_json::to_string(&frame).unwrap()
    }

    #[test]
    fn yields_typed_records_in_order() {
        let mut stream = String::new();
        stream.push_str(&good_frame_json());
        stream.push('\n');
        stream.push_str(&good_frame_json());
        stream.push('\n');

        let cursor = std::io::Cursor::new(stream.into_bytes());
        let iter = FrameIter::new(cursor);
        let records: Vec<_> = iter.collect();
        assert_eq!(records.len(), 2, "two records yielded for two lines");
        for (i, record) in records.iter().enumerate() {
            let r = record.as_ref().expect("good record");
            assert_eq!(r.line, (i as u64) + 1);
            assert_eq!(r.frame.schema_version, "1");
            assert_eq!(r.frame.tee_id, "tee-prod-1");
        }
    }

    #[test]
    fn skips_blank_lines() {
        let mut stream = String::new();
        stream.push('\n');
        stream.push_str(&good_frame_json());
        stream.push('\n');
        stream.push_str("   \n");
        stream.push_str(&good_frame_json());
        stream.push('\n');

        let cursor = std::io::Cursor::new(stream.into_bytes());
        let iter = FrameIter::new(cursor);
        let records: Vec<_> = iter.collect();
        // Two yielded records (lines 1 and 3 are blank/whitespace).
        assert_eq!(
            records.len(),
            2,
            "blank lines are silently skipped: {records:?}"
        );
        let first = records[0].as_ref().expect("good record");
        let second = records[1].as_ref().expect("good record");
        assert_eq!(first.line, 2);
        assert_eq!(second.line, 4);
    }

    #[test]
    fn malformed_line_returns_structured_error() {
        let mut stream = String::new();
        stream.push_str(&good_frame_json());
        stream.push('\n');
        stream.push_str("{not valid json\n");
        stream.push_str(&good_frame_json());
        stream.push('\n');

        let cursor = std::io::Cursor::new(stream.into_bytes());
        let mut iter = FrameIter::new(cursor);
        let first = iter.next().expect("first").expect("good first record");
        assert_eq!(first.line, 1);
        let second = iter.next().expect("second yields error");
        match second {
            Err(NdjsonError::Parse { line, message }) => {
                assert_eq!(line, 2);
                assert!(!message.is_empty(), "parse error carries serde detail");
            }
            other => panic!("expected NdjsonError::Parse, got {other:?}"),
        }
        // After a parse error the iterator is allowed to continue
        // (callers bail or keep going per replay-report policy). We
        // verify continuation here so downstream code can choose.
        let third = iter.next().expect("third").expect("good third record");
        assert_eq!(third.line, 3);
        assert!(iter.next().is_none(), "EOF after three lines");
    }

    #[test]
    fn empty_stream_yields_nothing() {
        let cursor = std::io::Cursor::new(Vec::new());
        let mut iter = FrameIter::new(cursor);
        assert!(iter.next().is_none());
        assert!(
            iter.next().is_none(),
            "iterator stays terminated after EOF",
        );
    }

    #[test]
    fn line_numbering_is_1_based() {
        let stream = format!("{}\n", good_frame_json());
        let cursor = std::io::Cursor::new(stream.into_bytes());
        let mut iter = FrameIter::new(cursor);
        let first = iter.next().expect("first").expect("good record");
        assert_eq!(first.line, 1, "lines are 1-based, not 0-based");
    }

    #[test]
    fn ndjson_error_exposes_line_number() {
        let err = NdjsonError::Parse {
            line: 42,
            message: "boom".to_string(),
        };
        assert_eq!(err.line(), 42);
        let io = NdjsonError::Io {
            line: 7,
            source: std::io::Error::other("eio"),
        };
        assert_eq!(io.line(), 7);
    }
}
