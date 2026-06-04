use std::io::BufRead;

use serde_json::Value;
use tracing::debug;

use crate::AdapterError;

pub(crate) const MAX_STDIO_MCP_FRAME_BYTES: usize = 1024 * 1024;

/// Read one newline-delimited JSON-RPC frame.
///
/// Empty or whitespace-only frames are skipped. A clean EOF before any frame is
/// returned as `Ok(None)` so callers can map it to their own connection state.
/// A non-empty EOF before the newline delimiter is a parse error because MCP
/// stdio framing is line-delimited.
pub(crate) fn read_jsonrpc_frame(reader: &mut impl BufRead) -> Result<Option<Value>, AdapterError> {
    loop {
        let Some(line) = read_bounded_line(reader, MAX_STDIO_MCP_FRAME_BYTES)? else {
            return Ok(None);
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        debug!("<- {}", line.trim_end());

        return serde_json::from_str(trimmed)
            .map(Some)
            .map_err(|e| AdapterError::ParseError(format!("invalid JSON from MCP server: {e}")));
    }
}

fn read_bounded_line(
    reader: &mut impl BufRead,
    max_bytes: usize,
) -> Result<Option<String>, AdapterError> {
    let mut bytes = Vec::new();
    loop {
        let (take, has_newline, exceeds_limit) = {
            let available = reader.fill_buf().map_err(|e| {
                AdapterError::ConnectionFailed(format!("failed to read from stdout: {e}"))
            })?;
            if available.is_empty() {
                if bytes.is_empty() {
                    return Ok(None);
                }
                return Err(AdapterError::ParseError(
                    "MCP JSON-RPC frame ended before newline delimiter".into(),
                ));
            }

            let take = match available.iter().position(|byte| *byte == b'\n') {
                Some(index) => index + 1,
                None => available.len(),
            };
            let has_newline = available.get(take.saturating_sub(1)) == Some(&b'\n');
            let exceeds_limit = bytes.len().saturating_add(take) > max_bytes;
            if !exceeds_limit {
                bytes.extend_from_slice(&available[..take]);
            }
            (take, has_newline, exceeds_limit)
        };

        reader.consume(take);
        if exceeds_limit {
            return Err(AdapterError::ParseError(format!(
                "MCP JSON-RPC frame exceeded {max_bytes} bytes"
            )));
        }

        if has_newline {
            break;
        }
    }

    String::from_utf8(bytes).map(Some).map_err(|error| {
        AdapterError::ParseError(format!("MCP JSON-RPC frame was not UTF-8: {error}"))
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::BufReader;

    use super::*;

    #[test]
    fn frame_reader_returns_none_on_clean_eof() {
        let input = b"";
        let mut reader = BufReader::new(&input[..]);
        assert!(read_jsonrpc_frame(&mut reader).unwrap().is_none());
    }

    #[test]
    fn frame_reader_rejects_delimiterless_non_empty_eof() {
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
        let mut reader = BufReader::new(&input[..]);
        let err = read_jsonrpc_frame(&mut reader).unwrap_err();
        assert!(
            matches!(err, AdapterError::ParseError(_)),
            "expected ParseError, got: {err}"
        );
    }

    #[test]
    fn frame_reader_skips_blank_frames_before_json() {
        let input = b"\n  \r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n";
        let mut reader = BufReader::new(&input[..]);
        let frame = read_jsonrpc_frame(&mut reader)
            .unwrap()
            .unwrap_or_else(|| panic!("expected frame"));
        assert_eq!(frame["id"], 1);
    }

    #[test]
    fn frame_reader_rejects_oversized_frame() {
        let input = format!("{}\n", "x".repeat(MAX_STDIO_MCP_FRAME_BYTES + 1));
        let mut reader = BufReader::new(input.as_bytes());
        let err = read_jsonrpc_frame(&mut reader).unwrap_err();
        assert!(
            matches!(err, AdapterError::ParseError(_)),
            "expected ParseError, got: {err}"
        );
    }
}
