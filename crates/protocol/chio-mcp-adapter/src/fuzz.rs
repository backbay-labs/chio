//! libFuzzer entry-point module for `chio-mcp-adapter`.
//!
//! Gated behind the `fuzz` Cargo feature so it only compiles into the standalone
//! `chio-fuzz` workspace at `../../fuzz`. Production builds never pull in
//! `arbitrary`, never expose these symbols, and never get recompiled with
//! libFuzzer instrumentation.
//!
//! [`fuzz_mcp_envelope_parse`] drives arbitrary bytes through the adapter's MCP
//! envelope parse path. MCP uses newline-delimited JSON-RPC over stdin/stdout,
//! so the fuzz entrypoint routes arbitrary bytes through the same internal
//! frame decoder that production stdio transport uses. Delimiter, size, UTF-8,
//! and JSON errors must surface as errors rather than panics.
//!
//! Companion entry point: the edge crate's
//! `chio_mcp_edge::fuzz::fuzz_mcp_envelope_decode` carries the full
//! decode-then-evaluator-dispatch pipeline. This adapter-side wrapper is retained
//! as a smaller seam targeting only the transport-side parse path.

use std::io::BufReader;

/// Drive arbitrary bytes through the adapter's MCP envelope parse path.
///
/// Bytes are interpreted as a newline-delimited JSON-RPC stream, mirroring
/// what `chio_mcp_adapter::transport::StdioMcpTransport`'s reader thread
/// receives from an upstream MCP subprocess. The wrapper:
///
/// 1. Wraps the byte slice in a `BufRead`.
/// 2. Iterates the shared production frame decoder used by
///    `StdioMcpTransport`.
///
/// Errors at every step are silently consumed: the trust-boundary contract
/// guarantees the only outcomes are an `AdapterError` (good), a successfully
/// decoded frame (good), clean EOF, or a panic / abort (which libFuzzer reports
/// as a crash).
pub fn fuzz_mcp_envelope_parse(data: &[u8]) {
    let mut reader = BufReader::new(data);
    loop {
        match crate::framing::read_jsonrpc_frame(&mut reader) {
            Ok(Some(_frame)) => continue,
            Ok(None) => return,
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzz_entrypoint_uses_strict_framing_without_panicking() {
        fuzz_mcp_envelope_parse(b"\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n");
        fuzz_mcp_envelope_parse(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
    }
}
