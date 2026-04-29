//! libFuzzer entry-point module for `chio-mcp-adapter`.
//!
//! Gated behind the `fuzz` Cargo feature so it only compiles into the standalone
//! `chio-fuzz` workspace at `../../fuzz`. Production builds never pull in
//! `arbitrary`, never expose these symbols, and never get recompiled with
//! libFuzzer instrumentation.
//!
//! [`fuzz_mcp_envelope_parse`] drives arbitrary bytes through the adapter's MCP
//! envelope parse path. MCP uses newline-delimited JSON-RPC over stdin/stdout
//! (see `crates/chio-mcp-adapter/src/transport.rs::read_line`), so the parse
//! contract is two-stage: split the byte stream into newline-terminated lines,
//! then `serde_json::from_str` each non-empty line into a `serde_json::Value`
//! envelope. Both stages must surface bad inputs as errors rather than panics.
//!
//! Companion entry point: the edge crate's
//! `chio_mcp_edge::fuzz::fuzz_mcp_envelope_decode` carries the full
//! decode-then-evaluator-dispatch pipeline. This adapter-side wrapper is retained
//! as a smaller seam targeting only the transport-side parse path.

use std::io::BufRead;

/// Drive arbitrary bytes through the adapter's MCP envelope parse path.
///
/// Bytes are interpreted as a newline-delimited JSON-RPC stream, mirroring
/// what `chio_mcp_adapter::transport::StdioMcpTransport`'s reader thread
/// receives from an upstream MCP subprocess. The wrapper:
///
/// 1. Wraps the byte slice in a `BufRead` and iterates `read_line` to mirror
///    the per-line framing used by the real transport.
/// 2. Trims each line and feeds the trimmed contents to
///    `serde_json::from_str::<serde_json::Value>`. Empty trimmed lines are
///    skipped to match the real loop's behaviour on blank framing bytes.
///
/// Errors at every step are silently consumed: the trust-boundary contract
/// guarantees the only outcomes are `Err(serde_json::Error)` (good),
/// successful `Ok(Value)` (good), or a panic / abort (which libFuzzer reports
/// as a crash).
pub fn fuzz_mcp_envelope_parse(data: &[u8]) {
    let mut reader = std::io::BufReader::new(data);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => return,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let _ = serde_json::from_str::<serde_json::Value>(trimmed);
            }
            Err(_) => return,
        }
    }
}
