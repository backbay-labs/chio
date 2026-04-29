//! libFuzzer entry-point module for `chio-mcp-edge`.
//!
//! Gated behind the `fuzz` Cargo feature so it only compiles into the standalone
//! `chio-fuzz` workspace at `../../fuzz`. Production builds never pull in
//! `arbitrary`, never expose these symbols, and never get recompiled with
//! libFuzzer instrumentation.
//!
//! [`fuzz_mcp_envelope_decode`] is the canonical "decode -> evaluator dispatch"
//! trust-boundary pipeline for the MCP edge:
//!
//! 1. **Decode stage.** Bytes are interpreted as a newline-delimited JSON-RPC
//!    stream. Each non-empty trimmed line is fed to
//!    `serde_json::from_str::<serde_json::Value>` to produce a JSON-RPC envelope.
//! 2. **Evaluator dispatch stage.** Successfully decoded envelopes are forwarded
//!    to [`ChioMcpEdge::handle_jsonrpc`], which routes `initialize`, `tools/list`,
//!    `tools/call`, notifications, and the rest of the MCP method namespace through
//!    the edge's capability evaluator and kernel-backed tool plumbing.
//!
//! The decode-then-dispatch combination catches bugs that pure structural-parse
//! fuzzing would miss: it exercises both the JSON parser and the downstream
//! method-dispatch state machine on the same byte stream.
//!
//! The kernel and edge fixtures are deterministic. The kernel keypair is derived
//! from a fixed 32-byte seed via [`Keypair::from_seed`], and the edge is rebuilt
//! fresh on every iteration so libFuzzer-injected sequences cannot poison
//! cross-iteration state.

use std::sync::OnceLock;

use chio_core::capability::ChioScope;
use chio_core::crypto::Keypair;
use chio_kernel::{ChioKernel, KernelConfig, DEFAULT_CHECKPOINT_BATCH_SIZE};

use crate::{ChioMcpEdge, McpEdgeConfig};

/// Deterministic 32-byte seed for the fuzz-only kernel keypair. Fixed so the
/// corpus surface is stable across libFuzzer runs.
const FUZZ_KERNEL_SEED: [u8; 32] = [
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
];

/// Deterministic 32-byte seed for the fuzz-only agent keypair.
const FUZZ_AGENT_SEED: [u8; 32] = [
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
];

/// Cached agent identifier (hex-encoded public key) for the fuzz fixture.
/// Built once per process so successive iterations see a stable identifier.
fn agent_id() -> &'static str {
    static AGENT_ID: OnceLock<String> = OnceLock::new();
    AGENT_ID
        .get_or_init(|| Keypair::from_seed(&FUZZ_AGENT_SEED).public_key().to_hex())
        .as_str()
}

/// Build a fresh [`ChioKernel`] for one fuzz iteration. The kernel is
/// rebuilt rather than cached because [`ChioMcpEdge`] takes ownership of
/// the kernel; sharing a single kernel across iterations would require
/// cloning, which is not part of the trust-boundary surface we want to
/// exercise.
fn make_kernel() -> ChioKernel {
    let keypair = Keypair::from_seed(&FUZZ_KERNEL_SEED);
    let config = KernelConfig {
        keypair,
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "fuzz-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    };
    ChioKernel::new(config)
}

/// Build a fresh [`ChioMcpEdge`] fixture for one fuzz iteration.
///
/// Returns `None` if the constructor surfaces an `AdapterError`. The
/// constructor is expected to succeed for the empty-manifest case used
/// here, but we propagate `Option` rather than `unwrap`/`expect` so the
/// crate's `unwrap_used = "deny"` lint stays satisfied.
fn make_edge() -> Option<ChioMcpEdge> {
    let kernel = make_kernel();
    let agent_id_str = agent_id().to_string();
    // `ChioScope::default()` is empty; capabilities are empty too. The fuzz
    // target probes the JSON-RPC method dispatcher itself, which on the
    // unhappy path surfaces JSON-RPC errors before consulting capabilities.
    let _scope = ChioScope::default();
    let capabilities = vec![];
    ChioMcpEdge::new(
        McpEdgeConfig::default(),
        kernel,
        agent_id_str,
        capabilities,
        vec![],
    )
    .ok()
}

/// Drive arbitrary bytes through the decode-then-evaluator-dispatch
/// trust-boundary pipeline.
///
/// Bytes are interpreted as a newline-delimited JSON-RPC stream. Every
/// non-empty trimmed line is parsed with `serde_json::from_str` and, on
/// success, forwarded to [`ChioMcpEdge::handle_jsonrpc`] against a fresh
/// per-iteration edge fixture. Errors and method-not-found responses are
/// silently consumed: the only outcomes are an `Err`-shaped JSON-RPC response
/// (good), an `Ok`-shaped JSON-RPC response (good), `None` for a notification
/// (good), or a panic / abort (which libFuzzer reports as a crash).
///
/// The fixture is rebuilt fresh on every iteration so libFuzzer-injected
/// sequences cannot poison cross-iteration kernel or session state.
pub fn fuzz_mcp_envelope_decode(data: &[u8]) {
    use std::io::BufRead;

    let mut reader = std::io::BufReader::new(data);
    let mut edge = match make_edge() {
        Some(edge) => edge,
        None => return,
    };
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => return,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let Ok(message) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                    continue;
                };
                let _ = edge.handle_jsonrpc(message);
            }
            Err(_) => return,
        }
    }
}
