//! libFuzzer entry-point module for `chio-acp-edge`. Gated behind `fuzz` feature.

use std::sync::OnceLock;

use chio_core::capability::{
    CapabilityToken, CapabilityTokenBody, ChioScope, Operation, ToolGrant,
};
use chio_core::crypto::Keypair;
use chio_kernel::{ChioKernel, KernelConfig, DEFAULT_CHECKPOINT_BATCH_SIZE};

use crate::{AcpEdgeConfig, AcpKernelExecutionContext, ChioAcpEdge};

/// Deterministic 32-byte seed for the fuzz-only kernel keypair. Fixed so the
/// corpus surface is stable across libFuzzer runs.
const FUZZ_KERNEL_SEED: [u8; 32] = [
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80,
];

/// Deterministic 32-byte seed for the fuzz-only agent keypair.
const FUZZ_AGENT_SEED: [u8; 32] = [
    0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
    0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0,
];

/// Cached agent identifier (hex-encoded public key) for the fuzz fixture.
/// Built once per process so successive iterations see a stable identifier.
fn agent_id() -> &'static str {
    static AGENT_ID: OnceLock<String> = OnceLock::new();
    AGENT_ID
        .get_or_init(|| Keypair::from_seed(&FUZZ_AGENT_SEED).public_key().to_hex())
        .as_str()
}

// Rebuilt per iteration because ChioAcpEdge is !Sync and cannot be cached.
fn make_kernel() -> ChioKernel {
    let keypair = Keypair::from_seed(&FUZZ_KERNEL_SEED);
    let config = KernelConfig {
        ca_public_keys: vec![keypair.public_key()],
        keypair,
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

fn make_edge() -> Option<ChioAcpEdge> {
    // Empty manifest: every tool/invoke hits ToolNotFound, exercising the error paths.
    ChioAcpEdge::new(AcpEdgeConfig::default(), vec![]).ok()
}

fn make_execution() -> Option<AcpKernelExecutionContext> {
    let issuer = Keypair::from_seed(&FUZZ_KERNEL_SEED);
    let subject = Keypair::from_seed(&FUZZ_AGENT_SEED);
    // Fixed timestamps: avoids touching the system clock inside the fuzz loop.
    let issued_at: u64 = 1_700_000_000;
    let expires_at: u64 = issued_at + 3600;
    let body = CapabilityTokenBody {
        id: "fuzz-acp-cap".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "fuzz-srv".to_string(),
                tool_name: "fuzz-tool".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: vec![],
            prompt_grants: vec![],
        },
        issued_at,
        expires_at,
        delegation_chain: vec![],
    };
    let capability: CapabilityToken = CapabilityToken::sign(body, &issuer).ok()?;
    Some(AcpKernelExecutionContext {
        capability,
        agent_id: agent_id().to_string(),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
    })
}

pub fn fuzz_acp_envelope_decode(data: &[u8]) {
    use std::io::BufRead;

    let kernel = make_kernel();
    let edge = match make_edge() {
        Some(edge) => edge,
        None => return,
    };
    let execution = match make_execution() {
        Some(execution) => execution,
        None => return,
    };

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
                let Ok(message) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                    continue;
                };
                let _ = edge.handle_jsonrpc(message, &kernel, &execution);
            }
            Err(_) => return,
        }
    }
}
