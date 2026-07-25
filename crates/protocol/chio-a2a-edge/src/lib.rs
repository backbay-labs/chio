//! # chio-a2a-edge
//!
//! Edge crate that exposes Chio tools as A2A (Agent-to-Agent) skills. This is
//! the reverse direction from `chio-a2a-adapter`: instead of consuming a remote
//! A2A server, this crate *serves* Chio tools to A2A clients.
//!
//! Responsibilities:
//!
//! 1. Publish an A2A Agent Card at `/.well-known/agent-card.json`.
//! 2. Accept `SendMessage` requests and route them through the Chio kernel by
//!    default.
//! 3. Expose a truthful blocking `message/send` surface plus deferred
//!    receipt-bearing `message/stream` task lifecycle.
//! 4. Evaluate `BridgeFidelity` per tool to signal translation quality.
//!
//! Kernel-backed entrypoints produce signed Chio receipts. Explicit passthrough
//! compatibility helpers remain available for bounded migration and tests, but
//! they are not the authoritative Chio trust path. The authoritative streaming
//! surface is truthful but bounded: `message/stream` creates a deferred task,
//! `task/get` resolves the terminal receipt-bearing result, and `task/cancel`
//! can cancel a deferred task before execution.
//!
//! ## Modules
//!
//! The implementation is split into focused source fragments that share this
//! crate-root module scope (via `include!`):
//!
//! - `sync_bridge`: compatibility-only synchronous bridge shim.
//! - `error`: the [`A2aEdgeError`] type and receipt-write accounting helpers.
//! - `config`: the [`A2aEdgeConfig`] published in the Agent Card.
//! - `types`: A2A protocol wire types and the kernel execution context.
//! - `bridge`: capability bridge, skill candidates, fidelity, orchestration.
//! - `conversion`: message conversion and Chio metadata envelope builders.
//! - `edge`: the [`ChioA2aEdge`] server and its compatibility wrapper.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::{
    governance::{GovernedApprovalToken, GovernedTransactionIntent, ThresholdApprovalProposal},
    scope::ModelMetadata,
    token::CapabilityToken,
};
use chio_core::session::OperationTerminalState;
use chio_cross_protocol::capability_bridge::{CapabilityBridge, CrossProtocolCapabilityRef};
use chio_cross_protocol::discovery::{
    target_protocol_for_tool_with_registry, DiscoveryProtocol, TargetProtocolRegistry,
};
use chio_cross_protocol::error::BridgeError;
use chio_cross_protocol::execution::{CrossProtocolExecutionRequest, OpenAiTargetExecutor};
use chio_cross_protocol::lifecycle::{
    runtime_lifecycle_contract, runtime_lifecycle_metadata, RuntimeLifecycleSurface,
};
use chio_cross_protocol::orchestrator::{CrossProtocolOrchestrator, OrchestratedToolCall};
use chio_cross_protocol::semantic_hints::{semantic_hints_for_tool, BridgeFidelity};
#[cfg(any(test, feature = "compatibility-surface"))]
use chio_kernel::ToolServerConnection;
use chio_kernel::{
    dpop, ChioKernel, SignedExecutionNonce, ToolCallOutput, Verdict as KernelVerdict,
};
use chio_manifest::{ToolDefinition, ToolManifest};
use chio_mcp_edge::McpTargetExecutor;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub mod metrics;
pub use metrics::{
    receipt_write_outcome_for_verdict, receipt_write_total, render_a2a_edge_metrics_prometheus,
    CHIO_RECEIPT_WRITE_TOTAL, RECEIPT_WRITE_OUTCOME_ALLOW, RECEIPT_WRITE_OUTCOME_DENY,
    RECEIPT_WRITE_OUTCOME_ERROR, RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL,
};

#[cfg(feature = "otel")]
pub mod otel;

// ---------- source fragments (include! pattern) ----------
//
// Each fragment merges into this crate-root module scope; item paths and
// visibility resolve as if the fragments were inlined here.

// The fail-closed sync-bridge helper lives once in `chio-cross-protocol`; the
// A2A and ACP edges share that single definition. Only used under the
// compatibility-surface passthrough, so the import is gated to match.
#[cfg(any(test, feature = "compatibility-surface"))]
use chio_cross_protocol::sync_bridge_shared::block_on_tool_server_invoke;
include!("error.rs");
include!("config.rs");
include!("types.rs");
include!("bridge.rs");
include!("conversion.rs");
include!("edge.rs");
include!("jsonrpc.rs");
include!("tests/all.rs");

#[cfg(test)]
#[path = "tests/nonce_preflight.rs"]
mod nonce_preflight_tests;
