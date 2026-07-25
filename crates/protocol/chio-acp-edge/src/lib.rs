//! # chio-acp-edge
//!
//! Edge crate that exposes Chio tools as ACP (Agent Client Protocol)
//! capabilities. This allows ACP-compatible editors and IDEs to access Chio
//! tools over ACP-shaped permission and invocation surfaces.
//!
//! Responsibilities:
//!
//! 1. Map Chio tool definitions to ACP capability advertisements.
//! 2. Intercept ACP `session/request_permission` calls.
//! 3. Expose truthful ACP lifecycle semantics: permission preview, blocking
//!    `tool/invoke`, and deferred-task `tool/stream` / `tool/cancel` /
//!    `tool/resume`.
//! 4. Route outward invocation through the Chio kernel by default while keeping
//!    explicit passthrough compatibility helpers.
//! 5. Evaluate `BridgeFidelity` per tool.
//!
//! Kernel-backed entrypoints emit signed Chio receipts. Direct passthrough
//! helpers remain available for compatibility and tests but are not sufficient
//! for full cross-protocol attestation claims.
//!
//! ## Modules
//!
//! The implementation is split into focused source fragments that share this
//! crate-root module scope (via `include!`):
//!
//! - `sync_bridge`: compatibility-only synchronous bridge shim.
//! - `error`: the [`AcpEdgeError`] type and receipt-write accounting helpers.
//! - `config`: the [`AcpEdgeConfig`] controlling permission defaults.
//! - `types`: ACP protocol wire types and the kernel execution context.
//! - `bridge`: capability bridge, target bindings, fidelity, orchestration.
//! - `conversion`: kernel-output conversion and Chio metadata builders.
//! - `edge`: the [`ChioAcpEdge`] server and its compatibility wrapper.

#![forbid(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
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
    capability_matches_request_with_model_metadata,
    capability_request_requires_dpop_with_model_metadata, dpop, ChioKernel, SignedExecutionNonce,
    ToolCallOutput, Verdict as KernelVerdict,
};
use chio_manifest::{ToolDefinition, ToolManifest};
use chio_mcp_edge::McpTargetExecutor;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[cfg(feature = "fuzz")]
pub mod fuzz;

pub mod metrics;
pub use metrics::{
    receipt_write_outcome_for_verdict, receipt_write_total, render_acp_edge_metrics_prometheus,
    CHIO_RECEIPT_WRITE_TOTAL, RECEIPT_WRITE_OUTCOME_ALLOW, RECEIPT_WRITE_OUTCOME_DENY,
    RECEIPT_WRITE_OUTCOME_ERROR, RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL,
};

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
