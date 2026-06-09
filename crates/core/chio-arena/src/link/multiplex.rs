//! Multi-kernel multiplexer.
//!
//! The arena holds an `Arc<ChioKernel>` per agent and routes
//! agent-to-agent tool calls through the in-process [`KernelLink`]
//! transport. The multiplexer never takes `&mut ChioKernel`; it only
//! clones the `Arc` so the kernel async surface remains untouched.

use std::collections::BTreeMap;
use std::sync::Arc;

use chio_kernel::{ChioKernel, ToolCallRequest, ToolCallResponse};
use thiserror::Error;

/// Multiplexer over a heterogeneous set of `Arc<ChioKernel>` handles, keyed by
/// agent id.
#[derive(Clone, Default)]
pub struct KernelMultiplexer {
    kernels: BTreeMap<String, Arc<ChioKernel>>,
}

impl KernelMultiplexer {
    /// Create an empty multiplexer.
    pub fn new() -> Self {
        Self {
            kernels: BTreeMap::new(),
        }
    }

    /// Register an agent against a kernel handle.
    pub fn register(
        &mut self,
        agent_id: impl Into<String>,
        kernel: Arc<ChioKernel>,
    ) -> Result<(), MultiplexError> {
        let agent_id = agent_id.into();
        if self.kernels.contains_key(&agent_id) {
            return Err(MultiplexError::DuplicateAgent(agent_id));
        }
        self.kernels.insert(agent_id, kernel);
        Ok(())
    }

    /// Returns the kernel handle registered for `agent_id`.
    pub fn kernel(&self, agent_id: &str) -> Result<Arc<ChioKernel>, MultiplexError> {
        self.kernels
            .get(agent_id)
            .cloned()
            .ok_or_else(|| MultiplexError::UnknownAgent(agent_id.to_string()))
    }

    /// Route a tool call through the kernel registered for `agent_id`.
    pub async fn route(
        &self,
        agent_id: &str,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, MultiplexError> {
        let kernel = self.kernel(agent_id)?;
        let response = kernel
            .evaluate_tool_call(request)
            .await
            .map_err(MultiplexError::Kernel)?;
        Ok(response)
    }

    /// Number of registered agents.
    pub fn len(&self) -> usize {
        self.kernels.len()
    }

    /// True when no agents are registered.
    pub fn is_empty(&self) -> bool {
        self.kernels.is_empty()
    }
}

/// Multiplexer errors.
#[derive(Debug, Error)]
pub enum MultiplexError {
    /// Agent already registered.
    #[error("kernel multiplexer already has an entry for agent {0}")]
    DuplicateAgent(String),
    /// Agent unknown.
    #[error("kernel multiplexer has no entry for agent {0}")]
    UnknownAgent(String),
    /// Kernel evaluation failed.
    #[error("kernel evaluation failed: {0}")]
    Kernel(#[from] chio_kernel::KernelError),
}
