//! Post-invocation hook pipeline executed after a tool returns output.

use chio_core::receipt::GuardEvidence;
use chio_core::{capability::scope::ChioScope, AgentId, ServerId};
use serde_json::Value;

use crate::runtime::ToolCallRequest;

/// Verdict from a post-invocation hook.
#[derive(Debug, Clone)]
pub enum PostInvocationVerdict {
    Allow,
    Block(String),
    Redact(Value),
    Escalate(String),
}

/// Context available to post-invocation hooks after a tool has executed.
#[derive(Clone, Copy, Debug)]
pub struct PostInvocationContext<'a> {
    pub tool_name: &'a str,
    pub request: Option<&'a ToolCallRequest>,
    pub scope: Option<&'a ChioScope>,
    pub agent_id: Option<&'a AgentId>,
    pub server_id: Option<&'a ServerId>,
    pub matched_grant_index: Option<usize>,
}

impl<'a> PostInvocationContext<'a> {
    #[must_use]
    pub fn synthetic(tool_name: &'a str) -> Self {
        Self {
            tool_name,
            request: None,
            scope: None,
            agent_id: None,
            server_id: None,
            matched_grant_index: None,
        }
    }

    #[must_use]
    pub fn from_request(request: &'a ToolCallRequest, matched_grant_index: Option<usize>) -> Self {
        Self {
            tool_name: request.tool_name.as_str(),
            request: Some(request),
            scope: Some(&request.capability.scope),
            agent_id: Some(&request.agent_id),
            server_id: Some(&request.server_id),
            matched_grant_index,
        }
    }
}

/// A hook that inspects tool responses after invocation.
pub trait PostInvocationHook: Send + Sync {
    fn name(&self) -> &str;

    fn inspect(&self, ctx: &PostInvocationContext<'_>, response: &Value) -> PostInvocationVerdict;

    fn take_evidence(&self) -> Option<GuardEvidence> {
        None
    }
}

/// Outcome of running the pipeline.
#[derive(Debug, Clone)]
pub struct PipelineOutcome {
    pub verdict: PostInvocationVerdict,
    pub escalations: Vec<String>,
    pub evidence: Vec<GuardEvidence>,
}

/// Pipeline of post-invocation hooks evaluated in registration order.
pub struct PostInvocationPipeline {
    hooks: Vec<Box<dyn PostInvocationHook>>,
}

impl PostInvocationPipeline {
    #[must_use]
    pub fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    pub fn add(&mut self, hook: Box<dyn PostInvocationHook>) {
        self.hooks.push(hook);
    }

    pub fn append(&mut self, mut other: Self) {
        self.hooks.append(&mut other.hooks);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.hooks.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    #[must_use]
    pub fn evaluate_with_evidence(&self, tool_name: &str, response: &Value) -> PipelineOutcome {
        let context = PostInvocationContext::synthetic(tool_name);
        self.evaluate_with_context_and_evidence(&context, response)
    }

    #[must_use]
    pub fn evaluate_with_context_and_evidence(
        &self,
        context: &PostInvocationContext<'_>,
        response: &Value,
    ) -> PipelineOutcome {
        let mut current_response = response.clone();
        let mut escalations = Vec::new();
        let mut evidence = Vec::new();

        for hook in &self.hooks {
            let verdict = hook.inspect(context, &current_response);
            if let Some(ev) = hook.take_evidence() {
                evidence.push(ev);
            }
            match verdict {
                PostInvocationVerdict::Allow => continue,
                PostInvocationVerdict::Block(reason) => {
                    return PipelineOutcome {
                        verdict: PostInvocationVerdict::Block(reason),
                        escalations,
                        evidence,
                    };
                }
                PostInvocationVerdict::Redact(redacted) => {
                    current_response = redacted;
                }
                PostInvocationVerdict::Escalate(message) => {
                    escalations.push(message);
                }
            }
        }

        let verdict = if current_response != *response {
            PostInvocationVerdict::Redact(current_response)
        } else if !escalations.is_empty() {
            PostInvocationVerdict::Escalate(escalations.join("; "))
        } else {
            PostInvocationVerdict::Allow
        };
        PipelineOutcome {
            verdict,
            escalations,
            evidence,
        }
    }

    #[must_use]
    pub fn evaluate(
        &self,
        tool_name: &str,
        response: &Value,
    ) -> (PostInvocationVerdict, Vec<String>) {
        let outcome = self.evaluate_with_evidence(tool_name, response);
        (outcome.verdict, outcome.escalations)
    }
}

impl Default for PostInvocationPipeline {
    fn default() -> Self {
        Self::new()
    }
}
