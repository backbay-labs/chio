//! Post-invocation hook pipeline executed after a tool returns output.

use chio_core::receipt::metadata::GuardEvidence;
use chio_core::{capability::scope::ChioScope, AgentId, ServerId};
use serde::Serialize;
use serde_json::Value;
use std::sync::{Mutex, MutexGuard};

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

    /// Stable identity for deterministic, non-blocking durable evaluation.
    ///
    /// Returning an identity asserts that `inspect` is a pure function of the
    /// request context and response, and that it returns only `Allow`,
    /// `Redact`, or `Escalate`. Hooks without this contract remain usable on
    /// non-durable paths and are rejected before a durable dispatch starts.
    fn durable_identity(&self) -> Result<Option<PostInvocationHookIdentity>, String> {
        Ok(None)
    }

    fn take_evidence(&self) -> Option<GuardEvidence> {
        None
    }
}

/// Canonical implementation and configuration identity for a durable hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostInvocationHookIdentity {
    component_id: String,
    component_version: String,
    implementation_digest: String,
}

impl PostInvocationHookIdentity {
    /// Bind an implementation tag and its complete effective configuration.
    pub fn from_canonical_config<T: Serialize>(
        component_id: impl Into<String>,
        component_version: impl Into<String>,
        implementation_tag: &str,
        configuration: &T,
    ) -> Result<Self, String> {
        #[derive(Serialize)]
        struct IdentityPreimage<'a, T> {
            schema: &'static str,
            component_id: &'a str,
            component_version: &'a str,
            implementation_tag: &'a str,
            configuration: &'a T,
        }

        let component_id = component_id.into();
        let component_version = component_version.into();
        for (field, value) in [
            ("component_id", component_id.as_str()),
            ("component_version", component_version.as_str()),
            ("implementation_tag", implementation_tag),
        ] {
            if value.trim().is_empty() || value.len() > 128 {
                return Err(format!(
                    "post-invocation {field} must contain 1 to 128 characters"
                ));
            }
        }
        let preimage = IdentityPreimage {
            schema: "chio.post-invocation-hook-identity.v1",
            component_id: &component_id,
            component_version: &component_version,
            implementation_tag,
            configuration,
        };
        let canonical = crate::canonical_json_bytes(&preimage)
            .map_err(|error| format!("post-invocation identity is not canonical JSON: {error}"))?;
        Ok(Self {
            component_id,
            component_version,
            implementation_digest: crate::sha256_hex(&canonical),
        })
    }

    #[must_use]
    pub fn component_id(&self) -> &str {
        &self.component_id
    }

    #[must_use]
    pub fn component_version(&self) -> &str {
        &self.component_version
    }

    #[must_use]
    pub fn implementation_digest(&self) -> &str {
        &self.implementation_digest
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
enum DurablePostInvocationVerdict {
    Allow,
    Redact,
    Escalate { message: String },
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurablePipelineStepResult {
    schema: &'static str,
    identity: PostInvocationHookIdentity,
    verdict: DurablePostInvocationVerdict,
    response: Value,
    evidence: Option<GuardEvidence>,
}

pub(crate) struct DurablePipelineOutcome {
    pub(crate) outcome: PipelineOutcome,
    pub(crate) step_results: Vec<DurablePipelineStepResult>,
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
    evaluation_lock: Mutex<()>,
}

impl PostInvocationPipeline {
    #[must_use]
    pub fn new() -> Self {
        Self {
            hooks: Vec::new(),
            evaluation_lock: Mutex::new(()),
        }
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

    pub(crate) fn durable_identities(&self) -> Result<Vec<PostInvocationHookIdentity>, String> {
        self.hooks
            .iter()
            .map(|hook| {
                hook.durable_identity()?.ok_or_else(|| {
                    format!(
                        "post-invocation hook {:?} has no durable implementation identity",
                        hook.name()
                    )
                })
            })
            .collect()
    }

    pub(crate) fn evaluate_durable_with_context_and_evidence(
        &self,
        context: &PostInvocationContext<'_>,
        response: &Value,
        expected_identities: &[PostInvocationHookIdentity],
    ) -> Result<DurablePipelineOutcome, String> {
        let _evaluation = self.lock_evaluation();
        if self.hooks.len() != expected_identities.len() {
            return Err("post-invocation pipeline changed after durable admission".to_owned());
        }

        let mut current_response = response.clone();
        let mut escalations = Vec::new();
        let mut evidence = Vec::new();
        let mut step_results = Vec::with_capacity(self.hooks.len());

        for (hook, expected_identity) in self.hooks.iter().zip(expected_identities) {
            let identity = hook.durable_identity()?.ok_or_else(|| {
                format!(
                    "post-invocation hook {:?} lost its durable implementation identity",
                    hook.name()
                )
            })?;
            if &identity != expected_identity {
                return Err(format!(
                    "post-invocation hook {:?} changed after durable admission",
                    hook.name()
                ));
            }
            let verdict = hook.inspect(context, &current_response);
            let hook_evidence = hook.take_evidence();
            if let Some(item) = hook_evidence.clone() {
                evidence.push(item);
            }
            let durable_verdict = match verdict {
                PostInvocationVerdict::Allow => DurablePostInvocationVerdict::Allow,
                PostInvocationVerdict::Redact(redacted) => {
                    current_response = redacted;
                    DurablePostInvocationVerdict::Redact
                }
                PostInvocationVerdict::Escalate(message) => {
                    escalations.push(message.clone());
                    DurablePostInvocationVerdict::Escalate { message }
                }
                PostInvocationVerdict::Block(_) => {
                    return Err(format!(
                        "durable post-invocation hook {:?} violated its non-blocking contract",
                        hook.name()
                    ));
                }
            };
            step_results.push(DurablePipelineStepResult {
                schema: "chio.durable-post-invocation-step-result.v1",
                identity,
                verdict: durable_verdict,
                response: current_response.clone(),
                evidence: hook_evidence,
            });
        }

        let verdict = if current_response != *response {
            PostInvocationVerdict::Redact(current_response)
        } else if !escalations.is_empty() {
            PostInvocationVerdict::Escalate(escalations.join("; "))
        } else {
            PostInvocationVerdict::Allow
        };
        Ok(DurablePipelineOutcome {
            outcome: PipelineOutcome {
                verdict,
                escalations,
                evidence,
            },
            step_results,
        })
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
        let _evaluation = self.lock_evaluation();
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

    fn lock_evaluation(&self) -> MutexGuard<'_, ()> {
        match self.evaluation_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    struct OverlapDetectingHook {
        active: Arc<AtomicUsize>,
        overlapped: Arc<AtomicBool>,
    }

    impl PostInvocationHook for OverlapDetectingHook {
        fn name(&self) -> &str {
            "overlap-detecting-hook"
        }

        fn inspect(
            &self,
            _ctx: &PostInvocationContext<'_>,
            _response: &Value,
        ) -> PostInvocationVerdict {
            if self.active.fetch_add(1, Ordering::SeqCst) != 0 {
                self.overlapped.store(true, Ordering::SeqCst);
            }
            thread::sleep(Duration::from_millis(25));
            self.active.fetch_sub(1, Ordering::SeqCst);
            PostInvocationVerdict::Allow
        }
    }

    #[test]
    fn pipeline_serializes_hook_evaluation_and_evidence_side_channels() {
        let active = Arc::new(AtomicUsize::new(0));
        let overlapped = Arc::new(AtomicBool::new(false));
        let mut pipeline = PostInvocationPipeline::new();
        pipeline.add(Box::new(OverlapDetectingHook {
            active,
            overlapped: overlapped.clone(),
        }));
        let pipeline = Arc::new(pipeline);
        let start = Arc::new(Barrier::new(3));
        let workers = (0..2)
            .map(|index| {
                let pipeline = pipeline.clone();
                let start = start.clone();
                thread::spawn(move || {
                    start.wait();
                    let _ = pipeline
                        .evaluate_with_evidence("tool", &serde_json::json!({"index": index}));
                })
            })
            .collect::<Vec<_>>();
        start.wait();
        for worker in workers {
            worker.join().expect("post-invocation worker");
        }

        assert!(!overlapped.load(Ordering::SeqCst));
    }
}
