//! HTTP-backed external guard adapters.
//!
//! This crate hosts the concrete cloud guardrail and threat-intel guards that
//! need an HTTP transport dependency. The generic async adapter, retry,
//! caching, and circuit-breaker infrastructure remains in `chio-guards`.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::future::Future;
use std::thread;

use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError};

pub mod external;

pub use external::{
    denied_external_guard_ip, retry_with_jitter, retry_with_jitter_rng,
    validate_external_guard_url, validate_external_guard_url_with_resolver,
    validate_external_guard_url_without_dns, AsyncGuardAdapter, AsyncGuardAdapterBuilder,
    AsyncGuardAdapterConfig, AzureCategory, AzureCategoryBreakdown, AzureContentSafetyConfig,
    AzureContentSafetyGuard, AzureDecisionDetails, BackoffStrategy, BedrockDecisionDetails,
    BedrockGuardrailConfig, BedrockGuardrailGuard, BedrockSource, CircuitBreaker,
    CircuitBreakerConfig, CircuitOpenVerdict, CircuitState, Clock, ExternalGuard,
    ExternalGuardError, GuardCallContext, RateLimitedVerdict, RetryConfig, SafeBrowsingConfig,
    SafeBrowsingGuard, SnykConfig, SnykGuard, SnykSeverity, TokenBucket, TokioClock, TtlCache,
    VertexDecisionDetails, VertexProbability, VertexRatingBreakdown, VertexSafetyConfig,
    VertexSafetyGuard, VirusTotalConfig, VirusTotalGuard,
};

/// Synchronous kernel bridge for an async external guard adapter.
///
/// The kernel guard pipeline is synchronous today, so this wrapper executes the
/// async adapter on a Tokio runtime and optionally scopes the guard to a subset
/// of tool-name patterns.
pub struct ScopedAsyncGuard<E: ExternalGuard> {
    adapter: AsyncGuardAdapter<E>,
    tool_patterns: Vec<String>,
}

impl<E: ExternalGuard> ScopedAsyncGuard<E> {
    /// Wrap an async adapter for the kernel guard pipeline.
    pub fn new(adapter: AsyncGuardAdapter<E>, tool_patterns: Vec<String>) -> Self {
        Self {
            adapter,
            tool_patterns: normalize_tool_patterns(tool_patterns),
        }
    }

    fn matches_tool(&self, tool_name: &str) -> bool {
        self.tool_patterns.is_empty()
            || self
                .tool_patterns
                .iter()
                .any(|pattern| wildcard_matches(pattern, tool_name))
    }

    fn call_context(&self, ctx: &GuardContext<'_>) -> GuardCallContext {
        GuardCallContext {
            tool_name: ctx.request.tool_name.clone(),
            agent_id: ctx.agent_id.clone(),
            server_id: ctx.server_id.clone(),
            arguments_json: ctx.request.arguments.to_string(),
        }
    }

    fn block_on<T>(&self, future: impl Future<Output = T> + Send) -> Result<T, KernelError>
    where
        T: Send,
    {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => match handle.runtime_flavor() {
                tokio::runtime::RuntimeFlavor::MultiThread => {
                    Ok(tokio::task::block_in_place(|| handle.block_on(future)))
                }
                tokio::runtime::RuntimeFlavor::CurrentThread => {
                    self.block_on_fallback_thread(future)
                }
                flavor => Err(KernelError::GuardDenied(format!(
                    "external guard {} cannot run on Tokio runtime flavor {flavor:?}",
                    self.name()
                ))),
            },
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    KernelError::GuardDenied(format!(
                        "external guard {} could not start a runtime: {error}",
                        self.name()
                    ))
                })
                .map(|runtime| runtime.block_on(future)),
        }
    }

    fn block_on_fallback_thread<T>(
        &self,
        future: impl Future<Output = T> + Send,
    ) -> Result<T, KernelError>
    where
        T: Send,
    {
        let guard_name = self.name().to_string();
        let runtime_guard_name = guard_name.clone();
        thread::scope(|scope| {
            let handle = scope.spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| {
                        KernelError::GuardDenied(format!(
                            "external guard {runtime_guard_name} could not start a fallback runtime: {error}"
                        ))
                    })?;
                Ok(runtime.block_on(future))
            });
            handle.join().map_err(|_| {
                KernelError::GuardDenied(format!(
                    "external guard {guard_name} fallback runtime thread panicked"
                ))
            })?
        })
    }
}

fn normalize_tool_patterns(patterns: Vec<String>) -> Vec<String> {
    patterns
        .into_iter()
        .filter_map(|pattern| {
            let trimmed = pattern.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
        .collect()
}

impl<E: ExternalGuard> Guard for ScopedAsyncGuard<E> {
    fn name(&self) -> &str {
        self.adapter.name()
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        // By design: a tool-scoped guard returns Allow for traffic outside
        // its scope. The deny-by-default contract is enforced by the
        // composing authority layer, not by this single scoped guard.
        if !self.matches_tool(&ctx.request.tool_name) {
            return Ok(GuardDecision::allow());
        }

        let call_ctx = self.call_context(ctx);
        self.block_on(self.adapter.evaluate(&call_ctx))
            .map(GuardDecision::from_verdict)
    }
}

fn wildcard_matches(pattern: &str, target: &str) -> bool {
    let pattern = pattern.as_bytes();
    let target = target.as_bytes();
    let mut pattern_index = 0usize;
    let mut target_index = 0usize;
    let mut star_index: Option<usize> = None;
    let mut match_index = 0usize;

    while target_index < target.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == target[target_index])
        {
            pattern_index += 1;
            target_index += 1;
            continue;
        }
        if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            match_index = target_index;
            continue;
        }
        if let Some(star) = star_index {
            pattern_index = star + 1;
            match_index += 1;
            target_index = match_index;
            continue;
        }
        return false;
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }

    pattern_index == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use chio_core_types::{
        capability::{
            scope::ChioScope,
            token::{CapabilityToken, CapabilityTokenBody},
        },
        Keypair,
    };
    use chio_kernel::Verdict;
    use std::sync::Arc;

    struct AllowExternalGuard;

    #[async_trait]
    impl ExternalGuard for AllowExternalGuard {
        fn name(&self) -> &str {
            "allow-external"
        }

        fn cache_key(&self, _ctx: &GuardCallContext) -> Option<String> {
            None
        }

        async fn eval(&self, _ctx: &GuardCallContext) -> Result<Verdict, ExternalGuardError> {
            Ok(Verdict::Allow)
        }
    }

    struct DenyExternalGuard;

    #[async_trait]
    impl ExternalGuard for DenyExternalGuard {
        fn name(&self) -> &str {
            "deny-external"
        }

        fn cache_key(&self, _ctx: &GuardCallContext) -> Option<String> {
            None
        }

        async fn eval(&self, _ctx: &GuardCallContext) -> Result<Verdict, ExternalGuardError> {
            Ok(Verdict::Deny)
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn scoped_async_guard_uses_fallback_runtime_on_current_thread_tokio() {
        let adapter = AsyncGuardAdapter::builder(Arc::new(AllowExternalGuard)).build();
        let guard = ScopedAsyncGuard::new(adapter, Vec::new());
        let context = GuardCallContext {
            tool_name: "echo".to_string(),
            agent_id: "agent".to_string(),
            server_id: "server".to_string(),
            arguments_json: "{}".to_string(),
        };

        let verdict = guard
            .block_on(guard.adapter.evaluate(&context))
            .expect("current-thread fallback should evaluate guard");

        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn scoped_async_guard_blank_patterns_do_not_disable_guard() {
        let adapter = AsyncGuardAdapter::builder(Arc::new(DenyExternalGuard)).build();
        let guard = ScopedAsyncGuard::new(
            adapter,
            vec![String::new(), " \t\n".to_string(), "  ".to_string()],
        );
        let keypair = Keypair::generate();
        let scope = ChioScope::default();
        let agent_id = keypair.public_key().to_hex();
        let server_id = "srv-test".to_string();
        let cap_body = CapabilityTokenBody {
            id: "cap-test".to_string(),
            issuer: keypair.public_key(),
            subject: keypair.public_key(),
            scope: scope.clone(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        };
        let capability =
            CapabilityToken::sign(cap_body, &keypair).expect("test capability should sign");
        let request = chio_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability,
            tool_name: "send_email".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({"to": "ops@example.com"}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        let context = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let verdict = guard
            .evaluate(&context)
            .expect("scoped guard should evaluate");

        assert_eq!(verdict, Verdict::Deny);
    }
}
