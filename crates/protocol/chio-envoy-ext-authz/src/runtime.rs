//! A deployable bridge to a durable Chio HTTP authority.
//!
//! The configured authority evaluates requests. Every returned decision is
//! checked against an operator-selected signer and this exact request before
//! Envoy is allowed to dispatch the upstream operation.
use crate::{EnvoyKernel, KernelError, ToolCallRequest, Verdict};
use async_trait::async_trait;
use chio_core_types::crypto::PublicKey;
use chio_http_core::{CallerIdentity, ChioHttpRequest, HttpReceipt};
use serde::Deserialize;
use std::time::Duration;

/// A bounded HTTP client for a pinned Chio authority.
pub struct HttpAuthorityKernel {
    client: reqwest::Client,
    endpoint: url::Url,
    signer: PublicKey,
}

#[derive(Deserialize)]
struct Evaluation {
    verdict: chio_http_core::Verdict,
    receipt: HttpReceipt,
}

impl HttpAuthorityKernel {
    /// Connect only to an explicitly configured authority. Plain HTTP is
    /// supported for loopback/pod-local networks; use HTTPS across hosts.
    pub fn new(base_url: &str, signer: PublicKey, timeout: Duration) -> Result<Self, KernelError> {
        let mut endpoint = url::Url::parse(base_url).map_err(KernelError::evaluation)?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !matches!(endpoint.path(), "" | "/")
        {
            return Err(KernelError::evaluation(
                "authority URL must be an HTTP(S) origin without credentials",
            ));
        }
        endpoint.set_path("/chio/evaluate");
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(KernelError::evaluation)?;
        Ok(Self {
            client,
            endpoint,
            signer,
        })
    }

    /// Whether the configured authority is responding to its health route.
    pub async fn ready(&self) -> bool {
        let mut url = self.endpoint.clone();
        url.set_path("/chio/health");
        self.client
            .get(url)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
    }

    async fn decision(
        &self,
        call: ToolCallRequest,
    ) -> Result<(Verdict, Option<String>), KernelError> {
        let method = serde_json::from_value(serde_json::Value::String(call.method))
            .map_err(KernelError::evaluation)?;
        // Each check receives a fresh bridge-owned identity. Caller-supplied
        // x-request-id cannot make an old receipt authorize a fresh effect.
        let mut request = ChioHttpRequest::new(
            uuid::Uuid::now_v7().to_string(),
            method,
            call.path.clone(),
            call.path,
            CallerIdentity::anonymous(),
        );
        for (key, value) in url::form_urlencoded::parse(call.query.as_bytes()) {
            if request
                .query
                .insert(key.into_owned(), value.into_owned())
                .is_some()
            {
                return Err(KernelError::evaluation(
                    "duplicate query parameters are unsupported",
                ));
            }
        }
        request.headers = call.headers.into_iter().collect();
        request.body_hash = call.body_hash;
        request.body_length = call.body_length;
        request.session_id = call.session_id;
        request.capability_id = call.capability_id;
        let mut post = self.client.post(self.endpoint.clone()).json(&request);
        if let Some(token) = call.capability_token {
            post = post.header("x-chio-capability", token);
        }
        let mut response = post.send().await.map_err(KernelError::evaluation)?;
        if !response.status().is_success() {
            return Err(KernelError::evaluation("authority refused evaluation"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(KernelError::evaluation)? {
            if bytes.len() + chunk.len() > 1_048_576 {
                return Err(KernelError::evaluation("authority response exceeded 1 MiB"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let result: Evaluation = serde_json::from_slice(&bytes).map_err(KernelError::evaluation)?;
        let receipt = result.receipt;
        request.route_pattern = receipt.route_pattern.clone();
        if receipt.kernel_key != self.signer
            || !receipt
                .verify_signature()
                .map_err(KernelError::evaluation)?
            || receipt.request_id != request.request_id
            || receipt.method != request.method
            || receipt.session_id != request.session_id
            || receipt.verdict != result.verdict
            || receipt.caller_identity_hash
                != request
                    .caller
                    .identity_hash()
                    .map_err(KernelError::evaluation)?
            || receipt.content_hash != request.content_hash().map_err(KernelError::evaluation)?
        {
            return Err(KernelError::evaluation(
                "authority receipt is not trusted or does not bind this request",
            ));
        }
        let verdict = match result.verdict {
            chio_http_core::Verdict::Allow if receipt.is_authorized() => Verdict::Allow,
            chio_http_core::Verdict::Deny {
                reason,
                guard,
                http_status,
                ..
            } => Verdict::Deny {
                reason,
                guard,
                http_status,
            },
            _ => {
                return Err(KernelError::evaluation(
                    "authority returned a non-authorizing outcome",
                ))
            }
        };
        Ok((verdict, Some(receipt.id)))
    }
}

#[async_trait]
impl EnvoyKernel for HttpAuthorityKernel {
    async fn evaluate(&self, request: ToolCallRequest) -> Result<Verdict, KernelError> {
        self.decision(request).await.map(|(verdict, _)| verdict)
    }
    async fn evaluate_with_receipt(
        &self,
        request: ToolCallRequest,
    ) -> Result<(Verdict, Option<String>), KernelError> {
        self.decision(request).await
    }
}
