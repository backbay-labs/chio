use crate::{host::Host, Run};
use anyhow::{Context, Result};
use chio_core::capability::token::CapabilityToken;
use serde_json::{json, Value};

/// A bounded tool loop. Model requests are made by the host. Every proposed
/// document/repository operation is submitted through the worker's capability.
pub async fn tool_loop(
    host: &Host,
    run: &Run,
    capability: &CapabilityToken,
    server: &str,
    instructions: &str,
    prompt: &str,
    tools: Value,
) -> Result<Value> {
    let gateway_key = std::env::var("AI_GATEWAY_API_KEY")
        .or_else(|_| std::env::var("VERCEL_OIDC_TOKEN"))
        .ok();
    let (endpoint, key, default_model) = if let Some(key) = gateway_key {
        (
            "https://ai-gateway.vercel.sh/v1/chat/completions",
            key,
            "openai/gpt-4.1-mini",
        )
    } else if std::env::var("CHIO_MODEL_PROVIDER").as_deref() == Ok("openai")
        || std::env::var("OPENROUTER_API_KEY").is_err()
    {
        ("https://api.openai.com/v1/chat/completions",std::env::var("OPENAI_API_KEY")
            .context("Set OPENAI_API_KEY or OPENROUTER_API_KEY on the application host to run a model worker")?,"gpt-4.1-mini")
    } else {
        (
            "https://openrouter.ai/api/v1/chat/completions",
            std::env::var("OPENROUTER_API_KEY")?,
            "openai/gpt-4.1-mini",
        )
    };
    let model = std::env::var("CHIO_MODEL").unwrap_or_else(|_| default_model.into());
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(90))
        .build()?;
    let mut messages = vec![
        json!({"role":"system","content":instructions}),
        json!({"role":"user","content":prompt}),
    ];
    let mut usage = Vec::new();
    for turn in 0..6 {
        run.emit(
            "model.started",
            "model",
            "Planning the next operation",
            json!({"model":model,"turn":turn+1}),
        )?;
        anyhow::ensure!(
            serde_json::to_vec(&messages)?.len() <= 160_000,
            "Worker context reached its 160 KB limit; narrow the input or task"
        );
        let response = client
            .post(endpoint)
            .bearer_auth(&key)
            .json(&json!({
                "model":model,"messages":messages,"tools":tools,"tool_choice":"auto",
                "max_tokens":1800,"temperature":0.1,
            }))
            .send()
            .await?;
        let status = response.status();
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            anyhow::ensure!(
                bytes.len().saturating_add(chunk.len()) <= 256_000,
                "Model response exceeded the 256 KB limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        let body: Value = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(
            status.is_success(),
            "Model provider returned HTTP {status}: {}",
            body.pointer("/error/message")
                .and_then(Value::as_str)
                .unwrap_or("Request failed")
        );
        if let Some(value) = body.get("usage") {
            usage.push(value.clone());
        }
        let message = body
            .pointer("/choices/0/message")
            .context("Model response contains no message")?
            .clone();
        let calls = message
            .get("tool_calls")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        messages.push(message.clone());
        if calls.is_empty() {
            let answer = message
                .get("content")
                .and_then(Value::as_str)
                .context("Model returned no answer")?;
            run.emit(
                "model.completed",
                "model",
                "Worker returned its answer",
                json!({"model":model,"answer":answer,"usage":usage}),
            )?;
            return Ok(json!({"answer":answer,"model":model,"usage":usage}));
        }
        anyhow::ensure!(
            calls.len() <= 8,
            "Model proposed too many operations in one turn"
        );
        for call in calls {
            let name = call
                .pointer("/function/name")
                .and_then(Value::as_str)
                .context("Tool call has no name")?;
            let id = call
                .get("id")
                .and_then(Value::as_str)
                .context("Tool call has no ID")?;
            let args = call
                .pointer("/function/arguments")
                .and_then(Value::as_str)
                .context("Tool call has no arguments")?;
            let result = match serde_json::from_str::<Value>(args) {
                Ok(arguments) => {
                    let result = host
                        .call(run, "model-worker", capability, server, name, arguments)
                        .await?;
                    json!({"allowed":result.allowed,"output":result.output,"receipt_id":result.receipt_id,"reason":result.reason})
                }
                Err(_) => json!({"error":"Tool arguments must be a JSON object"}),
            };
            messages.push(
                json!({"role":"tool","tool_call_id":id,"content":serde_json::to_string(&result)?}),
            );
        }
    }
    anyhow::bail!(
        "Worker reached its six-turn limit; inspect retained calls before starting another mission"
    )
}
