//! Host-owned model connection. No credentials are serialized or given to workers.
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::time::Duration;

pub fn configured() -> bool {
    let name = if std::env::var("CHIO_MODEL_PROVIDER").as_deref() == Ok("openrouter") {
        "OPENROUTER_API_KEY"
    } else {
        "OPENAI_API_KEY"
    };
    std::env::var(name).is_ok_and(|s| !s.is_empty())
}

pub async fn ask(instructions: &str, input: Value) -> Result<Value> {
    let router = std::env::var("CHIO_MODEL_PROVIDER").as_deref() == Ok("openrouter");
    let (key_name, endpoint, default_model) = if router {
        (
            "OPENROUTER_API_KEY",
            "https://openrouter.ai/api/v1/chat/completions",
            "openai/gpt-4.1-mini",
        )
    } else {
        (
            "OPENAI_API_KEY",
            "https://api.openai.com/v1/chat/completions",
            "gpt-4.1-mini",
        )
    };
    let key = std::env::var(key_name).with_context(|| {
        format!("Set {key_name} in the host environment, or choose the reference mission")
    })?;
    let model = std::env::var("CHIO_MODEL").unwrap_or_else(|_| default_model.into());
    let body = json!({"model":model,"messages":[{"role":"system","content":instructions},{"role":"user","content":serde_json::to_string(&input)?}],"response_format":{"type":"json_object"},"max_tokens":4000,"temperature":0.1});
    anyhow::ensure!(
        serde_json::to_vec(&body)?.len() <= 160_000,
        "Model context exceeds 160 KB"
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(90))
        .build()?;
    let mut response = client
        .post(endpoint)
        .bearer_auth(key)
        .json(&body)
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "Model connection returned HTTP {}; check host credentials, quota, and model selection",
        response.status()
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        anyhow::ensure!(
            bytes.len() + chunk.len() <= 256_000,
            "Model response exceeds 256 KB"
        );
        bytes.extend_from_slice(&chunk);
    }
    let body: Value = serde_json::from_slice(&bytes)?;
    let answer = body
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .context("Model returned no answer")?;
    let parsed: Value = serde_json::from_str(answer).context("Model must return a JSON object")?;
    anyhow::ensure!(parsed.is_object(), "Model answer must be an object");
    Ok(json!({"answer":parsed,"model":model,"usage":body["usage"]}))
}
