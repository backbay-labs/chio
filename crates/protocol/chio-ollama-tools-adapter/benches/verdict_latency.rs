use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chio_ollama_tools_adapter::{
    transport, OllamaAdapter, OllamaAdapterConfig, OLLAMA_API_VERSION,
};
use chio_tool_call_fabric::{ProviderError, ReceiptId, VerdictResult};
use serde_json::json;

const COLD_INIT_P99_BUDGET: Duration = Duration::from_millis(500);
const P99_SAMPLE_COUNT: usize = 128;

fn stream_bytes() -> Result<Vec<u8>, ProviderError> {
    let payload = json!({
        "model": "llama3.2:1b",
        "message": {
            "role": "assistant",
            "tool_calls": [
                {"function": {"name": "lookup_policy", "arguments": {"policy_id": "pol_latency"}}}
            ]
        },
        "done": true
    });
    let body = serde_json::to_vec(&payload).map_err(|error| {
        ProviderError::Malformed(format!("Ollama latency fixture encoding failed: {error}"))
    })?;
    let mut ndjson: Vec<u8> = Vec::with_capacity(body.len() + 1);
    ndjson.extend_from_slice(&body);
    ndjson.push(b'\n');
    Ok(ndjson)
}

fn cold_adapter() -> OllamaAdapter {
    let config = OllamaAdapterConfig::new(
        "ollama-latency",
        "Ollama Latency",
        "0.1.0",
        "deadbeef",
        "local_chio_latency",
    );
    OllamaAdapter::new(
        config,
        Arc::new(transport::MockTransport::new("mock://ollama")),
    )
}

fn allow_verdict() -> VerdictResult {
    VerdictResult::Allow {
        redactions: vec![],
        receipt_id: ReceiptId("rcpt_ollama_latency_allow".to_string()),
    }
}

fn run_cold_verdict_path() -> Result<(), ProviderError> {
    let adapter = cold_adapter();
    let stream = stream_bytes()?;
    let gated = adapter.gate_sse_stream(&stream, |invocation| {
        black_box(invocation);
        Ok(allow_verdict())
    })?;

    if gated.invocations.len() != 1 {
        return Err(ProviderError::Malformed(format!(
            "expected one Ollama tool invocation, observed {}",
            gated.invocations.len()
        )));
    }
    if adapter.api_version() != OLLAMA_API_VERSION {
        return Err(ProviderError::Malformed(format!(
            "Ollama API version drifted to {}",
            adapter.api_version()
        )));
    }
    black_box(gated);
    Ok(())
}

fn measure_p99() -> Result<Duration, ProviderError> {
    let mut samples = Vec::with_capacity(P99_SAMPLE_COUNT);
    for _ in 0..P99_SAMPLE_COUNT {
        let started = Instant::now();
        run_cold_verdict_path()?;
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let p99_index = ((samples.len() * 99).div_ceil(100)).saturating_sub(1);
    samples.get(p99_index).copied().ok_or_else(|| {
        ProviderError::Malformed("Ollama verdict latency bench produced no samples".to_string())
    })
}

#[test]
fn cold_init_p99_stays_under_500ms() {
    let p99 = match measure_p99() {
        Ok(p99) => p99,
        Err(error) => panic!("Ollama verdict latency bench failed: {error}"),
    };
    assert!(
        p99 <= COLD_INIT_P99_BUDGET,
        "Ollama cold-init verdict latency p99 {:?} exceeded {:?}",
        p99,
        COLD_INIT_P99_BUDGET
    );
}
