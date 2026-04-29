use std::sync::Arc;
use std::time::{Duration, Instant};

use chio_bedrock_converse_adapter::{
    transport, BedrockAdapter, BedrockAdapterConfig, BEDROCK_CONVERSE_API_VERSION,
};
use chio_tool_call_fabric::{ProviderError, ReceiptId, VerdictResult};
use serde_json::json;
use std::hint::black_box;

const COLD_INIT_P99_BUDGET: Duration = Duration::from_millis(500);
const P99_SAMPLE_COUNT: usize = 128;

fn stream_bytes() -> Result<Vec<u8>, ProviderError> {
    let events = json!([
        {"messageStart": {"role": "assistant"}},
        {
            "contentBlockStart": {
                "contentBlockIndex": 0,
                "start": {
                    "toolUse": {
                        "toolUseId": "tooluse_bedrock_latency",
                        "name": "lookup_policy"
                    }
                }
            }
        },
        {
            "contentBlockDelta": {
                "contentBlockIndex": 0,
                "delta": {
                    "toolUse": {
                        "input": "{\"policy_id\":\"pol_latency\"}"
                    }
                }
            }
        },
        {"contentBlockStop": {"contentBlockIndex": 0}},
        {"messageStop": {"stopReason": "tool_use"}}
    ]);
    serde_json::to_vec(&events).map_err(|error| {
        ProviderError::Malformed(format!("Bedrock latency fixture encoding failed: {error}"))
    })
}

fn cold_adapter() -> Result<BedrockAdapter, ProviderError> {
    let config = BedrockAdapterConfig::new(
        "bedrock-latency",
        "Bedrock Converse Latency",
        "0.1.0",
        "deadbeef",
        "arn:aws:iam::123456789012:role/ChioLatencyBenchRole",
        "123456789012",
    )
    .with_assumed_role_session_arn(
        "arn:aws:sts::123456789012:assumed-role/ChioLatencyBenchRole/session-latency",
    );
    BedrockAdapter::new(config, Arc::new(transport::MockTransport::new())).map_err(|error| {
        ProviderError::Malformed(format!("Bedrock cold adapter init failed: {error}"))
    })
}

fn allow_verdict() -> VerdictResult {
    VerdictResult::Allow {
        redactions: vec![],
        receipt_id: ReceiptId("rcpt_bedrock_latency_allow".to_string()),
    }
}

fn run_cold_verdict_path() -> Result<(), ProviderError> {
    let adapter = cold_adapter()?;
    let stream = stream_bytes()?;
    let gated = adapter.gate_converse_stream(&stream, |invocation| {
        black_box(invocation);
        Ok(allow_verdict())
    })?;

    if gated.invocations.len() != 1 {
        return Err(ProviderError::Malformed(format!(
            "expected one Bedrock tool invocation, observed {}",
            gated.invocations.len()
        )));
    }
    if gated.verdicts.len() != 1 {
        return Err(ProviderError::Malformed(format!(
            "expected one Bedrock verdict, observed {}",
            gated.verdicts.len()
        )));
    }
    if adapter.api_version() != BEDROCK_CONVERSE_API_VERSION {
        return Err(ProviderError::Malformed(format!(
            "Bedrock API version drifted to {}",
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
        ProviderError::Malformed("Bedrock verdict latency bench produced no samples".to_string())
    })
}

#[test]
fn cold_init_p99_stays_under_500ms() {
    let p99 = match measure_p99() {
        Ok(p99) => p99,
        Err(error) => panic!("Bedrock verdict latency bench failed: {error}"),
    };

    assert!(
        p99 <= COLD_INIT_P99_BUDGET,
        "Bedrock cold-init verdict latency p99 {:?} exceeded {:?}",
        p99,
        COLD_INIT_P99_BUDGET
    );
}
