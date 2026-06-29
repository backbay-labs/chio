use std::time::SystemTime;

use chio_provider_conformance::{canonical_json_bytes_for, CaptureRecord};
use chio_tool_call_fabric::{
    Principal, ProvenanceStamp, ProviderId, ReceiptId, ToolInvocation, VerdictResult,
};
use serde_json::{json, Value};

use crate::cli::ScenarioSeed;
use crate::util::{now_ts, required_json_str, sanitize_id, seed_api_snapshot};
use crate::RecordError;

#[derive(Debug)]
pub(crate) struct CapturedInvocation {
    pub(crate) invocation: ToolInvocation,
    pub(crate) verdict: VerdictResult,
    pub(crate) receipt_id: String,
    pub(crate) received_at: String,
}

pub(crate) fn extract_openai_invocations(
    seed: &ScenarioSeed,
    org_id: &str,
    payload: &Value,
) -> Result<Vec<ToolInvocation>, RecordError> {
    let output = payload
        .get("output")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    output
        .iter()
        .filter(|item| item.get("type").and_then(Value::as_str) == Some("function_call"))
        .map(|item| openai_invocation_from_item(seed, org_id, item))
        .collect()
}

pub(crate) fn openai_invocation_from_stream_record(
    seed: &ScenarioSeed,
    org_id: &str,
    record: &CaptureRecord,
) -> Result<Option<ToolInvocation>, RecordError> {
    if record.payload.get("event").and_then(Value::as_str) != Some("response.output_item.done") {
        return Ok(None);
    }
    let Some(item) = record.payload.get("data").and_then(|data| data.get("item")) else {
        return Ok(None);
    };
    if item.get("type").and_then(Value::as_str) != Some("function_call") {
        return Ok(None);
    }
    openai_invocation_from_item(seed, org_id, item).map(Some)
}

fn openai_invocation_from_item(
    seed: &ScenarioSeed,
    org_id: &str,
    item: &Value,
) -> Result<ToolInvocation, RecordError> {
    let request_id = required_json_str(item, "call_id", &seed.path)?;
    let tool_name = required_json_str(item, "name", &seed.path)?;
    let arguments_text = required_json_str(item, "arguments", &seed.path)?;
    let arguments = serde_json::from_str::<Value>(arguments_text)?;
    tool_invocation(
        ProviderId::OpenAi,
        tool_name,
        arguments,
        request_id,
        openai_api_version(seed),
        Principal::OpenAiOrg {
            org_id: org_id.to_string(),
        },
    )
}

pub(crate) fn extract_anthropic_invocations(
    seed: &ScenarioSeed,
    workspace_id: &str,
    payload: &Value,
) -> Result<Vec<ToolInvocation>, RecordError> {
    let content = payload
        .get("content")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    content
        .iter()
        .filter(|item| item.get("type").and_then(Value::as_str) == Some("tool_use"))
        .map(|item| anthropic_invocation_from_block(seed, workspace_id, item))
        .collect()
}

pub(crate) fn anthropic_invocation_from_stream_record(
    seed: &ScenarioSeed,
    workspace_id: &str,
    record: &CaptureRecord,
) -> Result<Option<ToolInvocation>, RecordError> {
    if record.payload.get("event").and_then(Value::as_str) != Some("content_block_start") {
        return Ok(None);
    }
    let Some(block) = record
        .payload
        .get("data")
        .and_then(|data| data.get("content_block"))
    else {
        return Ok(None);
    };
    if block.get("type").and_then(Value::as_str) != Some("tool_use") {
        return Ok(None);
    }
    anthropic_invocation_from_block(seed, workspace_id, block).map(Some)
}

fn anthropic_invocation_from_block(
    seed: &ScenarioSeed,
    workspace_id: &str,
    block: &Value,
) -> Result<ToolInvocation, RecordError> {
    let request_id = required_json_str(block, "id", &seed.path)?;
    let tool_name = required_json_str(block, "name", &seed.path)?;
    let arguments = block.get("input").cloned().unwrap_or_else(|| json!({}));
    tool_invocation(
        ProviderId::Anthropic,
        tool_name,
        arguments,
        request_id,
        seed_api_snapshot(seed).unwrap_or_else(|| "2023-06-01".to_string()),
        Principal::AnthropicWorkspace {
            workspace_id: workspace_id.to_string(),
        },
    )
}

pub(crate) fn extract_bedrock_invocations(
    seed: &ScenarioSeed,
    caller_arn: &str,
    account_id: &str,
    assumed_role_session_arn: Option<&str>,
    payload: &Value,
) -> Result<Vec<ToolInvocation>, RecordError> {
    let Some(content) = payload
        .get("output")
        .and_then(|output| output.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(Value::as_array)
    else {
        return Ok(Vec::new());
    };
    content
        .iter()
        .filter_map(|block| block.get("toolUse"))
        .map(|tool_use| {
            bedrock_invocation_from_tool_use(
                seed,
                caller_arn,
                account_id,
                assumed_role_session_arn,
                tool_use,
            )
        })
        .collect()
}

fn bedrock_invocation_from_tool_use(
    seed: &ScenarioSeed,
    caller_arn: &str,
    account_id: &str,
    assumed_role_session_arn: Option<&str>,
    tool_use: &Value,
) -> Result<ToolInvocation, RecordError> {
    let request_id = required_json_str(tool_use, "toolUseId", &seed.path)?;
    let tool_name = required_json_str(tool_use, "name", &seed.path)?;
    let arguments = tool_use.get("input").cloned().unwrap_or_else(|| json!({}));
    tool_invocation(
        ProviderId::Bedrock,
        tool_name,
        arguments,
        request_id,
        seed_api_snapshot(seed).unwrap_or_else(|| "bedrock.converse.v1".to_string()),
        Principal::BedrockIam {
            caller_arn: caller_arn.to_string(),
            account_id: account_id.to_string(),
            assumed_role_session_arn: assumed_role_session_arn.map(ToString::to_string),
        },
    )
}

fn tool_invocation(
    provider: ProviderId,
    tool_name: &str,
    arguments: Value,
    request_id: &str,
    api_version: String,
    principal: Principal,
) -> Result<ToolInvocation, RecordError> {
    Ok(ToolInvocation {
        provider,
        tool_name: tool_name.to_string(),
        arguments: canonical_json_bytes_for("recorded tool arguments", &arguments).map_err(
            |source| RecordError::CaptureShape {
                provider: "provider",
                message: source.to_string(),
            },
        )?,
        provenance: ProvenanceStamp {
            provider,
            request_id: request_id.to_string(),
            api_version,
            principal,
            received_at: SystemTime::now(),
        },
    })
}

fn openai_api_version(seed: &ScenarioSeed) -> String {
    seed_api_snapshot(seed)
        .map(|snapshot| {
            if snapshot.starts_with("responses.") {
                snapshot
            } else {
                format!("responses.{snapshot}")
            }
        })
        .unwrap_or_else(|| "responses.2026-04-25".to_string())
}

pub(crate) fn captured_invocations(
    seed: &ScenarioSeed,
    invocations: Vec<ToolInvocation>,
) -> Vec<CapturedInvocation> {
    invocations
        .into_iter()
        .enumerate()
        .map(|(index, invocation)| {
            let verdict = allow_verdict(seed, &invocation, index);
            let receipt_id = receipt_id_from_verdict(&verdict);
            CapturedInvocation {
                invocation,
                verdict,
                receipt_id,
                received_at: now_ts(),
            }
        })
        .collect()
}

fn allow_verdict(seed: &ScenarioSeed, invocation: &ToolInvocation, index: usize) -> VerdictResult {
    let receipt_id = format!(
        "rcpt_{}_{}_allow",
        sanitize_id(&seed.scenario),
        sanitize_id(&invocation.provenance.request_id)
    );
    let receipt_id = if index == 0 {
        receipt_id
    } else {
        format!("{receipt_id}_{index}")
    };
    VerdictResult::Allow {
        redactions: Vec::new(),
        receipt_id: ReceiptId(receipt_id),
    }
}

fn receipt_id_from_verdict(verdict: &VerdictResult) -> String {
    match verdict {
        VerdictResult::Allow { receipt_id, .. } | VerdictResult::Deny { receipt_id, .. } => {
            receipt_id.0.clone()
        }
    }
}
