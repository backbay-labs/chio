use std::env;
use std::fs;
use std::process::Command;

use chio_provider_conformance::CaptureDirection;
use serde_json::Value;

use crate::cli::ScenarioSeed;
use crate::fixture::RecordPlan;
use crate::invoke::{captured_invocations, extract_bedrock_invocations, CapturedInvocation};
use crate::record::{
    capture_record, insert_payload_field, live_request_record, request_body, stamp_bedrock_headers,
};
use crate::util::{now_ts, sanitize_id};
use crate::RecordError;

pub(crate) const BEDROCK_REGION: &str = "us-east-1";

pub(crate) fn record_bedrock(
    seed: ScenarioSeed,
    profile: Option<&str>,
    caller_arn: &str,
    account_id: &str,
    assumed_role_session_arn: Option<&str>,
) -> Result<RecordPlan, RecordError> {
    let mut request_record = live_request_record(&seed);
    stamp_bedrock_headers(
        &mut request_record,
        caller_arn,
        account_id,
        assumed_role_session_arn,
    )?;
    let request_body = request_body(&request_record)?;
    let stream = request_record
        .payload
        .get("method")
        .and_then(Value::as_str)
        .is_some_and(|method| method == "ConverseStream")
        || request_body
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    if stream {
        return Err(RecordError::BedrockStreamUnsupported);
    }

    let response_payload = bedrock_converse(profile, &request_body)?;
    let mut response_record =
        capture_record(&seed, CaptureDirection::UpstreamResponse, response_payload);
    if let Some(tool_config) = request_body.get("toolConfig") {
        insert_payload_field(
            &mut response_record.payload,
            "toolConfig",
            tool_config.clone(),
        )?;
    }

    let invocations = bedrock_batch_invocations(
        &seed,
        caller_arn,
        account_id,
        assumed_role_session_arn,
        &response_record.payload,
    )?;
    Ok(RecordPlan {
        seed,
        request_record,
        response_records: vec![response_record],
        invocations,
    })
}

fn bedrock_batch_invocations(
    seed: &ScenarioSeed,
    caller_arn: &str,
    account_id: &str,
    assumed_role_session_arn: Option<&str>,
    payload: &Value,
) -> Result<Vec<CapturedInvocation>, RecordError> {
    let invocations = extract_bedrock_invocations(
        seed,
        caller_arn,
        account_id,
        assumed_role_session_arn,
        payload,
    )?;
    if invocations.is_empty() && seed.expected_invocations > 0 {
        return Err(RecordError::CaptureShape {
            provider: "bedrock",
            message: "response did not include toolUse content blocks".to_string(),
        });
    }
    Ok(captured_invocations(seed, invocations))
}

#[derive(Debug)]
pub(crate) struct BedrockIdentity {
    pub(crate) caller_arn: String,
    pub(crate) account_id: String,
    pub(crate) assumed_role_session_arn: Option<String>,
}

pub(crate) fn bedrock_caller_identity(
    profile: Option<&str>,
) -> Result<BedrockIdentity, RecordError> {
    let mut command = Command::new("aws");
    command.args(["sts", "get-caller-identity", "--output", "json"]);
    if let Some(profile) = profile {
        command.args(["--profile", profile]);
    }
    let output = command.output().map_err(|source| RecordError::AwsCli {
        message: format!("failed to run `aws sts get-caller-identity`: {source}"),
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(RecordError::AwsCli { message: stderr });
    }
    let value = serde_json::from_slice::<Value>(&output.stdout)?;
    let caller_arn = value
        .get("Arn")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| RecordError::AwsCli {
            message: "STS output was missing Arn".to_string(),
        })?;
    let account_id = value
        .get("Account")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| RecordError::AwsCli {
            message: "STS output was missing Account".to_string(),
        })?;
    let assumed_role_session_arn = if caller_arn.starts_with("arn:aws:sts::") {
        Some(caller_arn.clone())
    } else {
        None
    };
    Ok(BedrockIdentity {
        caller_arn,
        account_id,
        assumed_role_session_arn,
    })
}

fn bedrock_converse(profile: Option<&str>, request_body: &Value) -> Result<Value, RecordError> {
    let input_path = env::temp_dir().join(format!("chio-bedrock-{}.json", sanitize_id(&now_ts())));
    fs::write(&input_path, serde_json::to_vec(request_body)?).map_err(|source| {
        RecordError::WriteFixture {
            path: input_path.clone(),
            source,
        }
    })?;

    let mut command = Command::new("aws");
    command.args([
        "bedrock-runtime",
        "converse",
        "--region",
        BEDROCK_REGION,
        "--cli-input-json",
        &format!("file://{}", input_path.display()),
        "--output",
        "json",
    ]);
    if let Some(profile) = profile {
        command.args(["--profile", profile]);
    }
    let output = command.output().map_err(|source| RecordError::AwsCli {
        message: format!("failed to run `aws bedrock-runtime converse`: {source}"),
    })?;
    let _ = fs::remove_file(&input_path);
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(RecordError::AwsCli { message: stderr });
    }
    serde_json::from_slice::<Value>(&output.stdout).map_err(RecordError::from)
}
