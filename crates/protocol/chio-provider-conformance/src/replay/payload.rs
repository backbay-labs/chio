use super::*;

#[cfg(feature = "fixtures-bedrock")]
pub(super) fn bedrock_response_has_no_tool_uses(payload: &Value) -> bool {
    !bedrock_content_blocks(payload).iter().any(|block| {
        block
            .get("toolUse")
            .or_else(|| {
                if block.get("toolUseId").is_some() && block.get("name").is_some() {
                    Some(block)
                } else {
                    None
                }
            })
            .is_some()
    })
}

#[cfg(feature = "fixtures-bedrock")]
pub(super) fn bedrock_content_blocks(value: &Value) -> Vec<&Value> {
    if let Some(values) = value.as_array() {
        return values.iter().collect();
    }
    let Some(map) = value.as_object() else {
        return Vec::new();
    };
    if map.contains_key("toolUse") {
        return vec![value];
    }
    if let Some(content) = map.get("content").and_then(Value::as_array) {
        return content.iter().collect();
    }
    if let Some(content) = map
        .get("output")
        .and_then(|output| output.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(Value::as_array)
    {
        return content.iter().collect();
    }
    if let Some(content) = map
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(Value::as_array)
    {
        return content.iter().collect();
    }
    Vec::new()
}

#[cfg(feature = "fixtures-openai")]
pub(super) fn response_has_no_tool_calls(payload: &Value) -> bool {
    let output = payload.get("output").and_then(Value::as_array);
    let Some(output) = output else {
        return true;
    };

    !output.iter().any(|item| {
        item.get("type")
            .and_then(Value::as_str)
            .is_some_and(|value| value == "function_call")
    })
}

#[cfg(feature = "fixtures-anthropic")]
pub(super) fn anthropic_response_has_no_tool_uses(payload: &Value) -> bool {
    let body = anthropic_message_body(payload);
    let content = body.get("content").and_then(Value::as_array);
    let Some(content) = content else {
        return true;
    };

    !content.iter().any(|item| {
        item.get("type")
            .and_then(Value::as_str)
            .is_some_and(|value| value == "tool_use")
    })
}

#[cfg(feature = "fixtures-anthropic")]
pub(super) fn anthropic_message_body(payload: &Value) -> &Value {
    ["body", "response", "payload", "message"]
        .iter()
        .find_map(|field| payload.get(field).filter(|value| value.is_object()))
        .unwrap_or(payload)
}

#[cfg(feature = "fixtures-openai")]
pub(super) fn org_id_from_payload(payload: &Value) -> Option<String> {
    let headers = payload.get("headers")?.as_object()?;
    headers.iter().find_map(|(key, value)| {
        if is_openai_org_header(key) {
            header_value(value)
        } else {
            None
        }
    })
}

#[cfg(any(
    feature = "fixtures-gemini",
    feature = "fixtures-mistral",
    feature = "fixtures-groq",
    feature = "fixtures-ollama",
    feature = "fixtures-cohere"
))]
pub(super) fn header_from_payload(payload: &Value, expected_header: &str) -> Option<String> {
    let headers = payload.get("headers")?.as_object()?;
    headers.iter().find_map(|(key, value)| {
        if key.eq_ignore_ascii_case(expected_header) {
            header_value(value)
        } else {
            None
        }
    })
}

#[cfg(feature = "fixtures-anthropic")]
pub(super) fn anthropic_workspace_id_from_payload(payload: &Value) -> Option<String> {
    let headers = payload.get("headers")?.as_object()?;
    headers.iter().find_map(|(key, value)| {
        if is_anthropic_workspace_header(key) {
            header_value(value)
        } else {
            None
        }
    })
}

#[cfg(feature = "fixtures-bedrock")]
pub(super) fn bedrock_principal_from_payload(payload: &Value) -> Option<BedrockFixturePrincipal> {
    let headers = payload.get("headers")?.as_object()?;
    let caller_arn = headers.iter().find_map(|(key, value)| {
        if key.eq_ignore_ascii_case("x-chio-bedrock-caller-arn") {
            header_value(value)
        } else {
            None
        }
    })?;
    let account_id = headers.iter().find_map(|(key, value)| {
        if key.eq_ignore_ascii_case("x-chio-bedrock-account-id") {
            header_value(value)
        } else {
            None
        }
    })?;
    let assumed_role_session_arn = headers.iter().find_map(|(key, value)| {
        if key.eq_ignore_ascii_case("x-chio-bedrock-assumed-role-session-arn") {
            header_value(value)
        } else {
            None
        }
    });

    Some(BedrockFixturePrincipal {
        caller_arn,
        account_id,
        assumed_role_session_arn,
    })
}

#[cfg(feature = "fixtures-anthropic")]
pub(super) fn is_anthropic_workspace_header(key: &str) -> bool {
    key.eq_ignore_ascii_case("x-chio-anthropic-workspace-id")
        || key.eq_ignore_ascii_case("anthropic-workspace-id")
}

#[cfg(feature = "fixtures-openai")]
pub(super) fn is_openai_org_header(key: &str) -> bool {
    key.eq_ignore_ascii_case("openai-organization")
        || key.eq_ignore_ascii_case("openai-org-id")
        || key.eq_ignore_ascii_case("x-openai-organization")
}

#[cfg(any(
    feature = "fixtures-openai",
    feature = "fixtures-anthropic",
    feature = "fixtures-bedrock",
    feature = "fixtures-gemini",
    feature = "fixtures-mistral",
    feature = "fixtures-groq",
    feature = "fixtures-ollama",
    feature = "fixtures-cohere"
))]
pub(super) fn header_value(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => non_empty(value),
        Value::Array(values) => values.iter().find_map(header_value),
        _ => None,
    }
}

#[cfg(any(
    feature = "fixtures-openai",
    feature = "fixtures-anthropic",
    feature = "fixtures-bedrock",
    feature = "fixtures-gemini",
    feature = "fixtures-mistral",
    feature = "fixtures-groq",
    feature = "fixtures-ollama",
    feature = "fixtures-cohere"
))]
pub(super) fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}
