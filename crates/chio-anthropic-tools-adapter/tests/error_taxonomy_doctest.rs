use std::collections::BTreeSet;
use std::sync::Arc;

use chio_anthropic_tools_adapter::transport::MockTransport;
use chio_anthropic_tools_adapter::{AnthropicAdapter, AnthropicAdapterConfig};
use chio_tool_call_fabric::{ProviderError, ProviderRequest, ReceiptId, Redaction, VerdictResult};
use serde_json::{json, Value};

const README: &str = include_str!("../README.md");

#[derive(Debug)]
struct TaxonomyRow {
    class: String,
    envelope: Value,
}

fn adapter() -> AnthropicAdapter {
    let config = AnthropicAdapterConfig::new(
        "anthropic-1",
        "Anthropic Messages",
        "0.1.0",
        "deadbeef",
        "wks_chio_demo",
    );
    AnthropicAdapter::new(config, Arc::new(MockTransport::new()))
}

fn raw(value: Value) -> Result<ProviderRequest, String> {
    serde_json::to_vec(&value)
        .map(ProviderRequest)
        .map_err(|error| format!("failed to encode provider request: {error}"))
}

fn allow_verdict() -> VerdictResult {
    VerdictResult::Allow {
        redactions: Vec::<Redaction>::new(),
        receipt_id: ReceiptId("rcpt_taxonomy_allow".to_string()),
    }
}

fn tool_use_stream() -> Vec<u8> {
    br#"event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_weather_1","name":"get_weather","input":{}}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_stop
data: {"type":"message_stop"}

"#
    .to_vec()
}

fn malformed_delta_stream() -> Vec<u8> {
    br#"event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}

"#
    .to_vec()
}

#[test]
fn readme_taxonomy_table_covers_adapter_visible_classes() -> Result<(), String> {
    let rows = taxonomy_rows()?;
    let classes = classes(&rows);
    for required in [
        "RateLimited",
        "ContentPolicy",
        "BadToolArgs",
        "Upstream5xx",
        "TransportTimeout",
        "VerdictBudgetExceeded",
        "Malformed",
    ] {
        if !classes.contains(required) {
            return Err(format!(
                "README taxonomy did not cover ProviderError::{required}"
            ));
        }
    }

    if classes.contains("Other") {
        return Err("README taxonomy must not map native envelopes to ProviderError::Other".into());
    }

    if README.contains('\u{2014}') {
        return Err("README taxonomy introduced an em dash".into());
    }

    Ok(())
}

#[test]
fn readme_taxonomy_envelopes_are_class_specific() -> Result<(), String> {
    for row in taxonomy_rows()? {
        match row.class.as_str() {
            "RateLimited" => {
                require_status(&row, 429)?;
                require_error_type(&row, "rate_limit_error")?;
            }
            "ContentPolicy" => {
                require_body_string(&row, "/body/stop_reason", "refusal")?;
            }
            "BadToolArgs" => {
                require_body_string(&row, "/type", "tool_use")?;
                if row.envelope.get("input").is_some_and(Value::is_object) {
                    return Err("BadToolArgs envelope input must not already be an object".into());
                }
            }
            "Upstream5xx" => {
                let status = status(&row)
                    .ok_or_else(|| "Upstream5xx envelope did not include status".to_string())?;
                if !(500..600).contains(&status) {
                    return Err(format!("Upstream5xx envelope used non-5xx status {status}"));
                }
                require_error_type(&row, "overloaded_error")?;
            }
            "TransportTimeout" => {
                require_body_string(&row, "/transport", "timeout")?;
                let elapsed_ms = row
                    .envelope
                    .get("elapsed_ms")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "TransportTimeout envelope missed elapsed_ms".to_string())?;
                if elapsed_ms == 0 {
                    return Err("TransportTimeout elapsed_ms must be non-zero".into());
                }
            }
            "VerdictBudgetExceeded" => {
                let observed_ms = row
                    .envelope
                    .get("observed_ms")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        "VerdictBudgetExceeded envelope missed observed_ms".to_string()
                    })?;
                let budget_ms = row
                    .envelope
                    .get("budget_ms")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "VerdictBudgetExceeded envelope missed budget_ms".to_string())?;
                if observed_ms <= budget_ms {
                    return Err("VerdictBudgetExceeded envelope must exceed budget_ms".into());
                }
            }
            "Malformed" => {
                require_body_string(&row, "/event", "content_block_delta")?;
            }
            other => {
                return Err(format!(
                    "unexpected ProviderError class documented: {other}"
                ));
            }
        }
    }

    Ok(())
}

#[test]
fn current_adapter_paths_match_documented_classes() -> Result<(), String> {
    let classes = classes(&taxonomy_rows()?);
    for required in ["BadToolArgs", "Malformed", "VerdictBudgetExceeded"] {
        if !classes.contains(required) {
            return Err(format!(
                "README taxonomy did not cover current class {required}"
            ));
        }
    }

    let adapter = adapter();
    let bad_args = adapter.lift_batch(raw(json!({
        "content": [
            {
                "type": "tool_use",
                "id": "toolu_bad_args",
                "name": "get_weather",
                "input": "not an object"
            }
        ]
    }))?);
    require_provider_error(bad_args, "BadToolArgs")?;

    let malformed =
        adapter.gate_sse_stream(&malformed_delta_stream(), |_invocation| Ok(allow_verdict()));
    require_provider_error(malformed, "Malformed")?;

    let budget = adapter.gate_sse_stream(&tool_use_stream(), |_invocation| {
        Err(ProviderError::VerdictBudgetExceeded {
            observed_ms: 300,
            budget_ms: 250,
        })
    });
    require_provider_error(budget, "VerdictBudgetExceeded")?;

    Ok(())
}

fn taxonomy_rows() -> Result<Vec<TaxonomyRow>, String> {
    let mut in_table = false;
    let mut rows = Vec::new();

    for line in README.lines() {
        let trimmed = line.trim();
        if trimmed == "<!-- error-taxonomy:start -->" {
            in_table = true;
            continue;
        }
        if trimmed == "<!-- error-taxonomy:end -->" {
            break;
        }
        if !in_table || !trimmed.starts_with('|') {
            continue;
        }
        if trimmed.contains("ProviderError class") || trimmed.contains("---") {
            continue;
        }

        let cells = table_cells(trimmed)?;
        if cells.len() != 4 {
            return Err(format!(
                "taxonomy row should have 4 cells, found {} in {trimmed}",
                cells.len()
            ));
        }

        rows.push(TaxonomyRow {
            class: extract_provider_error_class(&cells[0])?,
            envelope: extract_inline_json(&cells[1])?,
        });
    }

    if rows.is_empty() {
        return Err("README taxonomy table was not found".into());
    }

    Ok(rows)
}

fn table_cells(line: &str) -> Result<Vec<String>, String> {
    let without_prefix = line
        .strip_prefix('|')
        .ok_or_else(|| format!("taxonomy row missed leading pipe: {line}"))?;
    let without_suffix = without_prefix
        .strip_suffix('|')
        .ok_or_else(|| format!("taxonomy row missed trailing pipe: {line}"))?;
    Ok(without_suffix
        .split('|')
        .map(|cell| cell.trim().to_string())
        .collect())
}

fn extract_provider_error_class(cell: &str) -> Result<String, String> {
    for token in cell.split('`') {
        if let Some(class) = token.strip_prefix("ProviderError::") {
            return Ok(class.to_string());
        }
    }
    Err(format!(
        "cell did not contain a ProviderError class: {cell}"
    ))
}

fn extract_inline_json(cell: &str) -> Result<Value, String> {
    for token in cell.split('`') {
        let candidate = token.trim();
        if candidate.starts_with('{') {
            return serde_json::from_str(candidate)
                .map_err(|error| format!("inline JSON envelope did not parse: {error}"));
        }
    }
    Err(format!("cell did not contain inline JSON: {cell}"))
}

fn classes(rows: &[TaxonomyRow]) -> BTreeSet<String> {
    rows.iter().map(|row| row.class.clone()).collect()
}

fn require_status(row: &TaxonomyRow, expected: u64) -> Result<(), String> {
    let actual = status(row).ok_or_else(|| format!("{} envelope missed status", row.class))?;
    if actual != expected {
        return Err(format!(
            "{} envelope used status {actual}, wanted {expected}",
            row.class
        ));
    }
    Ok(())
}

fn status(row: &TaxonomyRow) -> Option<u64> {
    row.envelope.get("status").and_then(Value::as_u64)
}

fn require_error_type(row: &TaxonomyRow, expected: &str) -> Result<(), String> {
    let actual = row
        .envelope
        .pointer("/body/error/type")
        .or_else(|| row.envelope.pointer("/error/type"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{} envelope missed error.type", row.class))?;
    if actual != expected {
        return Err(format!(
            "{} envelope used error.type {actual}, wanted {expected}",
            row.class
        ));
    }
    Ok(())
}

fn require_body_string(row: &TaxonomyRow, pointer: &str, expected: &str) -> Result<(), String> {
    let actual = row
        .envelope
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{} envelope missed {pointer}", row.class))?;
    if actual != expected {
        return Err(format!(
            "{} envelope used {actual} at {pointer}, wanted {expected}",
            row.class
        ));
    }
    Ok(())
}

fn require_provider_error<T>(
    result: Result<T, ProviderError>,
    expected: &str,
) -> Result<(), String> {
    let error = match result {
        Ok(_) => return Err(format!("expected ProviderError::{expected}, got success")),
        Err(error) => error,
    };

    let actual = match error {
        ProviderError::RateLimited { .. } => "RateLimited",
        ProviderError::ContentPolicy(_) => "ContentPolicy",
        ProviderError::BadToolArgs(_) => "BadToolArgs",
        ProviderError::Upstream5xx { .. } => "Upstream5xx",
        ProviderError::TransportTimeout { .. } => "TransportTimeout",
        ProviderError::VerdictBudgetExceeded { .. } => "VerdictBudgetExceeded",
        ProviderError::Malformed(_) => "Malformed",
        ProviderError::Other(_) => "Other",
    };

    if actual != expected {
        return Err(format!(
            "expected ProviderError::{expected}, got ProviderError::{actual}"
        ));
    }

    Ok(())
}
