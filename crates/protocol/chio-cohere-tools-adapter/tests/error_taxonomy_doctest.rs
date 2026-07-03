use std::collections::BTreeSet;
use std::sync::Arc;

use chio_cohere_tools_adapter::transport::MockTransport;
use chio_cohere_tools_adapter::{CohereAdapter, CohereAdapterConfig};
use chio_tool_call_fabric::{ProviderError, ProviderRequest, ReceiptId, Redaction, VerdictResult};
use serde_json::{json, Value};

const README: &str = include_str!("../README.md");

#[derive(Debug)]
struct TaxonomyRow {
    class: String,
    #[allow(dead_code)]
    envelope: Value,
}

fn adapter() -> CohereAdapter {
    let config = CohereAdapterConfig::new(
        "cohere-1",
        "Cohere v2 chat",
        "0.1.0",
        "deadbeef",
        "org_chio_demo",
    );
    CohereAdapter::new(config, Arc::new(MockTransport::new()))
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

fn tool_call_stream() -> Vec<u8> {
    br#"event: tool-call-end
data: {"tool_call":{"id":"call_taxonomy_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}}}

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
        "message": {
            "role": "assistant",
            "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "not-json"}}
            ]
        }
    }))?);
    require_provider_error(bad_args, "BadToolArgs")?;

    let nonjson = adapter
        .gate_sse_stream(b"event: tool-call-end\ndata: not-json\n\n", |_invocation| {
            Ok(allow_verdict())
        });
    require_provider_error(nonjson, "Malformed")?;

    let budget = adapter.gate_sse_stream(&tool_call_stream(), |_invocation| {
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
