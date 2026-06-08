use chio_manifest::{LatencyHint, ToolDefinition};
use serde::{Deserialize, Serialize};

use crate::validation::schema_bool_extension;

/// Truthful bridge fidelity contract for publication gating.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum BridgeFidelity {
    Lossless,
    Adapted { caveats: Vec<String> },
    Unsupported { reason: String },
}

impl BridgeFidelity {
    #[must_use]
    pub fn published_by_default(&self) -> bool {
        !matches!(self, Self::Unsupported { .. })
    }

    #[must_use]
    pub fn caveats(&self) -> &[String] {
        match self {
            Self::Adapted { caveats } => caveats.as_slice(),
            Self::Lossless | Self::Unsupported { .. } => &[],
        }
    }

    #[must_use]
    pub fn unsupported_reason(&self) -> Option<&str> {
        match self {
            Self::Unsupported { reason } => Some(reason.as_str()),
            Self::Lossless | Self::Adapted { .. } => None,
        }
    }
}

/// Semantic hints that influence truthful bridge publication decisions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeSemanticHints {
    pub publish: bool,
    pub approval_required: bool,
    pub streams_output: bool,
    pub supports_cancellation: bool,
    pub partial_output: bool,
}

/// Extract bridge-semantic hints from a tool definition and optional `x-chio-*`
/// schema extensions.
#[must_use]
pub fn semantic_hints_for_tool(tool: &ToolDefinition) -> BridgeSemanticHints {
    let publish = schema_bool_extension(&tool.input_schema, "x-chio-publish")
        .or_else(|| {
            tool.output_schema
                .as_ref()
                .and_then(|schema| schema_bool_extension(schema, "x-chio-publish"))
        })
        .unwrap_or(true);

    let approval_required = schema_bool_extension(&tool.input_schema, "x-chio-approval-required")
        .or_else(|| {
            tool.output_schema
                .as_ref()
                .and_then(|schema| schema_bool_extension(schema, "x-chio-approval-required"))
        })
        .unwrap_or(false);

    let streams_output = schema_bool_extension(&tool.input_schema, "x-chio-streaming")
        .or_else(|| {
            tool.output_schema
                .as_ref()
                .and_then(|schema| schema_bool_extension(schema, "x-chio-streaming"))
        })
        .unwrap_or(matches!(
            tool.latency_hint,
            Some(LatencyHint::Moderate | LatencyHint::Slow)
        ));

    let supports_cancellation = schema_bool_extension(&tool.input_schema, "x-chio-cancellation")
        .or_else(|| {
            tool.output_schema
                .as_ref()
                .and_then(|schema| schema_bool_extension(schema, "x-chio-cancellation"))
        })
        .unwrap_or(matches!(tool.latency_hint, Some(LatencyHint::Slow)));

    let partial_output = schema_bool_extension(&tool.input_schema, "x-chio-partial-output")
        .or_else(|| {
            tool.output_schema
                .as_ref()
                .and_then(|schema| schema_bool_extension(schema, "x-chio-partial-output"))
        })
        .unwrap_or(streams_output);

    BridgeSemanticHints {
        publish,
        approval_required,
        streams_output,
        supports_cancellation,
        partial_output,
    }
}
