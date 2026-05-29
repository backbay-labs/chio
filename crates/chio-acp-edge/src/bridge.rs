// Cross-protocol capability bridge, target bindings, ACP categorization,
// fidelity evaluation, and the authoritative target registry / orchestration.

struct AcpCapabilityBridge;

static MCP_TARGET_EXECUTOR: McpTargetExecutor = McpTargetExecutor {
    peer_supports_chio_tool_streaming: false,
};
static OPENAI_TARGET_EXECUTOR: OpenAiTargetExecutor = OpenAiTargetExecutor;
const MAX_DEFERRED_ACP_TASKS: usize = 1024;
const DEFERRED_ACP_TASK_TTL_MILLIS: u64 = 5 * 60 * 1000;

#[derive(Debug, Clone)]
struct CapabilityBinding {
    target_protocol: DiscoveryProtocol,
    server_id: String,
    tool_name: String,
}

struct AcpRequestIds {
    origin_request_id: String,
    kernel_request_id: String,
}

impl CapabilityBridge for AcpCapabilityBridge {
    fn source_protocol(&self) -> DiscoveryProtocol {
        DiscoveryProtocol::Acp
    }

    fn extract_capability_ref(
        &self,
        request: &Value,
    ) -> Result<Option<CrossProtocolCapabilityRef>, BridgeError> {
        request
            .pointer("/metadata/chio/capabilityRef")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| BridgeError::InvalidRequest(error.to_string()))
    }

    fn inject_capability_ref(
        &self,
        envelope: &mut Value,
        cap_ref: &CrossProtocolCapabilityRef,
    ) -> Result<(), BridgeError> {
        let chio_metadata = ensure_chio_metadata(envelope)?;
        chio_metadata.insert(
            "capabilityRef".to_string(),
            serde_json::to_value(cap_ref)
                .map_err(|error| BridgeError::InvalidRequest(error.to_string()))?,
        );
        Ok(())
    }

    fn protocol_context(&self, request: &Value) -> Result<Option<Value>, BridgeError> {
        Ok(request
            .get("capabilityId")
            .and_then(Value::as_str)
            .map(|capability_id| json!({ "capabilityId": capability_id })))
    }
}

/// Infer the ACP category for a Chio tool based on its name and properties.
fn infer_acp_category(tool: &ToolDefinition, default: AcpCategory) -> AcpCategory {
    let name_lower = tool.name.to_lowercase();
    if name_lower.contains("read_file")
        || name_lower.contains("write_file")
        || name_lower.contains("list_dir")
        || name_lower.starts_with("fs_")
    {
        AcpCategory::Filesystem
    } else if name_lower.contains("terminal")
        || name_lower.contains("exec")
        || name_lower.contains("shell")
        || name_lower.contains("command")
    {
        AcpCategory::Terminal
    } else if name_lower.contains("browser")
        || name_lower.contains("navigate")
        || name_lower.contains("screenshot")
    {
        AcpCategory::Browser
    } else {
        default
    }
}

/// Evaluate bridge fidelity for a Chio tool to ACP mapping.
fn evaluate_bridge_fidelity(
    tool: &ToolDefinition,
    category: AcpCategory,
    target_protocol: DiscoveryProtocol,
) -> BridgeFidelity {
    let registry = authoritative_target_registry();
    let hints = semantic_hints_for_tool(tool);
    let lifecycle = runtime_lifecycle_contract(RuntimeLifecycleSurface::AcpAuthoritative);
    if !hints.publish {
        return BridgeFidelity::Unsupported {
            reason: "publication disabled by x-chio-publish=false".to_string(),
        };
    }
    if !registry.supports_target_protocol(target_protocol) {
        return BridgeFidelity::Unsupported {
            reason: format!(
                "ACP authoritative execution does not yet have a registered `{target_protocol}` target executor"
            ),
        };
    }

    match category {
        AcpCategory::Browser => BridgeFidelity::Unsupported {
            reason:
                "browser/session automation semantics are not yet truthfully projected on the ACP edge"
                    .to_string(),
        },
        AcpCategory::Tool if tool.has_side_effects => BridgeFidelity::Unsupported {
            reason:
                "generic side-effectful tools do not map honestly to ACP capability classes on this edge"
                    .to_string(),
        },
        _ => {
            let mut caveats = Vec::new();
            if hints.approval_required {
                caveats.push(
                    "permission preview is advisory only; enforcement happens at invoke time with Chio capability checks"
                        .to_string(),
                );
            }
            if hints.streams_output {
                caveats.push(format!(
                    "stream-capable tools execute through deferred `{}` tasks and surface output when resumed via `{}` rather than as incremental push updates",
                    lifecycle.stream_entrypoint, lifecycle.follow_up_entrypoint
                ));
            }
            if hints.partial_output {
                caveats.push(
                    "partial output is preserved only inside the resumed terminal payload, not incremental ACP updates"
                        .to_string(),
                );
            }
            if hints.supports_cancellation {
                caveats.push(format!(
                    "cancellation is available on deferred `{}` tasks via `{}`; blocking `{}` remains terminal",
                    lifecycle.stream_entrypoint, lifecycle.cancel_entrypoint, lifecycle.blocking_entrypoint
                ));
            }
            if matches!(category, AcpCategory::Tool) {
                caveats.push(
                    "generic Chio tools are exposed through ACP's tool category rather than a native ACP primitive"
                        .to_string(),
                );
            }

            if caveats.is_empty() {
                BridgeFidelity::Lossless
            } else {
                BridgeFidelity::Adapted { caveats }
            }
        }
    }
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn current_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}

fn execute_orchestrated_acp_request(
    kernel: &ChioKernel,
    request: CrossProtocolExecutionRequest,
) -> Result<OrchestratedToolCall, AcpEdgeError> {
    let registry = authoritative_target_registry();
    if !registry.supports_target_protocol(request.target_protocol) {
        return Err(AcpEdgeError::InvalidRequest(format!(
            "ACP authoritative execution does not have a registered `{}` target executor",
            request.target_protocol
        )));
    }

    match CrossProtocolOrchestrator::new(kernel)
        .with_registry(registry)
        .execute(&AcpCapabilityBridge, request)
    {
        Ok(orchestrated) => Ok(orchestrated),
        Err(error) => {
            record_receipt_write_bridge_error(&error);
            Err(error.into())
        }
    }
}

fn authoritative_target_registry() -> TargetProtocolRegistry<'static> {
    TargetProtocolRegistry::new(DiscoveryProtocol::Native)
        .with_executor(&MCP_TARGET_EXECUTOR)
        .with_executor(&OPENAI_TARGET_EXECUTOR)
}

fn capability_collision_reason(capability_id: &str, sources: &BTreeSet<String>) -> String {
    let source_list = sources.iter().cloned().collect::<Vec<_>>().join(", ");
    format!(
        "ACP capability `{capability_id}` is withheld from discovery because multiple manifests map it to different upstream bindings: {source_list}"
    )
}
