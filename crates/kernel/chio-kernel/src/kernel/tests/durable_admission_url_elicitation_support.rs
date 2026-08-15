struct DurableUrlElicitationServer {
    store: std::sync::Arc<TestAdmissionOperationStore>,
}

#[async_trait::async_trait]
impl ToolServerConnection for DurableUrlElicitationServer {
    fn server_id(&self) -> &str {
        "durable-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".to_owned()]
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        assert_eq!(
            self.store.operation().state(),
            AdmissionOperationState::DispatchCommitted,
            "dispatch must be durably committed before URL elicitation"
        );
        Err(KernelError::UrlElicitationsRequired {
            message: "URL elicitation required before tool execution".to_owned(),
            elicitations: vec![CreateElicitationOperation::Url {
                meta: None,
                message: "Authorize the provider URL".to_owned(),
                url: "https://provider.example/authorize".to_owned(),
                elicitation_id: "durable-elicitation-1".to_owned(),
            }],
        })
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "URL elicitation server unexpectedly used value invocation".to_owned(),
        ))
    }
}
