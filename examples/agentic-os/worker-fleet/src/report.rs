use chio_agent_os_shared::{host::write_json, json, Value};
use chio_kernel::{KernelError, NestedFlowBridge, ToolInvocationCost, ToolServerConnection};
use std::{collections::BTreeMap, path::PathBuf};
pub const PRICE: u64 = 20;
pub struct ReportTool {
    pub directory: PathBuf,
}
fn error(e: impl ToString) -> KernelError {
    KernelError::ToolServerError(e.to_string())
}
#[async_trait::async_trait]
impl ToolServerConnection for ReportTool {
    fn server_id(&self) -> &str {
        "reports"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["generate".into()]
    }
    async fn invoke(
        &self,
        tool: &str,
        input: Value,
        mut bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        if tool != "generate" {
            return Err(error("Unknown report tool"));
        }
        let id = uuid::Uuid::parse_str(input["operation_id"].as_str().unwrap_or(""))
            .map_err(error)?
            .to_string();
        let digest =
            chio_core::sha256_hex(&chio_core::canonical_json_bytes(&input).map_err(error)?);
        let destination = self.directory.join(format!("{id}.json"));
        if destination.exists() {
            let existing: Value =
                serde_json::from_slice(&std::fs::read(destination).map_err(error)?)
                    .map_err(error)?;
            if existing["input_sha256"] != digest {
                return Err(error(
                    "Operation ID already belongs to different report input",
                ));
            }
            return Ok(existing);
        }
        let text = input["text"]
            .as_str()
            .ok_or_else(|| error("Provide report text"))?;
        if text.is_empty() || text.len() > 64_000 {
            return Err(error("Report text must contain 1 to 64000 bytes"));
        }
        let section = input["section"]
            .as_str()
            .ok_or_else(|| error("Choose a report section"))?;
        for step in 0..4 {
            if let Some(bridge) = bridge.as_deref_mut() {
                bridge.poll_parent_cancellation()?;
            }
            write_json(
                &self.directory.join(format!("{id}.partial.json")),
                &json!({"operation_id":id,"step":step,"input_sha256":digest}),
            )
            .map_err(error)?;
            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        }
        if let Some(bridge) = bridge.as_deref_mut() {
            bridge.poll_parent_cancellation()?;
        }
        let result = match section {
            "summary" => {
                json!({
                    "paragraphs":text.split("\n\n").filter(|p|!p.trim().is_empty()).count(),
                    "words":text.split_whitespace().count(),
                    "opening":text.lines().filter(|l|!l.trim().is_empty()).take(3).collect::<Vec<_>>()
                })
            }
            "terms" => {
                let mut terms = BTreeMap::new();
                for word in text.split_whitespace() {
                    let word = word
                        .trim_matches(|c: char| !c.is_alphanumeric())
                        .to_lowercase();
                    if word.len() > 3 {
                        *terms.entry(word).or_insert(0u64) += 1;
                    }
                }
                let mut ranked: Vec<_> = terms.into_iter().collect();
                ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                ranked.truncate(12);
                json!({"terms":ranked})
            }
            "actions" => {
                json!({
                    "actions":text.lines().filter(|line|line.trim_start().starts_with("- [ ]")||line.to_lowercase().contains("must ")).collect::<Vec<_>>()
                })
            }
            "links" => {
                json!({"links":text.split_whitespace().filter(|word|word.contains("https://")||word.contains("http://")).collect::<Vec<_>>()})
            }
            _ => return Err(error("Choose summary, terms, actions, or links")),
        };
        let artifact = json!({
            "operation_id":id,
            "input_sha256":digest,
            "source_sha256":chio_core::sha256_hex(text.as_bytes()),
            "section":section,
            "result":result
        });
        write_json(&destination, &artifact).map_err(error)?;
        Ok(artifact)
    }
    async fn invoke_with_cost(
        &self,
        tool: &str,
        input: Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool, input, bridge).await?;
        Ok((
            value,
            Some(ToolInvocationCost {
                units: PRICE,
                currency: "USD".into(),
                breakdown: Some(json!({"local_demo_credits":true,"report":PRICE})),
            }),
        ))
    }
}
