use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection};
use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

pub struct Documents {
    text: String,
    calls: Mutex<BTreeMap<String, usize>>,
}
pub struct DocumentServer(pub Arc<Documents>);
impl Documents {
    pub fn new(text: String) -> Self {
        Self {
            text,
            calls: Mutex::new(BTreeMap::new()),
        }
    }
    pub fn counts(&self) -> Value {
        self.calls.lock().map(|v| json!(*v)).unwrap_or(Value::Null)
    }
    fn analyze(&self, tool: &str, arguments: &Value) -> Result<Value, KernelError> {
        let digest = chio_core::sha256_hex(self.text.as_bytes());
        if tool == "retrieve" {
            let query = arguments["query"]
                .as_str()
                .ok_or_else(|| KernelError::ToolServerError("Provide a retrieval query".into()))?;
            let terms: Vec<String> = query
                .split_whitespace()
                .map(|s| {
                    s.trim_matches(|c: char| !c.is_alphanumeric())
                        .to_lowercase()
                })
                .filter(|s| s.len() > 2)
                .collect();
            let mut passages = Vec::new();
            let mut start = 0;
            for paragraph in self.text.split_inclusive("\n\n") {
                let lower = paragraph.to_lowercase();
                let score = terms
                    .iter()
                    .filter(|term| lower.contains(term.as_str()))
                    .count();
                if score > 0 {
                    passages.push(json!({
                        "source_id":"mission-document",
                        "version_sha256":digest,
                        "start_byte":start,
                        "end_byte":start+paragraph.len(),
                        "text":paragraph,
                        "score":score
                    }));
                }
                start += paragraph.len();
            }
            passages.sort_by_key(|p| std::cmp::Reverse(p["score"].as_u64().unwrap_or(0)));
            passages.truncate(5);
            return Ok(json!({"input_sha256":digest,"passages":passages}));
        }
        let mut headings = Vec::new();
        let mut links = Vec::new();
        let mut heading: Option<(String, String)> = None;
        for event in Parser::new_ext(&self.text, Options::empty()) {
            match event {
                Event::Start(Tag::Heading { level, .. }) => {
                    heading = Some((level.to_string(), String::new()))
                }
                Event::Text(text) | Event::Code(text) => {
                    if let Some((_, value)) = &mut heading {
                        value.push_str(&text)
                    }
                }
                Event::SoftBreak | Event::HardBreak => {
                    if let Some((_, value)) = &mut heading {
                        value.push(' ')
                    }
                }
                Event::End(TagEnd::Heading(_)) => {
                    if let Some((level, title)) = heading.take() {
                        headings.push(json!({"level":level,"title":title}))
                    }
                }
                Event::Start(Tag::Link { dest_url, .. }) => {
                    links.push(json!({"kind":"link","target":dest_url.to_string()}))
                }
                Event::Start(Tag::Image { dest_url, .. }) => {
                    links.push(json!({"kind":"image","target":dest_url.to_string()}))
                }
                _ => {}
            }
        }
        match tool {
            "outline" => Ok(json!({"input_sha256":digest,"headings":headings})),
            "link_inventory" => Ok(json!({"input_sha256":digest,"links":links})),
            _ => Err(KernelError::ToolServerError(
                "Unknown document operation".into(),
            )),
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for DocumentServer {
    fn server_id(&self) -> &str {
        "documents"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["outline".into(), "link_inventory".into(), "retrieve".into()]
    }
    fn tool_is_read_only(&self, tool: &str) -> bool {
        matches!(tool, "outline" | "link_inventory" | "retrieve")
    }
    async fn invoke(
        &self,
        tool: &str,
        args: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        let result = self.0.analyze(tool, &args)?;
        *self
            .0
            .calls
            .lock()
            .map_err(|_| KernelError::ToolServerError("Document accounting lock failed".into()))?
            .entry(tool.into())
            .or_default() += 1;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn code_is_not_structure() -> anyhow::Result<()> {
        let tools = Documents::new(
            "# Actual\n\n```md\n# Fake\n[x](bad)\n```\n\n[Chio](https://chio.computer)".into(),
        );
        assert_eq!(
            tools.analyze("outline", &json!({}))?["headings"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
        assert_eq!(
            tools.analyze("link_inventory", &json!({}))?["links"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
        Ok(())
    }
    #[test]
    fn retrieved_ranges_resolve_exact_unicode() -> anyhow::Result<()> {
        let source = "# Café\n\nKeep receipts after restart.\n";
        let tools = Documents::new(source.into());
        let result = tools.analyze("retrieve", &json!({"query":"restart"}))?;
        let passage = &result["passages"][0];
        let start = passage["start_byte"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing start"))? as usize;
        let end = passage["end_byte"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing end"))? as usize;
        assert_eq!(source.get(start..end), passage["text"].as_str());
        assert_eq!(
            passage["version_sha256"],
            chio_core::sha256_hex(source.as_bytes())
        );
        Ok(())
    }
}
