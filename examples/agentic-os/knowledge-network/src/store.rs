use anyhow::{Context, Result};
use chio_agent_os_shared::{
    host::{private_directory, write_json},
    json, Value,
};
use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct Source {
    pub id: String,
    pub owner: String,
    pub title: String,
    pub text: String,
}
#[derive(Default)]
pub struct Corpus {
    sources: Mutex<BTreeMap<String, Source>>,
    returned: Mutex<BTreeMap<String, Value>>,
    calls: Mutex<BTreeMap<String, u64>>,
}
pub struct CorpusServer(pub Arc<Corpus>);

impl Corpus {
    pub fn load(sources: Vec<Source>, path: &Path) -> Result<Self> {
        anyhow::ensure!(
            !sources.is_empty() && sources.len() <= 32,
            "Provide 1 to 32 sources"
        );
        private_directory(path)?;
        let mut map = BTreeMap::new();
        let mut bytes = 0;
        for source in sources {
            anyhow::ensure!(
                ["engineering", "support"].contains(&source.owner.as_str()),
                "Source owner must be engineering or support"
            );
            anyhow::ensure!(
                !source.id.is_empty() && source.id.len() <= 100 && source.title.len() <= 200,
                "Source identifiers or titles are too long"
            );
            bytes += source.text.len();
            anyhow::ensure!(bytes <= 200_000, "Corpus exceeds 200000 bytes");
            anyhow::ensure!(
                map.insert(source.id.clone(), source).is_none(),
                "Source IDs must be unique"
            );
        }
        write_json(&path.join("sources.json"), &json!(map))?;
        Ok(Self {
            sources: Mutex::new(map),
            ..Self::default()
        })
    }
    pub fn counts(&self) -> Result<Value> {
        Ok(json!(*self
            .calls
            .lock()
            .map_err(|_| anyhow::anyhow!("Corpus lock failed"))?))
    }
    pub fn retrieve(&self, owner: &str, query: &str) -> Result<Value> {
        anyhow::ensure!(
            !query.trim().is_empty() && query.len() <= 2000,
            "Provide a query of 1 to 2000 bytes"
        );
        let terms: Vec<String> = query
            .split_whitespace()
            .map(|t| {
                t.trim_matches(|c: char| !c.is_alphanumeric())
                    .to_lowercase()
            })
            .filter(|t| t.len() > 2)
            .collect();
        let sources = self
            .sources
            .lock()
            .map_err(|_| anyhow::anyhow!("Corpus lock failed"))?;
        let mut passages = Vec::new();
        for source in sources.values().filter(|s| s.owner == owner) {
            let version = chio_core::sha256_hex(source.text.as_bytes());
            let mut offset = 0;
            for paragraph in source.text.split_inclusive("\n\n") {
                let lower = paragraph.to_lowercase();
                let score = terms.iter().filter(|t| lower.contains(t.as_str())).count();
                if score > 0 {
                    let end = offset + paragraph.len();
                    let id = chio_core::sha256_hex(
                        format!("{}:{version}:{offset}:{end}", source.id).as_bytes(),
                    );
                    passages.push(json!({
                        "id":id,
                        "source_id":source.id,
                        "owner":source.owner,
                        "title":source.title,
                        "version_sha256":version,
                        "start_byte":offset,
                        "end_byte":end,
                        "text":paragraph,
                        "score":score
                    }));
                }
                offset += paragraph.len();
            }
        }
        passages.sort_by(|a, b| {
            b["score"]
                .as_u64()
                .cmp(&a["score"].as_u64())
                .then_with(|| a["id"].as_str().cmp(&b["id"].as_str()))
        });
        passages.truncate(6);
        let mut returned = self
            .returned
            .lock()
            .map_err(|_| anyhow::anyhow!("Passage lock failed"))?;
        for passage in &passages {
            returned.insert(
                passage["id"].as_str().context("Missing passage ID")?.into(),
                passage.clone(),
            );
        }
        *self
            .calls
            .lock()
            .map_err(|_| anyhow::anyhow!("Corpus lock failed"))?
            .entry(owner.into())
            .or_default() += 1;
        Ok(json!({"owner":owner,"passages":passages}))
    }
    pub fn validate(&self, passage: &Value) -> Result<()> {
        let sources = self
            .sources
            .lock()
            .map_err(|_| anyhow::anyhow!("Corpus lock failed"))?;
        let source = sources
            .get(passage["source_id"].as_str().context("Missing source")?)
            .context("Source no longer exists")?;
        anyhow::ensure!(
            passage["version_sha256"] == chio_core::sha256_hex(source.text.as_bytes()),
            "Source changed; retrieve its current version before citing it"
        );
        let start = passage["start_byte"]
            .as_u64()
            .context("Missing start byte")? as usize;
        let end = passage["end_byte"].as_u64().context("Missing end byte")? as usize;
        anyhow::ensure!(
            source.text.get(start..end) == passage["text"].as_str(),
            "Citation does not resolve to the exact UTF-8 passage"
        );
        Ok(())
    }
    pub fn update(&self, id: &str, text: &str, path: &Path) -> Result<()> {
        anyhow::ensure!(
            !text.is_empty() && text.len() <= 32_000,
            "Replacement source must contain 1 to 32000 bytes"
        );
        let mut sources = self
            .sources
            .lock()
            .map_err(|_| anyhow::anyhow!("Corpus lock failed"))?;
        let mut replacement = sources.clone();
        replacement
            .get_mut(id)
            .context("Choose an existing source to update")?
            .text = text.into();
        write_json(&path.join("sources.json"), &json!(replacement))?;
        *sources = replacement;
        Ok(())
    }
    pub fn cited_passages(&self, ids: &Value) -> Result<Vec<Value>> {
        let returned = self
            .returned
            .lock()
            .map_err(|_| anyhow::anyhow!("Passage lock failed"))?;
        let ids = ids
            .as_array()
            .context("Answer must contain a citations array")?;
        anyhow::ensure!(ids.len() <= 12, "Too many answer citations");
        let mut selected = Vec::new();
        for id in ids {
            selected.push(
                returned
                    .get(id.as_str().context("Citation IDs must be strings")?)
                    .context("Answer cited a passage that was never returned")?
                    .clone(),
            );
        }
        drop(returned);
        for passage in &selected {
            self.validate(passage)?;
        }
        Ok(selected)
    }
}
#[async_trait::async_trait]
impl ToolServerConnection for CorpusServer {
    fn server_id(&self) -> &str {
        "knowledge"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["engineering_retrieve".into(), "support_retrieve".into()]
    }
    fn tool_is_read_only(&self, tool: &str) -> bool {
        self.tool_names().iter().any(|t| t == tool)
    }
    async fn invoke(
        &self,
        tool: &str,
        args: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        let owner = match tool {
            "engineering_retrieve" => "engineering",
            "support_retrieve" => "support",
            _ => return Err(KernelError::ToolServerError("Unknown source owner".into())),
        };
        self.0
            .retrieve(owner, args["query"].as_str().unwrap_or(""))
            .map_err(|e| KernelError::ToolServerError(e.to_string()))
    }
}

pub fn import_directory(root: &Path) -> Result<Vec<Source>> {
    let root = root.canonicalize()?;
    let mut sources = Vec::new();
    for owner in ["engineering", "support"] {
        let directory = root.join(owner);
        anyhow::ensure!(
            !directory.symlink_metadata()?.file_type().is_symlink(),
            "Corpus owner directories must not be symlinks"
        );
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file()
                || entry.path().extension().and_then(|s| s.to_str()) != Some("md")
            {
                continue;
            }
            anyhow::ensure!(
                sources.len() < 32 && entry.metadata()?.len() <= 32_000,
                "Imported corpus exceeds its limits"
            );
            let title = entry.file_name().to_string_lossy().into_owned();
            sources.push(Source {
                id: format!("{owner}/{title}"),
                owner: owner.into(),
                title,
                text: std::fs::read_to_string(entry.path())?,
            });
        }
    }
    sources.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(sources)
}
