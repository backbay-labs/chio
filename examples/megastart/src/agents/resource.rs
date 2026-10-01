//! The host owns this filesystem. Agent processes receive only governed tools.
use anyhow::{Context, Result};
use chio_agent_os_shared::runtime::files;
use serde_json::{json, Value};
use std::path::{Component, Path, PathBuf};
use tokio::io::{AsyncBufReadExt, BufReader};

const MAX_CONTENT: usize = 64_000;

fn resolve(root: &Path, logical: &str) -> Result<PathBuf> {
    let relative = logical
        .strip_prefix("/workspace/")
        .context("Path must begin with /workspace/")?;
    anyhow::ensure!(!relative.is_empty(), "A file or directory is required");
    let mut path = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(part) = component else {
            anyhow::bail!("Non-canonical resource path")
        };
        path.push(part);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "Resource symlinks are forbidden"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(path)
}

fn perform(root: &Path, name: &str, args: &Value) -> Result<String> {
    let logical = args["path"].as_str().context("Missing path")?;
    let path = resolve(root, logical)?;
    match name {
        "read_text_file" => Ok(files::read_text(&path, MAX_CONTENT)?),
        "list_directory" => {
            let mut entries = std::fs::read_dir(path)?
                .map(|entry| {
                    let entry = entry?;
                    Ok(entry.file_name().to_string_lossy().into_owned())
                })
                .collect::<std::io::Result<Vec<_>>>()?;
            anyhow::ensure!(entries.len() <= 256, "Directory exceeds listing bound");
            entries.sort();
            Ok(entries.join("\n"))
        }
        "write_file" | "edit_file" => {
            // Defense in depth: even an incorrectly configured grant cannot
            // modify the source snapshot, frozen handoffs, or regression suite.
            anyhow::ensure!(
                logical.starts_with("/workspace/outputs/"),
                "Only worker outputs are writable"
            );
            let content = if name == "write_file" {
                args["content"]
                    .as_str()
                    .context("Missing content")?
                    .to_owned()
            } else {
                let mut content = files::read_text(&path, MAX_CONTENT)?;
                let edits = args["edits"].as_array().context("Missing edits")?;
                anyhow::ensure!(
                    !edits.is_empty() && edits.len() <= 32,
                    "Expected 1..32 exact edits"
                );
                for edit in edits {
                    let old = edit["oldText"].as_str().context("Missing oldText")?;
                    let new = edit["newText"].as_str().context("Missing newText")?;
                    anyhow::ensure!(
                        !old.is_empty() && content.matches(old).count() == 1,
                        "Edit must match exactly once"
                    );
                    content = content.replacen(old, new, 1);
                    anyhow::ensure!(
                        content.len() <= MAX_CONTENT,
                        "Edited output exceeds size limit"
                    );
                }
                content
            };
            anyhow::ensure!(content.len() <= MAX_CONTENT, "Output exceeds size limit");
            // Parents are allocated by the host before the session starts.
            anyhow::ensure!(
                path.parent().is_some_and(Path::is_dir),
                "Output directory has not been assigned"
            );
            files::replace(&path, content.as_bytes())?;
            Ok(format!(
                "Retained {logical}; {} bytes; SHA-256 {}",
                content.len(),
                chio_core::sha256_hex(content.as_bytes())
            ))
        }
        _ => anyhow::bail!("Unknown operation"),
    }
}

pub async fn serve(root: &Path) -> Result<()> {
    let root = root.canonicalize()?;
    let mut input = BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();
    while !input.fill_buf().await?.is_empty() {
        let request: Value = crate::protocol::receive(&mut input).await?;
        let Some(id) = request.get("id") else {
            continue;
        };
        let result = match request["method"].as_str() {
            Some("initialize") => {
                json!({"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"Megastart workspace","version":"1"}})
            }
            Some("tools/list") => json!({"tools": tools()}),
            Some("tools/call") => {
                let params = &request["params"];
                match perform(
                    &root,
                    params["name"].as_str().unwrap_or_default(),
                    &params["arguments"],
                ) {
                    Ok(text) => json!({"content":[{"type":"text","text":text}]}),
                    Err(error) => {
                        json!({"isError":true,"content":[{"type":"text","text":error.to_string()}]})
                    }
                }
            }
            Some("ping") => json!({}),
            _ => {
                crate::protocol::send(&mut output, &json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"Unsupported method"}})).await?;
                continue;
            }
        };
        crate::protocol::send(
            &mut output,
            &json!({"jsonrpc":"2.0","id":id,"result":result}),
        )
        .await?;
    }
    Ok(())
}

fn tools() -> Vec<Value> {
    ["read_text_file", "write_file", "edit_file", "list_directory"].into_iter().map(|name| {
        let mut properties = json!({"path":{"type":"string","description":"Absolute resource path under /workspace/"}});
        let mut required = vec!["path"];
        match name {
            "write_file" => { properties["content"] = json!({"type":"string","maxLength":MAX_CONTENT}); required.push("content"); }
            "edit_file" => { properties["edits"] = json!({"type":"array","minItems":1,"maxItems":32,"items":{"type":"object","properties":{"oldText":{"type":"string"},"newText":{"type":"string"}},"required":["oldText","newText"],"additionalProperties":false}}); required.push("edits"); }
            _ => {}
        }
        json!({"name":name,"description":format!("{name} in the governed mission workspace. Source and handoffs are immutable; write only your assigned output."),"inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false}})
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn traversal_and_source_writes_are_refused() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("megastart-resource-{}", uuid::Uuid::new_v4()));
        files::private_directory(&root)?;
        for path in ["/workspace/../source", "/etc/passwd", "/workspace/"] {
            assert!(resolve(&root, path).is_err());
        }
        assert!(perform(
            &root,
            "write_file",
            &json!({"path":"/workspace/source/lib.rs","content":"changed"})
        )
        .is_err());
        std::fs::remove_dir(root)?;
        Ok(())
    }
}
