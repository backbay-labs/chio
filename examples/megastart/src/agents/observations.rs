//! Project native journals for the operator without exposing transport credentials.
use anyhow::Result;
use serde_json::{json, Value};
use std::path::Path;

pub fn calls(root: &Path) -> Result<Vec<Value>> {
    let mut calls = Vec::new();
    for worker in super::service::WORKERS {
        let directory = root.join("native").join(worker);
        if !directory.exists() {
            continue;
        }
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(id) = name.to_str().and_then(|name| name.strip_prefix("task-")) else {
                continue;
            };
            if uuid::Uuid::parse_str(id).is_err() {
                continue;
            }
            let task = entry.path();
            if !task.join("task.json").exists() {
                continue;
            }
            let identity: Value = crate::read(&task.join("task.json"))?;
            // The launcher retains task identity before starting the gateway.
            // A journal does not exist until that gateway starts its first call.
            let journal = match std::fs::read_dir(task.join("journal")) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            for entry in journal {
                let path = entry?.path();
                if path.extension().is_none_or(|extension| extension != "json") {
                    continue;
                }
                let record: Value = crate::read(&path)?;
                if !record["requestId"].is_string() {
                    continue;
                }
                anyhow::ensure!(calls.len() < 1024, "Native observation capacity reached");
                calls.push(json!({"assignment":id,"worker":worker,"agent":identity["agent"],"session":identity["session"],"request_id":record["requestId"],"tool":record["request"]["tool"],"arguments":record["request"]["arguments"],"state":record["state"],"evidence":record["outcome"]["evidence"],"delivered":record["acknowledged"] == true && record["hostDeliveryConfirmed"] == true,"receipt":record["outcome"]["receipt"],"result":record["outcome"]["result"],"reason":record["outcome"]["reason"]}));
            }
        }
    }
    calls.sort_by(|left, right| {
        left["worker"].as_str().cmp(&right["worker"].as_str()).then(
            left["request_id"]
                .as_str()
                .cmp(&right["request_id"].as_str()),
        )
    });
    Ok(calls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_task_can_precede_its_first_journal() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("megastart-observation-{}", uuid::Uuid::new_v4()));
        let task = root
            .join("native/research-0")
            .join(format!("task-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&task)?;
        std::fs::write(
            task.join("task.json"),
            br#"{"agent":"hermes","session":"prepared"}"#,
        )?;
        assert!(calls(&root)?.is_empty());
        std::fs::create_dir(task.join("journal"))?;
        std::fs::write(task.join("journal/invalid.json"), b"incomplete")?;
        assert!(
            calls(&root).is_err(),
            "malformed evidence must still surface"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
