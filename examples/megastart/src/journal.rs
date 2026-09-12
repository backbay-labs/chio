//! Mission-wide observations. Kernel receipts remain the decision evidence.
use crate::read;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::{fs::OpenOptions, io::Write, path::Path};

pub fn events(root: &Path) -> Result<Vec<Value>> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(root.join("events.lock"))?;
    fs2::FileExt::lock_shared(&lock)?;
    load(root)
}

fn load(root: &Path) -> Result<Vec<Value>> {
    let path = root.join("events.ndjson");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = chio_agent_os_shared::runtime::files::read_text(&path, 8_000_000)?;
    anyhow::ensure!(
        text.is_empty() || text.ends_with('\n'),
        "Interrupted journal write; reconcile before continuing"
    );
    let events: Vec<Value> = text
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    anyhow::ensure!(
        events
            .iter()
            .enumerate()
            .all(|(i, e)| e["sequence"].as_u64() == Some(i as u64 + 1)),
        "Mission event sequence is incomplete"
    );
    Ok(events)
}

pub fn emit(root: &Path, kind: &str, actor: &str, detail: Value) -> Result<()> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(root.join("events.lock"))?;
    fs2::FileExt::lock_exclusive(&lock)?;
    let previous = load(root)?;
    anyhow::ensure!(previous.len() < 4096, "Mission event capacity reached");
    let event = json!({"sequence":previous.len()+1,"kind":kind,"actor":actor,"detail":detail});
    let mut bytes = serde_json::to_vec(&event)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(root.join("events.ndjson"))?;
    anyhow::ensure!(
        file.metadata()?.len() + bytes.len() as u64 <= 8_000_000,
        "Mission journal is full"
    );
    file.write_all(&bytes)?;
    file.sync_data()?;
    Ok(())
}

pub fn proposal(root: &Path) -> Result<Option<Value>> {
    if root.join("proposal.json").exists() {
        Ok(Some(read(&root.join("proposal.json"))?))
    } else {
        Ok(None)
    }
}

pub fn snapshot(root: &Path) -> Result<Value> {
    let config: Value = read(&root.join("mission.json"))?;
    let events = events(root)?;
    let mut outcomes = Vec::new();
    for entry in std::fs::read_dir(root.join("outcomes"))? {
        let path = entry?.path();
        if path.extension().is_some_and(|x| x == "json") {
            outcomes.push(read::<Value>(&path)?);
        }
    }
    outcomes.sort_by_key(|v| v["assignment"]["worker"].as_str().unwrap_or("").to_owned());
    let proposal = proposal(root)?;
    let published = root.join("release/release.json").exists();
    let mut phase = if published {
        "published"
    } else if proposal.is_some() {
        "awaiting_review"
    } else {
        events
            .iter()
            .rev()
            .find_map(|e| {
                (e["kind"] == "mission.phase")
                    .then(|| e["detail"]["phase"].as_str())
                    .flatten()
            })
            .unwrap_or("ready")
    };
    if ["research", "implementation", "review"].contains(&phase) {
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("host.lock"))?;
        if fs2::FileExt::try_lock_exclusive(&lease).is_ok() {
            phase = "interrupted";
        }
    }
    let capacity = events
        .iter()
        .rev()
        .find(|e| e["kind"] == "authority.capacity")
        .map(|e| e["detail"].clone());
    let original = crate::operations::source(&root.join("source"))?;
    let candidate = if let Some(p) = &proposal {
        let id = p["candidate"]
            .as_str()
            .context("Candidate identity missing")?;
        uuid::Uuid::parse_str(id)?;
        Some(crate::operations::source(
            &root.join("candidates").join(id),
        )?)
    } else {
        None
    };
    Ok(
        json!({"mission":"Repair rolling averages","phase":phase,"config":config,"events":events,"outcomes":outcomes,"capacity":capacity,"proposal":proposal,"published":published,"original":original,"candidate":candidate}),
    )
}
