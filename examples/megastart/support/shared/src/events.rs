use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct Event {
    pub sequence: usize,
    pub timestamp_ms: u64,
    pub kind: String,
    pub actor: String,
    pub title: String,
    pub data: Value,
}

struct Record {
    directory: PathBuf,
    manifest: Value,
    events: Vec<Event>,
    event_bytes: usize,
}

/// Application observations and original kernel receipts, retained together.
/// The event envelope is not itself a Chio execution receipt.
#[derive(Clone)]
pub struct Run(Arc<Mutex<Record>>);

impl Run {
    pub fn create(root: &Path, application: &str, input: &Value) -> Result<Self> {
        let id = if std::env::var("CHIO_RUN_APPLICATION").as_deref() == Ok(application) {
            uuid::Uuid::parse_str(
                &std::env::var("CHIO_RUN_ID").context("Hosted run ID is missing")?,
            )?
            .to_string()
        } else {
            uuid::Uuid::new_v4().to_string()
        };
        anyhow::ensure!(
            !root.join(&id).exists(),
            "This run already exists; reconnect instead of repeating it"
        );
        let directory = root.join(&id);
        crate::host::private_directory(&directory)?;
        let manifest = json!({
            "schema":"chio.agent-os.run.v1", "id":id,
            "application":application, "version":env!("CARGO_PKG_VERSION"),
            "source_revision":option_env!("CHIO_SOURCE_REVISION").unwrap_or("development"),
            "input":input, "input_sha256":chio_core::sha256_hex(&chio_core::canonical_json_bytes(input)?),
            "status":"running", "created_at_ms":now_ms(), "output":null,
        });
        crate::host::write_json(&directory.join("run.json"), &manifest)?;
        Ok(Self(Arc::new(Mutex::new(Record {
            directory,
            manifest,
            events: Vec::new(),
            event_bytes: 0,
        }))))
    }

    pub fn id(&self) -> Result<String> {
        Ok(self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("Run state lock failed"))?
            .manifest["id"]
            .as_str()
            .context("Missing run ID")?
            .to_owned())
    }

    pub fn directory(&self) -> Result<PathBuf> {
        Ok(self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("Run state lock failed"))?
            .directory
            .clone())
    }

    pub fn emit(&self, kind: &str, actor: &str, title: &str, data: Value) -> Result<()> {
        let mut record = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("Run state lock failed"))?;
        let event = Event {
            sequence: record.events.len() + 1,
            timestamp_ms: now_ms(),
            kind: kind.into(),
            actor: actor.into(),
            title: title.into(),
            data,
        };
        let mut line = serde_json::to_vec(&event)?;
        line.push(b'\n');
        anyhow::ensure!(
            record.events.len() < 4096 && record.event_bytes + line.len() <= MAX_RECORD_BYTES,
            "Run event limit reached; inspect retained work before another attempt"
        );
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(record.directory.join("events.ndjson"))?;
        file.write_all(&line)?;
        file.sync_data()?;
        record.event_bytes += line.len();
        record.events.push(event);
        Ok(())
    }

    pub fn finish(&self, result: &Result<Value>) -> Result<()> {
        let mut record = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("Run state lock failed"))?;
        record.manifest["finished_at_ms"] = json!(now_ms());
        match result {
            Ok(output) => {
                record.manifest["status"] = json!("completed");
                record.manifest["output"] = output.clone();
            }
            Err(error) => {
                record.manifest["status"] = json!("failed");
                record.manifest["error"] = json!(error.to_string());
            }
        }
        record.manifest["output_sha256"] = json!(chio_core::sha256_hex(
            &chio_core::canonical_json_bytes(&record.manifest["output"])?
        ));
        record.manifest["events_sha256"] = json!(chio_core::sha256_hex(
            &chio_core::canonical_json_bytes(&record.events)?
        ));
        record.manifest["event_count"] = json!(record.events.len());
        crate::host::write_json(&record.directory.join("run.json"), &record.manifest)
    }

    pub fn snapshot(&self) -> Result<Value> {
        let record = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("Run state lock failed"))?;
        let mut manifest = record.manifest.clone();
        manifest["events"] = serde_json::to_value(&record.events)?;
        Ok(manifest)
    }

    pub fn capture(root: &Path, id: &str) -> Result<Value> {
        // IDs are server-generated UUIDs. Validate before constructing paths.
        let id = uuid::Uuid::parse_str(id)?.to_string();
        let directory = root.join(id);
        let mut manifest: Value =
            serde_json::from_slice(&read_bounded(&directory.join("run.json"))?)?;
        let path = directory.join("events.ndjson");
        let mut events = Vec::new();
        if path.exists() {
            let bytes = read_bounded(&path)?;
            for line in std::str::from_utf8(&bytes)?.lines() {
                anyhow::ensure!(
                    events.len() < 4096,
                    "Retained event count exceeds its bound"
                );
                events.push(serde_json::from_str::<Event>(line)?);
            }
        }
        anyhow::ensure!(
            events
                .iter()
                .enumerate()
                .all(|(index, event)| event.sequence == index + 1),
            "Retained event sequence is incomplete"
        );
        if manifest["status"] != "running" {
            anyhow::ensure!(
                manifest["output_sha256"]
                    == chio_core::sha256_hex(&chio_core::canonical_json_bytes(
                        &manifest["output"]
                    )?),
                "Retained output digest mismatch"
            );
            anyhow::ensure!(
                manifest["events_sha256"]
                    == chio_core::sha256_hex(&chio_core::canonical_json_bytes(&events)?),
                "Retained event digest mismatch"
            );
        }
        manifest["events"] = serde_json::to_value(events)?;
        Ok(manifest)
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// Bound file reads before allocation, including concurrent append growth.
const MAX_RECORD_BYTES: usize = 6_000_000;
fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take((MAX_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= MAX_RECORD_BYTES,
        "Retained run exceeds its size bound"
    );
    Ok(bytes)
}
