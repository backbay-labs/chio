use anyhow::{Context, Result};
use chio_agent_os_shared::{async_trait, host::Host, json, Run, Value};
use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
#[derive(Clone, Serialize, Deserialize)]
pub struct Source {
    pub id: String,
    pub title: String,
    pub text: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub task: String,
    pub source: String,
}
pub struct ResearchTools {
    pub sources: Vec<Source>,
    pub effects: AtomicUsize,
}
fn words(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 3)
        .map(str::to_lowercase)
        .collect()
}
fn citation(source: &Source, start: usize, end: usize) -> Value {
    json!({
        "source":source.id,
        "version_sha256":chio_core::sha256_hex(source.text.as_bytes()),
        "byte_range":[
            start,
            end
        ],
        "text":&source.text[
            start..end
        ]
    })
}
impl ResearchTools {
    pub fn observe(&self, question: &str) -> Value {
        let terms = words(question);
        let mut found = Vec::new();
        for source in &self.sources {
            let mut offset = 0;
            for line in source.text.split_inclusive('\n') {
                if !terms.is_disjoint(&words(line)) {
                    found.push(citation(source, offset, offset + line.len()));
                }
                offset += line.len();
            }
        }
        json!({"question":question,"passages":found,"source_count":self.sources.len()})
    }
    fn perform(&self, tool: &str, args: Value) -> Result<Value> {
        let source = self
            .sources
            .iter()
            .find(|s| s.id == args["source"])
            .context("Choose a source from the supplied corpus")?;
        let question = args["question"]
            .as_str()
            .context("Provide a research question")?;
        let result = match tool {
            "discover" => self.observe(question),
            "contradiction" => {
                // Surface competing numerical claims and retain the passages. The
                // reader or synthesis worker decides whether their contexts conflict.
                let mut claims = Vec::new();
                for s in &self.sources {
                    let mut start = 0;
                    for line in s.text.split_inclusive('\n') {
                        if line.chars().any(|c| c.is_ascii_digit())
                            && !words(question).is_disjoint(&words(line))
                        {
                            claims.push(citation(s, start, start + line.len()));
                        }
                        start += line.len();
                    }
                }
                json!({
                    "claims":claims,
                    "assessment":"Competing numerical statements require context review; no semantic contradiction is asserted by this extractor"
                })
            }
            "reproduce" => {
                let values = source
                    .text
                    .lines()
                    .find_map(|line| line.strip_prefix("samples:"))
                    .context("This source has no samples: line to reproduce")?;
                let values = values
                    .split(',')
                    .map(|s| s.trim().parse::<f64>())
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                anyhow::ensure!(
                    !values.is_empty()
                        && values.len() <= 100
                        && values.iter().all(|v| v.is_finite()),
                    "Use 1 to 100 finite numeric samples"
                );
                let mean = values.iter().sum::<f64>() / values.len() as f64;
                json!({
                    "source":source.id,
                    "version_sha256":chio_core::sha256_hex(source.text.as_bytes()),
                    "values":values,
                    "mean":mean,
                    "sample_count":values.len(),
                    "calculation":"sum(samples) / count(samples)"
                })
            }
            _ => anyhow::bail!("Unknown research responsibility"),
        };
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(result)
    }
}
pub struct ToolServer(pub Arc<ResearchTools>);
#[async_trait]
impl ToolServerConnection for ToolServer {
    fn server_id(&self) -> &str {
        "research"
    }
    fn tool_names(&self) -> Vec<String> {
        super::signals::CLASSES
            .iter()
            .map(|s| (*s).into())
            .collect()
    }
    fn tool_is_read_only(&self, _: &str) -> bool {
        true
    }
    async fn invoke(
        &self,
        tool: &str,
        args: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        self.0
            .perform(tool, args)
            .map_err(|e| KernelError::ToolServerError(e.to_string()))
    }
}
pub struct Claims(Mutex<rusqlite::Connection>);
impl Claims {
    pub fn open(path: &Path) -> Result<Self> {
        let connection = rusqlite::Connection::open(path)?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS claims(job TEXT PRIMARY KEY, worker TEXT NOT NULL, state TEXT NOT NULL, receipt TEXT);")?;
        Ok(Self(Mutex::new(connection)))
    }
    pub fn claim(&self, job: &str, worker: &str) -> Result<bool> {
        let connection = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("Claim lock failed"))?;
        Ok(connection.execute(
            "INSERT OR IGNORE INTO claims(job,worker,state) VALUES(?1,?2,'claimed')",
            rusqlite::params![job, worker],
        )? == 1)
    }
    pub fn finish(&self, job: &str, worker: &str, state: &str, receipt: &str) -> Result<()> {
        let connection = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("Claim lock failed"))?;
        anyhow::ensure!(connection.execute("UPDATE claims SET state=?3,receipt=?4 WHERE job=?1 AND worker=?2 AND state='claimed'",rusqlite::params![job,worker,state,receipt])?==1,"The worker no longer owns this claim");
        Ok(())
    }
}
pub async fn schedule(
    directory: &Path,
    run: &Run,
    label: &str,
    question: &str,
    sources: Vec<Source>,
    jobs: &[Job],
    order: &[String],
    allowance: usize,
    removed: Option<&str>,
) -> Result<Value> {
    let tools = Arc::new(ResearchTools {
        sources,
        effects: AtomicUsize::new(0),
    });
    let host = Host::open(
        &directory.join(label),
        "research-task-capabilities-v1",
        vec![Box::new(ToolServer(tools.clone()))],
    )?;
    let claims = Claims::open(&directory.join(format!("{label}-claims.db")))?;
    let mut capabilities = BTreeMap::new();
    for task in super::signals::CLASSES {
        capabilities.insert(
            task,
            host.issue(
                "research",
                &[if removed == Some(task) {
                    "unavailable"
                } else {
                    task
                }],
                allowance as u32,
            )?,
        );
    }
    let mut ranked = jobs.to_vec();
    ranked.sort_by_key(|j| {
        order
            .iter()
            .position(|task| *task == j.task)
            .unwrap_or(usize::MAX)
    });
    let mut completed = Vec::new();
    let mut refusals = 0;
    let mut suppressed = 0;
    for (index, job) in ranked.iter().take(allowance).enumerate() {
        let worker = format!("{label}-worker-{}", index % 3);
        anyhow::ensure!(
            claims.claim(&job.id, &worker)?,
            "Unexpected duplicate in the supplied workload"
        );
        if !claims.claim(&job.id, "competing-worker")? {
            suppressed += 1;
        }
        run.emit(
            "assignment.claimed",
            &worker,
            "Retained the selected assignment",
            json!({"job":job,"policy":label,"rank":index}),
        )?;
        let cap = capabilities
            .get(job.task.as_str())
            .context("Unknown task")?;
        let before = tools.effects.load(Ordering::SeqCst);
        let call = host
            .call(
                run,
                &worker,
                cap,
                "research",
                &job.task,
                json!({"source":job.source,"question":question}),
            )
            .await?;
        let accepted = call.allowed && !call.output.is_null();
        if !accepted {
            refusals += 1;
            anyhow::ensure!(
                tools.effects.load(Ordering::SeqCst) == before,
                "Refused research task entered the handler"
            );
        }
        claims.finish(
            &job.id,
            &worker,
            if accepted { "completed" } else { "refused" },
            &call.receipt_id,
        )?;
        completed.push(json!({"job":job,"worker":worker,"completed":accepted,"receipt_id":call.receipt_id,"result":call.output}));
    }
    let retained = Claims::open(&directory.join(format!("{label}-claims.db")))?;
    for job in ranked.iter().take(allowance) {
        anyhow::ensure!(
            !retained.claim(&job.id, "restarted-worker")?,
            "Restart made an existing assignment available again"
        );
    }
    let accepted = completed
        .iter()
        .filter(|entry| entry["completed"] == true)
        .count();
    let duplicate_executions = tools
        .effects
        .load(Ordering::SeqCst)
        .saturating_sub(accepted);
    anyhow::ensure!(
        duplicate_executions == 0,
        "Handler executions exceed completed assignments"
    );
    Ok(json!({
        "policy":label,
        "assignments":completed,
        "completed":tools.effects.load(Ordering::SeqCst),
        "refused":refusals,
        "duplicate_executions":duplicate_executions,
        "competing_claims_refused":suppressed,
        "retained_after_reopen":true,
        "work_units":tools.effects.load(Ordering::SeqCst),
        "intervention_required":refusals,
        "remaining":jobs.len().saturating_sub(allowance)
    }))
}
