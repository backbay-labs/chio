//! Private, inherited pipes bind a worker to its host-selected capability.
//! No issuer keys, model credentials, or bearer capabilities enter these processes.
use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
};

const MAX_MESSAGE: u64 = 65_536;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    pub id: String,
    pub worker: String,
    pub tool: String,
    pub input: Value,
}

pub async fn receive<T: DeserializeOwned>(reader: &mut (impl AsyncBufRead + Unpin)) -> Result<T> {
    use tokio::io::AsyncReadExt;
    let mut line = Vec::new();
    reader
        .take(MAX_MESSAGE + 1)
        .read_until(b'\n', &mut line)
        .await?;
    anyhow::ensure!(
        !line.is_empty() && line.len() <= MAX_MESSAGE as usize && line.last() == Some(&b'\n'),
        "Worker message missing, incomplete, or too large"
    );
    Ok(serde_json::from_slice(&line)?)
}

pub async fn send(writer: &mut (impl AsyncWrite + Unpin), value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    anyhow::ensure!(
        bytes.len() < MAX_MESSAGE as usize,
        "Message exceeds protocol bound"
    );
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

pub struct Process {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    pub ready: Value,
}

impl Process {
    pub async fn spawn(role: &str, name: &str) -> Result<Self> {
        let mut child = Command::new(std::env::current_exe()?)
            .args([role, name])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let input = child.stdin.take().context("Child stdin was not piped")?;
        let mut output = BufReader::new(child.stdout.take().context("Child stdout was not piped")?);
        let ready: Value =
            tokio::time::timeout(Duration::from_secs(15), receive(&mut output)).await??;
        anyhow::ensure!(
            ready["pid"].as_u64() == child.id().map(u64::from),
            "Readiness PID does not match the owned child"
        );
        anyhow::ensure!(ready["name"] == name, "Readiness identity mismatch");
        Ok(Self {
            child,
            input,
            output,
            ready,
        })
    }

    pub async fn exchange<T: DeserializeOwned>(&mut self, value: &impl Serialize) -> Result<T> {
        send(&mut self.input, value).await?;
        tokio::time::timeout(Duration::from_secs(30), receive(&mut self.output)).await?
    }

    pub async fn close(mut self) -> Result<()> {
        self.input.shutdown().await?;
        drop(self.input);
        let status = tokio::time::timeout(Duration::from_secs(10), self.child.wait()).await??;
        anyhow::ensure!(status.success(), "Child process failed: {status}");
        Ok(())
    }
}

pub async fn worker(name: &str) -> Result<()> {
    let mut input = BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();
    send(
        &mut output,
        &json!({"name": name, "pid": std::process::id()}),
    )
    .await?;
    while !input.fill_buf().await?.is_empty() {
        let mut task: Assignment = receive(&mut input).await?;
        anyhow::ensure!(
            task.worker == name,
            "Assignment belongs to a different worker"
        );
        plan(&mut task)?;
        // The worker proposes an operation. The owning host admits it and runs
        // the adapter; a process being scheduled conveys no execution authority.
        send(&mut output, &task).await?;
    }
    Ok(())
}

pub async fn coordinator(name: &str) -> Result<()> {
    let first_name = format!("{name}-0");
    let second_name = format!("{name}-1");
    let (mut first, mut second) = tokio::try_join!(
        Process::spawn("worker", &first_name),
        Process::spawn("worker", &second_name),
    )?;
    let mut input = BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();
    send(
        &mut output,
        &json!({"name": name, "pid": std::process::id(), "workers": [first.ready, second.ready]}),
    )
    .await?;
    while !input.fill_buf().await?.is_empty() {
        let tasks: Vec<Assignment> = receive(&mut input).await?;
        anyhow::ensure!(tasks.len() == 2, "A swarm round assigns both workers");
        let (a, b): (Assignment, Assignment) =
            tokio::try_join!(first.exchange(&tasks[0]), second.exchange(&tasks[1]))?;
        let mut expected = tasks.clone();
        for task in &mut expected {
            plan(task)?;
        }
        anyhow::ensure!(
            a == expected[0] && b == expected[1],
            "Worker changed its retained assignment"
        );
        send(&mut output, &vec![a, b]).await?;
    }
    tokio::try_join!(first.close(), second.close())?;
    Ok(())
}

pub fn plan(task: &mut Assignment) -> Result<()> {
    if task.tool == "repair" && task.input["mode"] != "model" {
        let source = task.input["source"]
            .as_str()
            .context("Repair assignment has no source")?;
        let widen = match task.input["strategy"].as_str() {
            Some("boundary") => false,
            Some("wide") => true,
            _ => anyhow::bail!("Unsupported repair strategy"),
        };
        task.input["candidate_source"] = json!(crate::operations::repair(source, widen)?);
    }
    Ok(())
}
