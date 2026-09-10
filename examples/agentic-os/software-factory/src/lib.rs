pub mod publication;
pub mod repository;
use anyhow::{Context, Result};
use chio_agent_os_shared::{
    async_trait, graph::GraphRuntime, host::Host, json, model, Application, Run, Value,
};
use chio_core::capability::token::CapabilityToken;
use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection};
use chio_swarm_authority::{SwarmFanoutRequest, SwarmFanoutTask, SwarmTaskCompletion};
use repository::{Repository, RepositoryServer};
use std::sync::{Arc, Mutex};

pub struct Factory;
struct Workers {
    repository: Arc<Repository>,
    tools: Host,
    repair_cap: CapabilityToken,
    run: Run,
    issue: String,
    mode: String,
    tests: Mutex<Option<Value>>,
}
struct WorkerServer(Arc<Workers>);
#[async_trait]
impl ToolServerConnection for WorkerServer {
    fn server_id(&self) -> &str {
        "factory-workers"
    }
    fn tool_names(&self) -> Vec<String> {
        vec![
            "plan".into(),
            "implement".into(),
            "test".into(),
            "review".into(),
        ]
    }
    async fn invoke(
        &self,
        tool: &str,
        input: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.0
            .execute(tool, input)
            .await
            .map_err(|e| KernelError::ToolServerError(e.to_string()))
    }
}
impl Workers {
    async fn execute(&self, tool: &str, input: Value) -> Result<Value> {
        match tool {
            "plan" => Ok(json!({
                "issue":self.issue,
                "tasks":[
                    "implement",
                    "test",
                    "review"
                ],
                "editable_files":self.repository.editable,
                "publication":"local release directory after explicit candidate approval"
            })),
            "implement" => {
                if self.mode == "model" {
                    let definitions = json!([
                      {"type":"function","function":{"name":"list_files","description":"List files the worker can read and edit.","parameters":{"type":"object","properties":{},"additionalProperties":false}}},
                      {"type":"function","function":{"name":"read_file","description":"Read a workspace file.","parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}}},
                      {"type":"function","function":{"name":"write_file","description":"Replace an allowed source file. The test file cannot be edited.","parameters":{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"],"additionalProperties":false}}}
                    ]);
                    let result=model::tool_loop(&self.tools,&self.run,&self.repair_cap,"repository","You repair a small Python repository. First call list_files to discover the actual filenames. Read the implementation and tests using those exact names, then use write_file to implement the requested behavior. Tests are immutable. Do not invent test results. Keep the change small and avoid network, process, or filesystem access in the generated code. Inspect tool refusals and correct the request. Never claim a file changed when write_file was refused. Return a concise explanation after a successful write.",&self.issue,definitions).await?;
                    Ok(
                        json!({"candidate_sha256":self.repository.digest()?,"diff":self.repository.diff()?,"worker":result}),
                    )
                } else {
                    anyhow::ensure!(
                        self.repository.editable == vec!["analysis.py".to_string()]
                            && std::env::var("CHIO_FACTORY_WORKSPACE").is_err(),
                        "The deterministic adapter only targets the supplied regression project"
                    );
                    let patch="def moving_average(values, window):\n    \"\"\"Return means for complete windows without changing the input.\"\"\"\n    if window <= 0:\n        raise ValueError('window must be positive')\n    return [sum(values[i:i + window]) / window\n            for i in range(len(values) - window + 1)]\n";
                    self.tools
                        .call(
                            &self.run,
                            "deterministic-regression-worker",
                            &self.repair_cap,
                            "repository",
                            "write_file",
                            json!({"path":"analysis.py","content":patch}),
                        )
                        .await?
                        .require_output()?;
                    Ok(json!({
                        "candidate_sha256":self.repository.digest()?,
                        "diff":self.repository.diff()?,
                        "worker":{
                            "adapter":"deterministic regression adapter; supplied repair, no autonomous generation"
                        }
                    }))
                }
            }
            "test" => {
                anyhow::ensure!(
                    input["candidate_sha256"] == self.repository.digest()?,
                    "Tests requested for a stale candidate"
                );
                let result = self.repository.test(false).await?;
                *self
                    .tests
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Test result lock failed"))? =
                    Some(result.clone());
                Ok(result)
            }
            "review" => {
                let candidate = self.repository.digest()?;
                anyhow::ensure!(
                    input["candidate_sha256"] == candidate,
                    "Review requested for a stale candidate"
                );
                let tests = self
                    .tests
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Test result lock failed"))?
                    .clone()
                    .context("Run tests before requesting review")?;
                anyhow::ensure!(
                    tests["candidate_sha256"] == candidate,
                    "Tests belong to another candidate"
                );
                let diff = self.repository.diff()?;
                let mut findings = Vec::new();
                if diff.is_empty() {
                    findings.push("No source change was produced".to_string());
                }
                for file in &self.repository.editable {
                    let text = std::fs::read_to_string(self.repository.directory.join(file))?;
                    for pattern in [
                        "import subprocess",
                        "import socket",
                        "os.system(",
                        "eval(",
                        "exec(",
                    ] {
                        if text.contains(pattern) {
                            findings.push(format!("Review required for {pattern} in {file}"));
                        }
                    }
                }
                let approved = tests["passed"] == true && findings.is_empty();
                Ok(json!({
                    "candidate_sha256":candidate,
                    "approved":approved,
                    "findings":findings,
                    "review_kind":"deterministic release checks: changed source, passing immutable tests, flagged risky constructs",
                    "tests":tests
                }))
            }
            _ => anyhow::bail!("Unknown factory responsibility"),
        }
    }
}
#[async_trait]
impl Application for Factory {
    fn name(&self) -> &'static str {
        "software-factory"
    }
    fn title(&self) -> &'static str {
        "From issue to a tested candidate"
    }
    fn description(&self) -> &'static str {
        "A repair worker edits a confined project. Separate graph continuations authorize implementation, testing, and candidate review."
    }
    fn sample(&self) -> Value {
        json!({
            "issue":"Fix moving_average so it returns only complete sliding-window means, handles empty and shorter inputs, rejects nonpositive windows with ValueError, and never mutates the input.",
            "mode":"deterministic",
            "exercise_denials":true
        })
    }
    async fn execute(&self, input: Value, run: Run) -> Result<Value> {
        if input["action"] == "decide" {
            return publication::decide(input, run).await;
        }
        let issue = chio_agent_os_shared::host::text(&input, "issue", 4000)?.to_owned();
        let mode = input["mode"].as_str().unwrap_or("deterministic").to_owned();
        anyhow::ensure!(
            ["deterministic", "model"].contains(&mode.as_str()),
            "Choose deterministic or model mode"
        );
        let repository = Arc::new(Repository::create(&run.directory()?.join("project"))?);
        let baseline = repository.test(true).await?;
        anyhow::ensure!(
            baseline["passed"] == false,
            "The starting project already passes; choose a failing issue and focused test"
        );
        run.emit(
            "factory.baseline",
            "test-runner",
            "The original project fails its focused tests",
            baseline.clone(),
        )?;
        let tools = Host::open(
            &run.directory()?.join("repository-host"),
            "factory-editable-files-v1",
            vec![Box::new(RepositoryServer(repository.clone()))],
        )?;
        let repair_cap =
            tools.issue("repository", &["list_files", "read_file", "write_file"], 12)?;
        let workers = Arc::new(Workers {
            repository: repository.clone(),
            tools,
            repair_cap,
            run: run.clone(),
            issue,
            mode,
            tests: Mutex::new(None),
        });
        let mut host = Host::open(
            &run.directory()?.join("worker-host"),
            "factory-signed-task-graph-v1",
            vec![Box::new(WorkerServer(workers.clone()))],
        )?;
        let planner = host.issue("factory-workers", &["plan"], 1)?;
        let planned = host
            .call(
                &run,
                "planner",
                &planner,
                "factory-workers",
                "plan",
                json!({}),
            )
            .await?;
        anyhow::ensure!(planned.allowed, "Planning was refused");
        let root = host.root("factory-workers", &["implement", "test", "review"], 3)?;
        let implement = host.delegate(&run, &root, "implement", &["implement"], 1, 3000)?;
        let test = host.delegate(&run, &root, "test", &["test"], 1, 3000)?;
        let review = host.delegate(&run, &root, "review", &["review"], 1, 3000)?;
        let tasks = [
            ("implement", &implement),
            ("test", &test),
            ("review", &review),
        ];
        let bundle = host.mint_graph(SwarmFanoutRequest {
            graph_id: run.id()?,
            root_transaction_ref: planned.receipt_id.clone(),
            parent_receipt_id: planned.receipt_id,
            session_anchor: run.id()?,
            parent: root.token,
            tasks: tasks
                .iter()
                .map(|(task, cap)| SwarmFanoutTask {
                    task_id: task.to_string(),
                    capability: (*cap).clone(),
                    protocol_target: "local://factory-workers".into(),
                    reserved_units: 1,
                })
                .collect(),
            policy_digest: chio_core::sha256_hex(b"factory-signed-task-graph-v1"),
            now_unix_ms: chio_agent_os_shared::events::now_ms(),
            lifetime_ms: 110_000,
        })?;
        run.emit("graph.issued","planner","Issued authority for three bounded responsibilities",json!({
    "graph":bundle.task_graph,
    "continuations":bundle.continuation_tokens,
    "trusted_issuer":host.signer.to_hex(),
    "scheduling":"The application orders implement, test, and review; the graph assigns authority and joins their results"
}))?;
        let runtime = GraphRuntime::attach(
            &mut host,
            bundle,
            &run.directory()?.join("orchestration.db"),
        )?;
        let repaired = runtime
            .call(
                &host,
                &run,
                &implement,
                "implement",
                "implement",
                json!({"issue":input["issue"]}),
            )
            .await?;
        let repair_receipt = repaired.receipt_id.clone();
        let repair = repaired.require_output()?;
        anyhow::ensure!(!repository.diff()?.is_empty(), "Worker produced no patch");
        let candidate = repository.digest()?;
        let tested = runtime
            .call(
                &host,
                &run,
                &test,
                "test",
                "test",
                json!({"candidate_sha256":candidate}),
            )
            .await?;
        let test_receipt = tested.receipt_id.clone();
        let tests = tested.require_output()?;
        let reviewed = runtime
            .call(
                &host,
                &run,
                &review,
                "review",
                "review",
                json!({"candidate_sha256":candidate}),
            )
            .await?;
        let review_receipt = reviewed.receipt_id.clone();
        let reviewed = reviewed.require_output()?;
        if input["exercise_denials"] == true {
            let writes = repository.writes.load(std::sync::atomic::Ordering::SeqCst);
            let replay = runtime
                .call(
                    &host,
                    &run,
                    &implement,
                    "implement",
                    "implement",
                    json!({"issue":input["issue"]}),
                )
                .await?;
            anyhow::ensure!(
                !replay.allowed
                    && repository.writes.load(std::sync::atomic::Ordering::SeqCst) == writes,
                "Reused implementation authority changed the candidate"
            );
            // Fresh authority isolates candidate binding from continuation replay.
            let stale_test = host.issue("factory-workers", &["test"], 1)?;
            let previous_tests = workers
                .tests
                .lock()
                .map_err(|_| anyhow::anyhow!("Test lock failed"))?
                .clone();
            let stale = host
                .call(
                    &run,
                    "stale-test-worker",
                    &stale_test,
                    "factory-workers",
                    "test",
                    json!({"candidate_sha256":"another-candidate"}),
                )
                .await?;
            anyhow::ensure!(
                stale.output.is_null()
                    && workers
                        .tests
                        .lock()
                        .map_err(|_| anyhow::anyhow!("Test lock failed"))?
                        .as_ref()
                        == previous_tests.as_ref(),
                "A stale candidate changed accepted test evidence"
            );
            let revoked = workers.tools.issue("repository", &["write_file"], 1)?;
            workers.tools.kernel.revoke_capability(&revoked.id)?;
            let revoked_call = workers
                .tools
                .call(
                    &run,
                    "revoked-repair-worker",
                    &revoked,
                    "repository",
                    "write_file",
                    json!({"path":"analysis.py","content":"wrong"}),
                )
                .await?;
            anyhow::ensure!(
                !revoked_call.allowed
                    && repository.writes.load(std::sync::atomic::Ordering::SeqCst) == writes
                    && repository.digest()? == candidate,
                "Revoked worker changed the candidate"
            );
            let read_only = workers.tools.issue("repository", &["read_file"], 1)?;
            let denied = workers
                .tools
                .call(
                    &run,
                    "review-worker",
                    &read_only,
                    "repository",
                    "write_file",
                    json!({"path":"analysis.py","content":"wrong"}),
                )
                .await?;
            anyhow::ensure!(
                !denied.allowed && repository.digest()? == candidate,
                "Read-only reviewer changed the candidate"
            );
            let bad = workers
                .tools
                .call(
                    &run,
                    "repair-worker",
                    &workers.repair_cap,
                    "repository",
                    "write_file",
                    json!({"path":"../outside.py","content":"wrong"}),
                )
                .await?;
            anyhow::ensure!(
                bad.output.is_null() && repository.digest()? == candidate,
                "Path escape changed the workspace"
            );
            run.emit(
                "factory.refusals",
                "operator",
                "Replay, revocation, stale tests, and unauthorized edits left the candidate unchanged",
                json!({"candidate_sha256":candidate,"writes":writes}),
            )?;
        }
        let eligible = tests["passed"] == true && reviewed["approved"] == true;
        let complete = if eligible {
            host.complete_graph(
                runtime.bundle,
                vec![
                    SwarmTaskCompletion {
                        task_id: "implement".into(),
                        receipt_id: repair_receipt,
                        consumed_units: 1,
                    },
                    SwarmTaskCompletion {
                        task_id: "test".into(),
                        receipt_id: test_receipt.clone(),
                        consumed_units: 1,
                    },
                    SwarmTaskCompletion {
                        task_id: "review".into(),
                        receipt_id: review_receipt.clone(),
                        consumed_units: 1,
                    },
                ],
                json!({"candidate_sha256":candidate,"tests":tests,"review":reviewed}),
            )?
        } else {
            runtime.bundle
        };
        if eligible {
            run.emit(
                "graph.completed",
                "coordinator",
                "Joined the actual worker results",
                json!({
                    "join":complete.join_receipts,
                    "terminal":complete.terminal_receipts,
                    "proof":chio_swarm_authority::verify_swarm_authority_bundle(&complete,
                    &[
                        host.signer
                    ])?
                }),
            )?;
        } else {
            run.emit(
                "graph.incomplete",
                "coordinator",
                "The candidate failed its acceptance checks; no successful join was issued",
                json!({"candidate_sha256":candidate,"tests":tests,"review":reviewed}),
            )?;
        }
        let proposal = json!({
            "candidate_sha256":candidate,
            "diff_sha256":chio_core::sha256_hex(repository.diff()?.as_bytes()),
            "test_receipt":test_receipt,
            "review_receipt":review_receipt,
            "eligible":eligible
        });
        run.emit(
            "publication.proposed",
            "release-owner",
            "A candidate is ready for an explicit publication decision",
            proposal.clone(),
        )?;
        let mut files = repository.editable.clone();
        files.push(repository.test_file.clone());
        let approval = publication::prepare(&run, proposal.clone(), files).await?;
        Ok(json!({
            "baseline":baseline,
            "repair":repair,
            "tests":tests,
            "review":reviewed,
            "candidate_sha256":candidate,
            "diff":repository.diff()?,
            "proposal":proposal,
            "approval":approval,
            "published":false,
            "graph":complete
        }))
    }
}
