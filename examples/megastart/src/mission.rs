use crate::{
    authority::Authority,
    digest,
    operations::{source, Workspace},
    protocol::{Assignment, Process},
    read, retain,
};
use anyhow::{Context, Result};
use chio_agent_os_shared::{
    host::{grant, request, Host},
    runtime::files,
    Run,
};
use chio_core::{
    capability::{
        governance::GovernedTransactionIntent,
        scope::{ChioScope, Constraint},
    },
    crypto::Keypair,
};
use chio_kernel::{KernelError, NestedFlowBridge, ToolCallRequest, ToolServerConnection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, Arc},
};

#[derive(Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub model: bool,
    pub allowance: u32,
    pub source_sha256: String,
    pub tests_sha256: String,
}

pub struct Mission {
    pub directory: PathBuf,
    pub config: Config,
    pub host: Host,
    pub authority: Authority,
    pub run: Run,
    _lease: File,
}

impl Mission {
    pub fn initialize(directory: &Path, project: &Path, allowance: u32) -> Result<()> {
        anyhow::ensure!(
            !directory.exists(),
            "Mission directory already exists; inspect or recover it"
        );
        anyhow::ensure!(
            (1..=1000).contains(&allowance),
            "Allowance must be 1..1000 invocations"
        );
        let code = source(project)?;
        let tests = files::read_text(&project.join("tests.rs"), 64_000)?;
        files::private_directory(directory)?;
        for name in [
            "source",
            "effects",
            "assignments",
            "requests",
            "outcomes",
            "candidates",
            "runs",
        ] {
            files::private_directory(&directory.join(name))?;
        }
        files::create(&directory.join("source/lib.rs"), code.as_bytes())?;
        files::create(&directory.join("source/tests.rs"), tests.as_bytes())?;
        files::create(
            &directory.join("protected.txt"),
            b"research workers cannot change this file\n",
        )?;
        retain(
            &directory.join("mission.json"),
            &Config {
                model: false,
                allowance,
                source_sha256: digest(&code)?,
                tests_sha256: digest(&tests)?,
            },
        )?;
        println!("mission initialized: allowance={allowance} invocations; publication requires explicit approval");
        Ok(())
    }

    pub fn open(directory: &Path) -> Result<Self> {
        let directory = directory.canonicalize()?;
        let lease = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("host.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lease)
            .context("Another host owns this mission; wait for it to stop")?;
        let config: Config = read(&directory.join("mission.json"))?;
        anyhow::ensure!(
            config.source_sha256 == digest(&source(&directory.join("source"))?)?,
            "Mission source changed; initialize a new mission"
        );
        anyhow::ensure!(
            config.tests_sha256
                == digest(&files::read_text(
                    &directory.join("source/tests.rs"),
                    64_000
                )?)?,
            "Mission tests changed; initialize a new mission"
        );
        files::private_directory(&directory.join("kernel"))?;
        let issuer = {
            let runtime = chio_control_plane::DurableAdmissionRuntime::open(
                &directory.join("kernel/admission.db"),
            )?;
            runtime.kernel_keypair()
        };
        let host = Host::open(
            &directory.join("kernel"),
            "megastart-scoped-family-and-exact-publication-v1",
            vec![
                Box::new(Workspace(directory.clone())),
                Box::new(Publisher(directory.clone())),
            ],
        )?;
        let authority = Authority::load_or_create(&directory, &host, &issuer, config.allowance)?;
        let run = Run::create(
            &directory.join("runs"),
            "megastart",
            &json!({"mission": config.source_sha256}),
        )?;
        Ok(Self {
            directory,
            config,
            host,
            authority,
            run,
            _lease: lease,
        })
    }

    fn assignment(
        &self,
        name: &str,
        worker: &str,
        tool: &str,
        mut input: Value,
    ) -> Result<Assignment> {
        let path = self
            .directory
            .join("assignments")
            .join(format!("{name}.json"));
        input["source_sha256"] = json!(self.config.source_sha256);
        input["mode"] = json!(if self.config.model {
            "model"
        } else {
            "reference"
        });
        if path.exists() {
            let task: Assignment = read(&path)?;
            let mut prior = task.input.clone();
            prior
                .as_object_mut()
                .context("Assignment input is not an object")?
                .remove("operation_id");
            anyhow::ensure!(
                prior == input && task.worker == worker && task.tool == tool,
                "Retained assignment has different inputs"
            );
            return Ok(task);
        }
        let id = uuid::Uuid::new_v4().to_string();
        input["operation_id"] = json!(id);
        let task = Assignment {
            id,
            worker: worker.into(),
            tool: tool.into(),
            input,
        };
        retain(&path, &task)?;
        crate::journal::emit(
            &self.directory,
            "worker.assigned",
            worker,
            json!({"operation":tool,"id":task.id}),
        )?;
        Ok(task)
    }

    async fn dispatch(&self, task: &Assignment) -> Result<Value> {
        let path = self
            .directory
            .join("outcomes")
            .join(format!("{}.json", task.id));
        if path.exists() {
            let value: Value = read(&path)?;
            anyhow::ensure!(
                value["assignment"] == json!(task),
                "Operation ID belongs to different work"
            );
            verify_outcome(&self.directory, &value, &self.host.signer.to_hex())?;
            crate::journal::emit(
                &self.directory,
                "operation.reconciled",
                &task.worker,
                json!({"operation":task.tool,"id":task.id}),
            )?;
            println!(
                "reconciled {}: original receipt retained; no dispatch",
                task.tool
            );
            return Ok(value);
        }
        anyhow::ensure!(!self.directory.join("effects").join(format!("{}.json", task.id)).exists() && !self.directory.join("requests").join(format!("{}.json", task.id)).exists(), "Operation has no retained outcome; unresolved: inspect kernel receipts and effects before any retry");
        let cap = self
            .authority
            .workers
            .get(&task.worker)
            .context("Worker has no capability")?;
        let call = request(cap, "workspace", &task.tool, task.input.clone());
        self.evaluate(task, call).await
    }

    async fn evaluate(&self, task: &Assignment, call: ToolCallRequest) -> Result<Value> {
        let request_id = call.request_id.clone();
        retain(
            &self
                .directory
                .join("requests")
                .join(format!("{}.json", task.id)),
            &call,
        )?;
        crate::journal::emit(
            &self.directory,
            "operation.submitted",
            &task.worker,
            json!({"operation":task.tool,"id":task.id}),
        )?;
        let result = self
            .host
            .call_controlled(
                &self.run,
                &task.worker,
                call,
                None,
                Arc::new(AtomicBool::new(false)),
            )
            .await?;
        let snapshot = self.run.snapshot()?;
        let receipt = snapshot["events"]
            .as_array()
            .context("Missing events")?
            .iter()
            .find_map(|event| {
                (event["data"]["request_id"] == request_id && event["data"]["receipt"].is_object())
                    .then(|| event["data"]["receipt"].clone())
            })
            .context("Kernel did not retain a receipt")?;
        let value = json!({"assignment": task, "allowed": result.allowed, "output": result.output,
            "reason": result.reason, "receipt": receipt, "trusted_kernel": self.host.signer.to_hex()});
        retain(
            &self
                .directory
                .join("outcomes")
                .join(format!("{}.json", task.id)),
            &value,
        )?;
        crate::journal::emit(
            &self.directory,
            if result.allowed {
                "operation.completed"
            } else {
                "operation.refused"
            },
            &task.worker,
            json!({"operation":task.tool,"id":task.id,"receipt":result.receipt_id}),
        )?;
        println!(
            "{} {}: receipt={}",
            if result.allowed { "allowed" } else { "refused" },
            task.tool,
            result.receipt_id
        );
        Ok(value)
    }

    async fn round(&self, process: &mut Process, tasks: Vec<Assignment>) -> Result<Vec<Value>> {
        let proposed: Vec<Assignment> = process.exchange(&tasks).await?;
        anyhow::ensure!(
            proposed.len() == tasks.len(),
            "Coordinator omitted assigned work"
        );
        // The host binds worker identity, operation, and all inputs. Worker
        // proposals are checked against the documented bounded repair adapter.
        for (expected, actual) in tasks.iter().zip(&proposed) {
            let mut expected = expected.clone();
            crate::protocol::plan(&mut expected)?;
            anyhow::ensure!(
                &expected == actual,
                "Worker proposed an operation outside its assignment"
            );
        }
        let (a, b) = tokio::try_join!(self.dispatch(&proposed[0]), self.dispatch(&proposed[1]))?;
        anyhow::ensure!(
            a["allowed"] == true && b["allowed"] == true,
            "Swarm could not complete its assigned operations; inspect retained outcomes before resuming"
        );
        self.report_capacity()?;
        Ok(vec![a, b])
    }

    fn report_capacity(&self) -> Result<()> {
        use chio_core::capability::aggregate_invocation::verify_aggregate_invocation_budget;
        use chio_kernel::{
            budget_store::{BudgetQuotaKey, BudgetQuotaProfile},
            BudgetStore,
        };
        let family = verify_aggregate_invocation_budget(
            &self.authority.root,
            std::slice::from_ref(&self.host.signer),
            None,
        )?
        .context("Mission has no aggregate family")?;
        let usage = self
            .host
            .budget
            .get_invocation_quota_usage(&BudgetQuotaKey {
                profile: BudgetQuotaProfile::AggregateFamilyInvocation,
                owner_id: family.owner_id,
                grant_index: None,
            })?
            .context("Mission quota has not been recorded")?;
        let consumed = usage
            .captured_invocations
            .checked_add(usage.reserved_invocations)
            .context("Invocation accounting overflow")?;
        crate::journal::emit(
            &self.directory,
            "authority.capacity",
            "kernel",
            json!({"remaining":family.max_invocations.saturating_sub(consumed),"total":family.max_invocations,"committed":usage.captured_invocations,"reserved":usage.reserved_invocations}),
        )?;
        println!(
            "shared capacity: {}/{} remaining ({} committed, {} reserved)",
            family.max_invocations.saturating_sub(consumed),
            family.max_invocations,
            usage.captured_invocations,
            usage.reserved_invocations
        );
        Ok(())
    }

    pub async fn run(&self, crash_after_repair: bool) -> Result<()> {
        let (mut research, mut implementation, mut review) = tokio::try_join!(
            Process::spawn("coordinator", "research"),
            Process::spawn("coordinator", "implementation"),
            Process::spawn("coordinator", "review"),
        )?;
        let ready = json!({"host_pid": std::process::id(), "swarms": [research.ready, implementation.ready, review.ready],
            "kernel": self.host.signer.to_hex(), "authority_expires_at": self.authority.root.expires_at});
        self.run.emit(
            "processes.ready",
            "mission-coordinator",
            "Three coordinators and six workers are ready",
            ready.clone(),
        )?;
        crate::journal::emit(&self.directory, "processes.ready", "host", ready)?;
        println!("ready: 1 host, 3 swarm coordinators, 6 workers; private IPC");
        crate::journal::emit(
            &self.directory,
            "mission.phase",
            "host",
            json!({"phase":"research"}),
        )?;
        let research_outputs = self
            .round(
                &mut research,
                vec![
                    self.assignment("inspect", "research-0", "inspect", json!({}))?,
                    self.assignment("reproduce", "research-1", "reproduce", json!({}))?,
                ],
            )
            .await?;
        anyhow::ensure!(
            research_outputs[1]["output"]["result"]["passed"] == false
                && research_outputs[1]["output"]["result"]["result"].is_object(),
            "The baseline must compile and execute a failing regression; inspect compiler output if it did not"
        );
        let findings = digest(&research_outputs)?;
        crate::journal::emit(
            &self.directory,
            "mission.phase",
            "host",
            json!({"phase":"implementation"}),
        )?;
        let candidates = self.round(&mut implementation, vec![
            self.assignment("repair-boundary", "implementation-0", "repair", json!({"source": source(&self.directory.join("source"))?, "strategy": "boundary", "findings_sha256": findings}))?,
            self.assignment("repair-wide", "implementation-1", "repair", json!({"source": source(&self.directory.join("source"))?, "strategy": "wide", "findings_sha256": findings}))?,
        ]).await?;
        // End the real process only after effect AND original receipt survive.
        // Children are first drained, so the injected failure leaves no orphans.
        if crash_after_repair {
            tokio::try_join!(research.close(), implementation.close(), review.close())?;
            println!("fault injected: repair effects and receipts committed; host exits before the next handoff (75)");
            std::process::exit(75);
        }
        let selected = candidates
            .iter()
            .find(|c| c["output"]["result"]["tests"]["passed"] == true)
            .context("No repair passed; inspect candidate test logs")?;
        let candidate = &selected["output"]["result"];
        let handoff = json!({"candidate": candidate["candidate"], "candidate_sha256": candidate["candidate_sha256"], "implementation_receipt": selected["receipt"]["id"]});
        crate::journal::emit(
            &self.directory,
            "mission.phase",
            "host",
            json!({"phase":"review"}),
        )?;
        let assessed = self
            .round(
                &mut review,
                vec![
                    self.assignment("test", "review-0", "test", handoff.clone())?,
                    self.assignment("review", "review-1", "review", handoff)?,
                ],
            )
            .await?;
        anyhow::ensure!(
            assessed[0]["output"]["result"]["tests"]["passed"] == true
                && assessed[1]["output"]["result"]["accepted"] == true,
            "Test or review did not accept the candidate"
        );
        let proposal = json!({"candidate": candidate["candidate"], "candidate_sha256": candidate["candidate_sha256"],
            "source_sha256": self.config.source_sha256, "tests_sha256": self.config.tests_sha256,
            "test_receipt": assessed[0]["receipt"]["id"], "review_receipt": assessed[1]["receipt"]["id"], "findings_sha256": findings});
        let proposal_path = self.directory.join("proposal.json");
        if proposal_path.exists() {
            anyhow::ensure!(
                read::<Value>(&proposal_path)? == proposal,
                "Retained proposal changed"
            );
        } else {
            retain(&proposal_path, &proposal)?;
        }
        tokio::try_join!(research.close(), implementation.close(), review.close())?;
        self.run.finish(&Ok(proposal.clone()))?;
        println!(
            "candidate: {}",
            proposal["candidate_sha256"]
                .as_str()
                .context("Candidate digest missing")?
        );
        crate::journal::emit(
            &self.directory,
            "mission.phase",
            "host",
            json!({"phase":"awaiting_review"}),
        )?;
        println!("Ready for your review. Run megastart review, or open the mission console.");
        Ok(())
    }

    pub async fn drill(&self, kind: &str) -> Result<()> {
        let before = files::read_text(&self.directory.join("protected.txt"), 64_000)?;
        let worker = "research-0";
        let tool = match kind {
            "authority" => "write",
            "allowance" => "inspect",
            _ => anyhow::bail!("Choose authority or allowance"),
        };
        let mut task = Assignment {
            id: uuid::Uuid::new_v4().to_string(),
            worker: worker.into(),
            tool: tool.into(),
            input: json!({"source_sha256": self.config.source_sha256}),
        };
        task.input["operation_id"] = json!(task.id);
        let outcome = self.dispatch(&task).await?;
        anyhow::ensure!(
            outcome["allowed"] == false,
            "Expected refusal; the allowance exercise requires a completed six-call mission"
        );
        anyhow::ensure!(
            before == files::read_text(&self.directory.join("protected.txt"), 64_000)?,
            "Protected file changed"
        );
        anyhow::ensure!(
            !self
                .directory
                .join("effects")
                .join(format!("{}.json", task.id))
                .exists(),
            "Refused operation entered the adapter"
        );
        self.run.finish(&Ok(outcome))?;
        println!("{kind}: protected file unchanged; no operation effect");
        Ok(())
    }

    pub async fn publish(&self, candidate: &str, approved: bool) -> Result<()> {
        let proposal: Value = read(&self.directory.join("proposal.json"))?;
        anyhow::ensure!(
            proposal["candidate_sha256"] == candidate,
            "Decision must name the reviewed candidate"
        );
        let request_path = self.directory.join("publication-request.json");
        let mut call: ToolCallRequest = if request_path.exists() {
            read(&request_path)?
        } else {
            let mut g = grant("release", "publish", 1);
            g.constraints = vec![
                Constraint::GovernedIntentRequired,
                Constraint::RequireApprovalAbove { threshold_units: 0 },
            ];
            let cap = self.host.kernel.issue_capability(
                &Keypair::generate().public_key(),
                ChioScope {
                    grants: vec![g],
                    ..Default::default()
                },
                86_400,
            )?;
            let mut call = request(&cap, "release", "publish", proposal.clone());
            call.governed_intent = Some(GovernedTransactionIntent {
                id: call.request_id.clone(),
                server_id: "release".into(),
                tool_name: "publish".into(),
                purpose: "Publish this exact tested candidate locally".into(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: None,
                autonomy: None,
                context: Some(json!({"proposal_sha256": digest(&proposal)?})),
                body: Default::default(),
            });
            retain(&request_path, &call)?;
            call
        };
        anyhow::ensure!(
            call.arguments == proposal,
            "Retained publication request differs from the proposal"
        );
        if approved {
            call.approval_token = Some(
                self.host.approve(
                    &call,
                    true,
                    call.capability
                        .expires_at
                        .min(chio_agent_os_shared::events::now_ms() / 1000 + 120),
                )?,
            );
            let decision = self.directory.join("approval.json");
            if !decision.exists() {
                retain(
                    &decision,
                    &json!({"candidate_sha256": candidate, "approval": call.approval_token}),
                )?;
            }
        } else {
            call.request_id = uuid::Uuid::new_v4().to_string();
        }
        let task = Assignment {
            id: call.request_id.clone(),
            worker: "release-owner".into(),
            tool: "publish".into(),
            input: proposal,
        };
        let outcome_path = self
            .directory
            .join("outcomes")
            .join(format!("{}.json", task.id));
        if outcome_path.exists() {
            let outcome: Value = read(&outcome_path)?;
            verify_outcome(&self.directory, &outcome, &self.host.signer.to_hex())?;
            anyhow::ensure!(
                outcome["allowed"] == true,
                "Prior publication did not complete; inspect the retained refusal"
            );
            println!("publication reconciled: original receipt; no dispatch");
            return Ok(());
        }
        anyhow::ensure!(
            !self.directory.join("release").exists(),
            "Release exists without retained outcome; unresolved: inspect before retry"
        );
        let outcome = self.evaluate(&task, call).await?;
        anyhow::ensure!(
            outcome["allowed"] == approved,
            "Publication did not match the requested decision; inspect receipt"
        );
        self.run.finish(&Ok(outcome))?;
        println!(
            "publication: {}",
            if approved {
                "approved candidate published to release/"
            } else {
                "approval required; release/ absent"
            }
        );
        Ok(())
    }
}

fn verify_outcome(directory: &Path, outcome: &Value, trusted: &str) -> Result<()> {
    let receipt: chio_core::receipt::body::ChioReceipt =
        serde_json::from_value(outcome["receipt"].clone())?;
    anyhow::ensure!(
        receipt.kernel_key.to_hex() == trusted && receipt.verify_signature()?,
        "Receipt signer or signature failed verification"
    );
    anyhow::ensure!(
        receipt.tool_name == outcome["assignment"]["tool"],
        "Receipt belongs to another operation"
    );
    let allowed = serde_json::to_value(&receipt.decision)?["verdict"] == "allow";
    anyhow::ensure!(
        outcome["allowed"] == allowed,
        "Outcome contradicts the signed decision"
    );
    if outcome["allowed"] == true {
        anyhow::ensure!(
            receipt.content_hash == digest(&outcome["output"])?,
            "Retained output does not match the signed content hash"
        );
        if outcome["assignment"]["tool"] == "publish" {
            let release: Value = read(&directory.join("release/release.json"))?;
            anyhow::ensure!(
                release == outcome["output"],
                "Release differs from retained output"
            );
            anyhow::ensure!(
                release["candidate_sha256"] == digest(&source(&directory.join("release"))?)?,
                "Published source changed"
            );
        } else {
            let id = outcome["assignment"]["id"]
                .as_str()
                .context("Missing operation ID")?;
            uuid::Uuid::parse_str(id)?;
            let effect: Value = read(&directory.join("effects").join(format!("{id}.json")))?;
            anyhow::ensure!(
                effect == outcome["output"]
                    && effect["input_sha256"] == digest(&outcome["assignment"]["input"])?,
                "Effect or input differs from retained outcome"
            );
        }
    }
    Ok(())
}

/// Export only inspectable records and effects; never copy authority databases,
/// host keys, worker capabilities, or pending approval tokens into the package.
pub fn export(directory: &Path, destination: &Path) -> Result<()> {
    anyhow::ensure!(!destination.exists(), "Evidence destination already exists");
    files::private_directory(destination)?;
    for name in ["outcomes", "effects", "release"] {
        let origin = directory.join(name);
        if !origin.exists() {
            continue;
        }
        files::private_directory(&destination.join(name))?;
        for entry in std::fs::read_dir(&origin)? {
            let entry = entry?;
            let text = files::read_text(&entry.path(), 2_000_000)?;
            files::create(
                &destination.join(name).join(entry.file_name()),
                text.as_bytes(),
            )?;
        }
    }
    println!("exported retained outcomes and effects; no database or private keys");
    Ok(())
}

pub fn inspect(directory: &Path, trusted: &str) -> Result<Value> {
    let mut receipts = 0;
    let mut refused = 0;
    for entry in std::fs::read_dir(directory.join("outcomes"))? {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let outcome: Value = read(&path)?;
        verify_outcome(directory, &outcome, trusted)?;
        receipts += 1;
        if outcome["allowed"] == false {
            refused += 1;
        }
    }
    Ok(json!({"verified_receipts": receipts, "refused": refused,
        "published": directory.join("release").exists(), "trusted_kernel": trusted}))
}

struct Publisher(PathBuf);
#[async_trait::async_trait]
impl ToolServerConnection for Publisher {
    fn server_id(&self) -> &str {
        "release"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["publish".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        args: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        let publish = || -> Result<Value> {
            let proposal: Value = read(&self.0.join("proposal.json"))?;
            anyhow::ensure!(
                args == proposal,
                "Publication differs from reviewed proposal"
            );
            let id = proposal["candidate"]
                .as_str()
                .context("Candidate missing")?;
            uuid::Uuid::parse_str(id)?;
            let code = source(&self.0.join("candidates").join(id))?;
            anyhow::ensure!(
                digest(&code)? == proposal["candidate_sha256"],
                "Candidate changed after approval"
            );
            let stage = files::StagedDirectory::new(&self.0)?;
            files::create(&stage.path().join("lib.rs"), code.as_bytes())?;
            retain(&stage.path().join("release.json"), &proposal)?;
            stage.publish(&self.0.join("release"))?;
            Ok(proposal)
        };
        publish().map_err(|e| KernelError::ToolServerError(format!("{e:#}")))
    }
}
