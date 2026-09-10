use anyhow::{Context, Result};
use chio_agent_os_shared::{
    graph::digest,
    host::{grant, private_directory, request, write_json, Host},
    json, Run, Value,
};
use chio_core::{
    capability::{
        governance::GovernedTransactionIntent,
        scope::{ChioScope, Constraint},
    },
    crypto::Keypair,
};
use chio_kernel::{KernelError, NestedFlowBridge, ToolCallRequest, ToolServerConnection};
use std::{
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, Arc},
};

struct Publisher {
    directory: PathBuf,
    proposal: Value,
}
#[async_trait::async_trait]
impl ToolServerConnection for Publisher {
    fn server_id(&self) -> &str {
        "releases"
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
        self.publish(args)
            .map_err(|e| KernelError::ToolServerError(e.to_string()))
    }
}
impl Publisher {
    fn publish(&self, args: Value) -> Result<Value> {
        anyhow::ensure!(
            args == self.proposal["arguments"],
            "Publication parameters differ from the reviewed proposal"
        );
        let files = read_files(
            &self.directory.join("project/candidate"),
            &self.proposal["files"],
        )?;
        anyhow::ensure!(
            digest(&files)? == args["candidate_sha256"],
            "Candidate changed after approval; run the tests and review the new candidate"
        );
        let destination = self.directory.join("release");
        anyhow::ensure!(
            !destination.exists(),
            "Release already exists; reconcile it instead of publishing again"
        );
        let staged = self
            .directory
            .join(format!("release-{}.staged", uuid::Uuid::new_v4()));
        private_directory(&staged)?;
        for (name, contents) in &files {
            std::fs::write(staged.join(name), contents)?;
        }
        write_json(
            &staged.join("release.json"),
            &json!({
                "candidate_sha256":args["candidate_sha256"],
                "test_receipt":args["test_receipt"],
                "review_receipt":args["review_receipt"],
                "files":files.keys().collect::<Vec<_>>()
            }),
        )?;
        std::fs::rename(&staged, &destination)?;
        Ok(
            json!({"published":true,"candidate_sha256":args["candidate_sha256"],"files":files,"release_directory":"release"}),
        )
    }
}
fn read_files(
    directory: &Path,
    names: &Value,
) -> Result<std::collections::BTreeMap<String, String>> {
    let mut files = std::collections::BTreeMap::new();
    for name in names.as_array().context("Proposal has no file set")? {
        let name = name.as_str().context("File names must be strings")?;
        anyhow::ensure!(
            Path::new(name).components().count() == 1
                && !name.starts_with('.')
                && name.ends_with(".py"),
            "Invalid publication filename"
        );
        let path = directory.join(name);
        anyhow::ensure!(
            !path.symlink_metadata()?.file_type().is_symlink(),
            "Publication refuses symlinks"
        );
        files.insert(name.into(), std::fs::read_to_string(path)?);
    }
    Ok(files)
}
fn boot(directory: &Path, proposal: Value) -> Result<Host> {
    Host::open(
        &directory.join("release-host"),
        "factory-exact-candidate-approval-v1",
        vec![Box::new(Publisher {
            directory: directory.into(),
            proposal,
        })],
    )
}

pub async fn prepare(run: &Run, arguments: Value, files: Vec<String>) -> Result<Value> {
    let directory = run.directory()?;
    let proposal = json!({"arguments":arguments,"files":files,"source_run":run.id()?});
    let host = boot(&directory, proposal.clone())?;
    let mut grant = grant("releases", "publish", 1);
    grant.constraints = vec![
        Constraint::GovernedIntentRequired,
        Constraint::RequireApprovalAbove { threshold_units: 0 },
    ];
    let cap = host.kernel.issue_capability(
        &Keypair::generate().public_key(),
        ChioScope {
            grants: vec![grant],
            ..Default::default()
        },
        900,
    )?;
    let mut call = request(&cap, "releases", "publish", proposal["arguments"].clone());
    call.governed_intent = Some(GovernedTransactionIntent {
        id: call.request_id.clone(),
        server_id: "releases".into(),
        tool_name: "publish".into(),
        purpose: "Publish the exact candidate reviewed by the release owner".into(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(
            json!({"publication":proposal["arguments"],"arguments_sha256":digest(&call.arguments)?}),
        ),
        body: Default::default(),
    });
    write_json(&directory.join("publication-proposal.json"), &proposal)?;
    write_json(&directory.join("publication-request.json"), &json!(call))?;
    let mut unapproved = call.clone();
    unapproved.request_id = uuid::Uuid::new_v4().to_string();
    let denied = host
        .call_controlled(
            run,
            "unapproved-publisher",
            unapproved,
            None,
            Arc::new(AtomicBool::new(false)),
        )
        .await?;
    anyhow::ensure!(
        !denied.allowed && !directory.join("release").exists(),
        "Unapproved publication produced an effect"
    );
    Ok(json!({
        "source_run":run.id()?,
        "candidate_sha256":arguments["candidate_sha256"],
        "proposal_sha256":digest(&proposal)?,
        "expires_at":cap.expires_at,
        "status":"pending",
        "request_id":call.request_id
    }))
}

pub async fn decide(input: Value, run: Run) -> Result<Value> {
    let source = uuid::Uuid::parse_str(
        input["source_run"]
            .as_str()
            .context("Choose the original run")?,
    )?
    .to_string();
    let current = run.directory()?;
    let directory = current
        .parent()
        .context("Run has no application root")?
        .join(&source);
    let proposal: Value =
        serde_json::from_slice(&std::fs::read(directory.join("publication-proposal.json"))?)?;
    anyhow::ensure!(
        proposal["source_run"] == source && input["proposal_sha256"] == digest(&proposal)?,
        "Proposal changed; reload the original run before deciding"
    );
    anyhow::ensure!(
        input["candidate_sha256"] == proposal["arguments"]["candidate_sha256"],
        "Approval must name the exact candidate"
    );
    let approved = match input["decision"].as_str() {
        Some("approve") => true,
        Some("reject") => false,
        _ => anyhow::bail!("Choose approve or reject"),
    };
    anyhow::ensure!(
        !approved || proposal["arguments"]["eligible"] == true,
        "Tests or review did not accept this candidate"
    );
    let actual = read_files(&directory.join("project/candidate"), &proposal["files"])?;
    anyhow::ensure!(
        digest(&actual)? == proposal["arguments"]["candidate_sha256"],
        "Candidate changed; rerun its tests and review before publication"
    );
    let decisionfile = directory.join("publication-decision.json");
    if decisionfile.exists() {
        let retained: Value = serde_json::from_slice(&std::fs::read(decisionfile)?)?;
        anyhow::ensure!(
            retained["decision"] == input["decision"],
            "A different decision already resolved this proposal"
        );
        if directory.join("publication-result.json").exists() {
            let result: Value =
                serde_json::from_slice(&std::fs::read(directory.join("publication-result.json"))?)?;
            if result["published"] == true {
                let release: Value = serde_json::from_slice(&std::fs::read(
                    directory.join("release/release.json"),
                )?)?;
                anyhow::ensure!(
                    release["candidate_sha256"] == input["candidate_sha256"]
                        && digest(&read_files(&directory.join("release"), &proposal["files"])?)?
                            == input["candidate_sha256"],
                    "Published release needs operator inspection"
                );
            }
            run.emit(
                "publication.reconciled",
                "release-owner",
                "Returned the retained publication decision",
                result.clone(),
            )?;
            return Ok(result);
        }
        anyhow::bail!("A decision was retained without a final acknowledgement. Inspect the release directory and admission record before retrying");
    }
    let mut lock = std::fs::OpenOptions::new();
    lock.write(true).create_new(true);
    let _lock = lock
        .open(directory.join("publication-decision.lock"))
        .context("Another decision is active or was interrupted; inspect its retained state")?;
    let host = boot(&directory, proposal.clone())?;
    let mut call: ToolCallRequest =
        serde_json::from_slice(&std::fs::read(directory.join("publication-request.json"))?)?;
    anyhow::ensure!(
        call.arguments == proposal["arguments"] && call.capability.issuer == host.signer,
        "Publication request does not match its retained host and proposal"
    );
    let now = chio_agent_os_shared::events::now_ms() / 1000;
    anyhow::ensure!(
        now < call.capability.expires_at,
        "Publication authority expired. Prepare and review a new proposal"
    );
    call.approval_token =
        Some(host.approve(&call, approved, call.capability.expires_at.min(now + 120))?);
    write_json(
        &decisionfile,
        &json!({"decision":input["decision"],"candidate_sha256":input["candidate_sha256"],"approval":call.approval_token}),
    )?;
    let result = host
        .call_controlled(
            &run,
            "release-owner",
            call,
            None,
            Arc::new(AtomicBool::new(false)),
        )
        .await?;
    let published = result.allowed && result.output["published"] == true;
    anyhow::ensure!(
        approved || !directory.join("release").exists(),
        "Rejected proposal produced a release"
    );
    let output = json!({
        "published":published,
        "decision":input["decision"],
        "source_run":source,
        "candidate_sha256":input["candidate_sha256"],
        "receipt_id":result.receipt_id,
        "release":result.output
    });
    write_json(&directory.join("publication-result.json"), &output)?;
    run.emit(
        "publication.decided",
        "release-owner",
        if published {
            "Published the approved candidate"
        } else {
            "Publication was refused"
        },
        output.clone(),
    )?;
    Ok(output)
}
