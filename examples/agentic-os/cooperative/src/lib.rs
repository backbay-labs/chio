pub mod threshold;
use anyhow::{Context, Result};
use chio_agent_os_shared::{
    async_trait, events::now_ms, graph::digest, json, Application, Run, Value,
};
use chio_personal_network::{
    directory,
    joint::{Action, Policy},
    node::Config,
    Process,
};
use std::path::PathBuf;

pub struct Cooperative;
#[async_trait]
impl Application for Cooperative {
    fn name(&self) -> &'static str {
        "cooperative"
    }
    fn title(&self) -> &'static str {
        "Two operators authorize shared research compute"
    }
    fn description(&self) -> &'static str {
        "Independent member policies decide an exact computation. Both signatures travel over Iroh before the compute owner accepts the work."
    }
    fn sample(&self) -> Value {
        json!({"values":[18,22,26,30],"member_budget":8,"member_accepts":true,"exercise_denials":true})
    }
    async fn execute(&self, input: Value, run: Run) -> Result<Value> {
        if input["mode"] == "threshold" {
            threshold::execute(input, run, std::env::current_exe()?).await
        } else {
            execute_bilateral(input, run, std::env::current_exe()?).await
        }
    }
}

pub async fn execute_bilateral(input: Value, run: Run, executable: PathBuf) -> Result<Value> {
    let values: Vec<f64> = serde_json::from_value(input["values"].clone())?;
    anyhow::ensure!(
        !values.is_empty() && values.len() <= 100 && values.iter().all(|v| v.is_finite()),
        "Provide 1 to 100 finite samples"
    );
    let budget = input["member_budget"]
        .as_u64()
        .context("Choose a member budget")?;
    anyhow::ensure!(budget <= 100, "Member budget cannot exceed 100 work units");
    let root = run.directory()?;
    let issuer = directory::key(&root.join("directory-owner.key"))?;
    let mut members = Vec::new();
    for (name, policy) in [
        (
            "research-lab",
            Policy {
                max_values: 100,
                max_work_units: 100,
                accept: true,
            },
        ),
        (
            "compute-owner",
            Policy {
                max_values: 100,
                max_work_units: budget,
                accept: input["member_accepts"] != false,
            },
        ),
    ] {
        members.push(
            Process::start(
                Config {
                    root: root.join(name),
                    role: "compute".into(),
                    directory_issuer: issuer.public_key(),
                    admin_token: uuid::Uuid::new_v4().to_string(),
                    http_bind: "127.0.0.1:0".into(),
                    http_public_url: None,
                    relay: false,
                    document: String::new(),
                    joint_policy: Some(policy),
                },
                &executable,
            )
            .await?,
        );
    }
    let entries = members
        .iter()
        .map(|m| m.enrollment.entry.clone())
        .collect::<Vec<_>>();
    let mut directories = Vec::new();
    for member in &members {
        let bundle = directory::bundle(
            &issuer,
            &member.enrollment.entry.kernel_id,
            entries.clone(),
            1,
            None,
            now_ms() + 300_000,
        )?;
        member.post("/directory", json!(bundle)).await?;
        directories.push(bundle);
    }
    let requester = &members[0];
    let owner = &members[1];
    let grant = owner
        .post(
            "/grant",
            json!({"peer":requester.enrollment.entry.kernel_id}),
        )
        .await?;
    let action = Action {
        schema: "chio.cooperative.computation.v1".into(),
        nonce: uuid::Uuid::new_v4().to_string(),
        issued_at_ms: now_ms(),
        expires_at_ms: now_ms() + 60_000,
        participants: entries.iter().map(|e| e.kernel_id.clone()).collect(),
        resource_id: "shared-research-compute".into(),
        work_units: values.len() as u64,
        values: values.clone(),
    };
    run.emit(
        "cooperative.proposed",
        "research-lab",
        "Request a bounded research computation",
        json!({
            "action":action,
            "action_sha256":digest(&action)?,
            "members":members.iter().map(|m|json!({
                "node":m.enrollment,
                "policy":m.config.joint_policy
            })).collect::<Vec<_>>()
        }),
    )?;
    let proof = requester
        .post("/cosign", json!({"peer":owner.enrollment,"action":action}))
        .await;
    let proof = match proof {
        Ok(value) => value,
        Err(error) => {
            anyhow::ensure!(
                owner.status().await?["effects"] == 0,
                "A refused proposal produced a protected effect"
            );
            run.emit(
                "cooperative.refused",
                "compute-owner",
                "Member policy refused the proposal before signing",
                json!({"reason":error.to_string(),"effects":0}),
            )?;
            return Ok(
                json!({"status":"denied","action":action,"reason":error.to_string(),"effects":0,"members":entries}),
            );
        }
    };
    let authorization = proof.clone();
    anyhow::ensure!(
        !authorization.is_null(),
        "Member did not return an authorization"
    );
    let dispatch = |args: Value| json!({"peer":owner.enrollment,"capability":grant["capability"],"tool":"statistics","arguments":args});
    let mut denials = json!({});
    if input["exercise_denials"] == true {
        let mut missing = authorization.clone();
        missing["signatures"]
            .as_array_mut()
            .context("No signature list")?
            .pop();
        let insufficient = requester
            .post(
                "/dispatch",
                dispatch(json!({"values":values,"authorization":missing})),
            )
            .await?;
        let mut changed = values.clone();
        changed[0] += 1.0;
        let tampered = requester
            .post(
                "/dispatch",
                dispatch(json!({"values":changed,"authorization":authorization})),
            )
            .await?;
        anyhow::ensure!(
            insufficient["output"].is_null()
                && tampered["output"].is_null()
                && owner.status().await?["effects"] == 0,
            "Invalid approval reached computation"
        );
        denials = json!({"missing_member":insufficient,"changed_values":tampered,"effects_after_refusals":0});
    }
    let computed = requester
        .post(
            "/dispatch",
            dispatch(json!({"values":values,"authorization":authorization})),
        )
        .await?;
    anyhow::ensure!(
        !computed["output"].is_null() && owner.status().await?["effects"] == 1,
        "Approved computation did not execute exactly once"
    );
    if input["exercise_denials"] == true {
        let replay = requester
            .post(
                "/dispatch",
                dispatch(json!({"values":values,"authorization":authorization})),
            )
            .await?;
        anyhow::ensure!(
            replay["output"].is_null() && owner.status().await?["effects"] == 1,
            "An approval nonce authorized a second effect"
        );
        denials["replay"] = replay;
        // A fresh signed action isolates membership removal from nonce replay.
        let mut fresh_action = action.clone();
        fresh_action.nonce = uuid::Uuid::new_v4().to_string();
        let fresh_authorization = requester
            .post(
                "/cosign",
                json!({"peer":owner.enrollment,"action":fresh_action}),
            )
            .await?;
        let mut removed = entries.clone();
        for member in &mut removed {
            if member.kernel_id == requester.enrollment.entry.kernel_id {
                member.removed = true;
            }
        }
        let successor = directory::bundle(
            &issuer,
            &owner.enrollment.entry.kernel_id,
            removed,
            2,
            Some(digest(&directories[1].body)?),
            now_ms() + 300_000,
        )?;
        owner.post("/directory", json!(successor)).await?;
        let refused_effect = requester
            .post(
                "/dispatch",
                dispatch(json!({"values":values,"authorization":fresh_authorization})),
            )
            .await;
        fresh_action.nonce = uuid::Uuid::new_v4().to_string();
        let refused_signature = requester
            .post(
                "/cosign",
                json!({"peer":owner.enrollment,"action":fresh_action}),
            )
            .await;
        anyhow::ensure!(
            refused_effect.is_err()
                && refused_signature.is_err()
                && owner.status().await?["effects"] == 1,
            "Removed membership authorized another signature or protected effect"
        );
        denials["removed_membership"] = json!({"new_signature_refused":true,"fresh_authorization_dispatch_refused":true,"effects":1});
    }
    for member in &members {
        run.emit(
            "cooperative.member",
            "member-host",
            "Independent member execution and original receipts",
            member.status().await?,
        )?;
    }
    run.emit(
        "cooperative.completed",
        "compute-owner",
        "Jointly authorized computation completed",
        computed.clone(),
    )?;
    Ok(json!({
        "status":"completed",
        "action":action,
        "authorization":authorization,
        "computation":computed,
        "effects":1,
        "denials":denials,
        "members":entries,
        "transport":"Chio Iroh bilateral DSSE co-signing; passport-authenticated HTTP execution"
    }))
}
