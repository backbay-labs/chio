use crate::{
    host::{request, Call, Host},
    Run,
};
use anyhow::{Context, Result};
use chio_core::capability::{governance::GovernedTransactionIntent, token::CapabilityToken};
use chio_runtime_core::{
    runtime_admission_bundle_sha256, ChioRuntimeAdmissionHook, RuntimeAdmissionBundle,
    RuntimeAdmissionProfile, RuntimeRequestBinding, SqliteRuntimeOrchestrationStore,
};
use chio_swarm_authority::SwarmAuthorityBundle;
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    path::Path,
    sync::{atomic::AtomicBool, Arc},
};

pub fn digest(value: &impl Serialize) -> Result<String> {
    Ok(chio_core::sha256_hex(&chio_core::canonical_json_bytes(
        value,
    )?))
}
fn reference(id: &str, value: &impl Serialize) -> Result<Value> {
    Ok(json!({"id":id,"sha256":digest(value)?}))
}

pub struct GraphRuntime {
    store: SqliteRuntimeOrchestrationStore,
    pub bundle: SwarmAuthorityBundle,
    local_id: String,
}
impl GraphRuntime {
    /// Install admission on the effect-owning kernel, after planning and before
    /// issuing any worker call. Subsequent calls require a stored admission.
    pub fn attach(host: &mut Host, bundle: SwarmAuthorityBundle, path: &Path) -> Result<Self> {
        let store = SqliteRuntimeOrchestrationStore::open(path)?;
        store.insert_swarm_authority_bundle(bundle.clone())?;
        let local_id = host.signer.to_hex();
        let profile = RuntimeAdmissionProfile {
            schema: "chio.runtime.admission-profile.v1".into(),
            profile_id: format!("{}:runtime", bundle.task_graph.graph_id),
            local_kernel_id: local_id.clone(),
            verifier_id: format!("did:chio:{local_id}"),
            issued_at_unix_ms: bundle.now_unix_ms,
            expires_at_unix_ms: bundle.task_graph.expires_at_unix_ms,
        };
        let hook =
            ChioRuntimeAdmissionHook::new(profile, SqliteRuntimeOrchestrationStore::open(path)?)
                .with_swarm_witness_keys(vec![host.signer.clone()]);
        Arc::get_mut(&mut host.kernel)
            .context("Install the graph before sharing this kernel with workers")?
            .set_runtime_admission_hook(Arc::new(hook));
        Ok(Self {
            store,
            bundle,
            local_id,
        })
    }
    pub fn prepare(
        &self,
        cap: &CapabilityToken,
        task_id: &str,
        tool: &str,
        args: Value,
    ) -> Result<(chio_kernel::ToolCallRequest, Value)> {
        let token = self
            .bundle
            .continuation_tokens
            .iter()
            .find(|token| token.child_task_id == task_id)
            .context("Task has no continuation")?;
        let route = self
            .bundle
            .route_plan_receipts
            .iter()
            .find(|route| route.route_plan_id == token.route_plan_receipt_id)
            .context("Task has no route")?;
        let chain = self
            .bundle
            .witness_chains
            .iter()
            .find(|chain| Some(chain.chain_id.as_str()) == token.witness_chain_ref.as_deref())
            .context("Task has no witness")?;
        let mut call = request(cap, "factory-workers", tool, args.clone());
        let id = format!("{}:admission", call.request_id);
        let admission = RuntimeAdmissionBundle {
            schema: "chio.runtime.admission-bundle.v1".into(),
            admission_id: id.clone(),
            binding: RuntimeRequestBinding {
                request_id: call.request_id.clone(),
                capability_id: cap.id.clone(),
                server_id: call.server_id.clone(),
                tool_name: tool.into(),
                tool_args_sha256: digest(&args)?,
                origin_kernel_id: None,
                host_kernel_id: self.local_id.clone(),
            },
            workflow_id: self.bundle.task_graph.graph_id.clone(),
            workflow_grant_id: cap.id.clone(),
            step_index: 1,
            destructive: false,
            lease_id: None,
            governance_receipt_id: None,
            trust_bundle_sha256: digest(&vec![&self.local_id])?,
            verification_context_sha256: digest(&self.bundle.task_graph)?,
        };
        let hash = runtime_admission_bundle_sha256(&admission)?;
        self.store.insert_bundle(admission)?;
        call.governed_intent = Some(GovernedTransactionIntent {
            id: format!("{}:intent", call.request_id),
            server_id: call.server_id.clone(),
            tool_name: tool.into(),
            purpose: format!("Execute {task_id} under its signed graph continuation"),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(
                json!({"chioAdmission":{"admissionId":id,"bundleSha256":hash},"chioSwarm":{
                    "taskGraph":reference(&self.bundle.task_graph.graph_id,&self.bundle.task_graph)?,
                    "continuationToken":reference(&token.token_id,token)?,
                    "routePlanReceipt":reference(&route.route_plan_id,route)?,
                    "delegationWitness":reference(&chain.chain_id,chain)?,
                    "revocationEpoch":reference(&self.bundle.revocation_epoch.epoch_id,&self.bundle.revocation_epoch)?,
                    "budgetPool":reference(&self.bundle.budget_pool.pool_id,&self.bundle.budget_pool)?,
                }}),
            ),
            body: Default::default(),
        });
        Ok((
            call,
            json!({
                "route":{
                    "bridge":route.bridge_id,
                    "protocolTarget":route.protocol_target,
                    "selectedRoute":route.selected_route
                }
            }),
        ))
    }
    pub async fn call(
        &self,
        host: &Host,
        run: &Run,
        cap: &CapabilityToken,
        task: &str,
        tool: &str,
        args: Value,
    ) -> Result<Call> {
        let (request, metadata) = self.prepare(cap, task, tool, args)?;
        host.call_controlled(
            run,
            task,
            request,
            Some(metadata),
            Arc::new(AtomicBool::new(false)),
        )
        .await
    }
}
