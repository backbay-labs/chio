//! One durable authority, a delegation family, and a shared invocation ceiling.
use anyhow::Result;
use chio_agent_os_shared::{
    events::now_ms,
    host::{grant, Host},
};
use chio_core::{
    capability::{
        attenuation::{
            compute_attenuation_witness, delegate, scope_hash, Attenuation, AttenuationProof,
        },
        scope::{ChioScope, Operation},
        token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody},
    },
    crypto::Keypair,
    delegation_receipt::ScopeAttenuation,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

#[derive(Serialize, Deserialize)]
pub struct Authority {
    pub root: CapabilityToken,
    pub coordinators: BTreeMap<String, CapabilityToken>,
    pub workers: BTreeMap<String, CapabilityToken>,
}

fn child(
    parent: &CapabilityToken,
    owner: &Keypair,
    issuer: &Keypair,
    tools: &[&str],
    delegable: bool,
) -> Result<(CapabilityToken, Keypair)> {
    let subject = Keypair::generate();
    let mut scope = parent.scope.clone();
    let mut steps = Vec::new();
    scope.grants.retain(|g| {
        if tools.contains(&g.tool_name.as_str()) {
            true
        } else {
            steps.push(Attenuation::RemoveTool {
                server_id: g.server_id.clone(),
                tool_name: g.tool_name.clone(),
            });
            false
        }
    });
    if !delegable {
        for g in &mut scope.grants {
            g.operations.retain(|op| *op != Operation::Delegate);
            steps.push(Attenuation::RemoveOperation {
                server_id: g.server_id.clone(),
                tool_name: g.tool_name.clone(),
                operation: Operation::Delegate,
            });
        }
    }
    let now = now_ms() / 1000;
    let delegation = delegate(
        parent,
        &scope,
        owner,
        &subject.public_key(),
        ScopeAttenuation {
            steps,
            child_expires_at: Some(parent.expires_at),
            budget_share_bps: Some(1_000),
        },
        now,
        *uuid::Uuid::new_v4().as_bytes(),
    )?;
    let token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: uuid::Uuid::new_v4().to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: scope.clone(),
                issued_at: now,
                expires_at: parent.expires_at,
                delegation_chain: delegation.complete_chain(),
                aggregate_invocation_budget: parent.aggregate_invocation_budget.clone(),
            },
            caveats: Vec::new(),
            scope_attenuations: delegation.attenuation.steps,
            attenuation_proof: AttenuationProof {
                parent_scope_hash: scope_hash(&parent.scope)?,
                child_scope_hash: scope_hash(&scope)?,
                normalized_subset_proof: compute_attenuation_witness(&parent.scope, &scope)?,
            },
            budget_share_bps: Some(1_000),
        },
        issuer,
    )?;
    Ok((token, subject))
}

impl Authority {
    pub fn load_or_create(
        directory: &Path,
        host: &Host,
        issuer: &Keypair,
        allowance: u32,
    ) -> Result<Self> {
        let path = directory.join("authority.json");
        let authority: Self = if path.exists() {
            crate::read(&path)?
        } else {
            let owner = Keypair::generate();
            let mut grants = Vec::new();
            for tool in ["inspect", "reproduce", "repair", "test", "review"] {
                let mut g = grant("workspace", tool, 32);
                g.operations.push(Operation::Delegate);
                grants.push(g);
            }
            let now = now_ms() / 1000;
            let root = CapabilityToken::sign_aggregate_family_root(
                CapabilityTokenBody {
                    id: uuid::Uuid::new_v4().to_string(),
                    issuer: issuer.public_key(),
                    subject: owner.public_key(),
                    scope: ChioScope {
                        grants,
                        ..Default::default()
                    },
                    issued_at: now,
                    expires_at: now + 86_400,
                    delegation_chain: Vec::new(),
                    aggregate_invocation_budget: None,
                },
                allowance,
                issuer,
            )?;
            let mut coordinators = BTreeMap::new();
            let mut workers = BTreeMap::new();
            for (swarm, tools) in [
                ("research", vec!["inspect", "reproduce"]),
                ("implementation", vec!["repair"]),
                ("review", vec!["test", "review"]),
            ] {
                let (coordinator, _) = child(&root, &owner, issuer, &tools, true)?;
                for index in 0..2 {
                    let worker_tools = match swarm {
                        "research" => vec![tools[index]],
                        "review" => vec![tools[index]],
                        _ => tools.clone(),
                    };
                    // This public kernel supports one-hop aggregate families.
                    // The mission authority issues each worker directly; swarm
                    // coordinators schedule work without extending that chain.
                    let (worker, _) = child(&root, &owner, issuer, &worker_tools, false)?;
                    workers.insert(format!("{swarm}-{index}"), worker);
                }
                coordinators.insert(swarm.to_owned(), coordinator);
            }
            let authority = Self {
                root,
                coordinators,
                workers,
            };
            crate::retain(&path, &authority)?;
            authority
        };
        anyhow::ensure!(
            authority.root.issuer == host.signer && authority.root.verify_signature()?,
            "Authority does not belong to this retained kernel"
        );
        host.kernel
            .set_capability_trust_root(host.signer.clone(), scope_hash(&authority.root.scope)?);
        host.kernel
            .register_budget_parent(authority.root.id.clone(), 10_000)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let receipts =
            chio_store_sqlite::SqliteReceiptStore::open(directory.join("kernel/receipts.db"))?;
        receipts.record_capability_snapshot(&authority.root, None)?;
        for coordinator in authority.coordinators.values() {
            receipts.record_capability_snapshot(coordinator, Some(&authority.root.id))?;
        }
        Ok(authority)
    }
}
