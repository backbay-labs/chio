//! A member's explicit policy and an exact-action bilateral authorization.
use anyhow::{Context, Result};
use chio_agent_os_shared::{events::now_ms, graph::digest, json, Value};
use chio_core::crypto::{canonical_json_bytes, Keypair, Signature};
use chio_federation::{
    bilateral::{BilateralCoSigningError, DsseCoSigningRequest},
    bilateral_dsse::pae,
};
use chio_federation_transport_iroh::{
    admission::DirectoryGate,
    lanes::bilateral::{BilateralCoSignHandler, IrohBilateralCoSigner, PinnedPassportKeys},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
const PAYLOAD_TYPE: &str = "application/vnd.chio.cooperative-computation.v1+json";
#[derive(Clone, Serialize, Deserialize)]
pub struct Policy {
    pub max_values: usize,
    pub max_work_units: u64,
    pub accept: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub schema: String,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub participants: Vec<String>,
    pub resource_id: String,
    pub values: Vec<f64>,
    pub work_units: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Approval {
    pub action: Action,
    pub signatures: Vec<MemberSignature>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct MemberSignature {
    pub member: String,
    pub signature: Signature,
}
pub fn preimage(action: &Action) -> Result<Vec<u8>> {
    Ok(pae(PAYLOAD_TYPE, &canonical_json_bytes(action)?))
}
fn decode(bytes: &[u8]) -> Result<Action> {
    let prefix = format!("DSSEv1 {} {} ", PAYLOAD_TYPE.len(), PAYLOAD_TYPE);
    let remaining = bytes
        .strip_prefix(prefix.as_bytes())
        .context("Unexpected DSSE payload type")?;
    let space = remaining
        .iter()
        .position(|b| *b == b' ')
        .context("Missing DSSE payload length")?;
    let length = std::str::from_utf8(&remaining[..space])?.parse::<usize>()?;
    let payload = &remaining[space + 1..];
    anyhow::ensure!(
        payload.len() == length && length <= 32_000,
        "Invalid action payload length"
    );
    let action: Action = serde_json::from_slice(payload)?;
    anyhow::ensure!(
        preimage(&action)? == bytes,
        "Action encoding is not canonical"
    );
    Ok(action)
}
pub fn allow(
    policy: &Policy,
    action: &Action,
    local: &str,
    other: &str,
    gate: &DirectoryGate,
) -> Result<()> {
    anyhow::ensure!(
        policy.accept,
        "This member declined the proposal under its local policy"
    );
    anyhow::ensure!(
        action.schema == "chio.cooperative.computation.v1",
        "Unsupported joint action"
    );
    uuid::Uuid::parse_str(&action.nonce)?;
    let now = now_ms();
    anyhow::ensure!(
        action.issued_at_ms <= now
            && now < action.expires_at_ms
            && action.expires_at_ms - action.issued_at_ms <= 300_000,
        "Proposal expired or has an excessive validity window"
    );
    anyhow::ensure!(
        action.participants.len() == 2
            && action.participants.contains(&local.to_string())
            && action.participants.contains(&other.to_string())
            && local != other,
        "Proposal does not bind these two independent members"
    );
    anyhow::ensure!(
        action.resource_id == "shared-research-compute"
            && !action.values.is_empty()
            && action.values.len() <= policy.max_values
            && action.values.iter().all(|v| v.is_finite())
            && action.work_units == action.values.len() as u64
            && action.work_units <= policy.max_work_units,
        "Computation exceeds this member's resource policy"
    );
    let directory = gate.directory();
    anyhow::ensure!(
        directory.expires_at_unix_ms() > now
            && action
                .participants
                .iter()
                .all(|id| directory.resolve_passport_key(id).is_some()),
        "A proposal member is no longer admitted"
    );
    Ok(())
}
struct Pins(DirectoryGate);
impl PinnedPassportKeys for Pins {
    fn passport_key(&self, id: &str) -> Option<chio_core::crypto::PublicKey> {
        self.0.directory().resolve_passport_key(id).cloned()
    }
}
pub fn handler(
    local: String,
    passport: Keypair,
    gate: DirectoryGate,
    policy: Option<Policy>,
) -> BilateralCoSignHandler {
    let checked_gate = gate.clone();
    let checked_local = local.clone();
    BilateralCoSignHandler::new(gate.clone(), local, passport, Arc::new(Pins(gate)))
        .with_request_policy(Arc::new(move |request| {
            let decision = (|| -> Result<()> {
                let policy = policy
                    .as_ref()
                    .context("This node has no joint signing policy")?;
                let action = decode(&request.pae_bytes)?;
                allow(
                    policy,
                    &action,
                    &checked_local,
                    &request.org_b_kernel_id,
                    &checked_gate,
                )
            })();
            decision.map_err(|e| BilateralCoSigningError::PeerRejected(e.to_string()))
        }))
}
pub async fn cosign(
    endpoint: iroh::Endpoint,
    gate: &DirectoryGate,
    local: &str,
    passport: &Keypair,
    policy: &Policy,
    peer: &super::directory::Enrollment,
    action: Action,
) -> Result<Approval> {
    allow(policy, &action, local, &peer.entry.kernel_id, gate)?;
    let bytes = preimage(&action)?;
    let local_signature = passport.sign(&bytes);
    let client = IrohBilateralCoSigner::new(
        endpoint,
        Arc::new(HashMap::from([(
            peer.entry.kernel_id.clone(),
            peer.address.clone(),
        )])),
    );
    let response = client
        .request_dsse_cosignature_over_iroh(&DsseCoSigningRequest::new(
            peer.entry.kernel_id.clone(),
            local.into(),
            bytes.clone(),
            local_signature.clone(),
        ))
        .await?;
    let directory = gate.directory();
    let other = directory
        .resolve_passport_key(&peer.entry.kernel_id)
        .context("Counterparty membership changed")?;
    anyhow::ensure!(
        other.verify_strict(&bytes, &response.org_a_signature),
        "Counterparty returned an invalid signature"
    );
    Ok(Approval {
        action,
        signatures: vec![
            MemberSignature {
                member: local.into(),
                signature: local_signature,
            },
            MemberSignature {
                member: peer.entry.kernel_id.clone(),
                signature: response.org_a_signature,
            },
        ],
    })
}
pub fn verify(
    args: &Value,
    local: &str,
    policy: &Policy,
    gate: &DirectoryGate,
) -> Result<Approval> {
    let proof: Approval = serde_json::from_value(args["authorization"].clone())
        .context("This compute service requires both members to authorize the exact proposal")?;
    let other = proof
        .action
        .participants
        .iter()
        .find(|id| id.as_str() != local)
        .context("Missing independent member")?;
    allow(policy, &proof.action, local, other, gate)?;
    anyhow::ensure!(
        json!(proof.action.values) == args["values"],
        "Approved values differ from the requested computation"
    );
    let bytes = preimage(&proof.action)?;
    let directory = gate.directory();
    anyhow::ensure!(proof.signatures.len() == 2, "Both members must approve");
    let mut seen = std::collections::BTreeSet::new();
    for signed in &proof.signatures {
        anyhow::ensure!(
            seen.insert(&signed.member) && proof.action.participants.contains(&signed.member),
            "Signature set does not match the proposal participants"
        );
        let key = directory
            .resolve_passport_key(&signed.member)
            .context("Signing member was removed")?;
        anyhow::ensure!(
            key.verify_strict(&bytes, &signed.signature),
            "Joint action signature failed"
        );
    }
    let _ = digest(&proof.action)?;
    Ok(proof)
}
