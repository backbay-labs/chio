use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::capability::attenuation::{validate_attenuation_proof, AttenuationWitness};
use chio_core_types::crypto::{PublicKey, Signature};
use serde::Serialize;

use crate::error::SwarmAuthorityError;
use crate::types::{
    SwarmAuthorityBundle, SwarmDelegationWitnessChain, SwarmDelegationWitnessHop, SwarmGraphNode,
    CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA,
};

use super::util::{rejected, require_non_empty, require_same_graph, require_sha256};

pub(super) const DID_CHIO_PREFIX: &str = "did:chio:";

const CHIO_SWARM_DELEGATION_WITNESS_HOP_SIGNATURE_SCHEMA: &str =
    "chio.swarm.delegation-witness-hop-signature.v1";

pub(super) fn validate_witness_chains(
    bundle: &SwarmAuthorityBundle,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
    edge_set: &BTreeSet<(&str, &str)>,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    let mut witnessed_edges = BTreeSet::new();
    for chain in &bundle.witness_chains {
        validate_witness_chain(
            bundle,
            chain,
            task_by_id,
            edge_set,
            trusted_witness_issuer_keys,
        )?;
        if !witnessed_edges.insert((chain.parent_task_id.as_str(), chain.child_task_id.as_str())) {
            return Err(rejected(format!(
                "duplicate swarm delegation witness chain: {} -> {}",
                chain.parent_task_id, chain.child_task_id
            )));
        }
    }
    for edge in edge_set {
        if !witnessed_edges.contains(edge) {
            return Err(rejected(format!(
                "missing swarm delegation witness chain: {} -> {}",
                edge.0, edge.1
            )));
        }
    }
    Ok(())
}

fn validate_witness_chain(
    bundle: &SwarmAuthorityBundle,
    chain: &SwarmDelegationWitnessChain,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
    edge_set: &BTreeSet<(&str, &str)>,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    if chain.schema != CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA {
        return Err(rejected(format!(
            "unsupported swarm delegation witness chain schema: {}",
            chain.schema
        )));
    }
    require_non_empty(&chain.chain_id, "swarm witness chain id")?;
    require_same_graph(
        &chain.graph_id,
        &bundle.task_graph.graph_id,
        "witness chain",
    )?;
    if !edge_set.contains(&(chain.parent_task_id.as_str(), chain.child_task_id.as_str())) {
        return Err(rejected(format!(
            "swarm witness chain edge mismatch: {}",
            chain.chain_id
        )));
    }
    let parent = task_by_id
        .get(chain.parent_task_id.as_str())
        .ok_or_else(|| {
            rejected(format!(
                "swarm witness chain parent task is unknown: {}",
                chain.parent_task_id
            ))
        })?;
    let child = task_by_id
        .get(chain.child_task_id.as_str())
        .ok_or_else(|| {
            rejected(format!(
                "swarm witness chain child task is unknown: {}",
                chain.child_task_id
            ))
        })?;
    if chain.hops.is_empty() {
        return Err(rejected(format!(
            "swarm witness chain has no hops: {}",
            chain.chain_id
        )));
    }
    let Some(first_hop) = chain.hops.first() else {
        return Err(rejected(format!(
            "swarm witness chain has no hops: {}",
            chain.chain_id
        )));
    };
    let Some(last_hop) = chain.hops.last() else {
        return Err(rejected(format!(
            "swarm witness chain has no hops: {}",
            chain.chain_id
        )));
    };
    if first_hop.parent_scope_hash != parent.scope_hash {
        return Err(rejected(format!(
            "swarm witness parent scope mismatch: {}",
            chain.chain_id
        )));
    }
    if last_hop.child_scope_hash != child.scope_hash {
        return Err(rejected(format!(
            "swarm witness child scope mismatch: {}",
            chain.chain_id
        )));
    }
    if chain.hops.len() > 1 && !bundle.task_graph.multi_hop_witness_chains {
        return Err(rejected(format!(
            "swarm multi-hop witness chain feature gate missing: {}",
            chain.chain_id
        )));
    }
    let mut previous_hop: Option<&SwarmDelegationWitnessHop> = None;
    for hop in &chain.hops {
        validate_witness_hop(bundle, chain, hop, trusted_witness_issuer_keys)?;
        if let Some(previous) = previous_hop {
            if previous.child_scope_hash != hop.parent_scope_hash {
                return Err(rejected(format!(
                    "swarm witness hop scope discontinuity: {}",
                    chain.chain_id
                )));
            }
            if previous.child_capability_digest != hop.parent_capability_digest {
                return Err(rejected(format!(
                    "swarm witness hop capability discontinuity: {}",
                    chain.chain_id
                )));
            }
        }
        previous_hop = Some(hop);
    }
    Ok(())
}

fn validate_witness_hop(
    bundle: &SwarmAuthorityBundle,
    chain: &SwarmDelegationWitnessChain,
    hop: &SwarmDelegationWitnessHop,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    require_sha256(
        &hop.parent_capability_digest,
        "swarm witness parent capability digest",
    )?;
    require_sha256(
        &hop.child_capability_digest,
        "swarm witness child capability digest",
    )?;
    require_sha256(&hop.parent_scope_hash, "swarm witness parent scope hash")?;
    require_sha256(&hop.child_scope_hash, "swarm witness child scope hash")?;
    require_non_empty(&hop.attenuation_rule_id, "swarm witness attenuation rule")?;
    require_non_empty(&hop.issuer, "swarm witness issuer")?;
    require_sha256(&hop.policy_digest, "swarm witness policy digest")?;
    require_non_empty(&hop.witness_signature, "swarm witness signature")?;
    if hop.expires_at_unix_ms <= bundle.now_unix_ms {
        return Err(rejected(format!(
            "swarm witness hop is stale: {}",
            chain.chain_id
        )));
    }
    validate_attenuation_proof(
        &hop.parent_scope_hash,
        &hop.child_scope_hash,
        &hop.scope_subset_proof,
    )
    .map_err(|error| rejected(format!("swarm attenuation witness invalid: {error}")))?;
    verify_witness_signature(chain, hop, trusted_witness_issuer_keys)?;
    Ok(())
}

fn verify_witness_signature(
    chain: &SwarmDelegationWitnessChain,
    hop: &SwarmDelegationWitnessHop,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    let public_key = witness_issuer_public_key(&hop.issuer)?;
    ensure_witness_issuer_is_pinned(chain, &public_key, trusted_witness_issuer_keys)?;
    let signature = Signature::from_hex(&hop.witness_signature).map_err(|error| {
        rejected(format!(
            "swarm witness signature invalid: {}: {error}",
            chain.chain_id
        ))
    })?;
    let body = witness_signature_body(chain, hop);
    let verified = public_key
        .verify_canonical(&body, &signature)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    if verified {
        Ok(())
    } else {
        Err(rejected(format!(
            "swarm witness signature invalid: {}",
            chain.chain_id
        )))
    }
}

fn ensure_witness_issuer_is_pinned(
    chain: &SwarmDelegationWitnessChain,
    public_key: &PublicKey,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    if trusted_witness_issuer_keys.is_empty() {
        return Err(rejected(
            "trusted swarm witness keys missing: CHIO_SWARM_TRUSTED_WITNESS_KEYS must pin trusted swarm witness keys",
        ));
    }
    if trusted_witness_issuer_keys
        .iter()
        .any(|trusted_key| trusted_key == public_key)
    {
        Ok(())
    } else {
        Err(rejected(format!(
            "swarm witness issuer is not trusted: {}",
            chain.chain_id
        )))
    }
}

pub(super) fn witness_issuer_public_key(issuer: &str) -> Result<PublicKey, SwarmAuthorityError> {
    let public_key_hex = if let Some(public_key_hex) = issuer.strip_prefix(DID_CHIO_PREFIX) {
        if public_key_hex.len() != 64 || !public_key_hex.bytes().all(is_lower_hex_byte) {
            return Err(rejected(
                "swarm witness issuer did:chio is not self-certifying",
            ));
        }
        public_key_hex
    } else {
        issuer
    };
    PublicKey::from_hex(public_key_hex)
        .map_err(|error| rejected(format!("swarm witness issuer public key invalid: {error}")))
}

fn is_lower_hex_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SwarmWitnessHopSignatureBody<'a> {
    schema: &'static str,
    graph_id: &'a str,
    chain_id: &'a str,
    parent_task_id: &'a str,
    child_task_id: &'a str,
    parent_capability_digest: &'a str,
    child_capability_digest: &'a str,
    parent_scope_hash: &'a str,
    child_scope_hash: &'a str,
    attenuation_rule_id: &'a str,
    scope_subset_proof: &'a AttenuationWitness,
    expires_at_unix_ms: u64,
    issuer: &'a str,
    policy_digest: &'a str,
}

pub(super) fn witness_signature_body<'a>(
    chain: &'a SwarmDelegationWitnessChain,
    hop: &'a SwarmDelegationWitnessHop,
) -> SwarmWitnessHopSignatureBody<'a> {
    SwarmWitnessHopSignatureBody {
        schema: CHIO_SWARM_DELEGATION_WITNESS_HOP_SIGNATURE_SCHEMA,
        graph_id: &chain.graph_id,
        chain_id: &chain.chain_id,
        parent_task_id: &chain.parent_task_id,
        child_task_id: &chain.child_task_id,
        parent_capability_digest: &hop.parent_capability_digest,
        child_capability_digest: &hop.child_capability_digest,
        parent_scope_hash: &hop.parent_scope_hash,
        child_scope_hash: &hop.child_scope_hash,
        attenuation_rule_id: &hop.attenuation_rule_id,
        scope_subset_proof: &hop.scope_subset_proof,
        expires_at_unix_ms: hop.expires_at_unix_ms,
        issuer: &hop.issuer,
        policy_digest: &hop.policy_digest,
    }
}
