use chio_core::web3::anchors::{
    verify_anchor_inclusion_proof, AnchorInclusionProof, CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA_V1,
    CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA_V2,
};
use chio_kernel::checkpoint::{describe_checkpoint_equivocation, CheckpointTransparencySummary};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    verify_bitcoin_anchor_for_proof, verify_solana_anchor, AnchorError, SolanaMemoAnchorRecord,
};

pub const CHIO_ANCHOR_PROOF_BUNDLE_SCHEMA_V1: &str = "chio.anchor-proof-bundle.v1";
pub const CHIO_ANCHOR_PROOF_BUNDLE_SCHEMA_V2: &str = "chio.anchor-proof-bundle.v2";
pub const CHIO_ANCHOR_PROOF_BUNDLE_SCHEMA: &str = CHIO_ANCHOR_PROOF_BUNDLE_SCHEMA_V2;

fn deserialize_non_null_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    if value.is_null() {
        return Err(<D::Error as serde::de::Error>::custom(
            "explicit null is not permitted; omit the optional field",
        ));
    }
    T::deserialize(value)
        .map(Some)
        .map_err(<D::Error as serde::de::Error>::custom)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorLaneKind {
    EvmPrimary,
    BitcoinOts,
    SolanaMemo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorProofBundle {
    pub schema: String,
    pub primary_proof: AnchorInclusionProof,
    pub secondary_lanes: Vec<AnchorLaneKind>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_option"
    )]
    pub solana_anchor: Option<SolanaMemoAnchorRecord>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_option"
    )]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorVerificationLane {
    pub lane: AnchorLaneKind,
    pub verified: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorVerificationReport {
    pub verified: bool,
    pub lanes: Vec<AnchorVerificationLane>,
}

pub fn verify_proof_bundle(
    bundle: &AnchorProofBundle,
) -> Result<AnchorVerificationReport, AnchorError> {
    let required_primary_schema = match bundle.schema.as_str() {
        CHIO_ANCHOR_PROOF_BUNDLE_SCHEMA_V1 => CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA_V1,
        CHIO_ANCHOR_PROOF_BUNDLE_SCHEMA_V2 => CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA_V2,
        _ => {
            return Err(AnchorError::Verification(format!(
                "unsupported bundle schema {}",
                bundle.schema
            )))
        }
    };
    if bundle.primary_proof.schema != required_primary_schema {
        return Err(AnchorError::Verification(format!(
            "bundle schema {} requires primary proof schema {}",
            bundle.schema, required_primary_schema
        )));
    }
    if bundle.secondary_lanes.is_empty() {
        return Err(AnchorError::Verification(
            "proof bundle must declare at least one lane".to_string(),
        ));
    }
    if bundle.secondary_lanes.contains(&AnchorLaneKind::EvmPrimary) {
        return Err(AnchorError::Verification(
            "proof bundle secondary lanes must not declare the primary EVM lane".to_string(),
        ));
    }

    let mut lanes = Vec::new();
    verify_anchor_inclusion_proof(&bundle.primary_proof)
        .map_err(|error| AnchorError::Verification(error.to_string()))?;
    lanes.push(AnchorVerificationLane {
        lane: AnchorLaneKind::EvmPrimary,
        verified: true,
        note: "primary EVM proof verified against Chio receipt and checkpoint truth".to_string(),
    });

    if bundle.primary_proof.bitcoin_anchor.is_some() {
        if !bundle.secondary_lanes.contains(&AnchorLaneKind::BitcoinOts) {
            return Err(AnchorError::Verification(
                "bundle includes Bitcoin anchor data but does not declare the Bitcoin OTS lane"
                    .to_string(),
            ));
        }
        let inspection = verify_bitcoin_anchor_for_proof(&bundle.primary_proof)?;
        // The `is_some()` guard above already proved bitcoin_anchor is
        // present, so the `.as_ref()` map is the live branch in
        // practice; the inspection-derived fallback exists only so this
        // expression is total without panicking on direct indexing.
        let bitcoin_height = match bundle
            .primary_proof
            .bitcoin_anchor
            .as_ref()
            .map(|anchor| anchor.bitcoin_block_height)
        {
            Some(height) => height,
            None => match inspection.bitcoin_attestation_heights.first().copied() {
                Some(height) => height,
                None => {
                    return Err(AnchorError::Verification(
                        "OTS proof has no Bitcoin attestation height to record".to_string(),
                    ));
                }
            },
        };
        lanes.push(AnchorVerificationLane {
            lane: AnchorLaneKind::BitcoinOts,
            verified: true,
            note: format!(
                "secondary Bitcoin OTS linkage commits to the Chio super-root digest and attests block {}",
                bitcoin_height
            ),
        });
    } else if bundle.secondary_lanes.contains(&AnchorLaneKind::BitcoinOts) {
        return Err(AnchorError::Verification(
            "bundle declares Bitcoin OTS lane but the primary proof lacks bitcoin anchor data"
                .to_string(),
        ));
    }

    if let Some(solana) = bundle.solana_anchor.as_ref() {
        if !bundle.secondary_lanes.contains(&AnchorLaneKind::SolanaMemo) {
            return Err(AnchorError::Verification(
                "bundle includes Solana anchor data but does not declare the Solana memo lane"
                    .to_string(),
            ));
        }
        verify_solana_anchor(&bundle.primary_proof, solana)?;
        lanes.push(AnchorVerificationLane {
            lane: AnchorLaneKind::SolanaMemo,
            verified: true,
            note: "secondary Solana memo anchor matches the canonical checkpoint payload"
                .to_string(),
        });
    } else if bundle.secondary_lanes.contains(&AnchorLaneKind::SolanaMemo) {
        return Err(AnchorError::Verification(
            "bundle declares Solana lane but does not include a Solana anchor record".to_string(),
        ));
    }

    Ok(AnchorVerificationReport {
        verified: true,
        lanes,
    })
}

pub fn verify_checkpoint_publication_records(
    transparency: &CheckpointTransparencySummary,
) -> Result<(), AnchorError> {
    if let Some(equivocation) = transparency.equivocations.first() {
        return Err(AnchorError::Verification(format!(
            "checkpoint publication conflict detected: {}",
            describe_checkpoint_equivocation(equivocation)
        )));
    }

    for publication in &transparency.publications {
        if let Some(binding) = publication.trust_anchor_binding.as_ref() {
            binding
                .validate()
                .map_err(|error| AnchorError::Verification(error.to_string()))?;
            continue;
        }

        let has_successor_witness = transparency.witnesses.iter().any(|witness| {
            witness.log_id == publication.log_id
                && witness.checkpoint_seq == publication.checkpoint_seq
        });
        if !has_successor_witness {
            return Err(AnchorError::Verification(format!(
                "checkpoint publication {} requires a trust-anchor binding or successor witness",
                publication.checkpoint_seq
            )));
        }
    }

    Ok(())
}
