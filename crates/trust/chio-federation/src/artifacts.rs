use serde::{Deserialize, Serialize};

use crate::listing::{GenericListingActorKind, GenericTrustAdmissionClass};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationArtifactKind {
    TrustActivation,
    Listing,
    ListingReport,
    GovernanceCharter,
    GovernanceCase,
    OpenMarketFeeSchedule,
    OpenMarketPenalty,
    PortableReputationSummary,
    PortableNegativeEvent,
    CrossIssuerTrustPack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationArtifactReference {
    pub kind: FederationArtifactKind,
    pub schema: String,
    pub artifact_id: String,
    pub operator_id: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationTrustScope {
    pub namespace: String,
    pub subject_operator_id: String,
    pub allowed_actor_kinds: Vec<GenericListingActorKind>,
    pub allowed_admission_classes: Vec<GenericTrustAdmissionClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationDelegationControl {
    pub delegator_operator_id: String,
    pub delegate_operator_id: String,
    pub max_hops: u32,
    pub attenuation_required: bool,
    pub visibility_only_until_local_activation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationImportControl {
    pub explicit_local_activation_required: bool,
    pub manual_review_required: bool,
    pub reject_stale_inputs: bool,
    pub allow_visibility_without_runtime_trust: bool,
    pub prohibit_ambient_runtime_admission: bool,
}

impl Default for FederationImportControl {
    fn default() -> Self {
        Self {
            explicit_local_activation_required: true,
            manual_review_required: true,
            reject_stale_inputs: true,
            allow_visibility_without_runtime_trust: true,
            prohibit_ambient_runtime_admission: true,
        }
    }
}
