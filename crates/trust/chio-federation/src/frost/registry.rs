use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use serde_json::{json, Value};

use super::action::{
    CHIO_FROST_CHANNEL_CLOSE_ACTION_SCHEMA, CHIO_FROST_CLEARING_ROUND_FINALIZE_ACTION_SCHEMA,
    CHIO_FROST_CREDENTIALS_PASSPORT_REVOKE_ACTION_SCHEMA,
    CHIO_FROST_GOVERNANCE_CASE_ENFORCE_SANCTION_ACTION_SCHEMA,
    CHIO_FROST_POUNCER_REVOKE_CREDENTIAL_ACTION_SCHEMA, CHIO_FROST_ROSTER_ROTATE_ACTION_SCHEMA,
    CHIO_FROST_SETTLE_COMMITMENT_ACTION_SCHEMA,
};
use super::types::{FrostAuthorizationDomain, FrostAuthorizationError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrostActionRegistration {
    pub domain: FrostAuthorizationDomain,
    pub ladder_action_class: &'static str,
    pub quorum_n: u16,
    pub quorum_m: u16,
    pub quorum_scope: &'static str,
    pub action_preimage_schema: &'static str,
}

impl FrostActionRegistration {
    pub fn ladder_contract_digest(&self) -> Result<String, FrostAuthorizationError> {
        let canonical = canonical_json_bytes(&self.ladder_entry()?)
            .map_err(|error| FrostAuthorizationError::Canonical(error.to_string()))?;
        Ok(sha256_hex(&canonical))
    }

    fn ladder_entry(&self) -> Result<Value, FrostAuthorizationError> {
        let entry = match self.domain {
            FrostAuthorizationDomain::SettleCommitment => json!({
                "id": self.ladder_action_class,
                "title": "SettlementCommitment dispatch",
                "mode": "receipt_backed",
                "destructive": true,
                "cross_org_visibility": "federated",
                "evidence_required": [
                    "trust_activation",
                    "workflow_receipt",
                    "anchor_epoch"
                ],
                "co_sign": "n_of_m",
                "co_sign_quorum": {
                    "n": self.quorum_n,
                    "m": self.quorum_m,
                    "scope": self.quorum_scope
                },
                "consistency_model": "quorum-required",
                "consistency_anchor": "frost-quorum"
            }),
            FrostAuthorizationDomain::ClearingRoundFinalize => json!({
                "id": self.ladder_action_class,
                "title": "Clearing round finalization",
                "mode": "receipt_backed",
                "destructive": true,
                "cross_org_visibility": "federated",
                "evidence_required": [
                    "trust_activation",
                    "workflow_receipt",
                    "anchor_epoch"
                ],
                "co_sign": "n_of_m",
                "co_sign_quorum": {
                    "n": self.quorum_n,
                    "m": self.quorum_m,
                    "scope": self.quorum_scope
                },
                "consistency_model": "quorum-required",
                "consistency_anchor": "frost-quorum"
            }),
            FrostAuthorizationDomain::ChannelClose => json!({
                "id": self.ladder_action_class,
                "title": "Escrow channel close",
                "mode": "receipt_backed",
                "destructive": true,
                "cross_org_visibility": "federated",
                "evidence_required": [
                    "trust_activation",
                    "workflow_receipt",
                    "anchor_epoch"
                ],
                "co_sign": "n_of_m",
                "co_sign_quorum": {
                    "n": self.quorum_n,
                    "m": self.quorum_m,
                    "scope": self.quorum_scope
                },
                "consistency_model": "quorum-required",
                "consistency_anchor": "frost-quorum"
            }),
            FrostAuthorizationDomain::PouncerRevokeCredential => json!({
                "id": self.ladder_action_class,
                "title": "Pouncer RevokeCredential (cross-issuer)",
                "mode": "receipt_backed",
                "destructive": true,
                "cross_org_visibility": "federated",
                "evidence_required": [
                    "trust_activation",
                    "passport_presentation",
                    "anchor_epoch"
                ],
                "co_sign": "n_of_m",
                "co_sign_quorum": {
                    "n": self.quorum_n,
                    "m": self.quorum_m,
                    "scope": self.quorum_scope
                },
                "consistency_model": "quorum-required",
                "consistency_anchor": "frost-quorum"
            }),
            FrostAuthorizationDomain::GovernanceCaseEnforceSanction => json!({
                "id": self.ladder_action_class,
                "title": "Sanction enforcement against operator",
                "mode": "receipt_backed",
                "destructive": true,
                "cross_org_visibility": "federated",
                "evidence_required": [
                    "trust_activation",
                    "registry_search",
                    "operator_report",
                    "anchor_epoch"
                ],
                "co_sign": "n_of_m",
                "co_sign_quorum": {
                    "n": self.quorum_n,
                    "m": self.quorum_m,
                    "scope": self.quorum_scope
                },
                "consistency_model": "quorum-required",
                "consistency_anchor": "frost-quorum"
            }),
            FrostAuthorizationDomain::CredentialsPassportRevoke => json!({
                "id": self.ladder_action_class,
                "title": "Passport revocation",
                "mode": "receipt_backed",
                "destructive": true,
                "cross_org_visibility": "federated",
                "evidence_required": [
                    "trust_activation",
                    "passport_presentation",
                    "anchor_epoch"
                ],
                "co_sign": "n_of_m",
                "co_sign_quorum": {
                    "n": self.quorum_n,
                    "m": self.quorum_m,
                    "scope": self.quorum_scope
                },
                "consistency_model": "quorum-required",
                "consistency_anchor": "frost-quorum",
                "aliases": [
                    { "domain": "cybersec", "id": "pouncer.revoke_credential" }
                ]
            }),
            FrostAuthorizationDomain::RosterRotate => json!({
                "id": self.ladder_action_class,
                "title": "FROST roster rotation",
                "mode": "receipt_backed",
                "destructive": true,
                "cross_org_visibility": "federated",
                "evidence_required": [
                    "trust_activation",
                    "registry_search",
                    "anchor_epoch"
                ],
                "co_sign": "n_of_m",
                "co_sign_quorum": {
                    "n": self.quorum_n,
                    "m": self.quorum_m,
                    "scope": self.quorum_scope
                },
                "consistency_model": "quorum-required",
                "consistency_anchor": "frost-quorum"
            }),
            FrostAuthorizationDomain::AdjudicationPanelDecision => {
                return Err(FrostAuthorizationError::DisabledDomain(
                    self.domain.as_str(),
                ));
            }
        };
        Ok(entry)
    }
}

const REGISTERED_FROST_ACTIONS: [FrostActionRegistration; 7] = [
    FrostActionRegistration {
        domain: FrostAuthorizationDomain::SettleCommitment,
        ladder_action_class: "settle.commitment",
        quorum_n: 2,
        quorum_m: 3,
        quorum_scope: "treaty",
        action_preimage_schema: CHIO_FROST_SETTLE_COMMITMENT_ACTION_SCHEMA,
    },
    FrostActionRegistration {
        domain: FrostAuthorizationDomain::ClearingRoundFinalize,
        ladder_action_class: "clearing.round_finalize",
        quorum_n: 2,
        quorum_m: 3,
        quorum_scope: "treaty",
        action_preimage_schema: CHIO_FROST_CLEARING_ROUND_FINALIZE_ACTION_SCHEMA,
    },
    FrostActionRegistration {
        domain: FrostAuthorizationDomain::ChannelClose,
        ladder_action_class: "channel.close",
        quorum_n: 2,
        quorum_m: 3,
        quorum_scope: "treaty",
        action_preimage_schema: CHIO_FROST_CHANNEL_CLOSE_ACTION_SCHEMA,
    },
    FrostActionRegistration {
        domain: FrostAuthorizationDomain::PouncerRevokeCredential,
        ladder_action_class: "pouncer.revoke_credential",
        quorum_n: 2,
        quorum_m: 3,
        quorum_scope: "treaty",
        action_preimage_schema: CHIO_FROST_POUNCER_REVOKE_CREDENTIAL_ACTION_SCHEMA,
    },
    FrostActionRegistration {
        domain: FrostAuthorizationDomain::GovernanceCaseEnforceSanction,
        ladder_action_class: "governance.case_enforce_sanction",
        quorum_n: 3,
        quorum_m: 5,
        quorum_scope: "treaty",
        action_preimage_schema: CHIO_FROST_GOVERNANCE_CASE_ENFORCE_SANCTION_ACTION_SCHEMA,
    },
    FrostActionRegistration {
        domain: FrostAuthorizationDomain::CredentialsPassportRevoke,
        ladder_action_class: "credentials.passport_revoke",
        quorum_n: 2,
        quorum_m: 3,
        quorum_scope: "treaty",
        action_preimage_schema: CHIO_FROST_CREDENTIALS_PASSPORT_REVOKE_ACTION_SCHEMA,
    },
    FrostActionRegistration {
        domain: FrostAuthorizationDomain::RosterRotate,
        ladder_action_class: "governance.roster_rotate",
        quorum_n: 3,
        quorum_m: 5,
        quorum_scope: "treaty",
        action_preimage_schema: CHIO_FROST_ROSTER_ROTATE_ACTION_SCHEMA,
    },
];

#[must_use]
pub fn registered_frost_actions() -> &'static [FrostActionRegistration] {
    &REGISTERED_FROST_ACTIONS
}

#[must_use]
pub fn frost_action_registration(
    domain: FrostAuthorizationDomain,
) -> Option<&'static FrostActionRegistration> {
    REGISTERED_FROST_ACTIONS
        .iter()
        .find(|registration| registration.domain == domain)
}
