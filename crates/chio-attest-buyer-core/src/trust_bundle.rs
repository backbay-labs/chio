use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::crypto::PublicKey;
use chio_federation::{bilateral_verifier::ActionClassKind, bilateral_verifier::PinnedEpoch};
use chio_governance::authorization::GovernanceReceiptCaseKind;
use chio_governance::lease::CapabilityLeaseActionClass;
use serde::{Deserialize, Serialize};

use crate::claims::{PeerLadderBinding, VendorKeyBinding};
use crate::context::ChioVerificationContext;
use crate::disclosure::{validate_disclosure_policy, ChioDisclosurePolicy};
use crate::error::ChioPackageError;
use crate::issuer::{
    TrustedBbsIssuer, TrustedIssuerRegistry, TrustedIssuerRegistryDocument,
    TRUSTED_ISSUER_REGISTRY_SCHEMA,
};
use crate::revocation::{
    revoked_key_fingerprints, validate_revocation_checkpoint, ChioRevocationMaterial,
    SignedChioRevocationCheckpoint,
};
use crate::validation::{
    canonical_sha256, key_fingerprint, validate_sha256_hex, validate_trust_field,
    validate_unique_action_classes, validate_unique_case_kinds,
};

pub const VERIFIER_TRUST_BUNDLE_SCHEMA: &str = "chio.federation.verifier-trust-bundle.v1";
pub const CHIO_FEDERATION_VERIFIER_TRUST_BUNDLE_SCHEMA: &str = VERIFIER_TRUST_BUNDLE_SCHEMA;
pub const WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID: &str = "workflow.grant_issue";
pub const WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID: &str = "workflow.aggregate_publish";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChioActionClassKind {
    Routine,
    ReceiptBacked,
}

impl From<ChioActionClassKind> for ActionClassKind {
    fn from(value: ChioActionClassKind) -> Self {
        match value {
            ChioActionClassKind::Routine => ActionClassKind::Routine,
            ChioActionClassKind::ReceiptBacked => ActionClassKind::ReceiptBacked,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioTrustedActionClass {
    pub action_class_id: String,
    pub tool_name: String,
    pub kind: ChioActionClassKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioTrustedWorkflowIntersection {
    pub intersection_id: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChioAuthorityStatus {
    Active,
    Inactive,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioTrustedLeaseAuthority {
    pub issuer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub public_key: PublicKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<ChioAuthorityStatus>,
    pub allowed_action_classes: Vec<CapabilityLeaseActionClass>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioTrustedGovernanceAuthority {
    pub authorizing_kernel: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub public_key: PublicKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<ChioAuthorityStatus>,
    pub allowed_case_kinds: Vec<GovernanceReceiptCaseKind>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioVerifierTrustBundleDocument {
    pub schema: String,
    pub trusted_bbs_issuers: Vec<TrustedBbsIssuer>,
    pub peers: Vec<PeerLadderBinding>,
    pub vendors: Vec<VendorKeyBinding>,
    pub action_classes: Vec<ChioTrustedActionClass>,
    pub workflow_intersections: Vec<ChioTrustedWorkflowIntersection>,
    #[serde(default)]
    pub runtime_policy_issuer_public_keys: Vec<PublicKey>,
    #[serde(default)]
    pub lease_authorities: Vec<ChioTrustedLeaseAuthority>,
    #[serde(default)]
    pub governance_authorities: Vec<ChioTrustedGovernanceAuthority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure_policy: Option<ChioDisclosurePolicy>,
    pub revocation: ChioRevocationMaterial,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChioVerifierTrustBundle {
    pub(crate) document_sha256: String,
    pub(crate) issuer_registry: TrustedIssuerRegistry,
    pub(crate) peers: BTreeMap<String, PeerLadderBinding>,
    pub(crate) vendors: BTreeMap<String, VendorKeyBinding>,
    pub(crate) action_classes: BTreeMap<String, ChioTrustedActionClass>,
    pub(crate) workflow_intersections: BTreeMap<String, String>,
    pub(crate) lease_authorities: BTreeMap<String, ChioTrustedLeaseAuthority>,
    pub(crate) governance_authorities: BTreeMap<String, ChioTrustedGovernanceAuthority>,
    pub(crate) runtime_policy_issuer_public_keys: Vec<PublicKey>,
    pub(crate) disclosure_policy: ChioDisclosurePolicy,
    pub(crate) revocation: SignedChioRevocationCheckpoint,
    pub(crate) revoked_key_fingerprints: BTreeSet<String>,
}

impl ChioVerifierTrustBundle {
    #[must_use]
    pub fn document_sha256(&self) -> &str {
        &self.document_sha256
    }

    #[must_use]
    pub fn runtime_policy_issuer_public_keys(&self) -> &[PublicKey] {
        &self.runtime_policy_issuer_public_keys
    }

    pub fn from_document(
        document: ChioVerifierTrustBundleDocument,
    ) -> Result<Self, ChioPackageError> {
        let document_sha256 = canonical_sha256(&document)?;
        if document.schema != VERIFIER_TRUST_BUNDLE_SCHEMA {
            return Err(ChioPackageError::TrustBundle(format!(
                "verifier trust bundle schema {} is unsupported",
                document.schema
            )));
        }
        if document.trusted_bbs_issuers.is_empty()
            || document.peers.is_empty()
            || document.vendors.is_empty()
            || document.action_classes.is_empty()
            || document.workflow_intersections.is_empty()
            || document.runtime_policy_issuer_public_keys.is_empty()
            || document.lease_authorities.is_empty()
            || document.governance_authorities.is_empty()
        {
            return Err(ChioPackageError::TrustBundle(
                "verifier trust bundle must contain issuers, peers, vendors, action classes, workflow intersections, runtime policy issuers, lease authorities, and governance authorities"
                    .to_string(),
            ));
        }
        let Some(disclosure_policy) = document.disclosure_policy else {
            return Err(ChioPackageError::TrustBundle(
                "verifier trust bundle v3 requires a disclosure policy".to_string(),
            ));
        };
        validate_disclosure_policy(&disclosure_policy)?;
        let ChioRevocationMaterial::Checkpoint(revocation) = document.revocation else {
            return Err(ChioPackageError::TrustBundle(
                "verifier trust bundle v3 requires a signed revocation checkpoint".to_string(),
            ));
        };
        validate_revocation_checkpoint(&revocation)?;
        let revoked_key_fingerprints =
            revoked_key_fingerprints(&revocation.body.revoked_key_fingerprints)?;

        let issuer_registry = TrustedIssuerRegistry::from_document(TrustedIssuerRegistryDocument {
            schema: TRUSTED_ISSUER_REGISTRY_SCHEMA.to_string(),
            issuers: document.trusted_bbs_issuers,
        })
        .map_err(|error| ChioPackageError::TrustBundle(error.to_string()))?;

        let mut peers = BTreeMap::new();
        for peer in document.peers {
            validate_trust_field(&peer.kernel_id, "peer.kernelId")?;
            peer.ladder_manifest_ref
                .validate()
                .map_err(|error| ChioPackageError::TrustBundle(error.to_string()))?;
            if peers.insert(peer.kernel_id.clone(), peer).is_some() {
                return Err(ChioPackageError::TrustBundle(
                    "duplicate trusted peer kernel id".to_string(),
                ));
            }
        }

        let mut vendors = BTreeMap::new();
        for vendor in document.vendors {
            validate_trust_field(&vendor.vendor_id, "vendor.vendorId")?;
            if vendors.insert(vendor.vendor_id.clone(), vendor).is_some() {
                return Err(ChioPackageError::TrustBundle(
                    "duplicate trusted vendor id".to_string(),
                ));
            }
        }

        let mut action_classes = BTreeMap::new();
        let mut action_class_ids = BTreeSet::new();
        for action_class in document.action_classes {
            validate_trust_field(&action_class.action_class_id, "actionClass.actionClassId")?;
            validate_trust_field(&action_class.tool_name, "actionClass.toolName")?;
            if !action_class_ids.insert(action_class.action_class_id.clone()) {
                return Err(ChioPackageError::TrustBundle(
                    "duplicate trusted action class id".to_string(),
                ));
            }
            if action_classes
                .insert(action_class.tool_name.clone(), action_class)
                .is_some()
            {
                return Err(ChioPackageError::TrustBundle(
                    "duplicate trusted action class tool name".to_string(),
                ));
            }
        }
        for required in [
            WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID,
            WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID,
        ] {
            if !action_class_ids.contains(required) {
                return Err(ChioPackageError::TrustBundle(format!(
                    "verifier trust bundle action classes must include {required}"
                )));
            }
        }

        let mut workflow_intersections = BTreeMap::new();
        for intersection in document.workflow_intersections {
            validate_trust_field(
                &intersection.intersection_id,
                "workflowIntersection.intersectionId",
            )?;
            validate_sha256_hex(&intersection.sha256, "workflowIntersection.sha256")?;
            if workflow_intersections
                .insert(intersection.intersection_id.clone(), intersection.sha256)
                .is_some()
            {
                return Err(ChioPackageError::TrustBundle(
                    "duplicate trusted workflow intersection id".to_string(),
                ));
            }
        }

        let mut lease_authorities = BTreeMap::new();
        for authority in document.lease_authorities {
            validate_trust_field(&authority.issuer, "leaseAuthority.issuer")?;
            validate_authority_lifecycle(
                authority.key_id.as_deref(),
                &authority.public_key,
                authority.valid_from_unix_ms,
                authority.valid_until_unix_ms,
                authority.status,
                "leaseAuthority",
            )?;
            validate_unique_action_classes(
                &authority.allowed_action_classes,
                "leaseAuthority.allowedActionClasses",
            )?;
            if lease_authorities
                .insert(authority.issuer.clone(), authority)
                .is_some()
            {
                return Err(ChioPackageError::TrustBundle(
                    "duplicate trusted lease authority issuer".to_string(),
                ));
            }
        }

        let mut governance_authorities = BTreeMap::new();
        for authority in document.governance_authorities {
            validate_trust_field(
                &authority.authorizing_kernel,
                "governanceAuthority.authorizingKernel",
            )?;
            validate_authority_lifecycle(
                authority.key_id.as_deref(),
                &authority.public_key,
                authority.valid_from_unix_ms,
                authority.valid_until_unix_ms,
                authority.status,
                "governanceAuthority",
            )?;
            validate_unique_case_kinds(
                &authority.allowed_case_kinds,
                "governanceAuthority.allowedCaseKinds",
            )?;
            if governance_authorities
                .insert(authority.authorizing_kernel.clone(), authority)
                .is_some()
            {
                return Err(ChioPackageError::TrustBundle(
                    "duplicate trusted governance authority kernel".to_string(),
                ));
            }
        }

        Ok(Self {
            document_sha256,
            issuer_registry,
            peers,
            vendors,
            action_classes,
            workflow_intersections,
            lease_authorities,
            governance_authorities,
            runtime_policy_issuer_public_keys: document.runtime_policy_issuer_public_keys,
            disclosure_policy,
            revocation: *revocation,
            revoked_key_fingerprints,
        })
    }

    pub(crate) fn issuer_public_key_hex(&self, issuer_fingerprint: &str) -> Option<&str> {
        self.issuer_registry.public_key_hex(issuer_fingerprint)
    }

    pub(crate) fn peer(&self, kernel_id: &str) -> Option<&PeerLadderBinding> {
        self.peers.get(kernel_id)
    }

    pub(crate) fn action_class_map(&self) -> BTreeMap<String, ActionClassKind> {
        self.action_classes
            .iter()
            .map(|(tool_name, class)| (tool_name.clone(), class.kind.into()))
            .collect()
    }

    pub(crate) fn workflow_intersection_hash(&self, intersection_id: &str) -> Option<&str> {
        self.workflow_intersections
            .get(intersection_id)
            .map(std::string::String::as_str)
    }

    pub(crate) fn lease_authority(&self, issuer: &str) -> Option<&ChioTrustedLeaseAuthority> {
        self.lease_authorities.get(issuer)
    }

    pub(crate) fn governance_authority(
        &self,
        authorizing_kernel: &str,
    ) -> Option<&ChioTrustedGovernanceAuthority> {
        self.governance_authorities.get(authorizing_kernel)
    }

    pub(crate) fn pinned_epoch(&self) -> PinnedEpoch {
        PinnedEpoch {
            now_unix_ms: self.revocation.body.issued_at_unix_ms,
            epoch_height: self.revocation.body.epoch_height,
        }
    }

    pub(crate) fn revocation_epoch_height(&self) -> u64 {
        self.revocation.body.epoch_height
    }

    pub(crate) fn verification_time_unix_ms(&self) -> u64 {
        self.revocation.body.issued_at_unix_ms
    }

    pub(crate) fn ensure_not_revoked(
        &self,
        fingerprint: &str,
        label: &str,
    ) -> Result<(), ChioPackageError> {
        if self.revoked_key_fingerprints.contains(fingerprint) {
            return Err(ChioPackageError::TrustBundle(format!(
                "{label} is revoked by checkpoint {}",
                self.revocation.body.checkpoint_id
            )));
        }
        Ok(())
    }

    pub(crate) fn ensure_public_key_not_revoked(
        &self,
        public_key: &PublicKey,
        label: &str,
    ) -> Result<(), ChioPackageError> {
        self.ensure_not_revoked(&key_fingerprint(public_key), label)
    }

    pub(crate) fn ensure_checkpoint_active_at(
        &self,
        now_unix_ms: u64,
    ) -> Result<(), ChioPackageError> {
        if now_unix_ms < self.revocation.body.issued_at_unix_ms {
            return Err(ChioPackageError::TrustBundle(format!(
                "revocation checkpoint {} is issued in the future",
                self.revocation.body.checkpoint_id
            )));
        }
        if now_unix_ms >= self.revocation.body.expires_at_unix_ms {
            return Err(ChioPackageError::TrustBundle(format!(
                "revocation checkpoint {} is stale",
                self.revocation.body.checkpoint_id
            )));
        }
        Ok(())
    }

    pub(crate) fn ensure_checkpoint_covers_context(
        &self,
        context: &ChioVerificationContext,
    ) -> Result<(), ChioPackageError> {
        self.ensure_checkpoint_active_at(context.expires_at_unix_ms.saturating_sub(1))
    }
}

fn validate_authority_lifecycle(
    declared_key_id: Option<&str>,
    public_key: &PublicKey,
    valid_from_unix_ms: Option<u64>,
    valid_until_unix_ms: Option<u64>,
    status: Option<ChioAuthorityStatus>,
    label: &str,
) -> Result<(), ChioPackageError> {
    let Some(key_id) = declared_key_id else {
        return Err(ChioPackageError::TrustBundle(format!(
            "{label}.keyId is required"
        )));
    };
    let expected = key_fingerprint(public_key);
    if key_id != expected {
        return Err(ChioPackageError::TrustBundle(format!(
            "{label}.keyId does not match public key fingerprint"
        )));
    }
    let Some(valid_from) = valid_from_unix_ms else {
        return Err(ChioPackageError::TrustBundle(format!(
            "{label}.validFromUnixMs is required"
        )));
    };
    let Some(valid_until) = valid_until_unix_ms else {
        return Err(ChioPackageError::TrustBundle(format!(
            "{label}.validUntilUnixMs is required"
        )));
    };
    if valid_until <= valid_from {
        return Err(ChioPackageError::TrustBundle(format!(
            "{label} validity window is invalid"
        )));
    }
    let Some(status) = status else {
        return Err(ChioPackageError::TrustBundle(format!(
            "{label}.status is required"
        )));
    };
    if status != ChioAuthorityStatus::Active {
        return Err(ChioPackageError::TrustBundle(format!(
            "{label} status is not active"
        )));
    }
    Ok(())
}

pub fn verifier_trust_bundle_from_json(
    json: &str,
) -> Result<ChioVerifierTrustBundle, ChioPackageError> {
    let document: ChioVerifierTrustBundleDocument =
        serde_json::from_str(json).map_err(|error| ChioPackageError::Json(error.to_string()))?;
    ChioVerifierTrustBundle::from_document(document)
}

pub fn verifier_trust_bundle_json(
    trust_bundle: &ChioVerifierTrustBundleDocument,
) -> Result<String, ChioPackageError> {
    serde_json::to_string_pretty(trust_bundle)
        .map_err(|error| ChioPackageError::Json(error.to_string()))
}

pub fn verifier_trust_bundle_document_sha256(
    document: &ChioVerifierTrustBundleDocument,
) -> Result<String, ChioPackageError> {
    canonical_sha256(document)
}
