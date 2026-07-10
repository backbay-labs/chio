use serde::{Deserialize, Serialize};

/// Schema for the BBS projection manifest that binds proof slots to policy.
pub const BBS_PROJECTION_MANIFEST_SCHEMA_V2: &str = "chio.bbs-projection.manifest.v2";

/// Per-slot disclosure policy in a BBS projection manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BbsProjectionDisclosure {
    Disclosed,
    Hidden,
}

/// One message slot in a BBS projection manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BbsProjectionMessageSlot {
    pub slot: u16,
    pub field: String,
    pub message_class: String,
    pub sensitivity_class: String,
    pub encoding: String,
    pub disclosure: BbsProjectionDisclosure,
    pub wholesale_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_sha256: Option<String>,
}

/// One hidden predicate declared by a BBS projection manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BbsProjectionHiddenPredicate {
    pub predicate_id: String,
    pub field: String,
    pub operator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_sha256: Option<String>,
}

/// Manifest that makes the BBS slot table explicit and verifier-checkable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BbsProjectionManifest {
    pub schema: String,
    pub manifest_id: String,
    pub artifact_ref: String,
    pub canonicalization: String,
    pub hash_algorithm: String,
    pub message_slots: Vec<BbsProjectionMessageSlot>,
    pub hidden_predicates: Vec<BbsProjectionHiddenPredicate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_key_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_ref: Option<String>,
}
