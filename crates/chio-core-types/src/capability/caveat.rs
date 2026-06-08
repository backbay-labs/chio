use alloc::string::String;

use serde::{Deserialize, Serialize};

use crate::crypto::Signature;

/// First-party caveat attached to a attenuated capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Caveat {
    pub kind: CaveatKind,
    pub predicate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<Signature>,
}

/// Built-in first-party caveat kinds. Third-party discharges are deferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaveatKind {
    RestrictTool,
    BindSession,
    RestrictAudience,
    RestrictGeo,
    RestrictTimeWindow,
}

/// Per-grant subset relation recorded in an attenuation witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantSubsetRelation {
    pub grant_kind: String,
    pub child_index: u32,
    pub parent_index: u32,
    pub subset: bool,
}
