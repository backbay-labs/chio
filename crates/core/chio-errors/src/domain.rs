use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    Capability,
    Policy,
    Guard,
    Attest,
    Replay,
    Provider,
    Manifest,
    Kernel,
    Transport,
    Cli,
    Delegation,
    Adversarial,
    Threat,
    Arena,
    Economy,
    Lineage,
    Custody,
    Weights,
    Mobile,
    Transaction,
}

impl Domain {
    pub const ALL: [Self; 20] = [
        Self::Capability,
        Self::Policy,
        Self::Guard,
        Self::Attest,
        Self::Replay,
        Self::Provider,
        Self::Manifest,
        Self::Kernel,
        Self::Transport,
        Self::Cli,
        Self::Delegation,
        Self::Adversarial,
        Self::Threat,
        Self::Arena,
        Self::Economy,
        Self::Lineage,
        Self::Custody,
        Self::Weights,
        Self::Mobile,
        Self::Transaction,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Capability => "capability",
            Self::Policy => "policy",
            Self::Guard => "guard",
            Self::Attest => "attest",
            Self::Replay => "replay",
            Self::Provider => "provider",
            Self::Manifest => "manifest",
            Self::Kernel => "kernel",
            Self::Transport => "transport",
            Self::Cli => "cli",
            Self::Delegation => "delegation",
            Self::Adversarial => "adversarial",
            Self::Threat => "threat",
            Self::Arena => "arena",
            Self::Economy => "economy",
            Self::Lineage => "lineage",
            Self::Custody => "custody",
            Self::Weights => "weights",
            Self::Mobile => "mobile",
            Self::Transaction => "transaction",
        }
    }

    #[must_use]
    pub fn lookup(value: &str) -> Option<Self> {
        match value {
            "capability" => Some(Self::Capability),
            "policy" => Some(Self::Policy),
            "guard" => Some(Self::Guard),
            "attest" => Some(Self::Attest),
            "replay" => Some(Self::Replay),
            "provider" => Some(Self::Provider),
            "manifest" => Some(Self::Manifest),
            "kernel" => Some(Self::Kernel),
            "transport" => Some(Self::Transport),
            "cli" => Some(Self::Cli),
            "delegation" => Some(Self::Delegation),
            "adversarial" => Some(Self::Adversarial),
            "threat" => Some(Self::Threat),
            "arena" => Some(Self::Arena),
            "economy" => Some(Self::Economy),
            "lineage" => Some(Self::Lineage),
            "custody" => Some(Self::Custody),
            "weights" => Some(Self::Weights),
            "mobile" => Some(Self::Mobile),
            "transaction" => Some(Self::Transaction),
            _ => None,
        }
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Domain {
    type Err = UnknownDomain;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::lookup(value).ok_or_else(|| UnknownDomain::new(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown error domain: {value}")]
pub struct UnknownDomain {
    value: String,
}

impl UnknownDomain {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}
