use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
    Fatal,
}

impl Severity {
    pub const ALL: [Self; 4] = [Self::Info, Self::Warning, Self::Error, Self::Fatal];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Fatal => "fatal",
        }
    }

    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Warning => 1,
            Self::Error => 2,
            Self::Fatal => 3,
        }
    }

    #[must_use]
    pub fn lookup(value: &str) -> Option<Self> {
        match value {
            "info" => Some(Self::Info),
            "warn" | "warning" => Some(Self::Warning),
            "error" => Some(Self::Error),
            "fatal" => Some(Self::Fatal),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = UnknownSeverity;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::lookup(value).ok_or_else(|| UnknownSeverity::new(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown error severity: {value}")]
pub struct UnknownSeverity {
    value: String,
}

impl UnknownSeverity {
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
