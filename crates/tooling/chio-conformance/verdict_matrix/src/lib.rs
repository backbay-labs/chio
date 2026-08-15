pub mod cross_language;
pub mod diff_oracle;
pub mod driver;

use std::str::FromStr;

pub const MANIFEST_SCHEMA: &str = "chio.verdict-matrix.manifest.v1";
pub const SCENARIO_SCHEMA: &str = "chio.verdict-matrix.scenario.v1";
pub const MANIFEST_PATH: &str = "manifest.toml";
pub const SCENARIOS_SPEC_PATH: &str = "SCENARIOS.md";

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Deny,
    Error,
}

impl Verdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Error => "error",
        }
    }
}

impl FromStr for Verdict {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            "error" => Ok(Self::Error),
            _ => Err(format!("unknown verdict `{value}`")),
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "lowercase")]
pub enum ScenarioCategory {
    Capability,
    Revocation,
    Replay,
    Redaction,
    Receipt,
    #[serde(rename = "delivery_contract")]
    DeliveryContract,
}

impl ScenarioCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Capability => "capability",
            Self::Revocation => "revocation",
            Self::Replay => "replay",
            Self::Redaction => "redaction",
            Self::Receipt => "receipt",
            Self::DeliveryContract => "delivery_contract",
        }
    }
}

impl FromStr for ScenarioCategory {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "capability" => Ok(Self::Capability),
            "revocation" => Ok(Self::Revocation),
            "replay" => Ok(Self::Replay),
            "redaction" => Ok(Self::Redaction),
            "receipt" => Ok(Self::Receipt),
            "delivery_contract" => Ok(Self::DeliveryContract),
            _ => Err(format!("unknown scenario category `{value}`")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct VerdictTuple {
    pub verdict: Verdict,
    pub reason_code: String,
    pub scope_set: Vec<String>,
}

impl VerdictTuple {
    pub fn normalized(mut self) -> Self {
        self.scope_set.sort();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{ScenarioCategory, Verdict, VerdictTuple, MANIFEST_SCHEMA, SCENARIO_SCHEMA};

    #[test]
    fn schema_constants_match_spec_names() {
        assert_eq!(MANIFEST_SCHEMA, "chio.verdict-matrix.manifest.v1");
        assert_eq!(SCENARIO_SCHEMA, "chio.verdict-matrix.scenario.v1");
    }

    #[test]
    fn labels_are_stable() {
        assert_eq!(Verdict::Allow.as_str(), "allow");
        assert_eq!(Verdict::Deny.as_str(), "deny");
        assert_eq!(Verdict::Error.as_str(), "error");
        assert_eq!(ScenarioCategory::Capability.as_str(), "capability");
        assert_eq!(ScenarioCategory::Revocation.as_str(), "revocation");
        assert_eq!(ScenarioCategory::Replay.as_str(), "replay");
        assert_eq!(ScenarioCategory::Redaction.as_str(), "redaction");
        assert_eq!(ScenarioCategory::Receipt.as_str(), "receipt");
        assert_eq!(
            ScenarioCategory::DeliveryContract.as_str(),
            "delivery_contract"
        );
        assert_eq!(
            "delivery_contract".parse::<ScenarioCategory>(),
            Ok(ScenarioCategory::DeliveryContract)
        );
    }

    #[test]
    fn verdict_tuple_normalizes_scope_set_without_deduping() {
        let tuple = VerdictTuple {
            verdict: Verdict::Allow,
            reason_code: String::from("urn:chio:error:none"),
            scope_set: vec![
                String::from("tool:write"),
                String::from("tool:read"),
                String::from("tool:read"),
            ],
        };

        assert_eq!(
            tuple.normalized().scope_set,
            vec![
                String::from("tool:read"),
                String::from("tool:read"),
                String::from("tool:write")
            ]
        );
    }
}
