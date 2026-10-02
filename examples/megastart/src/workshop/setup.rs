use anyhow::{bail, ensure, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Agent {
    Claude,
    Codex,
    Hermes,
    Pi,
}
impl Agent {
    pub fn name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Hermes => "hermes",
            Self::Pi => "pi",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "claude" => Ok(Self::Claude),
            "codex" => Ok(Self::Codex),
            "hermes" => Ok(Self::Hermes),
            "pi" => Ok(Self::Pi),
            _ => bail!("Unsupported worker identity"),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Roles {
    pub research: Agent,
    pub implementation: Agent,
    pub review: Agent,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum Workers {
    Reference,
    Native { roles: Roles },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Setup {
    pub schema_version: u32,
    pub system: String,
    pub project: String,
    pub example_revision: u32,
    pub workers: Workers,
}
impl Setup {
    pub fn reference() -> Self {
        Self {
            schema_version: 1,
            system: "software-factory".into(),
            project: "moving-average".into(),
            example_revision: 1,
            workers: Workers::Reference,
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.example_revision == 1
                && self.system == "software-factory"
                && self.project == "moving-average",
            "Unsupported workshop setup or example revision"
        );
        Ok(())
    }
    pub fn decode(code: &str) -> Result<Self> {
        ensure!(
            code.len() <= 96
                && code
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.'),
            "Invalid workshop setup code"
        );
        let mut setup = Self::reference();
        let parts: Vec<_> = code.split('.').collect();
        match parts.as_slice() {
            ["sf1", "reference"] => {}
            ["sf1", "native", research, implementation, review] => {
                setup.workers = Workers::Native {
                    roles: Roles {
                        research: Agent::parse(research)?,
                        implementation: Agent::parse(implementation)?,
                        review: Agent::parse(review)?,
                    },
                }
            }
            _ => bail!("Unsupported workshop setup code"),
        }
        Ok(setup)
    }
    pub fn encode(&self) -> Result<String> {
        self.validate()?;
        Ok(match &self.workers {
            Workers::Reference => "sf1.reference".into(),
            Workers::Native { roles } => format!(
                "sf1.native.{}.{}.{}",
                roles.research.name(),
                roles.implementation.name(),
                roles.review.name()
            ),
        })
    }
}
