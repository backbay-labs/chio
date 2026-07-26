use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconomicStateReadQuery {
    pub resource_keys: Vec<EconomicResourceKeyV1>,
    pub request_keys: Vec<EconomicRequestKeyV1>,
}

impl EconomicStateReadQuery {
    pub fn validate(&self) -> Result<(), EconomicStateAnchorError> {
        if self.resource_keys.len() > MAX_ECONOMIC_TRANSITIONS
            || self.request_keys.len() > MAX_ECONOMIC_TRANSITIONS
        {
            return Err(EconomicStateAnchorError::InvalidView(
                "read query exceeds the bound",
            ));
        }
        if !self.resource_keys.windows(2).all(|pair| pair[0] < pair[1])
            || !self.request_keys.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(EconomicStateAnchorError::InvalidView(
                "read query keys must be sorted and unique",
            ));
        }
        for key in &self.resource_keys {
            key.validate()?;
        }
        for key in &self.request_keys {
            key.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconomicCheckpointReadQuery {
    pub checkpoint_sequence: u64,
    pub checkpoint_digest: String,
    pub query: EconomicStateReadQuery,
}

impl EconomicCheckpointReadQuery {
    pub fn validate(&self) -> Result<(), EconomicStateAnchorError> {
        validate_positive("checkpoint_sequence", self.checkpoint_sequence)?;
        validate_digest("checkpoint_digest", &self.checkpoint_digest)?;
        self.query.validate()
    }
}
