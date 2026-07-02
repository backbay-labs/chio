use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_event_limit: Option<usize>,
}

impl Default for CapitalBookQuery {
    fn default() -> Self {
        Self {
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            since: None,
            until: None,
            receipt_limit: Some(100),
            facility_limit: Some(10),
            bond_limit: Some(10),
            loss_event_limit: Some(25),
        }
    }
}

impl CapitalBookQuery {
    #[must_use]
    pub fn receipt_limit_or_default(&self) -> usize {
        bounded_limit_or_default(self.receipt_limit, 100, MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT)
    }

    #[must_use]
    pub fn facility_limit_or_default(&self) -> usize {
        bounded_limit_or_default(self.facility_limit, 10, MAX_CREDIT_FACILITY_LIST_LIMIT)
    }

    #[must_use]
    pub fn bond_limit_or_default(&self) -> usize {
        bounded_limit_or_default(self.bond_limit, 10, MAX_CREDIT_BOND_LIST_LIMIT)
    }

    #[must_use]
    pub fn loss_event_limit_or_default(&self) -> usize {
        bounded_limit_or_default(
            self.loss_event_limit,
            25,
            MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT,
        )
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.receipt_limit = Some(self.receipt_limit_or_default());
        normalized.facility_limit = Some(self.facility_limit_or_default());
        normalized.bond_limit = Some(self.bond_limit_or_default());
        normalized.loss_event_limit = Some(self.loss_event_limit_or_default());
        normalized
    }

    #[must_use]
    pub fn exposure_query(&self) -> ExposureLedgerQuery {
        ExposureLedgerQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            since: self.since,
            until: self.until,
            receipt_limit: self.receipt_limit,
            decision_limit: Some(1),
        }
    }

    #[must_use]
    pub fn facility_query(&self) -> CreditFacilityListQuery {
        CreditFacilityListQuery {
            facility_id: None,
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            disposition: None,
            lifecycle_state: None,
            limit: self.facility_limit,
        }
    }

    #[must_use]
    pub fn bond_query(&self) -> CreditBondListQuery {
        CreditBondListQuery {
            bond_id: None,
            facility_id: None,
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            disposition: None,
            lifecycle_state: None,
            limit: self.bond_limit,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        self.exposure_query().validate()?;
        if self.agent_subject.is_none() {
            return Err(
                "capital book queries require --agent-subject because source-of-funds truth must resolve one counterparty"
                    .to_string(),
            );
        }
        Ok(())
    }
}
