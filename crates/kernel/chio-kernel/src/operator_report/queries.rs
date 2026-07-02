use super::*;

/// Filter surface for the operator-facing reporting API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OperatorReportQuery {
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
    pub group_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_bucket: Option<AnalyticsTimeBucket>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metered_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub economic_limit: Option<usize>,
    /// Auth-derived read authority. This is never accepted from request bodies.
    #[serde(skip)]
    pub read_context: Option<ReceiptReadContext>,
}

impl Default for OperatorReportQuery {
    fn default() -> Self {
        Self {
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            since: None,
            until: None,
            group_limit: Some(50),
            time_bucket: Some(AnalyticsTimeBucket::Day),
            attribution_limit: Some(100),
            budget_limit: Some(50),
            settlement_limit: Some(50),
            metered_limit: Some(50),
            authorization_limit: Some(50),
            economic_limit: Some(50),
            read_context: None,
        }
    }
}

impl OperatorReportQuery {
    #[must_use]
    pub fn to_receipt_analytics_query(&self) -> crate::ReceiptAnalyticsQuery {
        crate::ReceiptAnalyticsQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            since: self.since,
            until: self.until,
            group_limit: self.group_limit,
            time_bucket: self.time_bucket,
            read_context: self.read_context.clone(),
        }
    }

    #[must_use]
    pub fn to_cost_attribution_query(&self) -> CostAttributionQuery {
        CostAttributionQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            since: self.since,
            until: self.until,
            limit: self.attribution_limit,
            read_context: self.read_context.clone(),
        }
    }

    pub fn to_evidence_export_query(&self) -> Result<EvidenceExportQuery, String> {
        let (tenant, read_boundary) = match self.read_context.as_ref() {
            Some(ReceiptReadContext {
                boundary: ReceiptReadBoundary::AdminAll,
                ..
            }) => (None, Some(ReceiptReadBoundary::AdminAll)),
            Some(ReceiptReadContext {
                boundary: ReceiptReadBoundary::TenantScoped { tenant },
                ..
            }) => (
                Some(tenant.clone()),
                Some(ReceiptReadBoundary::tenant_scoped(tenant.clone())),
            ),
            None => {
                return Err(
                    "operator report evidence export requires an explicit read context".to_string(),
                );
            }
        };
        Ok(EvidenceExportQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            since: self.since,
            until: self.until,
            tenant,
            read_boundary,
        })
    }

    #[must_use]
    pub fn direct_evidence_export_supported(&self) -> bool {
        self.tool_server.is_none() && self.tool_name.is_none()
    }

    #[must_use]
    pub fn budget_limit_or_default(&self) -> usize {
        self.budget_limit
            .unwrap_or(50)
            .clamp(1, MAX_OPERATOR_BUDGET_LIMIT)
    }

    #[must_use]
    pub fn settlement_limit_or_default(&self) -> usize {
        self.settlement_limit
            .unwrap_or(50)
            .clamp(1, MAX_SETTLEMENT_BACKLOG_LIMIT)
    }

    #[must_use]
    pub fn metered_limit_or_default(&self) -> usize {
        self.metered_limit
            .unwrap_or(50)
            .clamp(1, MAX_METERED_BILLING_LIMIT)
    }

    #[must_use]
    pub fn authorization_limit_or_default(&self) -> usize {
        self.authorization_limit
            .unwrap_or(50)
            .clamp(1, MAX_AUTHORIZATION_CONTEXT_LIMIT)
    }

    #[must_use]
    pub fn economic_limit_or_default(&self) -> usize {
        self.economic_limit
            .unwrap_or(50)
            .clamp(1, MAX_ECONOMIC_RECEIPT_LIMIT)
    }

    #[must_use]
    pub fn to_shared_evidence_query(&self) -> SharedEvidenceQuery {
        SharedEvidenceQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            since: self.since,
            until: self.until,
            issuer: None,
            partner: None,
            limit: self.group_limit,
            read_context: self.read_context.clone(),
        }
    }
}

/// Filter surface for the signed insurer/risk behavioral feed export.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedQuery {
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
    /// Auth-derived read authority. This is never accepted from request bodies.
    #[serde(skip)]
    pub read_context: Option<ReceiptReadContext>,
}

impl Default for BehavioralFeedQuery {
    fn default() -> Self {
        Self {
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            since: None,
            until: None,
            receipt_limit: Some(100),
            read_context: None,
        }
    }
}

impl BehavioralFeedQuery {
    #[must_use]
    pub fn receipt_limit_or_default(&self) -> usize {
        self.receipt_limit
            .unwrap_or(100)
            .clamp(1, MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.receipt_limit = Some(self.receipt_limit_or_default());
        normalized
    }

    #[must_use]
    pub fn to_operator_report_query(&self) -> OperatorReportQuery {
        OperatorReportQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            since: self.since,
            until: self.until,
            read_context: self.read_context.clone(),
            ..OperatorReportQuery::default()
        }
    }

    #[must_use]
    pub fn to_receipt_query(&self) -> ReceiptQuery {
        ReceiptQuery {
            capability_id: self.capability_id.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            outcome: None,
            since: self.since,
            until: self.until,
            min_cost: None,
            max_cost: None,
            cursor: None,
            limit: self.receipt_limit_or_default(),
            agent_subject: self.agent_subject.clone(),
            tenant_filter: None,
            read_context: self.read_context.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SharedEvidenceQuery {
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
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    /// Auth-derived read authority. This is never accepted from request bodies.
    #[serde(skip)]
    pub read_context: Option<ReceiptReadContext>,
}

impl Default for SharedEvidenceQuery {
    fn default() -> Self {
        Self {
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            since: None,
            until: None,
            issuer: None,
            partner: None,
            limit: Some(50),
            read_context: None,
        }
    }
}

impl SharedEvidenceQuery {
    #[must_use]
    pub fn limit_or_default(&self) -> usize {
        self.limit.unwrap_or(50).clamp(1, MAX_SHARED_EVIDENCE_LIMIT)
    }
}
