use super::*;

#[derive(Debug, Clone)]
pub(crate) struct TrustHttpError {
    pub(crate) status: StatusCode,
    pub(crate) message: String,
}

impl TrustHttpError {
    pub(crate) fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }

    pub(crate) fn into_response(self) -> Response {
        plain_http_error(self.status, &self.message)
    }
}

impl From<TrustHttpError> for CliError {
    fn from(error: TrustHttpError) -> Self {
        CliError::cli_other_error(error.message)
    }
}

impl From<ReceiptStoreError> for TrustHttpError {
    fn from(error: ReceiptStoreError) -> Self {
        trust_http_error_from_receipt_store(error)
    }
}

impl From<CliError> for TrustHttpError {
    fn from(error: CliError) -> Self {
        TrustHttpError::internal(error.to_string())
    }
}

pub(crate) fn liability_market_http_error(message: &str) -> Response {
    let status = if message.contains("not found") {
        StatusCode::NOT_FOUND
    } else if message.contains("already")
        || message.contains("stale")
        || message.contains("unsupported")
        || message.contains("not active")
        || message.contains("superseded")
        || message.contains("expires")
        || message.contains("mismatch")
        || message.contains("must match")
        || message.contains("cannot be issued")
    {
        StatusCode::CONFLICT
    } else {
        StatusCode::BAD_REQUEST
    };
    plain_http_error(status, message)
}

#[derive(Debug, Clone)]
pub(crate) enum UnderwritingQuotedExposure {
    None,
    Single(MonetaryAmount),
    MixedCurrencies(BTreeSet<String>),
}

impl UnderwritingQuotedExposure {
    pub(crate) fn amount_for_pricing(&self) -> Option<MonetaryAmount> {
        match self {
            Self::Single(amount) => Some(amount.clone()),
            Self::None | Self::MixedCurrencies(_) => None,
        }
    }

    pub(crate) fn apply_to_artifact(
        &self,
        artifact: &mut chio_kernel::UnderwritingDecisionArtifact,
    ) {
        let Self::MixedCurrencies(currencies) = self else {
            return;
        };
        if artifact.premium.state != chio_kernel::UnderwritingPremiumState::Quoted {
            return;
        }

        artifact.premium.state = chio_kernel::UnderwritingPremiumState::Withheld;
        artifact.premium.basis_points = None;
        artifact.premium.quoted_amount = None;
        artifact.premium.rationale = format!(
            "premium is withheld because governed exposure spans multiple currencies: {}",
            currencies.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ChildReceiptQuery {
    /// Point-load a single child receipt by its `receipt_id`. When set, the
    /// handler resolves exactly this receipt from the durable store (bounded to
    /// one row), so a store-authoritative `--control-url` deployment can resolve
    /// a child receipt that the kernel's bounded mirror has evicted.
    #[serde(default)]
    pub receipt_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub parent_request_id: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub terminal_state: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RevocationQuery {
    #[serde(default)]
    pub capability_id: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRecordView {
    pub capability_id: String,
    pub revoked_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationListResponse {
    pub configured: bool,
    pub backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
    pub count: usize,
    pub revocations: Vec<RevocationRecordView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptListResponse {
    pub configured: bool,
    pub backend: String,
    pub kind: String,
    pub count: usize,
    pub filters: Value,
    pub receipts: Vec<Value>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BudgetQuery {
    #[serde(default)]
    pub capability_id: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug)]
pub struct BudgetUsageView {
    pub capability_id: String,
    pub grant_index: u32,
    pub invocation_count: u32,
    pub total_cost_exposed: u64,
    pub total_cost_realized_spend: u64,
    pub updated_at: i64,
    pub seq: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BudgetUsageViewWire<'a> {
    capability_id: &'a str,
    grant_index: u32,
    invocation_count: u32,
    total_exposure_charged: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_realized_spend: Option<u64>,
    updated_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seq: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BudgetUsageViewWireInput {
    capability_id: String,
    grant_index: u32,
    invocation_count: u32,
    #[serde(default)]
    total_exposure_charged: Option<u64>,
    #[serde(default)]
    total_realized_spend: Option<u64>,
    updated_at: i64,
    #[serde(default)]
    seq: Option<u64>,
}

impl Serialize for BudgetUsageView {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        BudgetUsageViewWire {
            capability_id: &self.capability_id,
            grant_index: self.grant_index,
            invocation_count: self.invocation_count,
            total_exposure_charged: self.total_cost_exposed,
            total_realized_spend: Some(self.total_cost_realized_spend),
            updated_at: self.updated_at,
            seq: self.seq,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BudgetUsageView {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = BudgetUsageViewWireInput::deserialize(deserializer)?;
        Ok(Self {
            capability_id: wire.capability_id,
            grant_index: wire.grant_index,
            invocation_count: wire.invocation_count,
            total_cost_exposed: require_budget_amount(
                wire.total_exposure_charged,
                "`totalExposureCharged`",
            )?,
            total_cost_realized_spend: wire.total_realized_spend.unwrap_or(0),
            updated_at: wire.updated_at,
            seq: wire.seq,
        })
    }
}

pub(super) fn require_budget_amount<E>(
    amount: Option<u64>,
    missing_field_name: &str,
) -> Result<u64, E>
where
    E: serde::de::Error,
{
    amount.ok_or_else(|| E::custom(format!("missing required field {missing_field_name}")))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetListResponse {
    pub configured: bool,
    pub backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    pub count: usize,
    pub usages: Vec<BudgetUsageView>,
}
