#[derive(Debug, thiserror::Error)]
pub enum ReputationError {
    #[error("failed to decode capability scope json: {0}")]
    InvalidScopeJson(#[from] serde_json::Error),
}

/// Normalized local view of a persisted capability-lineage snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityLineageRecord {
    pub capability_id: String,
    pub subject_key: String,
    pub issuer_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub scope: ChioScope,
    pub delegation_depth: u64,
    pub parent_capability_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CapabilityLineageScopeJsonInput<'a> {
    pub capability_id: String,
    pub subject_key: String,
    pub issuer_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub scope_json: &'a str,
    pub delegation_depth: u64,
    pub parent_capability_id: Option<String>,
}

impl CapabilityLineageRecord {
    pub fn from_scope_json(input: CapabilityLineageScopeJsonInput<'_>) -> Result<Self, ReputationError> {
        Ok(Self {
            capability_id: input.capability_id,
            subject_key: input.subject_key,
            issuer_key: input.issuer_key,
            issued_at: input.issued_at,
            expires_at: input.expires_at,
            scope: serde_json::from_str(input.scope_json)?,
            delegation_depth: input.delegation_depth,
            parent_capability_id: input.parent_capability_id,
        })
    }
}

/// Normalized local view of per-grant budget usage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BudgetUsageRecord {
    pub capability_id: String,
    pub grant_index: u32,
    pub invocation_count: u32,
    pub updated_at: i64,
    pub total_cost_charged: u64,
}

/// Optional external incident data. `None` at the corpus level means the
/// incident metric is unavailable, not zero.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncidentRecord {
    pub timestamp: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalReputationCorpus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<ChioReceipt>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<CapabilityLineageRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub budget_usage: Vec<BudgetUsageRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_reports: Option<Vec<IncidentRecord>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
pub enum MetricValue {
    Known(f64),
    Unknown,
}

impl MetricValue {
    fn known(value: f64) -> Self {
        Self::Known(clamp01(value))
    }

    #[must_use]
    pub fn as_option(self) -> Option<f64> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct ReputationWeights {
    pub boundary_pressure: f64,
    pub resource_stewardship: f64,
    pub least_privilege: f64,
    pub history_depth: f64,
    pub tool_diversity: f64,
    pub delegation_hygiene: f64,
    pub reliability: f64,
    pub incident_correlation: f64,
}

impl Default for ReputationWeights {
    fn default() -> Self {
        Self {
            boundary_pressure: 0.20,
            resource_stewardship: 0.10,
            least_privilege: 0.15,
            history_depth: 0.10,
            tool_diversity: 0.05,
            delegation_hygiene: 0.15,
            reliability: 0.15,
            incident_correlation: 0.10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReputationConfig {
    pub weights: ReputationWeights,
    pub target_utilization: f64,
    pub diversity_cap: f64,
    pub temporal_decay_half_life_days: u32,
    pub history_receipt_target: u64,
    pub history_day_target: u64,
    pub incident_penalty: f64,
    #[serde(default)]
    pub trusted_kernel_keys: BTreeSet<String>,
}

impl Default for ReputationConfig {
    /// Fail-closed default. The empty `trusted_kernel_keys` set will cause
    /// every receipt to fail integrity validation, which yields zero / unknown
    /// scores. Callers MUST populate trusted kernel keys via
    /// [`ReputationConfig::with_trusted_kernel_keys`] before scoring or the
    /// caller's reputation history will be silently filtered out. A
    /// `tracing::warn!` is emitted the first time integrity is checked with an
    /// empty trust set to surface the misconfiguration.
    fn default() -> Self {
        Self {
            weights: ReputationWeights::default(),
            target_utilization: 0.75,
            diversity_cap: 1.0,
            temporal_decay_half_life_days: 30,
            history_receipt_target: DEFAULT_HISTORY_RECEIPT_TARGET,
            history_day_target: DEFAULT_HISTORY_DAY_TARGET,
            incident_penalty: DEFAULT_INCIDENT_PENALTY,
            trusted_kernel_keys: BTreeSet::new(),
        }
    }
}

impl ReputationConfig {
    /// Builder: replace the trusted-kernel-key set with the supplied keys.
    /// Each accepted item is the exact hex form returned by
    /// `PublicKey::to_hex()`. Empty or whitespace-padded inputs are ignored so
    /// malformed trust anchors cannot make the config appear trusted.
    ///
    /// Returns `self` for chaining, e.g.
    /// ```ignore
    /// let config = ReputationConfig::default()
    ///     .with_trusted_kernel_keys([kernel_pubkey.to_hex()]);
    /// ```
    ///
    /// Calling this with an empty iterator preserves the fail-closed behaviour
    /// of [`Default`]: every receipt will continue to fail integrity validation.
    #[must_use]
    pub fn with_trusted_kernel_keys<I, S>(mut self, trusted_kernel_keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.trusted_kernel_keys = trusted_kernel_keys
            .into_iter()
            .filter_map(|trusted_kernel_key| {
                let trusted_kernel_key = trusted_kernel_key.into();
                is_non_empty_unpadded(&trusted_kernel_key).then_some(trusted_kernel_key)
            })
            .collect();
        self
    }

    /// Returns true when the configuration has no trusted kernel keys and
    /// therefore cannot validate any receipt. Callers should treat this as a
    /// misconfiguration: scoring will return unknown / zero metrics.
    #[must_use]
    pub fn has_trusted_kernel_keys(&self) -> bool {
        !self.trusted_kernel_keys.is_empty()
    }
}

fn is_non_empty_unpadded(value: &str) -> bool {
    !value.is_empty() && value.trim() == value
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BoundaryPressureMetrics {
    pub deny_ratio: MetricValue,
    pub policies_observed: usize,
    pub receipts_observed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceStewardshipMetrics {
    pub average_utilization: MetricValue,
    pub fit_score: MetricValue,
    pub capped_grants_observed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LeastPrivilegeMetrics {
    pub score: MetricValue,
    pub capabilities_observed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoryDepthMetrics {
    pub score: MetricValue,
    pub receipt_count: usize,
    pub active_days: usize,
    pub first_seen: Option<u64>,
    pub last_seen: Option<u64>,
    pub span_days: u64,
    pub activity_ratio: MetricValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpecializationMetrics {
    pub score: MetricValue,
    pub distinct_tools: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DelegationHygieneMetrics {
    pub score: MetricValue,
    pub delegations_observed: usize,
    pub scope_reduction_rate: MetricValue,
    pub ttl_reduction_rate: MetricValue,
    pub budget_reduction_rate: MetricValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReliabilityMetrics {
    pub score: MetricValue,
    pub completion_rate: MetricValue,
    pub cancellation_rate: MetricValue,
    pub incompletion_rate: MetricValue,
    pub receipts_observed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IncidentCorrelationMetrics {
    pub score: MetricValue,
    pub incidents_observed: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocalReputationScorecard {
    pub subject_key: String,
    pub computed_at: u64,
    pub boundary_pressure: BoundaryPressureMetrics,
    pub resource_stewardship: ResourceStewardshipMetrics,
    pub least_privilege: LeastPrivilegeMetrics,
    pub history_depth: HistoryDepthMetrics,
    pub specialization: SpecializationMetrics,
    pub delegation_hygiene: DelegationHygieneMetrics,
    pub reliability: ReliabilityMetrics,
    pub incident_correlation: IncidentCorrelationMetrics,
    pub composite_score: MetricValue,
    pub effective_weight_sum: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportedIssuerIdentity {
    pub issuer: String,
    pub signer_public_key: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ImportedTrustMode {
    #[default]
    BilateralEvidenceShare,
    NetworkCleared,
}

impl ImportedTrustMode {
    #[must_use]
    pub fn satisfies(self, required: Self) -> bool {
        matches!(required, Self::BilateralEvidenceShare) || self == required
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImportedReputationProvenance {
    pub share_id: String,
    pub issuer: String,
    pub partner: String,
    pub signer_public_key: String,
    pub imported_at: u64,
    pub exported_at: u64,
    pub require_proofs: bool,
    pub tool_receipts: u64,
    pub capability_lineage: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImportedTrustPolicy {
    pub attenuation_factor: f64,
    pub require_proofs: bool,
    #[serde(default = "default_require_signer_identity")]
    pub require_signer_identity: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_signal_age_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_issuers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_signer_public_keys: Vec<String>,
    #[serde(default)]
    pub required_trust_mode: ImportedTrustMode,
}

impl Default for ImportedTrustPolicy {
    fn default() -> Self {
        Self {
            attenuation_factor: 0.50,
            require_proofs: true,
            require_signer_identity: default_require_signer_identity(),
            max_signal_age_days: Some(30),
            allowed_issuers: Vec::new(),
            allowed_signer_public_keys: Vec::new(),
            required_trust_mode: ImportedTrustMode::BilateralEvidenceShare,
        }
    }
}

fn default_require_signer_identity() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImportedReputationSignal {
    pub provenance: ImportedReputationProvenance,
    pub issuer_identity: ImportedIssuerIdentity,
    pub policy: ImportedTrustPolicy,
    pub trust_mode: ImportedTrustMode,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    pub scorecard: LocalReputationScorecard,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attenuated_composite_score: Option<f64>,
}
