use chio_core::receipt::lineage::SignedExportEnvelope;

fn validate_non_empty(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field} must be non-empty"))
    } else {
        Ok(())
    }
}

fn validate_http_url(value: &str, field: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} must be non-empty"));
    }
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return Err(format!("{field} must start with http:// or https://"));
    }
    Ok(())
}

fn round_portable_score(value: f64) -> f64 {
    if value == 0.0 {
        0.0
    } else {
        (value * 1_000_000_000.0).round() / 1_000_000_000.0
    }
}

fn normalize_metric_value(value: &MetricValue) -> MetricValue {
    match value {
        MetricValue::Known(score) => MetricValue::Known(round_portable_score(*score)),
        MetricValue::Unknown => MetricValue::Unknown,
    }
}

fn normalize_scorecard(scorecard: &LocalReputationScorecard) -> LocalReputationScorecard {
    LocalReputationScorecard {
        subject_key: scorecard.subject_key.clone(),
        computed_at: scorecard.computed_at,
        boundary_pressure: BoundaryPressureMetrics {
            deny_ratio: normalize_metric_value(&scorecard.boundary_pressure.deny_ratio),
            policies_observed: scorecard.boundary_pressure.policies_observed,
            receipts_observed: scorecard.boundary_pressure.receipts_observed,
        },
        resource_stewardship: ResourceStewardshipMetrics {
            average_utilization: normalize_metric_value(
                &scorecard.resource_stewardship.average_utilization,
            ),
            fit_score: normalize_metric_value(&scorecard.resource_stewardship.fit_score),
            capped_grants_observed: scorecard.resource_stewardship.capped_grants_observed,
        },
        least_privilege: LeastPrivilegeMetrics {
            score: normalize_metric_value(&scorecard.least_privilege.score),
            capabilities_observed: scorecard.least_privilege.capabilities_observed,
        },
        history_depth: HistoryDepthMetrics {
            score: normalize_metric_value(&scorecard.history_depth.score),
            receipt_count: scorecard.history_depth.receipt_count,
            active_days: scorecard.history_depth.active_days,
            first_seen: scorecard.history_depth.first_seen,
            last_seen: scorecard.history_depth.last_seen,
            span_days: scorecard.history_depth.span_days,
            activity_ratio: normalize_metric_value(&scorecard.history_depth.activity_ratio),
        },
        specialization: SpecializationMetrics {
            score: normalize_metric_value(&scorecard.specialization.score),
            distinct_tools: scorecard.specialization.distinct_tools,
        },
        delegation_hygiene: DelegationHygieneMetrics {
            score: normalize_metric_value(&scorecard.delegation_hygiene.score),
            delegations_observed: scorecard.delegation_hygiene.delegations_observed,
            scope_reduction_rate: normalize_metric_value(
                &scorecard.delegation_hygiene.scope_reduction_rate,
            ),
            ttl_reduction_rate: normalize_metric_value(
                &scorecard.delegation_hygiene.ttl_reduction_rate,
            ),
            budget_reduction_rate: normalize_metric_value(
                &scorecard.delegation_hygiene.budget_reduction_rate,
            ),
        },
        reliability: ReliabilityMetrics {
            score: normalize_metric_value(&scorecard.reliability.score),
            completion_rate: normalize_metric_value(&scorecard.reliability.completion_rate),
            cancellation_rate: normalize_metric_value(&scorecard.reliability.cancellation_rate),
            incompletion_rate: normalize_metric_value(&scorecard.reliability.incompletion_rate),
            receipts_observed: scorecard.reliability.receipts_observed,
        },
        incident_correlation: IncidentCorrelationMetrics {
            score: normalize_metric_value(&scorecard.incident_correlation.score),
            incidents_observed: scorecard.incident_correlation.incidents_observed,
        },
        composite_score: normalize_metric_value(&scorecard.composite_score),
        effective_weight_sum: round_portable_score(scorecard.effective_weight_sum),
    }
}

pub const PORTABLE_REPUTATION_SUMMARY_SCHEMA: &str = "chio.portable-reputation-summary.v1";
pub const PORTABLE_NEGATIVE_EVENT_SCHEMA: &str = "chio.portable-negative-event.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortableNegativeEventKind {
    PolicyViolation,
    AvailabilityIncident,
    PaymentDefault,
    FraudSignal,
    DisputeLoss,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortableNegativeEventEvidenceKind {
    Receipt,
    GovernanceCase,
    Listing,
    External,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortableReputationFindingCode {
    SummaryUnverifiable,
    SummaryExpired,
    SummaryStale,
    NegativeEventUnverifiable,
    NegativeEventExpired,
    NegativeEventStale,
    SubjectMismatch,
    IssuerNotAllowed,
    DuplicateIssuer,
    ProbationaryRejected,
    BlockingNegativeEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortableNegativeEventEvidenceReference {
    pub kind: PortableNegativeEventEvidenceKind,
    pub reference_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

impl PortableNegativeEventEvidenceReference {
    fn validate(&self, field: &str) -> Result<(), CredentialError> {
        validate_non_empty(&self.reference_id, &format!("{field}.referenceId"))
            .map_err(CredentialError::InvalidPortableReputation)?;
        if let Some(uri) = self.uri.as_deref() {
            validate_http_url(uri, &format!("{field}.uri"))
                .map_err(CredentialError::InvalidPortableReputation)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PortableReputationSummaryArtifact {
    pub schema: String,
    pub summary_id: String,
    pub subject_key: String,
    pub issuer_operator_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_operator_name: Option<String>,
    pub issued_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub window: AttestationWindow,
    pub probationary: bool,
    pub effective_score: f64,
    pub scorecard: LocalReputationScorecard,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported_signal_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_imported_signal_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl PortableReputationSummaryArtifact {
    pub fn validate(&self) -> Result<(), CredentialError> {
        if self.schema != PORTABLE_REPUTATION_SUMMARY_SCHEMA {
            return Err(CredentialError::InvalidPortableReputation(format!(
                "unsupported portable reputation summary schema: {}",
                self.schema
            )));
        }
        validate_non_empty(&self.summary_id, "summaryId")
            .map_err(CredentialError::InvalidPortableReputation)?;
        validate_non_empty(&self.subject_key, "subjectKey")
            .map_err(CredentialError::InvalidPortableReputation)?;
        validate_non_empty(&self.issuer_operator_id, "issuerOperatorId")
            .map_err(CredentialError::InvalidPortableReputation)?;
        if !(0.0..=1.0).contains(&self.effective_score) {
            return Err(CredentialError::InvalidPortableReputation(
                "effectiveScore must be within [0.0, 1.0]".to_string(),
            ));
        }
        if self.scorecard.subject_key != self.subject_key {
            return Err(CredentialError::InvalidPortableReputation(
                "scorecard.subjectKey must match subjectKey".to_string(),
            ));
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at <= self.issued_at {
                return Err(CredentialError::InvalidPortableReputation(
                    "expiresAt must be greater than issuedAt".to_string(),
                ));
            }
        }
        if self.window.until < self.window.since.unwrap_or(0) {
            return Err(CredentialError::InvalidPortableReputation(
                "window.until must be greater than or equal to window.since".to_string(),
            ));
        }
        Ok(())
    }
}

pub type SignedPortableReputationSummary = SignedExportEnvelope<PortableReputationSummaryArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PortableNegativeEventArtifact {
    pub schema: String,
    pub event_id: String,
    pub subject_key: String,
    pub issuer_operator_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_operator_name: Option<String>,
    pub kind: PortableNegativeEventKind,
    pub severity: f64,
    pub observed_at: u64,
    pub published_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<PortableNegativeEventEvidenceReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl PortableNegativeEventArtifact {
    pub fn validate(&self) -> Result<(), CredentialError> {
        if self.schema != PORTABLE_NEGATIVE_EVENT_SCHEMA {
            return Err(CredentialError::InvalidPortableReputation(format!(
                "unsupported portable negative event schema: {}",
                self.schema
            )));
        }
        validate_non_empty(&self.event_id, "eventId")
            .map_err(CredentialError::InvalidPortableReputation)?;
        validate_non_empty(&self.subject_key, "subjectKey")
            .map_err(CredentialError::InvalidPortableReputation)?;
        validate_non_empty(&self.issuer_operator_id, "issuerOperatorId")
            .map_err(CredentialError::InvalidPortableReputation)?;
        if !(0.0..=1.0).contains(&self.severity) {
            return Err(CredentialError::InvalidPortableReputation(
                "severity must be within [0.0, 1.0]".to_string(),
            ));
        }
        if self.published_at < self.observed_at {
            return Err(CredentialError::InvalidPortableReputation(
                "publishedAt must be greater than or equal to observedAt".to_string(),
            ));
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at <= self.published_at {
                return Err(CredentialError::InvalidPortableReputation(
                    "expiresAt must be greater than publishedAt".to_string(),
                ));
            }
        }
        for (index, evidence_ref) in self.evidence_refs.iter().enumerate() {
            evidence_ref.validate(&format!("evidenceRefs[{index}]"))?;
        }
        Ok(())
    }
}

pub type SignedPortableNegativeEvent = SignedExportEnvelope<PortableNegativeEventArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PortableReputationSummaryIssueRequest {
    pub subject_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PortableNegativeEventIssueRequest {
    pub subject_key: String,
    pub kind: PortableNegativeEventKind,
    pub severity: f64,
    pub observed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<PortableNegativeEventEvidenceReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PortableReputationWeightingProfile {
    pub profile_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_issuer_operator_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub issuer_weights: BTreeMap<String, f64>,
    pub max_summary_age_secs: u64,
    pub max_event_age_secs: u64,
    pub reject_probationary: bool,
    pub negative_event_weight: f64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocking_event_kinds: Vec<PortableNegativeEventKind>,
}

impl PortableReputationWeightingProfile {
    pub fn validate(&self) -> Result<(), CredentialError> {
        validate_non_empty(&self.profile_id, "profileId")
            .map_err(CredentialError::InvalidPortableReputation)?;
        if self.max_summary_age_secs == 0 {
            return Err(CredentialError::InvalidPortableReputation(
                "maxSummaryAgeSecs must be greater than zero".to_string(),
            ));
        }
        if self.max_event_age_secs == 0 {
            return Err(CredentialError::InvalidPortableReputation(
                "maxEventAgeSecs must be greater than zero".to_string(),
            ));
        }
        if !(0.0..=1.0).contains(&self.negative_event_weight) {
            return Err(CredentialError::InvalidPortableReputation(
                "negativeEventWeight must be within [0.0, 1.0]".to_string(),
            ));
        }
        for issuer in &self.allowed_issuer_operator_ids {
            validate_non_empty(issuer, "allowedIssuerOperatorIds")
                .map_err(CredentialError::InvalidPortableReputation)?;
        }
        for (issuer, weight) in &self.issuer_weights {
            validate_non_empty(issuer, "issuerWeights.key")
                .map_err(CredentialError::InvalidPortableReputation)?;
            if !weight.is_finite() || *weight < 0.0 {
                return Err(CredentialError::InvalidPortableReputation(
                    "issuerWeights values must be finite and non-negative".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PortableReputationEvaluationRequest {
    pub subject_key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub summaries: Vec<SignedPortableReputationSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub negative_events: Vec<SignedPortableNegativeEvent>,
    pub weighting_profile: PortableReputationWeightingProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluated_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PortableReputationFinding {
    pub code: PortableReputationFindingCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_operator_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PortableReputationEvaluation {
    pub subject_key: String,
    pub evaluated_at: u64,
    pub accepted_summary_count: usize,
    pub rejected_summary_count: usize,
    pub accepted_negative_event_count: usize,
    pub rejected_negative_event_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported_positive_score: Option<f64>,
    pub negative_event_penalty: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_score: Option<f64>,
    pub blocked: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<PortableReputationFinding>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PortableReputationSummaryArtifactContext {
    pub issuer_operator_name: Option<String>,
    pub effective_score: f64,
    pub probationary: bool,
    pub imported_signal_count: Option<usize>,
    pub accepted_imported_signal_count: Option<usize>,
    pub issued_at: u64,
}

pub fn build_portable_reputation_summary_artifact(
    issuer_operator_id: &str,
    request: &PortableReputationSummaryIssueRequest,
    scorecard: &LocalReputationScorecard,
    context: PortableReputationSummaryArtifactContext,
) -> Result<PortableReputationSummaryArtifact, CredentialError> {
    let PortableReputationSummaryArtifactContext {
        issuer_operator_name,
        effective_score,
        probationary,
        imported_signal_count,
        accepted_imported_signal_count,
        issued_at,
    } = context;
    validate_non_empty(issuer_operator_id, "issuerOperatorId")
        .map_err(CredentialError::InvalidPortableReputation)?;
    validate_non_empty(&request.subject_key, "subjectKey")
        .map_err(CredentialError::InvalidPortableReputation)?;
    let normalized_scorecard = normalize_scorecard(scorecard);
    let identity = serde_json::json!({
        "issuerOperatorId": issuer_operator_id,
        "subjectKey": request.subject_key,
        "issuedAt": issued_at,
        "window": {
            "since": request.since,
            "until": request.until.unwrap_or(issued_at),
        },
    });
    let summary_id = format!(
        "portable-reputation-{}",
        sha256_hex(&canonical_json_bytes(&identity).map_err(CredentialError::Core)?)
    );
    let artifact = PortableReputationSummaryArtifact {
        schema: PORTABLE_REPUTATION_SUMMARY_SCHEMA.to_string(),
        summary_id,
        subject_key: request.subject_key.clone(),
        issuer_operator_id: issuer_operator_id.to_string(),
        issuer_operator_name,
        issued_at,
        expires_at: request.expires_at,
        window: AttestationWindow {
            since: request.since,
            until: request.until.unwrap_or(issued_at),
        },
        probationary,
        effective_score: round_portable_score(effective_score),
        scorecard: normalized_scorecard,
        imported_signal_count,
        accepted_imported_signal_count,
        note: request.note.clone(),
    };
    artifact.validate()?;
    Ok(artifact)
}

pub fn build_portable_negative_event_artifact(
    issuer_operator_id: &str,
    issuer_operator_name: Option<String>,
    request: &PortableNegativeEventIssueRequest,
    issued_at: u64,
) -> Result<PortableNegativeEventArtifact, CredentialError> {
    validate_non_empty(issuer_operator_id, "issuerOperatorId")
        .map_err(CredentialError::InvalidPortableReputation)?;
    validate_non_empty(&request.subject_key, "subjectKey")
        .map_err(CredentialError::InvalidPortableReputation)?;
    let published_at = request.published_at.unwrap_or(issued_at);
    let identity = serde_json::json!({
        "issuerOperatorId": issuer_operator_id,
        "subjectKey": request.subject_key,
        "kind": request.kind,
        "observedAt": request.observed_at,
        "publishedAt": published_at,
        "severity": request.severity,
    });
    let event_id = format!(
        "portable-negative-event-{}",
        sha256_hex(&canonical_json_bytes(&identity).map_err(CredentialError::Core)?)
    );
    let artifact = PortableNegativeEventArtifact {
        schema: PORTABLE_NEGATIVE_EVENT_SCHEMA.to_string(),
        event_id,
        subject_key: request.subject_key.clone(),
        issuer_operator_id: issuer_operator_id.to_string(),
        issuer_operator_name,
        kind: request.kind,
        severity: request.severity,
        observed_at: request.observed_at,
        published_at,
        expires_at: request.expires_at,
        evidence_refs: request.evidence_refs.clone(),
        note: request.note.clone(),
    };
    artifact.validate()?;
    Ok(artifact)
}

pub fn evaluate_portable_reputation(
    request: &PortableReputationEvaluationRequest,
    evaluated_at: u64,
) -> Result<PortableReputationEvaluation, CredentialError> {
    validate_non_empty(&request.subject_key, "subjectKey")
        .map_err(CredentialError::InvalidPortableReputation)?;
    request.weighting_profile.validate()?;

    let mut findings = Vec::new();
    let mut accepted_summary_count = 0usize;
    let mut rejected_summary_count = 0usize;
    let mut accepted_negative_event_count = 0usize;
    let mut rejected_negative_event_count = 0usize;
    let mut weighted_score_total = 0.0f64;
    let mut weight_total = 0.0f64;
    let mut negative_event_penalty = 0.0f64;
    let mut blocked = false;
    let mut accepted_issuers = BTreeSet::new();

    for summary in &request.summaries {
        let issuer = Some(summary.body.issuer_operator_id.clone());
        let reference = Some(summary.body.summary_id.clone());
        match summary.verify_signature() {
            Ok(true) => {}
            _ => {
                rejected_summary_count += 1;
                findings.push(PortableReputationFinding {
                    code: PortableReputationFindingCode::SummaryUnverifiable,
                    message: "portable reputation summary signature is invalid".to_string(),
                    issuer_operator_id: issuer,
                    reference_id: reference,
                });
                continue;
            }
        }
        if let Err(error) = summary.body.validate() {
            rejected_summary_count += 1;
            findings.push(PortableReputationFinding {
                code: PortableReputationFindingCode::SummaryUnverifiable,
                message: error.to_string(),
                issuer_operator_id: issuer,
                reference_id: reference,
            });
            continue;
        }
        if summary.body.subject_key != request.subject_key {
            rejected_summary_count += 1;
            findings.push(PortableReputationFinding {
                code: PortableReputationFindingCode::SubjectMismatch,
                message: "portable reputation summary subject does not match evaluation subject"
                    .to_string(),
                issuer_operator_id: issuer,
                reference_id: reference,
            });
            continue;
        }
        if summary.body.issued_at > evaluated_at {
            rejected_summary_count += 1;
            findings.push(PortableReputationFinding {
                code: PortableReputationFindingCode::SummaryUnverifiable,
                message: "portable reputation summary is issued in the future".to_string(),
                issuer_operator_id: issuer,
                reference_id: reference,
            });
            continue;
        }
        if summary
            .body
            .expires_at
            .is_some_and(|expires_at| expires_at <= evaluated_at)
        {
            rejected_summary_count += 1;
            findings.push(PortableReputationFinding {
                code: PortableReputationFindingCode::SummaryExpired,
                message: "portable reputation summary has expired".to_string(),
                issuer_operator_id: issuer,
                reference_id: reference,
            });
            continue;
        }
        if evaluated_at.saturating_sub(summary.body.issued_at)
            > request.weighting_profile.max_summary_age_secs
        {
            rejected_summary_count += 1;
            findings.push(PortableReputationFinding {
                code: PortableReputationFindingCode::SummaryStale,
                message: "portable reputation summary is older than the local freshness window"
                    .to_string(),
                issuer_operator_id: issuer,
                reference_id: reference,
            });
            continue;
        }
        if !request.weighting_profile.allowed_issuer_operator_ids.is_empty()
            && !request
                .weighting_profile
                .allowed_issuer_operator_ids
                .contains(&summary.body.issuer_operator_id)
        {
            rejected_summary_count += 1;
            findings.push(PortableReputationFinding {
                code: PortableReputationFindingCode::IssuerNotAllowed,
                message: "portable reputation summary issuer is not allowed by the local weighting profile".to_string(),
                issuer_operator_id: issuer,
                reference_id: reference,
            });
            continue;
        }
        if request.weighting_profile.reject_probationary && summary.body.probationary {
            rejected_summary_count += 1;
            findings.push(PortableReputationFinding {
                code: PortableReputationFindingCode::ProbationaryRejected,
                message: "portable reputation summary is probationary under the local weighting profile".to_string(),
                issuer_operator_id: issuer,
                reference_id: reference,
            });
            continue;
        }
        if !accepted_issuers.insert(summary.body.issuer_operator_id.clone()) {
            rejected_summary_count += 1;
            findings.push(PortableReputationFinding {
                code: PortableReputationFindingCode::DuplicateIssuer,
                message:
                    "portable reputation summary set contains multiple accepted summaries from the same issuer".to_string(),
                issuer_operator_id: issuer,
                reference_id: reference,
            });
            continue;
        }
        let issuer_weight = request
            .weighting_profile
            .issuer_weights
            .get(&summary.body.issuer_operator_id)
            .copied()
            .unwrap_or(1.0);
        weighted_score_total += summary.body.effective_score * issuer_weight;
        weight_total += issuer_weight;
        accepted_summary_count += 1;
    }

    for event in &request.negative_events {
        let issuer = Some(event.body.issuer_operator_id.clone());
        let reference = Some(event.body.event_id.clone());
        match event.verify_signature() {
            Ok(true) => {}
            _ => {
                rejected_negative_event_count += 1;
                findings.push(PortableReputationFinding {
                    code: PortableReputationFindingCode::NegativeEventUnverifiable,
                    message: "portable negative event signature is invalid".to_string(),
                    issuer_operator_id: issuer,
                    reference_id: reference,
                });
                continue;
            }
        }
        if let Err(error) = event.body.validate() {
            rejected_negative_event_count += 1;
            findings.push(PortableReputationFinding {
                code: PortableReputationFindingCode::NegativeEventUnverifiable,
                message: error.to_string(),
                issuer_operator_id: issuer,
                reference_id: reference,
            });
            continue;
        }
        if event.body.subject_key != request.subject_key {
            rejected_negative_event_count += 1;
            findings.push(PortableReputationFinding {
                code: PortableReputationFindingCode::SubjectMismatch,
                message: "portable negative event subject does not match evaluation subject"
                    .to_string(),
                issuer_operator_id: issuer,
                reference_id: reference,
            });
            continue;
        }
        if event.body.published_at > evaluated_at {
            rejected_negative_event_count += 1;
            findings.push(PortableReputationFinding {
                code: PortableReputationFindingCode::NegativeEventUnverifiable,
                message: "portable negative event is published in the future".to_string(),
                issuer_operator_id: issuer,
                reference_id: reference,
            });
            continue;
        }
        if event
            .body
            .expires_at
            .is_some_and(|expires_at| expires_at <= evaluated_at)
        {
            rejected_negative_event_count += 1;
            findings.push(PortableReputationFinding {
                code: PortableReputationFindingCode::NegativeEventExpired,
                message: "portable negative event has expired".to_string(),
                issuer_operator_id: issuer,
                reference_id: reference,
            });
            continue;
        }
        if evaluated_at.saturating_sub(event.body.published_at)
            > request.weighting_profile.max_event_age_secs
        {
            rejected_negative_event_count += 1;
            findings.push(PortableReputationFinding {
                code: PortableReputationFindingCode::NegativeEventStale,
                message: "portable negative event is older than the local freshness window"
                    .to_string(),
                issuer_operator_id: issuer,
                reference_id: reference,
            });
            continue;
        }
        if !request.weighting_profile.allowed_issuer_operator_ids.is_empty()
            && !request
                .weighting_profile
                .allowed_issuer_operator_ids
                .contains(&event.body.issuer_operator_id)
        {
            rejected_negative_event_count += 1;
            findings.push(PortableReputationFinding {
                code: PortableReputationFindingCode::IssuerNotAllowed,
                message: "portable negative event issuer is not allowed by the local weighting profile".to_string(),
                issuer_operator_id: issuer,
                reference_id: reference,
            });
            continue;
        }
        let issuer_weight = request
            .weighting_profile
            .issuer_weights
            .get(&event.body.issuer_operator_id)
            .copied()
            .unwrap_or(1.0);
        negative_event_penalty += event.body.severity
            * request.weighting_profile.negative_event_weight
            * issuer_weight;
        accepted_negative_event_count += 1;
        if request
            .weighting_profile
            .blocking_event_kinds
            .contains(&event.body.kind)
        {
            blocked = true;
            findings.push(PortableReputationFinding {
                code: PortableReputationFindingCode::BlockingNegativeEvent,
                message: "portable negative event kind is locally configured as blocking"
                    .to_string(),
                issuer_operator_id: issuer,
                reference_id: reference,
            });
        }
    }

    negative_event_penalty = negative_event_penalty.clamp(0.0, 1.0);
    let imported_positive_score = if weight_total > 0.0 {
        Some((weighted_score_total / weight_total).clamp(0.0, 1.0))
    } else {
        None
    };
    let effective_score = imported_positive_score.map(|score| {
        if blocked {
            0.0
        } else {
            (score - negative_event_penalty).clamp(0.0, 1.0)
        }
    });

    Ok(PortableReputationEvaluation {
        subject_key: request.subject_key.clone(),
        evaluated_at,
        accepted_summary_count,
        rejected_summary_count,
        accepted_negative_event_count,
        rejected_negative_event_count,
        imported_positive_score,
        negative_event_penalty,
        effective_score,
        blocked,
        findings,
    })
}

#[cfg(test)]
mod portable_reputation_tests {
    use super::*;
    use chio_core::Keypair;
    use chio_reputation::{
        BoundaryPressureMetrics, DelegationHygieneMetrics, HistoryDepthMetrics,
        IncidentCorrelationMetrics, LeastPrivilegeMetrics, ReliabilityMetrics,
        ResourceStewardshipMetrics, SpecializationMetrics,
    };

    fn assert_close(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() < 1e-9,
            "expected {expected}, got {actual}"
        );
    }

    fn scorecard(subject_key: &str, composite: f64) -> LocalReputationScorecard {
        LocalReputationScorecard {
            subject_key: subject_key.to_string(),
            computed_at: 1_700_000_100,
            boundary_pressure: BoundaryPressureMetrics {
                deny_ratio: MetricValue::Known(0.1),
                policies_observed: 4,
                receipts_observed: 8,
            },
            resource_stewardship: ResourceStewardshipMetrics {
                average_utilization: MetricValue::Known(0.8),
                fit_score: MetricValue::Known(0.9),
                capped_grants_observed: 3,
            },
            least_privilege: LeastPrivilegeMetrics {
                score: MetricValue::Known(0.9),
                capabilities_observed: 6,
            },
            history_depth: HistoryDepthMetrics {
                score: MetricValue::Known(0.8),
                receipt_count: 8,
                active_days: 4,
                first_seen: Some(1_700_000_000),
                last_seen: Some(1_700_000_100),
                span_days: 4,
                activity_ratio: MetricValue::Known(0.75),
            },
            specialization: SpecializationMetrics {
                score: MetricValue::Known(0.7),
                distinct_tools: 2,
            },
            delegation_hygiene: DelegationHygieneMetrics {
                score: MetricValue::Known(0.8),
                delegations_observed: 2,
                scope_reduction_rate: MetricValue::Known(0.8),
                ttl_reduction_rate: MetricValue::Known(0.8),
                budget_reduction_rate: MetricValue::Known(0.8),
            },
            reliability: ReliabilityMetrics {
                score: MetricValue::Known(0.9),
                completion_rate: MetricValue::Known(0.95),
                cancellation_rate: MetricValue::Known(0.02),
                incompletion_rate: MetricValue::Known(0.03),
                receipts_observed: 8,
            },
            incident_correlation: IncidentCorrelationMetrics {
                score: MetricValue::Known(0.9),
                incidents_observed: Some(0),
            },
            composite_score: MetricValue::Known(composite),
            effective_weight_sum: 1.0,
        }
    }

    #[test]
    fn portable_reputation_evaluation_applies_weighting_and_negative_events() {
        let issuer = Keypair::generate();
        let subject_key = issuer.public_key().to_hex();
        let summary = SignedPortableReputationSummary::sign(
            build_portable_reputation_summary_artifact(
                "https://issuer.example",
                &PortableReputationSummaryIssueRequest {
                    subject_key: subject_key.clone(),
                    since: Some(1_700_000_000),
                    until: Some(1_700_000_100),
                    issued_at: Some(1_700_000_100),
                    expires_at: Some(1_700_000_500),
                    note: None,
                },
                &scorecard(&subject_key, 0.8),
                PortableReputationSummaryArtifactContext {
                    issuer_operator_name: None,
                    effective_score: 0.8,
                    probationary: false,
                    imported_signal_count: Some(0),
                    accepted_imported_signal_count: Some(0),
                    issued_at: 1_700_000_100,
                },
            )
            .expect("build summary"),
            &issuer,
        )
        .expect("sign summary");
        let event = SignedPortableNegativeEvent::sign(
            build_portable_negative_event_artifact(
                "https://issuer.example",
                None,
                &PortableNegativeEventIssueRequest {
                    subject_key: subject_key.clone(),
                    kind: PortableNegativeEventKind::PolicyViolation,
                    severity: 0.4,
                    observed_at: 1_700_000_090,
                    published_at: Some(1_700_000_100),
                    expires_at: Some(1_700_000_600),
                    evidence_refs: vec![PortableNegativeEventEvidenceReference {
                        kind: PortableNegativeEventEvidenceKind::External,
                        reference_id: "case-1".to_string(),
                        uri: Some("https://issuer.example/cases/1".to_string()),
                        sha256: None,
                    }],
                    note: None,
                },
                1_700_000_100,
            )
            .expect("build event"),
            &issuer,
        )
        .expect("sign event");

        let evaluation = evaluate_portable_reputation(
            &PortableReputationEvaluationRequest {
                subject_key: subject_key.clone(),
                summaries: vec![summary],
                negative_events: vec![event],
                weighting_profile: PortableReputationWeightingProfile {
                    profile_id: "profile-1".to_string(),
                    allowed_issuer_operator_ids: vec!["https://issuer.example".to_string()],
                    issuer_weights: BTreeMap::from([("https://issuer.example".to_string(), 0.75)]),
                    max_summary_age_secs: 3600,
                    max_event_age_secs: 3600,
                    reject_probationary: false,
                    negative_event_weight: 0.5,
                    blocking_event_kinds: Vec::new(),
                },
                evaluated_at: Some(1_700_000_120),
            },
            1_700_000_120,
        )
        .expect("evaluate");

        assert_eq!(evaluation.accepted_summary_count, 1);
        assert_eq!(evaluation.accepted_negative_event_count, 1);
        assert_eq!(evaluation.rejected_summary_count, 0);
        assert_eq!(evaluation.rejected_negative_event_count, 0);
        assert_close(
            evaluation
                .imported_positive_score
                .expect("expected imported positive score"),
            0.8,
        );
        assert_close(evaluation.negative_event_penalty, 0.15);
        assert_close(
            evaluation.effective_score.expect("expected effective score"),
            0.65,
        );
        assert!(!evaluation.blocked);
    }

    #[test]
    fn portable_reputation_evaluation_rejects_duplicate_or_disallowed_issuers() {
        let issuer = Keypair::generate();
        let subject_key = issuer.public_key().to_hex();
        let summary = SignedPortableReputationSummary::sign(
            build_portable_reputation_summary_artifact(
                "https://issuer.example",
                &PortableReputationSummaryIssueRequest {
                    subject_key: subject_key.clone(),
                    since: None,
                    until: Some(1_700_000_100),
                    issued_at: Some(1_700_000_100),
                    expires_at: Some(1_700_000_500),
                    note: None,
                },
                &scorecard(&subject_key, 0.7),
                PortableReputationSummaryArtifactContext {
                    issuer_operator_name: None,
                    effective_score: 0.7,
                    probationary: true,
                    imported_signal_count: Some(0),
                    accepted_imported_signal_count: Some(0),
                    issued_at: 1_700_000_100,
                },
            )
            .expect("build summary"),
            &issuer,
        )
        .expect("sign summary");

        let evaluation = evaluate_portable_reputation(
            &PortableReputationEvaluationRequest {
                subject_key,
                summaries: vec![summary.clone(), summary],
                negative_events: Vec::new(),
                weighting_profile: PortableReputationWeightingProfile {
                    profile_id: "profile-2".to_string(),
                    allowed_issuer_operator_ids: vec!["https://other.example".to_string()],
                    issuer_weights: BTreeMap::new(),
                    max_summary_age_secs: 3600,
                    max_event_age_secs: 3600,
                    reject_probationary: true,
                    negative_event_weight: 0.5,
                    blocking_event_kinds: Vec::new(),
                },
                evaluated_at: Some(1_700_000_120),
            },
            1_700_000_120,
        )
        .expect("evaluate");

        assert_eq!(evaluation.accepted_summary_count, 0);
        assert_eq!(evaluation.rejected_summary_count, 2);
        assert_eq!(evaluation.effective_score, None);
        assert!(evaluation.findings.iter().all(|finding| {
            finding.code == PortableReputationFindingCode::IssuerNotAllowed
        }));
    }

    #[test]
    fn signed_portable_reputation_summary_survives_json_roundtrip() {
        let issuer = Keypair::generate();
        let subject_key = issuer.public_key().to_hex();
        let summary = SignedPortableReputationSummary::sign(
            build_portable_reputation_summary_artifact(
                "https://issuer.example",
                &PortableReputationSummaryIssueRequest {
                    subject_key: subject_key.clone(),
                    since: Some(1_700_000_000),
                    until: Some(1_700_000_100),
                    issued_at: Some(1_700_000_100),
                    expires_at: Some(1_700_000_500),
                    note: None,
                },
                &scorecard(&subject_key, 0.8),
                PortableReputationSummaryArtifactContext {
                    issuer_operator_name: None,
                    effective_score: 0.8,
                    probationary: false,
                    imported_signal_count: Some(1),
                    accepted_imported_signal_count: Some(1),
                    issued_at: 1_700_000_100,
                },
            )
            .expect("build summary"),
            &issuer,
        )
        .expect("sign summary");

        let encoded = serde_json::to_string(&summary).expect("serialize summary");
        let decoded: SignedPortableReputationSummary =
            serde_json::from_str(&encoded).expect("deserialize summary");
        assert!(
            decoded.verify_signature().expect("verify summary"),
            "summary roundtrip invalidated signature: {encoded}"
        );
    }
}
