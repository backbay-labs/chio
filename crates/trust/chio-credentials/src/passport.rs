#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentPassport {
    pub schema: String,
    pub subject: String,
    pub credentials: Vec<ReputationCredential>,
    pub merkle_roots: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enterprise_identity_provenance: Vec<EnterpriseIdentityProvenance>,
    pub issued_at: String,
    pub valid_until: String,
    /// Trust tier synthesized from the operator's compliance score and
    /// behavioral-anomaly signal. Optional for wire back-compat: passports
    /// without the field omit it entirely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_tier: Option<TrustTier>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PassportLifecycleState {
    Active,
    Stale,
    Superseded,
    Revoked,
    NotFound,
}

impl PassportLifecycleState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
            Self::NotFound => "not-found",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassportStatusDistribution {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolve_urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_ttl_secs: Option<u64>,
}

impl PassportStatusDistribution {
    pub fn is_empty(&self) -> bool {
        self.resolve_urls.is_empty() && self.cache_ttl_secs.is_none()
    }

    pub fn validate(&self) -> Result<(), CredentialError> {
        if self.cache_ttl_secs == Some(0) {
            return Err(CredentialError::InvalidPassportLifecycle(
                "passport status distribution cache_ttl_secs must be greater than zero when present"
                    .to_string(),
            ));
        }
        if !self.resolve_urls.is_empty() && self.cache_ttl_secs.is_none() {
            return Err(CredentialError::InvalidPassportLifecycle(
                "passport status distribution must include cache_ttl_secs when resolve_urls are published"
                    .to_string(),
            ));
        }
        let mut seen = BTreeSet::new();
        for url in &self.resolve_urls {
            let trimmed = url.trim();
            if trimmed.is_empty() {
                return Err(CredentialError::InvalidPassportLifecycle(
                    "passport status distribution resolve_urls must be non-empty".to_string(),
                ));
            }
            if !seen.insert(trimmed.to_string()) {
                return Err(CredentialError::InvalidPassportLifecycle(format!(
                    "passport status distribution contains duplicate resolve_url `{trimmed}`"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassportLifecycleRecord {
    pub passport_id: String,
    pub subject: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuers: Vec<String>,
    pub issuer_count: usize,
    pub published_at: u64,
    #[serde(default)]
    pub updated_at: u64,
    pub status: PassportLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_reason: Option<String>,
    #[serde(default, skip_serializing_if = "PassportStatusDistribution::is_empty")]
    pub distribution: PassportStatusDistribution,
    pub valid_until: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassportLifecycleResolution {
    pub passport_id: String,
    pub subject: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuers: Vec<String>,
    pub issuer_count: usize,
    pub state: PassportLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_reason: Option<String>,
    #[serde(default, skip_serializing_if = "PassportStatusDistribution::is_empty")]
    pub distribution: PassportStatusDistribution,
    pub valid_until: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl PassportLifecycleRecord {
    pub fn validate(&self) -> Result<(), CredentialError> {
        validate_passport_lifecycle_common(
            &self.passport_id,
            &self.subject,
            &self.issuers,
            self.issuer_count,
            Some(self.published_at),
            &self.valid_until,
        )?;
        if self.status == PassportLifecycleState::NotFound
            || self.status == PassportLifecycleState::Stale
        {
            return Err(CredentialError::InvalidPassportLifecycle(format!(
                "passport lifecycle entry `{}` cannot persist stale or not-found state",
                self.passport_id
            )));
        }
        if self.updated_at == 0 {
            return Err(CredentialError::InvalidPassportLifecycle(format!(
                "passport lifecycle entry `{}` must include a non-zero updated_at",
                self.passport_id
            )));
        }
        if self.updated_at < self.published_at {
            return Err(CredentialError::InvalidPassportLifecycle(format!(
                "passport lifecycle entry `{}` cannot have updated_at earlier than published_at",
                self.passport_id
            )));
        }
        self.distribution.validate()?;
        validate_passport_lifecycle_state_fields(
            &self.passport_id,
            self.status,
            self.superseded_by.as_deref(),
            self.revoked_at,
            self.revoked_reason.as_deref(),
            true,
        )
    }

    /// Project this lifecycle record into the bridge value the
    /// `chio-revocation-oracle::passport_bridge` surface ingests.
    ///
    /// Returns `Ok(Some(_))` only when `self.status` is
    /// `PassportLifecycleState::Revoked` and the record carries the
    /// non-zero `revoked_at` the lifecycle validator already enforces;
    /// non-revoked records yield `Ok(None)`. Malformed revoked records
    /// surface the bridge's structural validation through
    /// `Err(PassportRevocationBridgeError)` so callers stay fail-closed.
    ///
    /// This method does NOT modify the record: the named
    /// `property_passport::*` invariants remain green because the
    /// projection is read-only on the credentials side.
    pub fn to_revocation_event(
        &self,
    ) -> Result<
        Option<chio_revocation_oracle::PassportRevocationEvent>,
        chio_revocation_oracle::PassportRevocationBridgeError,
    > {
        if self.status != PassportLifecycleState::Revoked {
            return Ok(None);
        }
        let revoked_at = self.revoked_at.unwrap_or(0);
        let event = chio_revocation_oracle::PassportRevocationEvent::new(
            self.passport_id.clone(),
            self.subject.clone(),
            revoked_at,
            self.revoked_reason.clone(),
        )?;
        Ok(Some(event))
    }
}

impl PassportLifecycleResolution {
    pub fn validate(&self) -> Result<(), CredentialError> {
        if self.state != PassportLifecycleState::NotFound {
            validate_passport_lifecycle_common(
                &self.passport_id,
                &self.subject,
                &self.issuers,
                self.issuer_count,
                self.published_at,
                &self.valid_until,
            )?;
            let updated_at = self.updated_at.ok_or_else(|| {
                CredentialError::InvalidPassportLifecycle(format!(
                    "passport lifecycle entry `{}` must include updated_at",
                    self.passport_id
                ))
            })?;
            if let Some(published_at) = self.published_at {
                if updated_at < published_at {
                    return Err(CredentialError::InvalidPassportLifecycle(format!(
                        "passport lifecycle entry `{}` cannot have updated_at earlier than published_at",
                        self.passport_id
                    )));
                }
            }
        } else if self.passport_id.trim().is_empty() {
            return Err(CredentialError::InvalidPassportLifecycle(
                "passport lifecycle resolution must include a non-empty passport_id".to_string(),
            ));
        }
        self.distribution.validate()?;
        if self.state == PassportLifecycleState::NotFound && !self.distribution.is_empty() {
            return Err(CredentialError::InvalidPassportLifecycle(format!(
                "not-found passport lifecycle entry `{}` cannot include distribution metadata",
                self.passport_id
            )));
        }
        if self.state == PassportLifecycleState::NotFound && self.updated_at.is_some() {
            return Err(CredentialError::InvalidPassportLifecycle(format!(
                "not-found passport lifecycle entry `{}` cannot include updated_at",
                self.passport_id
            )));
        }
        validate_passport_lifecycle_state_fields(
            &self.passport_id,
            self.state,
            self.superseded_by.as_deref(),
            self.revoked_at,
            self.revoked_reason.as_deref(),
            self.published_at.is_some(),
        )
    }
}

fn validate_passport_lifecycle_common(
    passport_id: &str,
    subject: &str,
    issuers: &[String],
    issuer_count: usize,
    published_at: Option<u64>,
    valid_until: &str,
) -> Result<(), CredentialError> {
    if passport_id.trim().is_empty() {
        return Err(CredentialError::InvalidPassportLifecycle(
            "passport lifecycle entries must include a non-empty passport_id".to_string(),
        ));
    }
    if subject.trim().is_empty() {
        return Err(CredentialError::InvalidPassportLifecycle(format!(
            "passport lifecycle entry `{passport_id}` must include a non-empty subject"
        )));
    }
    DidChio::from_str(subject)?;
    if issuers.is_empty() {
        return Err(CredentialError::InvalidPassportLifecycle(format!(
            "passport lifecycle entry `{passport_id}` must include at least one issuer"
        )));
    }
    if issuer_count != issuers.len() {
        return Err(CredentialError::InvalidPassportLifecycle(format!(
            "passport lifecycle entry `{passport_id}` has mismatched issuer_count"
        )));
    }
    let mut deduped = issuers.to_vec();
    deduped.sort();
    deduped.dedup();
    if deduped != issuers {
        return Err(CredentialError::InvalidPassportLifecycle(format!(
            "passport lifecycle entry `{passport_id}` must store issuers in sorted unique order"
        )));
    }
    if let Some(published_at) = published_at {
        if published_at == 0 {
            return Err(CredentialError::InvalidPassportLifecycle(format!(
                "passport lifecycle entry `{passport_id}` must include a non-zero published_at"
            )));
        }
    }
    unix_from_rfc3339(valid_until)?;
    Ok(())
}

fn validate_passport_lifecycle_state_fields(
    passport_id: &str,
    state: PassportLifecycleState,
    superseded_by: Option<&str>,
    revoked_at: Option<u64>,
    revoked_reason: Option<&str>,
    has_published_at: bool,
) -> Result<(), CredentialError> {
    if let Some(value) = superseded_by {
        if value.trim().is_empty() {
            return Err(CredentialError::InvalidPassportLifecycle(format!(
                "passport lifecycle entry `{passport_id}` cannot include an empty superseded_by"
            )));
        }
    }
    if let Some(value) = revoked_reason {
        if value.trim().is_empty() {
            return Err(CredentialError::InvalidPassportLifecycle(format!(
                "passport lifecycle entry `{passport_id}` cannot include an empty revoked_reason"
            )));
        }
    }
    match state {
        PassportLifecycleState::Active => {
            if !has_published_at {
                return Err(CredentialError::InvalidPassportLifecycle(format!(
                    "active passport lifecycle entry `{passport_id}` must include published_at"
                )));
            }
            if superseded_by.is_some() || revoked_at.is_some() || revoked_reason.is_some() {
                return Err(CredentialError::InvalidPassportLifecycle(format!(
                    "active passport lifecycle entry `{passport_id}` cannot include supersession or revocation fields"
                )));
            }
        }
        PassportLifecycleState::Stale => {
            if !has_published_at {
                return Err(CredentialError::InvalidPassportLifecycle(format!(
                    "stale passport lifecycle entry `{passport_id}` must include published_at"
                )));
            }
            if superseded_by.is_some() || revoked_at.is_some() || revoked_reason.is_some() {
                return Err(CredentialError::InvalidPassportLifecycle(format!(
                    "stale passport lifecycle entry `{passport_id}` cannot include supersession or revocation fields"
                )));
            }
        }
        PassportLifecycleState::Superseded => {
            if !has_published_at {
                return Err(CredentialError::InvalidPassportLifecycle(format!(
                    "superseded passport lifecycle entry `{passport_id}` must include published_at"
                )));
            }
            if superseded_by.is_none() {
                return Err(CredentialError::InvalidPassportLifecycle(format!(
                    "superseded passport lifecycle entry `{passport_id}` must include superseded_by"
                )));
            }
            if revoked_at.is_some() || revoked_reason.is_some() {
                return Err(CredentialError::InvalidPassportLifecycle(format!(
                    "superseded passport lifecycle entry `{passport_id}` cannot include revocation fields"
                )));
            }
        }
        PassportLifecycleState::Revoked => {
            if !has_published_at {
                return Err(CredentialError::InvalidPassportLifecycle(format!(
                    "revoked passport lifecycle entry `{passport_id}` must include published_at"
                )));
            }
            if revoked_at.is_none() {
                return Err(CredentialError::InvalidPassportLifecycle(format!(
                    "revoked passport lifecycle entry `{passport_id}` must include revoked_at"
                )));
            }
        }
        PassportLifecycleState::NotFound => {
            if has_published_at || superseded_by.is_some() || revoked_at.is_some() || revoked_reason.is_some()
            {
                return Err(CredentialError::InvalidPassportLifecycle(format!(
                    "not-found passport lifecycle entry `{passport_id}` cannot include published, supersession, or revocation fields"
                )));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassportVerification {
    pub passport_id: String,
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuers: Vec<String>,
    pub issuer_count: usize,
    pub credential_count: usize,
    pub merkle_root_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enterprise_identity_provenance: Vec<EnterpriseIdentityProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport_lifecycle: Option<PassportLifecycleResolution>,
    pub verified_at: u64,
    pub valid_until: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassportVerifierPolicy {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub issuer_allowlist: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_composite_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_reliability: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_least_privilege: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_delegation_hygiene: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_boundary_pressure: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_receipt_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_lineage_records: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_history_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_attestation_age_days: Option<u32>,
    #[serde(default)]
    pub require_checkpoint_coverage: bool,
    #[serde(default)]
    pub require_receipt_log_urls: bool,
    #[serde(default)]
    pub require_enterprise_identity_provenance: bool,
    #[serde(default)]
    pub require_active_lifecycle: bool,
}

impl PassportVerifierPolicy {
    pub fn validate(&self) -> Result<(), CredentialError> {
        validate_unit_interval("min_composite_score", self.min_composite_score)?;
        validate_unit_interval("min_reliability", self.min_reliability)?;
        validate_unit_interval("min_least_privilege", self.min_least_privilege)?;
        validate_unit_interval("min_delegation_hygiene", self.min_delegation_hygiene)?;
        validate_unit_interval("max_boundary_pressure", self.max_boundary_pressure)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedPassportVerifierPolicyBody {
    pub schema: String,
    pub policy_id: String,
    pub verifier: String,
    pub signer_public_key: PublicKey,
    pub created_at: u64,
    pub expires_at: u64,
    pub policy: PassportVerifierPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedPassportVerifierPolicy {
    pub body: SignedPassportVerifierPolicyBody,
    pub signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassportVerifierPolicyReference {
    pub policy_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialPolicyEvaluation {
    pub index: usize,
    pub issuer: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    pub issuance_date: String,
    pub expiration_date: String,
    pub attestation_until: u64,
    pub receipt_count: usize,
    pub lineage_records: usize,
    pub uncheckpointed_receipts: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliability: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub least_privilege: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_hygiene: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary_pressure: Option<f64>,
    #[serde(default)]
    pub enterprise_identity_present: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enterprise_provider_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassportPolicyEvaluation {
    pub verification: PassportVerification,
    pub accepted: bool,
    pub matched_credential_indexes: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_issuers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passport_reasons: Vec<String>,
    pub policy: PassportVerifierPolicy,
    pub credential_results: Vec<CredentialPolicyEvaluation>,
}
