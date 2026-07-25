use super::*;

#[derive(Debug, Clone, PartialEq)]
pub struct FinancialVerifierPolicyInputV1 {
    pub policy_id: String,
    pub tenant: String,
    pub verifier: String,
    pub accepted_issuers: BTreeSet<String>,
    pub accepted_families: BTreeSet<FinancialCredentialFamilyV1>,
    pub thresholds: FinancialVerifierThresholdsV1,
    pub max_credential_age_seconds: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub configuration_generation: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FinancialVerifierPolicyDigestPreimageV1<'a> {
    schema: &'a str,
    policy_id: &'a str,
    tenant: &'a str,
    verifier: &'a str,
    accepted_issuers: &'a BTreeSet<String>,
    accepted_families: &'a BTreeSet<FinancialCredentialFamilyV1>,
    thresholds: &'a FinancialVerifierThresholdsV1,
    max_credential_age_seconds: u64,
    not_before: u64,
    expires_at: u64,
    configuration_generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialVerifierPolicyActivationV1 {
    pub tenant: String,
    pub verifier: String,
    pub policy_id: String,
    pub configuration_generation: u64,
    pub body_digest: String,
}

#[derive(Debug, Clone)]
pub struct VerifiedFinancialVerifierPolicy {
    policy: FinancialVerifierPolicyV1,
}

impl VerifiedFinancialVerifierPolicy {
    #[must_use]
    pub fn policy(&self) -> &FinancialVerifierPolicyV1 {
        &self.policy
    }

    #[must_use]
    pub fn policy_id(&self) -> &str {
        &self.policy.policy_id
    }

    #[must_use]
    pub fn body_digest(&self) -> &str {
        &self.policy.body_digest
    }

    #[must_use]
    pub const fn configuration_generation(&self) -> u64 {
        self.policy.configuration_generation
    }
}

#[derive(Debug, Clone, Default)]
pub struct FinancialVerifierPolicyRegistry {
    policies: BTreeMap<(String, String, u64), FinancialVerifierPolicyV1>,
    active: BTreeMap<(String, String), FinancialVerifierPolicyActivationV1>,
}

impl FinancialVerifierPolicyRegistry {
    pub fn new(
        policies: Vec<FinancialVerifierPolicyV1>,
        active: Vec<FinancialVerifierPolicyActivationV1>,
    ) -> Result<Self, CredentialError> {
        let mut policy_map = BTreeMap::new();
        for policy in policies {
            validate_financial_verifier_policy(&policy)?;
            let key = (
                policy.tenant.clone(),
                policy.policy_id.clone(),
                policy.configuration_generation,
            );
            if policy_map.insert(key, policy).is_some() {
                return Err(authority_error("duplicate financial verifier policy body"));
            }
        }
        let mut active_map = BTreeMap::new();
        for activation in active {
            validate_text("policyActivation.tenant", &activation.tenant)?;
            validate_text("policyActivation.verifier", &activation.verifier)?;
            validate_text("policyActivation.policyId", &activation.policy_id)?;
            validate_time(
                "policyActivation.configurationGeneration",
                activation.configuration_generation,
            )?;
            validate_digest("policyActivation.bodyDigest", &activation.body_digest)?;
            let policy_key = (
                activation.tenant.clone(),
                activation.policy_id.clone(),
                activation.configuration_generation,
            );
            let policy = policy_map
                .get(&policy_key)
                .ok_or_else(|| authority_error("active financial policy body is missing"))?;
            if policy.verifier != activation.verifier
                || policy.body_digest != activation.body_digest
            {
                return Err(authority_error(
                    "active financial policy pointer does not match its pinned body",
                ));
            }
            let scope = (activation.tenant.clone(), activation.verifier.clone());
            if active_map.insert(scope, activation).is_some() {
                return Err(authority_error(
                    "financial verifier policy scope has ambiguous active config",
                ));
            }
        }
        Ok(Self {
            policies: policy_map,
            active: active_map,
        })
    }

    pub fn resolve(
        &self,
        tenant: &str,
        verifier: &str,
        now: u64,
    ) -> Result<VerifiedFinancialVerifierPolicy, CredentialError> {
        let activation = self
            .active
            .get(&(tenant.to_string(), verifier.to_string()))
            .ok_or_else(|| authority_error("active financial verifier policy is unavailable"))?;
        let policy = self
            .policies
            .get(&(
                tenant.to_string(),
                activation.policy_id.clone(),
                activation.configuration_generation,
            ))
            .ok_or_else(|| authority_error("active financial verifier policy body is missing"))?;
        validate_financial_verifier_policy(policy)?;
        if policy.body_digest != activation.body_digest
            || policy.tenant != tenant
            || policy.verifier != verifier
        {
            return Err(authority_error(
                "resolved financial verifier policy does not match its active pointer",
            ));
        }
        if now < policy.not_before {
            return Err(authority_error(
                "financial verifier policy is not yet valid",
            ));
        }
        if now >= policy.expires_at {
            return Err(authority_error("financial verifier policy has expired"));
        }
        Ok(VerifiedFinancialVerifierPolicy {
            policy: policy.clone(),
        })
    }
}

pub fn create_financial_verifier_policy_v1(
    input: FinancialVerifierPolicyInputV1,
) -> Result<FinancialVerifierPolicyV1, CredentialError> {
    let mut policy = FinancialVerifierPolicyV1 {
        schema: FINANCIAL_VERIFIER_POLICY_SCHEMA_V1.to_string(),
        policy_id: input.policy_id,
        tenant: input.tenant,
        verifier: input.verifier,
        accepted_issuers: input.accepted_issuers,
        accepted_families: input.accepted_families,
        thresholds: input.thresholds,
        max_credential_age_seconds: input.max_credential_age_seconds,
        not_before: input.not_before,
        expires_at: input.expires_at,
        configuration_generation: input.configuration_generation,
        body_digest: String::new(),
    };
    policy.body_digest = recompute_financial_verifier_policy_digest(&policy)?;
    validate_financial_verifier_policy(&policy)?;
    Ok(policy)
}

fn validate_financial_verifier_policy(
    policy: &FinancialVerifierPolicyV1,
) -> Result<(), CredentialError> {
    if policy.schema != FINANCIAL_VERIFIER_POLICY_SCHEMA_V1 {
        return Err(authority_error(
            "financial verifier policy schema is invalid",
        ));
    }
    validate_text("financialPolicy.policyId", &policy.policy_id)?;
    validate_text("financialPolicy.tenant", &policy.tenant)?;
    validate_text("financialPolicy.verifier", &policy.verifier)?;
    if policy.accepted_issuers.is_empty() || policy.accepted_families.is_empty() {
        return Err(authority_error(
            "financial verifier policy trust and family sets must be nonempty",
        ));
    }
    for issuer in &policy.accepted_issuers {
        DidChio::from_str(issuer)?;
    }
    if policy.max_credential_age_seconds == 0
        || policy.configuration_generation == 0
        || policy.not_before >= policy.expires_at
    {
        return Err(authority_error(
            "financial verifier policy validity or generation is invalid",
        ));
    }
    if policy
        .thresholds
        .min_credit_score
        .is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
        || policy
            .thresholds
            .max_open_exposure_ratio_bps
            .is_some_and(|value| value > 10_000)
        || policy
            .thresholds
            .min_settlement_reliability_bps
            .is_some_and(|value| value > 10_000)
    {
        return Err(authority_error(
            "financial verifier policy threshold is invalid",
        ));
    }
    for currency in policy.thresholds.max_premium_units_by_currency.keys() {
        validate_text("financialPolicy.premiumCurrency", currency)?;
    }
    validate_digest("financialPolicy.bodyDigest", &policy.body_digest)?;
    if recompute_financial_verifier_policy_digest(policy)? != policy.body_digest {
        return Err(authority_error(
            "financial verifier policy body digest does not match",
        ));
    }
    Ok(())
}

fn recompute_financial_verifier_policy_digest(
    policy: &FinancialVerifierPolicyV1,
) -> Result<String, CredentialError> {
    authority_digest(
        FINANCIAL_POLICY_DIGEST_DOMAIN,
        &FinancialVerifierPolicyDigestPreimageV1 {
            schema: &policy.schema,
            policy_id: &policy.policy_id,
            tenant: &policy.tenant,
            verifier: &policy.verifier,
            accepted_issuers: &policy.accepted_issuers,
            accepted_families: &policy.accepted_families,
            thresholds: &policy.thresholds,
            max_credential_age_seconds: policy.max_credential_age_seconds,
            not_before: policy.not_before,
            expires_at: policy.expires_at,
            configuration_generation: policy.configuration_generation,
        },
    )
}
