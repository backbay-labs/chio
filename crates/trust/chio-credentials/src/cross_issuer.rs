#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum CrossIssuerPortfolioEntryKind {
    Native,
    Imported,
    Migrated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CrossIssuerPortfolioEntry {
    pub entry_id: String,
    pub profile_family: String,
    pub source_kind: CrossIssuerPortfolioEntryKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub passport: AgentPassport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<PassportLifecycleResolution>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certification_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CrossIssuerPortfolio {
    pub schema: String,
    pub portfolio_id: String,
    pub subject: String,
    pub entries: Vec<CrossIssuerPortfolioEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub migrations: Vec<SignedCrossIssuerMigration>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedCrossIssuerMigrationBody {
    pub schema: String,
    pub migration_id: String,
    pub attester: String,
    pub signer_public_key: PublicKey,
    pub from_issuer: String,
    pub to_issuer: String,
    pub from_subject: String,
    pub to_subject: String,
    pub prior_passport_ids: Vec<String>,
    pub reason: String,
    pub continuity_ref: String,
    pub issued_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedCrossIssuerMigration {
    pub body: SignedCrossIssuerMigrationBody,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSignedCrossIssuerMigrationArgs {
    pub migration_id: String,
    pub attester: String,
    pub from_issuer: String,
    pub to_issuer: String,
    pub from_subject: String,
    pub to_subject: String,
    pub prior_passport_ids: Vec<String>,
    pub reason: String,
    pub continuity_ref: String,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CrossIssuerTrustPackPolicy {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub allowed_issuers: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub allowed_profile_families: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub allowed_entry_kinds: BTreeSet<CrossIssuerPortfolioEntryKind>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub allowed_migration_ids: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub allowed_certification_refs: BTreeSet<String>,
    #[serde(default)]
    pub require_active_lifecycle: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedCrossIssuerTrustPackBody {
    pub schema: String,
    pub pack_id: String,
    pub verifier: String,
    pub signer_public_key: PublicKey,
    pub created_at: u64,
    pub expires_at: u64,
    pub policy: CrossIssuerTrustPackPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedCrossIssuerTrustPack {
    pub body: SignedCrossIssuerTrustPackBody,
    pub signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CrossIssuerPortfolioEntryVerification {
    pub entry_id: String,
    pub passport_id: String,
    pub subject: String,
    pub issuers: Vec<String>,
    pub issuer_count: usize,
    pub profile_family: String,
    pub source_kind: CrossIssuerPortfolioEntryKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<PassportLifecycleState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CrossIssuerPortfolioVerification {
    pub schema: String,
    pub portfolio_id: String,
    pub subject: String,
    pub entry_count: usize,
    pub issuer_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuers: Vec<String>,
    pub migration_count: usize,
    pub verified_at: u64,
    pub entry_results: Vec<CrossIssuerPortfolioEntryVerification>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CrossIssuerPortfolioEntryEvaluation {
    pub entry_id: String,
    pub passport_id: String,
    pub accepted: bool,
    pub subject: String,
    pub profile_family: String,
    pub source_kind: CrossIssuerPortfolioEntryKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<PassportLifecycleState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CrossIssuerPortfolioEvaluation {
    pub schema: String,
    pub portfolio_id: String,
    pub subject: String,
    pub trust_pack_id: String,
    pub verifier: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub activated_entry_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub activated_issuers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub portfolio_reasons: Vec<String>,
    pub evaluated_at: u64,
    pub entry_results: Vec<CrossIssuerPortfolioEntryEvaluation>,
}

pub fn create_signed_cross_issuer_migration(
    signer: &Keypair,
    args: CreateSignedCrossIssuerMigrationArgs,
) -> Result<SignedCrossIssuerMigration, CredentialError> {
    let CreateSignedCrossIssuerMigrationArgs {
        migration_id,
        attester,
        from_issuer,
        to_issuer,
        from_subject,
        to_subject,
        prior_passport_ids,
        reason,
        continuity_ref,
        issued_at,
        expires_at,
    } = args;
    let body = SignedCrossIssuerMigrationBody {
        schema: CROSS_ISSUER_MIGRATION_SCHEMA.to_string(),
        migration_id,
        attester,
        signer_public_key: signer.public_key(),
        from_issuer,
        to_issuer,
        from_subject,
        to_subject,
        prior_passport_ids,
        reason,
        continuity_ref,
        issued_at,
        expires_at,
    };
    verify_signed_cross_issuer_migration_body(&body)?;
    let (signature, _) = signer.sign_canonical(&body)?;
    Ok(SignedCrossIssuerMigration { body, signature })
}

pub fn verify_signed_cross_issuer_migration(
    migration: &SignedCrossIssuerMigration,
    now: u64,
) -> Result<(), CredentialError> {
    verify_signed_cross_issuer_migration_body(&migration.body)?;
    if now < migration.body.issued_at {
        return Err(CredentialError::InvalidCrossIssuerMigration(format!(
            "cross-issuer migration `{}` is not yet valid",
            migration.body.migration_id
        )));
    }
    if let Some(expires_at) = migration.body.expires_at {
        if now > expires_at {
            return Err(CredentialError::InvalidCrossIssuerMigration(format!(
                "cross-issuer migration `{}` has expired",
                migration.body.migration_id
            )));
        }
    }
    let signed = migration.body.signer_public_key.verify(
        &canonical_json_bytes(&migration.body)?,
        &migration.signature,
    );
    if !signed {
        return Err(CredentialError::InvalidCrossIssuerMigration(format!(
            "cross-issuer migration `{}` signature verification failed",
            migration.body.migration_id
        )));
    }
    Ok(())
}

pub fn create_signed_cross_issuer_trust_pack(
    signer: &Keypair,
    pack_id: impl Into<String>,
    verifier: impl Into<String>,
    created_at: u64,
    expires_at: u64,
    policy: CrossIssuerTrustPackPolicy,
) -> Result<SignedCrossIssuerTrustPack, CredentialError> {
    let body = SignedCrossIssuerTrustPackBody {
        schema: CROSS_ISSUER_TRUST_PACK_SCHEMA.to_string(),
        pack_id: pack_id.into(),
        verifier: verifier.into(),
        signer_public_key: signer.public_key(),
        created_at,
        expires_at,
        policy,
    };
    verify_signed_cross_issuer_trust_pack_body(&body)?;
    let (signature, _) = signer.sign_canonical(&body)?;
    Ok(SignedCrossIssuerTrustPack { body, signature })
}

pub fn verify_signed_cross_issuer_trust_pack(
    pack: &SignedCrossIssuerTrustPack,
    now: u64,
) -> Result<(), CredentialError> {
    verify_signed_cross_issuer_trust_pack_body(&pack.body)?;
    if now < pack.body.created_at {
        return Err(CredentialError::InvalidCrossIssuerTrustPack(format!(
            "cross-issuer trust pack `{}` is not yet valid",
            pack.body.pack_id
        )));
    }
    if now > pack.body.expires_at {
        return Err(CredentialError::InvalidCrossIssuerTrustPack(format!(
            "cross-issuer trust pack `{}` has expired",
            pack.body.pack_id
        )));
    }
    let signed = pack
        .body
        .signer_public_key
        .verify(&canonical_json_bytes(&pack.body)?, &pack.signature);
    if !signed {
        return Err(CredentialError::InvalidCrossIssuerTrustPack(format!(
            "cross-issuer trust pack `{}` signature verification failed",
            pack.body.pack_id
        )));
    }
    Ok(())
}

pub fn verify_cross_issuer_portfolio(
    portfolio: &CrossIssuerPortfolio,
    now: u64,
) -> Result<CrossIssuerPortfolioVerification, CredentialError> {
    if portfolio.schema != CROSS_ISSUER_PORTFOLIO_SCHEMA {
        return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
            "cross-issuer portfolio schema must be {CROSS_ISSUER_PORTFOLIO_SCHEMA}"
        )));
    }
    if portfolio.portfolio_id.trim().is_empty() {
        return Err(CredentialError::InvalidCrossIssuerPortfolio(
            "cross-issuer portfolios must include a non-empty portfolio_id".to_string(),
        ));
    }
    DidChio::from_str(&portfolio.subject)?;
    if portfolio.entries.is_empty() {
        return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
            "cross-issuer portfolio `{}` must include at least one entry",
            portfolio.portfolio_id
        )));
    }

    let migration_map = portfolio
        .migrations
        .iter()
        .map(|migration| {
            verify_signed_cross_issuer_migration(migration, now)?;
            Ok((
                migration.body.migration_id.clone(),
                migration.body.clone(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, CredentialError>>()?;
    if migration_map.len() != portfolio.migrations.len() {
        return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
            "cross-issuer portfolio `{}` contains duplicate migration ids",
            portfolio.portfolio_id
        )));
    }

    let mut seen_entry_ids = BTreeSet::new();
    let mut seen_passport_ids = BTreeSet::new();
    let mut issuers = BTreeSet::new();
    let mut entry_results = Vec::with_capacity(portfolio.entries.len());
    for entry in &portfolio.entries {
        validate_cross_issuer_portfolio_entry(entry)?;
        if !seen_entry_ids.insert(entry.entry_id.clone()) {
            return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                "cross-issuer portfolio `{}` contains duplicate entry_id `{}`",
                portfolio.portfolio_id, entry.entry_id
            )));
        }
        let verification = verify_agent_passport(&entry.passport, now)?;
        let passport_id = verification.passport_id.clone();
        if !seen_passport_ids.insert(passport_id.clone()) {
            return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                "cross-issuer portfolio `{}` contains duplicate passport `{}`",
                portfolio.portfolio_id, passport_id
            )));
        }
        if let Some(lifecycle) = &entry.lifecycle {
            lifecycle.validate()?;
            if lifecycle.passport_id != passport_id {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "portfolio entry `{}` lifecycle passport_id does not match embedded passport",
                    entry.entry_id
                )));
            }
            if lifecycle.subject != verification.subject {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "portfolio entry `{}` lifecycle subject does not match embedded passport",
                    entry.entry_id
                )));
            }
            if lifecycle.issuers != verification.issuers {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "portfolio entry `{}` lifecycle issuers do not match embedded passport",
                    entry.entry_id
                )));
            }
        }

        if let Some(migration_id) = &entry.migration_id {
            let migration = migration_map.get(migration_id).ok_or_else(|| {
                CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "portfolio entry `{}` references unknown migration `{migration_id}`",
                    entry.entry_id
                ))
            })?;
            if migration.from_subject != verification.subject {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "portfolio entry `{}` migration `{migration_id}` does not match entry subject",
                    entry.entry_id
                )));
            }
            if migration.to_subject != portfolio.subject {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "portfolio entry `{}` migration `{migration_id}` does not target the portfolio subject",
                    entry.entry_id
                )));
            }
            if !verification.issuers.contains(&migration.from_issuer) {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "portfolio entry `{}` migration `{migration_id}` does not match an embedded issuer",
                    entry.entry_id
                )));
            }
            if !migration.prior_passport_ids.contains(&passport_id) {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "portfolio entry `{}` migration `{migration_id}` does not reference the embedded passport",
                    entry.entry_id
                )));
            }
        }

        issuers.extend(verification.issuers.iter().cloned());
        entry_results.push(CrossIssuerPortfolioEntryVerification {
            entry_id: entry.entry_id.clone(),
            passport_id,
            subject: verification.subject,
            issuers: verification.issuers,
            issuer_count: verification.issuer_count,
            profile_family: entry.profile_family.clone(),
            source_kind: entry.source_kind,
            source: entry.source.clone(),
            migration_id: entry.migration_id.clone(),
            lifecycle_state: entry.lifecycle.as_ref().map(|lifecycle| lifecycle.state),
        });
    }

    Ok(CrossIssuerPortfolioVerification {
        schema: CROSS_ISSUER_PORTFOLIO_SCHEMA.to_string(),
        portfolio_id: portfolio.portfolio_id.clone(),
        subject: portfolio.subject.clone(),
        entry_count: entry_results.len(),
        issuer_count: issuers.len(),
        issuers: issuers.into_iter().collect(),
        migration_count: portfolio.migrations.len(),
        verified_at: now,
        entry_results,
    })
}

pub fn evaluate_cross_issuer_portfolio(
    portfolio: &CrossIssuerPortfolio,
    now: u64,
    trust_pack: &SignedCrossIssuerTrustPack,
) -> Result<CrossIssuerPortfolioEvaluation, CredentialError> {
    let verification = verify_cross_issuer_portfolio(portfolio, now)?;
    verify_signed_cross_issuer_trust_pack(trust_pack, now)?;

    let mut activated_entry_ids = Vec::new();
    let mut activated_issuers = BTreeSet::new();
    let entry_results = verification
        .entry_results
        .iter()
        .map(|entry| {
            let mut reasons = Vec::new();
            let policy = &trust_pack.body.policy;

            if !policy.allowed_profile_families.is_empty()
                && !policy.allowed_profile_families.contains(&entry.profile_family)
            {
                reasons.push(format!(
                    "profile family {} is not activated by the trust pack",
                    entry.profile_family
                ));
            }
            if !policy.allowed_entry_kinds.is_empty()
                && !policy.allowed_entry_kinds.contains(&entry.source_kind)
            {
                reasons.push(format!(
                    "entry kind {} is not activated by the trust pack",
                    cross_issuer_entry_kind_label(entry.source_kind)
                ));
            }
            if !policy.allowed_issuers.is_empty() {
                let disallowed_issuers = entry
                    .issuers
                    .iter()
                    .filter(|issuer| !policy.allowed_issuers.contains(*issuer))
                    .cloned()
                    .collect::<Vec<_>>();
                if !disallowed_issuers.is_empty() {
                    reasons.push(format!(
                        "entry issuers are outside the trust pack allowlist: {}",
                        disallowed_issuers.join(", ")
                    ));
                }
            }
            if policy.require_active_lifecycle {
                match entry.lifecycle_state {
                    Some(PassportLifecycleState::Active) => {}
                    Some(state) => reasons.push(format!(
                        "entry lifecycle state {} is not active",
                        state.label()
                    )),
                    None => reasons.push(
                        "entry does not include an active lifecycle record required by the trust pack"
                            .to_string(),
                    ),
                }
            }
            if entry.subject != portfolio.subject {
                match entry.migration_id.as_ref() {
                    Some(migration_id) => {
                        if !policy.allowed_migration_ids.is_empty()
                            && !policy.allowed_migration_ids.contains(migration_id)
                        {
                            reasons.push(format!(
                                "migration {} is not activated by the trust pack",
                                migration_id
                            ));
                        }
                    }
                    None => reasons.push(
                        "entry subject differs from the portfolio subject without an explicit migration"
                            .to_string(),
                    ),
                }
            }
            if !policy.allowed_certification_refs.is_empty() {
                match portfolio
                    .entries
                    .iter()
                    .find(|candidate| candidate.entry_id == entry.entry_id)
                {
                    Some(portfolio_entry) => {
                        let matched_ref = portfolio_entry
                            .certification_refs
                            .iter()
                            .any(|reference| policy.allowed_certification_refs.contains(reference));
                        if !matched_ref {
                            reasons.push(
                                "entry does not include a certification reference activated by the trust pack"
                                    .to_string(),
                            );
                        }
                    }
                    None => reasons.push(
                        "verified entry is missing from the source portfolio".to_string(),
                    ),
                }
            }

            let accepted = reasons.is_empty();
            if accepted {
                activated_entry_ids.push(entry.entry_id.clone());
                activated_issuers.extend(entry.issuers.iter().cloned());
            }

            CrossIssuerPortfolioEntryEvaluation {
                entry_id: entry.entry_id.clone(),
                passport_id: entry.passport_id.clone(),
                accepted,
                subject: entry.subject.clone(),
                profile_family: entry.profile_family.clone(),
                source_kind: entry.source_kind,
                issuers: entry.issuers.clone(),
                migration_id: entry.migration_id.clone(),
                lifecycle_state: entry.lifecycle_state,
                reasons,
            }
        })
        .collect::<Vec<_>>();
    let accepted = !activated_entry_ids.is_empty();
    let portfolio_reasons = if accepted {
        Vec::new()
    } else {
        vec!["no portfolio entry satisfied the activated trust-pack policy".to_string()]
    };

    Ok(CrossIssuerPortfolioEvaluation {
        schema: CROSS_ISSUER_PORTFOLIO_EVALUATION_SCHEMA.to_string(),
        portfolio_id: portfolio.portfolio_id.clone(),
        subject: portfolio.subject.clone(),
        trust_pack_id: trust_pack.body.pack_id.clone(),
        verifier: trust_pack.body.verifier.clone(),
        accepted,
        activated_entry_ids,
        activated_issuers: activated_issuers.into_iter().collect(),
        portfolio_reasons,
        evaluated_at: now,
        entry_results,
    })
}

fn validate_cross_issuer_portfolio_entry(
    entry: &CrossIssuerPortfolioEntry,
) -> Result<(), CredentialError> {
    if entry.entry_id.trim().is_empty() {
        return Err(CredentialError::InvalidCrossIssuerPortfolio(
            "cross-issuer portfolio entries must include a non-empty entry_id".to_string(),
        ));
    }
    if entry.profile_family.trim().is_empty() {
        return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
            "portfolio entry `{}` must include a non-empty profile_family",
            entry.entry_id
        )));
    }
    if let Some(source) = &entry.source {
        if source.trim().is_empty() {
            return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                "portfolio entry `{}` cannot include an empty source",
                entry.entry_id
            )));
        }
    }
    if let Some(migration_id) = &entry.migration_id {
        if migration_id.trim().is_empty() {
            return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                "portfolio entry `{}` cannot include an empty migration_id",
                entry.entry_id
            )));
        }
    }
    match entry.source_kind {
        CrossIssuerPortfolioEntryKind::Native => {
            if entry.migration_id.is_some() {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "native portfolio entry `{}` cannot include a migration_id",
                    entry.entry_id
                )));
            }
        }
        CrossIssuerPortfolioEntryKind::Imported => {
            if entry.source.is_none() {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "imported portfolio entry `{}` must include a source",
                    entry.entry_id
                )));
            }
            if entry.migration_id.is_some() {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "imported portfolio entry `{}` cannot include a migration_id unless it is marked migrated",
                    entry.entry_id
                )));
            }
        }
        CrossIssuerPortfolioEntryKind::Migrated => {
            if entry.source.is_none() {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "migrated portfolio entry `{}` must include a source",
                    entry.entry_id
                )));
            }
            if entry.migration_id.is_none() {
                return Err(CredentialError::InvalidCrossIssuerPortfolio(format!(
                    "migrated portfolio entry `{}` must include a migration_id",
                    entry.entry_id
                )));
            }
        }
    }
    if let Some(lifecycle) = &entry.lifecycle {
        lifecycle.validate()?;
    }
    validate_sorted_unique_strings(
        &entry.certification_refs,
        "certification_refs",
        &entry.entry_id,
        CredentialError::InvalidCrossIssuerPortfolio,
    )
}

fn verify_signed_cross_issuer_migration_body(
    body: &SignedCrossIssuerMigrationBody,
) -> Result<(), CredentialError> {
    if body.schema != CROSS_ISSUER_MIGRATION_SCHEMA {
        return Err(CredentialError::InvalidCrossIssuerMigration(format!(
            "cross-issuer migration schema must be {CROSS_ISSUER_MIGRATION_SCHEMA}"
        )));
    }
    if body.migration_id.trim().is_empty() {
        return Err(CredentialError::InvalidCrossIssuerMigration(
            "cross-issuer migrations must include a non-empty migration_id".to_string(),
        ));
    }
    if body.attester.trim().is_empty() {
        return Err(CredentialError::InvalidCrossIssuerMigration(format!(
            "cross-issuer migration `{}` must include a non-empty attester",
            body.migration_id
        )));
    }
    DidChio::from_str(&body.from_issuer)?;
    DidChio::from_str(&body.to_issuer)?;
    DidChio::from_str(&body.from_subject)?;
    DidChio::from_str(&body.to_subject)?;
    if body.reason.trim().is_empty() {
        return Err(CredentialError::InvalidCrossIssuerMigration(format!(
            "cross-issuer migration `{}` must include a non-empty reason",
            body.migration_id
        )));
    }
    if body.continuity_ref.trim().is_empty() {
        return Err(CredentialError::InvalidCrossIssuerMigration(format!(
            "cross-issuer migration `{}` must include a non-empty continuity_ref",
            body.migration_id
        )));
    }
    if body.prior_passport_ids.is_empty() {
        return Err(CredentialError::InvalidCrossIssuerMigration(format!(
            "cross-issuer migration `{}` must reference at least one prior passport",
            body.migration_id
        )));
    }
    validate_sorted_unique_strings(
        &body.prior_passport_ids,
        "prior_passport_ids",
        &body.migration_id,
        CredentialError::InvalidCrossIssuerMigration,
    )?;
    if let Some(expires_at) = body.expires_at {
        if body.issued_at > expires_at {
            return Err(CredentialError::InvalidCrossIssuerMigration(format!(
                "cross-issuer migration `{}` must not expire before it is issued",
                body.migration_id
            )));
        }
    }
    Ok(())
}

fn verify_signed_cross_issuer_trust_pack_body(
    body: &SignedCrossIssuerTrustPackBody,
) -> Result<(), CredentialError> {
    if body.schema != CROSS_ISSUER_TRUST_PACK_SCHEMA {
        return Err(CredentialError::InvalidCrossIssuerTrustPack(format!(
            "cross-issuer trust-pack schema must be {CROSS_ISSUER_TRUST_PACK_SCHEMA}"
        )));
    }
    if body.pack_id.trim().is_empty() {
        return Err(CredentialError::InvalidCrossIssuerTrustPack(
            "cross-issuer trust packs must include a non-empty pack_id".to_string(),
        ));
    }
    if body.verifier.trim().is_empty() {
        return Err(CredentialError::InvalidCrossIssuerTrustPack(format!(
            "cross-issuer trust pack `{}` must include a non-empty verifier",
            body.pack_id
        )));
    }
    if body.created_at > body.expires_at {
        return Err(CredentialError::InvalidCrossIssuerTrustPack(format!(
            "cross-issuer trust pack `{}` must not expire before it is created",
            body.pack_id
        )));
    }
    body.policy.validate(&body.pack_id)
}

impl CrossIssuerTrustPackPolicy {
    pub fn validate(&self, pack_id: &str) -> Result<(), CredentialError> {
        validate_non_empty_string_set(
            &self.allowed_issuers,
            "allowed_issuers",
            pack_id,
            CredentialError::InvalidCrossIssuerTrustPack,
        )?;
        validate_non_empty_string_set(
            &self.allowed_profile_families,
            "allowed_profile_families",
            pack_id,
            CredentialError::InvalidCrossIssuerTrustPack,
        )?;
        validate_non_empty_string_set(
            &self.allowed_migration_ids,
            "allowed_migration_ids",
            pack_id,
            CredentialError::InvalidCrossIssuerTrustPack,
        )?;
        validate_non_empty_string_set(
            &self.allowed_certification_refs,
            "allowed_certification_refs",
            pack_id,
            CredentialError::InvalidCrossIssuerTrustPack,
        )
    }
}

fn cross_issuer_entry_kind_label(kind: CrossIssuerPortfolioEntryKind) -> &'static str {
    match kind {
        CrossIssuerPortfolioEntryKind::Native => "native",
        CrossIssuerPortfolioEntryKind::Imported => "imported",
        CrossIssuerPortfolioEntryKind::Migrated => "migrated",
    }
}

fn validate_non_empty_string_set(
    values: &BTreeSet<String>,
    field: &str,
    id: &str,
    error: fn(String) -> CredentialError,
) -> Result<(), CredentialError> {
    for value in values {
        if value.trim().is_empty() {
            return Err(error(format!(
                "`{field}` for `{id}` cannot contain empty values"
            )));
        }
    }
    Ok(())
}

fn validate_sorted_unique_strings(
    values: &[String],
    field: &str,
    id: &str,
    error: fn(String) -> CredentialError,
) -> Result<(), CredentialError> {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted != values {
        return Err(error(format!(
            "`{field}` for `{id}` must be stored in sorted unique order"
        )));
    }
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(error(format!(
            "`{field}` for `{id}` cannot contain empty values"
        )));
    }
    Ok(())
}
