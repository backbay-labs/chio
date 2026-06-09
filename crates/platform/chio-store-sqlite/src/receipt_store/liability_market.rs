use super::*;

impl SqliteReceiptStore {
    pub fn record_liability_provider(
        &mut self,
        provider: &SignedLiabilityProvider,
    ) -> Result<(), ReceiptStoreError> {
        if !provider
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability provider signature verification failed".to_string(),
            ));
        }
        provider
            .body
            .report
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &provider.body;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT provider_record_id FROM liability_providers WHERE provider_record_id = ?1",
                params![artifact.provider_record_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability provider `{}` already exists",
                artifact.provider_record_id
            )));
        }

        if let Some(supersedes_provider_record_id) =
            artifact.supersedes_provider_record_id.as_deref()
        {
            let state = tx
                .query_row(
                    "SELECT raw_json, lifecycle_state, superseded_by_provider_record_id
                     FROM liability_providers
                     WHERE provider_record_id = ?1",
                    params![supersedes_provider_record_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<String>>(2)?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    ReceiptStoreError::NotFound(format!(
                        "superseded liability provider `{supersedes_provider_record_id}` not found"
                    ))
                })?;
            let persisted: SignedLiabilityProvider = serde_json::from_str(&state.0)?;
            if persisted.body.report.provider_id != artifact.report.provider_id {
                return Err(ReceiptStoreError::Conflict(format!(
                    "liability provider `{}` cannot supersede `{}` because provider_id differs",
                    artifact.provider_record_id, supersedes_provider_record_id
                )));
            }
            if state.1
                != liability_provider_lifecycle_state_label(LiabilityProviderLifecycleState::Active)
                || state.2.is_some()
            {
                return Err(ReceiptStoreError::Conflict(format!(
                    "liability provider `{supersedes_provider_record_id}` is not active"
                )));
            }
        }

        tx.execute(
            "INSERT INTO liability_providers (
                provider_record_id, issued_at, provider_id, lifecycle_state,
                supersedes_provider_record_id, superseded_by_provider_record_id, raw_json,
                signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8)",
            params![
                artifact.provider_record_id,
                artifact.issued_at as i64,
                artifact.report.provider_id,
                liability_provider_lifecycle_state_label(artifact.lifecycle_state),
                artifact.supersedes_provider_record_id.as_deref(),
                serde_json::to_string(provider)?,
                provider.signer_key.to_hex(),
                provider.signature.to_hex(),
            ],
        )?;

        if let Some(supersedes_provider_record_id) =
            artifact.supersedes_provider_record_id.as_deref()
        {
            tx.execute(
                "UPDATE liability_providers
                 SET lifecycle_state = ?1, superseded_by_provider_record_id = ?2
                 WHERE provider_record_id = ?3",
                params![
                    liability_provider_lifecycle_state_label(
                        LiabilityProviderLifecycleState::Superseded,
                    ),
                    artifact.provider_record_id,
                    supersedes_provider_record_id,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn query_liability_providers(
        &self,
        query: &LiabilityProviderListQuery,
    ) -> Result<LiabilityProviderListReport, ReceiptStoreError> {
        let normalized = query.normalized();
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT raw_json, lifecycle_state, superseded_by_provider_record_id
             FROM liability_providers
             ORDER BY issued_at DESC, provider_record_id DESC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;

        let mut matching_providers = 0_u64;
        let mut active_providers = 0_u64;
        let mut suspended_providers = 0_u64;
        let mut superseded_providers = 0_u64;
        let mut retired_providers = 0_u64;
        let mut providers = Vec::new();

        for row in rows {
            let (raw_json, lifecycle_state_raw, superseded_by_provider_record_id) = row?;
            let provider: SignedLiabilityProvider = serde_json::from_str(&raw_json)?;
            let lifecycle_state =
                parse_liability_provider_lifecycle_state(&lifecycle_state_raw).map_err(|error| {
                    ReceiptStoreError::Conflict(format!(
                        "invalid liability provider lifecycle state `{lifecycle_state_raw}`: {error}"
                    ))
                })?;
            if !liability_provider_matches_query(&provider, lifecycle_state, &normalized) {
                continue;
            }

            matching_providers += 1;
            match lifecycle_state {
                LiabilityProviderLifecycleState::Active => active_providers += 1,
                LiabilityProviderLifecycleState::Suspended => suspended_providers += 1,
                LiabilityProviderLifecycleState::Superseded => superseded_providers += 1,
                LiabilityProviderLifecycleState::Retired => retired_providers += 1,
            }

            if providers.len() < normalized.limit_or_default() {
                providers.push(LiabilityProviderRow {
                    provider,
                    lifecycle_state,
                    superseded_by_provider_record_id,
                });
            }
        }

        Ok(LiabilityProviderListReport {
            schema: LIABILITY_PROVIDER_LIST_REPORT_SCHEMA.to_string(),
            generated_at: unix_now(),
            query: normalized,
            summary: LiabilityProviderListSummary {
                matching_providers,
                returned_providers: providers.len() as u64,
                active_providers,
                suspended_providers,
                superseded_providers,
                retired_providers,
            },
            providers,
        })
    }

    pub fn resolve_liability_provider(
        &self,
        query: &LiabilityProviderResolutionQuery,
    ) -> Result<LiabilityProviderResolutionReport, ReceiptStoreError> {
        query.validate().map_err(ReceiptStoreError::Conflict)?;
        let normalized = query.normalized();
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT raw_json, lifecycle_state
             FROM liability_providers
             WHERE provider_id = ?1
             ORDER BY issued_at DESC, provider_record_id DESC",
        )?;
        let rows = statement.query_map(params![normalized.provider_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut active_provider = None;
        let mut saw_provider = false;
        for row in rows {
            let (raw_json, lifecycle_state_raw) = row?;
            saw_provider = true;
            let provider: SignedLiabilityProvider = serde_json::from_str(&raw_json)?;
            let lifecycle_state =
                parse_liability_provider_lifecycle_state(&lifecycle_state_raw).map_err(|error| {
                    ReceiptStoreError::Conflict(format!(
                        "invalid liability provider lifecycle state `{lifecycle_state_raw}`: {error}"
                    ))
                })?;
            if lifecycle_state == LiabilityProviderLifecycleState::Active {
                active_provider = Some(provider);
                break;
            }
        }

        let provider = active_provider.ok_or_else(|| {
            if saw_provider {
                ReceiptStoreError::Conflict(format!(
                    "liability provider `{}` has no active registry entry",
                    normalized.provider_id
                ))
            } else {
                ReceiptStoreError::NotFound(format!(
                    "liability provider `{}` not found",
                    normalized.provider_id
                ))
            }
        })?;

        let matched_policy = provider
            .body
            .report
            .policies
            .iter()
            .find(|policy| liability_provider_policy_matches_resolution(policy, &normalized))
            .cloned()
            .ok_or_else(|| {
                ReceiptStoreError::Conflict(format!(
                    "liability provider `{}` does not support jurisdiction `{}`, coverage `{}` in currency `{}`",
                    normalized.provider_id,
                    normalized.jurisdiction,
                    serde_json::to_string(&normalized.coverage_class)
                        .unwrap_or_else(|_| "\"unknown\"".to_string()),
                    normalized.currency,
                ))
            })?;

        Ok(LiabilityProviderResolutionReport {
            schema: LIABILITY_PROVIDER_RESOLUTION_REPORT_SCHEMA.to_string(),
            generated_at: unix_now(),
            query: normalized,
            provider: provider.clone(),
            matched_policy,
            support_boundary: provider.body.report.support_boundary.clone(),
        })
    }

    pub fn record_liability_quote_request(
        &mut self,
        request: &SignedLiabilityQuoteRequest,
    ) -> Result<(), ReceiptStoreError> {
        if !request
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability quote request signature verification failed".to_string(),
            ));
        }
        request
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &request.body;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT quote_request_id FROM liability_quote_requests WHERE quote_request_id = ?1",
                params![artifact.quote_request_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability quote request `{}` already exists",
                artifact.quote_request_id
            )));
        }

        let (provider_raw_json, lifecycle_state_raw) = tx
            .query_row(
                "SELECT raw_json, lifecycle_state
                 FROM liability_providers
                 WHERE provider_record_id = ?1",
                params![artifact.provider_policy.provider_record_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability provider `{}` not found",
                    artifact.provider_policy.provider_record_id
                ))
            })?;
        let provider: SignedLiabilityProvider = serde_json::from_str(&provider_raw_json)?;
        let lifecycle_state = parse_liability_provider_lifecycle_state(&lifecycle_state_raw)?;
        if lifecycle_state != LiabilityProviderLifecycleState::Active {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability provider `{}` is not active",
                artifact.provider_policy.provider_record_id
            )));
        }
        if provider.body.report.provider_id != artifact.provider_policy.provider_id {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability quote request provider `{}` does not match active provider `{}`",
                artifact.provider_policy.provider_id, provider.body.report.provider_id
            )));
        }
        let policy_supported = provider.body.report.policies.iter().any(|policy| {
            policy
                .jurisdiction
                .eq_ignore_ascii_case(&artifact.provider_policy.jurisdiction)
                && policy
                    .coverage_classes
                    .contains(&artifact.provider_policy.coverage_class)
                && policy.supported_currencies.iter().any(|currency| {
                    currency.eq_ignore_ascii_case(&artifact.provider_policy.currency)
                })
        });
        if !policy_supported {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability provider `{}` does not support jurisdiction `{}`, coverage, and currency requested by quote request",
                artifact.provider_policy.provider_id, artifact.provider_policy.jurisdiction
            )));
        }

        tx.execute(
            "INSERT INTO liability_quote_requests (
                quote_request_id, issued_at, provider_id, jurisdiction, coverage_class,
                currency, subject_key, raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                artifact.quote_request_id,
                artifact.issued_at as i64,
                artifact.provider_policy.provider_id,
                artifact.provider_policy.jurisdiction,
                serde_json::to_string(&artifact.provider_policy.coverage_class)?,
                artifact.provider_policy.currency,
                artifact.risk_package.body.subject_key,
                serde_json::to_string(request)?,
                request.signer_key.to_hex(),
                request.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn record_liability_quote_response(
        &mut self,
        response: &SignedLiabilityQuoteResponse,
    ) -> Result<(), ReceiptStoreError> {
        if !response
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability quote response signature verification failed".to_string(),
            ));
        }
        response
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &response.body;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT quote_response_id FROM liability_quote_responses WHERE quote_response_id = ?1",
                params![artifact.quote_response_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability quote response `{}` already exists",
                artifact.quote_response_id
            )));
        }

        let stored_request_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_quote_requests
                 WHERE quote_request_id = ?1",
                params![artifact.quote_request.body.quote_request_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability quote request `{}` not found",
                    artifact.quote_request.body.quote_request_id
                ))
            })?;
        let stored_request: SignedLiabilityQuoteRequest =
            serde_json::from_str(&stored_request_raw_json)?;
        if stored_request.body != artifact.quote_request.body {
            return Err(ReceiptStoreError::Conflict(
                "liability quote response quote_request does not match the persisted request"
                    .to_string(),
            ));
        }

        if let Some(supersedes_quote_response_id) = artifact.supersedes_quote_response_id.as_deref()
        {
            let state = tx
                .query_row(
                    "SELECT raw_json, superseded_by_quote_response_id
                     FROM liability_quote_responses
                     WHERE quote_response_id = ?1",
                    params![supersedes_quote_response_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .optional()?
                .ok_or_else(|| {
                    ReceiptStoreError::NotFound(format!(
                        "superseded liability quote response `{supersedes_quote_response_id}` not found"
                    ))
                })?;
            let prior: SignedLiabilityQuoteResponse = serde_json::from_str(&state.0)?;
            if prior.body.quote_request.body.quote_request_id
                != artifact.quote_request.body.quote_request_id
            {
                return Err(ReceiptStoreError::Conflict(format!(
                    "liability quote response `{}` cannot supersede `{}` because quote_request_id differs",
                    artifact.quote_response_id, supersedes_quote_response_id
                )));
            }
            if state.1.is_some() {
                return Err(ReceiptStoreError::Conflict(format!(
                    "liability quote response `{supersedes_quote_response_id}` is already superseded"
                )));
            }
        } else {
            let active_response = tx
                .query_row(
                    "SELECT quote_response_id
                     FROM liability_quote_responses
                     WHERE quote_request_id = ?1 AND superseded_by_quote_response_id IS NULL",
                    params![artifact.quote_request.body.quote_request_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if let Some(active_response) = active_response {
                return Err(ReceiptStoreError::Conflict(format!(
                    "liability quote request `{}` already has active response `{active_response}`",
                    artifact.quote_request.body.quote_request_id
                )));
            }
        }

        let expires_at = artifact
            .quoted_terms
            .as_ref()
            .map(|terms| terms.expires_at as i64);
        tx.execute(
            "INSERT INTO liability_quote_responses (
                quote_response_id, issued_at, quote_request_id, provider_id, disposition,
                expires_at, supersedes_quote_response_id, superseded_by_quote_response_id,
                raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, ?9, ?10)",
            params![
                artifact.quote_response_id,
                artifact.issued_at as i64,
                artifact.quote_request.body.quote_request_id,
                artifact.quote_request.body.provider_policy.provider_id,
                liability_quote_disposition_label(&artifact.disposition),
                expires_at,
                artifact.supersedes_quote_response_id.as_deref(),
                serde_json::to_string(response)?,
                response.signer_key.to_hex(),
                response.signature.to_hex(),
            ],
        )?;

        if let Some(supersedes_quote_response_id) = artifact.supersedes_quote_response_id.as_deref()
        {
            tx.execute(
                "UPDATE liability_quote_responses
                 SET superseded_by_quote_response_id = ?1
                 WHERE quote_response_id = ?2",
                params![artifact.quote_response_id, supersedes_quote_response_id],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn record_liability_placement(
        &mut self,
        placement: &SignedLiabilityPlacement,
    ) -> Result<(), ReceiptStoreError> {
        if !placement
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability placement signature verification failed".to_string(),
            ));
        }
        placement
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &placement.body;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT placement_id FROM liability_placements WHERE placement_id = ?1",
                params![artifact.placement_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability placement `{}` already exists",
                artifact.placement_id
            )));
        }

        let stored_request_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_quote_requests
                 WHERE quote_request_id = ?1",
                params![
                    artifact
                        .quote_response
                        .body
                        .quote_request
                        .body
                        .quote_request_id
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability quote request `{}` not found",
                    artifact
                        .quote_response
                        .body
                        .quote_request
                        .body
                        .quote_request_id
                ))
            })?;
        let stored_request: SignedLiabilityQuoteRequest =
            serde_json::from_str(&stored_request_raw_json)?;
        if stored_request.body != artifact.quote_response.body.quote_request.body {
            return Err(ReceiptStoreError::Conflict(
                "liability placement quote_request does not match the persisted request"
                    .to_string(),
            ));
        }

        let (stored_response_raw_json, superseded_by_quote_response_id) = tx
            .query_row(
                "SELECT raw_json, superseded_by_quote_response_id
                 FROM liability_quote_responses
                 WHERE quote_response_id = ?1",
                params![artifact.quote_response.body.quote_response_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability quote response `{}` not found",
                    artifact.quote_response.body.quote_response_id
                ))
            })?;
        if superseded_by_quote_response_id.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability quote response `{}` is superseded",
                artifact.quote_response.body.quote_response_id
            )));
        }
        let stored_response: SignedLiabilityQuoteResponse =
            serde_json::from_str(&stored_response_raw_json)?;
        if stored_response.body != artifact.quote_response.body {
            return Err(ReceiptStoreError::Conflict(
                "liability placement quote_response does not match the persisted response"
                    .to_string(),
            ));
        }

        let existing_request_placement = tx
            .query_row(
                "SELECT placement_id
                 FROM liability_placements
                 WHERE quote_request_id = ?1",
                params![
                    artifact
                        .quote_response
                        .body
                        .quote_request
                        .body
                        .quote_request_id
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing_request_placement) = existing_request_placement {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability quote request `{}` already has placement `{existing_request_placement}`",
                artifact
                    .quote_response
                    .body
                    .quote_request
                    .body
                    .quote_request_id
            )));
        }

        tx.execute(
            "INSERT INTO liability_placements (
                placement_id, issued_at, quote_request_id, quote_response_id, provider_id,
                raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                artifact.placement_id,
                artifact.issued_at as i64,
                artifact
                    .quote_response
                    .body
                    .quote_request
                    .body
                    .quote_request_id,
                artifact.quote_response.body.quote_response_id,
                artifact
                    .quote_response
                    .body
                    .quote_request
                    .body
                    .provider_policy
                    .provider_id,
                serde_json::to_string(placement)?,
                placement.signer_key.to_hex(),
                placement.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn record_liability_pricing_authority(
        &mut self,
        authority: &SignedLiabilityPricingAuthority,
    ) -> Result<(), ReceiptStoreError> {
        if !authority
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability pricing authority signature verification failed".to_string(),
            ));
        }
        authority
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &authority.body;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT authority_id FROM liability_pricing_authorities WHERE authority_id = ?1",
                params![artifact.authority_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability pricing authority `{}` already exists",
                artifact.authority_id
            )));
        }

        let stored_request_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_quote_requests
                 WHERE quote_request_id = ?1",
                params![artifact.quote_request.body.quote_request_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability quote request `{}` not found",
                    artifact.quote_request.body.quote_request_id
                ))
            })?;
        let stored_request: SignedLiabilityQuoteRequest =
            serde_json::from_str(&stored_request_raw_json)?;
        if stored_request.body != artifact.quote_request.body {
            return Err(ReceiptStoreError::Conflict(
                "liability pricing authority quote_request does not match the persisted request"
                    .to_string(),
            ));
        }

        let existing_request_authority = tx
            .query_row(
                "SELECT authority_id
                 FROM liability_pricing_authorities
                 WHERE quote_request_id = ?1",
                params![artifact.quote_request.body.quote_request_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing_request_authority) = existing_request_authority {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability quote request `{}` already has pricing authority `{existing_request_authority}`",
                artifact.quote_request.body.quote_request_id
            )));
        }

        tx.execute(
            "INSERT INTO liability_pricing_authorities (
                authority_id, issued_at, quote_request_id, provider_id, facility_id,
                underwriting_decision_id, expires_at, raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                artifact.authority_id,
                artifact.issued_at as i64,
                artifact.quote_request.body.quote_request_id,
                artifact.provider_policy.provider_id,
                artifact.facility.body.facility_id,
                artifact.underwriting_decision.body.decision_id,
                artifact.expires_at as i64,
                serde_json::to_string(authority)?,
                authority.signer_key.to_hex(),
                authority.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn record_liability_bound_coverage(
        &mut self,
        coverage: &SignedLiabilityBoundCoverage,
    ) -> Result<(), ReceiptStoreError> {
        if !coverage
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability bound coverage signature verification failed".to_string(),
            ));
        }
        coverage
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &coverage.body;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT bound_coverage_id FROM liability_bound_coverages WHERE bound_coverage_id = ?1",
                params![artifact.bound_coverage_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability bound coverage `{}` already exists",
                artifact.bound_coverage_id
            )));
        }

        let stored_placement_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_placements
                 WHERE placement_id = ?1",
                params![artifact.placement.body.placement_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability placement `{}` not found",
                    artifact.placement.body.placement_id
                ))
            })?;
        let stored_placement: SignedLiabilityPlacement =
            serde_json::from_str(&stored_placement_raw_json)?;
        if stored_placement.body != artifact.placement.body {
            return Err(ReceiptStoreError::Conflict(
                "liability bound coverage placement does not match the persisted placement"
                    .to_string(),
            ));
        }

        let existing_bound = tx
            .query_row(
                "SELECT bound_coverage_id
                 FROM liability_bound_coverages
                 WHERE placement_id = ?1",
                params![artifact.placement.body.placement_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing_bound) = existing_bound {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability placement `{}` already has bound coverage `{existing_bound}`",
                artifact.placement.body.placement_id
            )));
        }

        tx.execute(
            "INSERT INTO liability_bound_coverages (
                bound_coverage_id, issued_at, quote_request_id, quote_response_id, placement_id,
                provider_id, raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                artifact.bound_coverage_id,
                artifact.issued_at as i64,
                artifact
                    .placement
                    .body
                    .quote_response
                    .body
                    .quote_request
                    .body
                    .quote_request_id,
                artifact
                    .placement
                    .body
                    .quote_response
                    .body
                    .quote_response_id,
                artifact.placement.body.placement_id,
                artifact
                    .placement
                    .body
                    .quote_response
                    .body
                    .quote_request
                    .body
                    .provider_policy
                    .provider_id,
                serde_json::to_string(coverage)?,
                coverage.signer_key.to_hex(),
                coverage.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn record_liability_auto_bind_decision(
        &mut self,
        decision: &SignedLiabilityAutoBindDecision,
    ) -> Result<(), ReceiptStoreError> {
        if !decision
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability auto-bind decision signature verification failed".to_string(),
            ));
        }
        decision
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &decision.body;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT decision_id FROM liability_auto_bind_decisions WHERE decision_id = ?1",
                params![artifact.decision_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability auto-bind decision `{}` already exists",
                artifact.decision_id
            )));
        }

        let stored_authority_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_pricing_authorities
                 WHERE authority_id = ?1",
                params![artifact.authority.body.authority_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability pricing authority `{}` not found",
                    artifact.authority.body.authority_id
                ))
            })?;
        let stored_authority: SignedLiabilityPricingAuthority =
            serde_json::from_str(&stored_authority_raw_json)?;
        if stored_authority.body != artifact.authority.body {
            return Err(ReceiptStoreError::Conflict(
                "liability auto-bind authority does not match the persisted authority".to_string(),
            ));
        }

        let (stored_response_raw_json, superseded_by_quote_response_id) = tx
            .query_row(
                "SELECT raw_json, superseded_by_quote_response_id
                 FROM liability_quote_responses
                 WHERE quote_response_id = ?1",
                params![artifact.quote_response.body.quote_response_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability quote response `{}` not found",
                    artifact.quote_response.body.quote_response_id
                ))
            })?;
        if superseded_by_quote_response_id.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability quote response `{}` is superseded",
                artifact.quote_response.body.quote_response_id
            )));
        }
        let stored_response: SignedLiabilityQuoteResponse =
            serde_json::from_str(&stored_response_raw_json)?;
        if stored_response.body != artifact.quote_response.body {
            return Err(ReceiptStoreError::Conflict(
                "liability auto-bind quote_response does not match the persisted response"
                    .to_string(),
            ));
        }

        let existing_response_decision = tx
            .query_row(
                "SELECT decision_id
                 FROM liability_auto_bind_decisions
                 WHERE quote_response_id = ?1",
                params![artifact.quote_response.body.quote_response_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing_response_decision) = existing_response_decision {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability quote response `{}` already has auto-bind decision `{existing_response_decision}`",
                artifact.quote_response.body.quote_response_id
            )));
        }

        if let Some(placement) = artifact.placement.as_ref() {
            let placement_artifact = &placement.body;
            let existing_placement = tx
                .query_row(
                    "SELECT placement_id FROM liability_placements WHERE placement_id = ?1",
                    params![placement_artifact.placement_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if existing_placement.is_some() {
                return Err(ReceiptStoreError::Conflict(format!(
                    "liability placement `{}` already exists",
                    placement_artifact.placement_id
                )));
            }
            let existing_request_placement = tx
                .query_row(
                    "SELECT placement_id
                     FROM liability_placements
                     WHERE quote_request_id = ?1",
                    params![
                        artifact
                            .quote_response
                            .body
                            .quote_request
                            .body
                            .quote_request_id
                    ],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if let Some(existing_request_placement) = existing_request_placement {
                return Err(ReceiptStoreError::Conflict(format!(
                    "liability quote request `{}` already has placement `{existing_request_placement}`",
                    artifact.quote_response.body.quote_request.body.quote_request_id
                )));
            }
            tx.execute(
                "INSERT INTO liability_placements (
                    placement_id, issued_at, quote_request_id, quote_response_id, provider_id,
                    raw_json, signer_key, signature
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    placement_artifact.placement_id,
                    placement_artifact.issued_at as i64,
                    placement_artifact
                        .quote_response
                        .body
                        .quote_request
                        .body
                        .quote_request_id,
                    placement_artifact.quote_response.body.quote_response_id,
                    placement_artifact
                        .quote_response
                        .body
                        .quote_request
                        .body
                        .provider_policy
                        .provider_id,
                    serde_json::to_string(placement)?,
                    placement.signer_key.to_hex(),
                    placement.signature.to_hex(),
                ],
            )?;
        }

        if let Some(bound_coverage) = artifact.bound_coverage.as_ref() {
            let bound_artifact = &bound_coverage.body;
            let existing_bound = tx
                .query_row(
                    "SELECT bound_coverage_id
                     FROM liability_bound_coverages
                     WHERE bound_coverage_id = ?1",
                    params![bound_artifact.bound_coverage_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if existing_bound.is_some() {
                return Err(ReceiptStoreError::Conflict(format!(
                    "liability bound coverage `{}` already exists",
                    bound_artifact.bound_coverage_id
                )));
            }
            let existing_placement_bound = tx
                .query_row(
                    "SELECT bound_coverage_id
                     FROM liability_bound_coverages
                     WHERE placement_id = ?1",
                    params![bound_artifact.placement.body.placement_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if let Some(existing_placement_bound) = existing_placement_bound {
                return Err(ReceiptStoreError::Conflict(format!(
                    "liability placement `{}` already has bound coverage `{existing_placement_bound}`",
                    bound_artifact.placement.body.placement_id
                )));
            }
            tx.execute(
                "INSERT INTO liability_bound_coverages (
                    bound_coverage_id, issued_at, quote_request_id, quote_response_id, placement_id,
                    provider_id, raw_json, signer_key, signature
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    bound_artifact.bound_coverage_id,
                    bound_artifact.issued_at as i64,
                    bound_artifact
                        .placement
                        .body
                        .quote_response
                        .body
                        .quote_request
                        .body
                        .quote_request_id,
                    bound_artifact
                        .placement
                        .body
                        .quote_response
                        .body
                        .quote_response_id,
                    bound_artifact.placement.body.placement_id,
                    bound_artifact
                        .placement
                        .body
                        .quote_response
                        .body
                        .quote_request
                        .body
                        .provider_policy
                        .provider_id,
                    serde_json::to_string(bound_coverage)?,
                    bound_coverage.signer_key.to_hex(),
                    bound_coverage.signature.to_hex(),
                ],
            )?;
        }

        tx.execute(
            "INSERT INTO liability_auto_bind_decisions (
                decision_id, issued_at, quote_request_id, quote_response_id, authority_id,
                provider_id, disposition, raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                artifact.decision_id,
                artifact.issued_at as i64,
                artifact
                    .quote_response
                    .body
                    .quote_request
                    .body
                    .quote_request_id,
                artifact.quote_response.body.quote_response_id,
                artifact.authority.body.authority_id,
                artifact
                    .quote_response
                    .body
                    .quote_request
                    .body
                    .provider_policy
                    .provider_id,
                liability_auto_bind_disposition_label(&artifact.disposition),
                serde_json::to_string(decision)?,
                decision.signer_key.to_hex(),
                decision.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn query_liability_market_workflows(
        &self,
        query: &LiabilityMarketWorkflowQuery,
    ) -> Result<LiabilityMarketWorkflowReport, ReceiptStoreError> {
        let normalized = query.normalized();
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT raw_json
             FROM liability_quote_requests
             ORDER BY issued_at DESC, quote_request_id DESC",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;

        let mut matching_requests = 0_u64;
        let mut quote_responses = 0_u64;
        let mut quoted_responses = 0_u64;
        let mut declined_responses = 0_u64;
        let mut pricing_authorities = 0_u64;
        let mut auto_bind_decisions = 0_u64;
        let mut auto_bound_decisions = 0_u64;
        let mut manual_review_decisions = 0_u64;
        let mut denied_decisions = 0_u64;
        let mut placements = 0_u64;
        let mut bound_coverages = 0_u64;
        let mut workflows = Vec::new();

        for row in rows {
            let raw_json = row?;
            let quote_request: SignedLiabilityQuoteRequest = serde_json::from_str(&raw_json)?;
            if !liability_market_workflow_matches_query(&quote_request, &normalized) {
                continue;
            }
            matching_requests += 1;

            let latest_quote_response = self
                .connection()?
                .query_row(
                    "SELECT raw_json
                     FROM liability_quote_responses
                     WHERE quote_request_id = ?1 AND superseded_by_quote_response_id IS NULL
                     ORDER BY issued_at DESC, quote_response_id DESC
                     LIMIT 1",
                    params![quote_request.body.quote_request_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw_json| serde_json::from_str::<SignedLiabilityQuoteResponse>(&raw_json))
                .transpose()?;
            if let Some(response) = latest_quote_response.as_ref() {
                quote_responses += 1;
                match response.body.disposition {
                    LiabilityQuoteDisposition::Quoted => quoted_responses += 1,
                    LiabilityQuoteDisposition::Declined => declined_responses += 1,
                }
            }

            let pricing_authority = self
                .connection()?
                .query_row(
                    "SELECT raw_json
                     FROM liability_pricing_authorities
                     WHERE quote_request_id = ?1
                     ORDER BY issued_at DESC, authority_id DESC
                     LIMIT 1",
                    params![quote_request.body.quote_request_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw_json| serde_json::from_str::<SignedLiabilityPricingAuthority>(&raw_json))
                .transpose()?;
            if pricing_authority.is_some() {
                pricing_authorities += 1;
            }

            let latest_auto_bind_decision = self
                .connection()?
                .query_row(
                    "SELECT raw_json
                     FROM liability_auto_bind_decisions
                     WHERE quote_request_id = ?1
                     ORDER BY issued_at DESC, decision_id DESC
                     LIMIT 1",
                    params![quote_request.body.quote_request_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw_json| serde_json::from_str::<SignedLiabilityAutoBindDecision>(&raw_json))
                .transpose()?;
            if let Some(decision) = latest_auto_bind_decision.as_ref() {
                auto_bind_decisions += 1;
                match decision.body.disposition {
                    LiabilityAutoBindDisposition::AutoBound => auto_bound_decisions += 1,
                    LiabilityAutoBindDisposition::ManualReview => manual_review_decisions += 1,
                    LiabilityAutoBindDisposition::Denied => denied_decisions += 1,
                }
            }

            let placement = self
                .connection()?
                .query_row(
                    "SELECT raw_json
                     FROM liability_placements
                     WHERE quote_request_id = ?1
                     ORDER BY issued_at DESC, placement_id DESC
                     LIMIT 1",
                    params![quote_request.body.quote_request_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw_json| serde_json::from_str::<SignedLiabilityPlacement>(&raw_json))
                .transpose()?;
            if placement.is_some() {
                placements += 1;
            }

            let bound_coverage = self
                .connection()?
                .query_row(
                    "SELECT raw_json
                     FROM liability_bound_coverages
                     WHERE quote_request_id = ?1
                     ORDER BY issued_at DESC, bound_coverage_id DESC
                     LIMIT 1",
                    params![quote_request.body.quote_request_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw_json| serde_json::from_str::<SignedLiabilityBoundCoverage>(&raw_json))
                .transpose()?;
            if bound_coverage.is_some() {
                bound_coverages += 1;
            }

            if workflows.len() < normalized.limit_or_default() {
                workflows.push(LiabilityMarketWorkflowRow {
                    quote_request,
                    latest_quote_response,
                    pricing_authority,
                    latest_auto_bind_decision,
                    placement,
                    bound_coverage,
                });
            }
        }

        Ok(LiabilityMarketWorkflowReport {
            schema: LIABILITY_MARKET_WORKFLOW_REPORT_SCHEMA.to_string(),
            generated_at: unix_now(),
            query: normalized,
            summary: LiabilityMarketWorkflowSummary {
                matching_requests,
                returned_requests: workflows.len() as u64,
                quote_responses,
                quoted_responses,
                declined_responses,
                pricing_authorities,
                auto_bind_decisions,
                auto_bound_decisions,
                manual_review_decisions,
                denied_decisions,
                placements,
                bound_coverages,
            },
            workflows,
        })
    }
}
