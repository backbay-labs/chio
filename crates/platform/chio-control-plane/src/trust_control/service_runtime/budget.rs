use super::client::build_client;
use super::errors::into_budget_store_error;
use super::*;

#[path = "budget/lifecycle.rs"]
mod lifecycle;
#[path = "budget/structured.rs"]
mod structured;

#[derive(Clone, Copy)]
enum StructuredUsageSequenceRelation {
    None,
    ExistingProjection,
    AdvancesAtCommit,
}

pub fn build_remote_budget_store(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn BudgetStore>, CliError> {
    Ok(Box::new(remote_budget_store(control_url, control_token)?))
}

pub(crate) fn build_shared_remote_budget_store(
    control_url: &str,
    control_token: &str,
) -> Result<Arc<RemoteBudgetStore>, CliError> {
    remote_budget_store(control_url, control_token).map(Arc::new)
}

fn remote_budget_store(
    control_url: &str,
    control_token: &str,
) -> Result<RemoteBudgetStore, CliError> {
    Ok(RemoteBudgetStore {
        client: build_client(control_url, control_token)?,
        cached_usage: Mutex::new(HashMap::new()),
    })
}

fn remote_budget_grant_index(grant_index: usize) -> Result<u32, BudgetStoreError> {
    u32::try_from(grant_index)
        .map_err(|_| BudgetStoreError::Invariant("grant_index exceeds u32 range".to_string()))
}

fn validate_remote_optional_budget_identity(
    hold_id: Option<&str>,
    event_id: Option<&str>,
    transition: &str,
) -> Result<(), BudgetStoreError> {
    match (hold_id, event_id) {
        (None, None) => Ok(()),
        (None, Some(event_id)) if !event_id.is_empty() => Ok(()),
        (Some(hold_id), Some(event_id)) if !hold_id.is_empty() && !event_id.is_empty() => Ok(()),
        _ => Err(BudgetStoreError::Invariant(format!(
            "remote budget {transition} requires non-empty identifiers and any hold_id requires an event_id"
        ))),
    }
}

fn validate_remote_budget_identity(
    capability_id: &str,
    grant_index: usize,
    response_capability_id: &str,
    response_grant_index: usize,
    transition: &str,
) -> Result<(), BudgetStoreError> {
    if response_capability_id != capability_id || response_grant_index != grant_index {
        return Err(BudgetStoreError::Invariant(format!(
            "remote budget {transition} response changed the request identity"
        )));
    }
    Ok(())
}

fn validate_remote_budget_transition_identity(
    request_hold_id: Option<&str>,
    request_event_id: Option<&str>,
    response_hold_id: Option<&str>,
    response_event_id: Option<&str>,
    transition: &str,
    require_exact: bool,
) -> Result<(), BudgetStoreError> {
    let changed = if require_exact {
        response_hold_id != request_hold_id || response_event_id != request_event_id
    } else {
        response_hold_id.is_some() && response_hold_id != request_hold_id
            || request_event_id.is_some()
                && response_event_id.is_some()
                && response_event_id != request_event_id
    };
    if changed {
        return Err(BudgetStoreError::Invariant(format!(
            "remote budget {transition} response changed or omitted the request hold/event identity"
        )));
    }
    Ok(())
}

fn validate_remote_authorize_decision(
    decision: BudgetAuthorizeExposureDecision,
    allowed: bool,
) -> Result<(), BudgetStoreError> {
    if matches!(
        (decision, allowed),
        (BudgetAuthorizeExposureDecision::Authorized, true)
            | (BudgetAuthorizeExposureDecision::Denied, false)
            | (BudgetAuthorizeExposureDecision::AlreadyCaptured, false)
    ) {
        Ok(())
    } else {
        Err(BudgetStoreError::Invariant(
            "remote budget authorization decision contradicted its allowed flag".to_string(),
        ))
    }
}

fn required_remote_hold_event<'a>(
    hold_id: Option<&'a str>,
    event_id: Option<&'a str>,
    transition: &str,
) -> Result<(&'a str, &'a str), BudgetStoreError> {
    match (hold_id, event_id) {
        (Some(hold_id), Some(event_id)) if !hold_id.is_empty() && !event_id.is_empty() => {
            Ok((hold_id, event_id))
        }
        _ => Err(BudgetStoreError::Invariant(format!(
            "structured remote budget {transition} requires non-empty hold_id and event_id"
        ))),
    }
}

fn structured_budget_error(error: impl Into<String>) -> BudgetStoreError {
    BudgetStoreError::Invariant(error.into())
}

fn reject_unsupported_remote_hard_authority(
    request: &BudgetAuthorizeHoldRequest,
) -> Result<(), BudgetStoreError> {
    if request
        .invocation_quotas
        .iter()
        .any(|quota| quota.key.profile == BudgetQuotaProfile::AggregateFamilyInvocation)
    {
        return Err(structured_budget_error(
            "advisory remote budget authority cannot enforce aggregate family invocation limits without a modeled partition escrow profile",
        ));
    }
    if request.cumulative_approval.is_some() {
        return Err(structured_budget_error(
            "advisory remote budget authority cannot reserve cumulative family approval without a modeled partition escrow profile",
        ));
    }
    Ok(())
}

impl BudgetStore for RemoteBudgetStore {
    fn budget_guarantee_level(&self) -> BudgetGuaranteeLevel {
        BudgetGuaranteeLevel::AdvisoryPosthoc
    }

    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        remote_budget_grant_index(grant_index)?;
        let response = self
            .client
            .try_increment_budget(capability_id, grant_index, max_invocations)
            .map_err(into_budget_store_error)?;
        validate_remote_budget_identity(
            capability_id,
            grant_index,
            &response.capability_id,
            response.grant_index,
            "increment",
        )?;
        self.cache_usage(
            capability_id,
            grant_index,
            response_budget_commit_index(response.budget_authority.as_ref(), None),
            response.invocation_count,
            None,
            None,
        )?;
        Ok(response.allowed)
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        remote_budget_grant_index(grant_index)?;
        let response = self
            .client
            .try_charge_cost(
                capability_id,
                grant_index,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
            )
            .map_err(into_budget_store_error)?;
        validate_remote_budget_identity(
            capability_id,
            grant_index,
            &response.capability_id,
            response.grant_index,
            "authorization",
        )?;
        validate_remote_authorize_decision(response.decision, response.allowed)?;
        self.cache_usage(
            capability_id,
            grant_index,
            response_budget_commit_index(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
            ),
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        )?;
        Ok(response.allowed)
    }

    fn try_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        remote_budget_grant_index(grant_index)?;
        validate_remote_optional_budget_identity(hold_id, event_id, "authorization")?;
        let response = self
            .client
            .try_charge_cost_with_ids(
                capability_id,
                grant_index,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
                hold_id,
                event_id,
            )
            .map_err(into_budget_store_error)?;
        validate_remote_budget_identity(
            capability_id,
            grant_index,
            &response.capability_id,
            response.grant_index,
            "authorization",
        )?;
        validate_remote_authorize_decision(response.decision, response.allowed)?;
        validate_remote_budget_transition_identity(
            hold_id,
            event_id,
            response.hold_id.as_deref(),
            response.event_id.as_deref(),
            "authorization",
            false,
        )?;
        if !matches!(
            response.decision,
            BudgetAuthorizeExposureDecision::AlreadyCaptured
        ) && event_id.is_some()
            && response.event_id.as_deref() != event_id
        {
            return Err(BudgetStoreError::Invariant(
                "remote budget authorization response changed the request event identity"
                    .to_string(),
            ));
        }
        self.cache_usage(
            capability_id,
            grant_index,
            response_budget_commit_index(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
            ),
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        )?;
        Ok(response.allowed)
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        remote_budget_grant_index(grant_index)?;
        let response = self
            .client
            .reverse_charge_cost(capability_id, grant_index, cost_units)
            .map_err(into_budget_store_error)?;
        validate_remote_budget_identity(
            capability_id,
            grant_index,
            &response.capability_id,
            response.grant_index,
            "reversal",
        )?;
        self.cache_usage(
            capability_id,
            grant_index,
            response_budget_commit_index(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
            ),
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        )?;
        Ok(())
    }

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        remote_budget_grant_index(grant_index)?;
        validate_remote_optional_budget_identity(hold_id, event_id, "reversal")?;
        let response = self
            .client
            .reverse_charge_cost_with_ids(capability_id, grant_index, cost_units, hold_id, event_id)
            .map_err(into_budget_store_error)?;
        validate_remote_budget_identity(
            capability_id,
            grant_index,
            &response.capability_id,
            response.grant_index,
            "reversal",
        )?;
        validate_remote_budget_transition_identity(
            hold_id,
            event_id,
            response.hold_id.as_deref(),
            response.event_id.as_deref(),
            "reversal",
            false,
        )?;
        self.cache_usage(
            capability_id,
            grant_index,
            response_budget_commit_index(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
            ),
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        )?;
        Ok(())
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        remote_budget_grant_index(grant_index)?;
        let response = self
            .client
            .reduce_charge_cost(capability_id, grant_index, cost_units)
            .map_err(into_budget_store_error)?;
        validate_remote_budget_identity(
            capability_id,
            grant_index,
            &response.capability_id,
            response.grant_index,
            "release",
        )?;
        if response
            .released_exposure_units
            .is_some_and(|released| released != cost_units)
        {
            return Err(BudgetStoreError::Invariant(
                "remote budget release response changed the released exposure".to_string(),
            ));
        }
        self.cache_usage(
            capability_id,
            grant_index,
            response_budget_commit_index(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
            ),
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        )?;
        Ok(())
    }

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        remote_budget_grant_index(grant_index)?;
        validate_remote_optional_budget_identity(hold_id, event_id, "release")?;
        let response = self
            .client
            .reduce_charge_cost_with_ids(capability_id, grant_index, cost_units, hold_id, event_id)
            .map_err(into_budget_store_error)?;
        validate_remote_budget_identity(
            capability_id,
            grant_index,
            &response.capability_id,
            response.grant_index,
            "release",
        )?;
        validate_remote_budget_transition_identity(
            hold_id,
            event_id,
            response.hold_id.as_deref(),
            response.event_id.as_deref(),
            "release",
            false,
        )?;
        if response
            .released_exposure_units
            .is_some_and(|released| released != cost_units)
        {
            return Err(BudgetStoreError::Invariant(
                "remote budget release response changed the released exposure".to_string(),
            ));
        }
        self.cache_usage(
            capability_id,
            grant_index,
            response_budget_commit_index(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
            ),
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        )?;
        Ok(())
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        remote_budget_grant_index(grant_index)?;
        let released_exposure_units = exposed_cost_units
            .checked_sub(realized_cost_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "realized spend cannot exceed exposed cost during reconciliation".to_string(),
                )
            })?;
        let response = self
            .client
            .reconcile_budget_spend(
                capability_id,
                grant_index,
                exposed_cost_units,
                realized_cost_units,
            )
            .map_err(into_budget_store_error)?;
        validate_remote_budget_identity(
            capability_id,
            grant_index,
            &response.capability_id,
            response.grant_index,
            "reconciliation",
        )?;
        if response
            .released_exposure_units
            .is_some_and(|released| released != released_exposure_units)
        {
            return Err(BudgetStoreError::Invariant(
                "remote budget reconciliation response changed the released exposure".to_string(),
            ));
        }
        self.cache_usage(
            capability_id,
            grant_index,
            response_budget_commit_index(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
            ),
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        )?;
        Ok(())
    }

    fn settle_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        remote_budget_grant_index(grant_index)?;
        validate_remote_optional_budget_identity(hold_id, event_id, "reconciliation")?;
        let released_exposure_units = exposed_cost_units
            .checked_sub(realized_cost_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "realized spend cannot exceed exposed cost during reconciliation".to_string(),
                )
            })?;
        let response = self
            .client
            .reconcile_budget_spend_with_ids(
                capability_id,
                grant_index,
                exposed_cost_units,
                realized_cost_units,
                hold_id,
                event_id,
            )
            .map_err(into_budget_store_error)?;
        validate_remote_budget_identity(
            capability_id,
            grant_index,
            &response.capability_id,
            response.grant_index,
            "reconciliation",
        )?;
        validate_remote_budget_transition_identity(
            hold_id,
            event_id,
            response.hold_id.as_deref(),
            response.event_id.as_deref(),
            "reconciliation",
            false,
        )?;
        if response
            .released_exposure_units
            .is_some_and(|released| released != released_exposure_units)
        {
            return Err(BudgetStoreError::Invariant(
                "remote budget reconciliation response changed the released exposure".to_string(),
            ));
        }
        self.cache_usage(
            capability_id,
            grant_index,
            response_budget_commit_index(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
            ),
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        )?;
        Ok(())
    }

    fn try_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<bool, BudgetStoreError> {
        if authority.is_some() {
            return Err(structured_budget_error(
                "remote budget store does not support authority-fenced charging",
            ));
        }
        self.try_charge_cost_with_ids(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
        )
    }

    fn reverse_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        if authority.is_some() {
            return Err(structured_budget_error(
                "remote budget store does not support authority-fenced reversal",
            ));
        }
        self.reverse_charge_cost_with_ids(capability_id, grant_index, cost_units, hold_id, event_id)
    }

    fn reduce_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        if authority.is_some() {
            return Err(structured_budget_error(
                "remote budget store does not support authority-fenced release",
            ));
        }
        self.reduce_charge_cost_with_ids(capability_id, grant_index, cost_units, hold_id, event_id)
    }

    fn settle_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        if authority.is_some() {
            return Err(structured_budget_error(
                "remote budget store does not support authority-fenced settlement",
            ));
        }
        self.settle_charge_cost_with_ids(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
        )
    }

    fn authorize_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        remote_budget_grant_index(request.grant_index)?;
        request.validate()?;
        reject_unsupported_remote_hard_authority(&request)?;
        if !request.invocation_quotas.is_empty()
            || request.cumulative_approval.is_some()
            || request.admission_binding.is_some()
        {
            return self.authorize_structured_budget_hold(request);
        }
        let response = self
            .client
            .try_charge_cost_with_ids(
                &request.capability_id,
                request.grant_index,
                request.max_invocations,
                request.requested_exposure_units,
                request.max_cost_per_invocation,
                request.max_total_cost_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
            )
            .map_err(into_budget_store_error)?;
        validate_remote_budget_identity(
            &request.capability_id,
            request.grant_index,
            &response.capability_id,
            response.grant_index,
            "authorization",
        )?;
        if response.hold_id != request.hold_id {
            return Err(BudgetStoreError::Invariant(
                "remote budget authorization response changed or omitted the request hold identity"
                    .to_string(),
            ));
        }
        validate_remote_authorize_decision(response.decision, response.allowed)?;
        if matches!(
            response.decision,
            BudgetAuthorizeExposureDecision::AlreadyCaptured
        ) && request.hold_id.is_none()
        {
            return Err(BudgetStoreError::Invariant(
                "captured remote authorization replay requires a hold identity".to_string(),
            ));
        }
        let event_id = match response.decision {
            BudgetAuthorizeExposureDecision::AlreadyCaptured => {
                let Some(event_id) = response.event_id.clone().filter(|event_id| !event_id.is_empty())
                else {
                    return Err(BudgetStoreError::Invariant(
                        "captured remote authorization replay omitted non-empty capture event identity"
                            .to_string(),
                    ));
                };
                Some(event_id)
            }
            BudgetAuthorizeExposureDecision::Authorized
            | BudgetAuthorizeExposureDecision::Denied => {
                match request.event_id.as_deref() {
                    Some(request_event_id)
                        if response.event_id.as_deref() == Some(request_event_id) =>
                    {
                        request.event_id.clone()
                    }
                    None => response.event_id.clone().filter(|event_id| !event_id.is_empty()),
                    _ => None,
                }
            }
        }
        .ok_or_else(|| {
            BudgetStoreError::Invariant(
                "remote budget authorization response changed or omitted the request event identity"
                    .to_string(),
            )
        })?;
        let mutation_invocation_count_after =
            response.mutation_invocation_count_after.ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "remote budget authorization response omitted event-time invocation count"
                        .to_string(),
                )
            })?;
        let mutation_committed_cost_units_after = response
            .mutation_committed_cost_units_after
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "remote budget authorization response omitted event-time committed cost"
                        .to_string(),
                )
            })?;
        let captured_state = if matches!(
            response.decision,
            BudgetAuthorizeExposureDecision::AlreadyCaptured
        ) {
            Some((
                response.exposure_units.ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "captured remote authorization replay omitted original exposure"
                            .to_string(),
                    )
                })?,
                response.realized_spend_units.ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "captured remote authorization replay omitted original realized spend"
                            .to_string(),
                    )
                })?,
            ))
        } else {
            None
        };
        match response.decision {
            BudgetAuthorizeExposureDecision::Authorized
                if response.exposure_units == Some(request.requested_exposure_units)
                    && response.realized_spend_units == Some(0) => {}
            BudgetAuthorizeExposureDecision::Denied
                if response.exposure_units.is_none() && response.realized_spend_units.is_none() => {
            }
            BudgetAuthorizeExposureDecision::AlreadyCaptured => {}
            _ => {
                return Err(BudgetStoreError::Invariant(
                    "remote budget authorization response changed the event-time exposure state"
                        .to_string(),
                ))
            }
        }
        let required_committed_cost = match response.decision {
            BudgetAuthorizeExposureDecision::Authorized => Some(request.requested_exposure_units),
            BudgetAuthorizeExposureDecision::AlreadyCaptured => {
                let (exposure_units, realized_spend_units) = captured_state.ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "captured remote authorization replay omitted original mutation state"
                            .to_string(),
                    )
                })?;
                Some(
                    exposure_units
                        .checked_add(realized_spend_units)
                        .ok_or_else(|| {
                            BudgetStoreError::Overflow(
                                "captured remote authorization replay overflowed committed cost"
                                    .to_string(),
                            )
                        })?,
                )
            }
            BudgetAuthorizeExposureDecision::Denied => None,
        };
        if required_committed_cost.is_some_and(|required| {
            mutation_invocation_count_after == 0 || mutation_committed_cost_units_after < required
        }) {
            return Err(BudgetStoreError::Invariant(
                "remote budget authorization response returned impossible event-time state"
                    .to_string(),
            ));
        }
        let metadata = self.remote_budget_commit_metadata(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            request.authority.as_ref(),
            Some(event_id),
        );
        let decision = match response.decision {
            BudgetAuthorizeExposureDecision::Authorized => {
                BudgetAuthorizeHoldDecision::Authorized(AuthorizedBudgetHold {
                    hold_id: request.hold_id,
                    admission_binding: None,
                    authorized_exposure_units: request.requested_exposure_units,
                    committed_cost_units_after: mutation_committed_cost_units_after,
                    invocation_count_after: mutation_invocation_count_after,
                    invocation_quota_usages: Vec::new(),
                    cumulative_approval: None,
                    invocation_state: BudgetInvocationState::Authorized,
                    monetary_state: if request.requested_exposure_units == 0 {
                        BudgetMonetaryState::None
                    } else {
                        BudgetMonetaryState::Exposed
                    },
                    metadata,
                })
            }
            BudgetAuthorizeExposureDecision::Denied => {
                BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                    hold_id: request.hold_id,
                    admission_binding: None,
                    attempted_exposure_units: request.requested_exposure_units,
                    committed_cost_units_after: mutation_committed_cost_units_after,
                    invocation_count_after: mutation_invocation_count_after,
                    invocation_quota_usages: Vec::new(),
                    cumulative_approval: None,
                    invocation_state: BudgetInvocationState::Denied,
                    monetary_state: BudgetMonetaryState::None,
                    metadata,
                })
            }
            BudgetAuthorizeExposureDecision::AlreadyCaptured => {
                let (exposure_units, realized_spend_units) = captured_state.ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "captured remote authorization replay omitted original mutation state"
                            .to_string(),
                    )
                })?;
                BudgetAuthorizeHoldDecision::AlreadyCaptured(BudgetHoldMutationDecision {
                    hold_id: request.hold_id,
                    admission_binding: None,
                    exposure_units,
                    realized_spend_units,
                    committed_cost_units_after: mutation_committed_cost_units_after,
                    invocation_count_after: mutation_invocation_count_after,
                    invocation_quota_usages: Vec::new(),
                    cumulative_approval: None,
                    invocation_state: BudgetInvocationState::Captured,
                    monetary_state: if exposure_units == 0 {
                        BudgetMonetaryState::None
                    } else {
                        BudgetMonetaryState::Exposed
                    },
                    metadata,
                })
            }
        };
        self.cache_usage(
            &request.capability_id,
            request.grant_index,
            response.usage_seq,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        )?;
        Ok(decision)
    }

    fn capture_invocation_reservations(
        &self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetInvocationCaptureDecision, BudgetStoreError> {
        self.capture_invocation_reservations_remote(request)
    }

    fn authorize_cumulative_approval(
        &self,
        request: BudgetAuthorizeCumulativeApprovalRequest,
    ) -> Result<BudgetCumulativeApprovalAuthorizationDecision, BudgetStoreError> {
        self.authorize_cumulative_approval_remote(request)
    }

    fn cancel_captured_before_dispatch(
        &self,
        request: BudgetCancelCapturedBeforeDispatchRequest,
    ) -> Result<BudgetCapturedBeforeDispatchCancellationDecision, BudgetStoreError> {
        self.cancel_captured_before_dispatch_remote(request)
    }

    fn reverse_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        self.reverse_budget_hold_remote(request)
    }

    fn release_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        self.release_budget_hold_remote(request)
    }

    fn reconcile_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        self.reconcile_budget_hold_remote(request)
    }

    fn capture_budget_hold(
        &self,
        request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        self.capture_budget_hold_remote(request)
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let response = self
            .client
            .list_budgets(&BudgetQuery {
                capability_id: capability_id.map(ToOwned::to_owned),
                limit: Some(limit),
            })
            .map_err(into_budget_store_error)?;
        let usages: Vec<_> = response
            .usages
            .into_iter()
            .map(|usage| BudgetUsageRecord {
                capability_id: usage.capability_id,
                grant_index: usage.grant_index,
                invocation_count: usage.invocation_count,
                updated_at: usage.updated_at,
                seq: usage.seq.unwrap_or(0),
                total_cost_exposed: usage.total_cost_exposed,
                total_cost_realized_spend: usage.total_cost_realized_spend,
            })
            .collect();
        self.merge_cached_usages(capability_id, &usages)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        let grant_index_u32 = remote_budget_grant_index(grant_index)?;
        if let Some(cached) = self.cached_entry(capability_id, grant_index) {
            if cached.cost_authoritative {
                cached.record.committed_cost_units()?;
                return Ok(Some(cached.record));
            }
        }
        self.list_usages(MAX_LIST_LIMIT, Some(capability_id))
            .map(|usages| {
                usages
                    .into_iter()
                    .find(|usage| usage.grant_index == grant_index_u32)
            })
    }

    fn get_cumulative_approval_operation_usage(
        &self,
        operation_id: &str,
    ) -> Result<Option<BudgetCumulativeApprovalUsage>, BudgetStoreError> {
        self.get_cumulative_approval_operation_usage_remote(operation_id)
    }
}

impl RemoteBudgetStore {
    pub(super) fn cache_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
        seq: Option<u64>,
        invocation_count: Option<u32>,
        total_cost_exposed: Option<u64>,
        total_cost_realized_spend: Option<u64>,
    ) -> Result<BudgetUsageRecord, BudgetStoreError> {
        let grant_index_u32 = remote_budget_grant_index(grant_index)?;
        let mut cached_usage = match self.cached_usage.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let key = (capability_id.to_string(), grant_index);
        let updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
        let existing_cost_authoritative = cached_usage
            .get(&key)
            .is_some_and(|entry| entry.cost_authoritative);

        if let Some(existing) = cached_usage.get(&key).map(|entry| &entry.record) {
            if seq == Some(existing.seq) {
                // Totals defaulted by a partial response were never observed, so they
                // cannot conflict with the ones a later response actually carries.
                let conflicts = invocation_count
                    .is_some_and(|value| value != existing.invocation_count)
                    || existing_cost_authoritative
                        && (total_cost_exposed
                            .is_some_and(|value| value != existing.total_cost_exposed)
                            || total_cost_realized_spend
                                .is_some_and(|value| value != existing.total_cost_realized_spend));
                if conflicts {
                    return Err(BudgetStoreError::Invariant(
                        "remote budget cache replay changed state at the same sequence".to_string(),
                    ));
                }
                let upgrades_costs = !existing_cost_authoritative
                    && (total_cost_exposed.is_some() || total_cost_realized_spend.is_some());
                if !upgrades_costs {
                    existing.committed_cost_units()?;
                    return Ok(existing.clone());
                }
            } else if seq.is_some_and(|seq| seq < existing.seq) || seq.is_none() && existing.seq > 0
            {
                existing.committed_cost_units()?;
                return Ok(existing.clone());
            }
        }

        if invocation_count.is_none()
            && total_cost_exposed.is_none()
            && total_cost_realized_spend.is_none()
        {
            return Ok(cached_usage
                .get(&key)
                .map(|entry| entry.record.clone())
                .unwrap_or(BudgetUsageRecord {
                    capability_id: capability_id.to_string(),
                    grant_index: grant_index_u32,
                    invocation_count: 0,
                    updated_at,
                    seq: 0,
                    total_cost_exposed: 0,
                    total_cost_realized_spend: 0,
                }));
        }

        let mut projected = cached_usage
            .get(&key)
            .map(|entry| entry.record.clone())
            .unwrap_or(BudgetUsageRecord {
                capability_id: capability_id.to_string(),
                grant_index: grant_index_u32,
                invocation_count: 0,
                updated_at,
                seq: seq.unwrap_or(0),
                total_cost_exposed: 0,
                total_cost_realized_spend: 0,
            });
        if let Some(seq) = seq {
            projected.seq = seq;
        }
        if let Some(invocation_count) = invocation_count {
            projected.invocation_count = invocation_count;
        }
        if let Some(total_cost_exposed) = total_cost_exposed {
            projected.total_cost_exposed = total_cost_exposed;
        }
        if let Some(total_cost_realized_spend) = total_cost_realized_spend {
            projected.total_cost_realized_spend = total_cost_realized_spend;
        }
        projected.updated_at = updated_at;
        projected.committed_cost_units()?;
        let cost_authoritative = existing_cost_authoritative
            || total_cost_exposed.is_some()
            || total_cost_realized_spend.is_some();
        cached_usage.insert(
            key,
            CachedBudgetUsage {
                record: projected.clone(),
                cost_authoritative,
            },
        );
        Ok(projected)
    }

    #[cfg(test)]
    pub(super) fn cached_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Option<BudgetUsageRecord> {
        self.cached_entry(capability_id, grant_index)
            .map(|entry| entry.record)
    }

    fn cached_entry(&self, capability_id: &str, grant_index: usize) -> Option<CachedBudgetUsage> {
        match self.cached_usage.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
        .get(&(capability_id.to_string(), grant_index))
        .cloned()
    }

    fn merge_cached_usages(
        &self,
        capability_id: Option<&str>,
        usages: &[BudgetUsageRecord],
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let keyed_usages = usages
            .iter()
            .map(|usage| {
                if capability_id.is_some_and(|expected| usage.capability_id != expected) {
                    return Err(BudgetStoreError::Invariant(
                        "remote budget list response changed the requested capability identity"
                            .to_string(),
                    ));
                }
                usage.committed_cost_units()?;
                let grant_index = usize::try_from(usage.grant_index).map_err(|_| {
                    BudgetStoreError::Invariant("grant_index exceeds usize range".to_string())
                })?;
                Ok(((usage.capability_id.clone(), grant_index), usage.clone()))
            })
            .collect::<Result<Vec<_>, BudgetStoreError>>()?;
        let mut cached_usage = match self.cached_usage.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut merged = cached_usage.clone();
        for (key, usage) in &keyed_usages {
            if let Some(existing) = merged.get(key) {
                if usage.seq < existing.record.seq {
                    continue;
                }
                if usage.seq == existing.record.seq {
                    // Totals defaulted by a partial response were never observed, so a
                    // list that carries them upgrades the entry rather than conflicting.
                    if usage.invocation_count != existing.record.invocation_count
                        || existing.cost_authoritative
                            && (usage.total_cost_exposed != existing.record.total_cost_exposed
                                || usage.total_cost_realized_spend
                                    != existing.record.total_cost_realized_spend)
                    {
                        return Err(BudgetStoreError::Invariant(
                            "remote budget cache replay changed state at the same sequence"
                                .to_string(),
                        ));
                    }
                    if existing.cost_authoritative {
                        continue;
                    }
                }
            }
            // List responses always carry both monetary totals.
            merged.insert(
                key.clone(),
                CachedBudgetUsage {
                    record: usage.clone(),
                    cost_authoritative: true,
                },
            );
        }
        let merged_usages = keyed_usages
            .iter()
            .map(|(key, _)| {
                merged
                    .get(key)
                    .map(|entry| entry.record.clone())
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant(
                            "remote budget list merge omitted a validated usage".to_string(),
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        *cached_usage = merged;
        Ok(merged_usages)
    }

    fn remote_budget_commit_metadata(
        &self,
        authority: Option<&BudgetAuthorityMetadataView>,
        commit: Option<&BudgetWriteCommitView>,
        fallback_authority: Option<&BudgetEventAuthority>,
        event_id: Option<String>,
    ) -> BudgetCommitMetadata {
        BudgetCommitMetadata {
            authority: remote_budget_event_authority(authority, commit)
                .or_else(|| fallback_authority.cloned()),
            guarantee_level: remote_budget_guarantee_level(authority, commit),
            budget_profile: self.budget_authority_profile(),
            metering_profile: self.budget_metering_profile(),
            budget_commit_index: response_budget_commit_index(authority, commit),
            event_id,
            recorded_at_unix_seconds: None,
        }
    }
}

fn response_budget_commit_index(
    authority: Option<&BudgetAuthorityMetadataView>,
    commit: Option<&BudgetWriteCommitView>,
) -> Option<u64> {
    commit
        .map(|commit| commit.commit_index)
        .or_else(|| authority.and_then(|authority| authority.budget_commit_index))
}

fn remote_budget_event_authority(
    authority: Option<&BudgetAuthorityMetadataView>,
    commit: Option<&BudgetWriteCommitView>,
) -> Option<BudgetEventAuthority> {
    commit
        .filter(|commit| commit.quorum_committed)
        .map(|commit| BudgetEventAuthority {
            authority_id: commit.authority_id.clone(),
            lease_id: commit.lease_id.clone(),
            lease_epoch: commit.lease_epoch,
        })
        .or_else(|| {
            authority.map(|authority| BudgetEventAuthority {
                authority_id: authority.authority_id.clone(),
                lease_id: authority.lease_id.clone(),
                lease_epoch: authority.lease_epoch,
            })
        })
}

fn remote_budget_guarantee_level(
    _authority: Option<&BudgetAuthorityMetadataView>,
    _commit: Option<&BudgetWriteCommitView>,
) -> BudgetGuaranteeLevel {
    BudgetGuaranteeLevel::AdvisoryPosthoc
}
