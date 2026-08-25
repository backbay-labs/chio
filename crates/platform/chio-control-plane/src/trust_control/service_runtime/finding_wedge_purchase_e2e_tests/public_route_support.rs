use super::*;

pub(super) struct RoutedPurchaseExecutor {
    pub(super) authority: Arc<SqliteAuthorityStore>,
    pub(super) web: MarketWeb,
    pub(super) witness: VerifiedFindingAdmission,
    pub(super) buyer: Keypair,
    pub(super) kernel_keypair: Keypair,
    pub(super) calls: Arc<PaymentCalls>,
    pub(super) invocations: Arc<AtomicU64>,
    pub(super) attempts: Arc<AtomicU64>,
    pub(super) exchange_now: u64,
    pub(super) now: Arc<AtomicU64>,
    pub(super) status_proof_b64: String,
}

impl RoutedPurchaseExecutor {
    pub(super) fn execution_error(error: impl std::fmt::Display) -> FindingPurchaseExecutionError {
        FindingPurchaseExecutionError::Internal(error.to_string())
    }
}

pub(super) struct FixedTerminalExecutor {
    pub(super) authority: Arc<SqliteAuthorityStore>,
    pub(super) result: FindingPurchaseResult,
}

#[async_trait::async_trait]
impl FindingPurchaseExecutor for FixedTerminalExecutor {
    fn mutation_fence(&self) -> chio_kernel::admission_operation::StoreMutationFence {
        self.authority.mutation_fence()
    }

    fn authenticate_buyer(
        &self,
        bearer_token: &str,
    ) -> Result<AuthenticatedFindingBuyer, FindingBuyerAuthenticationError> {
        if bearer_token != BUYER_TOKEN {
            return Err(FindingBuyerAuthenticationError);
        }
        AuthenticatedFindingBuyer::new(
            "buyer-agent-1".to_owned(),
            self.result.payer.clone(),
            self.result.payer_key.clone(),
        )
        .map_err(|_| FindingBuyerAuthenticationError)
    }

    async fn execute(
        &self,
        _buyer: AuthenticatedFindingBuyer,
        _request: FindingPurchaseRequest,
    ) -> Result<FindingPurchaseResult, FindingPurchaseExecutionError> {
        Ok(self.result.clone())
    }
}

pub(super) async fn assert_terminal_cannot_rebind_public_request(
    state: &mut TrustServiceState,
    authority: &Arc<SqliteAuthorityStore>,
    path: &str,
    first: &FindingPurchaseResult,
    finding_id: &str,
    payer: &str,
) -> TestResult {
    let other_request = FindingPurchaseRequest::new(
        finding_id.to_owned(),
        PRICE_UNITS + 51,
        "USD".to_owned(),
        Some(payer.to_owned()),
        Some(900),
    )?;
    let mut rebound = first.clone();
    rebound.request_id = other_request.request_id.clone();
    state.finding_purchase_executor = Some(Arc::new(FixedTerminalExecutor {
        authority: authority.clone(),
        result: rebound,
    }));
    let (status, body) = send(
        state,
        buyer_post(path, canonical_json_bytes(&other_request)?)?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(
        json_body(&body)?["code"],
        serde_json::json!("purchase_terminal_invalid")
    );
    Ok(())
}
