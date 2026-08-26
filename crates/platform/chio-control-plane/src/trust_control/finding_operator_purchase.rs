//! Production-composed purchase executor for a single-operator market.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chio_core::capability::governance::{GovernedTransactionIntent, GovernedTransactionIntentBody};
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::Keypair;
use chio_core::merkle::MerkleTree;
use chio_core::receipt::decision::Decision;
use chio_core::{canonical_json_bytes, sha256_hex};
use chio_finding::{
    FindingFacetKind, FindingFacetOutcome, FindingPurchaseContext, PURCHASE_CONTEXT_SCHEMA,
};
use chio_kernel::checkpoint::{build_checkpoint, build_inclusion_proof};
use chio_kernel::finding_purchase::{
    FINDING_PURCHASE_CONTEXT_KEY, FINDING_STATUS_PROOF_CONTEXT_KEY,
};
use chio_kernel::{
    ChioKernel, DpopConfig, DpopNonceStore, DpopProof, DpopProofBody, KernelConfig, ReceiptStore,
    ToolCallOutput, ToolCallRequest, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES, DPOP_SCHEMA,
};
use chio_open_market::bidding::{
    BidMintContext, BidRequest, RequestedScope, SignedAcceptedBid, SignedAskResponse,
    SignedBidRequest, SignedReservationReceipt, VerifiedReservationReceipt, BID_REQUEST_SCHEMA,
};
use chio_open_market::finding_admission::{
    accept_finding_purchase, bid_with_finding_purchase, verify_finding_admission,
    FindingAdmissionContext, FindingAdmissionPenaltyGate,
    FindingAllocationSnapshot as AdmissionAllocationSnapshot, FindingAllocationStatus,
    FindingConstituentExpiryBounds, FindingFeeScheduleGate, VerifiedFindingAdmission,
    VerifiedFindingPurchaseAsk,
};
use chio_open_market::purchase_verification::{
    derive_payment_operation_id, derive_purchase_intent_id, PurchaseVerificationAuthorities,
};
use chio_store_sqlite::{
    FindingAllocationState, FindingPublicPurchaseRequestBinding, FindingPublicPurchaseTerminal,
    FindingPublicPurchaseTerminalKind, FindingPurchaseReservationRecord,
    FindingPurchaseReservationState, SqliteAuthorityStore, SqliteFindingOperatorBundleStore,
    SqliteFindingOperatorPaymentAdapter, SqliteFindingPayloadStore, SqliteReceiptStore, TenantId,
    TenantKey,
};
use subtle::ConstantTimeEq;

use super::finding_challenge_coordinator::FindingAuthorityStatusResolver;
use super::finding_operator_bundle::FindingOperatorBundle;
use super::finding_purchase_coordinator::{
    CoordinatorReservationReader, FindingPurchaseCoordinator, PurchaseCoordinatorError,
};
use super::finding_purchase_routes::{
    AuthenticatedFindingBuyer, FindingBuyerAuthenticationError, FindingPurchaseExecutionError,
    FindingPurchaseExecutor, FindingPurchaseRequest, FindingPurchaseResult,
    FindingPurchaseSettlementTerminal, FindingPurchaseVerdict, FindingPurchasedOutput,
    FINDING_PURCHASE_RESULT_SCHEMA,
};
use super::finding_purchase_verifier::MarketFindingPurchaseVerifier;
use super::finding_reveal_server::{
    FindingRevealServer, SqliteFindingPayloadResolver, READ_FINDING_TOOL,
};
use super::finding_status_publisher::FindingStatusEpochPublisher;
use super::finding_status_verifier::MarketFindingStatusVerifier;
use super::FindingMarketConfig;

const MAX_CREDENTIAL_TEXT_BYTES: usize = 512;
const FINDING_OPERATOR_PURCHASE_JOB_SCHEMA: &str = "chio.finding.operator-purchase-job.v1";
const PREDISPATCH_RELEASE_REJECTION: &str =
    "purchase failed before dispatch and its reservation was released";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FindingOperatorPurchaseJob {
    schema: String,
    principal_id: String,
    request_sha256: String,
    prepared_at: u64,
    bid: SignedBidRequest,
    ask: SignedAskResponse,
    buyer_signature: String,
}

/// One buyer identity and scoped credential installed by the operator.
pub struct FindingOperatorBuyerCredential {
    principal_id: String,
    bearer_token: String,
    signing_key: Keypair,
    payout_destination: String,
}

impl std::fmt::Debug for FindingOperatorBuyerCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FindingOperatorBuyerCredential")
            .field("principal_id", &self.principal_id)
            .field("bearer_token", &"[REDACTED]")
            .field("public_key", &self.signing_key.public_key())
            .field("payout_destination", &self.payout_destination)
            .finish()
    }
}

impl FindingOperatorBuyerCredential {
    pub fn new(
        principal_id: String,
        bearer_token: String,
        signing_key: Keypair,
        payout_destination: String,
    ) -> Result<Self, String> {
        validate_credential_text(&principal_id, "buyer principal id")?;
        validate_credential_text(&bearer_token, "buyer bearer token")?;
        chio_finding::canonical_evm_payout_destination(&payout_destination)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            principal_id,
            bearer_token,
            signing_key,
            payout_destination,
        })
    }
}

/// Private signing material required by the operator purchase runtime.
pub struct FindingOperatorPurchaseKeys {
    pub listing: Keypair,
    pub purchase: Keypair,
    pub failed_delivery: Keypair,
    pub status_operator: Keypair,
    pub kernel: Keypair,
    pub sellers: Vec<Keypair>,
}

/// Durable paths and private payload scope used to compose the executor.
pub struct FindingOperatorPurchaseStorage {
    pub authority: Arc<SqliteAuthorityStore>,
    pub operator_db_path: PathBuf,
    pub receipt_db_path: PathBuf,
    pub payload_tenant_id: TenantId,
    pub payload_key: TenantKey,
}

/// Production executor backed only by restart-safe stores and explicit keys.
pub struct FindingOperatorPurchaseExecutor {
    authority: Arc<SqliteAuthorityStore>,
    bundle_store: SqliteFindingOperatorBundleStore,
    payload_store: Arc<SqliteFindingPayloadStore>,
    payment_adapter: SqliteFindingOperatorPaymentAdapter,
    receipt_store: Arc<SqliteReceiptStore>,
    payload_tenant_id: TenantId,
    payload_key: Arc<TenantKey>,
    market: FindingMarketConfig,
    authority_status: Arc<dyn FindingAuthorityStatusResolver>,
    keys: FindingOperatorPurchaseKeys,
    buyers: Vec<FindingOperatorBuyerCredential>,
    #[cfg(test)]
    stop_after_purchase_job_once: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    stop_after_reservation_once: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    stop_after_terminal_capacity_once: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    fail_predispatch_once: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    stop_after_kernel_response_once: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    test_now: std::sync::atomic::AtomicU64,
}

impl FindingOperatorPurchaseExecutor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        storage: FindingOperatorPurchaseStorage,
        market: FindingMarketConfig,
        authority_status: Arc<dyn FindingAuthorityStatusResolver>,
        keys: FindingOperatorPurchaseKeys,
        buyers: Vec<FindingOperatorBuyerCredential>,
        global_service_token: &str,
    ) -> Result<Self, String> {
        market.validate().map_err(|error| error.to_string())?;
        if keys.listing.public_key() != market.listing.key().map_err(|e| e.to_string())?
            || keys.purchase.public_key() != market.purchase.key().map_err(|e| e.to_string())?
            || keys.failed_delivery.public_key()
                != market.failed_delivery.key().map_err(|e| e.to_string())?
            || keys.status_operator.public_key()
                != market
                    .status_feed_operator
                    .authority
                    .key()
                    .map_err(|e| e.to_string())?
        {
            return Err("finding operator private keys do not match the market pins".to_owned());
        }
        if buyers.is_empty() {
            return Err("finding operator requires at least one buyer credential".to_owned());
        }
        if keys.sellers.is_empty() {
            return Err("finding operator requires at least one seller signing key".to_owned());
        }
        for (index, seller) in keys.sellers.iter().enumerate() {
            if keys
                .sellers
                .iter()
                .skip(index.saturating_add(1))
                .any(|other| other.public_key() == seller.public_key())
            {
                return Err("finding operator seller signing keys must be distinct".to_owned());
            }
        }
        for (index, buyer) in buyers.iter().enumerate() {
            if bool::from(
                buyer
                    .bearer_token
                    .as_bytes()
                    .ct_eq(global_service_token.as_bytes()),
            ) {
                return Err("buyer credential must differ from the global service token".to_owned());
            }
            if buyers.iter().skip(index + 1).any(|other| {
                other.principal_id == buyer.principal_id
                    || bool::from(
                        other
                            .bearer_token
                            .as_bytes()
                            .ct_eq(buyer.bearer_token.as_bytes()),
                    )
                    || other.signing_key.public_key() == buyer.signing_key.public_key()
            }) {
                return Err("buyer credentials must have distinct ids, tokens, and keys".to_owned());
            }
        }
        let bundle_store = SqliteFindingOperatorBundleStore::open(&storage.operator_db_path)
            .map_err(|error| error.to_string())?;
        let payload_store = Arc::new(
            SqliteFindingPayloadStore::open(&storage.operator_db_path)
                .map_err(|error| error.to_string())?,
        );
        let payment_adapter = SqliteFindingOperatorPaymentAdapter::open(&storage.operator_db_path)
            .map_err(|error| error.to_string())?;
        let receipt_store = Arc::new(
            SqliteReceiptStore::open(&storage.receipt_db_path)
                .map_err(|error| error.to_string())?,
        );
        receipt_store
            .wait_for_writer_ready(std::time::Duration::from_secs(30))
            .map_err(|error| error.to_string())?;
        Ok(Self {
            authority: storage.authority,
            bundle_store,
            payload_store,
            payment_adapter,
            receipt_store,
            payload_tenant_id: storage.payload_tenant_id,
            payload_key: Arc::new(storage.payload_key),
            market,
            authority_status,
            keys,
            buyers,
            #[cfg(test)]
            stop_after_purchase_job_once: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            stop_after_reservation_once: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            stop_after_terminal_capacity_once: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_predispatch_once: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            stop_after_kernel_response_once: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            test_now: std::sync::atomic::AtomicU64::new(0),
        })
    }

    #[cfg(test)]
    pub(crate) fn stop_after_purchase_job_once(&self) {
        self.stop_after_purchase_job_once
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn stop_after_reservation_once(&self) {
        self.stop_after_reservation_once
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn stop_after_terminal_capacity_once(&self) {
        self.stop_after_terminal_capacity_once
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn fail_predispatch_once(&self) {
        self.fail_predispatch_once
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn stop_after_kernel_response_once(&self) {
        self.stop_after_kernel_response_once
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn set_test_now(&self, now: u64) {
        self.test_now
            .store(now, std::sync::atomic::Ordering::SeqCst);
    }

    fn current_time(&self) -> Result<u64, FindingPurchaseExecutionError> {
        #[cfg(test)]
        {
            let now = self.test_now.load(std::sync::atomic::Ordering::SeqCst);
            if now != 0 {
                return Ok(now);
            }
        }
        unix_timestamp_now()
    }

    fn credential(
        &self,
        authenticated: &AuthenticatedFindingBuyer,
    ) -> Result<&FindingOperatorBuyerCredential, FindingPurchaseExecutionError> {
        self.buyers
            .iter()
            .find(|credential| credential.principal_id == authenticated.principal_id())
            .filter(|credential| {
                credential.signing_key.public_key() == *authenticated.public_key()
                    && authenticated.payer() == credential.signing_key.public_key().to_hex()
            })
            .ok_or_else(|| {
                FindingPurchaseExecutionError::Rejected(
                    "authenticated buyer is not mapped to its signing key".to_owned(),
                )
            })
    }

    fn seller_key(
        &self,
        bundle: &FindingOperatorBundle,
    ) -> Result<&Keypair, FindingPurchaseExecutionError> {
        self.keys
            .sellers
            .iter()
            .find(|key| key.public_key() == bundle.seller_authorization.body.seller)
            .ok_or_else(|| {
                FindingPurchaseExecutionError::Rejected(
                    "admitted Finding seller has no local signing key".to_owned(),
                )
            })
    }

    fn coordinator(&self) -> Result<FindingPurchaseCoordinator, FindingPurchaseExecutionError> {
        FindingPurchaseCoordinator::new(
            self.authority.finding_purchase_store(),
            self.authority.finding_market_store(),
            self.authority.admission_operation_store(),
            self.authority.tool_outcome_store(),
            self.keys.purchase.clone(),
            &self.keys.purchase.public_key(),
            self.keys.failed_delivery.clone(),
            &self.keys.failed_delivery.public_key(),
            self.authority_status.clone(),
            &self.market.authority_status,
            &self.market.status_feed_operator,
            &self.market.status_feed_service_bond,
            self.market.status_max_epoch_age_secs,
            &self.market.listing,
            &self.market.venue,
            &self.market.venue_id,
        )
        .map_err(execution_internal)
    }

    fn load_bundle(
        &self,
        finding_id: &str,
        now: u64,
    ) -> Result<FindingOperatorBundle, FindingPurchaseExecutionError> {
        let record = self
            .bundle_store
            .get(finding_id)
            .map_err(execution_unavailable)?;
        let bundle: FindingOperatorBundle = serde_json::from_slice(&record.bundle_json)
            .map_err(|error| execution_internal(error.to_string()))?;
        bundle.verify_at(&self.market, now).map_err(|error| {
            FindingPurchaseExecutionError::Rejected(format!(
                "finding bundle is not purchasable: {error}"
            ))
        })?;
        Ok(bundle)
    }

    fn admission_witness(
        &self,
        bundle: &FindingOperatorBundle,
        now: u64,
    ) -> Result<VerifiedFindingAdmission, FindingPurchaseExecutionError> {
        let allocation = self
            .authority
            .finding_market_store()
            .get_allocation(&bundle.admission.body.backing_allocation_id)
            .map_err(execution_unavailable)?
            .ok_or_else(|| {
                FindingPurchaseExecutionError::Rejected(
                    "admission backing allocation is not retained".to_owned(),
                )
            })?;
        let collateral = self.market.collateral.key().map_err(execution_internal)?;
        let trusted_fee_signers = self
            .market
            .fee_schedule_operators()
            .map_err(execution_internal)?;
        let context = FindingAdmissionContext {
            venue_authority: &self.market.venue.key().map_err(execution_internal)?,
            venue_id: &self.market.venue_id,
            now,
            fee_schedule: &bundle.fee_schedule,
            fee_schedule_gate: FindingFeeScheduleGate::Legacy,
            trusted_local_operator_signers: &trusted_fee_signers,
            seller_authorization: &bundle.seller_authorization,
            terms: &bundle.market_terms,
            backing: &bundle.bond_backing,
            allocation_snapshot: AdmissionAllocationSnapshot {
                allocation_id: allocation.backing.allocation_id.clone(),
                backing_envelope_sha256: allocation.backing_envelope_sha256.clone(),
                expires_at: allocation.backing.expires_at,
                status: match allocation.state {
                    FindingAllocationState::Live => FindingAllocationStatus::Available,
                    FindingAllocationState::Consumed => FindingAllocationStatus::Consumed,
                    FindingAllocationState::Expired => FindingAllocationStatus::Expired,
                    FindingAllocationState::Released => FindingAllocationStatus::Released,
                },
                active_admission_id: allocation.active_admission_id,
                prepared_admission_id: None,
                accepted_at: allocation.accepted_at,
            },
            bond_backing_observed_at: (bundle
                .verifier_report
                .body
                .facet_outcome(FindingFacetKind::BondBacking)
                == Some(FindingFacetOutcome::Verified))
            .then_some(bundle.verifier_report.body.evaluation_time),
            penalty_gate: FindingAdmissionPenaltyGate::Ungoverned,
            collateral_authority: &collateral,
            constituent_expiry_bounds: FindingConstituentExpiryBounds {
                finding: bundle.finding.expires_at,
                listing: bundle.listing.listing.body.expires_at.unwrap_or(u64::MAX),
                pricing_hint: bundle.listing.pricing.body.expires_at,
                seller_authorization: bundle.seller_authorization.body.expires_at,
                profile: bundle.verifier_profile.body.expires_at,
            },
        };
        verify_finding_admission(&bundle.admission, &context).map_err(|error| {
            FindingPurchaseExecutionError::Rejected(format!(
                "current admission verification failed: {error}"
            ))
        })
    }

    fn build_kernel(
        &self,
        bundle: &FindingOperatorBundle,
    ) -> Result<ChioKernel, FindingPurchaseExecutionError> {
        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: self.keys.kernel.clone(),
            ca_public_keys: vec![
                self.keys.listing.public_key(),
                bundle.seller_authorization.body.seller.clone(),
            ],
            max_delegation_depth: 5,
            policy_hash: sha256_hex(b"cognition-market-single-operator-v1"),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: false,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        });
        kernel
            .set_receipt_store_handle(self.receipt_store.clone())
            .map_err(execution_internal)?;
        kernel
            .set_durable_admission_store(
                Arc::new(self.authority.admission_operation_store()),
                Arc::new(self.authority.tool_outcome_store()),
                self.authority.mutation_fence(),
            )
            .map_err(execution_internal)?;
        kernel.set_budget_store_handle(Arc::new(self.authority.budget_store()));
        kernel.set_payment_adapter(Box::new(self.payment_adapter.clone()));
        let resolver = SqliteFindingPayloadResolver::new(
            self.payload_store.clone(),
            self.payload_tenant_id.clone(),
            self.payload_key.clone(),
        );
        kernel.register_tool_server(Box::new(FindingRevealServer::with_resolver(
            bundle.admission.body.server_id.clone(),
            Arc::new(resolver),
        )));
        let dpop = DpopConfig::default();
        kernel.set_dpop_store(
            DpopNonceStore::new(
                dpop.nonce_store_capacity,
                std::time::Duration::from_secs(dpop.proof_ttl_secs),
            ),
            dpop,
        );
        kernel.set_finding_purchase_verifier(Arc::new(MarketFindingPurchaseVerifier::new(
            PurchaseVerificationAuthorities {
                venue_authority: self.market.venue.key().map_err(execution_internal)?,
                venue_id: self.market.venue_id.clone(),
                reservation_authority: self.keys.purchase.public_key(),
            },
            CoordinatorReservationReader::shared(
                self.authority.finding_purchase_store(),
                self.authority.finding_market_store(),
            ),
        )));
        kernel.set_finding_status_proof_verifier(Arc::new(
            MarketFindingStatusVerifier::new(
                self.market.status_feed_operator.clone(),
                self.market.status_feed_service_bond.clone(),
                self.market.status_max_epoch_age_secs,
                self.authority.finding_status_store(),
            )
            .map_err(execution_internal)?,
        ));
        Ok(kernel)
    }

    fn cached_terminal(
        &self,
        buyer: &AuthenticatedFindingBuyer,
        request: &FindingPurchaseRequest,
        request_sha256: &str,
    ) -> Result<Option<FindingPurchaseResult>, FindingPurchaseExecutionError> {
        let Some(record) = self
            .bundle_store
            .get_terminal(&request.request_id)
            .map_err(execution_unavailable)?
        else {
            return Ok(None);
        };
        if record.principal_id != buyer.principal_id() || record.request_sha256 != request_sha256 {
            return Err(FindingPurchaseExecutionError::Conflict(
                "purchase request id is bound to another authenticated request".to_owned(),
            ));
        }
        serde_json::from_slice(&record.result_json)
            .map(Some)
            .map_err(|error| execution_internal(error.to_string()))
    }

    fn retain_terminal(
        &self,
        buyer: &AuthenticatedFindingBuyer,
        request_sha256: &str,
        result: &FindingPurchaseResult,
    ) -> Result<(), FindingPurchaseExecutionError> {
        let bytes = canonical_json_bytes(result).map_err(execution_internal)?;
        self.bundle_store
            .put_terminal(
                &result.request_id,
                buyer.principal_id(),
                request_sha256,
                &bytes,
            )
            .map_err(execution_unavailable)?;
        Ok(())
    }

    fn reserve_terminal_capacity(
        &self,
        buyer: &AuthenticatedFindingBuyer,
        request: &FindingPurchaseRequest,
        request_sha256: &str,
    ) -> Result<(), FindingPurchaseExecutionError> {
        self.bundle_store
            .reserve_terminal_capacity(&request.request_id, buyer.principal_id(), request_sha256)
            .map_err(execution_unavailable)?;
        Ok(())
    }

    fn release_terminal_capacity(
        &self,
        buyer: &AuthenticatedFindingBuyer,
        request: &FindingPurchaseRequest,
        request_sha256: &str,
    ) -> Result<(), FindingPurchaseExecutionError> {
        self.bundle_store
            .release_terminal_capacity(&request.request_id, buyer.principal_id(), request_sha256)
            .map_err(execution_unavailable)?;
        Ok(())
    }

    fn recover_released_reservation(
        &self,
        buyer: &AuthenticatedFindingBuyer,
        request: &FindingPurchaseRequest,
        request_sha256: &str,
        reservation_id: &str,
    ) -> Result<FindingPurchaseResult, FindingPurchaseExecutionError> {
        match self.recover_terminal(buyer, request, reservation_id) {
            Err(FindingPurchaseExecutionError::Pending(_)) => Err(
                FindingPurchaseExecutionError::Rejected(PREDISPATCH_RELEASE_REJECTION.to_owned()),
            ),
            Ok(result) => {
                self.reserve_terminal_capacity(buyer, request, request_sha256)?;
                Ok(result)
            }
            Err(error) => Err(error),
        }
    }

    fn expire_open_reservation(
        &self,
        buyer: &AuthenticatedFindingBuyer,
        request: &FindingPurchaseRequest,
        request_sha256: &str,
        reservation: &FindingPurchaseReservationRecord,
        now: u64,
    ) -> Result<(), FindingPurchaseExecutionError> {
        if !self
            .coordinator()?
            .expire_reservation(&reservation.reservation_id, now)
            .map_err(execution_internal)?
        {
            return Err(execution_internal(
                "due purchase reservation did not reach the expired terminal",
            ));
        }
        self.release_terminal_capacity(buyer, request, request_sha256)
    }

    fn reconcile_and_expire_slot_reservation(
        &self,
        buyer: &AuthenticatedFindingBuyer,
        request: &FindingPurchaseRequest,
        request_sha256: &str,
        reservation: &FindingPurchaseReservationRecord,
        now: u64,
    ) -> Result<(), FindingPurchaseExecutionError> {
        self.payment_adapter
            .reconcile_expired_governed_intent(
                &format!("intent-{}", request.request_id),
                &request.request_id,
                &reservation.payer_hex,
                reservation.amount_units,
                &reservation.currency,
            )
            .map_err(execution_unavailable)?;
        self.expire_open_reservation(buyer, request, request_sha256, reservation, now)
    }

    fn load_purchase_job(
        &self,
        buyer: &AuthenticatedFindingBuyer,
        request: &FindingPurchaseRequest,
        request_sha256: &str,
    ) -> Result<Option<FindingOperatorPurchaseJob>, FindingPurchaseExecutionError> {
        let Some(record) = self
            .bundle_store
            .get_purchase_job(&request.request_id)
            .map_err(execution_unavailable)?
        else {
            return Ok(None);
        };
        if record.principal_id != buyer.principal_id() || record.request_sha256 != request_sha256 {
            return Err(FindingPurchaseExecutionError::Conflict(
                "purchase request id is bound to another prepared transaction".to_owned(),
            ));
        }
        let job: FindingOperatorPurchaseJob = serde_json::from_slice(&record.job_json)
            .map_err(|error| execution_internal(error.to_string()))?;
        if canonical_json_bytes(&job).map_err(execution_internal)? != record.job_json {
            return Err(execution_internal(
                "prepared purchase job is not typed canonical JSON",
            ));
        }
        if job.schema != FINDING_OPERATOR_PURCHASE_JOB_SCHEMA
            || job.principal_id != buyer.principal_id()
            || job.request_sha256 != request_sha256
        {
            return Err(execution_internal(
                "prepared purchase job failed its identity binding",
            ));
        }
        Ok(Some(job))
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_purchase_job(
        &self,
        buyer: &AuthenticatedFindingBuyer,
        credential: &FindingOperatorBuyerCredential,
        request: &FindingPurchaseRequest,
        request_sha256: &str,
        bundle: &FindingOperatorBundle,
        witness: &VerifiedFindingAdmission,
        now: u64,
    ) -> Result<FindingOperatorPurchaseJob, FindingPurchaseExecutionError> {
        let deadline_secs = request.deadline_secs.unwrap_or(3_600);
        let bid = SignedBidRequest::sign(
            BidRequest {
                schema: BID_REQUEST_SCHEMA.to_owned(),
                agent_id: credential.signing_key.public_key().to_hex(),
                payout_destination: Some(credential.payout_destination.clone()),
                listing_id: bundle.admission.body.listing_id.clone(),
                max_price_per_call: request.max_price.clone(),
                window_seconds: deadline_secs,
                requested_scope: RequestedScope {
                    server_id: bundle.admission.body.server_id.clone(),
                    tool_name: bundle.seller_authorization.body.provider_tool.clone(),
                    max_invocations: Some(1),
                    capability_scope_prefix: bundle.admission.body.capability_scope.clone(),
                },
                issued_at: now,
            },
            &credential.signing_key,
        )
        .map_err(execution_internal)?;
        let verified_ask = bid_with_finding_purchase(
            &bid,
            BidMintContext {
                listing: &bundle.listing,
                issuer_keypair: self.seller_key(bundle)?,
                agent_subject: credential.signing_key.public_key(),
                token_id: format!("finding-token-{}", request.request_id),
                now,
                grant_constraints: Vec::new(),
                dpop_required: None,
            },
            witness,
            &bundle.finding,
        )
        .map_err(execution_internal)?;
        let ask = verified_ask.signed_ask().clone();
        let ask_digest = canonical_json_bytes(&ask.body)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(execution_internal)?;
        let job = FindingOperatorPurchaseJob {
            schema: FINDING_OPERATOR_PURCHASE_JOB_SCHEMA.to_owned(),
            principal_id: buyer.principal_id().to_owned(),
            request_sha256: request_sha256.to_owned(),
            prepared_at: now,
            bid,
            ask,
            buyer_signature: credential.signing_key.sign(ask_digest.as_bytes()).to_hex(),
        };
        self.validate_purchase_job(&job, credential, request, request_sha256, bundle)?;
        let bytes = canonical_json_bytes(&job).map_err(execution_internal)?;
        self.bundle_store
            .put_purchase_job(
                &request.request_id,
                buyer.principal_id(),
                request_sha256,
                &bytes,
            )
            .map_err(execution_unavailable)?;
        Ok(job)
    }

    fn validate_purchase_job(
        &self,
        job: &FindingOperatorPurchaseJob,
        credential: &FindingOperatorBuyerCredential,
        request: &FindingPurchaseRequest,
        request_sha256: &str,
        bundle: &FindingOperatorBundle,
    ) -> Result<(), FindingPurchaseExecutionError> {
        let expected_window = request.deadline_secs.unwrap_or(3_600);
        let bid_digest = canonical_json_bytes(&job.bid.body)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(execution_internal)?;
        let ask_digest = canonical_json_bytes(&job.ask.body)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(execution_internal)?;
        let signature =
            chio_core::Signature::from_hex(&job.buyer_signature).map_err(execution_internal)?;
        if job.schema != FINDING_OPERATOR_PURCHASE_JOB_SCHEMA
            || job.principal_id != credential.principal_id
            || job.request_sha256 != request_sha256
            || job.prepared_at != job.bid.body.issued_at
            || job.bid.signer_key != credential.signing_key.public_key()
            || !matches!(job.bid.verify_signature(), Ok(true))
            || !matches!(job.ask.verify_signature(), Ok(true))
            || job.ask.body.bid_digest != bid_digest
            || job.ask.body.listing_id != bundle.admission.body.listing_id
            || job.ask.body.agent_id != credential.signing_key.public_key().to_hex()
            || job.bid.body.max_price_per_call != request.max_price
            || job.bid.body.window_seconds != expected_window
            || job.bid.body.payout_destination.as_deref()
                != Some(credential.payout_destination.as_str())
            || (job.ask.signer_key != bundle.seller_authorization.body.issuer
                && job.ask.signer_key != bundle.seller_authorization.body.seller)
            || !credential
                .signing_key
                .public_key()
                .verify(ask_digest.as_bytes(), &signature)
        {
            return Err(execution_internal(
                "prepared purchase job failed signature or request binding",
            ));
        }
        Ok(())
    }

    fn recover_terminal(
        &self,
        buyer: &AuthenticatedFindingBuyer,
        request: &FindingPurchaseRequest,
        reservation_id: &str,
    ) -> Result<FindingPurchaseResult, FindingPurchaseExecutionError> {
        let store = self.authority.finding_purchase_store();
        let payer_hex = buyer.public_key().to_hex();
        let public_request = FindingPublicPurchaseRequestBinding {
            request_id: &request.request_id,
            finding_id: &request.finding_id,
            requested_payer: request.payer.as_deref(),
            resolved_payer: buyer.payer(),
            payer_hex: &payer_hex,
            max_price_units: request.max_price.units,
            currency: &request.max_price.currency,
            deadline_secs: request.deadline_secs,
        };
        store
            .verify_public_purchase_reservation(&public_request, reservation_id)
            .map_err(execution_internal)?;
        let receipt_store = self.receipt_store.clone();

        if let Some(row) = store
            .get_purchase_record_by_reservation(reservation_id)
            .map_err(execution_unavailable)?
        {
            let record: chio_finding::SignedFindingPurchaseRecord =
                serde_json::from_slice(&row.record_json).map_err(execution_internal)?;
            let delivery_receipt = receipt_store
                .load_retained_chio_receipt(&row.delivery_receipt_id)
                .map_err(execution_unavailable)?
                .ok_or_else(|| {
                    execution_unavailable("settled purchase lost its retained delivery receipt")
                })?;
            let payload = self
                .payload_store
                .get(
                    &self.payload_tenant_id,
                    self.payload_key.as_ref(),
                    &request.finding_id,
                )
                .map_err(execution_unavailable)?;
            let terminal = FindingPublicPurchaseTerminal {
                kind: FindingPublicPurchaseTerminalKind::PurchaseRecord,
                terminal_id: &record.body.purchase_key,
                receipt_id: &delivery_receipt.id,
            };
            store
                .verify_public_purchase_terminal(&public_request, reservation_id, &terminal)
                .map_err(execution_internal)?;
            return Ok(FindingPurchaseResult {
                schema: FINDING_PURCHASE_RESULT_SCHEMA.to_owned(),
                request_id: request.request_id.clone(),
                finding_id: request.finding_id.clone(),
                payer: buyer.payer().to_owned(),
                payer_key: buyer.public_key().clone(),
                reservation_id: reservation_id.to_owned(),
                purchase_intent_id: record.body.purchase_intent_id.clone(),
                authoritative_payment_operation_id: record
                    .body
                    .authoritative_payment_operation_id
                    .clone(),
                verdict: FindingPurchaseVerdict::Allow,
                settlement: FindingPurchaseSettlementTerminal::Captured,
                accepted_price: record.body.accepted_price.clone(),
                realized_spend: record.body.realized_spend.clone(),
                delivery_receipt,
                purchase_record: Some(record),
                failed_delivery: None,
                output: Some(FindingPurchasedOutput {
                    media_type: payload.media_type,
                    payload_b64: STANDARD.encode(payload.payload),
                }),
            });
        }

        if let Some(row) = store
            .get_failed_delivery_record_by_reservation(reservation_id)
            .map_err(execution_unavailable)?
        {
            let failed: chio_finding::SignedFindingFailedDelivery =
                serde_json::from_slice(&row.record_json).map_err(execution_internal)?;
            let delivery_receipt = receipt_store
                .load_retained_chio_receipt(&row.deny_receipt_id)
                .map_err(execution_unavailable)?
                .ok_or_else(|| {
                    execution_unavailable("failed delivery lost its retained denial receipt")
                })?;
            let terminal = FindingPublicPurchaseTerminal {
                kind: FindingPublicPurchaseTerminalKind::FailedDelivery,
                terminal_id: &failed.body.failed_delivery_id,
                receipt_id: &delivery_receipt.id,
            };
            store
                .verify_public_purchase_terminal(&public_request, reservation_id, &terminal)
                .map_err(execution_internal)?;
            return Ok(FindingPurchaseResult {
                schema: FINDING_PURCHASE_RESULT_SCHEMA.to_owned(),
                request_id: request.request_id.clone(),
                finding_id: request.finding_id.clone(),
                payer: buyer.payer().to_owned(),
                payer_key: buyer.public_key().clone(),
                reservation_id: reservation_id.to_owned(),
                purchase_intent_id: failed.body.purchase_intent_id.clone(),
                authoritative_payment_operation_id: failed
                    .body
                    .authoritative_payment_operation_id
                    .clone(),
                verdict: FindingPurchaseVerdict::Deny,
                settlement: FindingPurchaseSettlementTerminal::Released,
                accepted_price: MonetaryAmount {
                    units: request.max_price.units.min(
                        self.authority
                            .finding_purchase_store()
                            .get_reservation(reservation_id)
                            .map_err(execution_unavailable)?
                            .ok_or_else(|| execution_internal("terminal lost its reservation"))?
                            .amount_units,
                    ),
                    currency: failed.body.currency.clone(),
                },
                realized_spend: MonetaryAmount {
                    units: 0,
                    currency: failed.body.currency.clone(),
                },
                delivery_receipt,
                purchase_record: None,
                failed_delivery: Some(failed),
                output: None,
            });
        }

        Err(FindingPurchaseExecutionError::Pending(
            "durable reservation has no recoverable terminal".to_owned(),
        ))
    }

    async fn execute_new(
        &self,
        authenticated: &AuthenticatedFindingBuyer,
        request: &FindingPurchaseRequest,
    ) -> Result<FindingPurchaseResult, FindingPurchaseExecutionError> {
        if request.max_price.units > i64::MAX as u64 {
            return Err(FindingPurchaseExecutionError::Rejected(
                "maximum price exceeds the durable payment range".to_owned(),
            ));
        }
        let now = self.current_time()?;
        let credential = self.credential(authenticated)?;
        if request
            .payer
            .as_deref()
            .is_some_and(|payer| payer != authenticated.payer())
        {
            return Err(FindingPurchaseExecutionError::Rejected(
                "requested payer does not match the authenticated buyer".to_owned(),
            ));
        }
        let payer = authenticated.payer().to_owned();
        let request_bytes = canonical_json_bytes(request).map_err(execution_internal)?;
        let request_sha256 = sha256_hex(&request_bytes);
        let payer_hex = credential.signing_key.public_key().to_hex();
        let public_request = FindingPublicPurchaseRequestBinding {
            request_id: &request.request_id,
            finding_id: &request.finding_id,
            requested_payer: request.payer.as_deref(),
            resolved_payer: &payer,
            payer_hex: &payer_hex,
            max_price_units: request.max_price.units,
            currency: &request.max_price.currency,
            deadline_secs: request.deadline_secs,
        };
        let existing_reservation = self
            .authority
            .finding_purchase_store()
            .resolve_public_purchase_reservation(&public_request)
            .map_err(execution_unavailable)?;
        if let Some(existing) = existing_reservation.as_ref() {
            match existing.state {
                FindingPurchaseReservationState::Consumed => {
                    self.reserve_terminal_capacity(authenticated, request, &request_sha256)?;
                    return self.recover_terminal(authenticated, request, &existing.reservation_id);
                }
                FindingPurchaseReservationState::Released => {
                    return self.recover_released_reservation(
                        authenticated,
                        request,
                        &request_sha256,
                        &existing.reservation_id,
                    );
                }
                FindingPurchaseReservationState::Expired => {
                    self.release_terminal_capacity(authenticated, request, &request_sha256)?;
                    return Err(FindingPurchaseExecutionError::Rejected(
                        "durable purchase reservation expired before recovery".to_owned(),
                    ));
                }
                FindingPurchaseReservationState::Open if now >= existing.expires_at => {
                    self.expire_open_reservation(
                        authenticated,
                        request,
                        &request_sha256,
                        existing,
                        now,
                    )?;
                    return Err(FindingPurchaseExecutionError::Rejected(
                        "durable purchase reservation expired before recovery".to_owned(),
                    ));
                }
                FindingPurchaseReservationState::SlotReserved if now >= existing.expires_at => {
                    self.reconcile_and_expire_slot_reservation(
                        authenticated,
                        request,
                        &request_sha256,
                        existing,
                        now,
                    )?;
                    return Err(FindingPurchaseExecutionError::Rejected(
                        "durable purchase reservation expired before recovery".to_owned(),
                    ));
                }
                FindingPurchaseReservationState::Open
                | FindingPurchaseReservationState::SlotReserved => {}
            }
        }
        let release_unreserved_capacity = |original| {
            if existing_reservation.is_none() {
                release_terminal_capacity_after_error(
                    &self.bundle_store,
                    authenticated,
                    request,
                    &request_sha256,
                    original,
                )
            } else {
                original
            }
        };
        let stored_job = self.load_purchase_job(authenticated, request, &request_sha256)?;
        if existing_reservation.is_some() && stored_job.is_none() {
            return Err(FindingPurchaseExecutionError::Pending(
                "legacy durable reservation has no prepared recovery job".to_owned(),
            ));
        }
        let prepared_at = stored_job.as_ref().map_or(now, |job| job.prepared_at);
        // A prepared job is only immutable construction evidence. Until a
        // reservation exists, a retry is a new commitment of market exposure
        // and must re-check every constituent at the current clock.
        let validation_time = if stored_job.is_some() && existing_reservation.is_none() {
            now
        } else {
            prepared_at
        };
        let bundle = self
            .load_bundle(&request.finding_id, validation_time)
            .map_err(&release_unreserved_capacity)?;
        let witness = self
            .admission_witness(&bundle, validation_time)
            .map_err(&release_unreserved_capacity)?;
        let job = match stored_job {
            Some(job) => {
                self.validate_purchase_job(&job, credential, request, &request_sha256, &bundle)
                    .map_err(&release_unreserved_capacity)?;
                job
            }
            None => self
                .prepare_purchase_job(
                    authenticated,
                    credential,
                    request,
                    &request_sha256,
                    &bundle,
                    &witness,
                    now,
                )
                .map_err(&release_unreserved_capacity)?,
        };
        #[cfg(test)]
        if self
            .stop_after_purchase_job_once
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(release_unreserved_capacity(
                FindingPurchaseExecutionError::Pending(
                    "test interruption after durable purchase job".to_owned(),
                ),
            ));
        }
        let bid = &job.bid;
        let seller_key = self
            .seller_key(&bundle)
            .map_err(&release_unreserved_capacity)?;
        let ask = bid_with_finding_purchase(
            bid,
            BidMintContext {
                listing: &bundle.listing,
                issuer_keypair: seller_key,
                agent_subject: credential.signing_key.public_key(),
                token_id: format!("finding-token-{}", request.request_id),
                now: job.prepared_at,
                grant_constraints: Vec::new(),
                dpop_required: None,
            },
            &witness,
            &bundle.finding,
        )
        .map_err(|error| release_unreserved_capacity(execution_internal(error)))?;
        if canonical_json_bytes(ask.signed_ask())
            .map_err(|error| release_unreserved_capacity(execution_internal(error)))?
            != canonical_json_bytes(&job.ask)
                .map_err(|error| release_unreserved_capacity(execution_internal(error)))?
        {
            return Err(release_unreserved_capacity(execution_internal(
                "prepared purchase ask could not be reconstructed exactly",
            )));
        }
        let signed_ask = ask.signed_ask();
        let ask_digest = canonical_json_bytes(&signed_ask.body)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|error| release_unreserved_capacity(execution_internal(error)))?;
        let reservation_id = super::finding_purchase_coordinator::derive_reservation_id(
            &ask_digest,
            &credential.signing_key.public_key().to_hex(),
        );
        if existing_reservation.is_none() && now >= signed_ask.body.expires_at {
            self.release_terminal_capacity(authenticated, request, &request_sha256)?;
            return Err(FindingPurchaseExecutionError::Rejected(
                "prepared purchase ask expired before reservation".to_owned(),
            ));
        }
        let coordinator = self.coordinator().map_err(&release_unreserved_capacity)?;
        match coordinator.resolve(&reservation_id) {
            Ok(existing) if existing.state == FindingPurchaseReservationState::Consumed => {
                self.reserve_terminal_capacity(authenticated, request, &request_sha256)?;
                return self.recover_terminal(authenticated, request, &reservation_id);
            }
            Ok(existing) if existing.state == FindingPurchaseReservationState::Released => {
                return self.recover_released_reservation(
                    authenticated,
                    request,
                    &request_sha256,
                    &reservation_id,
                );
            }
            Ok(existing) if existing.state == FindingPurchaseReservationState::Expired => {
                self.release_terminal_capacity(authenticated, request, &request_sha256)?;
                return Err(FindingPurchaseExecutionError::Rejected(
                    "durable purchase reservation expired before recovery".to_owned(),
                ));
            }
            Ok(_) | Err(PurchaseCoordinatorError::UnknownReservation) => {}
            Err(error) => {
                return Err(release_unreserved_capacity(execution_internal(error)));
            }
        }
        self.reserve_terminal_capacity(authenticated, request, &request_sha256)?;
        #[cfg(test)]
        if self
            .stop_after_terminal_capacity_once
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(FindingPurchaseExecutionError::Pending(
                "test interruption after durable terminal-capacity reservation".to_owned(),
            ));
        }
        let reservation_receipt = coordinator
            .reserve_for_public_request(
                bid,
                signed_ask,
                &job.buyer_signature,
                &bundle.admission,
                &bundle.seller_authorization,
                bundle
                    .market_terms
                    .body
                    .backing_requirement
                    .maximum_sale_exposure
                    .units,
                request.deadline_secs.unwrap_or(3_600),
                job.prepared_at,
                &public_request,
            )
            .map_err(|error| {
                release_terminal_capacity_after_error(
                    &self.bundle_store,
                    authenticated,
                    request,
                    &request_sha256,
                    execution_internal(error),
                )
            })?;
        #[cfg(test)]
        if self
            .stop_after_reservation_once
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(FindingPurchaseExecutionError::Pending(
                "test interruption after durable reservation".to_owned(),
            ));
        }
        if let Some(expected) = existing_reservation.as_ref() {
            if expected.reservation_id != reservation_id {
                return Err(FindingPurchaseExecutionError::Pending(
                    "prepared purchase job names a different reservation".to_owned(),
                ));
            }
        }
        let release_predispatch = |original| {
            release_predispatch_reservation(
                &coordinator,
                &self.bundle_store,
                authenticated,
                request,
                &request_sha256,
                &reservation_id,
                now,
                original,
            )
        };
        let verified_reservation = VerifiedReservationReceipt::from_signed(
            &reservation_receipt,
            &self.keys.purchase.public_key(),
        )
        .map_err(|error| release_predispatch(execution_internal(error)))?;
        let accepted = accept_finding_purchase(
            &ask,
            &verified_reservation,
            &credential.signing_key,
            job.prepared_at,
            &witness,
            &bundle.finding,
        )
        .map_err(|error| release_predispatch(execution_internal(error)))?;
        coordinator
            .reserve_slot(&reservation_id, now)
            .map_err(|error| release_predispatch(execution_internal(error)))?;
        #[cfg(test)]
        if self
            .fail_predispatch_once
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(release_predispatch(execution_internal(
                "test pre-dispatch failure",
            )));
        }
        let context_b64 = purchase_context_b64(
            &bundle,
            bid,
            &ask,
            &accepted,
            &reservation_receipt,
            &reservation_id,
        )
        .map_err(&release_predispatch)?;
        let publisher = FindingStatusEpochPublisher::new(
            self.authority.finding_status_store(),
            self.market.status_feed_operator.clone(),
            self.market.status_feed_service_bond.clone(),
            self.keys.status_operator.clone(),
            self.market.status_max_epoch_age_secs,
        )
        .map_err(|error| release_predispatch(execution_internal(error)))?;
        let status = publisher
            .publish_non_inclusion(&request.finding_id, &[], now)
            .map_err(|error| release_predispatch(execution_internal(error)))?;
        let status_proof_b64 = STANDARD.encode(status.proof_bytes);
        let arguments = serde_json::json!({"finding_id": request.finding_id});
        let capability = ask.body.token_offer.clone();
        let dpop = DpopProof::sign(
            DpopProofBody {
                schema: DPOP_SCHEMA.to_owned(),
                capability_id: capability.id.clone(),
                tool_server: bundle.admission.body.server_id.clone(),
                tool_name: READ_FINDING_TOOL.to_owned(),
                action_hash: sha256_hex(
                    &canonical_json_bytes(&arguments)
                        .map_err(|error| release_predispatch(execution_internal(error)))?,
                ),
                nonce: request.request_id.clone(),
                issued_at: now,
                agent_key: credential.signing_key.public_key(),
            },
            &credential.signing_key,
        )
        .map_err(|error| release_predispatch(execution_internal(error)))?;
        let kernel = self.build_kernel(&bundle).map_err(&release_predispatch)?;
        let response = kernel
            .evaluate_tool_call_blocking(&ToolCallRequest {
                request_id: request.request_id.clone(),
                capability,
                tool_name: READ_FINDING_TOOL.to_owned(),
                server_id: bundle.admission.body.server_id.clone(),
                agent_id: credential.signing_key.public_key().to_hex(),
                arguments,
                dpop_proof: Some(dpop),
                execution_nonce: None,
                governed_intent: Some(governed_reveal_intent(
                    &request.request_id,
                    &bundle.admission.body.server_id,
                    &context_b64,
                    &status_proof_b64,
                )),
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .map_err(|error| release_predispatch(execution_internal(error)))?;
        #[cfg(test)]
        if self
            .stop_after_kernel_response_once
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(FindingPurchaseExecutionError::Pending(
                "test interruption after durable kernel response".to_owned(),
            ));
        }
        let finalized_at = self.current_time()?;
        let payer_key = credential.signing_key.public_key();
        let result = match response.verdict {
            Verdict::Allow => {
                let output = match response.output.as_ref() {
                    Some(ToolCallOutput::Value(value)) => value,
                    _ => {
                        return Err(FindingPurchaseExecutionError::Internal(
                            "allowed reveal omitted its value".to_owned(),
                        ));
                    }
                };
                let media_type = output
                    .get("media_type")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| execution_internal("reveal media type is missing"))?
                    .to_owned();
                let payload_b64 = output
                    .get("payload_b64")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| execution_internal("reveal payload is missing"))?
                    .to_owned();
                self.authority
                    .finding_purchase_store()
                    .register_community_fund_destination(
                        &bundle.admission.body.backing_allocation_id,
                        &self.market.community_fund_destination,
                        finalized_at,
                    )
                    .map_err(execution_internal)?;
                let record = coordinator
                    .finalize_delivery(
                        &reservation_id,
                        &response.receipt,
                        &bundle.admission,
                        &bundle.bond_backing,
                        finalized_at,
                    )
                    .map_err(execution_internal)?;
                FindingPurchaseResult {
                    schema: FINDING_PURCHASE_RESULT_SCHEMA.to_owned(),
                    request_id: request.request_id.clone(),
                    finding_id: request.finding_id.clone(),
                    payer,
                    payer_key,
                    reservation_id: reservation_id.clone(),
                    purchase_intent_id: record.body.purchase_intent_id.clone(),
                    authoritative_payment_operation_id: record
                        .body
                        .authoritative_payment_operation_id
                        .clone(),
                    verdict: FindingPurchaseVerdict::Allow,
                    settlement: FindingPurchaseSettlementTerminal::Captured,
                    accepted_price: record.body.accepted_price.clone(),
                    realized_spend: record.body.realized_spend.clone(),
                    delivery_receipt: response.receipt,
                    purchase_record: Some(record),
                    failed_delivery: None,
                    output: Some(FindingPurchasedOutput {
                        media_type,
                        payload_b64,
                    }),
                }
            }
            Verdict::Deny => {
                if !matches!(response.receipt.decision, Some(Decision::Deny { .. })) {
                    return Err(execution_internal("denied reveal omitted a Deny receipt"));
                }
                let receipt_bytes =
                    canonical_json_bytes(&response.receipt).map_err(execution_internal)?;
                let tree = MerkleTree::from_leaves(std::slice::from_ref(&receipt_bytes))
                    .map_err(execution_internal)?;
                let checkpoint = build_checkpoint(
                    1,
                    1,
                    1,
                    std::slice::from_ref(&receipt_bytes),
                    &self.keys.kernel,
                )
                .map_err(execution_internal)?;
                let proof = build_inclusion_proof(&tree, 0, checkpoint.body.checkpoint_seq, 1)
                    .map_err(execution_internal)?;
                let failed = coordinator
                    .finalize_denial(
                        &reservation_id,
                        &response.receipt,
                        &bundle.admission,
                        &checkpoint,
                        &proof,
                        finalized_at,
                    )
                    .map_err(execution_internal)?;
                FindingPurchaseResult {
                    schema: FINDING_PURCHASE_RESULT_SCHEMA.to_owned(),
                    request_id: request.request_id.clone(),
                    finding_id: request.finding_id.clone(),
                    payer,
                    payer_key,
                    reservation_id: reservation_id.clone(),
                    purchase_intent_id: derive_purchase_intent_id(&reservation_id),
                    authoritative_payment_operation_id: derive_payment_operation_id(
                        &reservation_id,
                    ),
                    verdict: FindingPurchaseVerdict::Deny,
                    settlement: FindingPurchaseSettlementTerminal::Released,
                    accepted_price: bundle.listing.pricing.body.price_per_call.clone(),
                    realized_spend: MonetaryAmount {
                        units: 0,
                        currency: bundle.listing.pricing.body.price_per_call.currency.clone(),
                    },
                    delivery_receipt: response.receipt,
                    purchase_record: None,
                    failed_delivery: Some(failed),
                    output: None,
                }
            }
            Verdict::PendingApproval => {
                return Err(FindingPurchaseExecutionError::Internal(
                    "finding reveal unexpectedly required approval".to_owned(),
                ));
            }
        };
        Ok(result)
    }
}

#[async_trait::async_trait]
impl FindingPurchaseExecutor for FindingOperatorPurchaseExecutor {
    fn mutation_fence(&self) -> chio_kernel::admission_operation::StoreMutationFence {
        self.authority.mutation_fence()
    }

    fn authenticate_buyer(
        &self,
        bearer_token: &str,
    ) -> Result<AuthenticatedFindingBuyer, FindingBuyerAuthenticationError> {
        let credential = self
            .buyers
            .iter()
            .find(|credential| {
                bool::from(
                    credential
                        .bearer_token
                        .as_bytes()
                        .ct_eq(bearer_token.as_bytes()),
                )
            })
            .ok_or(FindingBuyerAuthenticationError)?;
        let key = credential.signing_key.public_key();
        AuthenticatedFindingBuyer::new(credential.principal_id.clone(), key.to_hex(), key)
            .map_err(|_| FindingBuyerAuthenticationError)
    }

    fn publish_live_status(&self, finding_id: &str, now: u64) -> Result<String, String> {
        let publisher = FindingStatusEpochPublisher::new(
            self.authority.finding_status_store(),
            self.market.status_feed_operator.clone(),
            self.market.status_feed_service_bond.clone(),
            self.keys.status_operator.clone(),
            self.market.status_max_epoch_age_secs,
        )?;
        let proof = publisher.publish_non_inclusion(finding_id, &[], now)?;
        Ok(sha256_hex(&proof.proof_bytes))
    }

    fn public_proof(&self, finding_id: &str) -> Result<Vec<u8>, String> {
        self.bundle_store
            .get_proof(finding_id)
            .map(|record| record.proof_json)
            .map_err(|error| error.to_string())
    }

    async fn execute(
        &self,
        buyer: AuthenticatedFindingBuyer,
        request: FindingPurchaseRequest,
    ) -> Result<FindingPurchaseResult, FindingPurchaseExecutionError> {
        let request_bytes = canonical_json_bytes(&request).map_err(execution_internal)?;
        let request_sha256 = sha256_hex(&request_bytes);
        if let Some(cached) = self.cached_terminal(&buyer, &request, &request_sha256)? {
            return Ok(cached);
        }
        let result = self.execute_new(&buyer, &request).await?;
        self.retain_terminal(&buyer, &request_sha256, &result)?;
        Ok(result)
    }
}

fn purchase_context_b64(
    bundle: &FindingOperatorBundle,
    bid: &SignedBidRequest,
    ask: &VerifiedFindingPurchaseAsk,
    accepted: &SignedAcceptedBid,
    reservation: &SignedReservationReceipt,
    reservation_id: &str,
) -> Result<String, FindingPurchaseExecutionError> {
    let context = FindingPurchaseContext {
        schema: PURCHASE_CONTEXT_SCHEMA.to_owned(),
        finding_json: canonical_string(&bundle.finding)?,
        listing_envelope_json: canonical_string(&bundle.listing.listing)?,
        pricing_hint_envelope_json: canonical_string(&bundle.listing.pricing)?,
        venue_admission_envelope_json: canonical_string(&bundle.admission)?,
        market_terms_envelope_json: canonical_string(&bundle.market_terms)?,
        seller_authorization_envelope_json: canonical_string(&bundle.seller_authorization)?,
        verifier_profile_envelope_json: canonical_string(&bundle.verifier_profile)?,
        seller_backing_envelope_json: canonical_string(&bundle.bond_backing)?,
        verifier_report_envelope_json: canonical_string(&bundle.verifier_report)?,
        bid_request_envelope_json: canonical_string(bid)?,
        ask_response_envelope_json: canonical_string(ask)?,
        accepted_bid_envelope_json: canonical_string(accepted)?,
        reservation_receipt_envelope_json: canonical_string(reservation)?,
        reservation_store_key: reservation_id.to_owned(),
        token_offer_json: canonical_string(&ask.body.token_offer)?,
    };
    context.validate().map_err(execution_internal)?;
    canonical_json_bytes(&context)
        .map(|bytes| STANDARD.encode(bytes))
        .map_err(execution_internal)
}

fn governed_reveal_intent(
    request_id: &str,
    server_id: &str,
    context_b64: &str,
    status_proof_b64: &str,
) -> GovernedTransactionIntent {
    GovernedTransactionIntent {
        id: format!("intent-{request_id}"),
        server_id: server_id.to_owned(),
        tool_name: READ_FINDING_TOOL.to_owned(),
        purpose: "purchased finding reveal".to_owned(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(serde_json::json!({
            FINDING_PURCHASE_CONTEXT_KEY: context_b64,
            FINDING_STATUS_PROOF_CONTEXT_KEY: status_proof_b64,
        })),
        body: GovernedTransactionIntentBody::ToolInvocation,
    }
}

fn canonical_string<T: serde::Serialize>(
    value: &T,
) -> Result<String, FindingPurchaseExecutionError> {
    canonical_json_bytes(value)
        .and_then(|bytes| {
            String::from_utf8(bytes)
                .map_err(|error| chio_core::Error::CanonicalJson(error.to_string()))
        })
        .map_err(execution_internal)
}

fn validate_credential_text(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_CREDENTIAL_TEXT_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

fn unix_timestamp_now() -> Result<u64, FindingPurchaseExecutionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(execution_internal)
}

fn execution_internal(error: impl std::fmt::Display) -> FindingPurchaseExecutionError {
    FindingPurchaseExecutionError::Internal(error.to_string())
}

fn execution_unavailable(error: impl std::fmt::Display) -> FindingPurchaseExecutionError {
    FindingPurchaseExecutionError::Unavailable(error.to_string())
}

fn release_predispatch_reservation(
    coordinator: &FindingPurchaseCoordinator,
    bundle_store: &SqliteFindingOperatorBundleStore,
    buyer: &AuthenticatedFindingBuyer,
    request: &FindingPurchaseRequest,
    request_sha256: &str,
    reservation_id: &str,
    now: u64,
    original: FindingPurchaseExecutionError,
) -> FindingPurchaseExecutionError {
    let reservation_release = coordinator.release(reservation_id, now);
    let capacity_release = bundle_store.release_terminal_capacity(
        &request.request_id,
        buyer.principal_id(),
        request_sha256,
    );
    match (reservation_release, capacity_release) {
        (Ok(()), Ok(_)) => {
            FindingPurchaseExecutionError::Rejected(PREDISPATCH_RELEASE_REJECTION.to_owned())
        }
        (reservation, capacity) => FindingPurchaseExecutionError::Internal(format!(
            "{original}; durable pre-dispatch cleanup failed: reservation={reservation:?}, capacity={capacity:?}"
        )),
    }
}

fn release_terminal_capacity_after_error(
    bundle_store: &SqliteFindingOperatorBundleStore,
    buyer: &AuthenticatedFindingBuyer,
    request: &FindingPurchaseRequest,
    request_sha256: &str,
    original: FindingPurchaseExecutionError,
) -> FindingPurchaseExecutionError {
    match bundle_store.release_terminal_capacity(
        &request.request_id,
        buyer.principal_id(),
        request_sha256,
    ) {
        Ok(_) => original,
        Err(release_error) => FindingPurchaseExecutionError::Internal(format!(
            "{original}; durable terminal-capacity release failed: {release_error}"
        )),
    }
}
