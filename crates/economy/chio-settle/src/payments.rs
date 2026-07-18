use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Mutex;

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolValue;
use chio_core::capability::governance::{GovernedApprovalDecision, GovernedApprovalToken};
use chio_core::capability::scope::MonetaryAmount;
use chio_core::hashing::sha256;
use chio_core::web3::settlement::Web3SettlementDispatchArtifact;
use serde::{Deserialize, Serialize};

use crate::SettlementError;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum X402SettlementMode {
    PrepaidAuthorization,
    EscrowBacked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct X402PaymentRequirements {
    pub version: String,
    pub chain_id: String,
    pub facilitator_url: String,
    pub resource: String,
    pub pay_to: String,
    pub accepted_tokens: Vec<String>,
    pub dispatch_id: String,
    pub capability_id: String,
    pub amount_minor_units: u64,
    pub currency: String,
    pub settlement_mode: X402SettlementMode,
    pub governed_authorization_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Eip3009Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransferWithAuthorizationInput {
    pub from_address: String,
    pub to_address: String,
    pub value_minor_units: u128,
    pub valid_after: u64,
    pub valid_before: u64,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedTransferWithAuthorization {
    pub domain: Eip3009Domain,
    pub authorization: TransferWithAuthorizationInput,
    pub domain_separator: String,
    pub struct_hash: String,
    pub authorization_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CircleNanopaymentPolicy {
    pub enabled: bool,
    pub managed_balance_id: String,
    pub supported_chain_ids: Vec<String>,
    pub supported_token_symbols: Vec<String>,
    pub max_amount_minor_units: u64,
    pub operator_managed_custody_explicit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedCircleNanopayment {
    pub payment_id: String,
    pub managed_balance_id: String,
    pub chain_id: String,
    pub amount_minor_units: u64,
    pub currency: String,
    pub beneficiary_address: String,
    pub dispatch_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Erc4337PaymasterPolicy {
    pub entry_point: String,
    pub paymaster_address: String,
    pub supported_chain_ids: Vec<String>,
    pub max_sponsor_gas_limit: u64,
    pub max_reimbursement_minor_units: u64,
    pub settlement_deduction_explicit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedPaymasterCompatibility {
    pub dispatch_id: String,
    pub chain_id: String,
    pub entry_point: String,
    pub paymaster_address: String,
    pub user_operation_hash: String,
    pub sponsor_gas_limit: u64,
    pub estimated_reimbursement_minor_units: u64,
    pub allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
}

pub fn build_x402_payment_requirements(
    dispatch: &Web3SettlementDispatchArtifact,
    facilitator_url: &str,
    resource: &str,
    accepted_tokens: Vec<String>,
    settlement_mode: X402SettlementMode,
) -> Result<X402PaymentRequirements, SettlementError> {
    validate_x402_field("facilitator URL", facilitator_url)?;
    validate_x402_field("resource", resource)?;
    if accepted_tokens.is_empty() {
        return Err(SettlementError::InvalidInput(
            "x402 compatibility requires at least one accepted token".to_string(),
        ));
    }
    for (index, token) in accepted_tokens.iter().enumerate() {
        validate_x402_field(&format!("accepted token {index}"), token)?;
    }
    Ok(X402PaymentRequirements {
        version: "x402".to_string(),
        chain_id: dispatch.chain_id.clone(),
        facilitator_url: facilitator_url.to_string(),
        resource: resource.to_string(),
        pay_to: dispatch.beneficiary_address.clone(),
        accepted_tokens,
        dispatch_id: dispatch.dispatch_id.clone(),
        capability_id: dispatch
            .capital_instruction
            .body
            .query
            .capability_id
            .clone()
            .unwrap_or_else(|| dispatch.dispatch_id.clone()),
        amount_minor_units: dispatch.settlement_amount.units,
        currency: dispatch.settlement_amount.currency.clone(),
        settlement_mode,
        governed_authorization_required: true,
    })
}

fn validate_x402_field(label: &str, value: &str) -> Result<(), SettlementError> {
    if value.trim().is_empty() {
        return Err(SettlementError::InvalidInput(format!(
            "x402 compatibility requires {label}"
        )));
    }
    if value.trim() != value || value.chars().any(char::is_whitespace) {
        return Err(SettlementError::InvalidInput(format!(
            "x402 compatibility {label} must not contain whitespace"
        )));
    }
    Ok(())
}

/// Approval-bound settlement parameters the caller MUST supply.
///
/// EIP-3009 authorizations are independently replay-able and are not, by
/// themselves, tied to the approval that governs the spend. This binding
/// requires the prepared authorization to be bound to its governing
/// approval so a captured signature cannot be redirected to a different
/// payee, inflated to a different amount, or replayed on a different chain.
///
/// This type is the seam to the governed-approval layer: once a verified
/// [`chio_core_types::capability::governance::GovernedApprovalToken`] is
/// available at the settlement layer, the caller derives these bound
/// values from that token's governed intent and passes them here. Until
/// then, the caller is the trust boundary that MUST extract the values
/// from the verified approval before calling
/// [`prepare_transfer_with_authorization`]. Either way the bound values
/// are asserted against the authorization and any mismatch fails closed.
///
/// The `GovernedApprovalToken` itself does not carry chain/amount/payee/token
/// as discrete fields (they are folded into its `governed_intent_hash`), so
/// this layer cannot re-derive them from the token alone; it asserts the
/// explicitly-bound values the caller resolved from the verified intent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBinding {
    /// Chain id the governing approval authorized the spend on. Must equal
    /// the EIP-3009 domain `chain_id`.
    pub chain_id: u64,
    /// Payee the governing approval authorized. Must equal the EIP-3009
    /// authorization `to` address (case-insensitive hex / checksum).
    pub payee_address: String,
    /// Amount in token minor units the governing approval authorized. Must
    /// equal the EIP-3009 authorization `value`.
    pub amount_minor_units: u128,
    /// Token/currency symbol the governing approval authorized (for example
    /// `"USDC"`). The chain id alone does not pin the token: a captured
    /// authorization for one token contract can otherwise be redirected to a
    /// different token on the same chain with the same payee and numeric
    /// amount. Each lane asserts its lane-specific token identity against
    /// this symbol (x402 accepted tokens, Circle token symbol). Compared
    /// case-insensitively after trimming.
    pub token_symbol: String,
    /// Token contract address the governing approval authorized (for example
    /// the USDC contract on the target chain). It is asserted against the
    /// EIP-3009 domain `verifying_contract`, which is the contract the signed
    /// transfer actually targets, so a captured authorization cannot be
    /// redirected to a different token contract on the same chain. Compared as
    /// parsed `Address` bytes so checksum vs lowercase hex compare equal.
    ///
    /// REQUIRED for the EIP-3009 lane: [`prepare_transfer_with_authorization`]
    /// fails closed when this is `None`, because a symbol alone cannot pin the
    /// on-chain token. The field stays `Option` only because lanes that
    /// identify their token by symbol and have no contract to compare against
    /// (the x402 accepted-token list and the Circle token symbol) still bind
    /// via `token_symbol` and legitimately leave this `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_contract: Option<String>,
    /// Approval expiry as a Unix timestamp in seconds. The prepared
    /// authorization MUST NOT outlive the governing approval: when an
    /// EIP-3009 `valid_before` would let a signed transfer stay broadcastable
    /// past this instant, preparation fails closed. Binds the off-chain
    /// authorization window to the approval window so a captured signature
    /// cannot be broadcast after the approval that governs it has expired.
    pub approval_expires_at: u64,
}

impl ApprovalBinding {
    /// Assert that a lane's token symbol matches the approval-bound token.
    ///
    /// Comparison is case-insensitive after trimming so `"usdc"`, `" USDC "`,
    /// and `"USDC"` are treated as the same token. Used by lanes that
    /// identify their token by symbol rather than by contract address (the
    /// x402 accepted-token list and the Circle token symbol). Fails closed
    /// on any mismatch so a captured authorization for one token cannot be
    /// redirected to a different token the approval never authorized.
    pub fn assert_token_symbol(
        &self,
        lane: &str,
        lane_token_symbol: &str,
    ) -> Result<(), SettlementError> {
        if !lane_token_symbol
            .trim()
            .eq_ignore_ascii_case(self.token_symbol.trim())
        {
            return Err(SettlementError::InvalidBinding(format!(
                "{lane} token mismatch: lane token {lane_token_symbol:?} is not the \
                 approval-bound token {:?}",
                self.token_symbol
            )));
        }
        Ok(())
    }
}

/// Outcome of a [`Eip3009NonceStore::record_if_fresh`] call.
///
/// Mirrors the `RecordOutcome` contract in
/// `chio-custody-hw::nonce_store` for consistency across the trust
/// boundaries: recording a fresh nonce returns [`NonceOutcome::Fresh`];
/// a previously-seen nonce returns [`NonceOutcome::Replayed`] and the
/// caller MUST abort settlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceOutcome {
    /// The `(authorizer, nonce)` pair was not present and has now been
    /// recorded.
    Fresh,
    /// The pair was already present. Settlement MUST fail closed.
    Replayed,
}

/// Default hard capacity for retained EIP-3009 authorization nonces.
///
/// A malicious or buggy client can present an unbounded stream of distinct
/// nonces. The store fails closed once this many entries are retained and
/// relies on the explicit [`Eip3009NonceStore::gc_expired`] path to reopen
/// capacity. Mirrors `DEFAULT_MAX_NONCE_ENTRIES` in `chio-custody-hw`.
pub const DEFAULT_MAX_EIP3009_NONCE_ENTRIES: usize = 65_536;

/// Single-use nonce store for EIP-3009 authorization replay resistance.
///
/// This is the trust-boundary surface settlement consults BEFORE
/// preparing a transfer. The store is keyed on the EIP-3009 authorizer
/// (`from` address) and a nonce key that scopes the 32-byte authorization
/// `nonce` to its EIP-712 domain (chain id + verifying contract): per
/// EIP-3009 the `(from, nonce)` pair is consumed on-chain by a SPECIFIC
/// token contract, so the same nonce value is an independent spend on a
/// different token or chain. Recording the domain-scoped pair here makes
/// the off-chain preparation path single-use per token contract as well,
/// closing the replay window before a signature is ever broadcast without
/// rejecting a legitimate reuse of the same nonce on a different contract.
///
/// [`prepare_transfer_with_authorization`] keys the store on the canonical
/// `0x` lowercase hex of the PARSED `from`/`nonce` bytes (with the chain id
/// and verifying contract folded into the nonce key), so a re-prefixed or
/// re-cased submission of the same authorization on the same domain maps to
/// the same entry. Implementations additionally lowercase the supplied key
/// defensively, so direct callers cannot evade detection through casing
/// either.
///
/// Implementations are `Send + Sync` so callers can hold them in an
/// `Arc<dyn Eip3009NonceStore>`. The contract intentionally mirrors
/// `chio_custody_hw::nonce_store::PasskeyNonceStore`:
///
/// - `record_if_fresh` is the only mutating entry point and MUST be
///   atomic with respect to concurrent calls, so two parallel replays of
///   the same `(from, nonce)` cannot both observe `Fresh`.
/// - Any present entry is treated as a replay; the record path never
///   prunes. `gc_expired` is the only entry point that drops entries, so
///   replay decisions stay decoupled from the wall clock.
pub trait Eip3009NonceStore: Send + Sync {
    /// Record `(from_address, nonce)` for replay detection.
    ///
    /// `retain_until_unix_seconds` is the time the entry stays GC-able
    /// until (typically the authorization `valid_before`). Atomicity:
    /// two concurrent calls with the same key cannot both observe
    /// [`NonceOutcome::Fresh`].
    fn record_if_fresh(
        &self,
        from_address: &str,
        nonce: &str,
        retain_until_unix_seconds: u64,
    ) -> Result<NonceOutcome, SettlementError>;

    /// Sweep entries whose retention bound is below `now_unix_seconds`.
    ///
    /// Returns the number of records pruned. Advisory: failing to run it
    /// never causes a false [`NonceOutcome::Fresh`].
    fn gc_expired(&self, now_unix_seconds: u64) -> Result<usize, SettlementError>;

    /// Number of currently retained entries. Used by tests and metrics.
    fn len(&self) -> Result<usize, SettlementError>;

    /// True if no entries are retained.
    fn is_empty(&self) -> Result<bool, SettlementError> {
        Ok(self.len()? == 0)
    }
}

/// Internal map keyed on `(from_address, nonce)` whose value is the
/// Unix-seconds retention bound past which the entry is GC-able. Keys are
/// canonicalized (optional `0x` prefix stripped, then lowercased) so that
/// checksum-cased, lowercase, and `0x`-prefixed-vs-bare hex all map to the
/// same entry and cannot evade replay detection.
type Eip3009NonceMap = HashMap<(String, String), u64>;

/// Canonicalize a hex key component for the nonce store: strip an optional
/// `0x`/`0X` prefix and lowercase. This makes `"0xABC"`, `"0xabc"`, and
/// `"abc"` collapse to the same key so prefix/casing formatting cannot be
/// used to replay a previously-seen `(from, nonce)` pair as `Fresh`.
fn canonicalize_nonce_key_component(value: &str) -> String {
    let trimmed = value.trim();
    let without_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    without_prefix.to_ascii_lowercase()
}

/// Process-local single-use EIP-3009 nonce store.
///
/// Backed by `Mutex<Eip3009NonceMap>`. Suitable for tests and
/// single-process deployments; replay state is lost on restart. Durable
/// deployments back the [`Eip3009NonceStore`] trait with
/// `chio_store_sqlite::SqliteEip3009NonceStore`, which persists nonces
/// across restarts and cannot wedge at capacity (its caller drives
/// `gc_expired` explicitly).
pub struct InMemoryEip3009NonceStore {
    inner: Mutex<Eip3009NonceMap>,
    max_entries: usize,
}

impl Default for InMemoryEip3009NonceStore {
    fn default() -> Self {
        Self::with_max_entries(DEFAULT_MAX_EIP3009_NONCE_ENTRIES)
    }
}

impl InMemoryEip3009NonceStore {
    /// Build a fresh store with the default hard capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a fresh store with a custom hard capacity.
    #[must_use]
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_entries,
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Eip3009NonceMap>, SettlementError> {
        self.inner.lock().map_err(|err| {
            SettlementError::InvalidBinding(format!("EIP-3009 nonce store mutex poisoned: {err}"))
        })
    }
}

impl Eip3009NonceStore for InMemoryEip3009NonceStore {
    fn record_if_fresh(
        &self,
        from_address: &str,
        nonce: &str,
        retain_until_unix_seconds: u64,
    ) -> Result<NonceOutcome, SettlementError> {
        let key = (
            canonicalize_nonce_key_component(from_address),
            canonicalize_nonce_key_component(nonce),
        );
        let mut guard = self.lock()?;

        // Fail-closed: any present entry, even past its retention bound,
        // is treated as a replay. `gc_expired` is the ONLY entry point
        // that drops entries; the record path never prunes so replay
        // decisions stay decoupled from the wall clock.
        if guard.contains_key(&key) {
            return Ok(NonceOutcome::Replayed);
        }
        if guard.len() >= self.max_entries {
            return Err(SettlementError::InvalidBinding(format!(
                "EIP-3009 nonce store capacity exceeded: {} retained entries (max {})",
                guard.len(),
                self.max_entries
            )));
        }
        guard.insert(key, retain_until_unix_seconds);
        Ok(NonceOutcome::Fresh)
    }

    fn gc_expired(&self, now_unix_seconds: u64) -> Result<usize, SettlementError> {
        let mut guard = self.lock()?;
        let before = guard.len();
        guard.retain(|_, retain_until| *retain_until >= now_unix_seconds);
        Ok(before - guard.len())
    }

    fn len(&self) -> Result<usize, SettlementError> {
        Ok(self.lock()?.len())
    }
}

/// Prepare an EIP-3009 `transferWithAuthorization` digest, enforcing the
/// money-safety invariants before any signature is broadcast:
///
/// 1. **Single-use nonce.** `nonce_store.record_if_fresh(from, nonce)` is
///    consulted first; a previously-seen `(from, nonce)` pair fails closed
///    with [`SettlementError::InvalidBinding`], rejecting replays.
/// 2. **Time window vs. now.** The authorization is accepted only when
///    `valid_before > now_unix_seconds > valid_after`; an expired or
///    not-yet-valid window fails closed.
/// 3. **Authorization must not outlive the approval.** The EIP-3009
///    `valid_before` must not exceed `binding.approval_expires_at`. A signed
///    transfer stays broadcastable on-chain until `valid_before`, so an
///    authorization whose window outlasts the governing approval is rejected
///    to keep the off-chain spend bounded by the approval window.
/// 4. **Approval binding.** The domain `chain_id`, authorization `to`
///    (payee), `value` (amount), and token identity (the domain
///    `verifying_contract` against the REQUIRED `binding.token_contract`) are
///    asserted against `binding`; any mismatch (or an absent token contract)
///    fails closed. The caller resolves `binding` from the verified governing
///    approval from governed approval validation.
///
/// All checks fail closed. The nonce is recorded only after the time-window,
/// expiry, and binding checks pass, so a rejected authorization does not burn
/// its nonce.
pub fn prepare_transfer_with_authorization(
    domain: Eip3009Domain,
    authorization: TransferWithAuthorizationInput,
    binding: &ApprovalBinding,
    now_unix_seconds: u64,
    nonce_store: &dyn Eip3009NonceStore,
) -> Result<PreparedTransferWithAuthorization, SettlementError> {
    if domain.name.trim().is_empty()
        || domain.version.trim().is_empty()
        || domain.verifying_contract.trim().is_empty()
    {
        return Err(SettlementError::InvalidInput(
            "EIP-3009 domain fields are required".to_string(),
        ));
    }
    if authorization.from_address.trim().is_empty()
        || authorization.to_address.trim().is_empty()
        || authorization.nonce.trim().is_empty()
    {
        return Err(SettlementError::InvalidInput(
            "EIP-3009 authorization requires from, to, and nonce".to_string(),
        ));
    }
    if authorization.value_minor_units == 0
        || authorization.valid_before <= authorization.valid_after
    {
        return Err(SettlementError::InvalidInput(
            "EIP-3009 authorization requires non-zero value and a valid time window".to_string(),
        ));
    }

    let verifying_contract = Address::from_str(&domain.verifying_contract)
        .map_err(|error| SettlementError::InvalidInput(error.to_string()))?;
    let from = Address::from_str(&authorization.from_address)
        .map_err(|error| SettlementError::InvalidInput(error.to_string()))?;
    let to = Address::from_str(&authorization.to_address)
        .map_err(|error| SettlementError::InvalidInput(error.to_string()))?;
    let nonce = B256::from_str(&authorization.nonce)
        .map_err(|error| SettlementError::InvalidInput(error.to_string()))?;

    // (2) Time window vs. current time: accept only when
    // valid_before > now > valid_after. Fail closed outside the window.
    if now_unix_seconds <= authorization.valid_after {
        return Err(SettlementError::InvalidBinding(format!(
            "EIP-3009 authorization is not yet valid: now {now_unix_seconds} <= validAfter {}",
            authorization.valid_after
        )));
    }
    if now_unix_seconds >= authorization.valid_before {
        return Err(SettlementError::InvalidBinding(format!(
            "EIP-3009 authorization is expired: now {now_unix_seconds} >= validBefore {}",
            authorization.valid_before
        )));
    }

    // (3) Authorization must not outlive the governing approval. A signed
    // transfer remains broadcastable on-chain until valid_before, so reject
    // any authorization whose window outlasts approval_expires_at. Fail
    // closed so a captured signature cannot be broadcast after the approval
    // that governs it has expired.
    if authorization.valid_before > binding.approval_expires_at {
        return Err(SettlementError::InvalidBinding(format!(
            "EIP-3009 authorization outlives approval: validBefore {} > approval expiry {}",
            authorization.valid_before, binding.approval_expires_at
        )));
    }

    // (4) Approval binding: chain / payee / amount / token must match the
    // governing approval. Parse the bound payee through the same address
    // codec so checksum vs. lowercase hex compare equal. Fail closed on
    // any mismatch.
    if domain.chain_id != binding.chain_id {
        return Err(SettlementError::InvalidBinding(format!(
            "EIP-3009 chain mismatch: domain chain_id {} != approval-bound chain_id {}",
            domain.chain_id, binding.chain_id
        )));
    }
    let bound_payee = Address::from_str(&binding.payee_address).map_err(|error| {
        SettlementError::InvalidBinding(format!("approval-bound payee address invalid: {error}"))
    })?;
    if to != bound_payee {
        return Err(SettlementError::InvalidBinding(
            "EIP-3009 payee mismatch: authorization `to` is not the approval-bound payee"
                .to_string(),
        ));
    }
    if authorization.value_minor_units != binding.amount_minor_units {
        return Err(SettlementError::InvalidBinding(format!(
            "EIP-3009 amount mismatch: authorization value {} != approval-bound amount {}",
            authorization.value_minor_units, binding.amount_minor_units
        )));
    }
    // Token contract: the domain `verifying_contract` selects the token the
    // signed transfer actually moves. The EIP-3009 lane REQUIRES the approval
    // to pin a token contract: a symbol alone does not identify the on-chain
    // token, so a captured authorization could otherwise be redirected to a
    // different token contract on the same chain with the same payee and
    // numeric amount. Fail closed when the binding carries no contract, then
    // assert the domain contract equals it. Compare parsed Address bytes so
    // checksum vs lowercase hex compare equal. (`verifying_contract` was
    // already parsed above.)
    let bound_token_contract = binding.token_contract.as_deref().ok_or_else(|| {
        SettlementError::InvalidBinding(
            "EIP-3009 requires an approval-bound token contract: a symbol alone cannot pin \
             the on-chain token the signed transfer targets"
                .to_string(),
        )
    })?;
    let bound_contract = Address::from_str(bound_token_contract.trim()).map_err(|error| {
        SettlementError::InvalidBinding(format!(
            "approval-bound token contract address invalid: {error}"
        ))
    })?;
    if verifying_contract != bound_contract {
        return Err(SettlementError::InvalidBinding(
            "EIP-3009 token contract mismatch: domain verifyingContract is not the \
             approval-bound token contract"
                .to_string(),
        ));
    }

    // (1) Single-use nonce: record AFTER the cheap fail-closed checks so a
    // rejected authorization does not consume its nonce, but BEFORE
    // returning a broadcastable digest so the first successful preparation
    // is the only one. Retain until the authorization's own expiry.
    //
    // Key the store on the PARSED canonical bytes (`from` Address, `nonce`
    // B256) rendered as their canonical lowercase `0x` hex, not on the
    // caller's raw text. `Address::from_str`/`B256::from_str` accept both
    // `0x`-prefixed and bare hex and either casing, so two submissions that
    // differ only in prefix/casing would otherwise lowercase to DIFFERENT
    // raw keys and the second would be treated as Fresh, evading replay
    // detection. Canonicalizing here closes that gap.
    //
    // Scope the nonce by the EIP-712 domain (chain id + verifying contract)
    // as well. Per EIP-3009 the same random `(from, nonce)` is an independent
    // authorization on each token contract (and chain): the on-chain nonce
    // state lives in the token contract, and the domain separator already
    // distinguishes the signatures. Keying only on `(from, nonce)` would
    // reject a legitimate second authorization that reuses the same nonce
    // value for a different token (for example USDC vs EURC) or chain. Folding
    // the chain id and canonical verifying-contract bytes into the nonce key
    // keeps each (chain, contract, from, nonce) tuple distinct while still
    // canonicalizing the parsed bytes.
    let canonical_from = format!("0x{}", hex::encode(from.as_slice()));
    let canonical_contract = format!("0x{}", hex::encode(verifying_contract.as_slice()));
    let canonical_nonce = format!(
        "{}:{}:0x{}",
        domain.chain_id,
        canonical_contract,
        hex::encode(nonce.as_slice())
    );
    // Caller-driven GC: pruning stays out of the record path by contract,
    // so this now-bearing verify path sweeps expired entries when the store
    // nears capacity, using the same clock it already validated the
    // authorization window against.
    if let Ok(len) = nonce_store.len() {
        if len >= (DEFAULT_MAX_EIP3009_NONCE_ENTRIES / 8) * 7 {
            let _ = nonce_store.gc_expired(now_unix_seconds);
        }
    }
    match nonce_store.record_if_fresh(
        &canonical_from,
        &canonical_nonce,
        authorization.valid_before,
    )? {
        NonceOutcome::Fresh => {}
        NonceOutcome::Replayed => {
            return Err(SettlementError::InvalidBinding(
                "EIP-3009 authorization nonce has already been used (replay rejected)".to_string(),
            ));
        }
    }

    let domain_typehash = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let domain_separator = keccak256(
        (
            domain_typehash,
            keccak256(domain.name.as_bytes()),
            keccak256(domain.version.as_bytes()),
            U256::from(domain.chain_id),
            verifying_contract,
        )
            .abi_encode(),
    );
    let auth_typehash = keccak256(
        b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
    );
    let struct_hash = keccak256(
        (
            auth_typehash,
            from,
            to,
            U256::from(authorization.value_minor_units),
            U256::from(authorization.valid_after),
            U256::from(authorization.valid_before),
            nonce,
        )
            .abi_encode(),
    );
    let mut digest_bytes = Vec::with_capacity(66);
    digest_bytes.extend_from_slice(&[0x19, 0x01]);
    digest_bytes.extend_from_slice(domain_separator.as_slice());
    digest_bytes.extend_from_slice(struct_hash.as_slice());
    let authorization_digest = keccak256(digest_bytes);

    Ok(PreparedTransferWithAuthorization {
        domain,
        authorization,
        domain_separator: format!("0x{}", hex::encode(domain_separator)),
        struct_hash: format!("0x{}", hex::encode(struct_hash)),
        authorization_digest: format!("0x{}", hex::encode(authorization_digest)),
    })
}

/// Resolved EVM rail parameters sourced from operator config.
///
/// Carries the on-chain identity of a seller's payment rail (chain, token
/// contract, payee address) as resolved by the CLI/control-plane layer from
/// the operator-configured seller-to-rail table. The kernel adapter stays
/// rail-agnostic; the caller resolves and validates the rail before bridging
/// to [`ApprovalBinding`] via [`approval_binding_from_governed`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RailBinding {
    /// EVM chain id for the target payment rail.
    pub chain_id: u64,
    /// Token contract address for the stablecoin on this rail (e.g. USDC).
    pub token_contract: String,
    /// Payee (seller) address that receives the transfer on this rail.
    pub payee_address: String,
    /// Token decimal precision (informational; not asserted at the binding layer).
    pub token_decimals: u8,
    /// Token symbol (e.g. `"USDC"`). Asserted case-insensitively by the
    /// token-symbol binding check on the approval.
    pub token_symbol: String,
}

/// Bridge a verified [`GovernedApprovalToken`] and a resolved [`RailBinding`]
/// into an [`ApprovalBinding`] suitable for [`prepare_transfer_with_authorization`].
///
/// The caller is the trust boundary: it resolves the rail from the operator
/// config and independently supplies the amount and approval expiry that the
/// verified token authorizes. The token is consulted for its `decision` and
/// its `expires_at`; the discrete rail fields (chain, token contract, payee,
/// symbol) come from the operator-configured [`RailBinding`] the caller
/// resolved and the caller-supplied `amount_minor_units` and
/// `approval_expires_at`.
///
/// The effective binding expiry is clamped to `min(approval_expires_at,
/// token.expires_at)`. The signed approval cannot justify any spend after it
/// lapses, so the binding must never outlive `token.expires_at`. A caller may
/// legitimately request a tighter (shorter) window for a specific dispatch and
/// that shorter value is preserved; a value later than the token's own expiry
/// is narrowed to the token expiry. Clamping only shrinks the window, so no
/// caller input can produce a binding whose
/// [`ApprovalBinding::approval_expires_at`] outlives the approval token, and
/// the invariant [`prepare_transfer_with_authorization`] enforces
/// (`validBefore <= approval_expires_at`) holds structurally at this bridge.
///
/// Fails closed when:
/// - `token.decision` is not [`GovernedApprovalDecision::Approved`].
/// - Any required rail field is empty.
/// - `amount_minor_units` is zero.
pub fn approval_binding_from_governed(
    token: &GovernedApprovalToken,
    rail: &RailBinding,
    amount_minor_units: u128,
    approval_expires_at: u64,
) -> Result<ApprovalBinding, SettlementError> {
    if token.decision != GovernedApprovalDecision::Approved {
        return Err(SettlementError::InvalidBinding(
            "governed approval token is not approved".to_string(),
        ));
    }
    if rail.token_contract.trim().is_empty() {
        return Err(SettlementError::InvalidInput(
            "rail binding requires a non-empty token contract".to_string(),
        ));
    }
    if rail.payee_address.trim().is_empty() {
        return Err(SettlementError::InvalidInput(
            "rail binding requires a non-empty payee address".to_string(),
        ));
    }
    if rail.token_symbol.trim().is_empty() {
        return Err(SettlementError::InvalidInput(
            "rail binding requires a non-empty token symbol".to_string(),
        ));
    }
    if amount_minor_units == 0 {
        return Err(SettlementError::InvalidInput(
            "rail binding requires a non-zero amount".to_string(),
        ));
    }
    Ok(ApprovalBinding {
        chain_id: rail.chain_id,
        payee_address: rail.payee_address.clone(),
        amount_minor_units,
        token_symbol: rail.token_symbol.clone(),
        token_contract: Some(rail.token_contract.clone()),
        // Clamp to the token's own expiry: the signed approval cannot justify
        // any spend after it lapses, so the effective binding window must never
        // outlive `token.expires_at`. A shorter caller value is a legitimately
        // tighter window and is preserved; a later value is narrowed to the
        // token's expiry. Clamping only shrinks the window, so no caller input
        // can produce a binding that outlives the approval that justified it.
        approval_expires_at: approval_expires_at.min(token.expires_at),
    })
}

/// Versioned schema identifier for off-chain settlement receipts.
pub const CHIO_OFFCHAIN_SETTLEMENT_RECEIPT_SCHEMA: &str = "chio.settle.offchain_receipt.v1";

/// Prepare-only off-chain settlement receipt binding the EIP-3009
/// authorization digest to a governed receipt.
///
/// Minted after a successful [`prepare_transfer_with_authorization`] call.
/// No broadcast path exists in this crate: this artifact records that an
/// authorization was prepared and binds it to the governed receipt that
/// authorized the spend. The `execution_nonce_ref` and `hold_ref` fields are
/// reserved linkage fields for the comptroller surface and are `None` until
/// the corresponding on-chain execution stage is implemented.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OffchainSettlementReceiptArtifact {
    /// Schema identifier. Must equal [`CHIO_OFFCHAIN_SETTLEMENT_RECEIPT_SCHEMA`].
    pub schema: String,
    /// Stable unique identifier for this off-chain settlement receipt.
    pub settlement_receipt_id: String,
    /// Unix timestamp (seconds) when this receipt was issued.
    pub issued_at: u64,
    /// EIP-712 digest from the prepared `transferWithAuthorization` call.
    /// Binds the off-chain authorization to this receipt.
    pub authorization_digest: String,
    /// Receipt id of the governed tool-call receipt that authorized this
    /// spend. Binds the settlement back to the governed receipt so a
    /// captured digest cannot be redirected to a different tool-call receipt.
    pub governed_receipt_id: String,
    /// Settled monetary amount.
    pub settled_amount: MonetaryAmount,
    /// Reserved linkage to the on-chain execution nonce reference used by the
    /// comptroller surface. `None` until on-chain execution is implemented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_nonce_ref: Option<String>,
    /// Reserved linkage to the budget hold that backs this settlement.
    /// `None` until the comptroller hold-linkage stage is implemented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_ref: Option<String>,
    /// Optional human-readable note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Validate an [`OffchainSettlementReceiptArtifact`] for structural integrity.
///
/// Fails closed when:
/// - Any of `schema`, `settlement_receipt_id`, `authorization_digest`, or
///   `governed_receipt_id` is empty.
/// - `settled_amount.units` is zero.
/// - `settled_amount.units` is positive but `settled_amount.currency` is blank
///   (empty or whitespace-only), leaving the paid amount without a denomination.
///
/// `execution_nonce_ref` and `hold_ref` are optional reserved linkage fields
/// and are not validated here.
pub fn validate_offchain_settlement_receipt(
    receipt: &OffchainSettlementReceiptArtifact,
) -> Result<(), SettlementError> {
    if receipt.schema != CHIO_OFFCHAIN_SETTLEMENT_RECEIPT_SCHEMA {
        return Err(SettlementError::InvalidInput(format!(
            "off-chain settlement receipt schema must be \"{CHIO_OFFCHAIN_SETTLEMENT_RECEIPT_SCHEMA}\", got \"{}\"",
            receipt.schema,
        )));
    }
    if receipt.settlement_receipt_id.trim().is_empty() {
        return Err(SettlementError::InvalidInput(
            "off-chain settlement receipt requires a non-empty settlement_receipt_id".to_string(),
        ));
    }
    if receipt.authorization_digest.trim().is_empty() {
        return Err(SettlementError::InvalidInput(
            "off-chain settlement receipt requires a non-empty authorization_digest".to_string(),
        ));
    }
    if receipt.governed_receipt_id.trim().is_empty() {
        return Err(SettlementError::InvalidInput(
            "off-chain settlement receipt requires a non-empty governed_receipt_id".to_string(),
        ));
    }
    if receipt.settled_amount.units == 0 {
        return Err(SettlementError::InvalidInput(
            "off-chain settlement receipt requires a positive settled_amount".to_string(),
        ));
    }
    // A settled amount with positive units but no denomination cannot be
    // reconciled: downstream ledgers and dashboards cannot tell what was paid.
    if receipt.settled_amount.currency.trim().is_empty() {
        return Err(SettlementError::InvalidInput(
            "off-chain settlement receipt requires a non-empty settled_amount.currency".to_string(),
        ));
    }
    Ok(())
}

pub fn evaluate_circle_nanopayment(
    dispatch: &Web3SettlementDispatchArtifact,
    policy: &CircleNanopaymentPolicy,
) -> Result<Option<PreparedCircleNanopayment>, SettlementError> {
    if !policy.enabled {
        return Ok(None);
    }
    if !policy.operator_managed_custody_explicit {
        return Err(SettlementError::InvalidInput(
            "Circle nanopayment policy must keep operator-managed custody explicit".to_string(),
        ));
    }
    if !policy
        .supported_chain_ids
        .iter()
        .any(|chain_id| chain_id == &dispatch.chain_id)
    {
        return Ok(None);
    }
    if !policy
        .supported_token_symbols
        .iter()
        .any(|symbol| symbol == &dispatch.settlement_amount.currency)
    {
        return Ok(None);
    }
    if dispatch.settlement_amount.units > policy.max_amount_minor_units {
        return Ok(None);
    }
    Ok(Some(PreparedCircleNanopayment {
        payment_id: format!(
            "chio-circle-{}",
            &sha256(
                format!(
                    "{}:{}:{}",
                    dispatch.dispatch_id, dispatch.chain_id, dispatch.settlement_amount.units
                )
                .as_bytes()
            )
            .to_hex()[..16]
        ),
        managed_balance_id: policy.managed_balance_id.clone(),
        chain_id: dispatch.chain_id.clone(),
        amount_minor_units: dispatch.settlement_amount.units,
        currency: dispatch.settlement_amount.currency.clone(),
        beneficiary_address: dispatch.beneficiary_address.clone(),
        dispatch_id: dispatch.dispatch_id.clone(),
    }))
}

pub fn prepare_paymaster_compatibility(
    dispatch: &Web3SettlementDispatchArtifact,
    policy: &Erc4337PaymasterPolicy,
    user_operation_hash: &str,
    sponsor_gas_limit: u64,
    estimated_reimbursement_minor_units: u64,
) -> Result<PreparedPaymasterCompatibility, SettlementError> {
    if user_operation_hash.trim().is_empty() {
        return Err(SettlementError::InvalidInput(
            "ERC-4337 compatibility requires a user operation hash".to_string(),
        ));
    }
    let supported_chain = policy
        .supported_chain_ids
        .iter()
        .any(|chain_id| chain_id == &dispatch.chain_id);
    let within_budget = sponsor_gas_limit <= policy.max_sponsor_gas_limit
        && estimated_reimbursement_minor_units <= policy.max_reimbursement_minor_units;
    let allowed = supported_chain && within_budget && policy.settlement_deduction_explicit;
    let rejection_reason = if allowed {
        None
    } else if !supported_chain {
        Some("requested chain is outside the bounded paymaster surface".to_string())
    } else if !policy.settlement_deduction_explicit {
        Some(
            "paymaster reimbursement must remain an explicit settlement-side deduction".to_string(),
        )
    } else {
        Some("requested sponsorship exceeds the bounded gas or reimbursement policy".to_string())
    };

    Ok(PreparedPaymasterCompatibility {
        dispatch_id: dispatch.dispatch_id.clone(),
        chain_id: dispatch.chain_id.clone(),
        entry_point: policy.entry_point.clone(),
        paymaster_address: policy.paymaster_address.clone(),
        user_operation_hash: user_operation_hash.to_string(),
        sponsor_gas_limit,
        estimated_reimbursement_minor_units,
        allowed,
        rejection_reason,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        approval_binding_from_governed, build_x402_payment_requirements,
        evaluate_circle_nanopayment, prepare_paymaster_compatibility,
        prepare_transfer_with_authorization, validate_offchain_settlement_receipt, ApprovalBinding,
        CircleNanopaymentPolicy, Eip3009Domain, Eip3009NonceStore, Erc4337PaymasterPolicy,
        InMemoryEip3009NonceStore, NonceOutcome, OffchainSettlementReceiptArtifact, RailBinding,
        SettlementError, TransferWithAuthorizationInput, X402SettlementMode,
        CHIO_OFFCHAIN_SETTLEMENT_RECEIPT_SCHEMA,
    };
    use chio_core::capability::governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    };
    use chio_core::capability::scope::MonetaryAmount;
    use chio_core::crypto::Keypair;
    use chio_core::web3::settlement::Web3SettlementDispatchArtifact;

    use chio_test_support::prelude::*;

    fn sample_dispatch() -> Web3SettlementDispatchArtifact {
        serde_json::from_str(include_str!(
            "../../../../docs/standards/CHIO_WEB3_SETTLEMENT_DISPATCH_EXAMPLE.json"
        ))
        .test_unwrap()
    }

    const SAMPLE_CHAIN_ID: u64 = 8453;
    const SAMPLE_PAYEE: &str = "0x1000000000000000000000000000000000000002";
    const SAMPLE_VALUE: u128 = 42_000;
    const SAMPLE_VALID_AFTER: u64 = 1_744_000_000;
    const SAMPLE_VALID_BEFORE: u64 = 1_744_000_600;
    /// A `now` strictly inside `(validAfter, validBefore)`.
    const SAMPLE_NOW: u64 = 1_744_000_300;
    const SAMPLE_NONCE: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    /// The token symbol the sample approval authorizes.
    const SAMPLE_TOKEN_SYMBOL: &str = "USDC";
    /// The token contract the sample EIP-3009 domain targets; the sample
    /// binding pins this so the contract-level check passes by default.
    const SAMPLE_TOKEN_CONTRACT: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

    fn sample_domain() -> Eip3009Domain {
        Eip3009Domain {
            name: "USD Coin".to_string(),
            version: "2".to_string(),
            chain_id: SAMPLE_CHAIN_ID,
            verifying_contract: SAMPLE_TOKEN_CONTRACT.to_string(),
        }
    }

    fn sample_authorization() -> TransferWithAuthorizationInput {
        TransferWithAuthorizationInput {
            from_address: "0x1000000000000000000000000000000000000001".to_string(),
            to_address: SAMPLE_PAYEE.to_string(),
            value_minor_units: SAMPLE_VALUE,
            valid_after: SAMPLE_VALID_AFTER,
            valid_before: SAMPLE_VALID_BEFORE,
            nonce: SAMPLE_NONCE.to_string(),
        }
    }

    fn sample_binding() -> ApprovalBinding {
        ApprovalBinding {
            chain_id: SAMPLE_CHAIN_ID,
            payee_address: SAMPLE_PAYEE.to_string(),
            amount_minor_units: SAMPLE_VALUE,
            token_symbol: SAMPLE_TOKEN_SYMBOL.to_string(),
            token_contract: Some(SAMPLE_TOKEN_CONTRACT.to_string()),
            // Approval expiry at least as late as the authorization window so
            // the default sample does not trip the outlives-approval check.
            approval_expires_at: SAMPLE_VALID_BEFORE,
        }
    }

    #[test]
    fn builds_x402_requirements() {
        let dispatch = sample_dispatch();
        let requirements = build_x402_payment_requirements(
            &dispatch,
            "https://facilitator.example/x402",
            "https://tool.example/v1/run",
            vec!["USDC".to_string(), "EURC".to_string()],
            X402SettlementMode::PrepaidAuthorization,
        )
        .test_unwrap();

        assert!(requirements.governed_authorization_required);
        assert_eq!(requirements.dispatch_id, dispatch.dispatch_id);
    }

    #[test]
    fn x402_requirements_reject_blank_accepted_tokens() {
        let dispatch = sample_dispatch();

        let error = build_x402_payment_requirements(
            &dispatch,
            "https://facilitator.example/x402",
            "https://tool.example/v1/run",
            vec!["USDC".to_string(), " ".to_string()],
            X402SettlementMode::PrepaidAuthorization,
        )
        .test_unwrap_err();

        assert!(error.to_string().contains("accepted token"));
    }

    #[test]
    fn prepares_transfer_with_authorization_digest() {
        let store = InMemoryEip3009NonceStore::new();
        let prepared = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap();

        assert!(prepared.authorization_digest.starts_with("0x"));
        assert_eq!(prepared.authorization_digest.len(), 66);
    }

    #[test]
    fn replayed_nonce_is_rejected_on_second_use() {
        let store = InMemoryEip3009NonceStore::new();

        // First preparation with a fresh nonce succeeds.
        let first = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        );
        assert!(first.is_ok(), "first use of a fresh nonce must succeed");

        // Replaying the same authorization (same from + nonce) against the
        // same store must fail closed.
        let replay = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        );
        let error = replay.test_unwrap_err();
        assert!(
            error.to_string().contains("replay"),
            "second use of the same nonce must be rejected by the nonce store, got: {error}"
        );
    }

    #[test]
    fn replay_is_detected_even_with_checksum_cased_address_and_nonce() {
        // EIP-3009 token contracts consume `(from, nonce)`; a re-cased hex
        // string is the same authorizer/nonce and must not bypass replay
        // detection.
        let store = InMemoryEip3009NonceStore::new();
        let _ = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap();

        let mut recased = sample_authorization();
        recased.from_address = recased.from_address.to_uppercase().replace("0X", "0x");
        recased.nonce = recased.nonce.to_uppercase().replace("0X", "0x");
        let replay = prepare_transfer_with_authorization(
            sample_domain(),
            recased,
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        );
        assert!(
            replay.test_unwrap_err().to_string().contains("replay"),
            "case-variant of the same (from, nonce) must still be a replay"
        );
    }

    #[test]
    fn expired_authorization_is_rejected() {
        let store = InMemoryEip3009NonceStore::new();
        // now == validBefore is outside the open window (requires now < validBefore).
        let error = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_VALID_BEFORE,
            &store,
        )
        .test_unwrap_err();
        assert!(
            error.to_string().contains("expired"),
            "an authorization at/after validBefore must be rejected, got: {error}"
        );
        assert!(
            store.is_empty().test_unwrap(),
            "a rejected (expired) authorization must not consume its nonce"
        );
    }

    #[test]
    fn not_yet_valid_authorization_is_rejected() {
        let store = InMemoryEip3009NonceStore::new();
        // now == validAfter is outside the open window (requires now > validAfter).
        let error = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_VALID_AFTER,
            &store,
        )
        .test_unwrap_err();
        assert!(
            error.to_string().contains("not yet valid"),
            "an authorization at/before validAfter must be rejected, got: {error}"
        );
        assert!(
            store.is_empty().test_unwrap(),
            "a rejected (not-yet-valid) authorization must not consume its nonce"
        );
    }

    #[test]
    fn chain_amount_and_payee_binding_mismatches_are_rejected() {
        let store = InMemoryEip3009NonceStore::new();

        // Chain mismatch.
        let mut wrong_chain = sample_binding();
        wrong_chain.chain_id = 1;
        let error = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &wrong_chain,
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap_err();
        assert!(error.to_string().contains("chain mismatch"), "got: {error}");

        // Amount mismatch.
        let mut wrong_amount = sample_binding();
        wrong_amount.amount_minor_units = SAMPLE_VALUE + 1;
        let error = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &wrong_amount,
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap_err();
        assert!(
            error.to_string().contains("amount mismatch"),
            "got: {error}"
        );

        // Payee mismatch.
        let mut wrong_payee = sample_binding();
        wrong_payee.payee_address = "0x1000000000000000000000000000000000000009".to_string();
        let error = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &wrong_payee,
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap_err();
        assert!(error.to_string().contains("payee mismatch"), "got: {error}");

        // None of the rejected bindings may have consumed the nonce.
        assert!(
            store.is_empty().test_unwrap(),
            "binding-mismatch rejections must not consume the nonce"
        );
    }

    #[test]
    fn payee_binding_accepts_checksum_vs_lowercase_hex() {
        // The bound payee may be checksum-cased while the authorization is
        // lowercase (or vice versa); they must compare equal.
        let store = InMemoryEip3009NonceStore::new();
        let mut binding = sample_binding();
        binding.payee_address = SAMPLE_PAYEE.to_uppercase().replace("0X", "0x");
        let prepared = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &binding,
            SAMPLE_NOW,
            &store,
        );
        assert!(
            prepared.is_ok(),
            "checksum vs lowercase payee hex must be treated as the same address"
        );
    }

    #[test]
    fn nonce_store_records_only_after_checks_pass() {
        // A fresh, in-window, correctly-bound authorization records exactly
        // one nonce entry.
        let store = InMemoryEip3009NonceStore::new();
        assert_eq!(
            store.record_if_fresh("0xabc", "0xdef", 0).test_unwrap(),
            NonceOutcome::Fresh
        );
        assert_eq!(
            store.record_if_fresh("0xabc", "0xdef", 0).test_unwrap(),
            NonceOutcome::Replayed
        );
    }

    #[test]
    fn nonce_store_canonicalizes_prefix_and_casing() {
        // The store must collapse `0x`-prefixed vs bare and checksum vs
        // lowercase keys so none of those formatting differences can present
        // the same (from, nonce) pair as Fresh twice.
        let store = InMemoryEip3009NonceStore::new();
        assert_eq!(
            store.record_if_fresh("0xABC", "0xDEF", 0).test_unwrap(),
            NonceOutcome::Fresh
        );
        // Same bytes, prefix stripped and lowercased: must be a replay.
        assert_eq!(
            store.record_if_fresh("abc", "def", 0).test_unwrap(),
            NonceOutcome::Replayed,
            "bare-hex form of an already-recorded 0x-prefixed key must replay"
        );
        // Same bytes, re-cased with prefix: must also replay.
        assert_eq!(
            store.record_if_fresh("0xAbC", "0xDeF", 0).test_unwrap(),
            NonceOutcome::Replayed,
            "re-cased form of an already-recorded key must replay"
        );
    }

    #[test]
    fn replay_is_detected_across_prefixed_and_bare_authorization_forms() {
        // End-to-end: the SAME authorization submitted once with 0x-prefixed
        // from/nonce and again WITHOUT the prefix parses to identical
        // Address/B256 bytes. Keying the store on the parsed canonical bytes
        // means the second submission is a replay, not Fresh.
        let store = InMemoryEip3009NonceStore::new();
        let _ = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap();

        // Strip the `0x` prefix from from/nonce; Address/B256 parse both.
        let mut bare = sample_authorization();
        bare.from_address = bare
            .from_address
            .strip_prefix("0x")
            .unwrap_or(&bare.from_address)
            .to_string();
        bare.nonce = bare
            .nonce
            .strip_prefix("0x")
            .unwrap_or(&bare.nonce)
            .to_string();

        let replay = prepare_transfer_with_authorization(
            sample_domain(),
            bare,
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        );
        assert!(
            replay.test_unwrap_err().to_string().contains("replay"),
            "the unprefixed form of an already-prepared authorization must be a replay"
        );
    }

    #[test]
    fn authorization_outliving_approval_is_rejected() {
        // The EIP-3009 window is open and well-bound, but valid_before runs
        // past the approval's expiry: the signed transfer would stay
        // broadcastable after the approval lapses, so it must fail closed and
        // not consume the nonce.
        let store = InMemoryEip3009NonceStore::new();
        let mut short_approval = sample_binding();
        short_approval.approval_expires_at = SAMPLE_VALID_BEFORE - 1;
        let error = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &short_approval,
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap_err();
        assert!(
            error.to_string().contains("outlives approval"),
            "an authorization that outlives its approval must be rejected, got: {error}"
        );
        assert!(
            store.is_empty().test_unwrap(),
            "an authorization rejected for outliving its approval must not consume its nonce"
        );
    }

    #[test]
    fn authorization_ending_exactly_at_approval_expiry_is_accepted() {
        // valid_before == approval_expires_at is the boundary the approval
        // still covers; it must be accepted.
        let store = InMemoryEip3009NonceStore::new();
        let mut binding = sample_binding();
        binding.approval_expires_at = SAMPLE_VALID_BEFORE;
        let prepared = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &binding,
            SAMPLE_NOW,
            &store,
        );
        assert!(
            prepared.is_ok(),
            "valid_before == approval_expires_at must be within the approval window"
        );
    }

    #[test]
    fn token_contract_mismatch_is_rejected() {
        // The approval is bound to a DIFFERENT token contract than the
        // EIP-3009 domain targets. Even with matching chain, payee, and
        // amount, redirecting to another token on the same chain must fail
        // closed and not consume the nonce.
        let store = InMemoryEip3009NonceStore::new();
        let mut wrong_token = sample_binding();
        wrong_token.token_contract = Some("0x4444444444444444444444444444444444444444".to_string());
        let error = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &wrong_token,
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap_err();
        assert!(
            error.to_string().contains("token contract mismatch"),
            "a different token contract on the same chain must be rejected, got: {error}"
        );
        assert!(
            store.is_empty().test_unwrap(),
            "a token-contract-mismatch rejection must not consume the nonce"
        );
    }

    #[test]
    fn token_contract_binding_accepts_checksum_vs_lowercase_hex() {
        // The bound token contract may be cased differently from the domain
        // verifyingContract; they must compare equal as parsed addresses.
        let store = InMemoryEip3009NonceStore::new();
        let mut binding = sample_binding();
        binding.token_contract = Some(SAMPLE_TOKEN_CONTRACT.to_lowercase());
        let prepared = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &binding,
            SAMPLE_NOW,
            &store,
        );
        assert!(
            prepared.is_ok(),
            "checksum vs lowercase token contract hex must be the same address"
        );
    }

    #[test]
    fn absent_token_contract_is_rejected_for_eip3009() {
        // The EIP-3009 lane REQUIRES a bound token contract: a symbol alone
        // cannot pin the on-chain token, so a captured authorization could be
        // redirected to a different token contract on the same chain. With no
        // bound contract the lane must fail closed and not consume the nonce.
        let store = InMemoryEip3009NonceStore::new();
        let mut binding = sample_binding();
        binding.token_contract = None;
        let error = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &binding,
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires an approval-bound token contract"),
            "an EIP-3009 binding with no token contract must be rejected, got: {error}"
        );
        assert!(
            store.is_empty().test_unwrap(),
            "a binding rejected for an absent token contract must not consume the nonce"
        );
    }

    #[test]
    fn same_nonce_on_a_different_token_contract_is_not_a_replay() {
        // Per EIP-3009 the same `(from, nonce)` is an independent spend on a
        // different token contract: the on-chain nonce state lives in the token
        // contract and the EIP-712 domain separates the signatures. The
        // off-chain store keys the nonce by its domain (chain + verifying
        // contract), so reusing the same nonce value against a different token
        // contract must still be Fresh, not a replay.
        let store = InMemoryEip3009NonceStore::new();
        let first = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        );
        assert!(first.is_ok(), "first use of a fresh nonce must succeed");

        // A different token contract on the same chain, with a binding that
        // pins that contract. Same from + nonce value, different domain.
        const OTHER_TOKEN_CONTRACT: &str = "0x4444444444444444444444444444444444444444";
        let mut other_domain = sample_domain();
        other_domain.verifying_contract = OTHER_TOKEN_CONTRACT.to_string();
        let mut other_binding = sample_binding();
        other_binding.token_contract = Some(OTHER_TOKEN_CONTRACT.to_string());

        let second = prepare_transfer_with_authorization(
            other_domain,
            sample_authorization(),
            &other_binding,
            SAMPLE_NOW,
            &store,
        );
        assert!(
            second.is_ok(),
            "the same nonce on a DIFFERENT token contract must not be a replay, got: {second:?}"
        );
        assert_eq!(
            store.len().test_unwrap(),
            2,
            "each (chain, contract, from, nonce) tuple must record a distinct nonce entry"
        );
    }

    #[test]
    fn same_nonce_on_the_same_token_contract_is_a_replay() {
        // Sibling to the cross-contract test: with the SAME domain (chain +
        // verifying contract) the same `(from, nonce)` must still be a replay,
        // so folding the contract into the key does not weaken replay
        // detection on the contract that actually consumes the nonce.
        let store = InMemoryEip3009NonceStore::new();
        let _ = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap();
        let replay = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        );
        assert!(
            replay.test_unwrap_err().to_string().contains("replay"),
            "the same nonce on the same token contract must still be a replay"
        );
    }

    #[test]
    fn assert_token_symbol_is_case_insensitive_and_fails_closed() {
        let binding = sample_binding();
        // Case and surrounding whitespace must not matter.
        assert!(binding.assert_token_symbol("x402", " usdc ").is_ok());
        assert!(binding.assert_token_symbol("circle", "USDC").is_ok());
        // A genuinely different token must be rejected.
        let error = binding
            .assert_token_symbol("x402", "EURC")
            .test_unwrap_err();
        assert!(
            error.to_string().contains("token mismatch"),
            "a different token symbol must be rejected, got: {error}"
        );
    }

    #[test]
    fn evaluates_circle_nanopayment_candidate() {
        let dispatch = sample_dispatch();
        let prepared = evaluate_circle_nanopayment(
            &dispatch,
            &CircleNanopaymentPolicy {
                enabled: true,
                managed_balance_id: "bal_123".to_string(),
                supported_chain_ids: vec!["eip155:8453".to_string()],
                supported_token_symbols: vec!["USD".to_string()],
                max_amount_minor_units: 200,
                operator_managed_custody_explicit: true,
            },
        )
        .test_unwrap()
        .test_unwrap();

        assert_eq!(prepared.dispatch_id, dispatch.dispatch_id);
    }

    #[test]
    fn evaluates_paymaster_compatibility() {
        let dispatch = sample_dispatch();
        let prepared = prepare_paymaster_compatibility(
            &dispatch,
            &Erc4337PaymasterPolicy {
                entry_point: "0x1000000000000000000000000000000000000100".to_string(),
                paymaster_address: "0x1000000000000000000000000000000000000101".to_string(),
                supported_chain_ids: vec!["eip155:8453".to_string()],
                max_sponsor_gas_limit: 300_000,
                max_reimbursement_minor_units: 10,
                settlement_deduction_explicit: true,
            },
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            250_000,
            5,
        )
        .test_unwrap();

        assert!(prepared.allowed);
        assert!(prepared.rejection_reason.is_none());
    }

    fn sample_verified_approval_token() -> GovernedApprovalToken {
        let kp = Keypair::generate();
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "test-approval-bridge-1".to_string(),
                approver: kp.public_key(),
                subject: kp.public_key(),
                governed_intent_hash: "test-intent-hash".to_string(),
                request_id: "test-req-1".to_string(),
                issued_at: SAMPLE_VALID_AFTER,
                expires_at: SAMPLE_VALID_BEFORE,
                decision: GovernedApprovalDecision::Approved,
            },
            &kp,
        )
        .test_unwrap()
    }

    fn sample_denied_approval_token() -> GovernedApprovalToken {
        let kp = Keypair::generate();
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "test-approval-bridge-denied".to_string(),
                approver: kp.public_key(),
                subject: kp.public_key(),
                governed_intent_hash: "test-intent-hash".to_string(),
                request_id: "test-req-denied".to_string(),
                issued_at: SAMPLE_VALID_AFTER,
                expires_at: SAMPLE_VALID_BEFORE,
                decision: GovernedApprovalDecision::Denied,
            },
            &kp,
        )
        .test_unwrap()
    }

    fn sample_rail() -> RailBinding {
        RailBinding {
            chain_id: SAMPLE_CHAIN_ID,
            token_contract: SAMPLE_TOKEN_CONTRACT.to_string(),
            payee_address: SAMPLE_PAYEE.to_string(),
            token_decimals: 6,
            token_symbol: SAMPLE_TOKEN_SYMBOL.to_string(),
        }
    }

    fn sample_authorization_input(binding: &ApprovalBinding) -> TransferWithAuthorizationInput {
        TransferWithAuthorizationInput {
            from_address: "0x1000000000000000000000000000000000000001".to_string(),
            to_address: binding.payee_address.clone(),
            value_minor_units: binding.amount_minor_units,
            valid_after: SAMPLE_VALID_AFTER,
            valid_before: binding.approval_expires_at,
            nonce: SAMPLE_NONCE.to_string(),
        }
    }

    fn sample_authorization_input_with_wrong_payee() -> TransferWithAuthorizationInput {
        TransferWithAuthorizationInput {
            from_address: "0x1000000000000000000000000000000000000001".to_string(),
            to_address: "0x9999999999999999999999999999999999999999".to_string(),
            value_minor_units: SAMPLE_VALUE,
            valid_after: SAMPLE_VALID_AFTER,
            valid_before: SAMPLE_VALID_BEFORE,
            nonce: SAMPLE_NONCE.to_string(),
        }
    }

    fn sample_nonce_store() -> InMemoryEip3009NonceStore {
        InMemoryEip3009NonceStore::new()
    }

    #[test]
    fn bridge_builds_binding_prepare_accepts_happy_path() {
        let token = sample_verified_approval_token();
        let rail = sample_rail();
        let binding = approval_binding_from_governed(&token, &rail, 1_000_000, token.expires_at)
            .test_unwrap();
        let prepared = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization_input(&binding),
            &binding,
            token.issued_at + 1,
            &sample_nonce_store(),
        )
        .test_unwrap();
        assert!(!prepared.authorization_digest.is_empty());
    }

    #[test]
    fn approval_binding_from_governed_rejects_denied_decision() {
        let token = sample_denied_approval_token();
        let error =
            approval_binding_from_governed(&token, &sample_rail(), 1_000_000, SAMPLE_VALID_BEFORE)
                .test_unwrap_err();
        assert!(
            matches!(error, SettlementError::InvalidBinding(_)),
            "a Denied token must produce InvalidBinding, got: {error}"
        );
    }

    #[test]
    fn approval_binding_from_governed_rejects_empty_payee_address() {
        let token = sample_verified_approval_token();
        let mut rail = sample_rail();
        rail.payee_address = String::new();
        let error = approval_binding_from_governed(&token, &rail, 1_000_000, SAMPLE_VALID_BEFORE)
            .test_unwrap_err();
        assert!(
            matches!(error, SettlementError::InvalidInput(_)),
            "an empty payee_address must produce InvalidInput, got: {error}"
        );
    }

    #[test]
    fn approval_binding_from_governed_rejects_zero_amount() {
        let token = sample_verified_approval_token();
        let error = approval_binding_from_governed(&token, &sample_rail(), 0, SAMPLE_VALID_BEFORE)
            .test_unwrap_err();
        assert!(
            matches!(error, SettlementError::InvalidInput(_)),
            "a zero amount must produce InvalidInput, got: {error}"
        );
    }

    #[test]
    fn bridge_prepare_rejects_payee_mismatch() {
        // Use a `now` inside the valid time window so the time-window gate
        // passes and the payee check is actually exercised.
        let error = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization_input_with_wrong_payee(),
            &sample_binding(),
            SAMPLE_NOW,
            &sample_nonce_store(),
        )
        .test_expect_err("payee mismatch must fail closed");
        assert!(
            matches!(error, SettlementError::InvalidBinding(_)),
            "payee mismatch must produce InvalidBinding"
        );
        assert!(
            error.to_string().contains("payee mismatch"),
            "error must identify the payee mismatch, got: {error}"
        );
    }

    fn sample_offchain_receipt() -> OffchainSettlementReceiptArtifact {
        OffchainSettlementReceiptArtifact {
            schema: CHIO_OFFCHAIN_SETTLEMENT_RECEIPT_SCHEMA.to_string(),
            settlement_receipt_id: "osr-1".to_string(),
            issued_at: 1_700_000_000,
            authorization_digest: "0xdigest".to_string(),
            governed_receipt_id: "rc-1".to_string(),
            settled_amount: MonetaryAmount {
                units: 1_000_000,
                currency: "USDC".to_string(),
            },
            execution_nonce_ref: None,
            hold_ref: None,
            note: None,
        }
    }

    #[test]
    fn offchain_receipt_validate_binds_digest_to_governed_receipt() {
        let receipt = sample_offchain_receipt();
        validate_offchain_settlement_receipt(&receipt).test_unwrap();
        let mut bad = receipt.clone();
        bad.governed_receipt_id = String::new();
        let error = validate_offchain_settlement_receipt(&bad)
            .test_expect_err("empty governed_receipt_id must fail");
        assert!(matches!(error, SettlementError::InvalidInput(_)));
    }

    #[test]
    fn offchain_receipt_schema_constant_is_pinned() {
        assert_eq!(
            CHIO_OFFCHAIN_SETTLEMENT_RECEIPT_SCHEMA,
            "chio.settle.offchain_receipt.v1"
        );
    }

    #[test]
    fn validate_offchain_settlement_receipt_rejects_wrong_schema() {
        let mut receipt = sample_offchain_receipt();
        receipt.schema = "chio.settle.offchain_receipt.v9".to_string();
        let error = validate_offchain_settlement_receipt(&receipt)
            .test_expect_err("wrong schema version must fail");
        assert!(
            matches!(error, SettlementError::InvalidInput(_)),
            "wrong schema must produce InvalidInput, got: {error}"
        );

        let mut empty_schema = sample_offchain_receipt();
        empty_schema.schema = String::new();
        let error = validate_offchain_settlement_receipt(&empty_schema)
            .test_expect_err("empty schema must fail");
        assert!(
            matches!(error, SettlementError::InvalidInput(_)),
            "empty schema must produce InvalidInput, got: {error}"
        );
    }

    #[test]
    fn validate_offchain_settlement_receipt_rejects_blank_currency_on_positive_units() {
        // A settled amount with positive units but no denomination cannot be
        // reconciled: dashboards and ledgers cannot tell what was paid.
        let valid = sample_offchain_receipt();
        validate_offchain_settlement_receipt(&valid).test_unwrap();

        let mut empty_currency = sample_offchain_receipt();
        empty_currency.settled_amount.currency = String::new();
        let error = validate_offchain_settlement_receipt(&empty_currency)
            .test_expect_err("empty currency with positive units must fail");
        assert!(
            matches!(error, SettlementError::InvalidInput(_)),
            "empty currency must produce InvalidInput, got: {error}"
        );

        let mut whitespace_currency = sample_offchain_receipt();
        whitespace_currency.settled_amount.currency = "   ".to_string();
        let error = validate_offchain_settlement_receipt(&whitespace_currency)
            .test_expect_err("whitespace currency with positive units must fail");
        assert!(
            matches!(error, SettlementError::InvalidInput(_)),
            "whitespace currency must produce InvalidInput, got: {error}"
        );
    }

    #[test]
    fn offchain_receipt_reserved_linkage_fields_are_present_and_optional() {
        // Pins the wire names of both reserved comptroller-surface linkage
        // fields. A present field must round-trip; absent fields must not
        // appear in serialized JSON (skip_serializing_if = "Option::is_none").
        let with_refs: OffchainSettlementReceiptArtifact = serde_json::from_str(
            r#"{
                "schema": "chio.settle.offchain_receipt.v1",
                "settlement_receipt_id": "osr-pin-1",
                "issued_at": 1700000000,
                "authorization_digest": "0xdigest",
                "governed_receipt_id": "rc-pin-1",
                "settled_amount": { "units": 1, "currency": "USDC" },
                "execution_nonce_ref": "nonce-ref-abc",
                "hold_ref": "hold-ref-xyz"
            }"#,
        )
        .test_unwrap();
        assert_eq!(
            with_refs.execution_nonce_ref.as_deref(),
            Some("nonce-ref-abc"),
            "execution_nonce_ref must deserialize from the wire field name"
        );
        assert_eq!(
            with_refs.hold_ref.as_deref(),
            Some("hold-ref-xyz"),
            "hold_ref must deserialize from the wire field name"
        );

        // Absent fields must not appear in serialized output.
        let absent = sample_offchain_receipt();
        let json = serde_json::to_string(&absent).test_unwrap();
        assert!(
            !json.contains("execution_nonce_ref"),
            "absent execution_nonce_ref must be omitted from JSON: {json}"
        );
        assert!(
            !json.contains("hold_ref"),
            "absent hold_ref must be omitted from JSON: {json}"
        );
    }

    #[test]
    fn approval_binding_from_governed_rejects_empty_token_contract() {
        let token = sample_verified_approval_token();
        let mut rail = sample_rail();
        rail.token_contract = String::new();
        let error = approval_binding_from_governed(&token, &rail, 1_000_000, SAMPLE_VALID_BEFORE)
            .test_unwrap_err();
        assert!(
            matches!(error, SettlementError::InvalidInput(_)),
            "an empty token_contract must produce InvalidInput, got: {error}"
        );
    }

    #[test]
    fn approval_binding_from_governed_rejects_empty_token_symbol() {
        let token = sample_verified_approval_token();
        let mut rail = sample_rail();
        rail.token_symbol = String::new();
        let error = approval_binding_from_governed(&token, &rail, 1_000_000, SAMPLE_VALID_BEFORE)
            .test_unwrap_err();
        assert!(
            matches!(error, SettlementError::InvalidInput(_)),
            "an empty token_symbol must produce InvalidInput, got: {error}"
        );
    }

    #[test]
    fn approval_binding_from_governed_clamps_expiry_to_token_expiry() {
        // A caller-supplied approval_expires_at LATER than the token's own
        // expiry cannot be honored: the token does not authorize a window
        // longer than its own life. The effective binding expiry must clamp
        // to token.expires_at so a prepared transfer can never stay valid
        // after the approval that justified it has lapsed.
        let token = sample_verified_approval_token();
        let rail = sample_rail();
        let binding =
            approval_binding_from_governed(&token, &rail, 1_000_000, token.expires_at + 3_600)
                .test_unwrap();
        assert_eq!(
            binding.approval_expires_at, token.expires_at,
            "an approval_expires_at later than the token must clamp to token.expires_at"
        );
    }

    #[test]
    fn approval_binding_from_governed_preserves_shorter_expiry() {
        // A caller may bind a tighter (shorter) window than the token's own
        // expiry for a specific dispatch. That shorter expiry must be
        // preserved, never widened to the token's expiry.
        let token = sample_verified_approval_token();
        let rail = sample_rail();
        let shorter = token.expires_at - 100;
        let binding =
            approval_binding_from_governed(&token, &rail, 1_000_000, shorter).test_unwrap();
        assert_eq!(
            binding.approval_expires_at, shorter,
            "a shorter approval_expires_at must be preserved, not widened to token.expires_at"
        );
    }
}
