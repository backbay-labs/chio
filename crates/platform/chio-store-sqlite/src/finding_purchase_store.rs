//! Durable storage for single-operator finding purchases: reservations,
//! seller exposure, the per-listing pending-purchase slot line, the
//! per-listing sales block, settled purchase records, failed-delivery
//! records, and payout destinations.
//!
//! Seven tables back the purchase path. `purchase_reservations` is the
//! durable fence a coordinator writes before it moves money: the row is
//! keyed by the reservation id the compatibility receipt carries, and it
//! is unique on both the purchase intent and the authoritative payment
//! operation, so no two reservations can name one payment.
//! `seller_exposure_encumbrances` holds the exposure that reservation
//! places against a consumed collateral allocation, which is what bounds a
//! seller's liability: exposure counts while the reservation is live and
//! keeps counting once the sale settles, through the retention horizon the
//! settlement pins. `pending_purchase_slots` is the monotonic per-listing
//! slot line the cutoff wait reads, and `listing_sales_blocks` is the
//! switch that stops that line growing: while a listing carries a live
//! block no reservation can take a fresh slot, so a frozen cutoff stays
//! the high-water mark it was frozen at. A block is an episode on that
//! listing, raised once and lifted at most once when the liability that
//! raised it is exonerated; the raise stays on the record either way, so
//! a lifted listing still shows when and for how long it was blocked.
//! `purchase_records` and `failed_delivery_records` are the two terminal
//! outcomes, retained without deletion and content-addressed against their
//! stored digests. `payout_destinations` is the bounded sixteen-slot
//! destination set per allocation, with slot zero reserved for the
//! community fund.
//!
//! Writes run under `TransactionBehavior::Immediate` behind the
//! serving-owner fence; reads run `Deferred`; a commit whose outcome
//! cannot be observed surfaces as outcome-unknown and poisons the owner
//! exactly like the sibling stores.
//!
//! The store is not an authority boundary: envelope signature
//! verification, price agreement, and payment authorization belong to the
//! surfaces that call in here. The store enforces the durable invariants
//! those surfaces rely on: one reservation per payment operation, exposure
//! that never exceeds the allocation's registered cap, an allocation that
//! backs the finding and listing it is charged for, a slot line that only
//! ever grows and stops growing while sales are blocked, terminal
//! records that cannot be edited or deleted, and the atomic close
//! transaction that moves reservation, slot, encumbrance, and record
//! together or not at all.
//!
//! Every mutation is idempotent by its natural key following the durable
//! fee-intent fence: a replay carrying the same identity succeeds without
//! re-applying the effect, and a replay with conflicting parameters
//! rejects rather than overwriting what is already durable. Identity is
//! the semantic content of the write; the trusted times a caller supplies
//! are not part of it, so a retry issued from a later clock replays rather
//! than stranding the durable row it is retrying.

use std::sync::{Arc, Mutex, MutexGuard};

use chio_core::{sha256_hex, StoreMutationFence};
use chio_kernel::admission_operation::AdmissionOperationStoreError;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use thiserror::Error;

use crate::admission_operation_store::verify_active_owner;
use crate::serving_owner::SqliteServingOwner;

const FINDING_PURCHASE_SCHEMA_KEY: &str = "finding_purchase";
/// Revision 3 turns the per-listing sales block into an episode line that
/// an exonerating reversal can lift. The schema batch is a sequence of
/// idempotent guards, so a revision-1 database adopts the new table on its
/// next open; a revision-2 database carries its listing-keyed blocks
/// across in [`carry_listing_sales_blocks_across`].
pub(crate) const FINDING_PURCHASE_SUPPORTED_SCHEMA_VERSION: i32 = 3;
/// Revision that introduced the listing-keyed, never-lifted sales block.
const FINDING_PURCHASE_LISTING_KEYED_BLOCK_VERSION: i32 = 2;
/// Name the listing-keyed block table is parked under while the episode
/// line is created beside it.
const LEGACY_SALES_BLOCK_TABLE: &str = "listing_sales_blocks_legacy";
const FINDING_PURCHASE_SCHEMA_ANCHORS: &[&str] = &[
    "purchase_reservations",
    "admission_operations",
    "chio_serving_owner",
];
const FINDING_PURCHASE_SCHEMA: &str = include_str!("finding_purchase_store.sql");

/// Terminal record bodies are capped at 256 KiB, the persisted-operation
/// scale precedent the sibling market store holds artifacts to.
const MAX_TERMINAL_RECORD_BYTES: usize = 256 * 1024;
/// Upper bound on every opaque identifier this store persists. An
/// unbounded identifier is an amplification vector rather than a name.
const MAX_IDENTIFIER_BYTES: usize = 512;
/// Payout destinations per allocation, slot zero included.
const PAYOUT_DESTINATION_SLOTS: u8 = 16;
/// Slot zero is reserved at store level for the community fund, so a buyer
/// destination can never displace it.
const COMMUNITY_FUND_SLOT_INDEX: u8 = 0;
/// Batch clamp for the expiry sweep, keeping one transaction bounded.
const MAX_EXPIRY_BATCH: usize = 512;

/// Errors surfaced by the finding-purchase store. Fail-closed: every
/// rejection denies the mutation and rolls the transaction back.
#[derive(Debug, Error)]
pub enum FindingPurchaseStoreError {
    #[error("finding purchase store is unavailable: {0}")]
    Unavailable(String),
    #[error("finding purchase store fence rejected the caller")]
    Fenced,
    #[error("finding purchase record not found")]
    NotFound,
    #[error("finding purchase conflict: {0}")]
    Conflict(String),
    #[error("finding purchase invariant violated: {0}")]
    Invariant(String),
    #[error(
        "seller exposure overcommitted for allocation {allocation_id}: {outstanding} outstanding plus {requested} requested exceeds the {maximum} cap"
    )]
    ExposureOvercommitted {
        allocation_id: String,
        outstanding: u64,
        requested: u64,
        maximum: u64,
    },
    #[error("collateral allocation {0} is not a consumed allocation")]
    AllocationNotConsumed(String),
    #[error(
        "collateral allocation {allocation_id} backs finding {backing_finding_id} on listing {backing_listing_id}, not finding {finding_id} on listing {listing_id}"
    )]
    AllocationNotBoundToSale {
        allocation_id: String,
        backing_finding_id: String,
        backing_listing_id: String,
        finding_id: String,
        listing_id: String,
    },
    #[error("payout destination slots are exhausted for allocation {0}")]
    DestinationSlotsExhausted(String),
    #[error("new purchases are blocked on listing {0}")]
    SalesBlocked(String),
    #[error("finding purchase commit outcome is unknown: {0}")]
    OutcomeUnknown(String),
}

/// Lifecycle of one purchase reservation. `open` and `slot_reserved` are
/// the two live states; `consumed`, `released`, and `expired` are terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingPurchaseReservationState {
    Open,
    SlotReserved,
    Consumed,
    Released,
    Expired,
}

/// Lifecycle of one seller exposure encumbrance. Exposure counts against
/// the allocation cap while it is `open`, and while it is `retained` up to
/// its retention horizon; `released` never counts. Every exit from `open`
/// is final.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingPurchaseEncumbranceState {
    Open,
    Released,
    Retained,
}

/// Lifecycle of one pending-purchase slot. A slot closes exactly once,
/// either against a settled record or against a denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingPurchaseSlotState {
    Reserved,
    ClosedRecord,
    ClosedDeny,
}

/// Whether a write created durable state or replayed identical prior
/// state as a no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingPurchaseWriteOutcome {
    Inserted,
    ExistingSame,
}

/// Every column of one reservation plus the exposure encumbrance opened
/// with it. `maximum_sale_exposure_units` is the caller-verified cap the
/// exposure check runs against; the store additionally refuses a cap above
/// the one the named allocation registered.
#[derive(Debug, Clone, Copy)]
pub struct FindingPurchaseReservationInput<'a> {
    /// Also the compatibility receipt id for this purchase.
    pub reservation_id: &'a str,
    pub purchase_intent_id: &'a str,
    pub authoritative_payment_operation_id: &'a str,
    pub payer_hex: &'a str,
    pub agent_id: &'a str,
    pub finding_id: &'a str,
    pub listing_id: &'a str,
    pub bid_envelope_sha256: &'a str,
    pub ask_digest: &'a str,
    pub admission_envelope_sha256: &'a str,
    pub amount_units: u64,
    pub currency: &'a str,
    pub expires_at: u64,
    pub encumbrance_id: &'a str,
    pub allocation_id: &'a str,
    pub maximum_sale_exposure_units: u64,
    pub created_at: u64,
}

/// One reservation row, including its live lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingPurchaseReservationRecord {
    pub reservation_id: String,
    pub purchase_intent_id: String,
    pub authoritative_payment_operation_id: String,
    pub payer_hex: String,
    pub agent_id: String,
    pub finding_id: String,
    pub listing_id: String,
    pub bid_envelope_sha256: String,
    pub ask_digest: String,
    pub admission_envelope_sha256: String,
    pub amount_units: u64,
    pub currency: String,
    pub expires_at: u64,
    pub state: FindingPurchaseReservationState,
    pub created_at: u64,
    pub updated_at: u64,
}

/// One seller exposure encumbrance row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingPurchaseEncumbranceRecord {
    pub encumbrance_id: String,
    pub allocation_id: String,
    pub reservation_id: String,
    pub amount_units: u64,
    pub currency: String,
    pub state: FindingPurchaseEncumbranceState,
    pub retention_expires_at: Option<u64>,
    pub opened_at: u64,
    pub updated_at: u64,
}

/// One pending-purchase slot row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingPurchaseSlotRecord {
    pub listing_id: String,
    pub slot_ordinal: u64,
    pub reservation_id: String,
    pub state: FindingPurchaseSlotState,
    pub reserved_at: u64,
    pub closed_at: Option<u64>,
}

/// Parameters closing one slot against a settled delivery. `record_json`
/// is retained verbatim and must hash to `record_sha256`.
#[derive(Debug, Clone, Copy)]
pub struct FindingPurchaseDeliveryInput<'a> {
    pub reservation_id: &'a str,
    pub purchase_key: &'a str,
    pub record_json: &'a [u8],
    pub record_sha256: &'a str,
    pub delivery_receipt_id: &'a str,
    /// Buyer payout destination admitted against the reservation's
    /// durable collateral allocation as part of the close transaction.
    pub payout_destination: &'a str,
    /// Trusted time through which the retained exposure stays encumbered
    /// and keeps counting against the allocation's cap.
    pub retention_expires_at: u64,
    pub now: u64,
}

/// Parameters closing one slot against a delivery denial.
#[derive(Debug, Clone, Copy)]
pub struct FindingPurchaseDenyInput<'a> {
    pub reservation_id: &'a str,
    pub failed_delivery_id: &'a str,
    pub record_json: &'a [u8],
    pub record_sha256: &'a str,
    pub deny_receipt_id: &'a str,
    pub now: u64,
}

/// One retained settled purchase record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingPurchaseRecordRow {
    pub purchase_key: String,
    pub reservation_id: String,
    pub record_json: Vec<u8>,
    pub record_sha256: String,
    pub delivery_receipt_id: String,
    pub recorded_at: u64,
}

/// One retained failed-delivery record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingFailedDeliveryRow {
    pub failed_delivery_id: String,
    pub reservation_id: String,
    pub record_json: Vec<u8>,
    pub record_sha256: String,
    pub deny_receipt_id: String,
    pub recorded_at: u64,
}

/// The slot one payout destination occupies, plus whether this call
/// admitted it or replayed an existing admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindingPayoutDestinationAdmission {
    pub slot_index: u8,
    pub admitted_at: u64,
    pub outcome: FindingPurchaseWriteOutcome,
}

#[derive(Clone)]
pub struct SqliteFindingPurchaseStore {
    connection: Arc<Mutex<Connection>>,
    serving_owner: Arc<SqliteServingOwner>,
}

impl SqliteFindingPurchaseStore {
    pub(crate) fn open_alongside(
        connection: Arc<Mutex<Connection>>,
        serving_owner: Arc<SqliteServingOwner>,
    ) -> Self {
        Self {
            connection,
            serving_owner,
        }
    }

    /// Serving identity shared by every store opened alongside this one.
    #[must_use]
    pub fn mutation_fence(&self) -> StoreMutationFence {
        self.serving_owner.fence.clone()
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, FindingPurchaseStoreError> {
        self.connection.lock().map_err(|_| {
            FindingPurchaseStoreError::Unavailable(
                "sqlite finding purchase lock poisoned".to_owned(),
            )
        })
    }

    fn begin_read<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, FindingPurchaseStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, None).map_err(admission_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(|error| FindingPurchaseStoreError::Unavailable(error.to_string()))?;
        Ok(transaction)
    }

    fn begin_write<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, FindingPurchaseStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, None).map_err(admission_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(|error| FindingPurchaseStoreError::Unavailable(error.to_string()))?;
        Ok(transaction)
    }

    fn commit_write(&self, transaction: Transaction<'_>) -> Result<(), FindingPurchaseStoreError> {
        transaction.commit().map_err(|error| {
            FindingPurchaseStoreError::OutcomeUnknown(
                self.serving_owner
                    .outcome_unknown(format!(
                        "sqlite finding purchase commit outcome is unknown: {error}"
                    ))
                    .to_string(),
            )
        })
    }

    fn sync_after_write(&self, connection: &Connection) -> Result<(), FindingPurchaseStoreError> {
        self.serving_owner
            .sync_authority_anchor(connection)
            .map_err(|error| FindingPurchaseStoreError::Unavailable(error.to_string()))
    }

    /// Seed the sibling admission table for cross-store unit tests whose
    /// subject is purchase or challenge transactionality, not activation.
    #[cfg(any(test, feature = "cognition-market-test-support"))]
    pub fn install_active_admission_for_tests(
        &self,
        finding_id: &str,
        allocation_id: &str,
        listing_id: &str,
        admission_id: &str,
        admission_envelope_sha256: &str,
        activated_at: u64,
    ) -> Result<(), FindingPurchaseStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        transaction
            .execute(
                "UPDATE admissions SET state = 'superseded' WHERE state = 'active' AND finding_id = ?1",
                [finding_id],
            )
            .map_err(sqlite_error)?;
        transaction
            .execute(
                r#"
                INSERT INTO admissions (
                    admission_id, finding_id, listing_id, backing_allocation_id,
                    admission_envelope_sha256, admission_envelope_json,
                    expires_at, activated_at, state
                ) VALUES (?1, ?2, ?3, ?4, ?5, '{}', ?6, ?7, 'active')
                "#,
                params![
                    admission_id,
                    finding_id,
                    listing_id,
                    allocation_id,
                    admission_envelope_sha256,
                    1_900_000_000_i64,
                    sqlite_i64(activated_at, "activated_at")?,
                ],
            )
            .map_err(sqlite_error)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)
    }

    /// Fence one purchase before its payment dispatches. In one immediate
    /// transaction this inserts the reservation `open` and opens the
    /// seller exposure encumbrance that backs it, after asserting the
    /// named collateral allocation is consumed, backs this finding on this
    /// listing, the reservation binds the finding's current active
    /// admission, and the new exposure plus every exposure still
    /// outstanding against that allocation at `created_at` stays within
    /// `maximum_sale_exposure_units`.
    ///
    /// Reservations encumbering this allocation whose expiry has passed
    /// are expired inside the same transaction before the cap is checked,
    /// so the cap bounds live exposure only: an abandoned reservation
    /// releases its encumbrance here rather than occupying the seller's
    /// capacity forever.
    /// If a bounded cleanup pass still leaves the request overcommitted,
    /// the cleanup commits before the refusal is returned. A retry then
    /// advances to the next batch instead of rolling back and revisiting
    /// the same expired rows forever.
    ///
    /// Idempotent on the reservation id: a replay carrying the same
    /// purchase identity returns
    /// [`FindingPurchaseWriteOutcome::ExistingSame`] without touching the
    /// exposure, and conflicting parameters under an existing reservation
    /// id reject. The trusted times are not part of that identity, so a
    /// retry from a later clock replays; the durable row keeps the expiry
    /// the first call fenced.
    pub fn open_reservation(
        &self,
        input: &FindingPurchaseReservationInput<'_>,
    ) -> Result<FindingPurchaseWriteOutcome, FindingPurchaseStoreError> {
        validate_reservation_input(input)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        assert_allocation_backs_sale(&transaction, input)?;
        assert_active_admission(&transaction, input)?;
        if let Some(existing) = load_reservation_tx(&transaction, input.reservation_id)? {
            let encumbrance = load_encumbrance_tx(&transaction, input.reservation_id)?
                .ok_or_else(|| invariant("reservation lost its exposure encumbrance"))?;
            if reservation_matches(&existing, input) && encumbrance_matches(&encumbrance, input) {
                return Ok(FindingPurchaseWriteOutcome::ExistingSame);
            }
            return Err(FindingPurchaseStoreError::Conflict(
                "reservation id is already bound to different purchase parameters".to_owned(),
            ));
        }
        reject_bound_identifier(
            &transaction,
            "SELECT reservation_id FROM purchase_reservations WHERE purchase_intent_id = ?1",
            input.purchase_intent_id,
            "purchase intent",
        )?;
        reject_bound_identifier(
            &transaction,
            r#"
            SELECT reservation_id FROM purchase_reservations
            WHERE authoritative_payment_operation_id = ?1
            "#,
            input.authoritative_payment_operation_id,
            "authoritative payment operation",
        )?;
        reject_bound_identifier(
            &transaction,
            "SELECT reservation_id FROM seller_exposure_encumbrances WHERE encumbrance_id = ?1",
            input.encumbrance_id,
            "encumbrance id",
        )?;
        assert_allocation_backs_sale(&transaction, input)?;
        expire_due_allocation_reservations_tx(&transaction, input.allocation_id, input.created_at)?;
        let outstanding =
            outstanding_exposure_total_tx(&transaction, input.allocation_id, input.created_at)?;
        let committed = outstanding
            .checked_add(input.amount_units)
            .ok_or_else(|| invariant("seller exposure total overflowed u64"))?;
        if committed > input.maximum_sale_exposure_units {
            let error = FindingPurchaseStoreError::ExposureOvercommitted {
                allocation_id: input.allocation_id.to_owned(),
                outstanding,
                requested: input.amount_units,
                maximum: input.maximum_sale_exposure_units,
            };
            self.commit_write(transaction)?;
            self.sync_after_write(&connection)?;
            return Err(error);
        }
        let created_at = sqlite_i64(input.created_at, "created_at")?;
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO purchase_reservations (
                    reservation_id, purchase_intent_id,
                    authoritative_payment_operation_id, payer_hex, agent_id,
                    finding_id, listing_id, bid_envelope_sha256, ask_digest,
                    admission_envelope_sha256, amount_units, currency,
                    expires_at, state, created_at, updated_at
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                    'open', ?14, ?14
                )
                "#,
                params![
                    input.reservation_id,
                    input.purchase_intent_id,
                    input.authoritative_payment_operation_id,
                    input.payer_hex,
                    input.agent_id,
                    input.finding_id,
                    input.listing_id,
                    input.bid_envelope_sha256,
                    input.ask_digest,
                    input.admission_envelope_sha256,
                    sqlite_i64(input.amount_units, "amount_units")?,
                    input.currency,
                    sqlite_i64(input.expires_at, "expires_at")?,
                    created_at,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("reservation insert did not affect one row"));
        }
        let encumbered = transaction
            .execute(
                r#"
                INSERT INTO seller_exposure_encumbrances (
                    encumbrance_id, allocation_id, reservation_id, amount_units,
                    currency, state, retention_expires_at, opened_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, 'open', NULL, ?6, ?6)
                "#,
                params![
                    input.encumbrance_id,
                    input.allocation_id,
                    input.reservation_id,
                    sqlite_i64(input.amount_units, "amount_units")?,
                    input.currency,
                    created_at,
                ],
            )
            .map_err(sqlite_error)?;
        if encumbered != 1 {
            return Err(invariant(
                "exposure encumbrance insert did not affect one row",
            ));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingPurchaseWriteOutcome::Inserted)
    }

    /// One reservation by its reservation id.
    pub fn get_reservation(
        &self,
        reservation_id: &str,
    ) -> Result<Option<FindingPurchaseReservationRecord>, FindingPurchaseStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_reservation_tx(&transaction, reservation_id)
    }

    /// One reservation by the purchase intent it fences.
    pub fn get_reservation_by_intent(
        &self,
        purchase_intent_id: &str,
    ) -> Result<Option<FindingPurchaseReservationRecord>, FindingPurchaseStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_reservation_row_tx(&transaction, "purchase_intent_id", purchase_intent_id)
    }

    /// The exposure encumbrance opened for one reservation.
    pub fn get_encumbrance(
        &self,
        reservation_id: &str,
    ) -> Result<Option<FindingPurchaseEncumbranceRecord>, FindingPurchaseStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_encumbrance_tx(&transaction, reservation_id)
    }

    /// The pending-purchase slot held by one reservation, if it took one.
    pub fn get_slot(
        &self,
        reservation_id: &str,
    ) -> Result<Option<FindingPurchaseSlotRecord>, FindingPurchaseStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_slot_tx(&transaction, reservation_id)
    }

    /// Take the next pending-purchase slot on the reservation's listing,
    /// moving the reservation `open` to `slot_reserved`. Ordinals are
    /// allocated strictly monotonically per listing inside this
    /// transaction, and slots are never deleted, so an ordinal is never
    /// reused. Idempotent: a reservation already holding a slot returns
    /// that ordinal. A reservation at or past its expiry cannot take a
    /// fresh slot, and neither can any reservation once the listing's
    /// sales are blocked: the block is read inside this transaction, so a
    /// reserve racing the block either commits before it or sees it.
    pub fn reserve_slot(
        &self,
        reservation_id: &str,
        now: u64,
    ) -> Result<u64, FindingPurchaseStoreError> {
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let reservation = load_reservation_tx(&transaction, reservation_id)?
            .ok_or(FindingPurchaseStoreError::NotFound)?;
        match reservation.state {
            FindingPurchaseReservationState::SlotReserved => {
                let slot = load_slot_tx(&transaction, reservation_id)?
                    .ok_or_else(|| invariant("slot-reserved reservation holds no slot"))?;
                return Ok(slot.slot_ordinal);
            }
            FindingPurchaseReservationState::Open => {}
            other => {
                return Err(FindingPurchaseStoreError::Conflict(format!(
                    "reservation is not open for a slot (state is {})",
                    reservation_state_name(other)
                )));
            }
        }
        if now >= reservation.expires_at {
            return Err(FindingPurchaseStoreError::Conflict(
                "reservation has reached its expiry".to_owned(),
            ));
        }
        if sales_blocked_tx(&transaction, &reservation.listing_id)? {
            return Err(FindingPurchaseStoreError::SalesBlocked(
                reservation.listing_id.clone(),
            ));
        }
        let highest: i64 = transaction
            .query_row(
                r#"
                SELECT COALESCE(MAX(slot_ordinal), 0) FROM pending_purchase_slots
                WHERE listing_id = ?1
                "#,
                [&reservation.listing_id],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        let ordinal = stored_u64(highest, "slot_ordinal")?
            .checked_add(1)
            .ok_or_else(|| invariant("slot ordinal overflowed u64"))?;
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO pending_purchase_slots (
                    listing_id, slot_ordinal, reservation_id, state,
                    reserved_at, closed_at
                ) VALUES (?1, ?2, ?3, 'reserved', ?4, NULL)
                "#,
                params![
                    &reservation.listing_id,
                    sqlite_i64(ordinal, "slot_ordinal")?,
                    reservation_id,
                    sqlite_i64(now, "now")?,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("slot insert did not affect one row"));
        }
        advance_reservation_tx(&transaction, reservation_id, "open", "slot_reserved", now)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(ordinal)
    }

    /// Settle one purchase. In one immediate transaction this closes the
    /// slot against the record, admits the payout destination against the
    /// reservation's durable allocation, moves the reservation
    /// `slot_reserved` to `consumed`, retains the exposure encumbrance
    /// through `retention_expires_at`, and inserts the retained purchase
    /// record.
    /// Idempotent: a replay of the same settled record succeeds as a
    /// no-op, and a different record against an already-settled purchase
    /// rejects. The pinned retention horizon is durable and is never
    /// rewritten, so a replay can neither extend nor shorten it.
    pub fn close_slot_with_record(
        &self,
        input: &FindingPurchaseDeliveryInput<'_>,
    ) -> Result<FindingPurchaseWriteOutcome, FindingPurchaseStoreError> {
        require_hex64(input.purchase_key, "purchase_key")?;
        require_hex64(input.record_sha256, "record_sha256")?;
        require_identifier(input.reservation_id, "reservation_id")?;
        require_identifier(input.delivery_receipt_id, "delivery_receipt_id")?;
        require_rail_destination(input.payout_destination)?;
        require_terminal_record(input.record_json, input.record_sha256)?;
        require_trusted_time(input.now, "now")?;
        require_trusted_time(input.retention_expires_at, "retention_expires_at")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let reservation = load_reservation_tx(&transaction, input.reservation_id)?
            .ok_or(FindingPurchaseStoreError::NotFound)?;
        let encumbrance = load_encumbrance_tx(&transaction, input.reservation_id)?
            .ok_or_else(|| invariant("reservation lost its exposure encumbrance"))?;
        match reservation.state {
            FindingPurchaseReservationState::Consumed => {
                if encumbrance.state != FindingPurchaseEncumbranceState::Retained {
                    return Err(invariant(
                        "consumed reservation does not retain its exposure encumbrance",
                    ));
                }
                let stored =
                    load_purchase_record_by_reservation_tx(&transaction, input.reservation_id)?
                        .ok_or_else(|| {
                            invariant("consumed reservation holds no purchase record")
                        })?;
                if stored.purchase_key == input.purchase_key
                    && stored.record_json == input.record_json
                    && stored.record_sha256 == input.record_sha256
                    && stored.delivery_receipt_id == input.delivery_receipt_id
                    && encumbrance.retention_expires_at == Some(input.retention_expires_at)
                {
                    if load_destination_tx(
                        &transaction,
                        &encumbrance.allocation_id,
                        input.payout_destination,
                    )?
                    .is_none()
                    {
                        return Err(FindingPurchaseStoreError::Conflict(
                            "settled reservation names a different payout destination".to_owned(),
                        ));
                    }
                    return Ok(FindingPurchaseWriteOutcome::ExistingSame);
                }
                return Err(FindingPurchaseStoreError::Conflict(
                    "reservation is already settled under different delivery parameters".to_owned(),
                ));
            }
            FindingPurchaseReservationState::SlotReserved => {
                if encumbrance.state != FindingPurchaseEncumbranceState::Open {
                    return Err(invariant(
                        "slot-reserved reservation does not hold open exposure",
                    ));
                }
                let slot = load_slot_tx(&transaction, input.reservation_id)?
                    .ok_or_else(|| invariant("slot-reserved reservation holds no slot"))?;
                if slot.state != FindingPurchaseSlotState::Reserved {
                    return Err(invariant("slot-reserved reservation holds a closed slot"));
                }
            }
            other => {
                return Err(FindingPurchaseStoreError::Conflict(format!(
                    "reservation cannot settle from state {}",
                    reservation_state_name(other)
                )));
            }
        }
        reject_bound_identifier(
            &transaction,
            "SELECT reservation_id FROM purchase_records WHERE purchase_key = ?1",
            input.purchase_key,
            "purchase key",
        )?;
        admit_payout_destination_tx(
            &transaction,
            &encumbrance.allocation_id,
            input.payout_destination,
            input.now,
        )?;
        close_reserved_slot_tx(
            &transaction,
            input.reservation_id,
            "closed_record",
            input.now,
        )?;
        advance_reservation_tx(
            &transaction,
            input.reservation_id,
            "slot_reserved",
            "consumed",
            input.now,
        )?;
        let retained = transaction
            .execute(
                r#"
                UPDATE seller_exposure_encumbrances
                SET state = 'retained', retention_expires_at = ?2, updated_at = ?3
                WHERE reservation_id = ?1 AND state = 'open'
                "#,
                params![
                    input.reservation_id,
                    sqlite_i64(input.retention_expires_at, "retention_expires_at")?,
                    sqlite_i64(input.now, "now")?,
                ],
            )
            .map_err(sqlite_error)?;
        if retained != 1 {
            return Err(invariant("exposure retention did not affect one row"));
        }
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO purchase_records (
                    purchase_key, reservation_id, record_json, record_sha256,
                    delivery_receipt_id, recorded_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                "#,
                params![
                    input.purchase_key,
                    input.reservation_id,
                    input.record_json,
                    input.record_sha256,
                    input.delivery_receipt_id,
                    sqlite_i64(input.now, "now")?,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("purchase record insert did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingPurchaseWriteOutcome::Inserted)
    }

    /// Deny one delivery. In one immediate transaction this closes the
    /// slot against the denial, moves the reservation `slot_reserved` to
    /// `released`, releases the exposure encumbrance, and inserts the
    /// retained failed-delivery record. Idempotent on identical
    /// parameters; conflicting parameters against an already-denied
    /// reservation reject.
    pub fn close_slot_with_deny(
        &self,
        input: &FindingPurchaseDenyInput<'_>,
    ) -> Result<FindingPurchaseWriteOutcome, FindingPurchaseStoreError> {
        require_identifier(input.reservation_id, "reservation_id")?;
        require_identifier(input.failed_delivery_id, "failed_delivery_id")?;
        require_identifier(input.deny_receipt_id, "deny_receipt_id")?;
        require_hex64(input.record_sha256, "record_sha256")?;
        require_terminal_record(input.record_json, input.record_sha256)?;
        require_trusted_time(input.now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let reservation = load_reservation_tx(&transaction, input.reservation_id)?
            .ok_or(FindingPurchaseStoreError::NotFound)?;
        match reservation.state {
            FindingPurchaseReservationState::Released => {
                let stored =
                    load_failed_delivery_by_reservation_tx(&transaction, input.reservation_id)?
                        .ok_or_else(|| {
                            FindingPurchaseStoreError::Conflict(
                                "reservation was released without a delivery denial".to_owned(),
                            )
                        })?;
                if stored.failed_delivery_id == input.failed_delivery_id
                    && stored.record_json == input.record_json
                    && stored.record_sha256 == input.record_sha256
                    && stored.deny_receipt_id == input.deny_receipt_id
                {
                    return Ok(FindingPurchaseWriteOutcome::ExistingSame);
                }
                return Err(FindingPurchaseStoreError::Conflict(
                    "reservation is already denied under different parameters".to_owned(),
                ));
            }
            FindingPurchaseReservationState::SlotReserved => {}
            other => {
                return Err(FindingPurchaseStoreError::Conflict(format!(
                    "reservation cannot deny delivery from state {}",
                    reservation_state_name(other)
                )));
            }
        }
        reject_bound_identifier(
            &transaction,
            "SELECT reservation_id FROM failed_delivery_records WHERE failed_delivery_id = ?1",
            input.failed_delivery_id,
            "failed delivery id",
        )?;
        close_reserved_slot_tx(&transaction, input.reservation_id, "closed_deny", input.now)?;
        advance_reservation_tx(
            &transaction,
            input.reservation_id,
            "slot_reserved",
            "released",
            input.now,
        )?;
        release_encumbrance_tx(&transaction, input.reservation_id, input.now)?;
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO failed_delivery_records (
                    failed_delivery_id, reservation_id, record_json,
                    record_sha256, deny_receipt_id, recorded_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                "#,
                params![
                    input.failed_delivery_id,
                    input.reservation_id,
                    input.record_json,
                    input.record_sha256,
                    input.deny_receipt_id,
                    sqlite_i64(input.now, "now")?,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant(
                "failed delivery record insert did not affect one row",
            ));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingPurchaseWriteOutcome::Inserted)
    }

    /// Abort one reservation before dispatch: the reservation moves to
    /// `released`, its exposure encumbrance releases, and any slot it took
    /// closes as a denial without a failed-delivery record. A released
    /// reservation never leaves a slot reserved. Idempotent on a
    /// reservation already released.
    pub fn release_reservation(
        &self,
        reservation_id: &str,
        now: u64,
    ) -> Result<(), FindingPurchaseStoreError> {
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let reservation = load_reservation_tx(&transaction, reservation_id)?
            .ok_or(FindingPurchaseStoreError::NotFound)?;
        let from = match reservation.state {
            FindingPurchaseReservationState::Released => return Ok(()),
            FindingPurchaseReservationState::Open => "open",
            FindingPurchaseReservationState::SlotReserved => "slot_reserved",
            other => {
                return Err(FindingPurchaseStoreError::Conflict(format!(
                    "reservation cannot release from state {}",
                    reservation_state_name(other)
                )));
            }
        };
        abandon_reservation_tx(&transaction, reservation_id, from, "released", now)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(())
    }

    /// Expire every reservation whose expiry has passed, releasing its
    /// exposure and closing any slot it still holds, up to `limit` rows in
    /// one bounded transaction. Returns how many reservations expired.
    pub fn expire_reservations(
        &self,
        now: u64,
        limit: usize,
    ) -> Result<usize, FindingPurchaseStoreError> {
        require_trusted_time(now, "now")?;
        let limit = limit.clamp(1, MAX_EXPIRY_BATCH);
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let due = due_reservations_tx(&transaction, now, limit)?;
        for (reservation_id, state) in &due {
            abandon_reservation_tx(&transaction, reservation_id, state, "expired", now)?;
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(due.len())
    }

    /// The lowest slot ordinal still reserved on one listing: the cutoff a
    /// waiter blocks behind. `None` means no purchase is in flight.
    pub fn open_slot_floor(
        &self,
        listing_id: &str,
    ) -> Result<Option<u64>, FindingPurchaseStoreError> {
        require_identifier(listing_id, "listing_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let floor: Option<i64> = transaction
            .query_row(
                r#"
                SELECT MIN(slot_ordinal) FROM pending_purchase_slots
                WHERE listing_id = ?1 AND state = 'reserved'
                "#,
                [listing_id],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        floor
            .map(|ordinal| stored_u64(ordinal, "slot_ordinal"))
            .transpose()
    }

    /// Block every new pending-purchase slot on one listing. While the
    /// block stands it is never rewritten, so a cutoff frozen against it
    /// can only ever be the listing's high-water mark. Idempotent, and a
    /// repeat keeps the trusted time the first block recorded.
    ///
    /// Slots already reserved are untouched. Blocking stops the line
    /// growing; it does not retract a purchase already in flight, which
    /// still has to reach a settled record or a denial.
    ///
    /// Nothing on this surface lifts a block. The one transition that
    /// does is the liability reversal that exonerates the seller, and it
    /// is composed into that reversal's own transaction rather than
    /// offered to a caller.
    pub fn block_new_slots(
        &self,
        listing_id: &str,
        now: u64,
    ) -> Result<FindingPurchaseWriteOutcome, FindingPurchaseStoreError> {
        require_identifier(listing_id, "listing_id")?;
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let outcome = block_new_slots_tx(&transaction, listing_id, now)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(outcome)
    }

    /// Whether new purchases are blocked on one listing.
    pub fn sales_blocked(&self, listing_id: &str) -> Result<bool, FindingPurchaseStoreError> {
        require_identifier(listing_id, "listing_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        sales_blocked_tx(&transaction, listing_id)
    }

    /// Whether every slot on one listing at or below `cutoff` has closed,
    /// against a settled record or against a denial. This is the exact
    /// predicate a claim snapshot waits on: slots above the cutoff are
    /// irrelevant to it, and a cutoff of zero is trivially satisfied
    /// because slot ordinals start at one.
    pub fn all_slots_closed_at_or_below(
        &self,
        listing_id: &str,
        cutoff: u64,
    ) -> Result<bool, FindingPurchaseStoreError> {
        require_identifier(listing_id, "listing_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let open: i64 = transaction
            .query_row(
                r#"
                SELECT COUNT(*) FROM pending_purchase_slots
                WHERE listing_id = ?1 AND slot_ordinal <= ?2 AND state = 'reserved'
                "#,
                params![listing_id, sqlite_i64(cutoff, "cutoff")?],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        Ok(open == 0)
    }

    /// Exposure still outstanding against one collateral allocation at
    /// `now`: every live reservation's open encumbrance plus every settled
    /// sale's retained encumbrance whose retention horizon has not lapsed.
    /// This is the quantity the allocation cap bounds.
    pub fn list_outstanding_exposure_total(
        &self,
        allocation_id: &str,
        now: u64,
    ) -> Result<u64, FindingPurchaseStoreError> {
        require_hex64(allocation_id, "allocation_id")?;
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        outstanding_exposure_total_tx(&transaction, allocation_id, now)
    }

    /// One retained settled purchase record, re-checked against its stored
    /// digest on the read path.
    pub fn get_purchase_record(
        &self,
        purchase_key: &str,
    ) -> Result<Option<FindingPurchaseRecordRow>, FindingPurchaseStoreError> {
        require_hex64(purchase_key, "purchase_key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_purchase_record_tx(&transaction, "purchase_key", purchase_key)
    }

    /// Every settled purchase charged to one allocation on one listing at
    /// or below a frozen slot cutoff. This is the authoritative claim set:
    /// callers may use hints to select work, but they cannot omit a retained
    /// settled record from the snapshot that determines buyer compensation.
    pub fn list_settled_purchase_keys_at_or_below(
        &self,
        listing_id: &str,
        allocation_id: &str,
        cutoff: u64,
    ) -> Result<Vec<String>, FindingPurchaseStoreError> {
        require_identifier(listing_id, "listing_id")?;
        require_hex64(allocation_id, "allocation_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        settled_purchase_keys_at_or_below_tx(&transaction, listing_id, allocation_id, cutoff)
    }

    /// Return the complete settled claim set only when every slot at or
    /// below the cutoff is terminal in the same database snapshot.
    ///
    /// The closure predicate and enumeration deliberately share one read
    /// transaction. A purchase that settles concurrently is therefore
    /// either still visible as reserved (and this returns `None`) or is
    /// included in the returned key set. Once the listing sales block is
    /// raised, a successful result cannot be invalidated by a new slot.
    pub fn closed_settled_purchase_keys_at_or_below(
        &self,
        listing_id: &str,
        allocation_id: &str,
        cutoff: u64,
    ) -> Result<Option<Vec<String>>, FindingPurchaseStoreError> {
        require_identifier(listing_id, "listing_id")?;
        require_hex64(allocation_id, "allocation_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let open: i64 = transaction
            .query_row(
                r#"
                SELECT COUNT(*) FROM pending_purchase_slots
                WHERE listing_id = ?1 AND slot_ordinal <= ?2 AND state = 'reserved'
                "#,
                params![listing_id, sqlite_i64(cutoff, "cutoff")?],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if open != 0 {
            return Ok(None);
        }
        settled_purchase_keys_at_or_below_tx(&transaction, listing_id, allocation_id, cutoff)
            .map(Some)
    }

    /// One retained failed-delivery record, re-checked against its stored
    /// digest on the read path.
    pub fn get_failed_delivery_record(
        &self,
        failed_delivery_id: &str,
    ) -> Result<Option<FindingFailedDeliveryRow>, FindingPurchaseStoreError> {
        require_identifier(failed_delivery_id, "failed_delivery_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_failed_delivery_tx(&transaction, "failed_delivery_id", failed_delivery_id)
    }

    /// Bind the community-fund destination at the reserved slot zero for
    /// one allocation. Idempotent on the same destination; a different
    /// destination for an allocation whose slot zero is already bound
    /// rejects, as does a destination already admitted as a buyer slot.
    pub fn register_community_fund_destination(
        &self,
        allocation_id: &str,
        destination: &str,
        admitted_at: u64,
    ) -> Result<FindingPayoutDestinationAdmission, FindingPurchaseStoreError> {
        require_hex64(allocation_id, "allocation_id")?;
        require_rail_destination(destination)?;
        require_trusted_time(admitted_at, "admitted_at")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if let Some(existing) = load_destination_tx(&transaction, allocation_id, destination)? {
            if existing.slot_index != COMMUNITY_FUND_SLOT_INDEX {
                return Err(FindingPurchaseStoreError::Conflict(
                    "destination is already admitted as a buyer payout slot".to_owned(),
                ));
            }
            return Ok(FindingPayoutDestinationAdmission {
                outcome: FindingPurchaseWriteOutcome::ExistingSame,
                ..existing
            });
        }
        let occupant: Option<String> = transaction
            .query_row(
                r#"
                SELECT destination FROM payout_destinations
                WHERE allocation_id = ?1 AND slot_index = ?2
                "#,
                params![allocation_id, i64::from(COMMUNITY_FUND_SLOT_INDEX)],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if occupant.is_some() {
            return Err(FindingPurchaseStoreError::Conflict(
                "the community fund slot is already bound to a different destination".to_owned(),
            ));
        }
        insert_destination_tx(
            &transaction,
            allocation_id,
            destination,
            COMMUNITY_FUND_SLOT_INDEX,
            admitted_at,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingPayoutDestinationAdmission {
            slot_index: COMMUNITY_FUND_SLOT_INDEX,
            admitted_at,
            outcome: FindingPurchaseWriteOutcome::Inserted,
        })
    }

    /// Admit one buyer payout destination for an allocation, returning the
    /// slot it occupies. An already-admitted destination replays with its
    /// existing slot; otherwise the lowest free slot in 1..=15 is taken,
    /// and an allocation whose buyer slots are full rejects.
    pub fn admit_payout_destination(
        &self,
        allocation_id: &str,
        destination: &str,
        admitted_at: u64,
    ) -> Result<FindingPayoutDestinationAdmission, FindingPurchaseStoreError> {
        require_hex64(allocation_id, "allocation_id")?;
        require_rail_destination(destination)?;
        require_trusted_time(admitted_at, "admitted_at")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let admission =
            admit_payout_destination_tx(&transaction, allocation_id, destination, admitted_at)?;
        if admission.outcome == FindingPurchaseWriteOutcome::ExistingSame {
            return Ok(admission);
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(admission)
    }

    /// Every payout destination admitted for one allocation, ordered by
    /// slot with the community fund first.
    pub fn list_payout_destinations(
        &self,
        allocation_id: &str,
    ) -> Result<Vec<(u8, String)>, FindingPurchaseStoreError> {
        require_hex64(allocation_id, "allocation_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction
            .prepare(
                r#"
                SELECT slot_index, destination FROM payout_destinations
                WHERE allocation_id = ?1 ORDER BY slot_index ASC
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([allocation_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        rows.into_iter()
            .map(|(slot_index, destination)| Ok((stored_slot_index(slot_index)?, destination)))
            .collect()
    }
}

const RESERVATION_COLUMNS: &str = r#"
    reservation_id, purchase_intent_id, authoritative_payment_operation_id,
    payer_hex, agent_id, finding_id, listing_id, bid_envelope_sha256,
    ask_digest, admission_envelope_sha256, amount_units, currency,
    expires_at, state, created_at, updated_at
"#;

struct RawReservation {
    reservation_id: String,
    purchase_intent_id: String,
    authoritative_payment_operation_id: String,
    payer_hex: String,
    agent_id: String,
    finding_id: String,
    listing_id: String,
    bid_envelope_sha256: String,
    ask_digest: String,
    admission_envelope_sha256: String,
    amount_units: i64,
    currency: String,
    expires_at: i64,
    state: String,
    created_at: i64,
    updated_at: i64,
}

fn map_reservation(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawReservation> {
    Ok(RawReservation {
        reservation_id: row.get(0)?,
        purchase_intent_id: row.get(1)?,
        authoritative_payment_operation_id: row.get(2)?,
        payer_hex: row.get(3)?,
        agent_id: row.get(4)?,
        finding_id: row.get(5)?,
        listing_id: row.get(6)?,
        bid_envelope_sha256: row.get(7)?,
        ask_digest: row.get(8)?,
        admission_envelope_sha256: row.get(9)?,
        amount_units: row.get(10)?,
        currency: row.get(11)?,
        expires_at: row.get(12)?,
        state: row.get(13)?,
        created_at: row.get(14)?,
        updated_at: row.get(15)?,
    })
}

fn reservation_from_raw(
    raw: RawReservation,
) -> Result<FindingPurchaseReservationRecord, FindingPurchaseStoreError> {
    Ok(FindingPurchaseReservationRecord {
        reservation_id: raw.reservation_id,
        purchase_intent_id: raw.purchase_intent_id,
        authoritative_payment_operation_id: raw.authoritative_payment_operation_id,
        payer_hex: raw.payer_hex,
        agent_id: raw.agent_id,
        finding_id: raw.finding_id,
        listing_id: raw.listing_id,
        bid_envelope_sha256: raw.bid_envelope_sha256,
        ask_digest: raw.ask_digest,
        admission_envelope_sha256: raw.admission_envelope_sha256,
        amount_units: stored_u64(raw.amount_units, "amount_units")?,
        currency: raw.currency,
        expires_at: stored_u64(raw.expires_at, "expires_at")?,
        state: reservation_state_from_name(&raw.state)?,
        created_at: stored_u64(raw.created_at, "created_at")?,
        updated_at: stored_u64(raw.updated_at, "updated_at")?,
    })
}

fn load_reservation_tx(
    transaction: &Transaction<'_>,
    reservation_id: &str,
) -> Result<Option<FindingPurchaseReservationRecord>, FindingPurchaseStoreError> {
    load_reservation_row_tx(transaction, "reservation_id", reservation_id)
}

/// `column` is a compile-time-fixed identifier from this module's own
/// schema, never caller input.
fn load_reservation_row_tx(
    transaction: &Transaction<'_>,
    column: &str,
    value: &str,
) -> Result<Option<FindingPurchaseReservationRecord>, FindingPurchaseStoreError> {
    let raw = transaction
        .query_row(
            &format!("SELECT {RESERVATION_COLUMNS} FROM purchase_reservations WHERE {column} = ?1"),
            [value],
            map_reservation,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(reservation_from_raw).transpose()
}

fn load_encumbrance_tx(
    transaction: &Transaction<'_>,
    reservation_id: &str,
) -> Result<Option<FindingPurchaseEncumbranceRecord>, FindingPurchaseStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT encumbrance_id, allocation_id, reservation_id, amount_units,
                   currency, state, retention_expires_at, opened_at, updated_at
            FROM seller_exposure_encumbrances WHERE reservation_id = ?1
            "#,
            [reservation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((
        encumbrance_id,
        allocation_id,
        reservation_id,
        amount_units,
        currency,
        state,
        retention_expires_at,
        opened_at,
        updated_at,
    )) = row
    else {
        return Ok(None);
    };
    Ok(Some(FindingPurchaseEncumbranceRecord {
        encumbrance_id,
        allocation_id,
        reservation_id,
        amount_units: stored_u64(amount_units, "amount_units")?,
        currency,
        state: encumbrance_state_from_name(&state)?,
        retention_expires_at: retention_expires_at
            .map(|value| stored_u64(value, "retention_expires_at"))
            .transpose()?,
        opened_at: stored_u64(opened_at, "opened_at")?,
        updated_at: stored_u64(updated_at, "updated_at")?,
    }))
}

fn load_slot_tx(
    transaction: &Transaction<'_>,
    reservation_id: &str,
) -> Result<Option<FindingPurchaseSlotRecord>, FindingPurchaseStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT listing_id, slot_ordinal, reservation_id, state, reserved_at,
                   closed_at
            FROM pending_purchase_slots WHERE reservation_id = ?1
            "#,
            [reservation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((listing_id, slot_ordinal, reservation_id, state, reserved_at, closed_at)) = row
    else {
        return Ok(None);
    };
    Ok(Some(FindingPurchaseSlotRecord {
        listing_id,
        slot_ordinal: stored_u64(slot_ordinal, "slot_ordinal")?,
        reservation_id,
        state: slot_state_from_name(&state)?,
        reserved_at: stored_u64(reserved_at, "reserved_at")?,
        closed_at: closed_at
            .map(|value| stored_u64(value, "closed_at"))
            .transpose()?,
    }))
}

/// `column` is a compile-time-fixed identifier from this module's own
/// schema, never caller input.
fn load_purchase_record_tx(
    transaction: &Transaction<'_>,
    column: &str,
    value: &str,
) -> Result<Option<FindingPurchaseRecordRow>, FindingPurchaseStoreError> {
    let row = transaction
        .query_row(
            &format!(
                r#"
                SELECT purchase_key, reservation_id, record_json, record_sha256,
                       delivery_receipt_id, recorded_at
                FROM purchase_records WHERE {column} = ?1
                "#
            ),
            [value],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((
        purchase_key,
        reservation_id,
        record_json,
        record_sha256,
        delivery_receipt_id,
        recorded_at,
    )) = row
    else {
        return Ok(None);
    };
    verify_stored_digest(&record_json, &record_sha256, "purchase record")?;
    Ok(Some(FindingPurchaseRecordRow {
        purchase_key,
        reservation_id,
        record_json,
        record_sha256,
        delivery_receipt_id,
        recorded_at: stored_u64(recorded_at, "recorded_at")?,
    }))
}

fn load_purchase_record_by_reservation_tx(
    transaction: &Transaction<'_>,
    reservation_id: &str,
) -> Result<Option<FindingPurchaseRecordRow>, FindingPurchaseStoreError> {
    load_purchase_record_tx(transaction, "reservation_id", reservation_id)
}

/// `column` is a compile-time-fixed identifier from this module's own
/// schema, never caller input.
fn load_failed_delivery_tx(
    transaction: &Transaction<'_>,
    column: &str,
    value: &str,
) -> Result<Option<FindingFailedDeliveryRow>, FindingPurchaseStoreError> {
    let row = transaction
        .query_row(
            &format!(
                r#"
                SELECT failed_delivery_id, reservation_id, record_json,
                       record_sha256, deny_receipt_id, recorded_at
                FROM failed_delivery_records WHERE {column} = ?1
                "#
            ),
            [value],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((
        failed_delivery_id,
        reservation_id,
        record_json,
        record_sha256,
        deny_receipt_id,
        recorded_at,
    )) = row
    else {
        return Ok(None);
    };
    verify_stored_digest(&record_json, &record_sha256, "failed delivery record")?;
    Ok(Some(FindingFailedDeliveryRow {
        failed_delivery_id,
        reservation_id,
        record_json,
        record_sha256,
        deny_receipt_id,
        recorded_at: stored_u64(recorded_at, "recorded_at")?,
    }))
}

fn load_failed_delivery_by_reservation_tx(
    transaction: &Transaction<'_>,
    reservation_id: &str,
) -> Result<Option<FindingFailedDeliveryRow>, FindingPurchaseStoreError> {
    load_failed_delivery_tx(transaction, "reservation_id", reservation_id)
}

fn load_destination_tx(
    transaction: &Transaction<'_>,
    allocation_id: &str,
    destination: &str,
) -> Result<Option<FindingPayoutDestinationAdmission>, FindingPurchaseStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT slot_index, admitted_at FROM payout_destinations
            WHERE allocation_id = ?1 AND destination = ?2
            "#,
            params![allocation_id, destination],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((slot_index, admitted_at)) = row else {
        return Ok(None);
    };
    Ok(Some(FindingPayoutDestinationAdmission {
        slot_index: stored_slot_index(slot_index)?,
        admitted_at: stored_u64(admitted_at, "admitted_at")?,
        outcome: FindingPurchaseWriteOutcome::ExistingSame,
    }))
}

fn admit_payout_destination_tx(
    transaction: &Transaction<'_>,
    allocation_id: &str,
    destination: &str,
    admitted_at: u64,
) -> Result<FindingPayoutDestinationAdmission, FindingPurchaseStoreError> {
    if let Some(existing) = load_destination_tx(transaction, allocation_id, destination)? {
        return Ok(FindingPayoutDestinationAdmission {
            outcome: FindingPurchaseWriteOutcome::ExistingSame,
            ..existing
        });
    }
    let mut taken = [false; PAYOUT_DESTINATION_SLOTS as usize];
    {
        let mut statement = transaction
            .prepare("SELECT slot_index FROM payout_destinations WHERE allocation_id = ?1")
            .map_err(sqlite_error)?;
        let slots = statement
            .query_map([allocation_id], |row| row.get::<_, i64>(0))
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        for slot in slots {
            let index = usize::try_from(slot)
                .map_err(|_| invariant("stored payout slot index is out of range"))?;
            let occupied = taken
                .get_mut(index)
                .ok_or_else(|| invariant("stored payout slot index is out of range"))?;
            *occupied = true;
        }
    }
    let slot_index = (1..PAYOUT_DESTINATION_SLOTS)
        .find(|index| !taken[usize::from(*index)])
        .ok_or_else(|| {
            FindingPurchaseStoreError::DestinationSlotsExhausted(allocation_id.to_owned())
        })?;
    insert_destination_tx(
        transaction,
        allocation_id,
        destination,
        slot_index,
        admitted_at,
    )?;
    Ok(FindingPayoutDestinationAdmission {
        slot_index,
        admitted_at,
        outcome: FindingPurchaseWriteOutcome::Inserted,
    })
}

fn insert_destination_tx(
    transaction: &Transaction<'_>,
    allocation_id: &str,
    destination: &str,
    slot_index: u8,
    admitted_at: u64,
) -> Result<(), FindingPurchaseStoreError> {
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO payout_destinations (
                allocation_id, destination, slot_index, admitted_at
            ) VALUES (?1, ?2, ?3, ?4)
            "#,
            params![
                allocation_id,
                destination,
                i64::from(slot_index),
                sqlite_i64(admitted_at, "admitted_at")?,
            ],
        )
        .map_err(sqlite_error)?;
    if inserted != 1 {
        return Err(invariant(
            "payout destination insert did not affect one row",
        ));
    }
    Ok(())
}

fn settled_purchase_keys_at_or_below_tx(
    transaction: &Transaction<'_>,
    listing_id: &str,
    allocation_id: &str,
    cutoff: u64,
) -> Result<Vec<String>, FindingPurchaseStoreError> {
    let mut statement = transaction
        .prepare(
            r#"
            SELECT records.purchase_key
            FROM purchase_records AS records
            JOIN pending_purchase_slots AS slots
              ON slots.reservation_id = records.reservation_id
            JOIN seller_exposure_encumbrances AS encumbrances
              ON encumbrances.reservation_id = records.reservation_id
            WHERE slots.listing_id = ?1
              AND slots.slot_ordinal <= ?2
              AND slots.state = 'closed_record'
              AND encumbrances.allocation_id = ?3
            ORDER BY records.purchase_key ASC
            "#,
        )
        .map_err(sqlite_error)?;
    let keys = statement
        .query_map(
            params![listing_id, sqlite_i64(cutoff, "cutoff")?, allocation_id],
            |row| row.get::<_, String>(0),
        )
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(keys)
}

/// Raise one listing's sales block inside a caller-supplied transaction.
/// This is the seam the challenge lane composes with: the liability CAS
/// that freezes a purchase cutoff and the block that stops the slot line
/// growing past it are one transaction on one connection, so no slot can
/// open between them.
///
/// Episodes are numbered strictly monotonically per listing and are never
/// deleted, so a listing blocked, exonerated, and blocked again keeps both
/// raises on the record. A listing that already carries a live block
/// replays: the second liability to reach it holds the same episode the
/// first raised, and that episode outlives either of them.
pub(crate) fn block_new_slots_tx(
    transaction: &Transaction<'_>,
    listing_id: &str,
    now: u64,
) -> Result<FindingPurchaseWriteOutcome, FindingPurchaseStoreError> {
    if sales_blocked_tx(transaction, listing_id)? {
        return Ok(FindingPurchaseWriteOutcome::ExistingSame);
    }
    let highest: i64 = transaction
        .query_row(
            r#"
            SELECT COALESCE(MAX(block_ordinal), 0) FROM listing_sales_blocks
            WHERE listing_id = ?1
            "#,
            [listing_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let ordinal = stored_u64(highest, "block_ordinal")?
        .checked_add(1)
        .ok_or_else(|| invariant("block ordinal overflowed u64"))?;
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO listing_sales_blocks (
                listing_id, block_ordinal, state, blocked_at, lifted_at
            ) VALUES (?1, ?2, 'blocked', ?3, NULL)
            "#,
            params![
                listing_id,
                sqlite_i64(ordinal, "block_ordinal")?,
                sqlite_i64(now, "now")?,
            ],
        )
        .map_err(sqlite_error)?;
    if inserted != 1 {
        return Err(invariant("listing sales block did not affect one row"));
    }
    Ok(FindingPurchaseWriteOutcome::Inserted)
}

/// Lift one listing's live sales block inside a caller-supplied
/// transaction, stamping when it was lifted and leaving the raise itself
/// untouched.
///
/// This is the counterpart seam to [`block_new_slots_tx`], and it exists
/// for exactly one caller: the liability reversal that exonerates the
/// seller before anything was impaired. The store cannot see what
/// authorizes a lift, so it is deliberately not reachable from the public
/// surface; the challenge lane composes it into the same transaction as
/// the compare-and-set that reaches the reversed terminal, and only once
/// no other liability still holds the listing.
///
/// Idempotent: a listing with no live block is already where the caller
/// wants it, whether it was never blocked or the lift already committed.
pub(crate) fn lift_sales_block_tx(
    transaction: &Transaction<'_>,
    listing_id: &str,
    now: u64,
) -> Result<FindingPurchaseWriteOutcome, FindingPurchaseStoreError> {
    let lifted = transaction
        .execute(
            r#"
            UPDATE listing_sales_blocks SET state = 'lifted', lifted_at = ?2
            WHERE listing_id = ?1 AND state = 'blocked'
            "#,
            params![listing_id, sqlite_i64(now, "now")?],
        )
        .map_err(sqlite_error)?;
    match lifted {
        0 => Ok(FindingPurchaseWriteOutcome::ExistingSame),
        1 => Ok(FindingPurchaseWriteOutcome::Inserted),
        _ => Err(invariant("listing sales block lift affected several rows")),
    }
}

/// The highest slot ordinal ever allocated on one listing, read inside a
/// caller-supplied transaction. Zero means the listing has never sold.
/// Ordinals are monotonic and slots are never deleted, so this is the
/// listing's high-water mark and, once its sales are blocked, its final
/// one.
pub(crate) fn highest_slot_ordinal_tx(
    transaction: &Transaction<'_>,
    listing_id: &str,
) -> Result<u64, FindingPurchaseStoreError> {
    let highest: i64 = transaction
        .query_row(
            r#"
            SELECT COALESCE(MAX(slot_ordinal), 0) FROM pending_purchase_slots
            WHERE listing_id = ?1
            "#,
            [listing_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    stored_u64(highest, "slot_ordinal")
}

/// Whether one listing's sales are blocked, read inside a caller-supplied
/// transaction. A listing sells again once its live block episode is
/// lifted; the lifted episodes it retains do not block anything.
pub(crate) fn sales_blocked_tx(
    transaction: &Transaction<'_>,
    listing_id: &str,
) -> Result<bool, FindingPurchaseStoreError> {
    let blocked: bool = transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM listing_sales_blocks
                WHERE listing_id = ?1 AND state = 'blocked'
            )
            "#,
            [listing_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    Ok(blocked)
}

/// The live reservations whose expiry has passed, oldest first, bounded
/// by `limit`, paired with the state each is leaving.
fn due_reservations_tx(
    transaction: &Transaction<'_>,
    now: u64,
    limit: usize,
) -> Result<Vec<(String, String)>, FindingPurchaseStoreError> {
    let now = sqlite_i64(now, "now")?;
    let limit = sqlite_i64(u64::try_from(limit).unwrap_or(u64::MAX), "limit")?;
    let mut statement = transaction
        .prepare(
            r#"
            SELECT reservation_id, state FROM purchase_reservations
            WHERE state IN ('open', 'slot_reserved') AND expires_at <= ?1
            ORDER BY expires_at ASC, reservation_id ASC
            LIMIT ?2
            "#,
        )
        .map_err(sqlite_error)?;
    let due = statement
        .query_map(params![now, limit], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(due)
}

/// Expire the due reservations still holding an open encumbrance against
/// one allocation, inside the caller's transaction, bounded by
/// [`MAX_EXPIRY_BATCH`]. This runs before the allocation's exposure cap is
/// checked so the cap bounds live exposure only; a residue past the batch
/// bound keeps counting until a later pass reaches it, which can only
/// deny a reservation, never overcommit one.
fn expire_due_allocation_reservations_tx(
    transaction: &Transaction<'_>,
    allocation_id: &str,
    now: u64,
) -> Result<(), FindingPurchaseStoreError> {
    let mut statement = transaction
        .prepare(
            r#"
            SELECT reservations.reservation_id, reservations.state
            FROM purchase_reservations AS reservations
            JOIN seller_exposure_encumbrances AS encumbrances
              ON encumbrances.reservation_id = reservations.reservation_id
            WHERE encumbrances.allocation_id = ?1
              AND encumbrances.state = 'open'
              AND reservations.state IN ('open', 'slot_reserved')
              AND reservations.expires_at <= ?2
            ORDER BY reservations.expires_at ASC, reservations.reservation_id ASC
            LIMIT ?3
            "#,
        )
        .map_err(sqlite_error)?;
    let due = statement
        .query_map(
            params![
                allocation_id,
                sqlite_i64(now, "now")?,
                sqlite_i64(u64::try_from(MAX_EXPIRY_BATCH).unwrap_or(u64::MAX), "limit")?,
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    drop(statement);
    for (reservation_id, state) in &due {
        abandon_reservation_tx(transaction, reservation_id, state, "expired", now)?;
    }
    Ok(())
}

/// Exposure booked against one allocation that is still outstanding at
/// `now`. A settled sale's exposure does not vanish when the money moves:
/// it stays encumbered until the retention horizon the settlement pinned
/// lapses, so one allocation can never back more concurrent plus retained
/// liability than the cap it registered.
///
/// An open encumbrance follows its reservation's own expiry semantics. A
/// reservation still `open` past its expiry can never take a slot, so it
/// can never become a sale: counting it would let an abandoned reservation
/// encumber the cap forever. A `slot_reserved` reservation past its expiry
/// keeps counting, because its delivery may still settle into a retained
/// encumbrance until the expiry sweep closes it; dropping it early would
/// undercount against exposure that can still materialize.
pub(crate) fn outstanding_exposure_total_tx(
    transaction: &Transaction<'_>,
    allocation_id: &str,
    now: u64,
) -> Result<u64, FindingPurchaseStoreError> {
    let total: i64 = transaction
        .query_row(
            r#"
            SELECT COALESCE(SUM(enc.amount_units), 0)
            FROM seller_exposure_encumbrances AS enc
            JOIN purchase_reservations AS res
              ON res.reservation_id = enc.reservation_id
            WHERE enc.allocation_id = ?1
              AND (
                (
                    enc.state = 'open'
                    AND NOT (res.state = 'open' AND res.expires_at <= ?2)
                )
                OR (enc.state = 'retained' AND enc.retention_expires_at > ?2)
              )
            "#,
            params![allocation_id, sqlite_i64(now, "now")?],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    stored_u64(total, "outstanding exposure total")
}

/// The named allocation must exist in the sibling market store's
/// collateral table, must have been consumed by an activation, must back
/// exactly the finding and listing this reservation sells, must price in
/// the reservation's currency, and must have registered a cap at least as
/// large as the one the caller verified. Anything else denies the
/// reservation: without the finding and listing comparison one seller's
/// collateral could be encumbered for a sale it never backed.
fn assert_allocation_backs_sale(
    transaction: &Transaction<'_>,
    input: &FindingPurchaseReservationInput<'_>,
) -> Result<(), FindingPurchaseStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT state, finding_id, listing_id, currency,
                   maximum_sale_exposure_units
            FROM collateral_allocations WHERE allocation_id = ?1
            "#,
            [input.allocation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((state, finding_id, listing_id, currency, registered_maximum)) = row else {
        return Err(FindingPurchaseStoreError::AllocationNotConsumed(
            input.allocation_id.to_owned(),
        ));
    };
    if state != "consumed" {
        return Err(FindingPurchaseStoreError::AllocationNotConsumed(
            input.allocation_id.to_owned(),
        ));
    }
    if finding_id != input.finding_id || listing_id != input.listing_id {
        return Err(FindingPurchaseStoreError::AllocationNotBoundToSale {
            allocation_id: input.allocation_id.to_owned(),
            backing_finding_id: finding_id,
            backing_listing_id: listing_id,
            finding_id: input.finding_id.to_owned(),
            listing_id: input.listing_id.to_owned(),
        });
    }
    if currency != input.currency {
        return Err(FindingPurchaseStoreError::Conflict(
            "reservation currency does not match the backing allocation".to_owned(),
        ));
    }
    if input.maximum_sale_exposure_units > stored_u64(registered_maximum, "maximum_sale_exposure")?
    {
        return Err(FindingPurchaseStoreError::Conflict(
            "supplied exposure cap exceeds the cap the allocation registered".to_owned(),
        ));
    }
    Ok(())
}

/// The admission digest a reservation binds must still be the active
/// admission for its finding at the instant the reservation opens. This
/// check shares the reservation's immediate transaction, so activation
/// cannot supersede the admission between validation and insertion.
fn assert_active_admission(
    transaction: &Transaction<'_>,
    input: &FindingPurchaseReservationInput<'_>,
) -> Result<(), FindingPurchaseStoreError> {
    let active: Option<i64> = transaction
        .query_row(
            r#"
            SELECT 1 FROM admissions
            WHERE finding_id = ?1
              AND admission_envelope_sha256 = ?2
              AND state = 'active'
            LIMIT 1
            "#,
            params![input.finding_id, input.admission_envelope_sha256],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if active.is_none() {
        return Err(FindingPurchaseStoreError::Conflict(
            "reservation does not bind the finding's current active admission".to_owned(),
        ));
    }
    Ok(())
}

/// Reject a natural key already bound to a different reservation. The
/// unique indexes make this unreachable as a silent overwrite; catching it
/// here turns a constraint abort into a typed conflict.
///
/// `query` is a compile-time-fixed statement from this module, never
/// caller input.
fn reject_bound_identifier(
    transaction: &Transaction<'_>,
    query: &str,
    value: &str,
    what: &str,
) -> Result<(), FindingPurchaseStoreError> {
    let bound: Option<String> = transaction
        .query_row(query, [value], |row| row.get(0))
        .optional()
        .map_err(sqlite_error)?;
    if bound.is_some() {
        return Err(FindingPurchaseStoreError::Conflict(format!(
            "{what} is already bound to another reservation"
        )));
    }
    Ok(())
}

fn advance_reservation_tx(
    transaction: &Transaction<'_>,
    reservation_id: &str,
    from: &str,
    to: &str,
    now: u64,
) -> Result<(), FindingPurchaseStoreError> {
    let changed = transaction
        .execute(
            r#"
            UPDATE purchase_reservations SET state = ?3, updated_at = ?4
            WHERE reservation_id = ?1 AND state = ?2
            "#,
            params![reservation_id, from, to, sqlite_i64(now, "now")?],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(invariant("reservation transition did not affect one row"));
    }
    Ok(())
}

fn close_reserved_slot_tx(
    transaction: &Transaction<'_>,
    reservation_id: &str,
    to: &str,
    now: u64,
) -> Result<(), FindingPurchaseStoreError> {
    let changed = transaction
        .execute(
            r#"
            UPDATE pending_purchase_slots SET state = ?2, closed_at = ?3
            WHERE reservation_id = ?1 AND state = 'reserved'
            "#,
            params![reservation_id, to, sqlite_i64(now, "now")?],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(invariant("slot close did not affect one row"));
    }
    Ok(())
}

fn release_encumbrance_tx(
    transaction: &Transaction<'_>,
    reservation_id: &str,
    now: u64,
) -> Result<(), FindingPurchaseStoreError> {
    let changed = transaction
        .execute(
            r#"
            UPDATE seller_exposure_encumbrances
            SET state = 'released', updated_at = ?2
            WHERE reservation_id = ?1 AND state = 'open'
            "#,
            params![reservation_id, sqlite_i64(now, "now")?],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(invariant("exposure release did not affect one row"));
    }
    Ok(())
}

/// Abandon one live reservation: the reservation moves to `to`, its open
/// exposure releases, and a slot it still holds closes as a denial. A
/// reservation must never be abandoned with a slot left reserved, so both
/// effects land in the caller's transaction or neither does.
fn abandon_reservation_tx(
    transaction: &Transaction<'_>,
    reservation_id: &str,
    from: &str,
    to: &str,
    now: u64,
) -> Result<(), FindingPurchaseStoreError> {
    advance_reservation_tx(transaction, reservation_id, from, to, now)?;
    release_encumbrance_tx(transaction, reservation_id, now)?;
    if from == "slot_reserved" {
        close_reserved_slot_tx(transaction, reservation_id, "closed_deny", now)?;
    }
    Ok(())
}

/// Whether a stored reservation is the same purchase the caller is
/// reserving. Identity is what the purchase is: who pays, for which
/// finding on which listing, under which digests, for how much.
///
/// The trusted times are deliberately excluded. A caller derives both
/// `created_at` and `expires_at` from its clock, so an honest retry of one
/// reserve carries later values than the durable row; comparing them would
/// turn every such retry into a conflict and strand the reservation the
/// caller is trying to recover. Excluding them cannot extend the fence:
/// the stored row is returned untouched, so the expiry the first call
/// committed remains the one the store enforces and a later `expires_at`
/// is ignored rather than applied. A caller that needs the authoritative
/// deadline reads it back off the reservation.
fn reservation_matches(
    existing: &FindingPurchaseReservationRecord,
    input: &FindingPurchaseReservationInput<'_>,
) -> bool {
    existing.purchase_intent_id == input.purchase_intent_id
        && existing.authoritative_payment_operation_id == input.authoritative_payment_operation_id
        && existing.payer_hex == input.payer_hex
        && existing.agent_id == input.agent_id
        && existing.finding_id == input.finding_id
        && existing.listing_id == input.listing_id
        && existing.bid_envelope_sha256 == input.bid_envelope_sha256
        && existing.ask_digest == input.ask_digest
        && existing.admission_envelope_sha256 == input.admission_envelope_sha256
        && existing.amount_units == input.amount_units
        && existing.currency == input.currency
}

fn encumbrance_matches(
    existing: &FindingPurchaseEncumbranceRecord,
    input: &FindingPurchaseReservationInput<'_>,
) -> bool {
    existing.encumbrance_id == input.encumbrance_id
        && existing.allocation_id == input.allocation_id
        && existing.amount_units == input.amount_units
        && existing.currency == input.currency
}

fn validate_reservation_input(
    input: &FindingPurchaseReservationInput<'_>,
) -> Result<(), FindingPurchaseStoreError> {
    require_identifier(input.reservation_id, "reservation_id")?;
    require_identifier(input.purchase_intent_id, "purchase_intent_id")?;
    require_identifier(
        input.authoritative_payment_operation_id,
        "authoritative_payment_operation_id",
    )?;
    require_identifier(input.agent_id, "agent_id")?;
    require_identifier(input.listing_id, "listing_id")?;
    require_identifier(input.encumbrance_id, "encumbrance_id")?;
    require_hex64(input.payer_hex, "payer_hex")?;
    require_hex64(input.finding_id, "finding_id")?;
    require_hex64(input.bid_envelope_sha256, "bid_envelope_sha256")?;
    require_hex64(input.ask_digest, "ask_digest")?;
    require_hex64(input.admission_envelope_sha256, "admission_envelope_sha256")?;
    require_hex64(input.allocation_id, "allocation_id")?;
    require_currency(input.currency)?;
    if input.amount_units == 0 {
        return Err(invariant("reservation amount must be nonzero"));
    }
    if input.maximum_sale_exposure_units == 0 {
        return Err(invariant("maximum sale exposure must be nonzero"));
    }
    require_trusted_time(input.created_at, "created_at")?;
    require_trusted_time(input.expires_at, "expires_at")?;
    if input.expires_at <= input.created_at {
        return Err(invariant("reservation expiry does not follow creation"));
    }
    Ok(())
}

fn reservation_state_from_name(
    name: &str,
) -> Result<FindingPurchaseReservationState, FindingPurchaseStoreError> {
    match name {
        "open" => Ok(FindingPurchaseReservationState::Open),
        "slot_reserved" => Ok(FindingPurchaseReservationState::SlotReserved),
        "consumed" => Ok(FindingPurchaseReservationState::Consumed),
        "released" => Ok(FindingPurchaseReservationState::Released),
        "expired" => Ok(FindingPurchaseReservationState::Expired),
        other => Err(invariant(format!("unknown reservation state {other}"))),
    }
}

const fn reservation_state_name(state: FindingPurchaseReservationState) -> &'static str {
    match state {
        FindingPurchaseReservationState::Open => "open",
        FindingPurchaseReservationState::SlotReserved => "slot_reserved",
        FindingPurchaseReservationState::Consumed => "consumed",
        FindingPurchaseReservationState::Released => "released",
        FindingPurchaseReservationState::Expired => "expired",
    }
}

fn encumbrance_state_from_name(
    name: &str,
) -> Result<FindingPurchaseEncumbranceState, FindingPurchaseStoreError> {
    match name {
        "open" => Ok(FindingPurchaseEncumbranceState::Open),
        "released" => Ok(FindingPurchaseEncumbranceState::Released),
        "retained" => Ok(FindingPurchaseEncumbranceState::Retained),
        other => Err(invariant(format!("unknown encumbrance state {other}"))),
    }
}

fn slot_state_from_name(name: &str) -> Result<FindingPurchaseSlotState, FindingPurchaseStoreError> {
    match name {
        "reserved" => Ok(FindingPurchaseSlotState::Reserved),
        "closed_record" => Ok(FindingPurchaseSlotState::ClosedRecord),
        "closed_deny" => Ok(FindingPurchaseSlotState::ClosedDeny),
        other => Err(invariant(format!("unknown slot state {other}"))),
    }
}

pub(crate) fn initialize_finding_purchase_schema(
    connection: &mut Connection,
) -> Result<(), FindingPurchaseStoreError> {
    let on_disk = crate::check_schema_version(
        connection,
        FINDING_PURCHASE_SCHEMA_KEY,
        FINDING_PURCHASE_SUPPORTED_SCHEMA_VERSION,
        FINDING_PURCHASE_SCHEMA_ANCHORS,
    )
    .map_err(|error| invariant(error.to_string()))?;
    if on_disk == FINDING_PURCHASE_SUPPORTED_SCHEMA_VERSION {
        return verify_finding_purchase_invariants(connection);
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;
    park_listing_keyed_sales_blocks(&transaction, on_disk)?;
    transaction
        .execute_batch(FINDING_PURCHASE_SCHEMA)
        .map_err(sqlite_error)?;
    carry_listing_sales_blocks_across(&transaction)?;
    crate::stamp_schema_version(
        &transaction,
        FINDING_PURCHASE_SCHEMA_KEY,
        FINDING_PURCHASE_SUPPORTED_SCHEMA_VERSION,
    )
    .map_err(|error| invariant(error.to_string()))?;
    verify_finding_purchase_invariants(&transaction)?;
    transaction.commit().map_err(sqlite_error)
}

/// Park a listing-keyed sales block table beside the schema batch so the
/// batch can create the episode line under the canonical name.
///
/// `CREATE TABLE IF NOT EXISTS` leaves an existing definition alone and
/// SQLite cannot re-key a table in place, so a database provisioned when a
/// block was a single never-lifted row per listing keeps that shape until
/// its rows are carried across. The two legacy triggers go with it: they
/// are attached to the parked table under names the episode line reuses,
/// and a surviving trigger would make the batch's `IF NOT EXISTS` guard
/// skip the definition that replaces it.
///
/// Gated structurally as well as by revision, so it applies at most once
/// and never touches a database that already carries the episode line.
fn park_listing_keyed_sales_blocks(
    transaction: &Transaction<'_>,
    on_disk_version: i32,
) -> Result<(), FindingPurchaseStoreError> {
    if on_disk_version != FINDING_PURCHASE_LISTING_KEYED_BLOCK_VERSION {
        return Ok(());
    }
    let definition: Option<String> = transaction
        .query_row(
            r#"
            SELECT sql FROM sqlite_schema
            WHERE type = 'table' AND name = 'listing_sales_blocks'
            "#,
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(definition) = definition else {
        return Ok(());
    };
    if definition.contains("block_ordinal") {
        return Ok(());
    }
    transaction
        .execute_batch(&format!(
            r#"
            DROP TRIGGER IF EXISTS listing_sales_blocks_immutable;
            DROP TRIGGER IF EXISTS listing_sales_blocks_no_delete;
            ALTER TABLE listing_sales_blocks RENAME TO {LEGACY_SALES_BLOCK_TABLE};
            "#
        ))
        .map_err(sqlite_error)?;
    Ok(())
}

/// Move every parked block onto the episode line as that listing's first
/// episode, still blocked, and drop the parked table once its rows are
/// across.
///
/// A listing-keyed block was raised and never lifted, so carrying it as a
/// live episode is what the listing's sales state already is: no listing
/// silently starts selling again across the upgrade, and none is stranded
/// under a block the reversal transition cannot reach. The copy is a plain
/// `INSERT`, so a row the episode line's constraints reject aborts the
/// open rather than being dropped.
fn carry_listing_sales_blocks_across(
    transaction: &Transaction<'_>,
) -> Result<(), FindingPurchaseStoreError> {
    let parked: bool = transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1
            )
            "#,
            [LEGACY_SALES_BLOCK_TABLE],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !parked {
        return Ok(());
    }
    let expected: i64 = transaction
        .query_row(
            &format!("SELECT COUNT(*) FROM {LEGACY_SALES_BLOCK_TABLE}"),
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let carried = transaction
        .execute(
            &format!(
                r#"
                INSERT INTO listing_sales_blocks (
                    listing_id, block_ordinal, state, blocked_at, lifted_at
                )
                SELECT listing_id, 1, 'blocked', blocked_at, NULL
                FROM {LEGACY_SALES_BLOCK_TABLE}
                "#
            ),
            [],
        )
        .map_err(sqlite_error)?;
    if i64::try_from(carried).unwrap_or(i64::MAX) != expected {
        return Err(invariant(format!(
            "listing sales block migration carried {carried} of {expected} rows"
        )));
    }
    transaction
        .execute_batch(&format!("DROP TABLE {LEGACY_SALES_BLOCK_TABLE};"))
        .map_err(sqlite_error)?;
    Ok(())
}

/// Verify the purchase schema's shape: this database's table, index, and
/// trigger definitions against a freshly created canonical schema. The
/// cost is a handful of `sqlite_schema` rows, independent of how many
/// purchases have accumulated, so this runs on every open.
///
/// Retained record digests are NOT re-hashed here. Every read path
/// re-verifies the exact bytes it returns against their stored digest
/// before handing them out, so a corrupted row is caught when it is used.
///
/// Fails closed: any schema-shape difference rejects the open.
pub(crate) fn verify_finding_purchase_invariants(
    connection: &Connection,
) -> Result<(), FindingPurchaseStoreError> {
    let expected = Connection::open_in_memory().map_err(sqlite_error)?;
    expected
        .execute_batch(FINDING_PURCHASE_SCHEMA)
        .map_err(sqlite_error)?;
    if finding_purchase_schema_catalog(connection)? != finding_purchase_schema_catalog(&expected)? {
        return Err(invariant(
            "finding purchase schema differs from the canonical definition",
        ));
    }
    Ok(())
}

type SchemaCatalogEntry = (String, String, String, Option<String>);

fn finding_purchase_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SchemaCatalogEntry>, FindingPurchaseStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT type, name, tbl_name, sql
            FROM sqlite_schema
            WHERE name GLOB 'purchase_reservations*'
               OR tbl_name GLOB 'purchase_reservations*'
               OR name GLOB 'seller_exposure_encumbrances*'
               OR tbl_name GLOB 'seller_exposure_encumbrances*'
               OR name GLOB 'pending_purchase_slots*'
               OR tbl_name GLOB 'pending_purchase_slots*'
               OR name GLOB 'purchase_records*' OR tbl_name GLOB 'purchase_records*'
               OR name GLOB 'failed_delivery_records*'
               OR tbl_name GLOB 'failed_delivery_records*'
               OR name GLOB 'payout_destinations*'
               OR tbl_name GLOB 'payout_destinations*'
               OR name GLOB 'listing_sales_blocks*'
               OR tbl_name GLOB 'listing_sales_blocks*'
               ORDER BY type, name, tbl_name
            "#,
        )
        .map_err(sqlite_error)?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(entries)
}

/// Recompute `bytes`' digest and compare it to the value stored alongside
/// them, failing closed on any mismatch. Both retained record columns
/// route through this one comparison so the check cannot drift between
/// call sites.
fn verify_stored_digest(
    bytes: &[u8],
    expected_hex: &str,
    what: &str,
) -> Result<(), FindingPurchaseStoreError> {
    if sha256_hex(bytes) == expected_hex {
        Ok(())
    } else {
        Err(invariant(format!("{what} digest is invalid")))
    }
}

fn require_terminal_record(
    bytes: &[u8],
    expected_hex: &str,
) -> Result<(), FindingPurchaseStoreError> {
    if bytes.is_empty() || bytes.len() > MAX_TERMINAL_RECORD_BYTES {
        return Err(invariant("terminal record byte length is out of bounds"));
    }
    if sha256_hex(bytes) != expected_hex {
        return Err(FindingPurchaseStoreError::Conflict(
            "terminal record bytes do not match the claimed digest".to_owned(),
        ));
    }
    Ok(())
}

fn require_hex64(value: &str, field: &'static str) -> Result<(), FindingPurchaseStoreError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(invariant(format!(
        "{field} is not 64 lowercase hex characters"
    )))
}

fn require_identifier(value: &str, field: &'static str) -> Result<(), FindingPurchaseStoreError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(invariant(format!("{field} byte length is out of bounds")));
    }
    Ok(())
}

/// A payout destination is rail-tagged: a nonempty rail prefix, a colon,
/// and a nonempty account. An untagged destination cannot be routed, so it
/// is refused rather than stored.
fn require_rail_destination(value: &str) -> Result<(), FindingPurchaseStoreError> {
    require_identifier(value, "destination")?;
    match value.split_once(':') {
        Some((rail, account)) if !rail.is_empty() && !account.is_empty() => Ok(()),
        _ => Err(invariant("payout destination is not rail-tagged")),
    }
}

fn require_currency(currency: &str) -> Result<(), FindingPurchaseStoreError> {
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(invariant("currency is not a three-letter uppercase code"));
    }
    Ok(())
}

fn require_trusted_time(value: u64, field: &'static str) -> Result<(), FindingPurchaseStoreError> {
    if value == 0 {
        return Err(invariant(format!("{field} must be nonzero")));
    }
    Ok(())
}

fn sqlite_i64(value: u64, field: &'static str) -> Result<i64, FindingPurchaseStoreError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite integer range")))
}

fn stored_u64(value: i64, field: &'static str) -> Result<u64, FindingPurchaseStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("{field} is negative")))
}

fn stored_slot_index(value: i64) -> Result<u8, FindingPurchaseStoreError> {
    u8::try_from(value)
        .ok()
        .filter(|index| *index < PAYOUT_DESTINATION_SLOTS)
        .ok_or_else(|| invariant("stored payout slot index is out of range"))
}

fn invariant(detail: impl Into<String>) -> FindingPurchaseStoreError {
    FindingPurchaseStoreError::Invariant(detail.into())
}

fn admission_error(error: AdmissionOperationStoreError) -> FindingPurchaseStoreError {
    match error {
        AdmissionOperationStoreError::Fenced => FindingPurchaseStoreError::Fenced,
        AdmissionOperationStoreError::NotFound => FindingPurchaseStoreError::NotFound,
        AdmissionOperationStoreError::Unavailable(detail) => {
            FindingPurchaseStoreError::Unavailable(detail)
        }
        AdmissionOperationStoreError::OutcomeUnknown(detail) => {
            FindingPurchaseStoreError::OutcomeUnknown(detail)
        }
        AdmissionOperationStoreError::Invariant(detail) => {
            FindingPurchaseStoreError::Invariant(detail)
        }
        AdmissionOperationStoreError::Operation(error) => invariant(error.to_string()),
    }
}

fn sqlite_error(error: rusqlite::Error) -> FindingPurchaseStoreError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::Utf8Error(..) => invariant(error.to_string()),
        other => FindingPurchaseStoreError::Unavailable(other.to_string()),
    }
}

#[cfg(test)]
#[path = "finding_purchase_store_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
