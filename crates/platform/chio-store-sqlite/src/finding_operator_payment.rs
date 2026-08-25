//! Durable reversible-hold payment adapter for a single-operator market.
//!
//! This adapter records local pilot credits, not external currency. Every
//! authorization and terminal action is idempotent and bound to the complete
//! payment request. It is suitable for the single-operator pilot where the
//! operator's venue ledger is the settlement rail.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::sha256_hex;
use chio_kernel::payment::{
    PaymentAdapter, PaymentAuthorization, PaymentAuthorizationState, PaymentAuthorizeRequest,
    PaymentError, PaymentRailMode, PaymentResult, RailSettlementStatus,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

const SCHEMA_KEY: &str = "finding_operator_payment";
const SUPPORTED_SCHEMA_VERSION: i32 = 0;
const SCHEMA_ANCHORS: &[&str] = &[
    "chio_finding_operator_bundles",
    "chio_finding_payloads",
    "chio_finding_operator_payments",
];
const RAIL_ID: &str = "finding-operator-ledger";
const MAX_TEXT_BYTES: usize = 512;

/// Durable local-credit settlement adapter for the operator pilot.
#[derive(Clone)]
pub struct SqliteFindingOperatorPaymentAdapter {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteFindingOperatorPaymentAdapter {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::builder()
            .max_size(8)
            .build(manager)
            .map_err(|error| error.to_string())?;
        let store = Self { pool };
        store.run_migrations()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, String> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder()
            .max_size(1)
            .build(manager)
            .map_err(|error| error.to_string())?;
        let store = Self { pool };
        store.run_migrations()?;
        Ok(store)
    }

    fn run_migrations(&self) -> Result<(), String> {
        let conn = self.pool.get().map_err(|error| error.to_string())?;
        crate::check_schema_version(&conn, SCHEMA_KEY, SUPPORTED_SCHEMA_VERSION, SCHEMA_ANCHORS)
            .map_err(|error| error.to_string())?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS chio_finding_operator_payments (
                authorization_id TEXT PRIMARY KEY,
                reference TEXT NOT NULL UNIQUE,
                payer TEXT NOT NULL,
                payee TEXT NOT NULL,
                amount_units INTEGER NOT NULL CHECK(amount_units > 0),
                currency TEXT NOT NULL CHECK(length(currency) = 3),
                state TEXT NOT NULL CHECK(state IN ('held', 'captured', 'released', 'refunded')),
                transaction_id TEXT,
                prior_transaction_id TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            "#,
        )
        .map_err(|error| error.to_string())?;
        crate::stamp_schema_version(&conn, SCHEMA_KEY, SUPPORTED_SCHEMA_VERSION)
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn authorize_durable(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, String> {
        validate_request(request)?;
        let authorization_id = authorization_id(request);
        let amount_units = i64::try_from(request.amount_units)
            .map_err(|_| "payment amount exceeds SQLite integer range".to_owned())?;
        let mut conn = self.pool.get().map_err(|error| error.to_string())?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let existing = load_by_reference(&tx, &request.reference)?;
        if let Some(existing) = existing {
            if existing.authorization_id != authorization_id
                || existing.payer != request.payer
                || existing.payee != request.payee
                || existing.amount_units != request.amount_units
                || existing.currency != request.currency
            {
                return Err("payment authorization conflicts with durable state".to_owned());
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(held_authorization(existing.authorization_id, true));
        }
        let now = now_secs();
        tx.execute(
            r#"
            INSERT INTO chio_finding_operator_payments
                (authorization_id, reference, payer, payee, amount_units, currency,
                 state, transaction_id, prior_transaction_id, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'held', NULL, NULL, ?7, ?7)
            "#,
            params![
                authorization_id,
                request.reference,
                request.payer,
                request.payee,
                amount_units,
                request.currency,
                now,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(held_authorization(authorization_id, false))
    }

    fn settle(
        &self,
        authorization_id: &str,
        action: SettlementAction<'_>,
    ) -> Result<PaymentResult, String> {
        validate_text(authorization_id, "authorization_id")?;
        let mut conn = self.pool.get().map_err(|error| error.to_string())?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let record = load_by_authorization(&tx, authorization_id)?
            .ok_or_else(|| "payment authorization was not found".to_owned())?;
        let (target_state, transaction_id, status) = match action {
            SettlementAction::Capture {
                amount_units,
                currency,
                reference,
            } => {
                if amount_units != record.amount_units
                    || currency != record.currency
                    || reference != record.reference
                {
                    return Err("capture does not bind the authorized payment".to_owned());
                }
                (
                    "captured",
                    terminal_id("capture", authorization_id),
                    RailSettlementStatus::Settled,
                )
            }
            SettlementAction::Release { reference } => {
                if reference != record.reference {
                    return Err("release does not bind the authorized payment".to_owned());
                }
                (
                    "released",
                    terminal_id("release", authorization_id),
                    RailSettlementStatus::Released,
                )
            }
            SettlementAction::Refund { transaction_id } => {
                let binds_capture = (record.state == "captured"
                    && record.transaction_id.as_deref() == Some(transaction_id))
                    || (record.state == "refunded"
                        && record.prior_transaction_id.as_deref() == Some(transaction_id));
                if !binds_capture {
                    return Err("refund does not bind a captured payment".to_owned());
                }
                (
                    "refunded",
                    terminal_id("refund", authorization_id),
                    RailSettlementStatus::Refunded,
                )
            }
        };

        if record.state == target_state {
            if record.transaction_id.as_deref() != Some(transaction_id.as_str()) {
                return Err("payment terminal conflicts with durable state".to_owned());
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(payment_result(transaction_id, status, true));
        }
        let source_allowed = match action {
            SettlementAction::Capture { .. } | SettlementAction::Release { .. } => {
                record.state == "held"
            }
            SettlementAction::Refund { .. } => record.state == "captured",
        };
        if !source_allowed {
            return Err("payment is already in an incompatible terminal state".to_owned());
        }
        let prior_transaction_id = matches!(action, SettlementAction::Refund { .. })
            .then_some(record.transaction_id.as_deref())
            .flatten();
        tx.execute(
            r#"
            UPDATE chio_finding_operator_payments
            SET state = ?2, transaction_id = ?3, updated_at = ?4,
                prior_transaction_id = ?5
            WHERE authorization_id = ?1
            "#,
            params![
                authorization_id,
                target_state,
                transaction_id,
                now_secs(),
                prior_transaction_id,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(payment_result(transaction_id, status, false))
    }

    /// Count durable captured or subsequently refunded payments for pilot
    /// conservation checks.
    pub fn capture_count(&self) -> Result<u64, String> {
        let conn = self.pool.get().map_err(|error| error.to_string())?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM chio_finding_operator_payments WHERE state IN ('captured', 'refunded')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        u64::try_from(count).map_err(|_| "payment count was negative".to_owned())
    }
}

impl PaymentAdapter for SqliteFindingOperatorPaymentAdapter {
    fn rail_id(&self) -> &'static str {
        RAIL_ID
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::ReversibleHold)
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.authorize_durable(request)
            .map_err(PaymentError::RailError)
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.settle(
            authorization_id,
            SettlementAction::Capture {
                amount_units,
                currency,
                reference,
            },
        )
        .map_err(PaymentError::RailError)
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.settle(authorization_id, SettlementAction::Release { reference })
            .map_err(PaymentError::RailError)
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        let conn = self
            .pool
            .get()
            .map_err(|error| PaymentError::RailError(error.to_string()))?;
        let authorization_id: Option<String> = conn
            .query_row(
                "SELECT authorization_id FROM chio_finding_operator_payments WHERE transaction_id = ?1",
                [transaction_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| PaymentError::RailError(error.to_string()))?;
        drop(conn);
        let authorization_id = authorization_id
            .ok_or_else(|| PaymentError::RailError("captured payment was not found".to_owned()))?;
        self.settle(
            &authorization_id,
            SettlementAction::Refund { transaction_id },
        )
        .map_err(PaymentError::RailError)
    }
}

#[derive(Clone, Copy)]
enum SettlementAction<'a> {
    Capture {
        amount_units: u64,
        currency: &'a str,
        reference: &'a str,
    },
    Release {
        reference: &'a str,
    },
    Refund {
        transaction_id: &'a str,
    },
}

struct PaymentRecord {
    authorization_id: String,
    reference: String,
    payer: String,
    payee: String,
    amount_units: u64,
    currency: String,
    state: String,
    transaction_id: Option<String>,
    prior_transaction_id: Option<String>,
}

fn load_by_reference(
    conn: &rusqlite::Connection,
    reference: &str,
) -> Result<Option<PaymentRecord>, String> {
    load_record(conn, "reference", reference)
}

fn load_by_authorization(
    conn: &rusqlite::Connection,
    authorization_id: &str,
) -> Result<Option<PaymentRecord>, String> {
    load_record(conn, "authorization_id", authorization_id)
}

fn load_record(
    conn: &rusqlite::Connection,
    column: &str,
    value: &str,
) -> Result<Option<PaymentRecord>, String> {
    let sql = format!(
        "SELECT authorization_id, reference, payer, payee, amount_units, currency, state, transaction_id, prior_transaction_id FROM chio_finding_operator_payments WHERE {column} = ?1"
    );
    conn.query_row(&sql, [value], |row| {
        let amount_units: i64 = row.get("amount_units")?;
        Ok((
            row.get("authorization_id")?,
            row.get("reference")?,
            row.get("payer")?,
            row.get("payee")?,
            amount_units,
            row.get("currency")?,
            row.get("state")?,
            row.get("transaction_id")?,
            row.get("prior_transaction_id")?,
        ))
    })
    .optional()
    .map_err(|error| error.to_string())?
    .map(
        |(
            authorization_id,
            reference,
            payer,
            payee,
            amount_units,
            currency,
            state,
            transaction_id,
            prior_transaction_id,
        )| {
            Ok(PaymentRecord {
                authorization_id,
                reference,
                payer,
                payee,
                amount_units: u64::try_from(amount_units)
                    .map_err(|_| "stored payment amount was negative".to_owned())?,
                currency,
                state,
                transaction_id,
                prior_transaction_id,
            })
        },
    )
    .transpose()
}

fn validate_request(request: &PaymentAuthorizeRequest) -> Result<(), String> {
    validate_text(&request.reference, "reference")?;
    validate_text(&request.payer, "payer")?;
    validate_text(&request.payee, "payee")?;
    if request.amount_units == 0 || request.amount_units > i64::MAX as u64 {
        return Err("payment amount is outside the supported range".to_owned());
    }
    if request.currency.len() != 3
        || !request
            .currency
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
    {
        return Err("payment currency must be three uppercase letters".to_owned());
    }
    Ok(())
}

fn validate_text(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(format!("invalid payment {field}"));
    }
    Ok(())
}

fn authorization_id(request: &PaymentAuthorizeRequest) -> String {
    let preimage = format!(
        "chio.finding.operator-payment.v1\0{}\0{}\0{}\0{}\0{}",
        request.reference, request.payer, request.payee, request.amount_units, request.currency
    );
    format!("hold:{}", sha256_hex(preimage.as_bytes()))
}

fn terminal_id(action: &str, authorization_id: &str) -> String {
    format!(
        "{action}:{}",
        sha256_hex(format!("{action}\0{authorization_id}").as_bytes())
    )
}

fn held_authorization(authorization_id: String, replay: bool) -> PaymentAuthorization {
    PaymentAuthorization {
        authorization_id,
        state: PaymentAuthorizationState::Held,
        metadata: serde_json::json!({
            "rail": RAIL_ID,
            "localCredits": true,
            "replay": replay,
        }),
    }
}

fn payment_result(
    transaction_id: String,
    settlement_status: RailSettlementStatus,
    replay: bool,
) -> PaymentResult {
    PaymentResult {
        transaction_id,
        settlement_status,
        metadata: serde_json::json!({
            "rail": RAIL_ID,
            "localCredits": true,
            "replay": replay,
        }),
    }
}

fn now_secs() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn request(reference: &str) -> PaymentAuthorizeRequest {
        PaymentAuthorizeRequest {
            amount_units: 25,
            currency: "USD".to_owned(),
            payer: "buyer-1".to_owned(),
            payee: "seller-1".to_owned(),
            reference: reference.to_owned(),
            governed: None,
            commerce: None,
        }
    }

    #[test]
    fn capture_is_restart_safe_and_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operator.db");
        let adapter = SqliteFindingOperatorPaymentAdapter::open(&path).unwrap();
        let first = adapter.authorize(&request("purchase-1")).unwrap();
        let captured = adapter
            .capture(&first.authorization_id, 25, "USD", "purchase-1")
            .unwrap();
        drop(adapter);

        let reopened = SqliteFindingOperatorPaymentAdapter::open(&path).unwrap();
        let replayed_auth = reopened.authorize(&request("purchase-1")).unwrap();
        let replayed_capture = reopened
            .capture(&replayed_auth.authorization_id, 25, "USD", "purchase-1")
            .unwrap();
        assert_eq!(captured.transaction_id, replayed_capture.transaction_id);
        assert_eq!(reopened.capture_count().unwrap(), 1);
    }

    #[test]
    fn release_and_capture_are_mutually_exclusive() {
        let adapter = SqliteFindingOperatorPaymentAdapter::open_in_memory().unwrap();
        let authorization = adapter.authorize(&request("purchase-2")).unwrap();
        let released = adapter
            .release(&authorization.authorization_id, "purchase-2")
            .unwrap();
        assert_eq!(released.settlement_status, RailSettlementStatus::Released);
        assert!(adapter
            .capture(&authorization.authorization_id, 25, "USD", "purchase-2")
            .is_err());
        assert_eq!(adapter.capture_count().unwrap(), 0);
    }

    #[test]
    fn changed_authorization_replay_is_rejected() {
        let adapter = SqliteFindingOperatorPaymentAdapter::open_in_memory().unwrap();
        adapter.authorize(&request("purchase-3")).unwrap();
        let mut changed = request("purchase-3");
        changed.amount_units = 26;
        assert!(adapter.authorize(&changed).is_err());
    }
}
