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
#[cfg(test)]
use chio_kernel::payment::GovernedPaymentContext;
use chio_kernel::payment::{
    PaymentAdapter, PaymentAuthorization, PaymentAuthorizationState, PaymentAuthorizeRequest,
    PaymentError, PaymentRailMode, PaymentResult, RailSettlementStatus,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

fn configure_pooled_connection(connection: &mut rusqlite::Connection) -> rusqlite::Result<()> {
    connection.execute_batch("PRAGMA busy_timeout = 5000;")
}

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
        let manager = SqliteConnectionManager::file(path).with_init(configure_pooled_connection);
        let pool = Pool::builder()
            .max_size(8)
            .build(manager)
            .map_err(|error| error.to_string())?;
        let store = Self { pool };
        store.run_migrations()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, String> {
        let manager = SqliteConnectionManager::memory().with_init(configure_pooled_connection);
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
                governed_intent_id TEXT,
                governed_intent_hash TEXT,
                state TEXT NOT NULL CHECK(state IN ('held', 'captured', 'released', 'refunded')),
                transaction_id TEXT,
                prior_transaction_id TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            "#,
        )
        .map_err(|error| error.to_string())?;
        ensure_payment_column(&conn, "governed_intent_id", "TEXT")?;
        ensure_payment_column(&conn, "governed_intent_hash", "TEXT")?;
        conn.execute_batch(
            r#"
            CREATE UNIQUE INDEX IF NOT EXISTS chio_finding_operator_payments_governed_intent
            ON chio_finding_operator_payments(governed_intent_id)
            WHERE governed_intent_id IS NOT NULL;
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
        let governed_intent_id = request
            .governed
            .as_ref()
            .map(|value| value.intent_id.as_str());
        let governed_intent_hash = request
            .governed
            .as_ref()
            .map(|value| value.intent_hash.as_str());
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
            match (
                existing.governed_intent_id.as_deref(),
                existing.governed_intent_hash.as_deref(),
                governed_intent_id,
                governed_intent_hash,
            ) {
                (None, None, Some(intent_id), Some(intent_hash)) => {
                    tx.execute(
                        r#"
                        UPDATE chio_finding_operator_payments
                        SET governed_intent_id = ?2, governed_intent_hash = ?3,
                            updated_at = ?4
                        WHERE authorization_id = ?1
                          AND governed_intent_id IS NULL
                          AND governed_intent_hash IS NULL
                        "#,
                        params![
                            existing.authorization_id,
                            intent_id,
                            intent_hash,
                            now_secs()
                        ],
                    )
                    .map_err(|error| error.to_string())?;
                }
                (Some(existing_id), None, Some(intent_id), Some(intent_hash))
                    if existing_id == intent_id =>
                {
                    tx.execute(
                        r#"
                        UPDATE chio_finding_operator_payments
                        SET governed_intent_hash = ?2, updated_at = ?3
                        WHERE authorization_id = ?1
                          AND governed_intent_id = ?4
                          AND governed_intent_hash IS NULL
                        "#,
                        params![
                            existing.authorization_id,
                            intent_hash,
                            now_secs(),
                            intent_id
                        ],
                    )
                    .map_err(|error| error.to_string())?;
                }
                (existing_id, existing_hash, requested_id, requested_hash)
                    if existing_id == requested_id && existing_hash == requested_hash => {}
                _ => {
                    return Err("payment authorization conflicts with durable state".to_owned());
                }
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(held_authorization(existing.authorization_id, true));
        }
        let now = now_secs();
        tx.execute(
            r#"
            INSERT INTO chio_finding_operator_payments
                (authorization_id, reference, payer, payee, amount_units, currency,
                 governed_intent_id, governed_intent_hash, state, transaction_id,
                 prior_transaction_id, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'held', NULL, NULL, ?9, ?9)
            "#,
            params![
                authorization_id,
                request.reference,
                request.payer,
                request.payee,
                amount_units,
                request.currency,
                governed_intent_id,
                governed_intent_hash,
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
            SettlementAction::Refund {
                transaction_id,
                amount_units,
                currency,
                reference,
            } => {
                let binds_capture = (record.state == "captured"
                    && record.transaction_id.as_deref() == Some(transaction_id))
                    || (record.state == "refunded"
                        && record.prior_transaction_id.as_deref() == Some(transaction_id));
                if !binds_capture
                    || amount_units != record.amount_units
                    || currency != record.currency
                    || reference != record.reference
                {
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

    /// Release or refund any durable local-credit payment before an expired
    /// purchase reservation is closed. Replays are exact and terminal.
    pub fn reconcile_expired_reference(
        &self,
        reference: &str,
        payer: &str,
        amount_units: u64,
        currency: &str,
    ) -> Result<(), String> {
        validate_reconciliation_binding(payer, amount_units, currency)?;
        validate_text(reference, "reference")?;
        let conn = self.pool.get().map_err(|error| error.to_string())?;
        let Some(record) = load_by_reference(&conn, reference)? else {
            return Ok(());
        };
        drop(conn);
        self.reconcile_record(record, payer, amount_units, currency)
    }

    /// Reconcile the payment bound to one governed cognition-market intent.
    /// Legacy rows without this binding fail closed if they could be live.
    pub fn reconcile_expired_governed_intent(
        &self,
        governed_intent_id: &str,
        request_id: &str,
        payer: &str,
        amount_units: u64,
        currency: &str,
    ) -> Result<(), String> {
        validate_reconciliation_binding(payer, amount_units, currency)?;
        validate_text(governed_intent_id, "governed_intent_id")?;
        validate_text(request_id, "request_id")?;
        let mut conn = self.pool.get().map_err(|error| error.to_string())?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let mut record = load_by_governed_intent_id(&tx, governed_intent_id)?;
        if record.is_none() {
            record = bind_legacy_payment_from_journal(
                &tx,
                governed_intent_id,
                request_id,
                payer,
                amount_units,
                currency,
            )?;
        }
        if record.is_none() {
            let amount_units = i64::try_from(amount_units)
                .map_err(|_| "payment amount exceeds SQLite integer range".to_owned())?;
            let legacy_live: i64 = tx
                .query_row(
                    r#"
                    SELECT COUNT(*) FROM chio_finding_operator_payments
                    WHERE governed_intent_id IS NULL
                      AND payer = ?1 AND amount_units = ?2 AND currency = ?3
                      AND state IN ('held', 'captured')
                    "#,
                    params![payer, amount_units, currency],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            if legacy_live != 0 {
                return Err(
                    "legacy live payment cannot be bound to the expired governed intent".to_owned(),
                );
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(());
        }
        tx.commit().map_err(|error| error.to_string())?;
        drop(conn);
        self.reconcile_record(
            record.ok_or_else(|| "governed payment disappeared".to_owned())?,
            payer,
            amount_units,
            currency,
        )
    }

    fn reconcile_record(
        &self,
        record: PaymentRecord,
        payer: &str,
        amount_units: u64,
        currency: &str,
    ) -> Result<(), String> {
        if record.payer != payer
            || record.amount_units != amount_units
            || record.currency != currency
        {
            return Err("expired payment reconciliation conflicts with durable state".to_owned());
        }
        let reference = record.reference.clone();
        match record.state.as_str() {
            "held" => {
                self.settle(
                    &record.authorization_id,
                    SettlementAction::Release {
                        reference: &reference,
                    },
                )?;
            }
            "captured" => {
                let transaction_id = record.transaction_id.as_deref().ok_or_else(|| {
                    "captured payment omitted its durable transaction id".to_owned()
                })?;
                self.settle(
                    &record.authorization_id,
                    SettlementAction::Refund {
                        transaction_id,
                        amount_units,
                        currency,
                        reference: &reference,
                    },
                )?;
            }
            "released" | "refunded" => {}
            _ => return Err("stored payment state is unsupported".to_owned()),
        }
        Ok(())
    }

    /// Count payments refunded by recovery after a prior capture.
    pub fn refund_count(&self) -> Result<u64, String> {
        let conn = self.pool.get().map_err(|error| error.to_string())?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM chio_finding_operator_payments WHERE state = 'refunded'",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        u64::try_from(count).map_err(|_| "payment count was negative".to_owned())
    }
}

fn bind_legacy_payment_from_journal(
    tx: &rusqlite::Transaction<'_>,
    governed_intent_id: &str,
    request_id: &str,
    payer: &str,
    amount_units: u64,
    currency: &str,
) -> Result<Option<PaymentRecord>, String> {
    let journal_exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'payment_journal')",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !journal_exists {
        return Ok(None);
    }
    let amount_units = i64::try_from(amount_units)
        .map_err(|_| "payment amount exceeds SQLite integer range".to_owned())?;
    let mut statement = tx
        .prepare(
            r#"
            SELECT payment.authorization_id
            FROM chio_finding_operator_payments AS payment
            INNER JOIN payment_journal AS journal
              ON journal.operation_id = payment.reference
             AND journal.authorization_id = payment.authorization_id
            WHERE journal.request_id = ?1
              AND payment.payer = ?2
              AND payment.amount_units = ?3
              AND payment.currency = ?4
              AND payment.governed_intent_id IS NULL
              AND payment.governed_intent_hash IS NULL
            ORDER BY payment.authorization_id
            LIMIT 2
            "#,
        )
        .map_err(|error| error.to_string())?;
    let candidates = statement
        .query_map(params![request_id, payer, amount_units, currency], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    drop(statement);
    let [authorization_id] = candidates.as_slice() else {
        if candidates.is_empty() {
            return Ok(None);
        }
        return Err("multiple legacy payments match the expired governed intent".to_owned());
    };
    let changed = tx
        .execute(
            r#"
            UPDATE chio_finding_operator_payments
            SET governed_intent_id = ?2, updated_at = ?3
            WHERE authorization_id = ?1
              AND governed_intent_id IS NULL
              AND governed_intent_hash IS NULL
            "#,
            params![authorization_id, governed_intent_id, now_secs()],
        )
        .map_err(|error| error.to_string())?;
    if changed != 1 {
        return Err("legacy payment binding changed concurrently".to_owned());
    }
    load_by_authorization(tx, authorization_id)
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
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        validate_text(transaction_id, "refund_identifier").map_err(PaymentError::RailError)?;
        let conn = self
            .pool
            .get()
            .map_err(|error| PaymentError::RailError(error.to_string()))?;
        let payment: Option<(String, String)> = conn
            .query_row(
                r#"
                SELECT authorization_id,
                       CASE WHEN state = 'refunded'
                            THEN prior_transaction_id ELSE transaction_id END
                FROM chio_finding_operator_payments
                WHERE authorization_id = ?1 OR transaction_id = ?1 OR prior_transaction_id = ?1
                "#,
                [transaction_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| PaymentError::RailError(error.to_string()))?;
        drop(conn);
        let (authorization_id, captured_transaction_id) = payment
            .ok_or_else(|| PaymentError::RailError("captured payment was not found".to_owned()))?;
        self.settle(
            &authorization_id,
            SettlementAction::Refund {
                transaction_id: &captured_transaction_id,
                amount_units,
                currency,
                reference,
            },
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
        amount_units: u64,
        currency: &'a str,
        reference: &'a str,
    },
}

struct PaymentRecord {
    authorization_id: String,
    reference: String,
    payer: String,
    payee: String,
    amount_units: u64,
    currency: String,
    governed_intent_id: Option<String>,
    governed_intent_hash: Option<String>,
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

fn load_by_governed_intent_id(
    conn: &rusqlite::Connection,
    governed_intent_id: &str,
) -> Result<Option<PaymentRecord>, String> {
    load_record(conn, "governed_intent_id", governed_intent_id)
}

fn load_record(
    conn: &rusqlite::Connection,
    column: &str,
    value: &str,
) -> Result<Option<PaymentRecord>, String> {
    let sql = format!(
        "SELECT authorization_id, reference, payer, payee, amount_units, currency, governed_intent_id, governed_intent_hash, state, transaction_id, prior_transaction_id FROM chio_finding_operator_payments WHERE {column} = ?1"
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
            row.get("governed_intent_id")?,
            row.get("governed_intent_hash")?,
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
            governed_intent_id,
            governed_intent_hash,
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
                governed_intent_id,
                governed_intent_hash,
                state,
                transaction_id,
                prior_transaction_id,
            })
        },
    )
    .transpose()
}

fn ensure_payment_column(
    conn: &rusqlite::Connection,
    column: &str,
    definition: &str,
) -> Result<(), String> {
    if !matches!(column, "governed_intent_id" | "governed_intent_hash") || definition != "TEXT" {
        return Err("unsupported operator payment migration column".to_owned());
    }
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('chio_finding_operator_payments') WHERE name = ?1)",
            [column],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !exists {
        conn.execute_batch(&format!(
            "ALTER TABLE chio_finding_operator_payments ADD COLUMN {column} {definition}"
        ))
        .map_err(|error| error.to_string())?;
    }
    Ok(())
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
    if let Some(governed) = request.governed.as_ref() {
        validate_text(&governed.intent_id, "governed_intent_id")?;
        validate_text(&governed.intent_hash, "governed_intent_hash")?;
    }
    Ok(())
}

fn validate_reconciliation_binding(
    payer: &str,
    amount_units: u64,
    currency: &str,
) -> Result<(), String> {
    validate_text(payer, "payer")?;
    if amount_units == 0 || amount_units > i64::MAX as u64 {
        return Err("payment amount is outside the supported range".to_owned());
    }
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
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

    fn governed_request(reference: &str, intent_id: &str) -> PaymentAuthorizeRequest {
        let mut request = request(reference);
        request.governed = Some(GovernedPaymentContext {
            intent_id: intent_id.to_owned(),
            intent_hash: "a".repeat(64),
            purpose: "purchase".to_owned(),
            server_id: "seller-1".to_owned(),
            tool_name: "read_finding".to_owned(),
            approval_token_id: None,
        });
        request
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
    fn every_pooled_connection_has_busy_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let adapter =
            SqliteFindingOperatorPaymentAdapter::open(dir.path().join("operator.db")).unwrap();
        let first = adapter.pool.get().unwrap();
        let second = adapter.pool.get().unwrap();

        for connection in [&first, &second] {
            let busy_timeout = connection
                .query_row("PRAGMA busy_timeout", [], |row| row.get::<_, i64>(0))
                .unwrap();
            assert!(busy_timeout >= 5_000);
        }
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

    #[test]
    fn refund_accepts_capture_or_authorization_id_and_replays_exactly() {
        let adapter = SqliteFindingOperatorPaymentAdapter::open_in_memory().unwrap();
        let authorization = adapter.authorize(&request("purchase-refund")).unwrap();
        let captured = adapter
            .capture(
                &authorization.authorization_id,
                25,
                "USD",
                "purchase-refund",
            )
            .unwrap();
        let refunded = adapter
            .refund(
                &authorization.authorization_id,
                25,
                "USD",
                "purchase-refund",
            )
            .unwrap();
        let replayed = adapter
            .refund(&captured.transaction_id, 25, "USD", "purchase-refund")
            .unwrap();
        let replayed_by_refund = adapter
            .refund(&refunded.transaction_id, 25, "USD", "purchase-refund")
            .unwrap();
        assert_eq!(refunded.transaction_id, replayed.transaction_id);
        assert_eq!(refunded.transaction_id, replayed_by_refund.transaction_id);
        assert_eq!(
            replayed_by_refund.settlement_status,
            RailSettlementStatus::Refunded
        );
    }

    #[test]
    fn refund_rejects_changed_payment_inputs() {
        let adapter = SqliteFindingOperatorPaymentAdapter::open_in_memory().unwrap();
        let authorization = adapter.authorize(&request("purchase-refund-bind")).unwrap();
        let captured = adapter
            .capture(
                &authorization.authorization_id,
                25,
                "USD",
                "purchase-refund-bind",
            )
            .unwrap();
        assert!(adapter
            .refund(&captured.transaction_id, 26, "USD", "purchase-refund-bind",)
            .is_err());
    }

    #[test]
    fn expired_reconciliation_releases_a_hold_exactly_once() {
        let adapter = SqliteFindingOperatorPaymentAdapter::open_in_memory().unwrap();
        let authorization = adapter
            .authorize(&request("purchase-expired-hold"))
            .unwrap();
        adapter
            .reconcile_expired_reference("purchase-expired-hold", "buyer-1", 25, "USD")
            .unwrap();
        adapter
            .reconcile_expired_reference("purchase-expired-hold", "buyer-1", 25, "USD")
            .unwrap();
        assert!(adapter
            .capture(
                &authorization.authorization_id,
                25,
                "USD",
                "purchase-expired-hold",
            )
            .is_err());
        assert_eq!(adapter.capture_count().unwrap(), 0);
    }

    #[test]
    fn expired_reconciliation_refunds_a_capture_exactly_once() {
        let adapter = SqliteFindingOperatorPaymentAdapter::open_in_memory().unwrap();
        let authorization = adapter
            .authorize(&request("purchase-expired-capture"))
            .unwrap();
        adapter
            .capture(
                &authorization.authorization_id,
                25,
                "USD",
                "purchase-expired-capture",
            )
            .unwrap();
        adapter
            .reconcile_expired_reference("purchase-expired-capture", "buyer-1", 25, "USD")
            .unwrap();
        adapter
            .reconcile_expired_reference("purchase-expired-capture", "buyer-1", 25, "USD")
            .unwrap();
        assert_eq!(adapter.capture_count().unwrap(), 1);
        assert_eq!(adapter.refund_count().unwrap(), 1);
    }

    #[test]
    fn expired_governed_intent_selects_the_exact_capture() {
        let adapter = SqliteFindingOperatorPaymentAdapter::open_in_memory().unwrap();
        let request = governed_request("durable-operation-1", "intent-request-1");
        let authorization = adapter.authorize(&request).unwrap();
        adapter
            .capture(
                &authorization.authorization_id,
                25,
                "USD",
                "durable-operation-1",
            )
            .unwrap();
        adapter
            .reconcile_expired_governed_intent(
                "intent-request-1",
                "purchase-expired-capture",
                "buyer-1",
                25,
                "USD",
            )
            .unwrap();
        assert_eq!(adapter.capture_count().unwrap(), 1);
        assert_eq!(adapter.refund_count().unwrap(), 1);
    }

    #[test]
    fn legacy_authorization_replay_backfills_governed_intent_binding() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy-operator.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE chio_finding_operator_payments (
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
        .unwrap();
        let request = governed_request("durable-operation-migrated", "intent-request-migrated");
        let authorization_id = authorization_id(&request);
        conn.execute(
            "INSERT INTO chio_finding_operator_payments (authorization_id, reference, payer, payee, amount_units, currency, state, transaction_id, prior_transaction_id, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'held', NULL, NULL, 1, 1)",
            params![
                authorization_id,
                request.reference,
                request.payer,
                request.payee,
                i64::try_from(request.amount_units).unwrap(),
                request.currency,
            ],
        )
        .unwrap();
        drop(conn);

        let adapter = SqliteFindingOperatorPaymentAdapter::open(&path).unwrap();
        let replay = adapter.authorize(&request).unwrap();
        assert_eq!(replay.authorization_id, authorization_id);
        assert_eq!(replay.metadata["replay"], true);
        let conn = rusqlite::Connection::open(&path).unwrap();
        let governed_binding: (String, String) = conn
            .query_row(
                "SELECT governed_intent_id, governed_intent_hash FROM chio_finding_operator_payments WHERE authorization_id = ?1",
                [&authorization_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            governed_binding,
            ("intent-request-migrated".to_owned(), "a".repeat(64))
        );
    }

    #[test]
    fn expired_legacy_payment_uses_exact_journal_binding() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy-expired-operator.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE chio_finding_operator_payments (
                authorization_id TEXT PRIMARY KEY,
                reference TEXT NOT NULL UNIQUE,
                payer TEXT NOT NULL,
                payee TEXT NOT NULL,
                amount_units INTEGER NOT NULL,
                currency TEXT NOT NULL,
                state TEXT NOT NULL,
                transaction_id TEXT,
                prior_transaction_id TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE payment_journal (
                operation_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                authorization_id TEXT
            );
            "#,
        )
        .unwrap();
        let request = request("legacy-payment-operation");
        let authorization_id = authorization_id(&request);
        conn.execute(
            "INSERT INTO chio_finding_operator_payments (authorization_id, reference, payer, payee, amount_units, currency, state, transaction_id, prior_transaction_id, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'held', NULL, NULL, 1, 1)",
            params![
                authorization_id,
                request.reference,
                request.payer,
                request.payee,
                i64::try_from(request.amount_units).unwrap(),
                request.currency,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO payment_journal (operation_id, request_id, authorization_id) VALUES (?1, ?2, ?3)",
            params![request.reference, "purchase-request-legacy", authorization_id],
        )
        .unwrap();
        drop(conn);

        let adapter = SqliteFindingOperatorPaymentAdapter::open(&path).unwrap();
        assert!(adapter
            .reconcile_expired_governed_intent(
                "expired-intent-legacy",
                "wrong-request",
                "buyer-1",
                25,
                "USD",
            )
            .is_err());
        adapter
            .reconcile_expired_governed_intent(
                "expired-intent-legacy",
                "purchase-request-legacy",
                "buyer-1",
                25,
                "USD",
            )
            .unwrap();
        adapter
            .reconcile_expired_governed_intent(
                "expired-intent-legacy",
                "purchase-request-legacy",
                "buyer-1",
                25,
                "USD",
            )
            .unwrap();

        let conn = rusqlite::Connection::open(&path).unwrap();
        let state: (String, String, Option<String>) = conn
            .query_row(
                "SELECT state, governed_intent_id, governed_intent_hash FROM chio_finding_operator_payments WHERE authorization_id = ?1",
                [&authorization_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            state,
            (
                "released".to_owned(),
                "expired-intent-legacy".to_owned(),
                None,
            )
        );
    }
}
