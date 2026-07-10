//! Persisted per-exporter high-water mark. A SIEM-owned RW SQLite file, distinct
//! from the read-only receipt DB (the receipt DB stays read-only). Fail-closed: a
//! write failure denies advancing the mark.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use crate::manager::SiemError;

pub struct SiemCursorStore {
    conn: Mutex<rusqlite::Connection>,
}

impl SiemCursorStore {
    pub fn open(path: &Path) -> Result<Self, SiemError> {
        let conn =
            rusqlite::Connection::open(path).map_err(|e| SiemError::DbError(e.to_string()))?;
        // The cursor table tracks the per-exporter high-water mark. The
        // dead_letters table durably captures malformed rows (keyed by their
        // raw receipt seq) BEFORE the read cursor is allowed to advance past
        // them, so at-least-once holds across restart/overflow: the in-memory
        // drop-oldest DLQ loses the raw_seq marker on restart while acked_seq
        // would skip the receipt permanently.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS siem_export_cursor (
                 exporter_name TEXT PRIMARY KEY,
                 acked_seq     INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS siem_dead_letters (
                 raw_seq       INTEGER PRIMARY KEY,
                 exporter_name TEXT NOT NULL,
                 raw_json      TEXT NOT NULL,
                 error         TEXT NOT NULL,
                 failed_at     INTEGER NOT NULL
             );",
        )
        .map_err(|e| SiemError::DbError(e.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn acked_seqs(&self) -> Result<BTreeMap<String, u64>, SiemError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| SiemError::DbError("cursor store lock poisoned".to_string()))?;
        let mut stmt = conn
            .prepare("SELECT exporter_name, acked_seq FROM siem_export_cursor")
            .map_err(|e| SiemError::DbError(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|e| SiemError::DbError(e.to_string()))?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (name, seq) = row.map_err(|e| SiemError::DbError(e.to_string()))?;
            out.insert(name, seq.max(0) as u64);
        }
        Ok(out)
    }

    /// Advance the mark for `exporter`. Monotonic: never regresses below the
    /// current value.
    pub fn set_acked(&self, exporter: &str, acked_seq: u64) -> Result<(), SiemError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| SiemError::DbError("cursor store lock poisoned".to_string()))?;
        conn.execute(
            "INSERT INTO siem_export_cursor (exporter_name, acked_seq) VALUES (?1, ?2) \
             ON CONFLICT(exporter_name) DO UPDATE SET acked_seq = MAX(acked_seq, excluded.acked_seq)",
            rusqlite::params![exporter, acked_seq as i64],
        )
        .map_err(|e| SiemError::DbError(e.to_string()))?;
        Ok(())
    }

    pub fn min_acked(&self) -> Result<Option<u64>, SiemError> {
        Ok(self.acked_seqs()?.values().copied().min())
    }

    /// Durably capture a malformed row (keyed by its raw receipt `seq`) so the
    /// read cursor may safely advance past it. Idempotent: re-persisting the
    /// same `raw_seq` (a redelivery after the cursor was held) is a no-op.
    /// Fail-closed: on a write failure the caller must leave the cursor behind
    /// the row rather than advance.
    ///
    /// Returns `true` when the row was newly inserted and `false` when it already
    /// existed (a redelivery). Callers use this to report the malformed row (DLQ
    /// push, `_deserialize` counters) only on first capture, so a stuck exporter
    /// holding the read cursor behind the batch cannot re-inflate the in-memory
    /// DLQ on every poll.
    pub fn persist_dead_letter(
        &self,
        raw_seq: u64,
        exporter: &str,
        raw_json: &str,
        error: &str,
        failed_at: u64,
    ) -> Result<bool, SiemError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| SiemError::DbError("cursor store lock poisoned".to_string()))?;
        // ON CONFLICT DO NOTHING reports 0 rows affected on a duplicate raw_seq
        // and 1 on a fresh insert, so the row count distinguishes first capture
        // from redelivery.
        let inserted = conn
            .execute(
                "INSERT INTO siem_dead_letters (raw_seq, exporter_name, raw_json, error, failed_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(raw_seq) DO NOTHING",
                rusqlite::params![raw_seq as i64, exporter, raw_json, error, failed_at as i64],
            )
            .map_err(|e| SiemError::DbError(e.to_string()))?;
        Ok(inserted == 1)
    }

    /// Raw receipt seqs durably captured in the dead-letter table, ascending.
    /// Used by operators (and tests) to confirm no malformed row was skipped.
    pub fn dead_letter_seqs(&self) -> Result<Vec<u64>, SiemError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| SiemError::DbError("cursor store lock poisoned".to_string()))?;
        let mut stmt = conn
            .prepare("SELECT raw_seq FROM siem_dead_letters ORDER BY raw_seq ASC")
            .map_err(|e| SiemError::DbError(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, i64>(0))
            .map_err(|e| SiemError::DbError(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| SiemError::DbError(e.to_string()))?.max(0) as u64);
        }
        Ok(out)
    }
}
