use std::collections::{HashMap, HashSet};
use std::path::Path as FsPath;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::CapabilityToken;
use rusqlite::{params, Connection};
use tracing::warn;

use super::{
    session_now_millis, CliError, RemoteSessionDiagnosticRecord, RemoteSessionResumeRecord,
};

pub(super) const SESSION_ACTIVE_TABLE: &str = "remote_active_sessions";
pub(super) const SESSION_TOMBSTONE_TABLE: &str = "remote_session_tombstones";

pub(super) struct LoadedActiveSessionRecords {
    pub(super) records: Vec<RemoteSessionResumeRecord>,
    pub(super) invalid_session_ids: Vec<String>,
}

pub(super) fn open_session_state_db(path: &FsPath) -> Result<Connection, CliError> {
    let conn = Connection::open(path)?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {active_table} (
            session_id TEXT PRIMARY KEY NOT NULL,
            updated_at INTEGER NOT NULL,
            record_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS {table} (
            session_id TEXT PRIMARY KEY NOT NULL,
            terminal_at INTEGER NOT NULL,
            record_json TEXT NOT NULL
        );",
        active_table = SESSION_ACTIVE_TABLE,
        table = SESSION_TOMBSTONE_TABLE,
    ))?;
    Ok(conn)
}

pub(super) fn load_active_session_records(
    path: &FsPath,
) -> Result<LoadedActiveSessionRecords, CliError> {
    let conn = open_session_state_db(path)?;
    let terminal_session_ids = load_terminal_session_ids(&conn)?;

    let mut stmt = conn.prepare(&format!(
        "SELECT session_id, record_json FROM {table}",
        table = SESSION_ACTIVE_TABLE,
    ))?;
    let mut rows = stmt.query([])?;
    let mut records = Vec::new();
    let mut invalid_session_ids = Vec::new();

    while let Some(row) = rows.next()? {
        let session_id: String = row.get(0)?;
        let record_json: String = row.get(1)?;
        if terminal_session_ids.contains(&session_id) {
            warn!(
                session_id = %session_id,
                "dropping persisted MCP active session row because a terminal tombstone exists"
            );
            invalid_session_ids.push(session_id);
            continue;
        }
        match serde_json::from_str::<RemoteSessionResumeRecord>(&record_json) {
            Ok(record) if record.session_id == session_id => records.push(record),
            Ok(record) => {
                warn!(
                    session_id = %session_id,
                    record_session_id = %record.session_id,
                    "dropping persisted MCP session row whose primary key does not match the stored session payload"
                );
                invalid_session_ids.push(session_id);
            }
            Err(error) => {
                warn!(
                    session_id = %session_id,
                    error = %error,
                    "dropping malformed persisted MCP session row"
                );
                invalid_session_ids.push(session_id);
            }
        }
    }

    Ok(LoadedActiveSessionRecords {
        records,
        invalid_session_ids,
    })
}

pub(super) fn load_terminal_session_records(
    path: &FsPath,
) -> Result<HashMap<String, Arc<RemoteSessionDiagnosticRecord>>, CliError> {
    let conn = open_session_state_db(path)?;
    let mut stmt = conn.prepare(&format!(
        "SELECT session_id, record_json FROM {table}",
        table = SESSION_TOMBSTONE_TABLE,
    ))?;
    let mut rows = stmt.query([])?;
    let mut records = HashMap::new();

    while let Some(row) = rows.next()? {
        let session_id: String = row.get(0)?;
        let record_json: String = row.get(1)?;
        if let Some(record) = parse_terminal_session_record(&session_id, &record_json) {
            records.insert(session_id, Arc::new(record));
        }
    }

    Ok(records)
}

fn load_terminal_session_ids(conn: &Connection) -> Result<HashSet<String>, CliError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT session_id, record_json FROM {table}",
        table = SESSION_TOMBSTONE_TABLE,
    ))?;
    let mut rows = stmt.query([])?;
    let mut terminal_session_ids = HashSet::new();

    while let Some(row) = rows.next()? {
        let session_id: String = row.get(0)?;
        let record_json: String = row.get(1)?;
        if parse_terminal_session_record(&session_id, &record_json).is_some() {
            terminal_session_ids.insert(session_id);
        }
    }

    Ok(terminal_session_ids)
}

fn parse_terminal_session_record(
    session_id: &str,
    record_json: &str,
) -> Option<RemoteSessionDiagnosticRecord> {
    let record: RemoteSessionDiagnosticRecord = match serde_json::from_str(record_json) {
        Ok(record) => record,
        Err(error) => {
            warn!(
                session_id = %session_id,
                error = %error,
                "dropping malformed terminal MCP session tombstone"
            );
            return None;
        }
    };
    if record.session_id != session_id {
        warn!(
            session_id = %session_id,
            record_session_id = %record.session_id,
            "dropping terminal MCP session tombstone whose primary key does not match the stored session payload"
        );
        return None;
    }
    Some(record)
}

pub(super) fn stored_capabilities_are_current(capabilities: &[CapabilityToken]) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    capabilities
        .iter()
        .all(|capability| capability.expires_at > now)
}

pub(super) fn stored_capability_issuers_are_trusted(
    kernel: &chio_kernel::ChioKernel,
    capabilities: &[CapabilityToken],
) -> bool {
    capabilities
        .iter()
        .all(|capability| kernel.capability_issuer_is_trusted(&capability.issuer))
}

pub(super) fn persist_terminal_session_record(
    path: &FsPath,
    record: &RemoteSessionDiagnosticRecord,
) -> Result<(), CliError> {
    let conn = open_session_state_db(path)?;
    let record_json = serde_json::to_string(record)?;
    conn.execute(
        &format!(
            "INSERT INTO {table} (session_id, terminal_at, record_json)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(session_id) DO UPDATE SET
                 terminal_at = excluded.terminal_at,
                 record_json = excluded.record_json",
            table = SESSION_TOMBSTONE_TABLE,
        ),
        params![
            record.session_id.as_str(),
            record.terminal_at as i64,
            record_json
        ],
    )?;
    Ok(())
}

pub(super) fn persist_active_session_record(
    path: &FsPath,
    record: &RemoteSessionResumeRecord,
) -> Result<(), CliError> {
    let conn = open_session_state_db(path)?;
    let record_json = serde_json::to_string(record)?;
    conn.execute(
        &format!(
            "INSERT INTO {table} (session_id, updated_at, record_json)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(session_id) DO UPDATE SET
                 updated_at = excluded.updated_at,
                 record_json = excluded.record_json",
            table = SESSION_ACTIVE_TABLE,
        ),
        params![
            record.session_id.as_str(),
            session_now_millis() as i64,
            record_json,
        ],
    )?;
    Ok(())
}

pub(super) fn delete_active_session_record(
    path: &FsPath,
    session_id: &str,
) -> Result<(), CliError> {
    let conn = open_session_state_db(path)?;
    conn.execute(
        &format!(
            "DELETE FROM {table} WHERE session_id = ?1",
            table = SESSION_ACTIVE_TABLE,
        ),
        params![session_id],
    )?;
    Ok(())
}

pub(super) fn purge_terminal_session_records_before(
    path: &FsPath,
    cutoff: u64,
) -> Result<(), CliError> {
    let conn = open_session_state_db(path)?;
    conn.execute(
        &format!(
            "DELETE FROM {terminal_table}
             WHERE terminal_at < ?1
               AND NOT EXISTS (
                   SELECT 1 FROM {active_table}
                   WHERE {active_table}.session_id = {terminal_table}.session_id
               )",
            active_table = SESSION_ACTIVE_TABLE,
            terminal_table = SESSION_TOMBSTONE_TABLE,
        ),
        params![cutoff as i64],
    )?;
    Ok(())
}
