use super::*;

use chio_kernel::receipt_store::{DispatchIntentRecord, SideEffectClass};

/// Column string for a side-effect class. The inverse mapping in
/// `select_open_dispatch_intents` treats any unknown string as side-effecting
/// (fail-safe: an unrecognized class is never demoted to read-only).
fn side_effect_class_str(class: SideEffectClass) -> &'static str {
    match class {
        SideEffectClass::ReadOnly => "read_only",
        SideEffectClass::SideEffecting => "side_effecting",
        SideEffectClass::Monetary => "monetary",
    }
}

/// Insert a dispatch intent. A row's identity is (tenant, request id):
/// request ids are caller-supplied and only unique within a tenant, so a
/// second insert reusing the id inside the SAME tenant scope collides and is
/// rejected fail-closed rather than duplicating an effect record, while an
/// unrelated tenant's request with the same id journals independently.
/// `owner_token` names the inserting store instance so reconciliation can
/// tell this instance's live work from another instance's rows.
pub(crate) fn insert_dispatch_intent_tx(
    tx: &rusqlite::Transaction<'_>,
    intent: &DispatchIntentRecord,
    owner_token: &str,
) -> Result<(), ReceiptStoreError> {
    // The unique index folds a NULL tenant to '' (`COALESCE(tenant_id, '')`)
    // so tenantless rows still conflict with each other. An explicit
    // empty-string tenant would fold to that same value and collide with
    // tenantless rows it does not belong to; reject it here so the
    // NULL-means-no-tenant invariant is explicit rather than surfacing as an
    // unexplained unique-constraint conflict.
    if intent.tenant_id.as_deref() == Some("") {
        return Err(ReceiptStoreError::Conflict(
            "dispatch intent tenant_id must not be an empty string; use no tenant (None) \
             instead of \"\""
                .to_string(),
        ));
    }
    let changed = tx.execute(
        "INSERT INTO chio_dispatch_intents (
            request_id, capability_id, tool_server, tool_name, parameter_hash,
            side_effect_class, monetary, rail, rail_authorization_id, tenant_id,
            created_at_unix_ms, state, owner_token
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'open', ?12)
        ON CONFLICT(COALESCE(tenant_id, ''), request_id) DO NOTHING",
        rusqlite::params![
            intent.request_id.as_str(),
            intent.capability_id.as_str(),
            intent.tool_server.as_str(),
            intent.tool_name.as_str(),
            intent.parameter_hash.as_str(),
            side_effect_class_str(intent.side_effect_class),
            i64::from(intent.monetary),
            intent.rail.as_deref(),
            intent.rail_authorization_id.as_deref(),
            intent.tenant_id.as_deref(),
            sqlite_i64(
                intent.created_at_unix_ms,
                "dispatch intent created_at_unix_ms"
            )?,
            owner_token,
        ],
    )?;
    if changed == 0 {
        return Err(ReceiptStoreError::Conflict(format!(
            "dispatch intent for request `{}` already exists in its tenant scope",
            intent.request_id
        )));
    }
    Ok(())
}

/// Writer job that durably inserts one dispatch intent in its own immediate
/// transaction. Used by the unbounded write path.
pub(crate) fn dispatch_intent_insert_job(
    intent: &DispatchIntentRecord,
    owner_token: String,
) -> impl FnOnce(&mut SqliteStoreConnection) -> Result<(), ReceiptStoreError> + Send + 'static {
    let intent = intent.clone();
    move |connection| {
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        insert_dispatch_intent_tx(&tx, &intent, &owner_token)?;
        tx.commit()?;
        Ok(())
    }
}

/// Bounded-path variant of [`dispatch_intent_insert_job`]: the caller marks
/// `abandoned` when its response wait times out, and the job refuses to
/// commit once marked. Without the marker, an insert queued behind a slow
/// (but alive) writer could land AFTER the caller already denied before
/// dispatch, and the stale row would dead-letter at the next boot as a false
/// orphan for a call that never executed. The marker is checked both before
/// the transaction (cheap skip) and again immediately before commit, so the
/// unguarded window is only the commit itself. A write racing that window
/// either answers in the instant between the deadline and the marker (and is
/// honored by the caller instead of reported as a timeout) or lands anyway;
/// a landed commit records itself in the shared `landed` slot, which the
/// sweep enqueued behind this job on the single writer reads before deleting
/// anything (see [`dispatch_intent_sweep_landed_job`]).
pub(crate) fn dispatch_intent_insert_job_unless_abandoned(
    intent: &DispatchIntentRecord,
    owner_token: String,
    abandoned: std::sync::Arc<std::sync::atomic::AtomicBool>,
    landed: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> impl FnOnce(&mut SqliteStoreConnection) -> Result<(), ReceiptStoreError> + Send + 'static {
    let intent = intent.clone();
    move |connection| {
        let abandoned_error = |request_id: &str| {
            ReceiptStoreError::Conflict(format!(
                "dispatch intent write for request `{request_id}` was abandoned by its \
                 timed-out caller; refusing to land a stale intent"
            ))
        };
        if abandoned.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(abandoned_error(&intent.request_id));
        }
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        insert_dispatch_intent_tx(&tx, &intent, &owner_token)?;
        if abandoned.load(std::sync::atomic::Ordering::SeqCst) {
            // Dropping the transaction rolls the insert back.
            return Err(abandoned_error(&intent.request_id));
        }
        tx.commit()?;
        landed.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

/// Timeout-path sweep for [`dispatch_intent_insert_job_unless_abandoned`]:
/// deletes the intent row only when the shared `landed` slot proves THIS
/// attempt's insert committed it. The timed-out attempt may have been a
/// retry or concurrent duplicate of a request whose intent is already open
/// from an earlier invocation; that insert refuses on the tenant-scoped
/// uniqueness of the request id, and
/// an unconditional delete here would erase the earlier invocation's durable
/// crash marker and reject its terminal receipt's consume. FIFO order on the
/// single writer runs this job strictly after the insert, so the slot is
/// always settled by the time it is read; a sweep with nothing of its own to
/// delete reports `NotFound` and leaves the row alone.
pub(crate) fn dispatch_intent_sweep_landed_job(
    key: &chio_kernel::receipt_store::DispatchIntentKey,
    landed: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> impl FnOnce(&mut SqliteStoreConnection) -> Result<(), ReceiptStoreError> + Send + 'static {
    let key = key.clone();
    move |connection| {
        if !landed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ReceiptStoreError::NotFound(format!(
                "timed-out dispatch intent write for request `{}` landed no row to sweep",
                key.request_id
            )));
        }
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        clear_dispatch_intent_tx(&tx, &key)?;
        tx.commit()?;
        Ok(())
    }
}

/// Writer job that binds a rail authorization id to one open intent in its
/// own immediate transaction. Shared by the bounded and unbounded paths.
pub(crate) fn dispatch_intent_rail_ref_job(
    request_id: &str,
    tenant_id: Option<&str>,
    rail_authorization_id: &str,
) -> impl FnOnce(&mut SqliteStoreConnection) -> Result<(), ReceiptStoreError> + Send + 'static {
    let request_id = request_id.to_string();
    let tenant_id = tenant_id.map(str::to_string);
    let rail_authorization_id = rail_authorization_id.to_string();
    move |connection| {
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        attach_dispatch_intent_rail_ref_tx(
            &tx,
            &request_id,
            tenant_id.as_deref(),
            &rail_authorization_id,
        )?;
        tx.commit()?;
        Ok(())
    }
}

/// Attach a rail authorization id to an open monetary intent (best-effort).
/// Keyed on the row's (tenant, request id) identity so a tenant's attach can
/// never annotate another tenant's row sharing the request id. Zero rows
/// changed (already consumed, or never written) is `NotFound`.
pub(crate) fn attach_dispatch_intent_rail_ref_tx(
    tx: &rusqlite::Transaction<'_>,
    request_id: &str,
    tenant_id: Option<&str>,
    rail_authorization_id: &str,
) -> Result<(), ReceiptStoreError> {
    let changed = tx.execute(
        "UPDATE chio_dispatch_intents SET rail_authorization_id = ?3 \
         WHERE request_id = ?1 \
           AND ((tenant_id IS NULL AND ?2 IS NULL) OR tenant_id = ?2) \
           AND state = 'open'",
        rusqlite::params![request_id, tenant_id, rail_authorization_id],
    )?;
    if changed == 0 {
        return Err(ReceiptStoreError::NotFound(format!(
            "open dispatch intent for request `{request_id}` not found for rail-ref attach"
        )));
    }
    Ok(())
}

/// Delete the intent matching `key` inside the receipt-append transaction.
/// Guarded on `request_id` + `parameter_hash` (+ `tenant_id`): a mismatch or
/// missing row returns `Conflict` from inside the transaction, aborting the
/// whole commit (no partial state). The `parameter_hash` guard proves the
/// consumed intent matches the exact call the receipt attests.
pub(crate) fn finalize_dispatch_intent_tx(
    tx: &rusqlite::Transaction<'_>,
    key: &chio_kernel::receipt_store::DispatchIntentKey,
) -> Result<(), ReceiptStoreError> {
    let changed = tx.execute(
        "DELETE FROM chio_dispatch_intents \
         WHERE request_id = ?1 AND parameter_hash = ?2 \
           AND ((tenant_id IS NULL AND ?3 IS NULL) OR tenant_id = ?3)",
        rusqlite::params![
            key.request_id.as_str(),
            key.parameter_hash.as_str(),
            key.tenant_id.as_deref(),
        ],
    )?;
    if changed == 0 {
        return Err(ReceiptStoreError::Conflict(format!(
            "dispatch intent for request `{}` not found with matching parameter_hash; \
             refusing to commit the receipt",
            key.request_id
        )));
    }
    Ok(())
}

/// Writer job that deletes one open intent in its own immediate transaction,
/// for an evaluation that exits without dispatching (no effect ran, no
/// terminal receipt will consume the row).
pub(crate) fn dispatch_intent_clear_job(
    key: &chio_kernel::receipt_store::DispatchIntentKey,
) -> impl FnOnce(&mut SqliteStoreConnection) -> Result<(), ReceiptStoreError> + Send + 'static {
    let key = key.clone();
    move |connection| {
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        clear_dispatch_intent_tx(&tx, &key)?;
        tx.commit()?;
        Ok(())
    }
}

/// Delete the open intent matching `key` for a call that provably never
/// dispatched. Guarded exactly like the consuming delete (request id,
/// parameter hash, tenant) plus the open state; zero rows changed is
/// `NotFound` so the caller logs the anomaly instead of assuming the row is
/// gone.
pub(crate) fn clear_dispatch_intent_tx(
    tx: &rusqlite::Transaction<'_>,
    key: &chio_kernel::receipt_store::DispatchIntentKey,
) -> Result<(), ReceiptStoreError> {
    let changed = tx.execute(
        "DELETE FROM chio_dispatch_intents \
         WHERE request_id = ?1 AND parameter_hash = ?2 \
           AND ((tenant_id IS NULL AND ?3 IS NULL) OR tenant_id = ?3) \
           AND state = 'open'",
        rusqlite::params![
            key.request_id.as_str(),
            key.parameter_hash.as_str(),
            key.tenant_id.as_deref(),
        ],
    )?;
    if changed == 0 {
        return Err(ReceiptStoreError::NotFound(format!(
            "open dispatch intent for request `{}` not found with matching parameter_hash",
            key.request_id
        )));
    }
    Ok(())
}

/// Column list shared by the open-intent queries, in the order
/// [`dispatch_intent_from_row`] reads them.
const OPEN_DISPATCH_INTENT_COLUMNS: &str =
    "request_id, capability_id, tool_server, tool_name, parameter_hash, \
     side_effect_class, monetary, rail, rail_authorization_id, tenant_id, \
     created_at_unix_ms";

fn dispatch_intent_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DispatchIntentRecord> {
    let class_raw: String = row.get(5)?;
    let side_effect_class = match class_raw.as_str() {
        "read_only" => SideEffectClass::ReadOnly,
        "monetary" => SideEffectClass::Monetary,
        // Fail-safe: an unrecognized class string is treated as
        // side-effecting, never demoted to read-only.
        _ => SideEffectClass::SideEffecting,
    };
    Ok(DispatchIntentRecord {
        request_id: row.get(0)?,
        capability_id: row.get(1)?,
        tool_server: row.get(2)?,
        tool_name: row.get(3)?,
        parameter_hash: row.get(4)?,
        side_effect_class,
        monetary: row.get::<_, i64>(6)? != 0,
        rail: row.get(7)?,
        rail_authorization_id: row.get(8)?,
        tenant_id: row.get(9)?,
        created_at_unix_ms: row.get::<_, i64>(10)?.max(0) as u64,
    })
}

/// Load every open intent, oldest first: the operator view of work that is
/// in flight or awaiting reconciliation. A missing table (a pre-journal
/// database sampled over a read-only connection, which runs no migration)
/// reports no open intents.
pub(crate) fn select_open_dispatch_intents(
    connection: &rusqlite::Connection,
) -> Result<Vec<DispatchIntentRecord>, ReceiptStoreError> {
    if !dispatch_intents_table_exists(connection)? {
        return Ok(Vec::new());
    }
    let mut statement = connection.prepare(&format!(
        "SELECT {OPEN_DISPATCH_INTENT_COLUMNS} \
         FROM chio_dispatch_intents WHERE state = 'open' ORDER BY created_at_unix_ms",
    ))?;
    let rows = statement.query_map([], dispatch_intent_from_row)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// One reconciliation candidate: an open intent journaled by some other
/// store instance, paired with the owner token naming that instance (or
/// `None` for a row journaled before owner tokens existed) so the pass can
/// judge the owner's liveness through its per-owner mark.
pub(crate) struct ForeignOpenIntent {
    pub(crate) owner_token: Option<String>,
    pub(crate) record: DispatchIntentRecord,
}

/// Load the open intents that are reconciliation candidates for the
/// instance identified by `owner_token`: every open row journaled by some
/// OTHER instance, oldest first. Rows carrying the caller's own token are
/// its live in-flight work and are never candidates, which is what makes a
/// reconcile pass safe to run while the store is serving. A NULL owner is
/// foreign by definition (no live instance journals without its token).
pub(crate) fn select_open_dispatch_intents_excluding_owner(
    connection: &rusqlite::Connection,
    owner_token: &str,
) -> Result<Vec<ForeignOpenIntent>, ReceiptStoreError> {
    if !dispatch_intents_table_exists(connection)? {
        return Ok(Vec::new());
    }
    let mut statement = connection.prepare(&format!(
        "SELECT {OPEN_DISPATCH_INTENT_COLUMNS}, owner_token \
         FROM chio_dispatch_intents \
         WHERE state = 'open' AND (owner_token IS NULL OR owner_token <> ?1) \
         ORDER BY created_at_unix_ms",
    ))?;
    let rows = statement.query_map(rusqlite::params![owner_token], |row| {
        Ok(ForeignOpenIntent {
            owner_token: row.get(11)?,
            record: dispatch_intent_from_row(row)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Mark an orphaned intent as a durable, operator-visible dead-letter
/// incident, recording the reconciler's outcome annotation. Keyed on the
/// row's (tenant, request id) identity: another tenant's still-live intent
/// sharing the request id must never be swept into the incident.
pub(crate) fn dead_letter_dispatch_intent_tx(
    tx: &rusqlite::Transaction<'_>,
    request_id: &str,
    tenant_id: Option<&str>,
    detail: &str,
) -> Result<(), ReceiptStoreError> {
    tx.execute(
        "UPDATE chio_dispatch_intents SET state = 'dead_letter', resolution_detail = ?3 \
         WHERE request_id = ?1 \
           AND ((tenant_id IS NULL AND ?2 IS NULL) OR tenant_id = ?2) \
           AND state = 'open'",
        rusqlite::params![request_id, tenant_id, detail],
    )?;
    Ok(())
}

/// Resolve a specific dead-letter dispatch intent: the sanctioned operator
/// remediation for the incident a nonzero `dead_letter_dispatch_intents`
/// count flags in health. The row's current state is read first rather than
/// inferred from an update's affected-row count, so a refusal names the
/// actual state: missing entirely, or present but not `dead_letter` (still
/// open, already reconciled, or already resolved). A resolved row is never
/// deleted and never loses its original incident detail: the operator's
/// note is appended to the existing `resolution_detail` rather than
/// overwriting it, so the row reads as a complete history and remains
/// auditable after it stops counting against health.
pub(crate) fn resolve_dead_letter_dispatch_intent_tx(
    tx: &rusqlite::Transaction<'_>,
    request_id: &str,
    tenant_id: Option<&str>,
    note: &str,
) -> Result<(), ReceiptStoreError> {
    let current_state: Option<String> = tx
        .query_row(
            "SELECT state FROM chio_dispatch_intents \
             WHERE request_id = ?1 AND ((tenant_id IS NULL AND ?2 IS NULL) OR tenant_id = ?2)",
            rusqlite::params![request_id, tenant_id],
            |row| row.get(0),
        )
        .optional()?;
    match current_state.as_deref() {
        None => Err(ReceiptStoreError::NotFound(format!(
            "no dispatch intent found for request `{request_id}`"
        ))),
        Some("dead_letter") => {
            tx.execute(
                "UPDATE chio_dispatch_intents SET state = 'resolved', resolution_detail = \
                 COALESCE(resolution_detail || '; ', '') || 'operator resolution: ' || ?3 \
                 WHERE request_id = ?1 \
                   AND ((tenant_id IS NULL AND ?2 IS NULL) OR tenant_id = ?2) \
                   AND state = 'dead_letter'",
                rusqlite::params![request_id, tenant_id, note],
            )?;
            Ok(())
        }
        Some(other) => Err(ReceiptStoreError::Conflict(format!(
            "dispatch intent for request `{request_id}` is in state `{other}`, not \
             `dead_letter`; refusing to resolve"
        ))),
    }
}

/// Mark an orphaned monetary intent whose outcome the reconciler PROVED
/// against the rail as terminally reconciled. Distinct from a dead letter:
/// the outcome is known, so the row must not count as an outcome-unknown
/// incident or flip store health; the annotation preserves the rail
/// reference the proof came from. Keyed on (tenant, request id) like every
/// resolution write.
pub(crate) fn reconcile_dispatch_intent_tx(
    tx: &rusqlite::Transaction<'_>,
    request_id: &str,
    tenant_id: Option<&str>,
    detail: &str,
) -> Result<(), ReceiptStoreError> {
    tx.execute(
        "UPDATE chio_dispatch_intents SET state = 'reconciled', resolution_detail = ?3 \
         WHERE request_id = ?1 \
           AND ((tenant_id IS NULL AND ?2 IS NULL) OR tenant_id = ?2) \
           AND state = 'open'",
        rusqlite::params![request_id, tenant_id, detail],
    )?;
    Ok(())
}

/// Delete an orphaned intent whose effect the reconciler PROVED never ran,
/// so the request is safe to run again. The replay travels the normal
/// pre-dispatch path and journals its own intent under the same (tenant,
/// request id) identity, so no row may survive in any state: a leftover
/// would refuse the replay's insert and fail the request before the tool
/// runs. Zero rows changed is tolerated, matching the other resolution
/// writes (the row was already consumed or cleared).
pub(crate) fn release_dispatch_intent_for_replay_tx(
    tx: &rusqlite::Transaction<'_>,
    request_id: &str,
    tenant_id: Option<&str>,
) -> Result<(), ReceiptStoreError> {
    tx.execute(
        "DELETE FROM chio_dispatch_intents \
         WHERE request_id = ?1 \
           AND ((tenant_id IS NULL AND ?2 IS NULL) OR tenant_id = ?2) \
           AND state = 'open'",
        rusqlite::params![request_id, tenant_id],
    )?;
    Ok(())
}

/// Bounded-path job for a reconciliation pass's resolution batch: applies
/// every claimed row's outcome (dead-letter, monetary-reconciled, or
/// release-for-replay) in one immediate transaction. The caller marks
/// `abandoned` when its response wait times out, and the job refuses to
/// commit once marked, checked both before the transaction (cheap skip) and
/// again immediately before commit, mirroring
/// [`dispatch_intent_insert_job_unless_abandoned`]. The check matters more
/// here than a plain bounded wait would suggest: each resolution write is
/// guarded on `state = 'open'` alone (see [`dead_letter_dispatch_intent_tx`],
/// [`reconcile_dispatch_intent_tx`], [`release_dispatch_intent_for_replay_tx`]),
/// which cannot distinguish the orphan this pass claimed from a fresh intent
/// a replay has since journaled under the same (tenant, request id) identity;
/// a commit that lands after the caller gave up could resolve the wrong row.
/// A row this job leaves untouched stays open for the next recovery pass to
/// re-claim.
pub(crate) fn dispatch_intent_resolution_batch_job(
    dead_letters: Vec<(String, Option<String>, String)>,
    reconciled: Vec<(String, Option<String>, String)>,
    replayable: Vec<(String, Option<String>)>,
    abandoned: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> impl FnOnce(&mut SqliteStoreConnection) -> Result<(), ReceiptStoreError> + Send + 'static {
    move |connection| {
        let abandoned_error = || {
            ReceiptStoreError::Conflict(
                "dispatch intent reconciliation resolution was abandoned by its timed-out \
                 caller; the next recovery pass will re-claim any row still open"
                    .to_string(),
            )
        };
        if abandoned.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(abandoned_error());
        }
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        for (request_id, tenant_id, detail) in &dead_letters {
            dead_letter_dispatch_intent_tx(&tx, request_id, tenant_id.as_deref(), detail)?;
        }
        for (request_id, tenant_id, detail) in &reconciled {
            reconcile_dispatch_intent_tx(&tx, request_id, tenant_id.as_deref(), detail)?;
        }
        for (request_id, tenant_id) in &replayable {
            release_dispatch_intent_for_replay_tx(&tx, request_id, tenant_id.as_deref())?;
        }
        if abandoned.load(std::sync::atomic::Ordering::SeqCst) {
            // Dropping the transaction rolls every resolution in this batch
            // back; none of the claimed rows change state.
            return Err(abandoned_error());
        }
        tx.commit()?;
        Ok(())
    }
}

/// Count of open (in-flight or unreconciled) dispatch intents, tolerant of a
/// missing table on a pre-journal database.
pub(crate) fn open_dispatch_intent_count_query(
    connection: &rusqlite::Connection,
) -> Result<u64, ReceiptStoreError> {
    dispatch_intent_count_by_state(connection, "open")
}

/// Count of dead-letter (orphaned, outcome-unknown) dispatch intents,
/// tolerant of a missing table on a pre-journal database.
pub(crate) fn dead_letter_dispatch_intent_count_query(
    connection: &rusqlite::Connection,
) -> Result<u64, ReceiptStoreError> {
    dispatch_intent_count_by_state(connection, "dead_letter")
}

fn dispatch_intent_count_by_state(
    connection: &rusqlite::Connection,
    state: &str,
) -> Result<u64, ReceiptStoreError> {
    if !dispatch_intents_table_exists(connection)? {
        return Ok(0);
    }
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_dispatch_intents WHERE state = ?1",
        rusqlite::params![state],
        |row| row.get(0),
    )?;
    Ok(count.max(0) as u64)
}

/// True if the non-audit `chio_dispatch_intents` journal table exists. Every
/// read-write open migrates the table into place and stamps the journal
/// schema revision, but the read-only health sampler may still observe a
/// pre-journal database; it reports a missing table as `false` and callers
/// treat that as zero open/dead-letter intents (an accurate report: a
/// database that never journaled has no orphans).
pub(crate) fn dispatch_intents_table_exists(
    connection: &rusqlite::Connection,
) -> Result<bool, ReceiptStoreError> {
    let name: Option<String> = connection
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'chio_dispatch_intents'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(name.is_some())
}
