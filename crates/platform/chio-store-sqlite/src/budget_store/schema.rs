use super::*;

pub(super) fn ensure_budget_seq_column(connection: &Connection) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(capability_grant_budgets)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let has_seq = columns
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|column| column == "seq");
    if !has_seq {
        connection.execute(
            "ALTER TABLE capability_grant_budgets ADD COLUMN seq INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_capability_grant_budgets_seq ON capability_grant_budgets(seq)",
        [],
    )?;
    Ok(())
}

pub(super) fn ensure_split_budget_cost_columns(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(capability_grant_budgets)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|c| c == "total_cost_exposed")
        || !columns.iter().any(|c| c == "total_cost_realized_spend")
    {
        return Err(BudgetStoreError::Invariant(
            "unsupported budget schema: missing split cost columns `total_cost_exposed` and `total_cost_realized_spend`".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn ensure_budget_hold_authority_columns(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(budget_authorization_holds)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|column| column == "authority_id") {
        connection.execute(
            "ALTER TABLE budget_authorization_holds ADD COLUMN authority_id TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "lease_id") {
        connection.execute(
            "ALTER TABLE budget_authorization_holds ADD COLUMN lease_id TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "lease_epoch") {
        connection.execute(
            "ALTER TABLE budget_authorization_holds ADD COLUMN lease_epoch INTEGER",
            [],
        )?;
    }
    Ok(())
}

pub(super) fn ensure_budget_hold_reserved_until_column(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(budget_authorization_holds)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|column| column == "reserved_until") {
        connection.execute(
            "ALTER TABLE budget_authorization_holds ADD COLUMN reserved_until INTEGER",
            [],
        )?;
    }
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_budget_authorization_holds_reserved_until \
         ON budget_authorization_holds(disposition, reserved_until)",
        [],
    )?;
    Ok(())
}

pub(super) fn ensure_budget_hold_reserved_currency_column(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(budget_authorization_holds)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|column| column == "reserved_currency") {
        connection.execute(
            "ALTER TABLE budget_authorization_holds ADD COLUMN reserved_currency TEXT",
            [],
        )?;
    }
    Ok(())
}

pub(super) fn ensure_budget_hold_reserved_payment_reference_column(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(budget_authorization_holds)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;
    if !columns
        .iter()
        .any(|column| column == "reserved_payment_reference")
    {
        connection.execute(
            "ALTER TABLE budget_authorization_holds ADD COLUMN reserved_payment_reference TEXT",
            [],
        )?;
    }
    Ok(())
}

pub(super) fn ensure_budget_hold_reserved_envelope_columns(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(budget_authorization_holds)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;
    if !columns
        .iter()
        .any(|column| column == "reserved_budget_total")
    {
        connection.execute(
            "ALTER TABLE budget_authorization_holds ADD COLUMN reserved_budget_total INTEGER",
            [],
        )?;
    }
    if !columns
        .iter()
        .any(|column| column == "reserved_delegation_depth")
    {
        connection.execute(
            "ALTER TABLE budget_authorization_holds ADD COLUMN reserved_delegation_depth INTEGER",
            [],
        )?;
    }
    if !columns
        .iter()
        .any(|column| column == "reserved_root_budget_holder")
    {
        connection.execute(
            "ALTER TABLE budget_authorization_holds ADD COLUMN reserved_root_budget_holder TEXT",
            [],
        )?;
    }
    Ok(())
}

pub(super) fn ensure_budget_hold_invocation_captured_column(
    connection: &Connection,
) -> Result<bool, BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(budget_authorization_holds)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    if !columns
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|column| column == "invocation_captured")
    {
        connection.execute(
            "ALTER TABLE budget_authorization_holds ADD COLUMN invocation_captured INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
        return Ok(true);
    }
    Ok(false)
}

pub(super) fn ensure_budget_mutation_event_authority_columns(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(budget_mutation_events)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|column| column == "authority_id") {
        connection.execute(
            "ALTER TABLE budget_mutation_events ADD COLUMN authority_id TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "lease_id") {
        connection.execute(
            "ALTER TABLE budget_mutation_events ADD COLUMN lease_id TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "lease_epoch") {
        connection.execute(
            "ALTER TABLE budget_mutation_events ADD COLUMN lease_epoch INTEGER",
            [],
        )?;
    }
    Ok(())
}

pub(super) fn ensure_budget_mutation_event_seq_column(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(budget_mutation_events)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|column| column == "event_seq") {
        connection.execute(
            "ALTER TABLE budget_mutation_events ADD COLUMN event_seq INTEGER",
            [],
        )?;
    }
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_budget_mutation_events_event_seq ON budget_mutation_events(event_seq)",
        [],
    )?;
    Ok(())
}

/// Ensure the AFTER DELETE trigger that resets the ack-head watermark AND clears
/// the per-origin heads exists, so any delete from `budget_mutation_events`
/// forces `budget_ack_heads` to re-verify contiguity from genesis (fail-closed).
///
/// The trigger deliberately does NOT record the deleted seq as abandoned: a delete
/// caused by DATA LOSS (a restored older DB) must CAP the head below the hole so a
/// data-losing node cannot over-count. Only a genuine rollback-retry records the
/// abandoned seq, explicitly at its own call site.
///
/// Idempotent and non-churning: the trigger is (re)created
/// only when it is absent or an OLDER version (one that predates the per-origin
/// `budget_origin_ack_heads` clear). Steady state is a single `sqlite_master`
/// read with NO DDL, so concurrent opens on the hot status path do not take
/// repeated schema locks. In the one-time upgrade window the drop and the create
/// are BOTH idempotent (`DROP TRIGGER IF EXISTS` then `CREATE TRIGGER IF NOT
/// EXISTS`), so two opens racing the upgrade cannot fail with "trigger already
/// exists"; the momentary drop window is covered by the manual
/// `reset_budget_ack_head_watermark` calls at each delete site (belt-and-suspenders).
pub(super) fn ensure_budget_ack_head_reset_trigger(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    const TRIGGER_NAME: &str = "budget_mutation_events_reset_ack_head_watermark";
    let existing_sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
            rusqlite::params![TRIGGER_NAME],
            |row| row.get(0),
        )
        .optional()?;
    // Up to date iff the trigger exists AND already clears the per-origin heads.
    let up_to_date = existing_sql
        .as_deref()
        .is_some_and(|sql| sql.contains("budget_origin_ack_heads"));
    if up_to_date {
        return Ok(());
    }
    connection.execute_batch(
        r#"
        DROP TRIGGER IF EXISTS budget_mutation_events_reset_ack_head_watermark;
        CREATE TRIGGER IF NOT EXISTS budget_mutation_events_reset_ack_head_watermark
        AFTER DELETE ON budget_mutation_events
        BEGIN
            UPDATE budget_ack_head_watermark SET head_seq = 0 WHERE singleton = 1;
            DELETE FROM budget_origin_ack_heads;
        END;
        "#,
    )?;
    Ok(())
}
