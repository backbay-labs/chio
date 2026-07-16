// Dispatch handlers for the `chio budget` command group.

use super::*;

use chio_kernel::budget_store::{BudgetStore, OpenHoldSummary};

pub(crate) fn dispatch_budget(
    command: BudgetCommands,
    json_output: bool,
    budget_db: Option<PathBuf>,
) -> Result<(), CliError> {
    match command {
        BudgetCommands::Holds { command } => match command {
            BudgetHoldsCommands::List {
                store,
                older_than_secs,
                json,
            } => {
                let path = resolve_store(store, budget_db)?;
                let cutoff_unix_ms = older_than_secs
                    .map(|secs| now_unix_ms().saturating_sub(secs.saturating_mul(1_000)))
                    .unwrap_or(u64::MAX);
                let holds = list_open_holds(&path, cutoff_unix_ms)?;
                if json || json_output {
                    let value = serde_json::json!({
                        "schema": "chio.cli.budget.holds.list.v1",
                        "openHolds": holds.iter().map(|hold| serde_json::json!({
                            "holdId": hold.hold_id,
                            "capabilityId": hold.capability_id,
                            "grantIndex": hold.grant_index,
                            "remainingExposureUnits": hold.remaining_exposure_units,
                            "createdAtUnixMs": hold.created_at_unix_ms,
                        })).collect::<Vec<_>>(),
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&value)
                            .map_err(|error| CliError::Other(format!("budget holds: {error}")))?
                    );
                } else {
                    for hold in &holds {
                        println!(
                            "{}  capability={} grant={} remaining={} created_ms={}",
                            hold.hold_id,
                            hold.capability_id,
                            hold.grant_index,
                            hold.remaining_exposure_units,
                            hold.created_at_unix_ms
                        );
                    }
                    println!("{} open hold(s)", holds.len());
                }
                Ok(())
            }
            BudgetHoldsCommands::Release {
                store,
                hold_id,
                json,
            } => {
                let path = resolve_store(store, budget_db)?;
                let released = release_open_hold(&path, &hold_id)?;
                if json || json_output {
                    println!(
                        "{}",
                        serde_json::json!({
                            "schema": "chio.cli.budget.holds.release.v1",
                            "holdId": hold_id,
                            "released": released,
                        })
                    );
                } else if released {
                    println!("released hold {hold_id}");
                } else {
                    println!("hold {hold_id} was not open (no change)");
                }
                Ok(())
            }
        },
    }
}

fn resolve_store(
    explicit: Option<PathBuf>,
    budget_db: Option<PathBuf>,
) -> Result<PathBuf, CliError> {
    explicit.or(budget_db).ok_or_else(|| {
        CliError::Other(
            "no budget store path (pass --store or the global --budget-db)".to_string(),
        )
    })
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn list_open_holds(
    path: &std::path::Path,
    cutoff_unix_ms: u64,
) -> Result<Vec<OpenHoldSummary>, CliError> {
    let store = chio_store_sqlite::SqliteBudgetStore::open(path)
        .map_err(|error| CliError::Other(format!("open budget store: {error}")))?;
    store
        .list_open_holds_older_than(cutoff_unix_ms, 10_000)
        .map_err(|error| CliError::Other(format!("list open holds: {error}")))
}

fn release_open_hold(path: &std::path::Path, hold_id: &str) -> Result<bool, CliError> {
    let store = chio_store_sqlite::SqliteBudgetStore::open(path)
        .map_err(|error| CliError::Other(format!("open budget store: {error}")))?;
    store
        .expire_open_hold(hold_id)
        .map_err(|error| CliError::Other(format!("release hold: {error}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "chio-{prefix}-{}-{nonce}.sqlite3",
            std::process::id()
        ))
    }

    #[test]
    fn holds_list_then_release_removes_the_open_hold() {
        use chio_kernel::budget_store::BudgetAuthorizeHoldRequest;

        let path = unique_db_path("cli-holds");
        {
            let store = chio_store_sqlite::SqliteBudgetStore::open(&path).unwrap();
            store
                .authorize_budget_hold(BudgetAuthorizeHoldRequest {
                    capability_id: "cap".to_string(),
                    grant_index: 0,
                    max_invocations: Some(5),
                    requested_exposure_units: 30,
                    max_cost_per_invocation: Some(30),
                    max_total_cost_units: Some(300),
                    hold_id: Some("cli-hold-1".to_string()),
                    event_id: Some("cli-hold-1:authorize".to_string()),
                    authority: None,
                    payment_journal: None,
                })
                .unwrap();
        }
        // List returns the open hold.
        let listed = list_open_holds(&path, u64::MAX).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].hold_id, "cli-hold-1");
        // Release expires it; a second release is an idempotent no-op.
        assert!(release_open_hold(&path, "cli-hold-1").unwrap());
        assert!(!release_open_hold(&path, "cli-hold-1").unwrap());
        assert!(list_open_holds(&path, u64::MAX).unwrap().is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
