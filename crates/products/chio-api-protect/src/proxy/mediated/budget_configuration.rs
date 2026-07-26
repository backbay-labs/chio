use super::*;

/// A configured budget store together with whether it supports the pre-execution
/// hold APIs the mediated reservation path depends on.
///
/// The local SQLite store implements `get_budget_hold`, `mark_hold_reserved`, and
/// `reap_expired_reserved_holds`, so a reserved hold can be resolved by nonce on
/// `/v1/reconcile` and reclaimed by the TTL reaper. The remote control-plane
/// store forwards only charge/reverse/reconcile and rejects the unsupported hold
/// APIs, so a reservation minted against it could never be reconciled by nonce
/// or reaped. Tracking hold capability at construction lets the mediated routes
/// fail closed rather than mint an unreconcilable reserved nonce.
pub(crate) struct ConfiguredBudgetStore {
    pub(crate) store: Arc<dyn BudgetStore>,
    pub(crate) hold_capable: bool,
}

/// Build the sidecar's budget store, preferring the hold-capable local SQLite
/// store (`--budget-db`) over the remote control-plane store (`--control-url`)
/// when both are configured; falling back to the remote store; else `None` (the
/// mediated route then denies fail-closed).
///
/// Only the local SQLite store is hold-capable. The mediated authorization and
/// reconcile routes need a hold-capable store to persist and resolve a durable
/// reserved hold, so when both are configured the local store is chosen and
/// mediation keeps working; a remote-only deployment stays not hold-capable and
/// those routes reject fail-closed rather than mint an unreconcilable reserved
/// nonce.
pub(crate) fn build_budget_store(
    config: &ProtectConfig,
) -> Result<Option<ConfiguredBudgetStore>, ProtectError> {
    if let Some(path) = config.budget_db.as_deref() {
        let store = chio_store_sqlite::budget_store::SqliteBudgetStore::open(path)
            .map_err(|error| ProtectError::Config(error.to_string()))?;
        return Ok(Some(ConfiguredBudgetStore {
            store: Arc::new(store),
            hold_capable: true,
        }));
    }
    if let Some(control_url) = config.control_url.as_deref() {
        let token = config.control_token.as_deref().unwrap_or("");
        let store =
            chio_control_plane::trust_control::service_runtime::budget::build_remote_budget_store(
                control_url,
                token,
            )
            .map_err(|error| ProtectError::Config(error.to_string()))?;
        return Ok(Some(ConfiguredBudgetStore {
            store: Arc::from(store),
            hold_capable: false,
        }));
    }
    Ok(None)
}
