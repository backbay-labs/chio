use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError};
use tracing::{debug, warn};

use crate::abi::{GuardRequest, GuardVerdict, WasmGuardAbi};
use crate::epoch::EpochId;
use crate::metrics::{classify_deny_reason_class, REASON_CLASS_MALFORMED};
use crate::observability::{
    guard_digest_or_unknown, guard_evaluate_span, DEFAULT_GUARD_VERSION, RELOAD_APPLIED,
    VERDICT_ALLOW, VERDICT_DENY, VERDICT_ERROR,
};

use super::evidence::LastEvaluationEvidence;
use super::module::LoadedModule;

/// A single WASM guard module loaded into the runtime.
///
/// Wraps a swappable `LoadedModule` and adapts it to the kernel's `Guard`
/// trait. On any error (fuel exhaustion, traps, serialization failures) the
/// guard fails closed and returns `Verdict::Deny`.
///
/// Carries optional receipt metadata: `manifest_sha256` (set at construction
/// from the guard manifest) plus the module epoch used by the most recent
/// `evaluate()` call.
pub struct WasmGuard {
    /// Guard name (from config).
    name: String,
    /// Guard semantic version from policy or manifest metadata.
    version: String,
    /// Current loaded module epoch.
    loaded: ArcSwap<LoadedModule>,
    /// Serializes module swaps with rollback baseline capture.
    reload_lock: Mutex<()>,
    /// Next epoch identifier reserved for future module swaps.
    next_epoch_id: AtomicU64,
    /// Latest reload sequence observed for this guard.
    reload_seq: AtomicU64,
    /// Whether this guard is advisory-only (non-blocking).
    advisory: bool,
    /// Evidence metadata captured from the most recent `evaluate()` call.
    last_evaluation_evidence: Mutex<Option<LastEvaluationEvidence>>,
}

impl WasmGuard {
    /// Create a new WASM guard from a loaded backend.
    ///
    /// `manifest_sha256` is the hex-encoded SHA-256 digest of the guard's
    /// manifest file, used for receipt metadata. Pass `None` when loading
    /// without a manifest (e.g. in tests).
    pub fn new(
        name: String,
        backend: Box<dyn WasmGuardAbi>,
        advisory: bool,
        manifest_sha256: Option<String>,
    ) -> Self {
        Self::new_with_metadata(
            name,
            DEFAULT_GUARD_VERSION.to_string(),
            backend,
            advisory,
            manifest_sha256,
        )
    }

    /// Create a new WASM guard with explicit guard metadata.
    pub fn new_with_metadata(
        name: String,
        version: String,
        backend: Box<dyn WasmGuardAbi>,
        advisory: bool,
        manifest_sha256: Option<String>,
    ) -> Self {
        Self {
            name,
            version,
            loaded: ArcSwap::from_pointee(LoadedModule::new(
                backend,
                EpochId::INITIAL,
                manifest_sha256,
            )),
            reload_lock: Mutex::new(()),
            next_epoch_id: AtomicU64::new(1),
            reload_seq: AtomicU64::new(0),
            advisory,
            last_evaluation_evidence: Mutex::new(None),
        }
    }

    /// Returns `true` if this guard is advisory-only.
    #[must_use]
    pub fn is_advisory(&self) -> bool {
        self.advisory
    }

    /// Returns the guard semantic version attached to tracing metadata.
    #[must_use]
    pub fn guard_version(&self) -> &str {
        &self.version
    }

    /// Returns the SHA-256 hex digest of the guard manifest, if set.
    #[must_use]
    pub fn manifest_sha256(&self) -> Option<String> {
        self.loaded
            .load()
            .manifest_sha256()
            .map(ToString::to_string)
    }

    /// Return a snapshot of the currently loaded module.
    #[must_use]
    pub fn loaded_module(&self) -> Arc<LoadedModule> {
        self.loaded.load_full()
    }

    /// Return the epoch identifier of the currently loaded module.
    #[must_use]
    pub fn current_epoch_id(&self) -> EpochId {
        self.loaded.load().epoch_id()
    }

    /// Return the latest observed reload sequence for this guard.
    #[must_use]
    pub fn current_reload_seq(&self) -> u64 {
        self.reload_seq.load(Ordering::SeqCst)
    }

    /// Record the latest reload sequence for evaluation spans.
    ///
    /// Only the successful hot-reload apply path calls this, so the reload
    /// counter uses the documented `applied` outcome (matching the
    /// `RELOAD_APPLIED` span and the descriptor's declared outcome values) rather
    /// than an undeclared `ok` series.
    pub fn record_reload_seq(&self, reload_seq: u64) {
        self.reload_seq.store(reload_seq, Ordering::SeqCst);
        chio_metrics_spec::runtime::families::GUARD_RELOAD.incr(&[&self.name, RELOAD_APPLIED]);
    }

    /// Reserve and return the next monotonic epoch identifier.
    ///
    /// Returns `None` if the counter is already exhausted.
    pub fn reserve_next_epoch_id(&self) -> Option<EpochId> {
        let next = self
            .next_epoch_id
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(1)
            })
            .ok()?;
        Some(EpochId::new(next))
    }

    /// Replace the current loaded module with a new backend and return its
    /// assigned epoch identifier.
    pub fn replace_loaded_module(
        &self,
        backend: Box<dyn WasmGuardAbi>,
        manifest_sha256: Option<String>,
    ) -> Option<EpochId> {
        self.replace_loaded_module_with_previous(backend, manifest_sha256)
            .map(|(_, epoch_id)| epoch_id)
    }

    /// Replace the loaded module and return the previous module snapshot.
    pub fn replace_loaded_module_with_previous(
        &self,
        backend: Box<dyn WasmGuardAbi>,
        manifest_sha256: Option<String>,
    ) -> Option<(Arc<LoadedModule>, EpochId)> {
        let _reload_guard = match self.reload_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let previous = self.loaded.load_full();
        let epoch_id = self.reserve_next_epoch_id()?;
        self.loaded.store(Arc::new(LoadedModule::new(
            backend,
            epoch_id,
            manifest_sha256,
        )));
        previous.clear_instance_pre_cache();
        if let Ok(mut evidence_lock) = self.last_evaluation_evidence.lock() {
            *evidence_lock = None;
        }
        Some((previous, epoch_id))
    }

    /// Restore a previously loaded module snapshot.
    ///
    /// Used by the hot-reload watchdog to roll back a published epoch without
    /// recompiling the prior module.
    pub fn restore_loaded_module(&self, module: Arc<LoadedModule>) {
        let _reload_guard = match self.reload_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let previous = self.loaded.load_full();
        self.loaded.store(module);
        previous.clear_instance_pre_cache();
        if let Ok(mut evidence_lock) = self.last_evaluation_evidence.lock() {
            *evidence_lock = None;
        }
    }

    /// Returns the fuel consumed during the most recent `evaluate()` call,
    /// or `None` if no evaluation has occurred or the backend does not track
    /// fuel.
    #[must_use]
    pub fn last_fuel_consumed(&self) -> Option<u64> {
        self.last_evaluation_evidence
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().and_then(|evidence| evidence.fuel_consumed))
    }

    /// Returns a JSON object containing receipt metadata from the most
    /// recent evaluation: `fuel_consumed` and `manifest_sha256`.
    #[must_use]
    pub fn guard_evidence_metadata(&self) -> serde_json::Value {
        if let Ok(evidence) = self.last_evaluation_evidence.lock() {
            if let Some(evidence) = evidence.as_ref() {
                return serde_json::json!({
                    "epoch_id": evidence.epoch_id.get(),
                    "fuel_consumed": evidence.fuel_consumed,
                    "manifest_sha256": evidence.manifest_sha256,
                });
            }
        }
        let loaded = self.loaded.load();
        serde_json::json!({
            "epoch_id": loaded.epoch_id().get(),
            "fuel_consumed": null,
            "manifest_sha256": loaded.manifest_sha256(),
        })
    }

    pub(crate) fn build_request(ctx: &GuardContext<'_>) -> GuardRequest {
        use chio_guards::ToolAction;

        let scopes = ctx
            .scope
            .grants
            .iter()
            .map(|g| format!("{}:{}", g.server_id, g.tool_name))
            .collect();

        let (action_type, extracted_path, extracted_target) =
            match chio_guards::extract_action_checked(
                &ctx.request.tool_name,
                &ctx.request.arguments,
            ) {
                Ok(action) => match &action {
                    ToolAction::FileAccess(path) => {
                        (Some("file_access".into()), Some(path.clone()), None)
                    }
                    ToolAction::FileWrite(path, _) => {
                        (Some("file_write".into()), Some(path.clone()), None)
                    }
                    ToolAction::NetworkEgress(host, _) => {
                        (Some("network_egress".into()), None, Some(host.clone()))
                    }
                    ToolAction::ShellCommand(_) => (Some("shell_command".into()), None, None),
                    ToolAction::McpTool(_, _) => (Some("mcp_tool".into()), None, None),
                    ToolAction::Patch(path, _) => (Some("patch".into()), Some(path.clone()), None),
                    ToolAction::CodeExecution { language, .. } => {
                        (Some("code_execution".into()), None, Some(language.clone()))
                    }
                    ToolAction::BrowserAction { verb, target } => (
                        Some("browser_action".into()),
                        None,
                        target.clone().or_else(|| Some(verb.clone())),
                    ),
                    ToolAction::DatabaseQuery { database, .. } => {
                        (Some("database_query".into()), None, Some(database.clone()))
                    }
                    ToolAction::ExternalApiCall { service, endpoint } => (
                        Some("external_api_call".into()),
                        None,
                        Some(format!("{service}:{endpoint}")),
                    ),
                    ToolAction::MemoryWrite { store, key } => (
                        Some("memory_write".into()),
                        None,
                        Some(format!("{store}/{key}")),
                    ),
                    ToolAction::MemoryRead { store, key } => (
                        Some("memory_read".into()),
                        None,
                        Some(match key {
                            Some(k) => format!("{store}/{k}"),
                            None => store.clone(),
                        }),
                    ),
                    ToolAction::Unknown => (Some("unknown".into()), None, None),
                },
                Err(err) => (Some("malformed_arguments".into()), None, Some(err.field)),
            };

        let filesystem_roots = ctx
            .session_filesystem_roots
            .map(|roots| roots.to_vec())
            .unwrap_or_default();

        GuardRequest {
            tool_name: ctx.request.tool_name.clone(),
            server_id: ctx.server_id.clone(),
            agent_id: ctx.agent_id.clone(),
            arguments: ctx.request.arguments.clone(),
            scopes,
            action_type,
            extracted_path,
            extracted_target,
            filesystem_roots,
            matched_grant_index: ctx.matched_grant_index,
        }
    }
}

impl std::fmt::Debug for WasmGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmGuard")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("advisory", &self.advisory)
            .finish()
    }
}

/// Emit the per-evaluation guard families: verdict count, evaluation duration,
/// and fuel consumed. Called from every verdict arm so allow, deny, and error
/// all record.
fn emit_guard_eval_metrics(guard_id: &str, verdict: &str, elapsed: std::time::Duration, fuel: u64) {
    use chio_metrics_spec::runtime::families;
    families::GUARD_VERDICT.incr(&[guard_id, verdict]);
    families::GUARD_EVAL_DURATION.observe(&[guard_id, verdict], elapsed.as_secs_f64());
    families::GUARD_FUEL_CONSUMED.incr_by(&[guard_id], fuel);
}

impl Guard for WasmGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        let eval_started = std::time::Instant::now();
        let request = Self::build_request(ctx);
        if request.action_type.as_deref() == Some("malformed_arguments") {
            warn!(
                guard = %self.name,
                tool_name = %request.tool_name,
                field = %request.extracted_target.as_deref().unwrap_or("unknown"),
                "WASM guard host action extraction failed, failing closed"
            );
            // Record the fail-closed deny so malformed-argument denials are
            // observable in the verdict/deny/duration families instead of
            // silently returning before the metrics path. The bounded `malformed`
            // reason class keeps cardinality finite.
            emit_guard_eval_metrics(&self.name, VERDICT_DENY, eval_started.elapsed(), 0);
            chio_metrics_spec::runtime::families::GUARD_DENY
                .incr(&[&self.name, REASON_CLASS_MALFORMED]);
            return Ok(GuardDecision::deny(Vec::new()));
        }

        let loaded = self.loaded.load_full();
        let span = guard_evaluate_span(
            &self.name,
            &self.version,
            guard_digest_or_unknown(loaded.manifest_sha256()),
            loaded.epoch_id().get(),
            self.current_reload_seq(),
            None,
        );
        let _span_guard = span.enter();

        let (result, fuel) = match loaded.evaluate(&request) {
            Ok(value) => value,
            Err(err) => {
                span.record("verdict", VERDICT_ERROR);
                emit_guard_eval_metrics(&self.name, VERDICT_ERROR, eval_started.elapsed(), 0);
                return Err(err);
            }
        };

        if let Ok(mut evidence_lock) = self.last_evaluation_evidence.lock() {
            *evidence_lock = Some(LastEvaluationEvidence {
                epoch_id: loaded.epoch_id(),
                manifest_sha256: loaded.manifest_sha256().map(ToString::to_string),
                fuel_consumed: fuel,
            });
        }

        match result {
            Ok(GuardVerdict::Allow) => {
                span.record("verdict", VERDICT_ALLOW);
                emit_guard_eval_metrics(
                    &self.name,
                    VERDICT_ALLOW,
                    eval_started.elapsed(),
                    fuel.unwrap_or(0),
                );
                debug!(
                    guard = %self.name,
                    epoch_id = loaded.epoch_id().get(),
                    "WASM guard allowed request"
                );
                Ok(GuardDecision::allow())
            }
            Ok(GuardVerdict::Deny { reason }) => {
                let reason_str = reason.as_deref().unwrap_or("denied by WASM guard");
                span.record("verdict", VERDICT_DENY);
                emit_guard_eval_metrics(
                    &self.name,
                    VERDICT_DENY,
                    eval_started.elapsed(),
                    fuel.unwrap_or(0),
                );
                // Classify the guard-provided reason into a bounded reason class
                // so `chio_guard_deny_total{reason_class}` cannot explode series
                // cardinality on free-form strings, and so the breakdown reflects
                // WHY the guard denied rather than the enforcement mode.
                let reason_class = classify_deny_reason_class(reason.as_deref());
                chio_metrics_spec::runtime::families::GUARD_DENY.incr(&[&self.name, reason_class]);
                if self.advisory {
                    debug!(
                        guard = %self.name,
                        epoch_id = loaded.epoch_id().get(),
                        reason = %reason_str,
                        "WASM advisory guard denied (non-blocking)"
                    );
                    Ok(GuardDecision::allow())
                } else {
                    warn!(
                        guard = %self.name,
                        epoch_id = loaded.epoch_id().get(),
                        reason = %reason_str,
                        "WASM guard denied request"
                    );
                    Ok(GuardDecision::deny(Vec::new()))
                }
            }
            Err(e) => {
                // Fail closed: any error during WASM execution denies.
                span.record("verdict", VERDICT_ERROR);
                emit_guard_eval_metrics(
                    &self.name,
                    VERDICT_ERROR,
                    eval_started.elapsed(),
                    fuel.unwrap_or(0),
                );
                warn!(
                    guard = %self.name,
                    epoch_id = loaded.epoch_id().get(),
                    error = %e,
                    "WASM guard error, failing closed"
                );
                if self.advisory {
                    Ok(GuardDecision::allow())
                } else {
                    Ok(GuardDecision::deny(Vec::new()))
                }
            }
        }
    }
}
