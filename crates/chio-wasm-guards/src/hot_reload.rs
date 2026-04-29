//! Hot-reload engine for WASM guards.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::runtime::Handle;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::warn;

use crate::blocklist::{GuardDigestBlocklist, E_GUARD_DIGEST_BLOCKLISTED};
use crate::incident::{EvalTrace, IncidentWriter, ReloadIncident};
use crate::observability::{
    guard_reload_span, RELOAD_APPLIED, RELOAD_CANARY_FAILED, RELOAD_ROLLED_BACK,
};
use crate::runtime::LoadedModule;
use crate::{EpochId, WasmGuard, WasmGuardAbi, WasmGuardError};
use crate::{GuardRequest, GuardVerdict};

/// Required number of frozen fixtures in a canary corpus.
pub const CANARY_FIXTURE_COUNT: usize = 32;

const MANIFEST_FILE_NAME: &str = "MANIFEST.sha256";

/// Frozen canary corpus for one guard.
#[derive(Debug, Clone)]
pub struct CanaryCorpus {
    guard_id: String,
    fixtures: Vec<CanaryFixture>,
}

impl CanaryCorpus {
    /// Load and verify a guard canary corpus from
    /// `tests/corpora/<guard_id>/canary`.
    pub fn from_dir(
        guard_id: impl Into<String>,
        canary_dir: impl AsRef<Path>,
    ) -> Result<Self, HotReloadError> {
        let guard_id = guard_id.into();
        let canary_dir = canary_dir.as_ref();
        let manifest_path = canary_dir.join(MANIFEST_FILE_NAME);
        let manifest = read_to_string(&manifest_path)?;
        let manifest_entries = parse_manifest(&manifest_path, &manifest)?;
        let fixture_names = json_fixture_names(canary_dir)?;
        let manifest_names = manifest_entries
            .iter()
            .map(|entry| entry.file_name.clone())
            .collect::<BTreeSet<_>>();

        if fixture_names != manifest_names {
            return Err(HotReloadError::CanaryManifest {
                path: manifest_path,
                reason: format!(
                    "manifest fixture set does not match directory fixtures: manifest={manifest_names:?} directory={fixture_names:?}"
                ),
            });
        }

        let mut fixtures = Vec::with_capacity(manifest_entries.len());
        for entry in manifest_entries {
            let fixture_path = canary_dir.join(&entry.file_name);
            let bytes = read_bytes(&fixture_path)?;
            let actual_sha256 = hex::encode(Sha256::digest(&bytes));
            if actual_sha256 != entry.sha256 {
                return Err(HotReloadError::CanaryManifest {
                    path: manifest_path.clone(),
                    reason: format!(
                        "fixture {} digest mismatch: expected {} got {}",
                        entry.file_name, entry.sha256, actual_sha256
                    ),
                });
            }

            let fixture_file: CanaryFixtureFile =
                serde_json::from_slice(&bytes).map_err(|source| {
                    HotReloadError::CanaryFixtureJson {
                        path: fixture_path.clone(),
                        source,
                    }
                })?;
            serde_json::from_slice::<CanaryExpectedVerdict>(
                fixture_file.expected_verdict_bytes.as_bytes(),
            )
            .map_err(|source| HotReloadError::CanaryFixtureJson {
                path: fixture_path.clone(),
                source,
            })?;

            fixtures.push(CanaryFixture {
                file_name: entry.file_name,
                request: fixture_file.request,
                expected_verdict_bytes: fixture_file.expected_verdict_bytes.into_bytes(),
            });
        }

        if fixtures.len() != CANARY_FIXTURE_COUNT {
            return Err(HotReloadError::CanaryFixtureCount {
                guard_id,
                expected: CANARY_FIXTURE_COUNT,
                actual: fixtures.len(),
            });
        }

        Ok(Self { guard_id, fixtures })
    }

    /// Guard identifier this corpus belongs to.
    #[must_use]
    pub fn guard_id(&self) -> &str {
        &self.guard_id
    }

    /// Frozen canary fixtures in manifest order.
    #[must_use]
    pub fn fixtures(&self) -> &[CanaryFixture] {
        &self.fixtures
    }
}

/// One frozen canary fixture.
#[derive(Debug, Clone)]
pub struct CanaryFixture {
    file_name: String,
    request: GuardRequest,
    expected_verdict_bytes: Vec<u8>,
}

impl CanaryFixture {
    /// Fixture file name relative to its canary directory.
    #[must_use]
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// Request evaluated during canary verification.
    #[must_use]
    pub fn request(&self) -> &GuardRequest {
        &self.request
    }

    /// Frozen expected verdict bytes.
    #[must_use]
    pub fn expected_verdict_bytes(&self) -> &[u8] {
        &self.expected_verdict_bytes
    }
}

#[derive(Debug, Clone, Deserialize)]
struct CanaryFixtureFile {
    request: GuardRequest,
    expected_verdict_bytes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
enum CanaryExpectedVerdict {
    Allow,
    Deny {
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

impl From<&GuardVerdict> for CanaryExpectedVerdict {
    fn from(verdict: &GuardVerdict) -> Self {
        match verdict {
            GuardVerdict::Allow => Self::Allow,
            GuardVerdict::Deny { reason } => Self::Deny {
                reason: reason.clone(),
            },
        }
    }
}

#[derive(Debug)]
struct ManifestEntry {
    sha256: String,
    file_name: String,
}

/// Factory used by [`Engine`] to compile replacement module bytes.
pub trait ReloadBackendFactory: Send + Sync + 'static {
    /// Build a loaded WASM backend from replacement module bytes.
    fn build_backend(
        &self,
        new_module_bytes: &[u8],
    ) -> Result<Box<dyn WasmGuardAbi>, WasmGuardError>;

    /// Build a backend for a specific guard ID.
    fn build_backend_for_guard(
        &self,
        guard_id: &str,
        new_module_bytes: &[u8],
    ) -> Result<Box<dyn WasmGuardAbi>, WasmGuardError> {
        let _ = guard_id;
        self.build_backend(new_module_bytes)
    }
}

impl<F> ReloadBackendFactory for F
where
    F: Fn(&[u8]) -> Result<Box<dyn WasmGuardAbi>, WasmGuardError> + Send + Sync + 'static,
{
    fn build_backend(
        &self,
        new_module_bytes: &[u8],
    ) -> Result<Box<dyn WasmGuardAbi>, WasmGuardError> {
        self(new_module_bytes)
    }
}

/// Poller used by [`Engine`] to fetch the current registry digest for a guard.
pub trait RegistryDigestPoller: Send + 'static {
    /// Return the current digest for a guard, if the registry has one.
    fn current_digest(&mut self, guard_id: &str) -> Result<Option<String>, HotReloadError>;
}

impl<F> RegistryDigestPoller for F
where
    F: for<'a> FnMut(&'a str) -> Result<Option<String>, HotReloadError> + Send + 'static,
{
    fn current_digest(&mut self, guard_id: &str) -> Result<Option<String>, HotReloadError> {
        self(guard_id)
    }
}

/// Source-specific reload trigger details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadTriggerSource {
    /// A watched file or directory changed.
    FileChanged {
        /// Path reported by the file watcher.
        path: PathBuf,
    },
    /// A registry poll observed a new digest for the guard artifact.
    RegistryDigestChanged {
        /// New digest returned by the registry poller.
        digest: String,
    },
    /// The file watcher reported an error.
    WatcherError {
        /// Human-readable watcher error.
        message: String,
    },
}

/// Reload trigger emitted by file watchers and registry poll tasks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadTrigger {
    /// Guard identifier associated with the trigger.
    pub guard_id: String,
    /// Trigger source.
    pub source: ReloadTriggerSource,
}

/// Result from an accepted debounced reload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebouncedReload {
    /// Monotonic per-guard reload sequence number.
    pub reload_seq: u64,
    /// Published module epoch.
    pub epoch_id: EpochId,
}

/// Watchdog settings for a post-swap guard epoch.
#[derive(Debug, Clone)]
pub struct WatchdogConfig {
    /// Consecutive error-class verdicts required before rollback.
    pub max_errors: usize,
    /// Sliding window for consecutive error-class verdicts.
    pub window: Duration,
    /// Incident directory writer.
    pub incident_writer: IncidentWriter,
}

impl WatchdogConfig {
    /// Create a watchdog config. M06 defaults use 5 errors in 60 seconds.
    #[must_use]
    pub fn new(incident_writer: IncidentWriter) -> Self {
        Self {
            max_errors: 5,
            window: Duration::from_secs(60),
            incident_writer,
        }
    }
}

/// Post-swap watchdog for one published reload.
#[derive(Debug)]
pub struct ReloadWatchdog {
    guard_id: String,
    guard: Arc<WasmGuard>,
    previous_module: Arc<LoadedModule>,
    reload_seq: u64,
    epoch_id: EpochId,
    config: WatchdogConfig,
    errors: Vec<Instant>,
    traces: Vec<EvalTrace>,
    rolled_back: bool,
}

impl ReloadWatchdog {
    /// Create a watchdog over an already-published reload.
    #[must_use]
    pub fn new(
        guard_id: impl Into<String>,
        guard: Arc<WasmGuard>,
        previous_module: Arc<LoadedModule>,
        reload_seq: u64,
        epoch_id: EpochId,
        config: WatchdogConfig,
    ) -> Self {
        Self {
            guard_id: guard_id.into(),
            guard,
            previous_module,
            reload_seq,
            epoch_id,
            config,
            errors: Vec::new(),
            traces: Vec::new(),
            rolled_back: false,
        }
    }

    /// Record one error-class verdict and roll back when the threshold trips.
    pub fn record_error(&mut self, trace: EvalTrace) -> Result<Option<PathBuf>, HotReloadError> {
        if self.rolled_back {
            return Ok(None);
        }

        let now = Instant::now();
        self.errors.push(now);
        self.errors
            .retain(|seen| now.duration_since(*seen) <= self.config.window);
        self.traces.push(trace);
        if self.traces.len() > 5 {
            self.traces.remove(0);
        }

        if self.errors.len() < self.config.max_errors {
            return Ok(None);
        }

        self.guard
            .restore_loaded_module(Arc::clone(&self.previous_module));
        self.rolled_back = true;
        let incident = ReloadIncident {
            guard_id: self.guard_id.clone(),
            reload_seq: self.reload_seq,
            epoch_id: self.epoch_id.get(),
            reason: format!(
                "{} error-class verdicts within {:?}",
                self.errors.len(),
                self.config.window
            ),
            last_5_eval_traces: self.traces.clone(),
        };
        let incident_dir = self
            .config
            .incident_writer
            .write_reload_incident(&incident)
            .map_err(|source| HotReloadError::IncidentWrite { source })?;
        let span = guard_reload_span(RELOAD_ROLLED_BACK, self.reload_seq);
        let _span_guard = span.enter();
        warn!(
            event = "chio.guard.reload.rolled_back",
            guard_id = %self.guard_id,
            reload_seq = self.reload_seq,
            epoch_id = self.epoch_id.get(),
            incident_dir = %incident_dir.display(),
            "WASM guard reload rolled back"
        );

        Ok(Some(incident_dir))
    }

    /// Record a successful evaluation and reset the consecutive error streak.
    pub fn record_success(&mut self) {
        self.errors.clear();
        self.traces.clear();
    }

    /// Return true after this watchdog has already rolled back.
    #[must_use]
    pub fn rolled_back(&self) -> bool {
        self.rolled_back
    }
}

#[derive(Debug, Default)]
struct ReloadSlot {
    seq: u64,
    in_flight: bool,
    pending_module_bytes: Option<Vec<u8>>,
}

struct ReloadInFlightReset {
    slot: Arc<Mutex<ReloadSlot>>,
    armed: bool,
}

impl ReloadInFlightReset {
    fn new(slot: Arc<Mutex<ReloadSlot>>) -> Self {
        Self { slot, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ReloadInFlightReset {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(mut slot) = self.slot.try_lock() {
            slot.in_flight = false;
        }
    }
}

/// Errors returned by the hot-reload engine.
#[derive(Debug, thiserror::Error)]
pub enum HotReloadError {
    /// The requested guard is not registered in this engine.
    #[error("guard {guard_id:?} is not registered")]
    GuardNotFound {
        /// Guard identifier passed to reload.
        guard_id: String,
    },

    /// Replacement module compilation or validation failed.
    #[error("failed to load replacement module for guard {guard_id:?}: {source}")]
    ReplacementLoad {
        /// Guard identifier passed to reload.
        guard_id: String,
        /// Backend load error.
        #[source]
        source: WasmGuardError,
    },

    /// The target guard's epoch counter is exhausted.
    #[error("epoch counter exhausted for guard {guard_id:?}")]
    EpochCounterExhausted {
        /// Guard identifier passed to reload.
        guard_id: String,
    },

    /// The internal guard registry lock was poisoned.
    #[error("hot-reload guard registry lock poisoned")]
    RegistryLockPoisoned,

    /// File watcher setup failed.
    #[error("hot-reload file watcher failed: {0}")]
    FileWatcher(#[from] notify::Error),

    /// Reload trigger receiver was closed before the trigger could be sent.
    #[error("reload trigger receiver closed")]
    TriggerReceiverClosed,

    /// Registry polling was requested without an active Tokio runtime.
    #[error("registry reload poll task requires an active tokio runtime")]
    NoTokioRuntime,

    /// The per-guard reload sequence counter is exhausted.
    #[error("reload sequence counter exhausted for guard {guard_id:?}")]
    ReloadSequenceExhausted {
        /// Guard identifier passed to reload.
        guard_id: String,
    },

    /// Debounced reload executor lost its pending module bytes.
    #[error("pending reload module bytes missing for guard {guard_id:?}")]
    PendingReloadMissing {
        /// Guard identifier passed to reload.
        guard_id: String,
    },

    /// Canary corpus file IO failed.
    #[error("canary corpus IO failed at {}: {source}", path.display())]
    CanaryIo {
        /// Corpus path.
        path: PathBuf,
        /// IO error.
        #[source]
        source: io::Error,
    },

    /// Canary fixture JSON failed to parse or validate.
    #[error("canary fixture JSON invalid at {}: {source}", path.display())]
    CanaryFixtureJson {
        /// Fixture path.
        path: PathBuf,
        /// JSON error.
        #[source]
        source: serde_json::Error,
    },

    /// Canary manifest failed validation.
    #[error("canary manifest invalid at {}: {reason}", path.display())]
    CanaryManifest {
        /// Manifest path.
        path: PathBuf,
        /// Validation failure.
        reason: String,
    },

    /// Canary corpus fixture count is not the required value.
    #[error("guard {guard_id:?} canary fixture count mismatch: expected {expected}, got {actual}")]
    CanaryFixtureCount {
        /// Guard identifier.
        guard_id: String,
        /// Expected fixture count.
        expected: usize,
        /// Actual fixture count.
        actual: usize,
    },

    /// Canary corpus was supplied for a different guard.
    #[error(
        "canary corpus guard mismatch: reload guard {guard_id:?}, corpus guard {corpus_guard_id:?}"
    )]
    CanaryGuardMismatch {
        /// Guard requested for reload.
        guard_id: String,
        /// Guard recorded on the corpus.
        corpus_guard_id: String,
    },

    /// Canary verdict serialization failed.
    #[error("canary verdict serialization failed: {source}")]
    CanaryVerdictSerialize {
        /// JSON serialization error.
        #[source]
        source: serde_json::Error,
    },

    /// Canary verification failed before the replacement module was published.
    #[error(
        "guard {guard_id:?} canary fixture {fixture:?} failed: expected {expected}, got {actual}"
    )]
    CanaryFailed {
        /// Guard requested for reload.
        guard_id: String,
        /// Fixture file name.
        fixture: String,
        /// Expected verdict bytes as UTF-8 lossless text.
        expected: String,
        /// Actual verdict bytes or error text.
        actual: String,
    },

    /// Replacement digest appears in the persistent blocklist.
    #[error("{code}: guard digest {digest} is blocklisted")]
    DigestBlocklisted {
        /// Structured machine-readable error code.
        code: &'static str,
        /// Normalized blocked digest.
        digest: String,
    },

    /// Blocklist access failed.
    #[error("guard digest blocklist failed: {source}")]
    Blocklist {
        /// Blocklist error.
        #[source]
        source: crate::blocklist::BlocklistError,
    },

    /// A guard ID was registered more than once.
    #[error("guard {guard_id:?} is already registered")]
    DuplicateGuard {
        /// Duplicate guard identifier.
        guard_id: String,
    },

    /// Incident directory write failed.
    #[error("guard reload incident write failed: {source}")]
    IncidentWrite {
        /// Incident writer error.
        #[source]
        source: crate::incident::IncidentError,
    },
}

/// Runtime hot-reload engine.
///
/// Guards are registered by stable guard ID. A reload builds the replacement
/// backend first, then atomically publishes it through the guard's ArcSwap
/// pointer. Existing evaluations that already loaded an older module snapshot
/// keep using that old epoch.
pub struct Engine<F>
where
    F: ReloadBackendFactory,
{
    guards: RwLock<HashMap<String, Arc<WasmGuard>>>,
    reload_slots: RwLock<HashMap<String, Arc<Mutex<ReloadSlot>>>>,
    blocklist: Option<GuardDigestBlocklist>,
    backend_factory: F,
}

impl<F> Engine<F>
where
    F: ReloadBackendFactory,
{
    /// Create a hot-reload engine with the supplied backend factory.
    #[must_use]
    pub fn new(backend_factory: F) -> Self {
        Self {
            guards: RwLock::new(HashMap::new()),
            reload_slots: RwLock::new(HashMap::new()),
            blocklist: Some(default_blocklist()),
            backend_factory,
        }
    }

    /// Override the digest blocklist consulted by reload paths.
    #[must_use]
    pub fn with_blocklist(mut self, blocklist: GuardDigestBlocklist) -> Self {
        self.blocklist = Some(blocklist);
        self
    }

    /// Disable digest blocklist checks for tests or offline harnesses.
    #[must_use]
    pub fn without_blocklist(mut self) -> Self {
        self.blocklist = None;
        self
    }

    /// Register a guard by stable guard ID.
    pub fn register_guard(
        &self,
        guard_id: impl Into<String>,
        guard: WasmGuard,
    ) -> Result<Arc<WasmGuard>, HotReloadError> {
        let guard = Arc::new(guard);
        let guard_id = guard_id.into();
        let mut guards = self
            .guards
            .write()
            .map_err(|_| HotReloadError::RegistryLockPoisoned)?;
        if guards.contains_key(&guard_id) {
            return Err(HotReloadError::DuplicateGuard { guard_id });
        }
        guards.insert(guard_id, Arc::clone(&guard));
        Ok(guard)
    }

    /// Return the guard registered for `guard_id`, if present.
    pub fn guard(&self, guard_id: &str) -> Result<Option<Arc<WasmGuard>>, HotReloadError> {
        Ok(self
            .guards
            .read()
            .map_err(|_| HotReloadError::RegistryLockPoisoned)?
            .get(guard_id)
            .cloned())
    }

    /// Replace a guard's loaded module and return the published epoch ID.
    pub fn reload(
        &self,
        guard_id: &str,
        new_module_bytes: &[u8],
    ) -> Result<EpochId, HotReloadError> {
        self.reload_with_observability(guard_id, new_module_bytes, None)
    }

    fn reload_with_observability(
        &self,
        guard_id: &str,
        new_module_bytes: &[u8],
        reload_seq: Option<u64>,
    ) -> Result<EpochId, HotReloadError> {
        let guard = self
            .guard(guard_id)?
            .ok_or_else(|| HotReloadError::GuardNotFound {
                guard_id: guard_id.to_string(),
            })?;

        let module_sha256 = hex::encode(Sha256::digest(new_module_bytes));
        self.ensure_digest_not_blocklisted(&module_sha256)?;

        let backend = self
            .backend_factory
            .build_backend_for_guard(guard_id, new_module_bytes)
            .map_err(|source| HotReloadError::ReplacementLoad {
                guard_id: guard_id.to_string(),
                source,
            })?;

        let epoch_id = guard
            .replace_loaded_module(backend, Some(module_sha256))
            .ok_or_else(|| HotReloadError::EpochCounterExhausted {
                guard_id: guard_id.to_string(),
            })?;
        guard.record_reload_seq(reload_seq.unwrap_or(0));
        let span = guard_reload_span(RELOAD_APPLIED, guard.current_reload_seq());
        let _span_guard = span.enter();
        Ok(epoch_id)
    }

    /// Verify the replacement module against a frozen canary corpus, then
    /// publish it atomically if all expected verdict bytes match.
    pub fn reload_with_canary(
        &self,
        guard_id: &str,
        new_module_bytes: &[u8],
        corpus: &CanaryCorpus,
    ) -> Result<EpochId, HotReloadError> {
        if corpus.guard_id() != guard_id {
            return Err(HotReloadError::CanaryGuardMismatch {
                guard_id: guard_id.to_string(),
                corpus_guard_id: corpus.guard_id().to_string(),
            });
        }

        let guard = self
            .guard(guard_id)?
            .ok_or_else(|| HotReloadError::GuardNotFound {
                guard_id: guard_id.to_string(),
            })?;

        let module_sha256 = hex::encode(Sha256::digest(new_module_bytes));
        self.ensure_digest_not_blocklisted(&module_sha256)?;

        let mut canary_backend = self
            .backend_factory
            .build_backend_for_guard(guard_id, new_module_bytes)
            .map_err(|source| HotReloadError::ReplacementLoad {
                guard_id: guard_id.to_string(),
                source,
            })?;

        for fixture in corpus.fixtures() {
            let actual = match canary_backend.evaluate(fixture.request()) {
                Ok(verdict) => serialize_canary_verdict(&verdict)?,
                Err(source) => {
                    let actual = format!("error:{source}");
                    let span = guard_reload_span(RELOAD_CANARY_FAILED, guard.current_reload_seq());
                    let _span_guard = span.enter();
                    warn!(
                        event = "chio.guard.reload.canary_failed",
                        guard_id,
                        fixture = fixture.file_name(),
                        expected = %String::from_utf8_lossy(fixture.expected_verdict_bytes()),
                        actual = %actual,
                        "WASM guard reload canary failed"
                    );
                    return Err(HotReloadError::CanaryFailed {
                        guard_id: guard_id.to_string(),
                        fixture: fixture.file_name().to_string(),
                        expected: String::from_utf8_lossy(fixture.expected_verdict_bytes())
                            .into_owned(),
                        actual,
                    });
                }
            };
            if actual != fixture.expected_verdict_bytes() {
                let actual = String::from_utf8_lossy(&actual).into_owned();
                let span = guard_reload_span(RELOAD_CANARY_FAILED, guard.current_reload_seq());
                let _span_guard = span.enter();
                warn!(
                    event = "chio.guard.reload.canary_failed",
                    guard_id,
                    fixture = fixture.file_name(),
                    expected = %String::from_utf8_lossy(fixture.expected_verdict_bytes()),
                    actual = %actual,
                    "WASM guard reload canary failed"
                );
                return Err(HotReloadError::CanaryFailed {
                    guard_id: guard_id.to_string(),
                    fixture: fixture.file_name().to_string(),
                    expected: String::from_utf8_lossy(fixture.expected_verdict_bytes())
                        .into_owned(),
                    actual,
                });
            }
        }

        let backend = self
            .backend_factory
            .build_backend_for_guard(guard_id, new_module_bytes)
            .map_err(|source| HotReloadError::ReplacementLoad {
                guard_id: guard_id.to_string(),
                source,
            })?;

        let epoch_id = guard
            .replace_loaded_module(backend, Some(module_sha256))
            .ok_or_else(|| HotReloadError::EpochCounterExhausted {
                guard_id: guard_id.to_string(),
            })?;
        let span = guard_reload_span(RELOAD_APPLIED, guard.current_reload_seq());
        let _span_guard = span.enter();
        Ok(epoch_id)
    }

    /// Reload a guard and return a watchdog that can roll back the new epoch.
    pub fn reload_with_watchdog(
        &self,
        guard_id: &str,
        new_module_bytes: &[u8],
        reload_seq: u64,
        config: WatchdogConfig,
    ) -> Result<ReloadWatchdog, HotReloadError> {
        let guard = self
            .guard(guard_id)?
            .ok_or_else(|| HotReloadError::GuardNotFound {
                guard_id: guard_id.to_string(),
            })?;
        let module_sha256 = hex::encode(Sha256::digest(new_module_bytes));
        self.ensure_digest_not_blocklisted(&module_sha256)?;
        let backend = self
            .backend_factory
            .build_backend_for_guard(guard_id, new_module_bytes)
            .map_err(|source| HotReloadError::ReplacementLoad {
                guard_id: guard_id.to_string(),
                source,
            })?;
        let (previous_module, epoch_id) = guard
            .replace_loaded_module_with_previous(backend, Some(module_sha256))
            .ok_or_else(|| HotReloadError::EpochCounterExhausted {
                guard_id: guard_id.to_string(),
            })?;
        guard.record_reload_seq(reload_seq);
        let span = guard_reload_span(RELOAD_APPLIED, guard.current_reload_seq());
        let _span_guard = span.enter();
        Ok(ReloadWatchdog::new(
            guard_id,
            guard,
            previous_module,
            reload_seq,
            epoch_id,
            config,
        ))
    }

    fn reload_slot(&self, guard_id: &str) -> Result<Arc<Mutex<ReloadSlot>>, HotReloadError> {
        if let Some(slot) = self
            .reload_slots
            .read()
            .map_err(|_| HotReloadError::RegistryLockPoisoned)?
            .get(guard_id)
            .cloned()
        {
            return Ok(slot);
        }

        let mut slots = self
            .reload_slots
            .write()
            .map_err(|_| HotReloadError::RegistryLockPoisoned)?;
        Ok(Arc::clone(
            slots
                .entry(guard_id.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(ReloadSlot::default()))),
        ))
    }

    fn ensure_digest_not_blocklisted(&self, digest: &str) -> Result<(), HotReloadError> {
        let Some(blocklist) = &self.blocklist else {
            return Ok(());
        };
        if blocklist
            .is_blocklisted(digest)
            .map_err(|source| HotReloadError::Blocklist { source })?
        {
            return Err(HotReloadError::DigestBlocklisted {
                code: E_GUARD_DIGEST_BLOCKLISTED,
                digest: crate::blocklist::normalize_digest(digest)
                    .map_err(|source| HotReloadError::Blocklist { source })?,
            });
        }
        Ok(())
    }

    /// Return the latest accepted reload sequence for a guard.
    pub async fn reload_seq(&self, guard_id: &str) -> Result<Option<u64>, HotReloadError> {
        let Some(slot) = self
            .reload_slots
            .read()
            .map_err(|_| HotReloadError::RegistryLockPoisoned)?
            .get(guard_id)
            .cloned()
        else {
            return Ok(None);
        };
        let seq = slot.lock().await.seq;
        Ok(Some(seq))
    }

    /// Submit a per-guard debounced reload request.
    ///
    /// Requests that arrive while another request for the same guard is inside
    /// the debounce window replace the pending module bytes and return `None`.
    /// The in-flight executor publishes the latest pending bytes once the
    /// window closes.
    pub async fn reload_debounced(
        &self,
        guard_id: &str,
        new_module_bytes: Vec<u8>,
        debounce: Duration,
    ) -> Result<Option<DebouncedReload>, HotReloadError> {
        let _guard = self
            .guard(guard_id)?
            .ok_or_else(|| HotReloadError::GuardNotFound {
                guard_id: guard_id.to_string(),
            })?;
        let slot = self.reload_slot(guard_id)?;
        {
            let mut slot_guard = slot.lock().await;
            slot_guard.pending_module_bytes = Some(new_module_bytes);
            if slot_guard.in_flight {
                return Ok(None);
            }
            slot_guard.in_flight = true;
            slot_guard.seq = slot_guard.seq.checked_add(1).ok_or_else(|| {
                HotReloadError::ReloadSequenceExhausted {
                    guard_id: guard_id.to_string(),
                }
            })?;
        }

        let mut in_flight_reset = ReloadInFlightReset::new(Arc::clone(&slot));
        tokio::time::sleep(debounce).await;

        let mut slot_guard = slot.lock().await;
        let Some(module_bytes) = slot_guard.pending_module_bytes.take() else {
            slot_guard.in_flight = false;
            in_flight_reset.disarm();
            return Err(HotReloadError::PendingReloadMissing {
                guard_id: guard_id.to_string(),
            });
        };
        let reload_seq = slot_guard.seq;
        let reload_result =
            self.reload_with_observability(guard_id, &module_bytes, Some(reload_seq));
        slot_guard.in_flight = false;
        in_flight_reset.disarm();
        let epoch_id = reload_result?;

        Ok(Some(DebouncedReload {
            reload_seq,
            epoch_id,
        }))
    }

    /// Watch a guard path and emit reload triggers when it changes.
    pub fn watch_guard_path(
        &self,
        guard_id: impl Into<String>,
        path: impl AsRef<Path>,
        trigger_tx: mpsc::Sender<ReloadTrigger>,
    ) -> Result<RecommendedWatcher, HotReloadError> {
        let guard_id = guard_id.into();
        let watched_path = path.as_ref().to_path_buf();
        let fallback_path = watched_path.clone();
        let mut watcher =
            notify::recommended_watcher(move |result: notify::Result<notify::Event>| {
                let event = match result {
                    Ok(event) => event,
                    Err(error) => {
                        let _ = trigger_tx.try_send(ReloadTrigger {
                            guard_id: guard_id.clone(),
                            source: ReloadTriggerSource::WatcherError {
                                message: error.to_string(),
                            },
                        });
                        return;
                    }
                };
                if !is_reload_file_event(&event.kind) {
                    return;
                }
                let path = event
                    .paths
                    .first()
                    .cloned()
                    .unwrap_or_else(|| fallback_path.clone());
                let _ = trigger_tx.try_send(ReloadTrigger {
                    guard_id: guard_id.clone(),
                    source: ReloadTriggerSource::FileChanged { path },
                });
            })?;
        watcher.watch(&watched_path, RecursiveMode::NonRecursive)?;
        Ok(watcher)
    }

    /// Spawn a registry digest poll task keyed by guard ID.
    ///
    /// The task emits a reload trigger each time the observed digest changes
    /// from the last seen digest.
    pub fn spawn_registry_poll_task<P>(
        &self,
        guard_id: impl Into<String>,
        initial_digest: Option<String>,
        interval: Duration,
        mut poller: P,
        trigger_tx: mpsc::Sender<ReloadTrigger>,
    ) -> Result<JoinHandle<Result<(), HotReloadError>>, HotReloadError>
    where
        P: RegistryDigestPoller,
    {
        let guard_id = guard_id.into();
        let handle = Handle::try_current().map_err(|_| HotReloadError::NoTokioRuntime)?;
        Ok(handle.spawn(async move {
            let mut last_digest = initial_digest;
            let mut interval = tokio::time::interval(interval);
            loop {
                interval.tick().await;
                let Some(current_digest) = poller.current_digest(&guard_id)? else {
                    continue;
                };
                if last_digest.as_deref() == Some(current_digest.as_str()) {
                    continue;
                }
                last_digest = Some(current_digest.clone());
                trigger_tx
                    .send(ReloadTrigger {
                        guard_id: guard_id.clone(),
                        source: ReloadTriggerSource::RegistryDigestChanged {
                            digest: current_digest,
                        },
                    })
                    .await
                    .map_err(|_| HotReloadError::TriggerReceiverClosed)?;
            }
        }))
    }
}

fn is_reload_file_event(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::Any | EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    )
}

fn default_blocklist() -> GuardDigestBlocklist {
    GuardDigestBlocklist::from_environment().unwrap_or_else(|_| {
        GuardDigestBlocklist::from_state_home(std::env::temp_dir().join("chio-guard-state"))
    })
}

fn read_to_string(path: &Path) -> Result<String, HotReloadError> {
    fs::read_to_string(path).map_err(|source| HotReloadError::CanaryIo {
        path: path.to_path_buf(),
        source,
    })
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, HotReloadError> {
    fs::read(path).map_err(|source| HotReloadError::CanaryIo {
        path: path.to_path_buf(),
        source,
    })
}

fn parse_manifest(
    manifest_path: &Path,
    manifest: &str,
) -> Result<Vec<ManifestEntry>, HotReloadError> {
    let mut entries = Vec::new();
    let mut names = BTreeSet::new();
    for (index, line) in manifest.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((sha256, file_name)) = line.split_once("  ") else {
            return Err(HotReloadError::CanaryManifest {
                path: manifest_path.to_path_buf(),
                reason: format!("line {} must be '<sha256>  <filename>'", index + 1),
            });
        };
        if sha256.len() != 64 || !sha256.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(HotReloadError::CanaryManifest {
                path: manifest_path.to_path_buf(),
                reason: format!("line {} has invalid sha256 digest", index + 1),
            });
        }
        if !is_safe_fixture_name(file_name) {
            return Err(HotReloadError::CanaryManifest {
                path: manifest_path.to_path_buf(),
                reason: format!("line {} has unsafe fixture name {file_name:?}", index + 1),
            });
        }
        if !names.insert(file_name.to_string()) {
            return Err(HotReloadError::CanaryManifest {
                path: manifest_path.to_path_buf(),
                reason: format!("line {} duplicates fixture {file_name:?}", index + 1),
            });
        }
        entries.push(ManifestEntry {
            sha256: sha256.to_ascii_lowercase(),
            file_name: file_name.to_string(),
        });
    }
    Ok(entries)
}

fn json_fixture_names(canary_dir: &Path) -> Result<BTreeSet<String>, HotReloadError> {
    let entries = fs::read_dir(canary_dir).map_err(|source| HotReloadError::CanaryIo {
        path: canary_dir.to_path_buf(),
        source,
    })?;
    let mut names = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|source| HotReloadError::CanaryIo {
            path: canary_dir.to_path_buf(),
            source,
        })?;
        let file_type = entry
            .file_type()
            .map_err(|source| HotReloadError::CanaryIo {
                path: entry.path(),
                source,
            })?;
        if !file_type.is_file() {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if file_name.ends_with(".json") {
            names.insert(file_name);
        }
    }
    Ok(names)
}

fn is_safe_fixture_name(file_name: &str) -> bool {
    let path = Path::new(file_name);
    !file_name.is_empty()
        && file_name.ends_with(".json")
        && path.components().count() == 1
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn serialize_canary_verdict(verdict: &GuardVerdict) -> Result<Vec<u8>, HotReloadError> {
    serde_json::to_vec(&CanaryExpectedVerdict::from(verdict))
        .map_err(|source| HotReloadError::CanaryVerdictSerialize { source })
}
