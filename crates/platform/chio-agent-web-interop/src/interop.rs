use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};

use chio_commerce_order::CommerceOrderContext;
use chio_core_types::{
    canonical_json_bytes,
    receipt::{
        body::ChioReceipt,
        decision::Decision,
        kinds::{ReceiptKind, TrustLevel},
    },
    sha256_hex, PublicKey, CHIO_AGENT_WEB_PROOF_ENVELOPE_V1_SCHEMA,
    CHIO_AGENT_WEB_PROOF_ENVELOPE_V2_SCHEMA,
};
use chio_transaction_passport::{
    verify_minimal_passport_artifacts, verify_transaction_passport_signature_with_evidence_graph,
    TransactionPassport, TransactionPassportError,
};

mod artifacts;
mod claims;
mod evidence;
mod policy;
mod protocols;

use artifacts::{
    validate_envelope, validate_external_subject, validate_projection_manifest,
    AgentWebProofEnvelope, ProjectionManifest,
};
use claims::{
    push_claim_once, CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND, CLAIM_PROJECTION_MANIFEST_BOUND,
    CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY, CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
};
use evidence::{
    find_legacy_receipt_node, find_node_by_path, find_receipt_node, graph_has_edge, parse_artifact,
    parse_graph, raw_artifact_bytes, receipt_node_ref_matches, AgentWebEvidenceRole,
    AgentWebReceiptRef,
};
use policy::parse_policy;

#[derive(Debug, Clone)]
pub struct AgentWebInteropBundle {
    pub passport: TransactionPassport,
    pub evidence_graph_bytes: Vec<u8>,
    pub root_evidence_graph_bytes: Option<Vec<u8>>,
    pub verifier_policy_bytes: Vec<u8>,
    pub artifacts: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Default)]
pub struct AgentWebVerifierTrust {
    trusted_passport_signer_keys: Vec<PublicKey>,
    default_standard_webhooks_secret: Option<Vec<u8>>,
    standard_webhooks_secrets: BTreeMap<String, Vec<u8>>,
    standard_webhooks_replay_window: Option<StandardWebhooksReplayWindow>,
    seen_standard_webhooks_ids: BTreeSet<String>,
    standard_webhooks_replay_store: Option<Arc<dyn AgentWebReplayStore>>,
    standard_webhooks_replay_reservation_id: Option<String>,
    trusted_receipt_kernel_keys: Vec<PublicKey>,
    trusted_envelope_sidecar_keys: Vec<PublicKey>,
}

pub const DEFAULT_AGENT_WEB_REPLAY_GLOBAL_CAPACITY: usize = 16_384;
pub const DEFAULT_AGENT_WEB_REPLAY_PER_SCOPE_CAPACITY: usize = 4_096;
pub const AGENT_WEB_REPLAY_SCOPE_HEX_LENGTH: usize = 64;
pub const MAX_STANDARD_WEBHOOK_ID_BYTES: usize = 512;

/// Opaque identity for one authenticated Standard Webhooks endpoint.
///
/// Values are domain-separated hashes of the signed endpoint digest. They stay
/// stable across verifier-secret rotation, and the raw endpoint URL is never
/// exposed to replay-store implementations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentWebReplayScope(String);

impl AgentWebReplayScope {
    pub fn parse(value: impl Into<String>) -> Result<Self, AgentWebReplayStoreError> {
        let value = value.into();
        if value.len() != AGENT_WEB_REPLAY_SCOPE_HEX_LENGTH
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AgentWebReplayStoreError::Unavailable(
                "replay scope must be exactly 64 lowercase hexadecimal characters".to_string(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn from_digest(digest: [u8; 32]) -> Self {
        Self(hex::encode(digest))
    }
}

impl fmt::Display for AgentWebReplayScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentWebReplayEntry {
    replay_scope: AgentWebReplayScope,
    webhook_id: String,
    expires_at_unix_seconds: u64,
}

impl AgentWebReplayEntry {
    pub fn new(
        replay_scope: AgentWebReplayScope,
        webhook_id: impl Into<String>,
        expires_at_unix_seconds: u64,
    ) -> Result<Self, AgentWebReplayStoreError> {
        let webhook_id = webhook_id.into();
        validate_standard_webhook_id(&webhook_id).map_err(AgentWebReplayStoreError::Unavailable)?;
        Ok(Self {
            replay_scope,
            webhook_id,
            expires_at_unix_seconds,
        })
    }

    #[must_use]
    pub fn replay_scope(&self) -> &AgentWebReplayScope {
        &self.replay_scope
    }

    #[must_use]
    pub fn webhook_id(&self) -> &str {
        &self.webhook_id
    }

    #[must_use]
    pub fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentWebReplayStoreError {
    Replayed(String),
    Unavailable(String),
}

impl fmt::Display for AgentWebReplayStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Replayed(webhook_id) => {
                write!(formatter, "replayed Standard Webhooks id: {webhook_id}")
            }
            Self::Unavailable(message) => {
                write!(
                    formatter,
                    "Standard Webhooks replay store unavailable: {message}"
                )
            }
        }
    }
}

impl std::error::Error for AgentWebReplayStoreError {}

/// Durable replay stores must reserve the entire batch atomically.
///
/// The consuming verifier calls this only after every signature, graph edge,
/// receipt, and claim has passed. Returning an error must leave replay entries
/// unmodified, although implementations may advance anti-rollback clock state.
pub trait AgentWebReplayStore: fmt::Debug + Send + Sync {
    fn check_and_insert(
        &self,
        now_unix_seconds: u64,
        entries: &[AgentWebReplayEntry],
    ) -> Result<(), AgentWebReplayStoreError>;

    /// Atomically reserves a replay batch for an idempotent external commit.
    ///
    /// The default remains strict for stores that do not implement durable
    /// reservation recovery. Such stores never turn a replay into a success.
    fn check_and_insert_for_reservation(
        &self,
        now_unix_seconds: u64,
        entries: &[AgentWebReplayEntry],
        _reservation_id: &str,
    ) -> Result<(), AgentWebReplayStoreError> {
        self.check_and_insert(now_unix_seconds, entries)
    }
}

#[derive(Debug, Default)]
struct InMemoryAgentWebReplayState {
    entries: BTreeMap<(AgentWebReplayScope, String), u64>,
    legacy_unscoped_entries: BTreeMap<String, u64>,
    wall_clock_high_water: u64,
}

#[derive(Debug)]
pub struct InMemoryAgentWebReplayStore {
    state: Mutex<InMemoryAgentWebReplayState>,
    global_capacity: usize,
    per_scope_capacity: usize,
}

impl Default for InMemoryAgentWebReplayStore {
    fn default() -> Self {
        Self {
            state: Mutex::new(InMemoryAgentWebReplayState::default()),
            global_capacity: DEFAULT_AGENT_WEB_REPLAY_GLOBAL_CAPACITY,
            per_scope_capacity: DEFAULT_AGENT_WEB_REPLAY_PER_SCOPE_CAPACITY,
        }
    }
}

impl InMemoryAgentWebReplayStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_capacity(
        global_capacity: usize,
        per_scope_capacity: usize,
    ) -> Result<Self, AgentWebReplayStoreError> {
        validate_replay_capacities(global_capacity, per_scope_capacity)?;
        Ok(Self {
            state: Mutex::new(InMemoryAgentWebReplayState::default()),
            global_capacity,
            per_scope_capacity,
        })
    }

    /// Seed a legacy unscoped marker that blocks every authenticated scope.
    ///
    /// New callers should reserve an [`AgentWebReplayEntry`] instead. This
    /// helper remains for compatibility with pre-scope test and migration code.
    pub fn with_seen_id(webhook_id: impl Into<String>, expires_at_unix_seconds: u64) -> Self {
        Self {
            state: Mutex::new(InMemoryAgentWebReplayState {
                entries: BTreeMap::new(),
                legacy_unscoped_entries: BTreeMap::from([(
                    webhook_id.into(),
                    expires_at_unix_seconds,
                )]),
                wall_clock_high_water: 0,
            }),
            global_capacity: DEFAULT_AGENT_WEB_REPLAY_GLOBAL_CAPACITY,
            per_scope_capacity: DEFAULT_AGENT_WEB_REPLAY_PER_SCOPE_CAPACITY,
        }
    }
}

impl AgentWebReplayStore for InMemoryAgentWebReplayStore {
    fn check_and_insert(
        &self,
        now_unix_seconds: u64,
        entries: &[AgentWebReplayEntry],
    ) -> Result<(), AgentWebReplayStoreError> {
        let mut state = self.state.lock().map_err(|_| {
            AgentWebReplayStoreError::Unavailable(
                "in-memory replay store lock poisoned".to_string(),
            )
        })?;
        if now_unix_seconds < state.wall_clock_high_water {
            return Err(AgentWebReplayStoreError::Unavailable(format!(
                "verifier clock rollback detected: {now_unix_seconds} is before high-water {}",
                state.wall_clock_high_water
            )));
        }
        state.wall_clock_high_water = now_unix_seconds;

        for entry in entries {
            if entry.expires_at_unix_seconds() < now_unix_seconds {
                return Err(AgentWebReplayStoreError::Unavailable(format!(
                    "replay expiry for {} is before verifier time",
                    entry.webhook_id()
                )));
            }
        }

        let mut batch_keys = BTreeSet::new();
        let mut batch_scope_counts = BTreeMap::<&AgentWebReplayScope, usize>::new();
        for entry in entries {
            let key = (entry.replay_scope(), entry.webhook_id());
            if !batch_keys.insert(key)
                || state
                    .entries
                    .get(&(entry.replay_scope().clone(), entry.webhook_id().to_string()))
                    .is_some_and(|expires_at| *expires_at >= now_unix_seconds)
                || state
                    .legacy_unscoped_entries
                    .get(entry.webhook_id())
                    .is_some_and(|expires_at| *expires_at >= now_unix_seconds)
            {
                return Err(AgentWebReplayStoreError::Replayed(
                    entry.webhook_id().to_string(),
                ));
            }
            *batch_scope_counts.entry(entry.replay_scope()).or_default() += 1;
        }

        let live_global = state
            .entries
            .values()
            .chain(state.legacy_unscoped_entries.values())
            .filter(|expires_at| **expires_at >= now_unix_seconds)
            .count();
        if live_global.saturating_add(entries.len()) > self.global_capacity {
            return Err(AgentWebReplayStoreError::Unavailable(format!(
                "global live-entry capacity {} exhausted; denying fail-closed",
                self.global_capacity
            )));
        }
        for (replay_scope, batch_count) in batch_scope_counts {
            let live_for_scope = state
                .entries
                .iter()
                .filter(|((scope, _), expires_at)| {
                    scope == replay_scope && **expires_at >= now_unix_seconds
                })
                .count();
            if live_for_scope.saturating_add(batch_count) > self.per_scope_capacity {
                return Err(AgentWebReplayStoreError::Unavailable(format!(
                    "per-scope live-entry capacity {} exhausted; denying fail-closed",
                    self.per_scope_capacity
                )));
            }
        }
        state
            .entries
            .retain(|_, expires_at| *expires_at >= now_unix_seconds);
        state
            .legacy_unscoped_entries
            .retain(|_, expires_at| *expires_at >= now_unix_seconds);
        for entry in entries {
            state.entries.insert(
                (entry.replay_scope().clone(), entry.webhook_id().to_string()),
                entry.expires_at_unix_seconds(),
            );
        }
        Ok(())
    }
}

fn validate_replay_capacities(
    global_capacity: usize,
    per_scope_capacity: usize,
) -> Result<(), AgentWebReplayStoreError> {
    if global_capacity == 0 || per_scope_capacity == 0 {
        return Err(AgentWebReplayStoreError::Unavailable(
            "global and per-scope replay capacities must be greater than zero".to_string(),
        ));
    }
    if per_scope_capacity > global_capacity {
        return Err(AgentWebReplayStoreError::Unavailable(
            "per-scope replay capacity cannot exceed global replay capacity".to_string(),
        ));
    }
    Ok(())
}

fn validate_standard_webhook_id(webhook_id: &str) -> Result<(), String> {
    if webhook_id.is_empty()
        || webhook_id.len() > MAX_STANDARD_WEBHOOK_ID_BYTES
        || webhook_id
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(format!(
            "Standard Webhooks id must be 1-{MAX_STANDARD_WEBHOOK_ID_BYTES} bytes without whitespace or control characters"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct StandardWebhooksReplayWindow {
    pub now_unix_seconds: u64,
    pub max_age_seconds: u64,
}

impl AgentWebVerifierTrust {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_standard_webhooks_secret(mut self, secret: impl Into<Vec<u8>>) -> Self {
        self.default_standard_webhooks_secret = Some(secret.into());
        self
    }

    pub fn with_trusted_passport_signer_keys(
        mut self,
        keys: impl IntoIterator<Item = PublicKey>,
    ) -> Self {
        self.trusted_passport_signer_keys.extend(keys);
        self
    }

    pub fn with_standard_webhooks_secret_for(
        mut self,
        webhook_id: impl Into<String>,
        secret: impl Into<Vec<u8>>,
    ) -> Self {
        self.standard_webhooks_secrets
            .insert(webhook_id.into(), secret.into());
        self
    }

    pub fn with_standard_webhooks_replay_window(
        mut self,
        now_unix_seconds: u64,
        max_age_seconds: u64,
    ) -> Self {
        self.standard_webhooks_replay_window = Some(StandardWebhooksReplayWindow {
            now_unix_seconds,
            max_age_seconds,
        });
        self
    }

    pub fn with_seen_standard_webhooks_id(mut self, webhook_id: impl Into<String>) -> Self {
        self.seen_standard_webhooks_ids.insert(webhook_id.into());
        self
    }

    pub fn with_standard_webhooks_replay_store(
        mut self,
        store: Arc<dyn AgentWebReplayStore>,
    ) -> Self {
        self.standard_webhooks_replay_store = Some(store);
        self
    }

    pub fn with_standard_webhooks_replay_reservation_id(
        mut self,
        reservation_id: impl Into<String>,
    ) -> Result<Self, AgentWebReplayStoreError> {
        let reservation_id = reservation_id.into();
        if reservation_id.len() != 64
            || !reservation_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AgentWebReplayStoreError::Unavailable(
                "replay reservation id must be exactly 64 lowercase hexadecimal characters"
                    .to_string(),
            ));
        }
        self.standard_webhooks_replay_reservation_id = Some(reservation_id);
        Ok(self)
    }

    pub fn with_trusted_receipt_kernel_keys(
        mut self,
        keys: impl IntoIterator<Item = PublicKey>,
    ) -> Self {
        self.trusted_receipt_kernel_keys.extend(keys);
        self
    }

    pub fn with_trusted_envelope_sidecar_keys(
        mut self,
        keys: impl IntoIterator<Item = PublicKey>,
    ) -> Self {
        self.trusted_envelope_sidecar_keys.extend(keys);
        self
    }

    pub(crate) fn standard_webhooks_secret(&self, webhook_id: &str) -> Option<&[u8]> {
        let secret = self
            .standard_webhooks_secrets
            .get(webhook_id)
            .or(self.default_standard_webhooks_secret.as_ref())?;
        if secret.is_empty() {
            None
        } else {
            Some(secret.as_slice())
        }
    }

    pub(crate) fn standard_webhooks_replay_window(&self) -> Option<&StandardWebhooksReplayWindow> {
        self.standard_webhooks_replay_window.as_ref()
    }

    pub(crate) fn has_seen_standard_webhooks_id(&self, webhook_id: &str) -> bool {
        self.seen_standard_webhooks_ids.contains(webhook_id)
    }

    fn trusts_receipt_kernel_key(&self, key: &PublicKey) -> bool {
        self.trusted_receipt_kernel_keys
            .iter()
            .any(|trusted_key| trusted_key == key)
    }

    fn trusts_envelope_sidecar_key(&self, key: &PublicKey) -> bool {
        self.trusted_envelope_sidecar_keys
            .iter()
            .any(|trusted_key| trusted_key == key)
    }

    fn validate_signer_role_separation(&self) -> Result<(), TransactionPassportError> {
        if trusted_key_sets_overlap(
            &self.trusted_passport_signer_keys,
            &self.trusted_receipt_kernel_keys,
        ) {
            return Err(claim_failed(
                "Agent Web passport and kernel signer roles overlap",
            ));
        }
        if trusted_key_sets_overlap(
            &self.trusted_passport_signer_keys,
            &self.trusted_envelope_sidecar_keys,
        ) {
            return Err(claim_failed(
                "Agent Web passport and sidecar signer roles overlap",
            ));
        }
        if trusted_key_sets_overlap(
            &self.trusted_receipt_kernel_keys,
            &self.trusted_envelope_sidecar_keys,
        ) {
            return Err(claim_failed(
                "Agent Web kernel and sidecar signer roles overlap",
            ));
        }
        Ok(())
    }

    fn commit_standard_webhooks_replays(
        &self,
        entries: &[AgentWebReplayEntry],
    ) -> Result<(), TransactionPassportError> {
        if entries.is_empty() {
            return Ok(());
        }
        if entries
            .iter()
            .any(|entry| self.has_seen_standard_webhooks_id(entry.webhook_id()))
        {
            return Err(claim_failed("replayed Standard Webhooks id"));
        }
        let replay_window = self
            .standard_webhooks_replay_window()
            .ok_or_else(|| claim_failed("missing Standard Webhooks replay window"))?;
        let store = self
            .standard_webhooks_replay_store
            .as_ref()
            .ok_or_else(|| claim_failed("missing durable Standard Webhooks replay store"))?;
        let reservation = self.standard_webhooks_replay_reservation_id.as_deref();
        let result = match reservation {
            Some(reservation_id) => store.check_and_insert_for_reservation(
                replay_window.now_unix_seconds,
                entries,
                reservation_id,
            ),
            None => store.check_and_insert(replay_window.now_unix_seconds, entries),
        };
        result
            .map_err(|error| match error {
                AgentWebReplayStoreError::Replayed(_) => {
                    claim_failed("replayed Standard Webhooks id")
                }
                AgentWebReplayStoreError::Unavailable(message) => claim_failed(format!(
                    "Standard Webhooks replay store unavailable: {message}"
                )),
            })
    }
}

fn trusted_key_sets_overlap(left: &[PublicKey], right: &[PublicKey]) -> bool {
    left.iter()
        .any(|left_key| right.iter().any(|right_key| right_key == left_key))
}

/// Canonical non-circular Agent-Web authorization scope derived from fields
/// covered by the passport root signature.
///
/// `evidence_graph_sha256` is excluded because the graph contains the
/// envelope and receipt that bind this digest. `signature` is excluded because
/// it signs the complete passport, including the graph digest. All remaining
/// identity, validity, claim-set, policy, path, and omission fields are bound.
#[derive(Serialize)]
struct AgentWebPassportScopeDigestInput<'a> {
    scope_schema: &'static str,
    passport_schema: &'a str,
    id: &'a str,
    issued_at: &'a str,
    not_before: Option<&'a str>,
    expires_at: Option<&'a str>,
    issuer: &'a str,
    evidence_graph_path: &'a str,
    claim_set_sha256: &'a str,
    claim_set_path: &'a str,
    verifier_policy_sha256: &'a str,
    verifier_policy_path: &'a str,
    omission_policy: &'a [chio_transaction_passport::TransactionOmissionPolicyEntry],
}

pub fn agent_web_passport_scope_sha256(
    passport: &TransactionPassport,
) -> Result<String, TransactionPassportError> {
    let input = AgentWebPassportScopeDigestInput {
        scope_schema: "chio.agent-web.passport-scope.v1",
        passport_schema: &passport.schema,
        id: &passport.id,
        issued_at: &passport.issued_at,
        not_before: passport.not_before.as_deref(),
        expires_at: passport.expires_at.as_deref(),
        issuer: &passport.issuer,
        evidence_graph_path: &passport.evidence_graph_path,
        claim_set_sha256: &passport.claim_set_sha256,
        claim_set_path: &passport.claim_set_path,
        verifier_policy_sha256: &passport.verifier_policy_sha256,
        verifier_policy_path: &passport.verifier_policy_path,
        omission_policy: &passport.omission_policy,
    };
    let canonical = canonical_json_bytes(&input)
        .map_err(|_| claim_failed("Agent Web passport scope digest invalid"))?;
    Ok(sha256_hex(&canonical))
}

struct ProjectionManifestEntry {
    node_id: String,
    node_sha256: String,
    manifest: ProjectionManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentWebInteropReport {
    pub schema: String,
    pub id: String,
    pub issued_at: String,
    pub verdict: String,
    pub passport_id: String,
    pub verified_claims: Vec<String>,
    pub projections: Vec<AgentWebProjectionResult>,
    pub unsupported_claims: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentWebProjectionResult {
    pub source_protocol: String,
    pub envelope_ref: String,
    pub projection_manifest_ref: String,
    pub external_subject_digest: String,
    pub evidence_classes: Vec<String>,
    pub claim_evidence: Vec<AgentWebClaimEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentWebClaimEvidence {
    pub claim_ref: String,
    pub evidence_class: String,
}

pub fn verify_agent_web_interop(
    bundle: &AgentWebInteropBundle,
) -> Result<AgentWebInteropReport, TransactionPassportError> {
    verify_agent_web_interop_with_trust(bundle, &AgentWebVerifierTrust::new())
}

/// Verifies an Agent Web bundle without reserving Standard Webhooks replay
/// identifiers. This read-only operation is safe to repeat for offline audit.
pub fn verify_agent_web_interop_with_trust(
    bundle: &AgentWebInteropBundle,
    trust: &AgentWebVerifierTrust,
) -> Result<AgentWebInteropReport, TransactionPassportError> {
    verify_agent_web_interop_with_trust_mode(bundle, trust, false, None)
}

/// Verifies an Agent Web bundle and atomically reserves its Standard Webhooks
/// replay identifiers after the entire bundle passes validation.
///
/// Unlike [`verify_agent_web_interop_with_trust`], this is a consuming
/// admission operation. It fails closed when webhook evidence is present and
/// no replay store is configured.
pub fn verify_agent_web_interop_with_trust_and_consume_replays(
    bundle: &AgentWebInteropBundle,
    trust: &AgentWebVerifierTrust,
) -> Result<AgentWebInteropReport, TransactionPassportError> {
    verify_agent_web_interop_with_trust_mode(bundle, trust, true, None)
}

/// Verifies an Agent Web bundle, confirms that its report matches a prior
/// read-only verification, and only then atomically reserves replay IDs.
pub fn verify_agent_web_interop_with_trust_and_consume_replays_if_report_matches(
    bundle: &AgentWebInteropBundle,
    trust: &AgentWebVerifierTrust,
    expected_read_only_report: &AgentWebInteropReport,
) -> Result<AgentWebInteropReport, TransactionPassportError> {
    verify_agent_web_interop_with_trust_mode(bundle, trust, true, Some(expected_read_only_report))
}

fn verify_agent_web_interop_with_trust_mode(
    bundle: &AgentWebInteropBundle,
    trust: &AgentWebVerifierTrust,
    consume_replays: bool,
    expected_read_only_report: Option<&AgentWebInteropReport>,
) -> Result<AgentWebInteropReport, TransactionPassportError> {
    trust.validate_signer_role_separation()?;
    let signed_evidence_graph_bytes = bundle
        .root_evidence_graph_bytes
        .as_deref()
        .unwrap_or(&bundle.evidence_graph_bytes);
    verify_transaction_passport_signature_with_evidence_graph(
        &bundle.passport,
        signed_evidence_graph_bytes,
        &bundle.evidence_graph_bytes,
        &trust.trusted_passport_signer_keys,
    )?;
    verify_minimal_passport_artifacts(
        &bundle.passport,
        "transaction-passport.json".to_string(),
        &bundle.evidence_graph_bytes,
        &bundle.verifier_policy_bytes,
    )?;

    let graph = parse_graph(&bundle.evidence_graph_bytes)?;
    let policy = parse_policy(&bundle.verifier_policy_bytes)?;
    let passport_scope_sha256 = agent_web_passport_scope_sha256(&bundle.passport)?;

    let mut manifests = BTreeMap::new();
    for node in graph
        .nodes
        .iter()
        .filter(|node| node.role == AgentWebEvidenceRole::ExternalProjectionManifest)
    {
        let manifest: ProjectionManifest = parse_artifact(
            bundle,
            node,
            "chio.agent-web.external-projection-manifest.v1",
        )?;
        validate_projection_manifest(&manifest)?;
        validate_required_unsupported_claims(&manifest)?;
        let projection_id = manifest.projection_id.clone();
        if manifests
            .insert(
                projection_id.clone(),
                ProjectionManifestEntry {
                    node_id: node.id.clone(),
                    node_sha256: node.sha256.clone(),
                    manifest,
                },
            )
            .is_some()
        {
            return Err(claim_failed(format!(
                "duplicate Agent Web projection id: {projection_id}"
            )));
        }
    }

    let mut verified_claims = Vec::new();
    let mut projections = Vec::new();
    let mut unsupported_claims = Vec::new();
    let mut limitations = Vec::new();
    let mut envelope_ids = BTreeSet::new();
    let mut pending_replay_entries = Vec::new();
    let mut replay_entry_subjects = BTreeMap::<(String, String), String>::new();

    for envelope_node in graph
        .nodes
        .iter()
        .filter(|node| node.role == AgentWebEvidenceRole::AgentWebProofEnvelope)
    {
        let envelope_schema = match envelope_node.schema.as_str() {
            CHIO_AGENT_WEB_PROOF_ENVELOPE_V1_SCHEMA => CHIO_AGENT_WEB_PROOF_ENVELOPE_V1_SCHEMA,
            CHIO_AGENT_WEB_PROOF_ENVELOPE_V2_SCHEMA => CHIO_AGENT_WEB_PROOF_ENVELOPE_V2_SCHEMA,
            schema => {
                return Err(claim_failed(format!(
                    "unsupported Agent Web proof envelope schema: {schema}"
                )));
            }
        };
        let envelope: AgentWebProofEnvelope =
            parse_artifact(bundle, envelope_node, envelope_schema)?;
        validate_envelope(&bundle.passport, &passport_scope_sha256, &envelope, trust)?;
        if !envelope_ids.insert(envelope.envelope_id.clone()) {
            return Err(claim_failed(format!(
                "duplicate Agent Web envelope id: {}",
                envelope.envelope_id
            )));
        }
        let manifest_entry = manifests
            .get(&envelope.projection_manifest_ref)
            .ok_or_else(|| claim_failed("missing projection manifest"))?;
        validate_envelope_manifest_binding(&envelope, manifest_entry)?;
        validate_required_edge(
            &graph,
            &envelope_node.id,
            &manifest_entry.node_id,
            "projects-to",
            "chio-sidecar-proof",
            "missing Agent Web manifest binding edge",
        )?;

        let external_node = find_node_by_path(
            &graph,
            AgentWebEvidenceRole::ExternalSubject,
            &envelope.external_subject_path,
        )
        .ok_or_else(|| claim_failed("missing external subject"))?;
        validate_required_edge(
            &graph,
            &envelope_node.id,
            &external_node.id,
            "binds",
            "digest-bound-reference",
            "missing Agent Web external subject binding edge",
        )?;
        validate_external_subject_schema(external_node, &envelope.source_protocol)?;
        let external_bytes = raw_artifact_bytes(bundle, external_node)?;
        if let Some(replay_entry) =
            validate_external_subject(&envelope, &manifest_entry.manifest, external_bytes, trust)?
        {
            retain_replay_entry_for_subject(
                &mut replay_entry_subjects,
                &mut pending_replay_entries,
                &external_node.id,
                replay_entry,
            )?;
        }
        if matches!(
            envelope.source_protocol.as_str(),
            "acp-commerce" | "ap2" | "x402"
        ) {
            validate_order_context_binding(
                &graph,
                bundle,
                external_node,
                external_bytes,
                &envelope.source_protocol,
            )?;
        }
        validate_receipt_refs(
            &graph,
            bundle,
            trust,
            &envelope_node.id,
            &envelope,
            &passport_scope_sha256,
        )?;

        verify_claim_mapping(
            &manifest_entry.manifest,
            &envelope.chio_claim_refs,
            &mut verified_claims,
        )?;
        extend_unique(
            &mut unsupported_claims,
            &manifest_entry.manifest.unsupported_claims,
        );
        extend_unique(&mut limitations, &manifest_entry.manifest.copy_limitations);
        extend_unique(&mut limitations, &envelope.limitations);

        projections.push(AgentWebProjectionResult {
            source_protocol: envelope.source_protocol.clone(),
            envelope_ref: envelope.envelope_id,
            projection_manifest_ref: manifest_entry.manifest.projection_id.clone(),
            external_subject_digest: envelope.external_subject_digest,
            evidence_classes: manifest_entry
                .manifest
                .claim_mapping
                .iter()
                .map(|mapping| mapping.evidence_class.clone())
                .collect(),
            claim_evidence: manifest_entry
                .manifest
                .claim_mapping
                .iter()
                .map(|mapping| AgentWebClaimEvidence {
                    claim_ref: mapping.claim_ref.clone(),
                    evidence_class: mapping.evidence_class.clone(),
                })
                .collect(),
        });
    }

    if projections.is_empty() {
        return Err(claim_failed("missing Agent Web proof envelope"));
    }
    reject_required_external_authority_claims(&policy.required_claims)?;
    ensure_required_claims_verified(&policy.required_claims, &verified_claims)?;

    let report = AgentWebInteropReport {
        schema: "chio.agent-web.interop-verifier-report.v1".to_string(),
        id: format!("agent-web-interop-report-{}", bundle.passport.id),
        issued_at: bundle.passport.issued_at.clone(),
        verdict: "verified".to_string(),
        passport_id: bundle.passport.id.clone(),
        verified_claims,
        projections,
        unsupported_claims,
        limitations,
    };
    if expected_read_only_report.is_some_and(|expected| expected != &report) {
        return Err(claim_failed(
            "consuming Agent Web report does not match its read-only verification",
        ));
    }
    if consume_replays {
        trust.commit_standard_webhooks_replays(&pending_replay_entries)?;
    }
    Ok(report)
}

fn retain_replay_entry_for_subject(
    replay_entry_subjects: &mut BTreeMap<(String, String), String>,
    pending_replay_entries: &mut Vec<AgentWebReplayEntry>,
    external_subject_node_id: &str,
    replay_entry: AgentWebReplayEntry,
) -> Result<(), TransactionPassportError> {
    let replay_key = (
        replay_entry.replay_scope().as_str().to_string(),
        replay_entry.webhook_id().to_string(),
    );
    match replay_entry_subjects.get(&replay_key) {
        Some(subject_node_id) if subject_node_id == external_subject_node_id => Ok(()),
        Some(_) => Err(claim_failed(format!(
            "Standard Webhooks id {} is reused across external subjects",
            replay_entry.webhook_id()
        ))),
        None => {
            replay_entry_subjects.insert(replay_key, external_subject_node_id.to_string());
            pending_replay_entries.push(replay_entry);
            Ok(())
        }
    }
}

fn validate_receipt_refs(
    graph: &evidence::AgentWebEvidenceGraph,
    bundle: &AgentWebInteropBundle,
    trust: &AgentWebVerifierTrust,
    envelope_node_id: &str,
    envelope: &AgentWebProofEnvelope,
    passport_scope_sha256: &str,
) -> Result<(), TransactionPassportError> {
    for receipt_ref in &envelope.receipt_refs {
        let receipt_node = if envelope.is_scope_bound_v2() {
            let canonical_ref = AgentWebReceiptRef::parse(receipt_ref)?;
            find_receipt_node(graph, &canonical_ref)
        } else {
            find_legacy_receipt_node(graph, receipt_ref)
        }
        .ok_or_else(|| claim_failed(format!("missing Agent Web receipt ref: {}", receipt_ref)))?;
        validate_required_edge(
            graph,
            envelope_node_id,
            &receipt_node.id,
            "binds",
            "digest-bound-reference",
            "missing Agent Web receipt binding edge",
        )?;
        let receipt_bytes = raw_artifact_bytes(bundle, receipt_node)?;
        validate_agent_web_receipt(
            receipt_bytes,
            receipt_ref,
            receipt_node,
            &bundle.passport,
            passport_scope_sha256,
            envelope,
            trust,
        )?;
    }
    Ok(())
}

fn validate_agent_web_receipt(
    receipt_bytes: &[u8],
    receipt_ref: &str,
    receipt_node: &evidence::AgentWebEvidenceNode,
    passport: &TransactionPassport,
    passport_scope_sha256: &str,
    envelope: &AgentWebProofEnvelope,
    trust: &AgentWebVerifierTrust,
) -> Result<(), TransactionPassportError> {
    let receipt: ChioReceipt = serde_json::from_slice(receipt_bytes)
        .map_err(|_| claim_failed("Agent Web receipt signature invalid"))?;
    let signature_valid = receipt
        .verify_signature()
        .map_err(|_| claim_failed("Agent Web receipt signature invalid"))?;
    if !signature_valid {
        return Err(claim_failed("Agent Web receipt signature invalid"));
    }
    let action_hash_valid = receipt
        .action
        .verify_hash()
        .map_err(|_| claim_failed("Agent Web receipt signature invalid"))?;
    if !action_hash_valid {
        return Err(claim_failed("Agent Web receipt signature invalid"));
    }
    if receipt.receipt_kind != ReceiptKind::MediatedDecision
        || receipt.trust_level != TrustLevel::Mediated
    {
        return Err(claim_failed("Agent Web receipt signature invalid"));
    }
    if !trust.trusts_receipt_kernel_key(&receipt.kernel_key) {
        return Err(claim_failed("Agent Web receipt kernel key untrusted"));
    }
    if receipt.tool_server != "agent-web-sidecar"
        || receipt.tool_name != "project-external-evidence"
    {
        return Err(claim_failed("Agent Web receipt producer mismatch"));
    }
    if receipt.decision.as_ref() != Some(&Decision::Allow) {
        return Err(claim_failed("Agent Web receipt did not execute"));
    }
    if receipt.content_hash != envelope.external_subject_digest {
        return Err(claim_failed("Agent Web receipt content digest mismatch"));
    }
    if receipt.policy_hash != passport.verifier_policy_sha256 {
        return Err(claim_failed("Agent Web receipt policy digest mismatch"));
    }
    if !envelope.is_scope_bound_v2() {
        let bound_ref = receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("agent_web_receipt_ref"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| claim_failed("Agent Web receipt ref mismatch"))?;
        let bound_ref_matches = if envelope.is_scope_bound_v2() {
            bound_ref == receipt_ref
        } else {
            receipt_node_ref_matches(receipt_node, bound_ref)
        };
        if !bound_ref_matches {
            return Err(claim_failed("Agent Web receipt ref mismatch"));
        }
    }
    if !envelope.is_scope_bound_v2() {
        return Ok(());
    }
    validate_receipt_action_parameter(
        &receipt,
        "agent_web_receipt_ref",
        receipt_ref,
        "Agent Web receipt action ref mismatch",
    )?;
    validate_receipt_action_parameter(
        &receipt,
        "content_hash",
        &envelope.external_subject_digest,
        "Agent Web receipt action content digest mismatch",
    )?;
    validate_receipt_action_parameter(
        &receipt,
        "transaction_passport_id",
        &passport.id,
        "Agent Web receipt action passport id mismatch",
    )?;
    validate_receipt_action_parameter(
        &receipt,
        "transaction_passport_issuer",
        &passport.issuer,
        "Agent Web receipt action passport issuer mismatch",
    )?;
    validate_receipt_action_parameter(
        &receipt,
        "agent_web_passport_scope_sha256",
        passport_scope_sha256,
        "Agent Web receipt action passport scope mismatch",
    )?;
    validate_receipt_action_parameter(
        &receipt,
        "agent_web_envelope_id",
        &envelope.envelope_id,
        "Agent Web receipt action envelope id mismatch",
    )?;
    validate_receipt_action_parameter(
        &receipt,
        "projection_manifest_sha256",
        &envelope.projection_manifest_sha256,
        "Agent Web receipt action projection manifest digest mismatch",
    )?;
    validate_receipt_action_parameter(
        &receipt,
        "source_protocol",
        &envelope.source_protocol,
        "Agent Web receipt action source protocol mismatch",
    )?;
    validate_receipt_action_parameter(
        &receipt,
        "source_protocol_version",
        &envelope.source_protocol_version,
        "Agent Web receipt action source protocol version mismatch",
    )?;
    Ok(())
}

fn validate_receipt_action_parameter(
    receipt: &ChioReceipt,
    parameter: &str,
    expected: &str,
    mismatch_message: &str,
) -> Result<(), TransactionPassportError> {
    let actual = receipt
        .action
        .parameters
        .get(parameter)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| claim_failed(mismatch_message))?;
    if actual != expected {
        return Err(claim_failed(mismatch_message));
    }
    Ok(())
}

fn validate_external_subject_schema(
    external_node: &evidence::AgentWebEvidenceNode,
    source_protocol: &str,
) -> Result<(), TransactionPassportError> {
    let expected_schema = expected_external_subject_schema(source_protocol)?;
    if external_node.schema != expected_schema {
        return Err(claim_failed(format!(
            "external subject schema mismatch: expected {expected_schema}, got {}",
            external_node.schema
        )));
    }
    Ok(())
}

fn expected_external_subject_schema(
    source_protocol: &str,
) -> Result<&'static str, TransactionPassportError> {
    protocols::external_subject_schema(source_protocol).ok_or_else(|| {
        claim_failed(format!(
            "unsupported Agent Web source protocol: {source_protocol}"
        ))
    })
}

fn validate_order_context_binding(
    graph: &evidence::AgentWebEvidenceGraph,
    bundle: &AgentWebInteropBundle,
    payment_node: &evidence::AgentWebEvidenceNode,
    payment_bytes: &[u8],
    source_protocol: &str,
) -> Result<(), TransactionPassportError> {
    let payment: serde_json::Value = serde_json::from_slice(payment_bytes).map_err(|error| {
        TransactionPassportError::InvalidAgentWebArtifact {
            path: payment_node.path.clone(),
            message: error.to_string(),
        }
    })?;
    let payment_order_id = payment
        .get("order_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| claim_failed(format!("missing {source_protocol} order id")))?;

    for order_node in graph.nodes.iter().filter(|node| {
        node.role == AgentWebEvidenceRole::ExternalSubject && node.id != payment_node.id
    }) {
        if !graph_has_edge(
            graph,
            &payment_node.id,
            &order_node.id,
            "binds",
            "digest-bound-reference",
        ) {
            continue;
        }
        let order_bytes = raw_artifact_bytes(bundle, order_node)?;
        let order_context: CommerceOrderContext =
            serde_json::from_slice(order_bytes).map_err(|error| {
                TransactionPassportError::InvalidAgentWebArtifact {
                    path: order_node.path.clone(),
                    message: error.to_string(),
                }
            })?;
        order_context.validate_shape().map_err(|error| {
            TransactionPassportError::InvalidAgentWebArtifact {
                path: order_node.path.clone(),
                message: error.to_string(),
            }
        })?;
        if order_context.order_id != payment_order_id {
            return Err(claim_failed(format!(
                "{source_protocol} payment order mismatch"
            )));
        }
        if source_protocol == "acp-commerce" {
            let order_context_digest = payment
                .get("order_context_digest")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| claim_failed("missing acp-commerce order context digest"))?;
            if order_context_digest != chio_core_types::sha256_hex(order_bytes) {
                return Err(claim_failed("acp-commerce order context digest mismatch"));
            }
        }
        if source_protocol == "ap2" {
            let transaction_context_digest = payment
                .get("transaction_context_digest")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| claim_failed("missing ap2 transaction context digest"))?;
            if transaction_context_digest != chio_core_types::sha256_hex(order_bytes) {
                return Err(claim_failed("ap2 transaction context digest mismatch"));
            }
        }
        if matches!(source_protocol, "acp-commerce" | "x402") {
            let payment_amount = payment
                .get("amount_units")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| claim_failed(format!("missing {source_protocol} amount")))?;
            if payment_amount != order_context.quote_amount_minor {
                return Err(claim_failed(format!(
                    "{source_protocol} payment amount mismatch"
                )));
            }
        }
        if source_protocol == "acp-commerce" {
            let payment_currency = payment
                .get("currency")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| claim_failed("missing acp-commerce currency"))?;
            if payment_currency != order_context.quote_currency {
                return Err(claim_failed("acp-commerce payment currency mismatch"));
            }
        }
        if source_protocol == "x402" {
            let payment_asset = payment
                .get("asset")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| claim_failed("missing x402 asset"))?;
            if !x402_asset_matches_quote_currency(payment_asset, &order_context.quote_currency) {
                return Err(claim_failed("x402 payment asset mismatch"));
            }
        }
        return Ok(());
    }

    Err(claim_failed(format!(
        "missing {source_protocol} order binding"
    )))
}

fn x402_asset_matches_quote_currency(asset: &str, quote_currency: &str) -> bool {
    match quote_currency {
        "USD" => matches!(asset, "USD" | "USDC"),
        _ => asset == quote_currency,
    }
}

fn validate_required_edge(
    graph: &evidence::AgentWebEvidenceGraph,
    from: &str,
    to: &str,
    predicate: &str,
    evidence_class: &str,
    message: &'static str,
) -> Result<(), TransactionPassportError> {
    if graph_has_edge(graph, from, to, predicate, evidence_class) {
        Ok(())
    } else {
        Err(claim_failed(message))
    }
}

fn validate_envelope_manifest_binding(
    envelope: &AgentWebProofEnvelope,
    manifest_entry: &ProjectionManifestEntry,
) -> Result<(), TransactionPassportError> {
    let manifest = &manifest_entry.manifest;
    if envelope.source_protocol != manifest.source_protocol
        || envelope.source_protocol_version != manifest.source_version
    {
        return Err(claim_failed("projection manifest protocol mismatch"));
    }
    if envelope.projection_manifest_sha256 != manifest_entry.node_sha256 {
        return Err(claim_failed("projection manifest digest mismatch"));
    }
    Ok(())
}

fn verify_claim_mapping(
    manifest: &ProjectionManifest,
    envelope_claims: &[String],
    verified_claims: &mut Vec<String>,
) -> Result<(), TransactionPassportError> {
    for mapping in &manifest.claim_mapping {
        if mapping.evidence_class == "native-external-proof"
            && manifest
                .unsupported_claims
                .iter()
                .any(|unsupported_claim| unsupported_claim == &mapping.claim_ref)
        {
            return Err(claim_failed(
                "unsupported external authority claim cannot be mapped as native external proof",
            ));
        }
    }

    for claim in envelope_claims {
        if is_agent_web_claim(claim) {
            continue;
        }
        if manifest
            .unsupported_claims
            .iter()
            .any(|unsupported_claim| unsupported_claim == claim)
        {
            continue;
        }
        return Err(claim_failed("unsupported claim was not limited"));
    }

    for required_claim in [
        CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
        CLAIM_PROJECTION_MANIFEST_BOUND,
        CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
        CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
    ] {
        if !envelope_claims.iter().any(|claim| claim == required_claim) {
            return Err(claim_failed(format!(
                "Agent Web envelope missing required claim: {required_claim}"
            )));
        }
        let mapping = manifest
            .claim_mapping
            .iter()
            .find(|mapping| mapping.claim_ref == required_claim)
            .ok_or_else(|| claim_failed(format!("missing claim mapping: {required_claim}")))?;
        if mapping.evidence_class == "native-external-proof" {
            return Err(claim_failed(
                "sidecar claim presented as native external proof",
            ));
        }
        push_claim_once(verified_claims, required_claim);
    }
    Ok(())
}

fn validate_required_unsupported_claims(
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    for required_claim in protocols::required_unsupported_claims(manifest.source_protocol.as_str())
    {
        if manifest
            .unsupported_claims
            .iter()
            .any(|unsupported_claim| unsupported_claim == required_claim)
        {
            continue;
        }
        return Err(claim_failed(format!(
            "missing Agent Web unsupported authority limitation: {required_claim}"
        )));
    }
    Ok(())
}

fn is_agent_web_claim(claim: &str) -> bool {
    matches!(
        claim,
        CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND
            | CLAIM_PROJECTION_MANIFEST_BOUND
            | CLAIM_UNSUPPORTED_CLAIMS_LIMITED
            | CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
    )
}

fn ensure_required_claims_verified(
    required_claims: &[String],
    verified_claims: &[String],
) -> Result<(), TransactionPassportError> {
    for required_claim in required_claims
        .iter()
        .filter(|claim| claim.starts_with("claim.agent_web."))
    {
        if !verified_claims
            .iter()
            .any(|verified_claim| verified_claim == required_claim)
        {
            return Err(claim_failed(format!(
                "required claim not verified: {required_claim}"
            )));
        }
    }
    Ok(())
}

fn reject_required_external_authority_claims(
    required_claims: &[String],
) -> Result<(), TransactionPassportError> {
    if let Some(required_claim) = required_claims
        .iter()
        .find(|claim| claim.starts_with("claim.external."))
    {
        return Err(claim_failed(format!(
            "Agent Web policy requires unsupported external claim: {required_claim}"
        )));
    }
    Ok(())
}

fn extend_unique(target: &mut Vec<String>, values: &[String]) {
    for value in values {
        if !target.iter().any(|existing| existing == value) {
            target.push(value.clone());
        }
    }
}

fn claim_failed(message: impl Into<String>) -> TransactionPassportError {
    TransactionPassportError::AgentWebClaimFailed(message.into())
}

#[cfg(test)]
mod replay_entry_tests {
    use super::*;

    fn replay_entry(webhook_id: &str) -> AgentWebReplayEntry {
        let Ok(scope) = AgentWebReplayScope::parse(format!("{:064x}", 1)) else {
            panic!("test replay scope must parse");
        };
        let Ok(entry) = AgentWebReplayEntry::new(scope, webhook_id, 20) else {
            panic!("test replay entry must validate");
        };
        entry
    }

    #[test]
    fn one_external_subject_is_reserved_once_across_envelopes() {
        let mut subjects = BTreeMap::new();
        let mut entries = Vec::new();

        assert!(retain_replay_entry_for_subject(
            &mut subjects,
            &mut entries,
            "subject-one",
            replay_entry("webhook-one"),
        )
        .is_ok());
        assert!(retain_replay_entry_for_subject(
            &mut subjects,
            &mut entries,
            "subject-one",
            replay_entry("webhook-one"),
        )
        .is_ok());
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn one_replay_key_cannot_name_distinct_external_subjects() {
        let mut subjects = BTreeMap::new();
        let mut entries = Vec::new();

        assert!(retain_replay_entry_for_subject(
            &mut subjects,
            &mut entries,
            "subject-one",
            replay_entry("webhook-one"),
        )
        .is_ok());
        let error = retain_replay_entry_for_subject(
            &mut subjects,
            &mut entries,
            "subject-two",
            replay_entry("webhook-one"),
        );
        assert!(error.is_err_and(|error| error
            .to_string()
            .contains("reused across external subjects")));
    }
}
