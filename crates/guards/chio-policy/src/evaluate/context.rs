use chio_core::capability::{runtime_attestation::{RuntimeAssuranceTier}, workload_identity::{WorkloadIdentity}};

// ---------------------------------------------------------------------------
// Panic mode (global emergency deny-all)
// ---------------------------------------------------------------------------

static PANIC_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Activate panic mode globally. All subsequent `evaluate()` calls will deny.
pub fn activate_panic() {
    PANIC_ACTIVE.store(true, Ordering::SeqCst);
}

/// Deactivate panic mode, restoring normal evaluation.
pub fn deactivate_panic() {
    PANIC_ACTIVE.store(false, Ordering::SeqCst);
}

/// Check if panic mode is currently active.
pub fn is_panic_active() -> bool {
    PANIC_ACTIVE.load(Ordering::SeqCst)
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Warn,
    Deny,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationAction {
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<OriginContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<RuntimeAttestationContext>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_participants: Option<bool>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_role: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAttestationContext {
    pub tier: RuntimeAssuranceTier,
    #[serde(default)]
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_identity: Option<WorkloadIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationResult {
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureResult>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureResult {
    pub current: String,
    pub next: String,
}
