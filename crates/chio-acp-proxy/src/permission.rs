/// Maps ACP permission requests to Chio capability decisions.
///
/// The mapper translates between ACP's permission model (allow_once,
/// allow_always, reject_once, reject_always) and Chio's capability
/// model (scoped, time-bounded grants).
#[derive(Debug, Clone)]
pub struct PermissionMapper {
    /// Default duration (seconds) for scoped allow grants.
    default_scope_duration_secs: u64,
}

/// The result of mapping a single ACP permission option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedPermission {
    /// The original ACP option ID so the caller can correlate.
    pub original_option_id: String,
    /// The Chio-side decision derived from the ACP permission kind.
    pub chio_decision: PermissionDecision,
}

/// An Chio capability decision derived from an ACP permission kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionDecision {
    /// Allow this single invocation.
    AllowOnce,
    /// Allow with a scoped time window.
    AllowScoped { duration_secs: u64 },
    /// Deny this single invocation.
    Deny,
    /// Deny permanently (for this session).
    DenyPermanent,
}

impl PermissionMapper {
    /// Create a mapper with the given default scope duration.
    pub fn new(default_scope_duration_secs: u64) -> Self {
        Self {
            default_scope_duration_secs,
        }
    }

    /// Map an ACP permission option to a Chio decision.
    ///
    /// Returns `None` if the `kind` string is not recognized --
    /// callers should treat unknown kinds as deny (fail-closed).
    pub fn map_option(&self, option: &PermissionOption) -> MappedPermission {
        let decision = match option.kind.as_str() {
            "allow_once" => PermissionDecision::AllowOnce,
            "allow_always" => PermissionDecision::AllowScoped {
                duration_secs: self.default_scope_duration_secs,
            },
            "reject_once" => PermissionDecision::Deny,
            "reject_always" => PermissionDecision::DenyPermanent,
            // Fail-closed: unknown kinds deny.
            _ => PermissionDecision::Deny,
        };
        MappedPermission {
            original_option_id: option.option_id.clone(),
            chio_decision: decision,
        }
    }
}
