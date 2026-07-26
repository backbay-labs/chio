use chio_core::capability::{
    runtime_attestation::RuntimeAttestationEvidence,
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::{Keypair, PublicKey};
use uuid::Uuid;

use crate::KernelError;

const DEFAULT_CAPABILITY_ISSUANCE_CLOCK_SKEW_SECONDS: u64 = 30;

/// Validate that the local authority can issue the requested scope semantics.
pub fn ensure_capability_issuance_supported(_scope: &ChioScope) -> Result<(), KernelError> {
    Ok(())
}

/// Validate that an authority response is exactly the direct capability requested.
pub fn validate_issued_capability_response(
    capability: &CapabilityToken,
    requested_subject: &PublicKey,
    requested_scope: &ChioScope,
    requested_ttl_seconds: u64,
    current_issuer: &PublicKey,
) -> Result<(), KernelError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?
        .as_secs();
    validate_issued_capability_response_at(
        capability,
        requested_subject,
        requested_scope,
        requested_ttl_seconds,
        current_issuer,
        now,
        DEFAULT_CAPABILITY_ISSUANCE_CLOCK_SKEW_SECONDS,
    )
}

/// Deterministically validate an issuance response against the request and current authority.
pub fn validate_issued_capability_response_at(
    capability: &CapabilityToken,
    requested_subject: &PublicKey,
    requested_scope: &ChioScope,
    requested_ttl_seconds: u64,
    current_issuer: &PublicKey,
    now: u64,
    allowed_clock_skew_seconds: u64,
) -> Result<(), KernelError> {
    if &capability.issuer != current_issuer {
        return Err(KernelError::UntrustedIssuer);
    }
    if !matches!(capability.verify_signature(), Ok(true)) {
        return Err(KernelError::InvalidSignature);
    }
    if capability.aggregate_invocation_budget.is_some() {
        return Err(KernelError::CapabilityIssuanceDenied(
            "aggregate invocation capability issuance requires atomic composite admission enforcement"
                .to_string(),
        ));
    }
    ensure_capability_issuance_supported(&capability.scope)?;
    if &capability.subject != requested_subject {
        return Err(KernelError::CapabilityIssuanceFailed(
            "issued capability subject does not match the requested subject".to_string(),
        ));
    }
    if capability.scope.has_cumulative_approval() {
        chio_core::capability::cumulative_approval::verify_cumulative_approval_constraints(
            capability,
            std::slice::from_ref(current_issuer),
            None,
        )
        .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
    }
    let mut issued_scope = capability.scope.clone();
    for grant in &mut issued_scope.grants {
        for constraint in &mut grant.constraints {
            if let chio_core::capability::scope::Constraint::RequireCumulativeApprovalAbove {
                cumulative_approval_root_binding,
                ..
            } = constraint
            {
                *cumulative_approval_root_binding = None;
            }
        }
    }
    let issued_scope = chio_core::canonical_json_bytes(&issued_scope)
        .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
    let requested_scope = chio_core::canonical_json_bytes(requested_scope)
        .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
    if issued_scope != requested_scope {
        return Err(KernelError::CapabilityIssuanceFailed(
            "issued capability scope does not match the requested scope".to_string(),
        ));
    }
    if !capability.delegation_chain.is_empty() {
        return Err(KernelError::CapabilityIssuanceFailed(
            "issued capability must be direct".to_string(),
        ));
    }
    let latest_issued_at = now.saturating_add(allowed_clock_skew_seconds);
    if capability.issued_at > latest_issued_at {
        return Err(KernelError::CapabilityIssuanceFailed(format!(
            "issued capability timestamp {} is too far in the future relative to {now}",
            capability.issued_at
        )));
    }
    if capability.expires_at <= now {
        return Err(KernelError::CapabilityIssuanceFailed(format!(
            "issued capability is already expired at {} relative to {now}",
            capability.expires_at
        )));
    }
    let latest_expires_at = now
        .saturating_add(requested_ttl_seconds)
        .saturating_add(allowed_clock_skew_seconds);
    if capability.expires_at > latest_expires_at {
        return Err(KernelError::CapabilityIssuanceFailed(format!(
            "issued capability wall-clock expiry {} exceeds allowed maximum {latest_expires_at}",
            capability.expires_at
        )));
    }
    let lifetime = capability
        .expires_at
        .checked_sub(capability.issued_at)
        .ok_or_else(|| {
            KernelError::CapabilityIssuanceFailed(
                "issued capability lifetime is reversed".to_string(),
            )
        })?;
    if lifetime > requested_ttl_seconds {
        return Err(KernelError::CapabilityIssuanceFailed(format!(
            "issued capability lifetime {lifetime} exceeds requested TTL {requested_ttl_seconds}"
        )));
    }
    Ok(())
}

pub trait CapabilityAuthority: Send + Sync {
    fn authority_public_key(&self) -> PublicKey;

    fn trusted_public_keys(&self) -> Vec<PublicKey> {
        vec![self.authority_public_key()]
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError>;

    fn issue_capability_with_attestation(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        _runtime_attestation: Option<RuntimeAttestationEvidence>,
    ) -> Result<CapabilityToken, KernelError> {
        self.issue_capability(subject, scope, ttl_seconds)
    }
}

pub struct LocalCapabilityAuthority {
    keypair: Keypair,
}

impl LocalCapabilityAuthority {
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
    }
}

impl CapabilityAuthority for LocalCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        ensure_capability_issuance_supported(&scope)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let body = CapabilityTokenBody {
            id: format!("cap-{}", Uuid::now_v7()),
            issuer: self.keypair.public_key(),
            subject: subject.clone(),
            scope,
            issued_at: now,
            expires_at: now.saturating_add(ttl_seconds),
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        };

        if body.scope.has_cumulative_approval()
            && body.scope.grants.iter().any(|grant| {
                grant
                    .operations
                    .contains(&chio_core::capability::scope::Operation::Delegate)
            })
        {
            CapabilityToken::sign_cumulative_approval_family_root(body, &self.keypair)
        } else {
            CapabilityToken::sign(body, &self.keypair)
        }
        .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::capability::{
        aggregate_invocation::{AggregateInvocationBudget, AggregateInvocationScope},
        attenuation::{DelegationLink, DelegationLinkBody},
        scope::{Constraint, MonetaryAmount, Operation, ToolGrant},
    };

    fn tool_scope() -> ChioScope {
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "server".to_string(),
                tool_name: "tool".to_string(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        }
    }

    fn signed_response(
        issuer: &Keypair,
        subject: &PublicKey,
        scope: ChioScope,
        issued_at: u64,
        expires_at: u64,
        delegation_chain: Vec<DelegationLink>,
        aggregate_invocation_budget: Option<AggregateInvocationBudget>,
    ) -> Result<CapabilityToken, chio_core::error::Error> {
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-issued-response".to_string(),
                issuer: issuer.public_key(),
                subject: subject.clone(),
                scope,
                issued_at,
                expires_at,
                delegation_chain,
                aggregate_invocation_budget,
            },
            issuer,
        )
    }

    #[test]
    fn issuance_response_accepts_exact_trusted_direct_capability(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let issuer = Keypair::generate();
        let subject = Keypair::generate().public_key();
        let scope = tool_scope();
        let capability = signed_response(&issuer, &subject, scope.clone(), 100, 160, vec![], None)?;

        validate_issued_capability_response_at(
            &capability,
            &subject,
            &scope,
            60,
            &issuer.public_key(),
            100,
            30,
        )?;
        Ok(())
    }

    #[test]
    fn issuance_response_rejects_historical_issuer() -> Result<(), Box<dyn std::error::Error>> {
        let historical_issuer = Keypair::generate();
        let current_issuer = Keypair::generate();
        let subject = Keypair::generate().public_key();
        let scope = tool_scope();
        let capability = signed_response(
            &historical_issuer,
            &subject,
            scope.clone(),
            100,
            160,
            vec![],
            None,
        )?;

        assert!(matches!(
            validate_issued_capability_response_at(
                &capability,
                &subject,
                &scope,
                60,
                &current_issuer.public_key(),
                100,
                30,
            ),
            Err(KernelError::UntrustedIssuer)
        ));
        Ok(())
    }

    #[test]
    fn issuance_response_rejects_far_future_issue_time() -> Result<(), Box<dyn std::error::Error>> {
        let issuer = Keypair::generate();
        let subject = Keypair::generate().public_key();
        let scope = tool_scope();
        let capability = signed_response(&issuer, &subject, scope.clone(), 131, 131, vec![], None)?;

        let error = validate_issued_capability_response_at(
            &capability,
            &subject,
            &scope,
            60,
            &issuer.public_key(),
            100,
            30,
        )
        .expect_err("future issuance must fail closed");
        assert!(error.to_string().contains("too far in the future"));
        Ok(())
    }

    #[test]
    fn issuance_response_rejects_overlong_wall_clock_expiry(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let issuer = Keypair::generate();
        let subject = Keypair::generate().public_key();
        let scope = tool_scope();
        let capability = signed_response(&issuer, &subject, scope.clone(), 130, 191, vec![], None)?;

        let error = validate_issued_capability_response_at(
            &capability,
            &subject,
            &scope,
            60,
            &issuer.public_key(),
            100,
            30,
        )
        .expect_err("wall-clock expiry beyond request allowance must fail closed");
        assert!(error.to_string().contains("wall-clock expiry"));
        Ok(())
    }

    #[test]
    fn issuance_response_rejects_already_expired_response() -> Result<(), Box<dyn std::error::Error>>
    {
        let issuer = Keypair::generate();
        let subject = Keypair::generate().public_key();
        let scope = tool_scope();
        let capability = signed_response(&issuer, &subject, scope.clone(), 40, 100, vec![], None)?;

        let error = match validate_issued_capability_response_at(
            &capability,
            &subject,
            &scope,
            60,
            &issuer.public_key(),
            100,
            30,
        ) {
            Ok(()) => panic!("expired issuance response must fail closed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("already expired"));
        Ok(())
    }

    #[test]
    fn issuance_response_rejects_trusted_signed_subject_and_scope_substitutions(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let issuer = Keypair::generate();
        let requested_subject = Keypair::generate().public_key();
        let substituted_subject = Keypair::generate().public_key();
        let requested_scope = ChioScope::default();
        let subject_substitution = signed_response(
            &issuer,
            &substituted_subject,
            requested_scope.clone(),
            100,
            160,
            vec![],
            None,
        )?;
        let scope_substitution = signed_response(
            &issuer,
            &requested_subject,
            tool_scope(),
            100,
            160,
            vec![],
            None,
        )?;

        for capability in [&subject_substitution, &scope_substitution] {
            assert!(matches!(
                validate_issued_capability_response(
                    capability,
                    &requested_subject,
                    &requested_scope,
                    60,
                    &issuer.public_key(),
                ),
                Err(KernelError::CapabilityIssuanceFailed(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn issuance_response_rejects_delegation_and_invalid_lifetimes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let issuer = Keypair::generate();
        let subject = Keypair::generate().public_key();
        let scope = tool_scope();
        let link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: "cap-parent".to_string(),
                delegator: issuer.public_key(),
                delegatee: subject.clone(),
                attenuations: Vec::new(),
                timestamp: 100,
                scope_hash: None,
                aggregate_budget: None,
                cumulative_approval: None,
            },
            &issuer,
        )?;
        let delegated =
            signed_response(&issuer, &subject, scope.clone(), 100, 160, vec![link], None)?;
        let widened = signed_response(&issuer, &subject, scope.clone(), 100, 161, vec![], None)?;
        let reversed = signed_response(&issuer, &subject, scope.clone(), 101, 100, vec![], None)?;

        for capability in [&delegated, &widened, &reversed] {
            assert!(matches!(
                validate_issued_capability_response(
                    capability,
                    &subject,
                    &scope,
                    60,
                    &issuer.public_key(),
                ),
                Err(KernelError::CapabilityIssuanceFailed(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn issuance_response_rejects_aggregate_and_accepts_cumulative_semantics(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let issuer = Keypair::generate();
        let subject = Keypair::generate().public_key();
        let aggregate_scope = tool_scope();
        let aggregate = signed_response(
            &issuer,
            &subject,
            aggregate_scope.clone(),
            100,
            160,
            vec![],
            Some(AggregateInvocationBudget {
                scope: AggregateInvocationScope::Capability,
                max_invocations: 2,
                root_binding: None,
            }),
        )?;
        assert!(matches!(
            validate_issued_capability_response(
                &aggregate,
                &subject,
                &aggregate_scope,
                60,
                &issuer.public_key(),
            ),
            Err(KernelError::CapabilityIssuanceDenied(_))
        ));

        let cumulative_scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: "server".to_string(),
                tool_name: "tool".to_string(),
                operations: vec![Operation::Invoke, Operation::Delegate],
                constraints: vec![Constraint::RequireCumulativeApprovalAbove {
                    threshold: MonetaryAmount {
                        units: 100,
                        currency: "USD".to_string(),
                    },
                    approval_budget_id: "budget-1".to_string(),
                    approval_budget_epoch: 1,
                    cumulative_approval_root_binding: None,
                }],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        };
        let requested_cumulative_scope = cumulative_scope.clone();
        let cumulative = CapabilityToken::sign_cumulative_approval_family_root(
            CapabilityTokenBody {
                id: "cap-cumulative-response".to_string(),
                issuer: issuer.public_key(),
                subject: subject.clone(),
                scope: cumulative_scope,
                issued_at: 100,
                expires_at: 160,
                delegation_chain: vec![],
                aggregate_invocation_budget: None,
            },
            &issuer,
        )?;
        validate_issued_capability_response_at(
            &cumulative,
            &subject,
            &requested_cumulative_scope,
            60,
            &issuer.public_key(),
            100,
            0,
        )?;
        Ok(())
    }

    #[test]
    fn local_authority_issues_cumulative_approval_capabilities() {
        let authority = LocalCapabilityAuthority::new(Keypair::generate());
        let scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: "server".to_string(),
                tool_name: "tool".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![Constraint::RequireCumulativeApprovalAbove {
                    threshold: MonetaryAmount {
                        units: 100,
                        currency: "USD".to_string(),
                    },
                    approval_budget_id: "budget-1".to_string(),
                    approval_budget_epoch: 1,
                    cumulative_approval_root_binding: None,
                }],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        };

        let capability = authority
            .issue_capability(&Keypair::generate().public_key(), scope, 300)
            .expect("cumulative approval capability");
        assert!(capability.scope.has_cumulative_approval());
        assert!(capability.scope.grants[0]
            .constraints
            .iter()
            .any(|constraint| {
                matches!(
                    constraint,
                    Constraint::RequireCumulativeApprovalAbove {
                        cumulative_approval_root_binding: None,
                        ..
                    }
                )
            }));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityStatus {
    pub public_key: PublicKey,
    pub generation: u64,
    pub rotated_at: u64,
    pub trusted_public_keys: Vec<PublicKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityTrustedKeySnapshot {
    pub public_key_hex: String,
    pub generation: u64,
    pub activated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySnapshot {
    pub public_key_hex: String,
    pub generation: u64,
    pub rotated_at: u64,
    pub trusted_keys: Vec<AuthorityTrustedKeySnapshot>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorityStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("failed to prepare authority store directory: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid authority seed: {0}")]
    Core(#[from] chio_core::error::Error),

    #[error("authority fence rejected mutation: {0}")]
    Fence(String),

    #[error("{0}")]
    Schema(String),
}
