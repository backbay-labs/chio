use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, ThresholdApprovalProposal,
};
use chio_core::capability::threshold_approval::ThresholdApprovalRequirement;
use chio_core::crypto::PublicKey;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedApproverIdentity {
    pub identifier: String,
    pub public_key: PublicKey,
    pub directory_version: String,
}

pub trait ApproverDirectory: Send + Sync {
    fn resolve_approver(&self, identifier: &str) -> Result<ResolvedApproverIdentity, String>;
}

pub trait ThresholdApprovalRequirementResolver: Send + Sync {
    fn resolve_requirement(
        &self,
        policy_hash: &str,
        server_id: &str,
        tool_name: &str,
    ) -> Result<Option<ThresholdApprovalRequirement>, String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdApprovalCollectorState {
    Collecting,
    Ready,
    Delivered,
    Cancelled,
}

impl ThresholdApprovalCollectorState {
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Delivered | Self::Cancelled)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ThresholdApprovalCollectorProposal {
    pub proposal: ThresholdApprovalProposal,
    pub requirement: ThresholdApprovalRequirement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submitter: Option<PublicKey>,
    #[serde(default)]
    pub require_submitter_separation: bool,
    pub state: ThresholdApprovalCollectorState,
    pub tokens: Vec<GovernedApprovalToken>,
    pub version: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CollectedThresholdApprovalSet {
    pub proposal: ThresholdApprovalProposal,
    pub tokens: Vec<GovernedApprovalToken>,
}

#[derive(Debug, thiserror::Error)]
pub enum ThresholdApprovalCollectorStoreError {
    #[error("threshold approval proposal not found: {0}")]
    NotFound(String),
    #[error("threshold approval collector conflict: {0}")]
    Conflict(String),
    #[error("threshold approval collector backend error: {0}")]
    Backend(String),
    #[error("threshold approval collector serialization error: {0}")]
    Serialization(String),
}

pub trait ThresholdApprovalCollectorStore: Send + Sync {
    fn create(
        &self,
        proposal: &ThresholdApprovalCollectorProposal,
    ) -> Result<(), ThresholdApprovalCollectorStoreError>;

    fn get(
        &self,
        proposal_id: &str,
    ) -> Result<Option<ThresholdApprovalCollectorProposal>, ThresholdApprovalCollectorStoreError>;

    fn append_token(
        &self,
        proposal_id: &str,
        expected_version: u64,
        token: &GovernedApprovalToken,
        replaced_token_id: Option<&str>,
        next_state: ThresholdApprovalCollectorState,
        updated_at: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError>;

    fn transition(
        &self,
        proposal_id: &str,
        expected_version: u64,
        next_state: ThresholdApprovalCollectorState,
        updated_at: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError>;
}

#[derive(Clone)]
pub struct ThresholdApprovalCollector {
    store: Arc<dyn ThresholdApprovalCollectorStore>,
    active_policy_hash: String,
    trusted_policy_authorities: Vec<PublicKey>,
}

impl std::fmt::Debug for ThresholdApprovalCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdApprovalCollector")
            .field("active_policy_hash", &self.active_policy_hash)
            .field(
                "trusted_policy_authority_count",
                &self.trusted_policy_authorities.len(),
            )
            .finish_non_exhaustive()
    }
}

impl ThresholdApprovalCollector {
    #[must_use]
    pub fn new(
        store: Arc<dyn ThresholdApprovalCollectorStore>,
        active_policy_hash: String,
        trusted_policy_authorities: Vec<PublicKey>,
    ) -> Self {
        Self {
            store,
            active_policy_hash,
            trusted_policy_authorities,
        }
    }

    pub fn create_proposal(
        &self,
        proposal: ThresholdApprovalProposal,
        requirement: ThresholdApprovalRequirement,
        submitter: Option<PublicKey>,
        require_submitter_separation: bool,
        now: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        requirement
            .validate()
            .map_err(ThresholdApprovalCollectorStoreError::Conflict)?;
        proposal
            .validate_at(now)
            .map_err(|error| ThresholdApprovalCollectorStoreError::Conflict(error.to_string()))?;
        if proposal.body.policy_hash != self.active_policy_hash
            || requirement.policy_hash != self.active_policy_hash
        {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal is stale for the active policy".to_string(),
            ));
        }
        if proposal.body.threshold != requirement.threshold
            || proposal.body.eligible_set_digest != requirement.eligible_set_digest
        {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal does not match its approver requirement".to_string(),
            ));
        }
        if !self
            .trusted_policy_authorities
            .contains(&proposal.body.policy_authority)
        {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal signer is not trusted".to_string(),
            ));
        }
        if !proposal
            .verify_signature()
            .map_err(|error| ThresholdApprovalCollectorStoreError::Conflict(error.to_string()))?
        {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal signature did not verify".to_string(),
            ));
        }
        let record = ThresholdApprovalCollectorProposal {
            proposal,
            requirement,
            submitter,
            require_submitter_separation,
            state: ThresholdApprovalCollectorState::Collecting,
            tokens: Vec::new(),
            version: 0,
            updated_at: now,
        };
        self.store.create(&record)?;
        Ok(record)
    }

    pub fn get_proposal(
        &self,
        proposal_id: &str,
    ) -> Result<Option<ThresholdApprovalCollectorProposal>, ThresholdApprovalCollectorStoreError>
    {
        self.store.get(proposal_id)
    }

    pub fn submit_token(
        &self,
        proposal_id: &str,
        token: GovernedApprovalToken,
        now: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        let record = self
            .store
            .get(proposal_id)?
            .ok_or_else(|| ThresholdApprovalCollectorStoreError::NotFound(proposal_id.into()))?;
        if record.state.is_terminal() {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal no longer accepts updates".to_string(),
            ));
        }
        let proposal = &record.proposal;
        proposal
            .validate_at(now)
            .map_err(|error| ThresholdApprovalCollectorStoreError::Conflict(error.to_string()))?;
        if proposal.body.policy_hash != self.active_policy_hash {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal is stale for the active policy".to_string(),
            ));
        }
        let proposal_hash = proposal
            .artifact_digest()
            .map_err(|error| ThresholdApprovalCollectorStoreError::Conflict(error.to_string()))?;
        if token.id.is_empty()
            || token.id.trim() != token.id
            || token.request_id != proposal.body.request_id
            || token.governed_intent_hash != proposal.body.governed_intent_hash
            || token.subject != proposal.body.subject
            || token.threshold_proposal_hash.as_deref() != Some(proposal_hash.as_str())
            || token.decision != GovernedApprovalDecision::Approved
            || token.issued_at < proposal.body.proposal_created_at
            || token.issued_at >= proposal.body.proposal_deadline
            || token.expires_at > proposal.body.proposal_deadline
        {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval token does not match the signed proposal".to_string(),
            ));
        }
        token
            .validate_time(now)
            .map_err(|error| ThresholdApprovalCollectorStoreError::Conflict(error.to_string()))?;
        if !record
            .requirement
            .eligible_approvers
            .iter()
            .any(|eligible| eligible.public_key == token.approver)
        {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval token signer is not eligible".to_string(),
            ));
        }
        if record.require_submitter_separation && record.submitter.as_ref() == Some(&token.approver)
        {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval submitter cannot approve their own proposal".to_string(),
            ));
        }
        if !token
            .verify_signature()
            .map_err(|error| ThresholdApprovalCollectorStoreError::Conflict(error.to_string()))?
        {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval token signature did not verify".to_string(),
            ));
        }
        let digest = token
            .artifact_digest()
            .map_err(|error| ThresholdApprovalCollectorStoreError::Conflict(error.to_string()))?;
        let mut replaced_token_id = None;
        for existing in &record.tokens {
            let existing_digest = existing.artifact_digest().map_err(|error| {
                ThresholdApprovalCollectorStoreError::Serialization(error.to_string())
            })?;
            if existing.id == token.id || existing_digest == digest {
                return Err(ThresholdApprovalCollectorStoreError::Conflict(
                    "threshold approval token id, digest, and signer must be unique".to_string(),
                ));
            }
            if existing.approver == token.approver {
                if existing.validate_time(now).is_ok() {
                    return Err(ThresholdApprovalCollectorStoreError::Conflict(
                        "threshold approval token id, digest, and signer must be unique"
                            .to_string(),
                    ));
                }
                replaced_token_id = Some(existing.id.as_str());
            }
        }
        let active_count = record
            .tokens
            .iter()
            .filter(|existing| {
                Some(existing.id.as_str()) != replaced_token_id
                    && existing.validate_time(now).is_ok()
            })
            .count()
            .checked_add(1)
            .ok_or_else(|| {
                ThresholdApprovalCollectorStoreError::Conflict(
                    "threshold approval token count overflowed".to_string(),
                )
            })?;
        let threshold = usize::try_from(record.requirement.threshold).map_err(|_| {
            ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval quorum does not fit this platform".to_string(),
            )
        })?;
        let next_state = if active_count >= threshold {
            ThresholdApprovalCollectorState::Ready
        } else {
            ThresholdApprovalCollectorState::Collecting
        };
        self.store.append_token(
            proposal_id,
            record.version,
            &token,
            replaced_token_id,
            next_state,
            now,
        )
    }

    pub fn deliver(
        &self,
        proposal_id: &str,
        now: u64,
    ) -> Result<CollectedThresholdApprovalSet, ThresholdApprovalCollectorStoreError> {
        let record = self
            .store
            .get(proposal_id)?
            .ok_or_else(|| ThresholdApprovalCollectorStoreError::NotFound(proposal_id.into()))?;
        if record.state != ThresholdApprovalCollectorState::Ready {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal is not ready for delivery".to_string(),
            ));
        }
        record
            .proposal
            .validate_at(now)
            .map_err(|error| ThresholdApprovalCollectorStoreError::Conflict(error.to_string()))?;
        if record.proposal.body.policy_hash != self.active_policy_hash {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal is stale for the active policy".to_string(),
            ));
        }
        // A token may expire well before the proposal deadline. Ignore superseded
        // or expired history and deliver only the currently valid set.
        let valid_tokens = record
            .tokens
            .iter()
            .filter(|token| token.validate_time(now).is_ok())
            .cloned()
            .collect::<Vec<_>>();
        let threshold = usize::try_from(record.requirement.threshold).map_err(|_| {
            ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval quorum does not fit this platform".to_string(),
            )
        })?;
        if valid_tokens.len() < threshold {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval quorum is no longer satisfied".to_string(),
            ));
        }
        let delivered = self.store.transition(
            proposal_id,
            record.version,
            ThresholdApprovalCollectorState::Delivered,
            now,
        )?;
        Ok(CollectedThresholdApprovalSet {
            proposal: delivered.proposal,
            tokens: valid_tokens,
        })
    }

    pub fn cancel(
        &self,
        proposal_id: &str,
        now: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        let record = self
            .store
            .get(proposal_id)?
            .ok_or_else(|| ThresholdApprovalCollectorStoreError::NotFound(proposal_id.into()))?;
        if record.state.is_terminal() {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal is already terminal".to_string(),
            ));
        }
        self.store.transition(
            proposal_id,
            record.version,
            ThresholdApprovalCollectorState::Cancelled,
            now,
        )
    }
}

#[derive(Default)]
pub struct InMemoryThresholdApprovalCollectorStore {
    proposals: RwLock<HashMap<String, ThresholdApprovalCollectorProposal>>,
}

impl InMemoryThresholdApprovalCollectorStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ThresholdApprovalCollectorStore for InMemoryThresholdApprovalCollectorStore {
    fn create(
        &self,
        proposal: &ThresholdApprovalCollectorProposal,
    ) -> Result<(), ThresholdApprovalCollectorStoreError> {
        let mut proposals = self.proposals.write().map_err(|_| {
            ThresholdApprovalCollectorStoreError::Backend("proposal map poisoned".to_string())
        })?;
        let id = &proposal.proposal.body.proposal_id;
        match proposals.get(id) {
            Some(existing) if existing == proposal => Ok(()),
            Some(_) => Err(ThresholdApprovalCollectorStoreError::Conflict(
                "proposal id already exists with different content".to_string(),
            )),
            None => {
                proposals.insert(id.clone(), proposal.clone());
                Ok(())
            }
        }
    }

    fn get(
        &self,
        proposal_id: &str,
    ) -> Result<Option<ThresholdApprovalCollectorProposal>, ThresholdApprovalCollectorStoreError>
    {
        self.proposals
            .read()
            .map_err(|_| {
                ThresholdApprovalCollectorStoreError::Backend("proposal map poisoned".to_string())
            })
            .map(|proposals| proposals.get(proposal_id).cloned())
    }

    fn append_token(
        &self,
        proposal_id: &str,
        expected_version: u64,
        token: &GovernedApprovalToken,
        replaced_token_id: Option<&str>,
        next_state: ThresholdApprovalCollectorState,
        updated_at: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        let mut proposals = self.proposals.write().map_err(|_| {
            ThresholdApprovalCollectorStoreError::Backend("proposal map poisoned".to_string())
        })?;
        let record = proposals.get_mut(proposal_id).ok_or_else(|| {
            ThresholdApprovalCollectorStoreError::NotFound(proposal_id.to_string())
        })?;
        if record.version != expected_version || record.state.is_terminal() {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal changed concurrently".to_string(),
            ));
        }
        if let Some(replaced_token_id) = replaced_token_id {
            let existing = record
                .tokens
                .iter_mut()
                .find(|existing| existing.id == replaced_token_id)
                .ok_or_else(|| {
                    ThresholdApprovalCollectorStoreError::Conflict(
                        "threshold approval replacement token disappeared".to_string(),
                    )
                })?;
            *existing = token.clone();
        } else {
            record.tokens.push(token.clone());
        }
        record.state = next_state;
        record.version = record.version.checked_add(1).ok_or_else(|| {
            ThresholdApprovalCollectorStoreError::Conflict("proposal version overflowed".into())
        })?;
        record.updated_at = updated_at;
        Ok(record.clone())
    }

    fn transition(
        &self,
        proposal_id: &str,
        expected_version: u64,
        next_state: ThresholdApprovalCollectorState,
        updated_at: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        let mut proposals = self.proposals.write().map_err(|_| {
            ThresholdApprovalCollectorStoreError::Backend("proposal map poisoned".to_string())
        })?;
        let record = proposals.get_mut(proposal_id).ok_or_else(|| {
            ThresholdApprovalCollectorStoreError::NotFound(proposal_id.to_string())
        })?;
        if record.version != expected_version || record.state.is_terminal() {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal changed concurrently".to_string(),
            ));
        }
        record.state = next_state;
        record.version = record.version.checked_add(1).ok_or_else(|| {
            ThresholdApprovalCollectorStoreError::Conflict("proposal version overflowed".into())
        })?;
        record.updated_at = updated_at;
        Ok(record.clone())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use chio_core::capability::governance::{
        GovernedApprovalTokenBody, ThresholdApprovalProposalBody,
    };
    use chio_core::capability::threshold_approval::ThresholdApproverIdentity;
    use chio_core::crypto::{sha256_hex, Keypair};

    struct Fixture {
        collector: ThresholdApprovalCollector,
        authority: Keypair,
        submitter: Keypair,
        alice: Keypair,
        bob: Keypair,
        subject: Keypair,
        requirement: ThresholdApprovalRequirement,
    }

    fn fixture() -> Fixture {
        let authority = Keypair::generate();
        let submitter = Keypair::generate();
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let subject = Keypair::generate();
        let policy_hash = sha256_hex(b"active-policy");
        let requirement = ThresholdApprovalRequirement::new(
            policy_hash.clone(),
            2,
            vec![
                ThresholdApproverIdentity {
                    identifier: "alice".to_string(),
                    public_key: alice.public_key(),
                },
                ThresholdApproverIdentity {
                    identifier: "bob".to_string(),
                    public_key: bob.public_key(),
                },
                ThresholdApproverIdentity {
                    identifier: "submitter".to_string(),
                    public_key: submitter.public_key(),
                },
            ],
            "directory-v1".to_string(),
            100,
        )
        .unwrap();
        let collector = ThresholdApprovalCollector::new(
            Arc::new(InMemoryThresholdApprovalCollectorStore::new()),
            policy_hash,
            vec![authority.public_key()],
        );
        Fixture {
            collector,
            authority,
            submitter,
            alice,
            bob,
            subject,
            requirement,
        }
    }

    fn proposal(fixture: &Fixture, proposal_id: &str) -> ThresholdApprovalProposal {
        ThresholdApprovalProposal::sign(
            ThresholdApprovalProposalBody {
                schema: chio_core::capability::governance::THRESHOLD_APPROVAL_PROPOSAL_SCHEMA
                    .to_string(),
                proposal_id: proposal_id.to_string(),
                request_id: "request-1".to_string(),
                governed_intent_hash: sha256_hex(b"intent"),
                subject: fixture.subject.public_key(),
                authorizing_capability_digest: sha256_hex(b"capability"),
                policy_hash: fixture.requirement.policy_hash.clone(),
                threshold: fixture.requirement.threshold,
                eligible_set_digest: fixture.requirement.eligible_set_digest.clone(),
                proposal_created_at: 100,
                proposal_deadline: 200,
                policy_authority: fixture.authority.public_key(),
            },
            &fixture.authority,
        )
        .unwrap()
    }

    fn token(
        proposal: &ThresholdApprovalProposal,
        approver: &Keypair,
        token_id: &str,
    ) -> GovernedApprovalToken {
        token_expiring_at(proposal, approver, token_id, 199)
    }

    fn token_expiring_at(
        proposal: &ThresholdApprovalProposal,
        approver: &Keypair,
        token_id: &str,
        expires_at: u64,
    ) -> GovernedApprovalToken {
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: token_id.to_string(),
                approver: approver.public_key(),
                subject: proposal.body.subject.clone(),
                governed_intent_hash: proposal.body.governed_intent_hash.clone(),
                request_id: proposal.body.request_id.clone(),
                threshold_proposal_hash: Some(proposal.artifact_digest().unwrap()),
                issued_at: 101,
                expires_at,
                decision: GovernedApprovalDecision::Approved,
            },
            approver,
        )
        .unwrap()
    }

    #[test]
    fn collector_persists_quorum_before_returning_original_tokens() {
        let fixture = fixture();
        let proposal = proposal(&fixture, "proposal-1");
        fixture
            .collector
            .create_proposal(
                proposal.clone(),
                fixture.requirement.clone(),
                Some(fixture.submitter.public_key()),
                true,
                100,
            )
            .unwrap();

        let separated = fixture
            .collector
            .submit_token(
                "proposal-1",
                token(&proposal, &fixture.submitter, "token-submitter"),
                110,
            )
            .unwrap_err();
        assert!(separated.to_string().contains("cannot approve"));

        let collecting = fixture
            .collector
            .submit_token(
                "proposal-1",
                token(&proposal, &fixture.alice, "token-alice"),
                110,
            )
            .unwrap();
        assert_eq!(
            collecting.state,
            ThresholdApprovalCollectorState::Collecting
        );
        let duplicate = fixture
            .collector
            .submit_token(
                "proposal-1",
                token(&proposal, &fixture.alice, "token-alice-2"),
                111,
            )
            .unwrap_err();
        assert!(duplicate.to_string().contains("must be unique"));

        let ready = fixture
            .collector
            .submit_token(
                "proposal-1",
                token(&proposal, &fixture.bob, "token-bob"),
                112,
            )
            .unwrap();
        assert_eq!(ready.state, ThresholdApprovalCollectorState::Ready);
        assert_eq!(ready.tokens.len(), 2);

        let delivered = fixture.collector.deliver("proposal-1", 113).unwrap();
        assert_eq!(delivered.proposal, proposal);
        assert_eq!(
            delivered
                .tokens
                .iter()
                .map(|value| value.id.as_str())
                .collect::<Vec<_>>(),
            vec!["token-alice", "token-bob"]
        );
        let stored = fixture
            .collector
            .get_proposal("proposal-1")
            .unwrap()
            .unwrap();
        assert_eq!(stored.state, ThresholdApprovalCollectorState::Delivered);
        assert!(fixture.collector.deliver("proposal-1", 114).is_err());
    }

    #[test]
    fn collector_rejects_stale_policy_changed_intent_and_terminal_updates() {
        let fixture = fixture();
        let mut stale_requirement = fixture.requirement.clone();
        stale_requirement.policy_hash = sha256_hex(b"stale-policy");
        assert!(fixture
            .collector
            .create_proposal(
                proposal(&fixture, "stale"),
                stale_requirement,
                None,
                false,
                100,
            )
            .is_err());

        let proposal = proposal(&fixture, "changed-intent");
        fixture
            .collector
            .create_proposal(
                proposal.clone(),
                fixture.requirement.clone(),
                None,
                false,
                100,
            )
            .unwrap();
        let mut changed = token(&proposal, &fixture.alice, "changed-token");
        changed.governed_intent_hash = sha256_hex(b"different-intent");
        assert!(fixture
            .collector
            .submit_token("changed-intent", changed, 110)
            .is_err());
        fixture.collector.cancel("changed-intent", 111).unwrap();
        assert!(fixture
            .collector
            .submit_token(
                "changed-intent",
                token(&proposal, &fixture.alice, "late-token"),
                112,
            )
            .is_err());
    }

    // Token expiry is bounded above by the proposal deadline but not below, so a
    // set that was quorate at submission can hold expired tokens by delivery time
    // while the proposal itself is still valid.
    #[test]
    fn ready_proposal_accepts_replacement_for_an_expired_token() {
        let fixture = fixture();
        let proposal = proposal(&fixture, "expiring");
        fixture
            .collector
            .create_proposal(
                proposal.clone(),
                fixture.requirement.clone(),
                None,
                false,
                100,
            )
            .unwrap();

        fixture
            .collector
            .submit_token(
                "expiring",
                token_expiring_at(&proposal, &fixture.alice, "token-alice", 120),
                110,
            )
            .unwrap();
        let ready = fixture
            .collector
            .submit_token(
                "expiring",
                token_expiring_at(&proposal, &fixture.bob, "token-bob", 199),
                110,
            )
            .unwrap();
        assert_eq!(ready.state, ThresholdApprovalCollectorState::Ready);

        // The proposal deadline is 200, so only the tokens have lapsed here.
        let expired = fixture.collector.deliver("expiring", 150).unwrap_err();
        assert!(
            expired
                .to_string()
                .contains("quorum is no longer satisfied"),
            "delivery must reject lapsed tokens; got: {expired}"
        );
        let stored = fixture.collector.get_proposal("expiring").unwrap().unwrap();
        assert_eq!(stored.state, ThresholdApprovalCollectorState::Ready);

        let refreshed = fixture
            .collector
            .submit_token(
                "expiring",
                token_expiring_at(&proposal, &fixture.alice, "token-alice-fresh", 199),
                150,
            )
            .unwrap();
        assert_eq!(refreshed.state, ThresholdApprovalCollectorState::Ready);
        assert_eq!(refreshed.tokens.len(), 2);
        assert!(refreshed
            .tokens
            .iter()
            .any(|token| token.id == "token-alice-fresh"));
        assert!(!refreshed
            .tokens
            .iter()
            .any(|token| token.id == "token-alice"));

        let delivered = fixture.collector.deliver("expiring", 151).unwrap();
        assert_eq!(delivered.tokens.len(), 2);
        assert!(delivered
            .tokens
            .iter()
            .any(|token| token.id == "token-alice-fresh"));
    }
}
