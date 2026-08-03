CREATE TABLE IF NOT EXISTS challenges (
    challenge_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(challenge_id) BETWEEN 1 AND 512),
    finding_id TEXT NOT NULL
        CHECK (length(finding_id) = 64 AND finding_id NOT GLOB '*[^0-9a-f]*'),
    listing_id TEXT NOT NULL CHECK (length(listing_id) BETWEEN 1 AND 512),
    challenge_envelope_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(challenge_envelope_sha256) = 64
        AND challenge_envelope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    authorization_branch TEXT NOT NULL CHECK (
        authorization_branch IN ('buyer_submission', 'venue_audit')
    ),
    evidence_class TEXT NOT NULL CHECK (
        evidence_class IN (
            'digest_mismatch', 'evidence_invalid', 'replay_contradiction'
        )
    ),
    challenger_hex TEXT CHECK (
        challenger_hex IS NULL
        OR (
            length(challenger_hex) = 64
            AND challenger_hex NOT GLOB '*[^0-9a-f]*'
        )
    ),
    state TEXT NOT NULL CHECK (
        state IN (
            'submitted', 'evaluating', 'rejected', 'indeterminate_retryable',
            'indeterminate_closed', 'upheld'
        )
    ),
    retry_count INTEGER NOT NULL CHECK (retry_count >= 0),
    retry_deadline INTEGER CHECK (retry_deadline IS NULL OR retry_deadline > 0),
    outcome_envelope_sha256 TEXT CHECK (
        outcome_envelope_sha256 IS NULL
        OR (
            length(outcome_envelope_sha256) = 64
            AND outcome_envelope_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    submitted_at INTEGER NOT NULL CHECK (submitted_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= submitted_at),
    -- A challenger is exactly what tells the two authorization branches
    -- apart: a buyer submission names one, a venue audit names none.
    CHECK (
        (authorization_branch = 'buyer_submission') = (challenger_hex IS NOT NULL)
    ),
    -- A retry deadline exists exactly when a retry was granted.
    CHECK ((retry_deadline IS NOT NULL) = (retry_count > 0))
);

CREATE INDEX IF NOT EXISTS challenges_finding
    ON challenges(finding_id, listing_id, challenge_id);

CREATE INDEX IF NOT EXISTS challenges_state
    ON challenges(state, challenge_id);

CREATE TRIGGER IF NOT EXISTS challenges_immutable_identity
BEFORE UPDATE ON challenges
WHEN NEW.challenge_id <> OLD.challenge_id
  OR NEW.finding_id <> OLD.finding_id
  OR NEW.listing_id <> OLD.listing_id
  OR NEW.challenge_envelope_sha256 <> OLD.challenge_envelope_sha256
  OR NEW.authorization_branch <> OLD.authorization_branch
  OR NEW.evidence_class <> OLD.evidence_class
  OR NEW.challenger_hex IS NOT OLD.challenger_hex
  OR NEW.submitted_at <> OLD.submitted_at
BEGIN
    SELECT RAISE(ABORT, 'finding challenge identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS challenges_terminal_immutable
BEFORE UPDATE ON challenges
WHEN OLD.state IN ('rejected', 'indeterminate_closed', 'upheld')
BEGIN
    SELECT RAISE(ABORT, 'terminal finding challenge is immutable');
END;

CREATE TRIGGER IF NOT EXISTS challenges_lifecycle
BEFORE UPDATE OF state ON challenges
WHEN NOT (
    (OLD.state = 'submitted' AND NEW.state IN ('evaluating', 'indeterminate_closed'))
    OR (OLD.state = 'evaluating' AND NEW.state IN (
        'rejected', 'indeterminate_retryable', 'indeterminate_closed', 'upheld'
    ))
    OR (OLD.state = 'indeterminate_retryable'
        AND NEW.state IN ('evaluating', 'indeterminate_closed'))
)
BEGIN
    SELECT RAISE(ABORT, 'invalid finding challenge lifecycle');
END;

CREATE TRIGGER IF NOT EXISTS challenges_retry_monotonic
BEFORE UPDATE ON challenges
WHEN NEW.retry_count < OLD.retry_count
  OR NEW.retry_count > OLD.retry_count + 1
BEGIN
    SELECT RAISE(ABORT, 'finding challenge retry count advances by at most one');
END;

CREATE TRIGGER IF NOT EXISTS challenges_no_delete
BEFORE DELETE ON challenges
BEGIN
    SELECT RAISE(ABORT, 'finding challenge must be retained');
END;

CREATE TABLE IF NOT EXISTS dispute_lock_reservations (
    lock_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(lock_id) BETWEEN 1 AND 512),
    challenge_id TEXT NOT NULL UNIQUE REFERENCES challenges(challenge_id),
    owner_hex TEXT NOT NULL
        CHECK (length(owner_hex) = 64 AND owner_hex NOT GLOB '*[^0-9a-f]*'),
    schedule_envelope_sha256 TEXT NOT NULL CHECK (
        length(schedule_envelope_sha256) = 64
        AND schedule_envelope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    amount_units INTEGER NOT NULL CHECK (amount_units > 0),
    currency TEXT NOT NULL
        CHECK (length(currency) = 3 AND currency NOT GLOB '*[^A-Z]*'),
    pool_principal_id TEXT NOT NULL
        CHECK (length(pool_principal_id) BETWEEN 1 AND 512),
    pool_rail_destination TEXT NOT NULL
        CHECK (length(pool_rail_destination) BETWEEN 1 AND 512),
    pool_authority_epoch INTEGER NOT NULL CHECK (pool_authority_epoch > 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > 0),
    locked_at INTEGER NOT NULL CHECK (locked_at > 0),
    reserved_at INTEGER NOT NULL CHECK (reserved_at > 0)
);

CREATE TRIGGER IF NOT EXISTS dispute_lock_reservations_immutable
BEFORE UPDATE ON dispute_lock_reservations
BEGIN
    SELECT RAISE(ABORT, 'dispute lock reservation is immutable');
END;

CREATE TRIGGER IF NOT EXISTS dispute_lock_reservations_no_delete
BEFORE DELETE ON dispute_lock_reservations
BEGIN
    SELECT RAISE(ABORT, 'dispute lock reservation must be retained');
END;

CREATE TABLE IF NOT EXISTS dispute_locks (
    lock_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(lock_id) BETWEEN 1 AND 512),
    challenge_id TEXT NOT NULL UNIQUE REFERENCES challenges(challenge_id),
    owner_hex TEXT NOT NULL
        CHECK (length(owner_hex) = 64 AND owner_hex NOT GLOB '*[^0-9a-f]*'),
    bond_class TEXT NOT NULL CHECK (bond_class = 'dispute'),
    schedule_envelope_sha256 TEXT NOT NULL CHECK (
        length(schedule_envelope_sha256) = 64
        AND schedule_envelope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    amount_units INTEGER NOT NULL CHECK (amount_units > 0),
    currency TEXT NOT NULL
        CHECK (length(currency) = 3 AND currency NOT GLOB '*[^A-Z]*'),
    pool_principal_id TEXT NOT NULL
        CHECK (length(pool_principal_id) BETWEEN 1 AND 512),
    pool_rail_destination TEXT NOT NULL
        CHECK (length(pool_rail_destination) BETWEEN 1 AND 512),
    pool_authority_epoch INTEGER NOT NULL CHECK (pool_authority_epoch > 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > 0),
    state TEXT NOT NULL CHECK (state IN ('locked', 'returned', 'forfeited')),
    locked_at INTEGER NOT NULL CHECK (locked_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= locked_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS dispute_locks_owner_challenge
    ON dispute_locks(owner_hex, challenge_id);

CREATE TRIGGER IF NOT EXISTS dispute_locks_immutable_identity
BEFORE UPDATE ON dispute_locks
WHEN NEW.lock_id <> OLD.lock_id
  OR NEW.challenge_id <> OLD.challenge_id
  OR NEW.owner_hex <> OLD.owner_hex
  OR NEW.bond_class <> OLD.bond_class
  OR NEW.schedule_envelope_sha256 <> OLD.schedule_envelope_sha256
  OR NEW.amount_units <> OLD.amount_units
  OR NEW.currency <> OLD.currency
  OR NEW.pool_principal_id <> OLD.pool_principal_id
  OR NEW.pool_rail_destination <> OLD.pool_rail_destination
  OR NEW.pool_authority_epoch <> OLD.pool_authority_epoch
  OR NEW.expires_at <> OLD.expires_at
  OR NEW.locked_at <> OLD.locked_at
BEGIN
    SELECT RAISE(ABORT, 'dispute lock identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS dispute_locks_lifecycle
BEFORE UPDATE OF state ON dispute_locks
WHEN NOT (OLD.state = 'locked' AND NEW.state IN ('returned', 'forfeited'))
BEGIN
    SELECT RAISE(ABORT, 'dispute lock is disposed exactly once');
END;

CREATE TRIGGER IF NOT EXISTS dispute_locks_no_delete
BEFORE DELETE ON dispute_locks
BEGIN
    SELECT RAISE(ABORT, 'dispute lock must be retained');
END;

CREATE TABLE IF NOT EXISTS liability_heads (
    liability_key TEXT NOT NULL PRIMARY KEY CHECK (
        length(liability_key) = 64 AND liability_key NOT GLOB '*[^0-9a-f]*'
    ),
    defect_key TEXT NOT NULL
        CHECK (length(defect_key) = 64 AND defect_key NOT GLOB '*[^0-9a-f]*'),
    finding_id TEXT NOT NULL
        CHECK (length(finding_id) = 64 AND finding_id NOT GLOB '*[^0-9a-f]*'),
    listing_id TEXT NOT NULL CHECK (length(listing_id) BETWEEN 1 AND 512),
    allocation_id TEXT NOT NULL CHECK (
        length(allocation_id) = 64 AND allocation_id NOT GLOB '*[^0-9a-f]*'
    ),
    seller_hex TEXT NOT NULL CHECK (
        length(seller_hex) = 64 AND seller_hex NOT GLOB '*[^0-9a-f]*'
    ),
    venue_id TEXT NOT NULL CHECK (length(venue_id) BETWEEN 1 AND 512),
    chain_id TEXT NOT NULL CHECK (length(chain_id) BETWEEN 1 AND 512),
    vault_contract TEXT NOT NULL
        CHECK (length(vault_contract) BETWEEN 1 AND 512),
    vault_id TEXT NOT NULL CHECK (length(vault_id) BETWEEN 1 AND 512),
    state TEXT NOT NULL CHECK (
        state IN (
            'open', 'upheld_pending_claims', 'pending_appeal', 'finalizing',
            'settled', 'reversed_before_impairment'
        )
    ),
    upheld_challenge_id TEXT REFERENCES challenges(challenge_id),
    purchase_cutoff_slot INTEGER
        CHECK (purchase_cutoff_slot IS NULL OR purchase_cutoff_slot >= 0),
    -- Trusted time at which the seller-signed claim window closes. No
    -- accounting may be sealed before it, so harmed buyers and omission
    -- proofs keep the whole window they were promised.
    claim_deadline INTEGER CHECK (claim_deadline IS NULL OR claim_deadline > 0),
    -- The appeal window is derived from the seller-signed terms when the
    -- head enters pending_appeal, then frozen for the rest of the lifecycle.
    appeal_window_opened_at INTEGER CHECK (
        appeal_window_opened_at IS NULL OR appeal_window_opened_at > 0
    ),
    appeal_deadline INTEGER CHECK (
        appeal_deadline IS NULL OR appeal_deadline > 0
    ),
    appeal_terms_envelope_sha256 TEXT CHECK (
        appeal_terms_envelope_sha256 IS NULL
        OR (length(appeal_terms_envelope_sha256) = 64
            AND appeal_terms_envelope_sha256 NOT GLOB '*[^0-9a-f]*')
    ),
    snapshot_digest TEXT CHECK (
        snapshot_digest IS NULL
        OR (length(snapshot_digest) = 64
            AND snapshot_digest NOT GLOB '*[^0-9a-f]*')
    ),
    allocation_digest TEXT CHECK (
        allocation_digest IS NULL
        OR (length(allocation_digest) = 64
            AND allocation_digest NOT GLOB '*[^0-9a-f]*')
    ),
    publication_pending INTEGER NOT NULL
        CHECK (publication_pending IN (0, 1)),
    quarantined INTEGER NOT NULL CHECK (quarantined IN (0, 1)),
    opened_at INTEGER NOT NULL CHECK (opened_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= opened_at),
    -- An open liability names no upheld challenge, and every state past
    -- open names exactly the one that carried it there.
    CHECK ((state = 'open') = (upheld_challenge_id IS NULL)),
    -- The cutoff and the claim deadline freeze in the same transaction
    -- that records the upheld challenge, so none exists without the rest.
    CHECK ((upheld_challenge_id IS NULL) = (purchase_cutoff_slot IS NULL)),
    CHECK ((upheld_challenge_id IS NULL) = (claim_deadline IS NULL)),
    -- All three appeal-window commitments appear together exactly when the
    -- liability reaches the appeal edge or a later state.
    CHECK ((appeal_window_opened_at IS NULL) = (appeal_deadline IS NULL)),
    CHECK ((appeal_window_opened_at IS NULL)
           = (appeal_terms_envelope_sha256 IS NULL)),
    CHECK (appeal_deadline IS NULL
           OR appeal_deadline > appeal_window_opened_at),
    CHECK ((appeal_deadline IS NOT NULL) = (state IN (
        'pending_appeal', 'finalizing', 'settled',
        'reversed_before_impairment'
    ))),
    -- Both snapshot commitments are sealed together or not at all.
    CHECK ((snapshot_digest IS NULL) = (allocation_digest IS NULL))
);

CREATE INDEX IF NOT EXISTS liability_heads_defect
    ON liability_heads(defect_key, liability_key);

CREATE INDEX IF NOT EXISTS liability_heads_listing
    ON liability_heads(finding_id, listing_id, liability_key);

CREATE TRIGGER IF NOT EXISTS liability_heads_immutable_identity
BEFORE UPDATE ON liability_heads
WHEN NEW.liability_key <> OLD.liability_key
  OR NEW.defect_key <> OLD.defect_key
  OR NEW.finding_id <> OLD.finding_id
  OR NEW.listing_id <> OLD.listing_id
  OR NEW.allocation_id <> OLD.allocation_id
  OR NEW.seller_hex <> OLD.seller_hex
  OR NEW.venue_id <> OLD.venue_id
  OR NEW.chain_id <> OLD.chain_id
  OR NEW.vault_contract <> OLD.vault_contract
  OR NEW.vault_id <> OLD.vault_id
  OR NEW.opened_at <> OLD.opened_at
BEGIN
    SELECT RAISE(ABORT, 'liability head identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS liability_heads_frozen_commitments
BEFORE UPDATE ON liability_heads
WHEN (OLD.upheld_challenge_id IS NOT NULL
      AND NEW.upheld_challenge_id IS NOT OLD.upheld_challenge_id)
  OR (OLD.purchase_cutoff_slot IS NOT NULL
      AND NEW.purchase_cutoff_slot IS NOT OLD.purchase_cutoff_slot)
  OR (OLD.claim_deadline IS NOT NULL
      AND NEW.claim_deadline IS NOT OLD.claim_deadline)
  OR (OLD.appeal_window_opened_at IS NOT NULL
      AND NEW.appeal_window_opened_at IS NOT OLD.appeal_window_opened_at)
  OR (OLD.appeal_deadline IS NOT NULL
      AND NEW.appeal_deadline IS NOT OLD.appeal_deadline)
  OR (OLD.appeal_terms_envelope_sha256 IS NOT NULL
      AND NEW.appeal_terms_envelope_sha256
          IS NOT OLD.appeal_terms_envelope_sha256)
  OR (OLD.snapshot_digest IS NOT NULL
      AND NEW.snapshot_digest IS NOT OLD.snapshot_digest)
  OR (OLD.allocation_digest IS NOT NULL
      AND NEW.allocation_digest IS NOT OLD.allocation_digest)
BEGIN
    SELECT RAISE(ABORT, 'liability head commitments are frozen once written');
END;

CREATE TRIGGER IF NOT EXISTS liability_heads_terminal_immutable
BEFORE UPDATE ON liability_heads
WHEN OLD.state IN ('settled', 'reversed_before_impairment')
BEGIN
    SELECT RAISE(ABORT, 'terminal liability head is immutable');
END;

CREATE TRIGGER IF NOT EXISTS liability_heads_lifecycle
BEFORE UPDATE OF state ON liability_heads
WHEN NOT (
    (OLD.state = 'open' AND NEW.state = 'upheld_pending_claims')
    OR (OLD.state = 'upheld_pending_claims' AND NEW.state = 'pending_appeal')
    OR (OLD.state = 'pending_appeal'
        AND NEW.state IN ('finalizing', 'reversed_before_impairment'))
    OR (OLD.state = 'finalizing' AND NEW.state = 'settled')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid liability head lifecycle');
END;

CREATE TRIGGER IF NOT EXISTS liability_heads_no_delete
BEFORE DELETE ON liability_heads
BEGIN
    SELECT RAISE(ABORT, 'liability head must be retained');
END;

CREATE TABLE IF NOT EXISTS governance_case_index (
    case_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(case_id) BETWEEN 1 AND 512),
    finding_id TEXT NOT NULL
        CHECK (length(finding_id) = 64 AND finding_id NOT GLOB '*[^0-9a-f]*'),
    listing_id TEXT NOT NULL CHECK (length(listing_id) BETWEEN 1 AND 512),
    liability_key TEXT NOT NULL REFERENCES liability_heads(liability_key),
    case_kind TEXT NOT NULL CHECK (case_kind IN ('sanction', 'appeal')),
    case_state TEXT NOT NULL CHECK (length(case_state) BETWEEN 1 AND 64),
    appeal_of_case_id TEXT REFERENCES governance_case_index(case_id),
    supersedes_case_id TEXT REFERENCES governance_case_index(case_id),
    superseded_by_case_id TEXT REFERENCES governance_case_index(case_id),
    recorded_at INTEGER NOT NULL CHECK (recorded_at > 0),
    -- Only an appeal appeals a prior case.
    CHECK (case_kind = 'appeal' OR appeal_of_case_id IS NULL),
    CHECK (appeal_of_case_id IS NULL OR appeal_of_case_id <> case_id),
    CHECK (supersedes_case_id IS NULL OR supersedes_case_id <> case_id),
    CHECK (superseded_by_case_id IS NULL OR superseded_by_case_id <> case_id)
);

CREATE INDEX IF NOT EXISTS governance_case_index_liability
    ON governance_case_index(liability_key, recorded_at, case_id);

CREATE UNIQUE INDEX IF NOT EXISTS governance_case_index_supersedes
    ON governance_case_index(supersedes_case_id)
    WHERE supersedes_case_id IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS governance_case_index_immutable_identity
BEFORE UPDATE ON governance_case_index
WHEN NEW.case_id <> OLD.case_id
  OR NEW.finding_id <> OLD.finding_id
  OR NEW.listing_id <> OLD.listing_id
  OR NEW.liability_key <> OLD.liability_key
  OR NEW.case_kind <> OLD.case_kind
  OR NEW.case_state <> OLD.case_state
  OR NEW.appeal_of_case_id IS NOT OLD.appeal_of_case_id
  OR NEW.supersedes_case_id IS NOT OLD.supersedes_case_id
  OR NEW.recorded_at <> OLD.recorded_at
BEGIN
    SELECT RAISE(ABORT, 'governance case identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS governance_case_index_supersede_once
BEFORE UPDATE OF superseded_by_case_id ON governance_case_index
WHEN OLD.superseded_by_case_id IS NOT NULL
  OR NEW.superseded_by_case_id IS NULL
BEGIN
    SELECT RAISE(ABORT, 'a governance case is superseded exactly once');
END;

CREATE TRIGGER IF NOT EXISTS governance_case_index_no_delete
BEFORE DELETE ON governance_case_index
BEGIN
    SELECT RAISE(ABORT, 'governance case must be retained');
END;

CREATE TABLE IF NOT EXISTS claim_snapshots (
    liability_key TEXT NOT NULL PRIMARY KEY
        REFERENCES liability_heads(liability_key),
    cutoff_slot INTEGER NOT NULL CHECK (cutoff_slot >= 0),
    snapshot_digest TEXT NOT NULL CHECK (
        length(snapshot_digest) = 64 AND snapshot_digest NOT GLOB '*[^0-9a-f]*'
    ),
    allocation_digest TEXT NOT NULL CHECK (
        length(allocation_digest) = 64
        AND allocation_digest NOT GLOB '*[^0-9a-f]*'
    ),
    total_realized_spend_units INTEGER NOT NULL
        CHECK (total_realized_spend_units >= 0),
    currency TEXT NOT NULL
        CHECK (length(currency) = 3 AND currency NOT GLOB '*[^A-Z]*'),
    buyer_pool_units INTEGER NOT NULL CHECK (buyer_pool_units >= 0),
    community_fund_units INTEGER NOT NULL CHECK (community_fund_units >= 0),
    sealed_at INTEGER NOT NULL CHECK (sealed_at > 0),
    -- The buyer pool is capped by verified realized spend, so a snapshot
    -- can never promise harmed buyers more than they provably spent.
    CHECK (buyer_pool_units <= total_realized_spend_units)
);

CREATE TRIGGER IF NOT EXISTS claim_snapshots_immutable
BEFORE UPDATE ON claim_snapshots
BEGIN
    SELECT RAISE(ABORT, 'sealed claim snapshot is immutable');
END;

CREATE TRIGGER IF NOT EXISTS claim_snapshots_no_delete
BEFORE DELETE ON claim_snapshots
BEGIN
    SELECT RAISE(ABORT, 'sealed claim snapshot must be retained');
END;

CREATE TABLE IF NOT EXISTS effect_intents (
    intent_key TEXT NOT NULL PRIMARY KEY
        CHECK (length(intent_key) = 64 AND intent_key NOT GLOB '*[^0-9a-f]*'),
    liability_key TEXT REFERENCES liability_heads(liability_key),
    kind TEXT NOT NULL CHECK (
        kind IN (
            'seller_impair', 'challenge_bond', 'fee', 'root_intent',
            'retraction'
        )
    ),
    intent_digest TEXT NOT NULL CHECK (
        length(intent_digest) = 64 AND intent_digest NOT GLOB '*[^0-9a-f]*'
    ),
    settlement_required INTEGER NOT NULL CHECK (settlement_required IN (0, 1)),
    state TEXT NOT NULL CHECK (
        state IN ('pending', 'dispatched', 'confirmed', 'failed', 'quarantined')
    ),
    attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0),
    recorded_at INTEGER NOT NULL CHECK (recorded_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= recorded_at)
);

CREATE INDEX IF NOT EXISTS effect_intents_liability
    ON effect_intents(liability_key, kind, intent_key);

CREATE INDEX IF NOT EXISTS effect_intents_state
    ON effect_intents(state, intent_key);

CREATE TRIGGER IF NOT EXISTS effect_intents_immutable_identity
BEFORE UPDATE ON effect_intents
WHEN NEW.intent_key <> OLD.intent_key
  OR NEW.liability_key IS NOT OLD.liability_key
  OR NEW.kind <> OLD.kind
  OR NEW.intent_digest <> OLD.intent_digest
  OR NEW.settlement_required <> OLD.settlement_required
  OR NEW.recorded_at <> OLD.recorded_at
BEGIN
    SELECT RAISE(ABORT, 'effect intent identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS effect_intents_lifecycle
BEFORE UPDATE OF state ON effect_intents
WHEN NOT (
    (OLD.state = 'pending'
        AND NEW.state IN ('dispatched', 'failed', 'quarantined'))
    OR (OLD.state = 'dispatched'
        AND NEW.state IN ('confirmed', 'failed', 'quarantined'))
    OR (OLD.state = 'failed' AND NEW.state IN ('dispatched', 'quarantined'))
)
BEGIN
    SELECT RAISE(ABORT, 'invalid effect intent lifecycle');
END;

CREATE TRIGGER IF NOT EXISTS effect_intents_attempts_monotonic
BEFORE UPDATE ON effect_intents
WHEN NEW.attempt_count < OLD.attempt_count
  OR NEW.attempt_count > OLD.attempt_count + 1
BEGIN
    SELECT RAISE(ABORT, 'effect intent attempts advance by at most one');
END;

CREATE TRIGGER IF NOT EXISTS effect_intents_no_delete
BEFORE DELETE ON effect_intents
BEGIN
    SELECT RAISE(ABORT, 'effect intent must be retained');
END;

-- Immutable local history for the challenge projection. Every mutation of
-- challenge state, including its composed listing sales block, appends one
-- row here and one exact reference in the authority-wide commit chain.
CREATE TABLE IF NOT EXISTS finding_challenge_projection_commits (
    projection_sequence INTEGER PRIMARY KEY CHECK (projection_sequence > 0),
    mutation_kind TEXT NOT NULL CHECK (mutation_kind = 'finding_challenge_write'),
    snapshot_digest TEXT NOT NULL CHECK (
        length(snapshot_digest) = 64
        AND snapshot_digest NOT GLOB '*[^0-9a-f]*'
    ),
    previous_commit_digest TEXT NOT NULL CHECK (
        length(previous_commit_digest) = 64
        AND previous_commit_digest NOT GLOB '*[^0-9a-f]*'
    ),
    commit_digest TEXT NOT NULL UNIQUE CHECK (
        length(commit_digest) = 64
        AND commit_digest NOT GLOB '*[^0-9a-f]*'
    )
);

CREATE TRIGGER IF NOT EXISTS finding_challenge_projection_commits_immutable
BEFORE UPDATE ON finding_challenge_projection_commits
BEGIN
    SELECT RAISE(ABORT, 'finding challenge projection commit is immutable');
END;

CREATE TRIGGER IF NOT EXISTS finding_challenge_projection_commits_no_delete
BEFORE DELETE ON finding_challenge_projection_commits
BEGIN
    SELECT RAISE(ABORT, 'finding challenge projection commit is immutable');
END;
