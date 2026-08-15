use super::*;

mod state_invariants;

/// Current composite budget schema revision.
const COMPOSITE_SCHEMA_VERSION: i32 = 11;
/// Revision that introduced the composite projection contract, the legacy event
/// lifecycle backfill, and zero-limit denial quota rows.
const COMPOSITE_PROJECTION_SCHEMA_VERSION: i32 = 10;
/// Revision that moved usage history anchors out of the live grant budget rows.
const BUDGET_USAGE_ANCHOR_SCHEMA_VERSION: i32 = 6;

pub(super) fn ensure_composite_budget_schema(
    transaction: &rusqlite::Transaction<'_>,
    on_disk_schema_version: i32,
) -> Result<(), BudgetStoreError> {
    for (table, column, definition) in [
        ("budget_authorization_holds", "operation_id", "TEXT"),
        (
            "budget_authorization_holds",
            "projection_kind",
            "TEXT NOT NULL DEFAULT 'legacy' CHECK (projection_kind IN ('legacy', 'composite_v1'))",
        ),
        (
            "budget_authorization_holds",
            "revocation_set_digest",
            "TEXT CHECK (revocation_set_digest IS NULL OR (length(revocation_set_digest) = 64 AND revocation_set_digest NOT GLOB '*[^0-9a-f]*'))",
        ),
        ("budget_authorization_holds", "expected_quota_count", "INTEGER CHECK (expected_quota_count IS NULL OR expected_quota_count BETWEEN 0 AND 8)"),
        ("budget_authorization_holds", "expected_revocation_count", "INTEGER CHECK (expected_revocation_count IS NULL OR expected_revocation_count BETWEEN 1 AND 256)"),
        ("budget_authorization_holds", "expected_artifact_count", "INTEGER CHECK (expected_artifact_count IS NULL OR expected_artifact_count BETWEEN 0 AND 8)"),
        ("budget_authorization_holds", "has_cumulative_approval", "INTEGER CHECK (has_cumulative_approval IS NULL OR has_cumulative_approval IN (0, 1))"),
        ("budget_authorization_holds", "has_revocation_commit", "INTEGER CHECK (has_revocation_commit IS NULL OR has_revocation_commit IN (0, 1))"),
        (
            "budget_authorization_holds",
            "authorization_outcome",
            "TEXT",
        ),
        ("budget_authorization_holds", "invocation_state", "TEXT"),
        ("budget_authorization_holds", "monetary_state", "TEXT"),
        (
            "budget_authorization_holds",
            "supplemental_verifier_id",
            "TEXT",
        ),
        (
            "budget_authorization_holds",
            "supplemental_verifier_config_digest",
            "TEXT",
        ),
        (
            "budget_authorization_holds",
            "supplemental_artifact_digest",
            "TEXT",
        ),
        (
            "budget_authorization_holds",
            "supplemental_expires_at",
            "INTEGER",
        ),
        (
            "budget_authorization_holds",
            "trusted_capture_time",
            "INTEGER CHECK (trusted_capture_time IS NULL OR trusted_capture_time >= 0)",
        ),
        ("budget_mutation_events", "operation_id", "TEXT"),
        (
            "budget_mutation_events",
            "projection_kind",
            "TEXT NOT NULL DEFAULT 'legacy' CHECK (projection_kind IN ('legacy', 'composite_v1'))",
        ),
        (
            "budget_mutation_events",
            "revocation_set_digest",
            "TEXT CHECK (revocation_set_digest IS NULL OR (length(revocation_set_digest) = 64 AND revocation_set_digest NOT GLOB '*[^0-9a-f]*'))",
        ),
        ("budget_mutation_events", "expected_quota_count", "INTEGER CHECK (expected_quota_count IS NULL OR expected_quota_count BETWEEN 0 AND 8)"),
        ("budget_mutation_events", "expected_revocation_count", "INTEGER CHECK (expected_revocation_count IS NULL OR expected_revocation_count BETWEEN 1 AND 256)"),
        ("budget_mutation_events", "expected_artifact_count", "INTEGER CHECK (expected_artifact_count IS NULL OR expected_artifact_count BETWEEN 0 AND 8)"),
        ("budget_mutation_events", "has_cumulative_approval", "INTEGER CHECK (has_cumulative_approval IS NULL OR has_cumulative_approval IN (0, 1))"),
        ("budget_mutation_events", "has_revocation_commit", "INTEGER CHECK (has_revocation_commit IS NULL OR has_revocation_commit IN (0, 1))"),
        ("budget_mutation_events", "authorization_outcome", "TEXT"),
        ("budget_mutation_events", "invocation_state_before", "TEXT"),
        ("budget_mutation_events", "invocation_state_after", "TEXT"),
        ("budget_mutation_events", "monetary_state_before", "TEXT"),
        ("budget_mutation_events", "monetary_state_after", "TEXT"),
        (
            "budget_mutation_events",
            "cumulative_approval_set_digest",
            "TEXT CHECK (
                cumulative_approval_set_digest IS NULL
                OR (
                    length(cumulative_approval_set_digest) = 64
                    AND cumulative_approval_set_digest NOT GLOB '*[^0-9a-f]*'
                )
            )",
        ),
        ("budget_mutation_events", "supplemental_verifier_id", "TEXT"),
        (
            "budget_mutation_events",
            "supplemental_verifier_config_digest",
            "TEXT",
        ),
        (
            "budget_mutation_events",
            "supplemental_artifact_digest",
            "TEXT",
        ),
        (
            "budget_mutation_events",
            "supplemental_expires_at",
            "INTEGER",
        ),
        (
            "budget_mutation_events",
            "invocation_quotas_explicit",
            "INTEGER",
        ),
        ("budget_mutation_events", "trusted_time", "INTEGER"),
        (
            "budget_mutation_events",
            "expected_cumulative_state",
            "TEXT",
        ),
    ] {
        ensure_column(transaction, table, column, definition)?;
    }

    transaction.execute_batch(
        r#"
        CREATE UNIQUE INDEX IF NOT EXISTS idx_budget_holds_operation
            ON budget_authorization_holds(operation_id)
            WHERE operation_id IS NOT NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS idx_budget_holds_operation_hold
            ON budget_authorization_holds(operation_id, hold_id);

        CREATE TABLE IF NOT EXISTS payment_journal (
            operation_id TEXT PRIMARY KEY CHECK (operation_id <> '' AND length(operation_id) <= 512),
            journal_version INTEGER NOT NULL CHECK (
                journal_version BETWEEN 1 AND 9007199254740991
            ),
            request_namespace_digest TEXT NOT NULL CHECK (
                length(request_namespace_digest) = 64
                AND request_namespace_digest NOT GLOB '*[^0-9a-f]*'
            ),
            request_id TEXT NOT NULL CHECK (request_id <> '' AND length(request_id) <= 512),
            capability_id TEXT NOT NULL CHECK (capability_id <> '' AND length(capability_id) <= 512),
            grant_index INTEGER NOT NULL CHECK (grant_index BETWEEN 0 AND 4294967295),
            hold_id TEXT NOT NULL UNIQUE CHECK (hold_id <> '' AND length(hold_id) <= 512),
            rail TEXT NOT NULL CHECK (
                rail <> '' AND rail <> 'unspecified' AND length(rail) <= 512
            ),
            rail_mode TEXT NOT NULL CHECK (rail_mode IN ('reversible_hold', 'prepaid_final')),
            authorization_id TEXT CHECK (
                authorization_id IS NULL
                OR (authorization_id <> '' AND length(authorization_id) <= 512)
            ),
            transaction_id TEXT CHECK (
                transaction_id IS NULL
                OR (transaction_id <> '' AND length(transaction_id) <= 512)
            ),
            amount_units INTEGER NOT NULL CHECK (
                amount_units BETWEEN 1 AND 9007199254740991
            ),
            settle_action TEXT CHECK (settle_action IN ('capture', 'release')),
            settle_amount_units INTEGER CHECK (
                settle_amount_units BETWEEN 1 AND amount_units
            ),
            release_authority_kind TEXT CHECK (
                release_authority_kind IN (
                    'pre_dispatch_no_effect',
                    'transport_not_accepted',
                    'contractual_zero_charge'
                )
            ),
            release_authority_evidence_id TEXT CHECK (
                release_authority_evidence_id IS NULL
                OR (release_authority_evidence_id <> ''
                    AND length(release_authority_evidence_id) <= 512)
            ),
            release_authority_evidence_digest TEXT CHECK (
                release_authority_evidence_digest IS NULL
                OR (length(release_authority_evidence_digest) = 64
                    AND release_authority_evidence_digest NOT GLOB '*[^0-9a-f]*')
            ),
            release_authority_operation_version INTEGER CHECK (
                release_authority_operation_version BETWEEN 1 AND 9007199254740991
            ),
            currency TEXT NOT NULL CHECK (
                length(currency) = 3 AND currency NOT GLOB '*[^A-Z]*'
            ),
            state TEXT NOT NULL CHECK (state IN (
                'hold_placed', 'authorized', 'settling', 'settled', 'closed',
                'reconcile_failed'
            )),
            created_at_unix_ms INTEGER NOT NULL CHECK (
                created_at_unix_ms BETWEEN 1 AND 9007199254740991
            ),
            updated_at_unix_ms INTEGER NOT NULL CHECK (
                updated_at_unix_ms BETWEEN created_at_unix_ms AND 9007199254740991
            ),
            FOREIGN KEY (hold_id) REFERENCES budget_authorization_holds(hold_id),
            CHECK (
                (state = 'hold_placed'
                 AND authorization_id IS NULL AND transaction_id IS NULL
                 AND settle_action IS NULL AND settle_amount_units IS NULL
                 AND release_authority_kind IS NULL
                 AND release_authority_evidence_id IS NULL
                 AND release_authority_evidence_digest IS NULL
                 AND release_authority_operation_version IS NULL)
                OR
                (state = 'authorized' AND rail_mode = 'reversible_hold'
                 AND authorization_id IS NOT NULL AND transaction_id IS NULL
                 AND settle_action IS NULL AND settle_amount_units IS NULL
                 AND release_authority_kind IS NULL
                 AND release_authority_evidence_id IS NULL
                 AND release_authority_evidence_digest IS NULL
                 AND release_authority_operation_version IS NULL)
                OR
                (state = 'settling' AND rail_mode = 'reversible_hold'
                 AND authorization_id IS NOT NULL AND transaction_id IS NULL
                 AND (
                    (settle_action = 'capture' AND settle_amount_units IS NOT NULL
                     AND release_authority_kind IS NULL
                     AND release_authority_evidence_id IS NULL
                     AND release_authority_evidence_digest IS NULL
                     AND release_authority_operation_version IS NULL)
                    OR
                    (settle_action = 'release' AND settle_amount_units IS NULL
                     AND release_authority_kind IS NOT NULL
                     AND release_authority_evidence_id IS NOT NULL
                     AND release_authority_evidence_digest IS NOT NULL
                     AND release_authority_operation_version IS NOT NULL)
                 ))
                OR
                (state IN ('settled', 'closed') AND authorization_id IS NOT NULL
                 AND (
                    (rail_mode = 'prepaid_final' AND transaction_id IS NULL
                     AND settle_action IS NULL AND settle_amount_units IS NULL
                     AND release_authority_kind IS NULL
                     AND release_authority_evidence_id IS NULL
                     AND release_authority_evidence_digest IS NULL
                     AND release_authority_operation_version IS NULL)
                    OR
                    (rail_mode = 'reversible_hold' AND transaction_id IS NOT NULL
                     AND (
                        (settle_action = 'capture' AND settle_amount_units IS NOT NULL
                         AND release_authority_kind IS NULL
                         AND release_authority_evidence_id IS NULL
                         AND release_authority_evidence_digest IS NULL
                         AND release_authority_operation_version IS NULL)
                        OR
                        (settle_action = 'release' AND settle_amount_units IS NULL
                         AND release_authority_kind IS NOT NULL
                         AND release_authority_evidence_id IS NOT NULL
                         AND release_authority_evidence_digest IS NOT NULL
                         AND release_authority_operation_version IS NOT NULL)
                     ))
                 ))
                OR
                (state = 'closed'
                 AND authorization_id IS NULL AND transaction_id IS NULL
                 AND settle_action IS NULL AND settle_amount_units IS NULL
                 AND release_authority_kind IS NULL
                 AND release_authority_evidence_id IS NULL
                 AND release_authority_evidence_digest IS NULL
                 AND release_authority_operation_version IS NULL)
                OR state = 'reconcile_failed'
            )
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_journal_request
            ON payment_journal(request_namespace_digest, request_id);
        CREATE INDEX IF NOT EXISTS idx_payment_journal_state
            ON payment_journal(state, updated_at_unix_ms);

        CREATE TABLE IF NOT EXISTS payment_release_evidence (
            operation_id TEXT PRIMARY KEY,
            evidence_id TEXT NOT NULL UNIQUE CHECK (
                evidence_id <> '' AND length(evidence_id) <= 512
            ),
            evidence_kind TEXT NOT NULL CHECK (evidence_kind IN (
                'pre_dispatch_no_effect',
                'transport_not_accepted',
                'contractual_zero_charge'
            )),
            operation_version INTEGER NOT NULL CHECK (
                operation_version BETWEEN 1 AND 9007199254740991
            ),
            canonical_bundle BLOB NOT NULL CHECK (
                length(canonical_bundle) BETWEEN 1 AND 1048576
            ),
            bundle_digest TEXT NOT NULL CHECK (
                length(bundle_digest) = 64
                AND bundle_digest NOT GLOB '*[^0-9a-f]*'
            ),
            created_at_unix_ms INTEGER NOT NULL CHECK (
                created_at_unix_ms BETWEEN 1 AND 9007199254740991
            ),
            FOREIGN KEY (operation_id) REFERENCES payment_journal(operation_id)
        );

        CREATE TRIGGER IF NOT EXISTS payment_journal_identity_immutable
        BEFORE UPDATE OF operation_id, request_namespace_digest, request_id,
                         capability_id, grant_index, hold_id, rail, rail_mode,
                         amount_units, currency, created_at_unix_ms
        ON payment_journal
        BEGIN
            SELECT RAISE(ABORT, 'payment journal identity is immutable');
        END;

        CREATE TRIGGER IF NOT EXISTS payment_journal_no_delete
        BEFORE DELETE ON payment_journal
        BEGIN
            SELECT RAISE(ABORT, 'payment journal is append-preserving');
        END;

        CREATE TRIGGER IF NOT EXISTS payment_release_evidence_immutable
        BEFORE UPDATE ON payment_release_evidence
        BEGIN
            SELECT RAISE(ABORT, 'payment release evidence is immutable');
        END;

        CREATE TRIGGER IF NOT EXISTS payment_release_evidence_no_delete
        BEFORE DELETE ON payment_release_evidence
        BEGIN
            SELECT RAISE(ABORT, 'payment release evidence is immutable');
        END;

        CREATE TABLE IF NOT EXISTS budget_invocation_quotas (
            profile TEXT NOT NULL,
            owner_id TEXT NOT NULL CHECK (owner_id <> ''),
            grant_index INTEGER NOT NULL,
            max_invocations INTEGER NOT NULL CHECK (max_invocations > 0),
            reserved_invocations INTEGER NOT NULL DEFAULT 0
                CHECK (reserved_invocations >= 0 AND reserved_invocations <= max_invocations),
            captured_invocations INTEGER NOT NULL DEFAULT 0
                CHECK (captured_invocations >= 0
                       AND captured_invocations <= max_invocations - reserved_invocations),
            version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
            PRIMARY KEY (profile, owner_id, grant_index),
            UNIQUE (profile, owner_id, grant_index, max_invocations),
            CHECK (
                (profile = 'chio.grant-invocation.v1' AND grant_index >= 0)
                OR
                (profile IN (
                    'chio.aggregate-capability-invocation.v1',
                    'chio.aggregate-family-invocation.v1',
                    'chio.broker-capability-execution.v1'
                ) AND grant_index = -1)
            )
        );

        CREATE TABLE IF NOT EXISTS budget_hold_quota_members (
            hold_id TEXT NOT NULL,
            profile TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            grant_index INTEGER NOT NULL,
            max_invocations INTEGER NOT NULL,
            PRIMARY KEY (hold_id, profile, owner_id, grant_index),
            FOREIGN KEY (hold_id)
                REFERENCES budget_authorization_holds(hold_id),
            FOREIGN KEY (profile, owner_id, grant_index, max_invocations)
                REFERENCES budget_invocation_quotas(
                    profile, owner_id, grant_index, max_invocations
                )
        );

        CREATE TABLE IF NOT EXISTS budget_event_quota_members (
            event_id TEXT NOT NULL,
            profile TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            grant_index INTEGER NOT NULL,
            max_invocations INTEGER NOT NULL CHECK (max_invocations >= 0),
            reserved_before INTEGER NOT NULL CHECK (reserved_before >= 0),
            captured_before INTEGER NOT NULL CHECK (
                captured_before >= 0 AND reserved_before <= max_invocations
                AND captured_before <= max_invocations - reserved_before
            ),
            reserved_after INTEGER NOT NULL CHECK (reserved_after >= 0),
            captured_after INTEGER NOT NULL CHECK (
                captured_after >= 0 AND reserved_after <= max_invocations
                AND captured_after <= max_invocations - reserved_after
            ),
            PRIMARY KEY (event_id, profile, owner_id, grant_index),
            FOREIGN KEY (event_id) REFERENCES budget_mutation_events(event_id),
            CHECK (owner_id <> ''),
            CHECK (
                (profile = 'chio.grant-invocation.v1' AND grant_index >= 0)
                OR
                (profile IN (
                    'chio.aggregate-capability-invocation.v1',
                    'chio.aggregate-family-invocation.v1',
                    'chio.broker-capability-execution.v1'
                ) AND grant_index = -1)
            )
        );

        CREATE TABLE IF NOT EXISTS budget_hold_revocation_members (
            hold_id TEXT NOT NULL,
            member_index INTEGER NOT NULL CHECK (
                member_index >= 0 AND member_index < 256
            ),
            capability_id TEXT NOT NULL CHECK (
                length(CAST(capability_id AS BLOB)) BETWEEN 1 AND 512
            ),
            PRIMARY KEY (hold_id, member_index),
            UNIQUE (hold_id, capability_id),
            FOREIGN KEY (hold_id)
                REFERENCES budget_authorization_holds(hold_id)
        );

        CREATE TABLE IF NOT EXISTS budget_event_revocation_members (
            event_id TEXT NOT NULL,
            member_index INTEGER NOT NULL CHECK (
                member_index >= 0 AND member_index < 256
            ),
            capability_id TEXT NOT NULL CHECK (
                length(CAST(capability_id AS BLOB)) BETWEEN 1 AND 512
            ),
            PRIMARY KEY (event_id, member_index),
            UNIQUE (event_id, capability_id),
            FOREIGN KEY (event_id) REFERENCES budget_mutation_events(event_id)
        );

        CREATE TABLE IF NOT EXISTS budget_hold_revocation_commits (
            hold_id TEXT PRIMARY KEY,
            authority_id TEXT NOT NULL CHECK (authority_id <> ''),
            lease_id TEXT NOT NULL CHECK (lease_id <> ''),
            lease_epoch INTEGER NOT NULL CHECK (lease_epoch > 0),
            guarantee_level TEXT NOT NULL CHECK (guarantee_level IN (
                'single_node_atomic', 'ha_linearizable'
            )),
            commit_index INTEGER NOT NULL CHECK (commit_index > 0),
            FOREIGN KEY (hold_id)
                REFERENCES budget_authorization_holds(hold_id)
        );

        CREATE TABLE IF NOT EXISTS budget_event_revocation_commits (
            event_id TEXT PRIMARY KEY,
            authority_id TEXT NOT NULL CHECK (authority_id <> ''),
            lease_id TEXT NOT NULL CHECK (lease_id <> ''),
            lease_epoch INTEGER NOT NULL CHECK (lease_epoch > 0),
            guarantee_level TEXT NOT NULL CHECK (guarantee_level IN (
                'single_node_atomic', 'ha_linearizable'
            )),
            commit_index INTEGER NOT NULL CHECK (commit_index > 0),
            FOREIGN KEY (event_id) REFERENCES budget_mutation_events(event_id)
        );

        CREATE TABLE IF NOT EXISTS budget_hold_authorization_artifacts (
            hold_id TEXT NOT NULL,
            artifact_index INTEGER NOT NULL CHECK (
                artifact_index >= 0 AND artifact_index < 8
            ),
            artifact_digest TEXT NOT NULL CHECK (
                length(artifact_digest) = 64
                AND artifact_digest NOT GLOB '*[^0-9a-f]*'
            ),
            PRIMARY KEY (hold_id, artifact_index),
            UNIQUE (hold_id, artifact_digest),
            FOREIGN KEY (hold_id)
                REFERENCES budget_authorization_holds(hold_id)
        );

        CREATE TABLE IF NOT EXISTS budget_event_authorization_artifacts (
            event_id TEXT NOT NULL,
            artifact_index INTEGER NOT NULL CHECK (
                artifact_index >= 0 AND artifact_index < 8
            ),
            artifact_digest TEXT NOT NULL CHECK (
                length(artifact_digest) = 64
                AND artifact_digest NOT GLOB '*[^0-9a-f]*'
            ),
            PRIMARY KEY (event_id, artifact_index),
            UNIQUE (event_id, artifact_digest),
            FOREIGN KEY (event_id) REFERENCES budget_mutation_events(event_id)
        );

        CREATE TABLE IF NOT EXISTS budget_cumulative_approval_accounts (
            authority_id TEXT NOT NULL CHECK (authority_id <> ''),
            owner_id TEXT NOT NULL CHECK (owner_id <> ''),
            approval_budget_id TEXT NOT NULL CHECK (approval_budget_id <> ''),
            approval_budget_epoch INTEGER NOT NULL
                CHECK (approval_budget_epoch >= 0),
            root_grant_hash TEXT NOT NULL CHECK (root_grant_hash <> ''),
            delegation_root_id TEXT,
            root_binding_digest TEXT,
            currency TEXT NOT NULL CHECK (currency <> ''),
            authority_threshold_units INTEGER NOT NULL
                CHECK (authority_threshold_units >= 0),
            reserved_authorized_units INTEGER NOT NULL DEFAULT 0
                CHECK (reserved_authorized_units >= 0),
            captured_authorized_units INTEGER NOT NULL DEFAULT 0
                CHECK (captured_authorized_units >= 0),
            version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
            PRIMARY KEY (
                authority_id, owner_id, approval_budget_id, approval_budget_epoch
            ),
            CHECK (
                (delegation_root_id IS NULL AND root_binding_digest IS NULL)
                OR
                (
                    delegation_root_id IS NOT NULL
                    AND root_binding_digest IS NOT NULL
                    AND delegation_root_id <> ''
                    AND root_binding_digest <> ''
                )
            )
        );

        CREATE TABLE IF NOT EXISTS budget_cumulative_approval_operations (
            operation_id TEXT PRIMARY KEY CHECK (operation_id <> ''),
            hold_id TEXT UNIQUE NOT NULL,
            authority_id TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            approval_budget_id TEXT NOT NULL,
            approval_budget_epoch INTEGER NOT NULL,
            effective_threshold_units INTEGER NOT NULL,
            requested_authorized_units INTEGER NOT NULL,
            state TEXT NOT NULL,
            approval_set_digest TEXT CHECK (
                approval_set_digest IS NULL
                OR (
                    length(approval_set_digest) = 64
                    AND approval_set_digest NOT GLOB '*[^0-9a-f]*'
                )
            ),
            account_version INTEGER NOT NULL CHECK (account_version >= 0),
            FOREIGN KEY (hold_id)
                REFERENCES budget_authorization_holds(hold_id),
            FOREIGN KEY (operation_id, hold_id)
                REFERENCES budget_authorization_holds(operation_id, hold_id),
            FOREIGN KEY (
                authority_id, owner_id, approval_budget_id, approval_budget_epoch
            ) REFERENCES budget_cumulative_approval_accounts (
                authority_id, owner_id, approval_budget_id, approval_budget_epoch
            )
        );

        CREATE TABLE IF NOT EXISTS budget_event_cumulative_approval (
            event_id TEXT PRIMARY KEY,
            operation_id TEXT NOT NULL,
            authority_id TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            approval_budget_id TEXT NOT NULL,
            approval_budget_epoch INTEGER NOT NULL,
            root_grant_hash TEXT NOT NULL,
            delegation_root_id TEXT,
            root_binding_digest TEXT,
            currency TEXT NOT NULL,
            authority_threshold_units INTEGER NOT NULL,
            effective_threshold_units INTEGER NOT NULL,
            requested_authorized_units INTEGER NOT NULL,
            state_before TEXT,
            state_after TEXT NOT NULL,
            reserved_authorized_before INTEGER NOT NULL,
            captured_authorized_before INTEGER NOT NULL,
            reserved_authorized_after INTEGER NOT NULL,
            captured_authorized_after INTEGER NOT NULL,
            version_before INTEGER NOT NULL,
            version_after INTEGER NOT NULL,
            FOREIGN KEY (event_id) REFERENCES budget_mutation_events(event_id)
        );

        CREATE TABLE IF NOT EXISTS budget_usage_history_anchors (
            capability_id TEXT NOT NULL,
            grant_index INTEGER NOT NULL,
            invocation_count INTEGER NOT NULL CHECK (invocation_count >= 0),
            updated_at INTEGER NOT NULL,
            seq INTEGER NOT NULL CHECK (seq > 0),
            total_cost_exposed INTEGER NOT NULL CHECK (total_cost_exposed >= 0),
            total_cost_realized_spend INTEGER NOT NULL
                CHECK (total_cost_realized_spend >= 0),
            anchored_schema_version INTEGER NOT NULL CHECK (anchored_schema_version = 6),
            PRIMARY KEY (capability_id, grant_index)
        );

        CREATE TABLE IF NOT EXISTS budget_usage_anchor_migration_gate (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1)
        );

        CREATE TABLE IF NOT EXISTS budget_snapshot_coverage (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            covered_head INTEGER NOT NULL DEFAULT 0 CHECK (covered_head >= 0)
        );

        INSERT INTO budget_snapshot_coverage(singleton, covered_head)
        VALUES (1, 0)
        ON CONFLICT(singleton) DO NOTHING;

        CREATE TABLE IF NOT EXISTS budget_snapshot_anchor_provenance (
            leader_url TEXT PRIMARY KEY CHECK (leader_url <> ''),
            commit_sequence INTEGER NOT NULL CHECK (commit_sequence > 0),
            chain_digest TEXT NOT NULL CHECK (
                length(chain_digest) = 64
                AND chain_digest NOT GLOB '*[^0-9a-f]*'
            ),
            anchor_set_digest TEXT NOT NULL CHECK (
                length(anchor_set_digest) = 64
                AND anchor_set_digest NOT GLOB '*[^0-9a-f]*'
            ),
            election_term INTEGER NOT NULL CHECK (election_term > 0),
            signer_public_key TEXT NOT NULL CHECK (signer_public_key <> ''),
            committed_at INTEGER NOT NULL CHECK (committed_at >= 0)
        );

        CREATE TRIGGER IF NOT EXISTS budget_usage_history_anchor_insert_fenced
        BEFORE INSERT ON budget_usage_history_anchors
        WHEN NOT EXISTS (
            SELECT 1 FROM budget_usage_anchor_migration_gate WHERE singleton = 1
        )
        BEGIN
            SELECT RAISE(ABORT, 'budget usage history anchor insertion is fenced');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_usage_history_anchor_immutable_update
        BEFORE UPDATE ON budget_usage_history_anchors
        BEGIN
            SELECT RAISE(ABORT, 'budget usage history anchor is immutable');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_usage_history_anchor_immutable_delete
        BEFORE DELETE ON budget_usage_history_anchors
        BEGIN
            SELECT RAISE(ABORT, 'budget usage history anchor is immutable');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_cumulative_account_identity_immutable
        BEFORE UPDATE OF root_grant_hash, delegation_root_id,
                         root_binding_digest, currency,
                         authority_threshold_units
        ON budget_cumulative_approval_accounts
        WHEN OLD.root_grant_hash IS NOT NEW.root_grant_hash
          OR OLD.delegation_root_id IS NOT NEW.delegation_root_id
          OR OLD.root_binding_digest IS NOT NEW.root_binding_digest
          OR OLD.currency IS NOT NEW.currency
          OR OLD.authority_threshold_units IS NOT NEW.authority_threshold_units
        BEGIN
            SELECT RAISE(ABORT, 'cumulative approval account identity is immutable');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_quota_maximum_immutable
        BEFORE UPDATE OF max_invocations ON budget_invocation_quotas
        WHEN OLD.max_invocations IS NOT NEW.max_invocations
        BEGIN
            SELECT RAISE(ABORT, 'budget quota maximum is immutable');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_quota_bounds_insert
        BEFORE INSERT ON budget_invocation_quotas
        WHEN NEW.max_invocations <= 0
          OR NEW.reserved_invocations < 0
          OR NEW.captured_invocations < 0
          OR NEW.reserved_invocations > NEW.max_invocations
          OR NEW.captured_invocations > NEW.max_invocations - NEW.reserved_invocations
          OR NEW.owner_id = ''
          OR NOT (
              (NEW.profile = 'chio.grant-invocation.v1' AND NEW.grant_index >= 0)
              OR (NEW.profile IN (
                  'chio.aggregate-capability-invocation.v1',
                  'chio.aggregate-family-invocation.v1',
                  'chio.broker-capability-execution.v1'
              ) AND NEW.grant_index = -1)
          )
        BEGIN
            SELECT RAISE(ABORT, 'budget quota is outside durable bounds');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_quota_bounds_update
        BEFORE UPDATE ON budget_invocation_quotas
        WHEN NEW.max_invocations <= 0
          OR NEW.reserved_invocations < 0
          OR NEW.captured_invocations < 0
          OR NEW.reserved_invocations > NEW.max_invocations
          OR NEW.captured_invocations > NEW.max_invocations - NEW.reserved_invocations
          OR NEW.owner_id = ''
          OR NOT (
              (NEW.profile = 'chio.grant-invocation.v1' AND NEW.grant_index >= 0)
              OR (NEW.profile IN (
                  'chio.aggregate-capability-invocation.v1',
                  'chio.aggregate-family-invocation.v1',
                  'chio.broker-capability-execution.v1'
              ) AND NEW.grant_index = -1)
          )
        BEGIN
            SELECT RAISE(ABORT, 'budget quota is outside durable bounds');
        END;

        CREATE TRIGGER IF NOT EXISTS budget_event_quota_bounds_insert
        BEFORE INSERT ON budget_event_quota_members
        WHEN NEW.max_invocations < 0
          OR (
              NEW.max_invocations = 0
              AND NOT EXISTS (
                  SELECT 1 FROM budget_mutation_events
                  WHERE event_id = NEW.event_id
                    AND authorization_outcome = 'denied'
              )
          )
          OR NEW.reserved_before < 0 OR NEW.captured_before < 0
          OR NEW.reserved_after < 0 OR NEW.captured_after < 0
          OR NEW.reserved_before > NEW.max_invocations
          OR NEW.captured_before > NEW.max_invocations - NEW.reserved_before
          OR NEW.reserved_after > NEW.max_invocations
          OR NEW.captured_after > NEW.max_invocations - NEW.reserved_after
          OR NEW.owner_id = ''
          OR NOT (
              (NEW.profile = 'chio.grant-invocation.v1' AND NEW.grant_index >= 0)
              OR (NEW.profile IN (
                  'chio.aggregate-capability-invocation.v1',
                  'chio.aggregate-family-invocation.v1',
                  'chio.broker-capability-execution.v1'
              ) AND NEW.grant_index = -1)
          )
        BEGIN
            SELECT RAISE(ABORT, 'budget event quota is outside durable bounds');
        END;

        DROP TRIGGER IF EXISTS budget_hold_projection_immutable;
        DROP TRIGGER IF EXISTS budget_event_projection_immutable;
        DROP TRIGGER IF EXISTS budget_hold_capture_time_immutable;

        CREATE TRIGGER budget_hold_projection_immutable
        BEFORE UPDATE OF projection_kind, operation_id, revocation_set_digest,
                         expected_revocation_count, expected_quota_count,
                         expected_artifact_count,
                         has_cumulative_approval, has_revocation_commit
        ON budget_authorization_holds
        WHEN OLD.projection_kind = 'composite_v1'
          AND OLD.expected_revocation_count IS NOT NULL AND (
            OLD.projection_kind IS NOT NEW.projection_kind
            OR OLD.operation_id IS NOT NEW.operation_id
            OR OLD.revocation_set_digest IS NOT NEW.revocation_set_digest
            OR OLD.expected_revocation_count IS NOT NEW.expected_revocation_count
            OR OLD.expected_quota_count IS NOT NEW.expected_quota_count
            OR OLD.expected_artifact_count IS NOT NEW.expected_artifact_count
            OR OLD.has_cumulative_approval IS NOT NEW.has_cumulative_approval
            OR OLD.has_revocation_commit IS NOT NEW.has_revocation_commit
        )
        BEGIN
            SELECT RAISE(ABORT, 'composite hold projection contract is immutable');
        END;

        CREATE TRIGGER budget_event_projection_immutable
        BEFORE UPDATE OF projection_kind, operation_id, revocation_set_digest,
                         expected_revocation_count, expected_quota_count,
                         expected_artifact_count,
                         has_cumulative_approval, has_revocation_commit
        ON budget_mutation_events
        WHEN OLD.projection_kind = 'composite_v1'
          AND OLD.expected_revocation_count IS NOT NULL AND (
            OLD.projection_kind IS NOT NEW.projection_kind
            OR OLD.operation_id IS NOT NEW.operation_id
            OR OLD.revocation_set_digest IS NOT NEW.revocation_set_digest
            OR OLD.expected_revocation_count IS NOT NEW.expected_revocation_count
            OR OLD.expected_quota_count IS NOT NEW.expected_quota_count
            OR OLD.expected_artifact_count IS NOT NEW.expected_artifact_count
            OR OLD.has_cumulative_approval IS NOT NEW.has_cumulative_approval
            OR OLD.has_revocation_commit IS NOT NEW.has_revocation_commit
        )
        BEGIN
            SELECT RAISE(ABORT, 'composite event projection contract is immutable');
        END;

        CREATE TRIGGER budget_hold_capture_time_immutable
        BEFORE UPDATE OF trusted_capture_time ON budget_authorization_holds
        WHEN OLD.trusted_capture_time IS NOT NULL
          AND OLD.trusted_capture_time IS NOT NEW.trusted_capture_time
        BEGIN
            SELECT RAISE(ABORT, 'composite hold capture time is immutable');
        END;
        "#,
    )?;
    migrate_zero_limit_denied_event_quotas(transaction, on_disk_schema_version)?;
    ensure_cumulative_operation_composite_fk(transaction)?;
    migrate_payment_journal_cancelled_hold_state(transaction, on_disk_schema_version)?;

    if on_disk_schema_version < COMPOSITE_PROJECTION_SCHEMA_VERSION {
        transaction.execute_batch(
            r#"
            DROP INDEX IF EXISTS idx_budget_events_operation_authorize;
            CREATE UNIQUE INDEX idx_budget_events_operation_authorize
                ON budget_mutation_events(operation_id)
                WHERE operation_id IS NOT NULL
                  AND kind IN ('reserve_invocation', 'authorize_exposure')
                  AND authorization_outcome IS NOT 'denied';
            "#,
        )?;
        if on_disk_schema_version < BUDGET_USAGE_ANCHOR_SCHEMA_VERSION {
            transaction.execute(
                "INSERT OR IGNORE INTO budget_usage_anchor_migration_gate(singleton) VALUES (1)",
                [],
            )?;
            transaction.execute(
                r#"
                INSERT INTO budget_usage_history_anchors (
                    capability_id, grant_index, invocation_count, updated_at, seq,
                    total_cost_exposed, total_cost_realized_spend,
                    anchored_schema_version
                )
                SELECT capability_id, grant_index, invocation_count, updated_at, seq,
                       total_cost_exposed, total_cost_realized_spend, 6
                FROM capability_grant_budgets
                WHERE seq > 0
                ON CONFLICT(capability_id, grant_index) DO NOTHING
                "#,
                [],
            )?;
            transaction.execute("DELETE FROM budget_usage_anchor_migration_gate", [])?;
        }
        transaction.execute(
            r#"
            UPDATE budget_authorization_holds
            SET authorization_outcome = COALESCE(authorization_outcome, 'authorized'),
                invocation_state = COALESCE(
                    invocation_state,
                    CASE
                        WHEN disposition = 'reversed' THEN 'reversed'
                        WHEN invocation_captured = 1 THEN 'captured'
                        ELSE 'authorized'
                    END
                ),
                monetary_state = COALESCE(
                    monetary_state,
                    CASE
                        WHEN disposition = 'reversed'
                             AND authorized_exposure_units > 0 THEN 'reversed'
                        WHEN disposition = 'reconciled' THEN 'reconciled'
                        WHEN disposition = 'released' THEN 'released'
                        WHEN remaining_exposure_units > 0 THEN 'exposed'
                        ELSE 'none'
                    END
                )
            WHERE operation_id IS NULL
            "#,
            [],
        )?;
        transaction.execute(
            r#"
            UPDATE budget_authorization_holds
            SET trusted_capture_time = (
                SELECT event.trusted_time
                FROM budget_mutation_events AS event
                WHERE event.hold_id = budget_authorization_holds.hold_id
                  AND event.kind = 'capture_invocation'
                ORDER BY event.event_seq DESC LIMIT 1
            )
            WHERE projection_kind = 'composite_v1'
              AND invocation_state = 'captured'
              AND trusted_capture_time IS NULL
            "#,
            [],
        )?;
        backfill_legacy_event_lifecycle(transaction)?;
        backfill_projection_contracts(transaction)?;
    }
    Ok(())
}

fn migrate_zero_limit_denied_event_quotas(
    transaction: &rusqlite::Transaction<'_>,
    on_disk_schema_version: i32,
) -> Result<(), BudgetStoreError> {
    if on_disk_schema_version >= COMPOSITE_PROJECTION_SCHEMA_VERSION {
        return Ok(());
    }
    let table_sql: String = transaction.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'budget_event_quota_members'",
        [],
        |row| row.get(0),
    )?;
    transaction.execute_batch("DROP TRIGGER IF EXISTS budget_event_quota_bounds_insert;")?;
    if table_sql.contains("max_invocations > 0") {
        transaction.execute_batch(
            r#"
            ALTER TABLE budget_event_quota_members
                RENAME TO budget_event_quota_members_v9;
            CREATE TABLE budget_event_quota_members (
                event_id TEXT NOT NULL,
                profile TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                grant_index INTEGER NOT NULL,
                max_invocations INTEGER NOT NULL CHECK (max_invocations >= 0),
                reserved_before INTEGER NOT NULL CHECK (reserved_before >= 0),
                captured_before INTEGER NOT NULL CHECK (
                    captured_before >= 0 AND reserved_before <= max_invocations
                    AND captured_before <= max_invocations - reserved_before
                ),
                reserved_after INTEGER NOT NULL CHECK (reserved_after >= 0),
                captured_after INTEGER NOT NULL CHECK (
                    captured_after >= 0 AND reserved_after <= max_invocations
                    AND captured_after <= max_invocations - reserved_after
                ),
                PRIMARY KEY (event_id, profile, owner_id, grant_index),
                FOREIGN KEY (event_id) REFERENCES budget_mutation_events(event_id),
                CHECK (owner_id <> ''),
                CHECK (
                    (profile = 'chio.grant-invocation.v1' AND grant_index >= 0)
                    OR
                    (profile IN (
                        'chio.aggregate-capability-invocation.v1',
                        'chio.aggregate-family-invocation.v1',
                        'chio.broker-capability-execution.v1'
                    ) AND grant_index = -1)
                )
            );
            INSERT INTO budget_event_quota_members (
                event_id, profile, owner_id, grant_index, max_invocations,
                reserved_before, captured_before, reserved_after, captured_after
            )
            SELECT event_id, profile, owner_id, grant_index, max_invocations,
                   reserved_before, captured_before, reserved_after, captured_after
            FROM budget_event_quota_members_v9;
            DROP TABLE budget_event_quota_members_v9;
            "#,
        )?;
    }
    transaction.execute_batch(
        r#"
        CREATE TRIGGER budget_event_quota_bounds_insert
        BEFORE INSERT ON budget_event_quota_members
        WHEN NEW.max_invocations < 0
          OR (
              NEW.max_invocations = 0
              AND NOT EXISTS (
                  SELECT 1 FROM budget_mutation_events
                  WHERE event_id = NEW.event_id
                    AND authorization_outcome = 'denied'
              )
          )
          OR NEW.reserved_before < 0 OR NEW.captured_before < 0
          OR NEW.reserved_after < 0 OR NEW.captured_after < 0
          OR NEW.reserved_before > NEW.max_invocations
          OR NEW.captured_before > NEW.max_invocations - NEW.reserved_before
          OR NEW.reserved_after > NEW.max_invocations
          OR NEW.captured_after > NEW.max_invocations - NEW.reserved_after
          OR NEW.owner_id = ''
          OR NOT (
              (NEW.profile = 'chio.grant-invocation.v1' AND NEW.grant_index >= 0)
              OR (NEW.profile IN (
                  'chio.aggregate-capability-invocation.v1',
                  'chio.aggregate-family-invocation.v1',
                  'chio.broker-capability-execution.v1'
              ) AND NEW.grant_index = -1)
          )
        BEGIN
            SELECT RAISE(ABORT, 'budget event quota is outside durable bounds');
        END;
        "#,
    )?;
    Ok(())
}

/// Widen the `payment_journal` row contract so a hold cancelled before any rail
/// authorization reaches `closed` without an authorization identifier.
///
/// The table is created with `CREATE TABLE IF NOT EXISTS` and SQLite cannot
/// alter a CHECK constraint in place, so a database provisioned under an earlier
/// revision keeps the narrower contract and still rejects that cancellation
/// until the table is rebuilt. The rebuild is skipped once the on-disk
/// definition already carries the widened branch, so it applies at most once.
fn migrate_payment_journal_cancelled_hold_state(
    transaction: &rusqlite::Transaction<'_>,
    on_disk_schema_version: i32,
) -> Result<(), BudgetStoreError> {
    if on_disk_schema_version >= COMPOSITE_SCHEMA_VERSION {
        return Ok(());
    }
    let table_sql: String = transaction.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'payment_journal'",
        [],
        |row| row.get(0),
    )?;
    if table_sql.contains("state = 'closed'") {
        return Ok(());
    }
    let rows_before: i64 =
        transaction.query_row("SELECT COUNT(*) FROM payment_journal", [], |row| row.get(0))?;
    // `payment_release_evidence` references `payment_journal`, so dropping the
    // table orphans its rows for the rest of the rebuild. Renaming the journal
    // aside instead would repoint that reference at the temporary name, which is
    // why the rebuild keeps the name and defers foreign key enforcement: the
    // drop counts the orphans and copying the rows back into the recreated
    // table clears the count before the enclosing transaction commits.
    transaction.execute_batch("PRAGMA defer_foreign_keys = ON;")?;
    let rebuilt = rebuild_payment_journal(transaction);
    let restored = transaction.execute_batch("PRAGMA defer_foreign_keys = OFF;");
    rebuilt?;
    restored?;
    let rows_after: i64 =
        transaction.query_row("SELECT COUNT(*) FROM payment_journal", [], |row| row.get(0))?;
    if rows_before != rows_after {
        return Err(BudgetStoreError::Invariant(format!(
            "payment journal rebuild carried {rows_after} of {rows_before} rows"
        )));
    }
    Ok(())
}

/// Copy every journal row aside, recreate the table under the widened contract,
/// copy the rows back, and restore the indexes and triggers that the drop
/// removed with the table. The copy back is a plain `INSERT`, so a row the
/// widened contract would reject aborts the rebuild instead of being dropped.
fn rebuild_payment_journal(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), BudgetStoreError> {
    transaction.execute_batch(
        r#"
        CREATE TABLE payment_journal_rebuild (
            operation_id TEXT,
            journal_version INTEGER,
            request_namespace_digest TEXT,
            request_id TEXT,
            capability_id TEXT,
            grant_index INTEGER,
            hold_id TEXT,
            rail TEXT,
            rail_mode TEXT,
            authorization_id TEXT,
            transaction_id TEXT,
            amount_units INTEGER,
            settle_action TEXT,
            settle_amount_units INTEGER,
            release_authority_kind TEXT,
            release_authority_evidence_id TEXT,
            release_authority_evidence_digest TEXT,
            release_authority_operation_version INTEGER,
            currency TEXT,
            state TEXT,
            created_at_unix_ms INTEGER,
            updated_at_unix_ms INTEGER
        );

        INSERT INTO payment_journal_rebuild (
            operation_id, journal_version, request_namespace_digest, request_id,
            capability_id, grant_index, hold_id, rail, rail_mode,
            authorization_id, transaction_id, amount_units, settle_action,
            settle_amount_units, release_authority_kind,
            release_authority_evidence_id, release_authority_evidence_digest,
            release_authority_operation_version, currency, state,
            created_at_unix_ms, updated_at_unix_ms
        )
        SELECT
            operation_id, journal_version, request_namespace_digest, request_id,
            capability_id, grant_index, hold_id, rail, rail_mode,
            authorization_id, transaction_id, amount_units, settle_action,
            settle_amount_units, release_authority_kind,
            release_authority_evidence_id, release_authority_evidence_digest,
            release_authority_operation_version, currency, state,
            created_at_unix_ms, updated_at_unix_ms
        FROM payment_journal;

        DROP TRIGGER IF EXISTS payment_journal_identity_immutable;
        DROP TRIGGER IF EXISTS payment_journal_no_delete;
        DROP INDEX IF EXISTS idx_payment_journal_request;
        DROP INDEX IF EXISTS idx_payment_journal_state;
        DROP TABLE payment_journal;

        CREATE TABLE payment_journal (
            operation_id TEXT PRIMARY KEY CHECK (operation_id <> '' AND length(operation_id) <= 512),
            journal_version INTEGER NOT NULL CHECK (
                journal_version BETWEEN 1 AND 9007199254740991
            ),
            request_namespace_digest TEXT NOT NULL CHECK (
                length(request_namespace_digest) = 64
                AND request_namespace_digest NOT GLOB '*[^0-9a-f]*'
            ),
            request_id TEXT NOT NULL CHECK (request_id <> '' AND length(request_id) <= 512),
            capability_id TEXT NOT NULL CHECK (capability_id <> '' AND length(capability_id) <= 512),
            grant_index INTEGER NOT NULL CHECK (grant_index BETWEEN 0 AND 4294967295),
            hold_id TEXT NOT NULL UNIQUE CHECK (hold_id <> '' AND length(hold_id) <= 512),
            rail TEXT NOT NULL CHECK (
                rail <> '' AND rail <> 'unspecified' AND length(rail) <= 512
            ),
            rail_mode TEXT NOT NULL CHECK (rail_mode IN ('reversible_hold', 'prepaid_final')),
            authorization_id TEXT CHECK (
                authorization_id IS NULL
                OR (authorization_id <> '' AND length(authorization_id) <= 512)
            ),
            transaction_id TEXT CHECK (
                transaction_id IS NULL
                OR (transaction_id <> '' AND length(transaction_id) <= 512)
            ),
            amount_units INTEGER NOT NULL CHECK (
                amount_units BETWEEN 1 AND 9007199254740991
            ),
            settle_action TEXT CHECK (settle_action IN ('capture', 'release')),
            settle_amount_units INTEGER CHECK (
                settle_amount_units BETWEEN 1 AND amount_units
            ),
            release_authority_kind TEXT CHECK (
                release_authority_kind IN (
                    'pre_dispatch_no_effect',
                    'transport_not_accepted',
                    'contractual_zero_charge'
                )
            ),
            release_authority_evidence_id TEXT CHECK (
                release_authority_evidence_id IS NULL
                OR (release_authority_evidence_id <> ''
                    AND length(release_authority_evidence_id) <= 512)
            ),
            release_authority_evidence_digest TEXT CHECK (
                release_authority_evidence_digest IS NULL
                OR (length(release_authority_evidence_digest) = 64
                    AND release_authority_evidence_digest NOT GLOB '*[^0-9a-f]*')
            ),
            release_authority_operation_version INTEGER CHECK (
                release_authority_operation_version BETWEEN 1 AND 9007199254740991
            ),
            currency TEXT NOT NULL CHECK (
                length(currency) = 3 AND currency NOT GLOB '*[^A-Z]*'
            ),
            state TEXT NOT NULL CHECK (state IN (
                'hold_placed', 'authorized', 'settling', 'settled', 'closed',
                'reconcile_failed'
            )),
            created_at_unix_ms INTEGER NOT NULL CHECK (
                created_at_unix_ms BETWEEN 1 AND 9007199254740991
            ),
            updated_at_unix_ms INTEGER NOT NULL CHECK (
                updated_at_unix_ms BETWEEN created_at_unix_ms AND 9007199254740991
            ),
            FOREIGN KEY (hold_id) REFERENCES budget_authorization_holds(hold_id),
            CHECK (
                (state = 'hold_placed'
                 AND authorization_id IS NULL AND transaction_id IS NULL
                 AND settle_action IS NULL AND settle_amount_units IS NULL
                 AND release_authority_kind IS NULL
                 AND release_authority_evidence_id IS NULL
                 AND release_authority_evidence_digest IS NULL
                 AND release_authority_operation_version IS NULL)
                OR
                (state = 'authorized' AND rail_mode = 'reversible_hold'
                 AND authorization_id IS NOT NULL AND transaction_id IS NULL
                 AND settle_action IS NULL AND settle_amount_units IS NULL
                 AND release_authority_kind IS NULL
                 AND release_authority_evidence_id IS NULL
                 AND release_authority_evidence_digest IS NULL
                 AND release_authority_operation_version IS NULL)
                OR
                (state = 'settling' AND rail_mode = 'reversible_hold'
                 AND authorization_id IS NOT NULL AND transaction_id IS NULL
                 AND (
                    (settle_action = 'capture' AND settle_amount_units IS NOT NULL
                     AND release_authority_kind IS NULL
                     AND release_authority_evidence_id IS NULL
                     AND release_authority_evidence_digest IS NULL
                     AND release_authority_operation_version IS NULL)
                    OR
                    (settle_action = 'release' AND settle_amount_units IS NULL
                     AND release_authority_kind IS NOT NULL
                     AND release_authority_evidence_id IS NOT NULL
                     AND release_authority_evidence_digest IS NOT NULL
                     AND release_authority_operation_version IS NOT NULL)
                 ))
                OR
                (state IN ('settled', 'closed') AND authorization_id IS NOT NULL
                 AND (
                    (rail_mode = 'prepaid_final' AND transaction_id IS NULL
                     AND settle_action IS NULL AND settle_amount_units IS NULL
                     AND release_authority_kind IS NULL
                     AND release_authority_evidence_id IS NULL
                     AND release_authority_evidence_digest IS NULL
                     AND release_authority_operation_version IS NULL)
                    OR
                    (rail_mode = 'reversible_hold' AND transaction_id IS NOT NULL
                     AND (
                        (settle_action = 'capture' AND settle_amount_units IS NOT NULL
                         AND release_authority_kind IS NULL
                         AND release_authority_evidence_id IS NULL
                         AND release_authority_evidence_digest IS NULL
                         AND release_authority_operation_version IS NULL)
                        OR
                        (settle_action = 'release' AND settle_amount_units IS NULL
                         AND release_authority_kind IS NOT NULL
                         AND release_authority_evidence_id IS NOT NULL
                         AND release_authority_evidence_digest IS NOT NULL
                         AND release_authority_operation_version IS NOT NULL)
                     ))
                 ))
                OR
                (state = 'closed'
                 AND authorization_id IS NULL AND transaction_id IS NULL
                 AND settle_action IS NULL AND settle_amount_units IS NULL
                 AND release_authority_kind IS NULL
                 AND release_authority_evidence_id IS NULL
                 AND release_authority_evidence_digest IS NULL
                 AND release_authority_operation_version IS NULL)
                OR state = 'reconcile_failed'
            )
        );

        INSERT INTO payment_journal (
            operation_id, journal_version, request_namespace_digest, request_id,
            capability_id, grant_index, hold_id, rail, rail_mode,
            authorization_id, transaction_id, amount_units, settle_action,
            settle_amount_units, release_authority_kind,
            release_authority_evidence_id, release_authority_evidence_digest,
            release_authority_operation_version, currency, state,
            created_at_unix_ms, updated_at_unix_ms
        )
        SELECT
            operation_id, journal_version, request_namespace_digest, request_id,
            capability_id, grant_index, hold_id, rail, rail_mode,
            authorization_id, transaction_id, amount_units, settle_action,
            settle_amount_units, release_authority_kind,
            release_authority_evidence_id, release_authority_evidence_digest,
            release_authority_operation_version, currency, state,
            created_at_unix_ms, updated_at_unix_ms
        FROM payment_journal_rebuild;

        DROP TABLE payment_journal_rebuild;

        CREATE UNIQUE INDEX idx_payment_journal_request
            ON payment_journal(request_namespace_digest, request_id);
        CREATE INDEX idx_payment_journal_state
            ON payment_journal(state, updated_at_unix_ms);

        CREATE TRIGGER payment_journal_identity_immutable
        BEFORE UPDATE OF operation_id, request_namespace_digest, request_id,
                         capability_id, grant_index, hold_id, rail, rail_mode,
                         amount_units, currency, created_at_unix_ms
        ON payment_journal
        BEGIN
            SELECT RAISE(ABORT, 'payment journal identity is immutable');
        END;

        CREATE TRIGGER payment_journal_no_delete
        BEFORE DELETE ON payment_journal
        BEGIN
            SELECT RAISE(ABORT, 'payment journal is append-preserving');
        END;
        "#,
    )?;
    Ok(())
}

fn backfill_legacy_event_lifecycle(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), BudgetStoreError> {
    type EventRow = (String, Option<String>, String, Option<bool>, u64);
    let events = {
        let mut statement = transaction.prepare(
            r#"
            SELECT event_id, hold_id, kind, allowed, exposure_units
            FROM budget_mutation_events
            WHERE projection_kind = 'legacy'
            ORDER BY event_seq, event_id
            "#,
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get::<_, Option<i64>>(3)?.map(|value| value != 0),
                    budget_u64_from_row(row, 4, "exposure_units")?,
                ))
            })?
            .collect::<Result<Vec<EventRow>, _>>()?;
        rows
    };
    type HoldState = (BudgetInvocationState, BudgetMonetaryState, u64);
    let mut holds = std::collections::BTreeMap::<String, HoldState>::new();
    for (event_id, hold_id, kind, allowed, exposure) in events {
        let kind = BudgetMutationKind::parse(&kind).ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "legacy budget event `{event_id}` has unknown mutation kind"
            ))
        })?;
        let live_money = if exposure == 0 {
            BudgetMonetaryState::None
        } else {
            BudgetMonetaryState::Exposed
        };
        let outcome = allowed.map(|allowed| {
            if allowed {
                BudgetAuthorizationOutcome::Authorized
            } else {
                BudgetAuthorizationOutcome::Denied
            }
        });
        let lifecycle = match (kind, hold_id.as_deref()) {
            (BudgetMutationKind::IncrementInvocation, _) => (
                outcome,
                BudgetInvocationState::Absent,
                if allowed == Some(true) {
                    BudgetInvocationState::Captured
                } else {
                    BudgetInvocationState::Denied
                },
                BudgetMonetaryState::None,
                BudgetMonetaryState::None,
            ),
            (BudgetMutationKind::AuthorizeExposure, Some(hold_id)) => {
                let invocation_after = if allowed == Some(false) {
                    BudgetInvocationState::Denied
                } else {
                    BudgetInvocationState::Authorized
                };
                let money_after = if allowed == Some(false) {
                    BudgetMonetaryState::None
                } else {
                    live_money
                };
                if allowed == Some(true) {
                    holds.insert(
                        hold_id.to_string(),
                        (invocation_after, money_after, exposure),
                    );
                }
                (
                    outcome,
                    BudgetInvocationState::Absent,
                    invocation_after,
                    BudgetMonetaryState::None,
                    money_after,
                )
            }
            (BudgetMutationKind::AuthorizeExposure, None) => (
                outcome,
                BudgetInvocationState::Absent,
                if allowed == Some(false) {
                    BudgetInvocationState::Denied
                } else {
                    BudgetInvocationState::Authorized
                },
                BudgetMonetaryState::None,
                if allowed == Some(false) {
                    BudgetMonetaryState::None
                } else {
                    live_money
                },
            ),
            (BudgetMutationKind::CaptureInvocation, Some(hold_id)) => {
                let state = holds.get_mut(hold_id).ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "legacy capture event `{event_id}` has no authorization history"
                    ))
                })?;
                let before = *state;
                state.0 = BudgetInvocationState::Captured;
                (None, before.0, state.0, before.1, state.1)
            }
            (
                BudgetMutationKind::ReverseExposure
                | BudgetMutationKind::CancelCapturedBeforeDispatch,
                Some(hold_id),
            ) => {
                let state = holds.get_mut(hold_id).ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "legacy reversal event `{event_id}` has no authorization history"
                    ))
                })?;
                let before = *state;
                state.0 = BudgetInvocationState::Reversed;
                state.1 = if state.2 == 0 {
                    BudgetMonetaryState::None
                } else {
                    BudgetMonetaryState::Reversed
                };
                state.2 = 0;
                (None, before.0, state.0, before.1, state.1)
            }
            (BudgetMutationKind::ReverseExposure, None) => (
                None,
                BudgetInvocationState::Authorized,
                BudgetInvocationState::Reversed,
                live_money,
                if exposure == 0 {
                    BudgetMonetaryState::None
                } else {
                    BudgetMonetaryState::Reversed
                },
            ),
            (BudgetMutationKind::ReleaseExposure, Some(hold_id)) => {
                let state = holds.get_mut(hold_id).ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "legacy release event `{event_id}` has no authorization history"
                    ))
                })?;
                let before = *state;
                state.2 = state.2.checked_sub(exposure).ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "legacy release event `{event_id}` exceeds held exposure"
                    ))
                })?;
                state.1 = if before.1 == BudgetMonetaryState::None {
                    BudgetMonetaryState::None
                } else if state.2 == 0 {
                    BudgetMonetaryState::Released
                } else {
                    BudgetMonetaryState::Exposed
                };
                (None, before.0, state.0, before.1, state.1)
            }
            (BudgetMutationKind::ReleaseExposure, None) => (
                None,
                BudgetInvocationState::Absent,
                BudgetInvocationState::Absent,
                live_money,
                if exposure == 0 {
                    BudgetMonetaryState::None
                } else {
                    BudgetMonetaryState::Released
                },
            ),
            (BudgetMutationKind::ReconcileSpend, Some(hold_id)) => {
                let state = holds.get_mut(hold_id).ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "legacy reconciliation event `{event_id}` has no authorization history"
                    ))
                })?;
                let before = *state;
                state.1 = BudgetMonetaryState::Reconciled;
                state.2 = 0;
                (None, before.0, state.0, before.1, state.1)
            }
            (BudgetMutationKind::ReconcileSpend, None) => (
                None,
                BudgetInvocationState::Absent,
                BudgetInvocationState::Absent,
                live_money,
                BudgetMonetaryState::Reconciled,
            ),
            _ => {
                return Err(BudgetStoreError::Invariant(format!(
                    "legacy budget event `{event_id}` uses unsupported mutation kind"
                )));
            }
        };
        transaction.execute(
            r#"
            UPDATE budget_mutation_events
            SET authorization_outcome = ?2,
                invocation_state_before = ?3,
                invocation_state_after = ?4,
                monetary_state_before = ?5,
                monetary_state_after = ?6
            WHERE event_id = ?1
            "#,
            params![
                event_id,
                lifecycle.0.map(budget_authorization_outcome_text),
                budget_invocation_state_text(lifecycle.1),
                budget_invocation_state_text(lifecycle.2),
                budget_monetary_state_text(lifecycle.3),
                budget_monetary_state_text(lifecycle.4),
            ],
        )?;
    }
    Ok(())
}

fn ensure_cumulative_operation_composite_fk(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), BudgetStoreError> {
    let mappings = {
        let mut statement = transaction
            .prepare("PRAGMA foreign_key_list(budget_cumulative_approval_operations)")?;
        let mappings = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        mappings
    };
    let has_composite = mappings.iter().any(|(id, table, from, to)| {
        table == "budget_authorization_holds"
            && from == "operation_id"
            && to == "operation_id"
            && mappings
                .iter()
                .any(|(other_id, other_table, other_from, other_to)| {
                    other_id == id
                        && other_table == table
                        && other_from == "hold_id"
                        && other_to == "hold_id"
                })
    });
    if has_composite {
        return Ok(());
    }
    transaction.execute_batch(
        r#"
        CREATE TABLE budget_cumulative_approval_operations_v4 (
            operation_id TEXT PRIMARY KEY CHECK (operation_id <> ''),
            hold_id TEXT UNIQUE NOT NULL,
            authority_id TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            approval_budget_id TEXT NOT NULL,
            approval_budget_epoch INTEGER NOT NULL,
            effective_threshold_units INTEGER NOT NULL,
            requested_authorized_units INTEGER NOT NULL,
            state TEXT NOT NULL,
            approval_set_digest TEXT CHECK (
                approval_set_digest IS NULL
                OR (
                    length(approval_set_digest) = 64
                    AND approval_set_digest NOT GLOB '*[^0-9a-f]*'
                )
            ),
            account_version INTEGER NOT NULL CHECK (account_version >= 0),
            FOREIGN KEY (hold_id)
                REFERENCES budget_authorization_holds(hold_id),
            FOREIGN KEY (operation_id, hold_id)
                REFERENCES budget_authorization_holds(operation_id, hold_id),
            FOREIGN KEY (
                authority_id, owner_id, approval_budget_id, approval_budget_epoch
            ) REFERENCES budget_cumulative_approval_accounts (
                authority_id, owner_id, approval_budget_id, approval_budget_epoch
            )
        );
        INSERT INTO budget_cumulative_approval_operations_v4
        SELECT * FROM budget_cumulative_approval_operations;
        DROP TABLE budget_cumulative_approval_operations;
        ALTER TABLE budget_cumulative_approval_operations_v4
            RENAME TO budget_cumulative_approval_operations;
        "#,
    )?;
    Ok(())
}

fn ensure_column(
    transaction: &rusqlite::Transaction<'_>,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), BudgetStoreError> {
    let mut statement = transaction.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|existing| existing == column) {
        transaction.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN {column} {definition}"
        ))?;
    }
    Ok(())
}

fn backfill_projection_contracts(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), BudgetStoreError> {
    for (parent, id_column, revocations, quotas, artifacts, cumulative, commits) in [
        (
            "budget_authorization_holds",
            "hold_id",
            "budget_hold_revocation_members",
            "budget_hold_quota_members",
            "budget_hold_authorization_artifacts",
            "budget_cumulative_approval_operations",
            "budget_hold_revocation_commits",
        ),
        (
            "budget_mutation_events",
            "event_id",
            "budget_event_revocation_members",
            "budget_event_quota_members",
            "budget_event_authorization_artifacts",
            "budget_event_cumulative_approval",
            "budget_event_revocation_commits",
        ),
    ] {
        let identities = {
            let mut statement = transaction.prepare(&format!(
                "SELECT {id_column} FROM {parent} WHERE operation_id IS NOT NULL"
            ))?;
            let values = statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            values
        };
        for identity in identities {
            let revocation_ids = {
                let mut statement = transaction.prepare(&format!(
                    "SELECT capability_id FROM {revocations} WHERE {id_column} = ?1 ORDER BY member_index"
                ))?;
                let values = statement
                    .query_map(params![&identity], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                values
            };
            let revocation_count = revocation_ids.len();
            let revocation_set =
                CanonicalRevocationSet::canonicalize(revocation_ids).map_err(|error| {
                    BudgetStoreError::Invariant(format!(
                        "cannot migrate composite projection `{identity}`: {error}"
                    ))
                })?;
            let (quota_count, artifact_count, cumulative_count, commit_count) = transaction
                .query_row(
                    &format!(
                        r#"
                        SELECT
                            (SELECT COUNT(*) FROM {quotas} WHERE {id_column} = ?1),
                            (SELECT COUNT(*) FROM {artifacts} WHERE {id_column} = ?1),
                            (SELECT COUNT(*) FROM {cumulative} WHERE {id_column} = ?1),
                            (SELECT COUNT(*) FROM {commits} WHERE {id_column} = ?1)
                        "#
                    ),
                    params![&identity],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )?;
            if cumulative_count > 1 || commit_count > 1 {
                return Err(BudgetStoreError::Invariant(format!(
                    "composite projection `{identity}` has duplicate optional children"
                )));
            }
            transaction.execute(
                &format!(
                    r#"
                    UPDATE {parent}
                    SET projection_kind = 'composite_v1',
                        revocation_set_digest = ?2,
                        expected_quota_count = ?3,
                        expected_artifact_count = ?4,
                        has_cumulative_approval = ?5,
                        has_revocation_commit = ?6,
                        expected_revocation_count = ?7
                    WHERE {id_column} = ?1
                    "#
                ),
                params![
                    &identity,
                    revocation_set.digest(),
                    quota_count,
                    artifact_count,
                    cumulative_count == 1,
                    commit_count == 1,
                    i64::try_from(revocation_count).map_err(|_| {
                        BudgetStoreError::Invariant(
                            "revocation count exceeds sqlite range".to_string(),
                        )
                    })?,
                ],
            )?;
        }
    }
    Ok(())
}

pub(super) fn verify_budget_foreign_keys(connection: &Connection) -> Result<(), BudgetStoreError> {
    let violation = connection
        .query_row("PRAGMA foreign_key_check", [], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .optional()?;
    if let Some((table, rowid)) = violation {
        return Err(BudgetStoreError::Invariant(format!(
            "sqlite foreign key violation in `{table}` row {rowid}"
        )));
    }
    Ok(())
}

pub(crate) fn verify_budget_projection_invariants(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let invalid = connection
        .query_row(
            r#"
            WITH projection_rows AS (
                SELECT 'hold' AS kind, hold_id AS owner_id,
                       artifact_index AS member_index,
                       artifact_digest AS value,
                       'artifact' AS member_kind
                FROM budget_hold_authorization_artifacts
                UNION ALL
                SELECT 'event', event_id, artifact_index, artifact_digest,
                       'artifact'
                FROM budget_event_authorization_artifacts
                UNION ALL
                SELECT 'hold', hold_id, member_index, capability_id,
                       'revocation'
                FROM budget_hold_revocation_members
                UNION ALL
                SELECT 'event', event_id, member_index, capability_id,
                       'revocation'
                FROM budget_event_revocation_members
            ), checked AS (
                SELECT kind, owner_id, member_kind, member_index, value,
                       ROW_NUMBER() OVER (
                           PARTITION BY kind, owner_id, member_kind
                           ORDER BY member_index
                       ) - 1 AS expected_index,
                       LAG(value) OVER (
                           PARTITION BY kind, owner_id, member_kind
                           ORDER BY member_index
                       ) AS previous_value
                FROM projection_rows
            )
            SELECT kind, owner_id, member_kind FROM checked
            WHERE member_index <> expected_index
               OR previous_value >= value
               OR (
                   member_kind = 'artifact'
                   AND (
                       member_index < 0
                       OR member_index >= 8
                       OR length(value) <> 64
                       OR value GLOB '*[^0-9a-f]*'
                   )
               )
               OR (
                   member_kind = 'revocation'
                   AND (
                       member_index < 0
                       OR member_index >= 256
                       OR length(CAST(value AS BLOB)) NOT BETWEEN 1 AND 512
                   )
               )
            LIMIT 1
            "#,
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    if let Some((kind, owner_id, member_kind)) = invalid {
        return Err(BudgetStoreError::Invariant(format!(
            "budget {kind} `{owner_id}` has non-canonical {member_kind} members"
        )));
    }
    verify_revocation_set_digests(connection)?;
    let invalid_contract = connection
        .query_row(
            r#"
            WITH parents AS (
                SELECT 'hold' AS owner_kind, hold_id AS owner_id,
                       projection_kind, operation_id, revocation_set_digest,
                       expected_quota_count, expected_artifact_count,
                       has_cumulative_approval, has_revocation_commit,
                       expected_revocation_count,
                       authorization_outcome,
                       invocation_state AS invocation_before,
                       invocation_state AS invocation_after,
                       monetary_state AS monetary_before,
                       monetary_state AS monetary_after,
                       (SELECT COUNT(*) FROM budget_hold_revocation_members
                        WHERE hold_id = parent.hold_id) AS revocation_count,
                       (SELECT COUNT(*) FROM budget_hold_quota_members
                        WHERE hold_id = parent.hold_id) AS quota_count,
                       (SELECT COUNT(*) FROM budget_hold_authorization_artifacts
                        WHERE hold_id = parent.hold_id) AS artifact_count,
                       (SELECT COUNT(*) FROM budget_cumulative_approval_operations
                        WHERE hold_id = parent.hold_id) AS cumulative_count,
                       (SELECT COUNT(*) FROM budget_hold_revocation_commits
                        WHERE hold_id = parent.hold_id) AS commit_count
                FROM budget_authorization_holds AS parent
                UNION ALL
                SELECT 'event', event_id, projection_kind, operation_id,
                       revocation_set_digest, expected_quota_count,
                       expected_artifact_count, has_cumulative_approval,
                       has_revocation_commit, expected_revocation_count,
                       authorization_outcome,
                       invocation_state_before, invocation_state_after,
                       monetary_state_before, monetary_state_after,
                       (SELECT COUNT(*) FROM budget_event_revocation_members
                        WHERE event_id = parent.event_id),
                       (SELECT COUNT(*) FROM budget_event_quota_members
                        WHERE event_id = parent.event_id),
                       (SELECT COUNT(*) FROM budget_event_authorization_artifacts
                        WHERE event_id = parent.event_id),
                       (SELECT COUNT(*) FROM budget_event_cumulative_approval
                        WHERE event_id = parent.event_id),
                       (SELECT COUNT(*) FROM budget_event_revocation_commits
                        WHERE event_id = parent.event_id)
                FROM budget_mutation_events AS parent
            )
            SELECT owner_kind, owner_id FROM parents
            WHERE projection_kind NOT IN ('legacy', 'composite_v1') OR (
                projection_kind = 'composite_v1'
                AND (
                    operation_id IS NULL OR operation_id = ''
                    OR revocation_set_digest IS NULL
                    OR length(revocation_set_digest) <> 64
                    OR revocation_set_digest GLOB '*[^0-9a-f]*'
                    OR expected_revocation_count IS NULL
                    OR expected_revocation_count NOT BETWEEN 1 AND 256
                    OR expected_quota_count IS NULL
                    OR expected_quota_count NOT BETWEEN 0 AND 8
                    OR expected_artifact_count IS NULL
                    OR expected_artifact_count NOT BETWEEN 0 AND 8
                    OR has_cumulative_approval IS NULL
                    OR has_cumulative_approval NOT IN (0, 1)
                    OR has_revocation_commit IS NULL
                    OR has_revocation_commit NOT IN (0, 1)
                    OR revocation_count <> expected_revocation_count
                    OR quota_count <> expected_quota_count
                    OR artifact_count <> expected_artifact_count
                    OR cumulative_count <> has_cumulative_approval
                    OR commit_count <> has_revocation_commit
                    OR (owner_kind = 'hold' AND authorization_outcome IS NULL)
                    OR authorization_outcome NOT IN (
                        'authorized', 'approval_required', 'denied'
                    )
                    OR invocation_before IS NULL
                    OR invocation_before NOT IN (
                        'absent', 'authorized', 'captured', 'reversed', 'denied'
                    )
                    OR invocation_after IS NULL
                    OR invocation_after NOT IN (
                        'authorized', 'captured', 'reversed', 'denied'
                    )
                    OR monetary_before IS NULL
                    OR monetary_before NOT IN (
                        'none', 'exposed', 'released', 'reconciled',
                        'captured', 'reversed'
                    )
                    OR monetary_after IS NULL
                    OR monetary_after NOT IN (
                        'none', 'exposed', 'released', 'reconciled',
                        'captured', 'reversed'
                    )
                    OR (invocation_after = 'authorized'
                        AND monetary_after NOT IN ('none', 'exposed', 'released'))
                    OR (invocation_after = 'captured'
                        AND monetary_after NOT IN (
                            'none', 'exposed', 'reconciled', 'captured'
                        ))
                    OR (invocation_after = 'reversed'
                        AND monetary_after NOT IN ('none', 'reversed'))
                    OR (invocation_after = 'denied' AND monetary_after <> 'none')
                )
            ) OR (
                projection_kind = 'legacy'
                AND (
                    operation_id IS NOT NULL
                    OR revocation_set_digest IS NOT NULL
                    OR expected_revocation_count IS NOT NULL
                    OR expected_quota_count IS NOT NULL
                    OR expected_artifact_count IS NOT NULL
                    OR has_cumulative_approval IS NOT NULL
                    OR has_revocation_commit IS NOT NULL
                    OR revocation_count <> 0 OR quota_count <> 0
                    OR artifact_count <> 0 OR cumulative_count <> 0
                    OR commit_count <> 0
                )
            )
            LIMIT 1
            "#,
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((kind, owner_id)) = invalid_contract {
        return Err(BudgetStoreError::Invariant(format!(
            "budget {kind} `{owner_id}` has an incomplete composite projection contract"
        )));
    }
    let invalid_quota = connection
        .query_row(
            r#"
            WITH quotas AS (
                SELECT 'quota' AS owner_kind,
                       profile || ':' || owner_id || ':' || grant_index AS owner_id,
                       profile, owner_id AS quota_owner, grant_index, max_invocations,
                       reserved_invocations AS reserved_before,
                       captured_invocations AS captured_before,
                       reserved_invocations AS reserved_after,
                       captured_invocations AS captured_after,
                       NULL AS authorization_outcome
                FROM budget_invocation_quotas
                UNION ALL
                SELECT 'event-quota', member.event_id || ':' || member.owner_id,
                       member.profile, member.owner_id, member.grant_index,
                       member.max_invocations, member.reserved_before,
                       member.captured_before, member.reserved_after,
                       member.captured_after, event.authorization_outcome
                FROM budget_event_quota_members AS member
                JOIN budget_mutation_events AS event
                  ON event.event_id = member.event_id
            )
            SELECT owner_kind, owner_id FROM quotas
            WHERE quota_owner = '' OR max_invocations < 0
               OR (
                   max_invocations = 0
                   AND (
                       owner_kind <> 'event-quota'
                       OR authorization_outcome IS NOT 'denied'
                   )
               )
               OR reserved_before < 0 OR captured_before < 0
               OR reserved_after < 0 OR captured_after < 0
               OR reserved_before > max_invocations
               OR captured_before > max_invocations - reserved_before
               OR reserved_after > max_invocations
               OR captured_after > max_invocations - reserved_after
               OR NOT (
                   (profile = 'chio.grant-invocation.v1' AND grant_index >= 0)
                   OR (profile IN (
                       'chio.aggregate-capability-invocation.v1',
                       'chio.aggregate-family-invocation.v1',
                       'chio.broker-capability-execution.v1'
                   ) AND grant_index = -1)
               )
            LIMIT 1
            "#,
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((kind, owner_id)) = invalid_quota {
        return Err(BudgetStoreError::Invariant(format!(
            "budget {kind} `{owner_id}` is outside durable quota bounds"
        )));
    }
    let invalid_approval = connection
        .query_row(
            r#"
            SELECT owner_kind, owner_id FROM (
                SELECT 'operation' AS owner_kind, operation_id AS owner_id,
                       approval_set_digest AS digest
                FROM budget_cumulative_approval_operations
                UNION ALL
                SELECT 'event', event_id, cumulative_approval_set_digest
                FROM budget_mutation_events
            )
            WHERE digest IS NOT NULL
              AND (
                  length(digest) <> 64
                  OR digest GLOB '*[^0-9a-f]*'
              )
            LIMIT 1
            "#,
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((kind, owner_id)) = invalid_approval {
        return Err(BudgetStoreError::Invariant(format!(
            "budget {kind} `{owner_id}` has a non-canonical approval set digest"
        )));
    }
    let invalid_commit = connection
        .query_row(
            r#"
            SELECT owner_kind, owner_id FROM (
                SELECT 'hold' AS owner_kind, hold_id AS owner_id,
                       authority_id, lease_id, lease_epoch,
                       guarantee_level, commit_index
                FROM budget_hold_revocation_commits
                UNION ALL
                SELECT 'event', event_id, authority_id, lease_id,
                       lease_epoch, guarantee_level, commit_index
                FROM budget_event_revocation_commits
            )
            WHERE authority_id = ''
               OR lease_id = ''
               OR lease_epoch <= 0
               OR commit_index <= 0
               OR guarantee_level NOT IN (
                   'single_node_atomic', 'ha_linearizable'
               )
            LIMIT 1
            "#,
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((kind, owner_id)) = invalid_commit {
        return Err(BudgetStoreError::Invariant(format!(
            "budget {kind} `{owner_id}` has invalid revocation commit metadata"
        )));
    }
    let invalid_supplemental = connection
        .query_row(
            r#"
            WITH supplemental AS (
                SELECT 'hold' AS owner_kind, hold_id AS owner_id,
                       supplemental_verifier_id AS verifier_id,
                       supplemental_verifier_config_digest AS config_digest,
                       supplemental_artifact_digest AS artifact_digest,
                       supplemental_expires_at AS expires_at
                FROM budget_authorization_holds
                UNION ALL
                SELECT 'event', event_id, supplemental_verifier_id,
                       supplemental_verifier_config_digest,
                       supplemental_artifact_digest, supplemental_expires_at
                FROM budget_mutation_events
            )
            SELECT owner_kind, owner_id FROM supplemental AS value
            WHERE (
                    verifier_id IS NOT NULL
                    OR config_digest IS NOT NULL
                    OR artifact_digest IS NOT NULL
                    OR expires_at IS NOT NULL
                  )
              AND (
                    verifier_id IS NULL OR verifier_id = ''
                    OR config_digest IS NULL
                    OR length(config_digest) <> 64
                    OR config_digest GLOB '*[^0-9a-f]*'
                    OR artifact_digest IS NULL
                    OR length(artifact_digest) <> 64
                    OR artifact_digest GLOB '*[^0-9a-f]*'
                    OR expires_at IS NULL OR expires_at <= 0
                    OR NOT EXISTS (
                        SELECT 1 FROM budget_hold_authorization_artifacts
                        WHERE value.owner_kind = 'hold'
                          AND hold_id = value.owner_id
                          AND artifact_digest = value.artifact_digest
                        UNION ALL
                        SELECT 1 FROM budget_event_authorization_artifacts
                        WHERE value.owner_kind = 'event'
                          AND event_id = value.owner_id
                          AND artifact_digest = value.artifact_digest
                    )
                    OR NOT EXISTS (
                        SELECT 1 FROM budget_hold_revocation_commits
                        WHERE value.owner_kind = 'hold'
                          AND hold_id = value.owner_id
                        UNION ALL
                        SELECT 1 FROM budget_event_revocation_commits
                        WHERE value.owner_kind = 'event'
                          AND event_id = value.owner_id
                    )
                  )
            LIMIT 1
            "#,
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((kind, owner_id)) = invalid_supplemental {
        return Err(BudgetStoreError::Invariant(format!(
            "budget {kind} `{owner_id}` has an incomplete supplemental authority binding"
        )));
    }
    state_invariants::verify_budget_state_invariants(connection)?;
    Ok(())
}

fn verify_revocation_set_digests(connection: &Connection) -> Result<(), BudgetStoreError> {
    for (kind, parent, id_column, members) in [
        (
            "hold",
            "budget_authorization_holds",
            "hold_id",
            "budget_hold_revocation_members",
        ),
        (
            "event",
            "budget_mutation_events",
            "event_id",
            "budget_event_revocation_members",
        ),
    ] {
        let parents = {
            let mut statement = connection.prepare(&format!(
                "SELECT {id_column}, revocation_set_digest FROM {parent} WHERE projection_kind = 'composite_v1'"
            ))?;
            let values = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            values
        };
        for (identity, digest) in parents {
            let ids = {
                let mut statement = connection.prepare(&format!(
                    "SELECT capability_id FROM {members} WHERE {id_column} = ?1 ORDER BY member_index"
                ))?;
                let values = statement
                    .query_map(params![&identity], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                values
            };
            let digest = digest.ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "budget {kind} `{identity}` lost its revocation-set digest"
                ))
            })?;
            CanonicalRevocationSet::from_canonical_parts(ids, digest).map_err(|error| {
                BudgetStoreError::Invariant(format!(
                    "budget {kind} `{identity}` has an invalid revocation-set projection: {error}"
                ))
            })?;
        }
    }
    Ok(())
}
