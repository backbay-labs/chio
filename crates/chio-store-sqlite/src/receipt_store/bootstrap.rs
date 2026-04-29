use super::*;

fn configure_sqlite_connection(connection: &mut Connection) -> Result<(), ReceiptStoreError> {
    connection.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = FULL;
        PRAGMA busy_timeout = 5000;
        "#,
    )?;
    Ok(())
}

impl SqliteReceiptStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReceiptStoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut connection = Connection::open(path)?;
        configure_sqlite_connection(&mut connection)?;
        connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS chio_tool_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                capability_id TEXT NOT NULL,
                subject_key TEXT,
                issuer_key TEXT,
                grant_index INTEGER,
                tool_server TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision_kind TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_timestamp
                ON chio_tool_receipts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_capability
                ON chio_tool_receipts(capability_id);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_subject
                ON chio_tool_receipts(subject_key);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_grant
                ON chio_tool_receipts(capability_id, grant_index);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_tool
                ON chio_tool_receipts(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_decision
                ON chio_tool_receipts(decision_kind);

            CREATE TABLE IF NOT EXISTS settlement_reconciliations (
                receipt_id TEXT PRIMARY KEY REFERENCES chio_tool_receipts(receipt_id) ON DELETE CASCADE,
                reconciliation_state TEXT NOT NULL,
                note TEXT,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_settlement_reconciliations_updated_at
                ON settlement_reconciliations(updated_at);

            CREATE TABLE IF NOT EXISTS metered_billing_reconciliations (
                receipt_id TEXT PRIMARY KEY REFERENCES chio_tool_receipts(receipt_id) ON DELETE CASCADE,
                adapter_kind TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                observed_units INTEGER NOT NULL,
                billed_cost_units INTEGER NOT NULL,
                billed_cost_currency TEXT NOT NULL,
                evidence_sha256 TEXT,
                recorded_at INTEGER NOT NULL,
                reconciliation_state TEXT NOT NULL,
                note TEXT,
                updated_at INTEGER NOT NULL,
                UNIQUE (adapter_kind, evidence_id)
            );
            CREATE INDEX IF NOT EXISTS idx_metered_billing_reconciliations_updated_at
                ON metered_billing_reconciliations(updated_at);

            CREATE TABLE IF NOT EXISTS underwriting_decisions (
                decision_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                capability_id TEXT,
                subject_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                outcome TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                review_state TEXT NOT NULL,
                risk_class TEXT NOT NULL,
                supersedes_decision_id TEXT REFERENCES underwriting_decisions(decision_id),
                superseded_by_decision_id TEXT REFERENCES underwriting_decisions(decision_id),
                premium_units INTEGER,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_issued_at
                ON underwriting_decisions(issued_at);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_capability
                ON underwriting_decisions(capability_id);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_subject
                ON underwriting_decisions(subject_key);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_tool
                ON underwriting_decisions(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_outcome
                ON underwriting_decisions(outcome);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_lifecycle
                ON underwriting_decisions(lifecycle_state);

            CREATE TABLE IF NOT EXISTS underwriting_appeals (
                appeal_id TEXT PRIMARY KEY,
                decision_id TEXT NOT NULL REFERENCES underwriting_decisions(decision_id) ON DELETE CASCADE,
                requested_by TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL,
                note TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                resolved_by TEXT,
                replacement_decision_id TEXT REFERENCES underwriting_decisions(decision_id)
            );
            CREATE INDEX IF NOT EXISTS idx_underwriting_appeals_decision
                ON underwriting_appeals(decision_id);
            CREATE INDEX IF NOT EXISTS idx_underwriting_appeals_status
                ON underwriting_appeals(status);
            CREATE INDEX IF NOT EXISTS idx_underwriting_appeals_updated_at
                ON underwriting_appeals(updated_at);

            CREATE TABLE IF NOT EXISTS credit_facilities (
                facility_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                capability_id TEXT,
                subject_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                disposition TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                supersedes_facility_id TEXT REFERENCES credit_facilities(facility_id),
                superseded_by_facility_id TEXT REFERENCES credit_facilities(facility_id),
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_issued_at
                ON credit_facilities(issued_at);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_expires_at
                ON credit_facilities(expires_at);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_capability
                ON credit_facilities(capability_id);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_subject
                ON credit_facilities(subject_key);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_tool
                ON credit_facilities(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_disposition
                ON credit_facilities(disposition);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_lifecycle
                ON credit_facilities(lifecycle_state);

            CREATE TABLE IF NOT EXISTS credit_bonds (
                bond_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                facility_id TEXT,
                capability_id TEXT,
                subject_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                disposition TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                supersedes_bond_id TEXT REFERENCES credit_bonds(bond_id),
                superseded_by_bond_id TEXT REFERENCES credit_bonds(bond_id),
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_issued_at
                ON credit_bonds(issued_at);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_expires_at
                ON credit_bonds(expires_at);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_facility
                ON credit_bonds(facility_id);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_capability
                ON credit_bonds(capability_id);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_subject
                ON credit_bonds(subject_key);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_tool
                ON credit_bonds(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_disposition
                ON credit_bonds(disposition);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_lifecycle
                ON credit_bonds(lifecycle_state);

            CREATE TABLE IF NOT EXISTS liability_providers (
                provider_record_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                provider_id TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                supersedes_provider_record_id TEXT REFERENCES liability_providers(provider_record_id),
                superseded_by_provider_record_id TEXT REFERENCES liability_providers(provider_record_id),
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_providers_issued_at
                ON liability_providers(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_providers_provider_id
                ON liability_providers(provider_id);
            CREATE INDEX IF NOT EXISTS idx_liability_providers_lifecycle
                ON liability_providers(lifecycle_state);

            CREATE TABLE IF NOT EXISTS liability_quote_requests (
                quote_request_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                provider_id TEXT NOT NULL,
                jurisdiction TEXT NOT NULL,
                coverage_class TEXT NOT NULL,
                currency TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_quote_requests_issued_at
                ON liability_quote_requests(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_quote_requests_provider
                ON liability_quote_requests(provider_id);
            CREATE INDEX IF NOT EXISTS idx_liability_quote_requests_subject
                ON liability_quote_requests(subject_key);

            CREATE TABLE IF NOT EXISTS liability_quote_responses (
                quote_response_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                quote_request_id TEXT NOT NULL REFERENCES liability_quote_requests(quote_request_id),
                provider_id TEXT NOT NULL,
                disposition TEXT NOT NULL,
                expires_at INTEGER,
                supersedes_quote_response_id TEXT REFERENCES liability_quote_responses(quote_response_id),
                superseded_by_quote_response_id TEXT REFERENCES liability_quote_responses(quote_response_id),
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_quote_responses_issued_at
                ON liability_quote_responses(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_quote_responses_request
                ON liability_quote_responses(quote_request_id);
            CREATE INDEX IF NOT EXISTS idx_liability_quote_responses_provider
                ON liability_quote_responses(provider_id);

            CREATE TABLE IF NOT EXISTS liability_pricing_authorities (
                authority_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                quote_request_id TEXT NOT NULL REFERENCES liability_quote_requests(quote_request_id),
                provider_id TEXT NOT NULL,
                facility_id TEXT NOT NULL,
                underwriting_decision_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_pricing_authorities_request
                ON liability_pricing_authorities(quote_request_id);
            CREATE INDEX IF NOT EXISTS idx_liability_pricing_authorities_provider
                ON liability_pricing_authorities(provider_id);
            CREATE INDEX IF NOT EXISTS idx_liability_pricing_authorities_facility
                ON liability_pricing_authorities(facility_id);

            CREATE TABLE IF NOT EXISTS liability_placements (
                placement_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                quote_request_id TEXT NOT NULL REFERENCES liability_quote_requests(quote_request_id),
                quote_response_id TEXT NOT NULL REFERENCES liability_quote_responses(quote_response_id),
                provider_id TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_placements_request
                ON liability_placements(quote_request_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_placements_response
                ON liability_placements(quote_response_id);
            CREATE INDEX IF NOT EXISTS idx_liability_placements_provider
                ON liability_placements(provider_id);

            CREATE TABLE IF NOT EXISTS liability_bound_coverages (
                bound_coverage_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                quote_request_id TEXT NOT NULL REFERENCES liability_quote_requests(quote_request_id),
                quote_response_id TEXT NOT NULL REFERENCES liability_quote_responses(quote_response_id),
                placement_id TEXT NOT NULL REFERENCES liability_placements(placement_id),
                provider_id TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_bound_coverages_request
                ON liability_bound_coverages(quote_request_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_bound_coverages_response
                ON liability_bound_coverages(quote_response_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_bound_coverages_placement
                ON liability_bound_coverages(placement_id);
            CREATE INDEX IF NOT EXISTS idx_liability_bound_coverages_provider
                ON liability_bound_coverages(provider_id);

            CREATE TABLE IF NOT EXISTS liability_auto_bind_decisions (
                decision_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                quote_request_id TEXT NOT NULL REFERENCES liability_quote_requests(quote_request_id),
                quote_response_id TEXT NOT NULL REFERENCES liability_quote_responses(quote_response_id),
                authority_id TEXT NOT NULL REFERENCES liability_pricing_authorities(authority_id),
                provider_id TEXT NOT NULL,
                disposition TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_auto_bind_decisions_response
                ON liability_auto_bind_decisions(quote_response_id);
            CREATE INDEX IF NOT EXISTS idx_liability_auto_bind_decisions_request
                ON liability_auto_bind_decisions(quote_request_id);
            CREATE INDEX IF NOT EXISTS idx_liability_auto_bind_decisions_authority
                ON liability_auto_bind_decisions(authority_id);

            CREATE TABLE IF NOT EXISTS liability_claim_packages (
                claim_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                provider_id TEXT NOT NULL,
                policy_number TEXT NOT NULL,
                jurisdiction TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                claim_event_at INTEGER NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_packages_issued_at
                ON liability_claim_packages(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_packages_provider
                ON liability_claim_packages(provider_id);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_packages_policy_number
                ON liability_claim_packages(policy_number);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_packages_subject
                ON liability_claim_packages(subject_key);

            CREATE TABLE IF NOT EXISTS liability_claim_responses (
                claim_response_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                provider_id TEXT NOT NULL,
                disposition TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_responses_issued_at
                ON liability_claim_responses(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_responses_provider
                ON liability_claim_responses(provider_id);

            CREATE TABLE IF NOT EXISTS liability_claim_disputes (
                dispute_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                claim_response_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_responses(claim_response_id),
                provider_id TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_disputes_issued_at
                ON liability_claim_disputes(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_disputes_provider
                ON liability_claim_disputes(provider_id);

            CREATE TABLE IF NOT EXISTS liability_claim_adjudications (
                adjudication_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                dispute_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_disputes(dispute_id),
                outcome TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_adjudications_issued_at
                ON liability_claim_adjudications(issued_at);

            CREATE TABLE IF NOT EXISTS liability_claim_payout_instructions (
                payout_instruction_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                adjudication_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_adjudications(adjudication_id),
                payout_amount_units INTEGER NOT NULL,
                payout_amount_currency TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_payout_instructions_issued_at
                ON liability_claim_payout_instructions(issued_at);

            CREATE TABLE IF NOT EXISTS liability_claim_payout_receipts (
                payout_receipt_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                payout_instruction_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_payout_instructions(payout_instruction_id),
                reconciliation_state TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_payout_receipts_issued_at
                ON liability_claim_payout_receipts(issued_at);

            CREATE TABLE IF NOT EXISTS liability_claim_settlement_instructions (
                settlement_instruction_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                payout_receipt_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_payout_receipts(payout_receipt_id),
                settlement_kind TEXT NOT NULL,
                payer_role TEXT NOT NULL,
                payer_id TEXT NOT NULL,
                payee_role TEXT NOT NULL,
                payee_id TEXT NOT NULL,
                settlement_amount_units INTEGER NOT NULL,
                settlement_amount_currency TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_settlement_instructions_issued_at
                ON liability_claim_settlement_instructions(issued_at);

            CREATE TABLE IF NOT EXISTS liability_claim_settlement_receipts (
                settlement_receipt_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                settlement_instruction_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_settlement_instructions(settlement_instruction_id),
                reconciliation_state TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_settlement_receipts_issued_at
                ON liability_claim_settlement_receipts(issued_at);

            CREATE TABLE IF NOT EXISTS credit_loss_lifecycle (
                event_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                bond_id TEXT NOT NULL REFERENCES credit_bonds(bond_id),
                facility_id TEXT,
                capability_id TEXT,
                subject_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                event_kind TEXT NOT NULL,
                projected_bond_lifecycle_state TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_issued_at
                ON credit_loss_lifecycle(issued_at);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_bond
                ON credit_loss_lifecycle(bond_id);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_facility
                ON credit_loss_lifecycle(facility_id);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_capability
                ON credit_loss_lifecycle(capability_id);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_subject
                ON credit_loss_lifecycle(subject_key);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_tool
                ON credit_loss_lifecycle(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_kind
                ON credit_loss_lifecycle(event_kind);

            CREATE TABLE IF NOT EXISTS chio_child_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                parent_request_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                operation_kind TEXT NOT NULL,
                terminal_state TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                outcome_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_chio_child_receipts_timestamp
                ON chio_child_receipts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_chio_child_receipts_session
                ON chio_child_receipts(session_id);
            CREATE INDEX IF NOT EXISTS idx_chio_child_receipts_parent
                ON chio_child_receipts(parent_request_id);
            CREATE INDEX IF NOT EXISTS idx_chio_child_receipts_request
                ON chio_child_receipts(request_id);

            CREATE TABLE IF NOT EXISTS claim_receipt_log_entries (
                entry_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                receipt_kind TEXT NOT NULL,
                source_seq INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                capability_id TEXT,
                session_id TEXT,
                parent_request_id TEXT,
                request_id TEXT,
                subject_key TEXT,
                issuer_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                raw_json TEXT NOT NULL,
                CHECK (receipt_kind IN ('tool_receipt', 'child_receipt')),
                CHECK (
                    (receipt_kind = 'tool_receipt'
                        AND capability_id IS NOT NULL
                        AND session_id IS NULL
                        AND parent_request_id IS NULL
                        AND request_id IS NULL
                        AND tool_server IS NOT NULL
                        AND tool_name IS NOT NULL)
                    OR
                    (receipt_kind = 'child_receipt'
                        AND capability_id IS NULL
                        AND session_id IS NOT NULL
                        AND parent_request_id IS NOT NULL
                        AND request_id IS NOT NULL
                        AND tool_server IS NULL
                        AND tool_name IS NULL)
                )
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_claim_receipt_log_kind_source
                ON claim_receipt_log_entries(receipt_kind, source_seq);
            CREATE INDEX IF NOT EXISTS idx_claim_receipt_log_timestamp
                ON claim_receipt_log_entries(timestamp, entry_seq);
            CREATE INDEX IF NOT EXISTS idx_claim_receipt_log_tool
                ON claim_receipt_log_entries(tool_server, tool_name, timestamp)
                WHERE receipt_kind = 'tool_receipt';
            CREATE INDEX IF NOT EXISTS idx_claim_receipt_log_child_request
                ON claim_receipt_log_entries(session_id, request_id, timestamp)
                WHERE receipt_kind = 'child_receipt';

            CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_project_claim_log_entry
            AFTER INSERT ON chio_tool_receipts
            BEGIN
                INSERT OR IGNORE INTO claim_receipt_log_entries (
                    receipt_id,
                    receipt_kind,
                    source_seq,
                    timestamp,
                    capability_id,
                    session_id,
                    parent_request_id,
                    request_id,
                    subject_key,
                    issuer_key,
                    tool_server,
                    tool_name,
                    raw_json
                ) VALUES (
                    NEW.receipt_id,
                    'tool_receipt',
                    NEW.seq,
                    NEW.timestamp,
                    NEW.capability_id,
                    NULL,
                    NULL,
                    NULL,
                    NEW.subject_key,
                    NEW.issuer_key,
                    NEW.tool_server,
                    NEW.tool_name,
                    NEW.raw_json
                );
            END;

            CREATE TRIGGER IF NOT EXISTS chio_child_receipts_project_claim_log_entry
            AFTER INSERT ON chio_child_receipts
            BEGIN
                INSERT OR IGNORE INTO claim_receipt_log_entries (
                    receipt_id,
                    receipt_kind,
                    source_seq,
                    timestamp,
                    capability_id,
                    session_id,
                    parent_request_id,
                    request_id,
                    subject_key,
                    issuer_key,
                    tool_server,
                    tool_name,
                    raw_json
                ) VALUES (
                    NEW.receipt_id,
                    'child_receipt',
                    NEW.seq,
                    NEW.timestamp,
                    NULL,
                    NEW.session_id,
                    NEW.parent_request_id,
                    NEW.request_id,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    NEW.raw_json
                );
            END;

            CREATE TABLE IF NOT EXISTS session_anchors (
                anchor_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                auth_context_fingerprint TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                supersedes_anchor_id TEXT REFERENCES session_anchors(anchor_id),
                is_current INTEGER NOT NULL DEFAULT 1,
                source_kind TEXT NOT NULL,
                json_sha256 TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_session_anchors_session
                ON session_anchors(session_id, issued_at DESC);
            CREATE INDEX IF NOT EXISTS idx_session_anchors_supersedes
                ON session_anchors(supersedes_anchor_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_session_anchors_current
                ON session_anchors(session_id)
                WHERE is_current = 1;

            CREATE TABLE IF NOT EXISTS request_lineage (
                session_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                parent_request_id TEXT,
                session_anchor_id TEXT REFERENCES session_anchors(anchor_id),
                recorded_at INTEGER NOT NULL,
                request_fingerprint TEXT,
                source_kind TEXT NOT NULL,
                json_sha256 TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                PRIMARY KEY (session_id, request_id)
            );
            CREATE INDEX IF NOT EXISTS idx_request_lineage_parent
                ON request_lineage(session_id, parent_request_id);
            CREATE INDEX IF NOT EXISTS idx_request_lineage_anchor
                ON request_lineage(session_anchor_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_request_lineage_fingerprint
                ON request_lineage(session_id, COALESCE(session_anchor_id, ''), request_fingerprint)
                WHERE request_fingerprint IS NOT NULL;

            CREATE TABLE IF NOT EXISTS receipt_lineage_statements (
                receipt_id TEXT PRIMARY KEY,
                statement_id TEXT,
                request_id TEXT,
                session_id TEXT,
                session_anchor_id TEXT REFERENCES session_anchors(anchor_id),
                chain_id TEXT,
                parent_request_id TEXT,
                parent_receipt_id TEXT,
                evidence_class TEXT,
                evidence_sources_json TEXT,
                verified_session_anchor INTEGER NOT NULL DEFAULT 0,
                verified_parent_request INTEGER NOT NULL DEFAULT 0,
                verified_parent_receipt INTEGER NOT NULL DEFAULT 0,
                replay_protected INTEGER NOT NULL DEFAULT 0,
                recorded_at INTEGER NOT NULL,
                source_kind TEXT NOT NULL,
                json_sha256 TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_receipt_lineage_request
                ON receipt_lineage_statements(session_id, request_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_receipt_lineage_statement_id
                ON receipt_lineage_statements(statement_id)
                WHERE statement_id IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_receipt_lineage_parent_request
                ON receipt_lineage_statements(session_id, parent_request_id);
            CREATE INDEX IF NOT EXISTS idx_receipt_lineage_parent_receipt
                ON receipt_lineage_statements(parent_receipt_id);
            CREATE INDEX IF NOT EXISTS idx_receipt_lineage_anchor
                ON receipt_lineage_statements(session_anchor_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_receipt_lineage_request_anchor
                ON receipt_lineage_statements(session_id, COALESCE(session_anchor_id, ''), request_id)
                WHERE session_id IS NOT NULL
                  AND request_id IS NOT NULL;

            CREATE TABLE IF NOT EXISTS kernel_checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checkpoint_seq INTEGER NOT NULL UNIQUE,
                batch_start_seq INTEGER NOT NULL,
                batch_end_seq INTEGER NOT NULL,
                tree_size INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                statement_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                kernel_key TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_kernel_checkpoints_batch_end
                ON kernel_checkpoints(batch_end_seq);

            CREATE TABLE IF NOT EXISTS checkpoint_tree_heads (
                checkpoint_seq INTEGER PRIMARY KEY
                    REFERENCES kernel_checkpoints(checkpoint_seq) ON DELETE CASCADE,
                batch_start_seq INTEGER NOT NULL,
                batch_end_seq INTEGER NOT NULL,
                tree_size INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                kernel_key TEXT NOT NULL,
                previous_checkpoint_sha256 TEXT,
                statement_json TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_checkpoint_tree_heads_tree_size
                ON checkpoint_tree_heads(tree_size);
            CREATE INDEX IF NOT EXISTS idx_checkpoint_tree_heads_previous
                ON checkpoint_tree_heads(previous_checkpoint_sha256);

            CREATE TABLE IF NOT EXISTS checkpoint_predecessor_witnesses (
                predecessor_checkpoint_seq INTEGER NOT NULL
                    REFERENCES checkpoint_tree_heads(checkpoint_seq) ON DELETE CASCADE,
                witness_checkpoint_seq INTEGER PRIMARY KEY
                    REFERENCES checkpoint_tree_heads(checkpoint_seq) ON DELETE CASCADE,
                previous_checkpoint_sha256 TEXT NOT NULL,
                witnessed_at INTEGER NOT NULL,
                witness_statement_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_checkpoint_predecessor_witnesses_predecessor
                ON checkpoint_predecessor_witnesses(predecessor_checkpoint_seq);
            CREATE INDEX IF NOT EXISTS idx_checkpoint_predecessor_witnesses_previous
                ON checkpoint_predecessor_witnesses(previous_checkpoint_sha256);

            CREATE TABLE IF NOT EXISTS checkpoint_publication_metadata (
                checkpoint_seq INTEGER PRIMARY KEY
                    REFERENCES kernel_checkpoints(checkpoint_seq) ON DELETE CASCADE,
                publication_schema TEXT NOT NULL,
                merkle_root TEXT NOT NULL,
                published_at INTEGER NOT NULL,
                kernel_key TEXT NOT NULL,
                log_tree_size INTEGER NOT NULL,
                entry_start_seq INTEGER NOT NULL,
                entry_end_seq INTEGER NOT NULL,
                previous_checkpoint_sha256 TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_checkpoint_publication_metadata_published_at
                ON checkpoint_publication_metadata(published_at);
            CREATE INDEX IF NOT EXISTS idx_checkpoint_publication_metadata_log_tree_size
                ON checkpoint_publication_metadata(log_tree_size);
            CREATE INDEX IF NOT EXISTS idx_checkpoint_publication_metadata_previous
                ON checkpoint_publication_metadata(previous_checkpoint_sha256);

            CREATE TABLE IF NOT EXISTS checkpoint_publication_trust_anchor_bindings (
                checkpoint_seq INTEGER PRIMARY KEY
                    REFERENCES kernel_checkpoints(checkpoint_seq) ON DELETE CASCADE,
                binding_json TEXT NOT NULL
            );

            CREATE TRIGGER IF NOT EXISTS kernel_checkpoints_project_tree_head
            AFTER INSERT ON kernel_checkpoints
            BEGIN
                INSERT OR IGNORE INTO checkpoint_tree_heads (
                    checkpoint_seq,
                    batch_start_seq,
                    batch_end_seq,
                    tree_size,
                    merkle_root,
                    issued_at,
                    kernel_key,
                    previous_checkpoint_sha256,
                    statement_json,
                    signature
                ) VALUES (
                    NEW.checkpoint_seq,
                    NEW.batch_start_seq,
                    NEW.batch_end_seq,
                    NEW.tree_size,
                    NEW.merkle_root,
                    NEW.issued_at,
                    NEW.kernel_key,
                    CAST(json_extract(NEW.statement_json, '$.previous_checkpoint_sha256') AS TEXT),
                    NEW.statement_json,
                    NEW.signature
                );

                INSERT OR IGNORE INTO checkpoint_predecessor_witnesses (
                    predecessor_checkpoint_seq,
                    witness_checkpoint_seq,
                    previous_checkpoint_sha256,
                    witnessed_at,
                    witness_statement_json
                )
                SELECT
                    NEW.checkpoint_seq - 1,
                    NEW.checkpoint_seq,
                    CAST(json_extract(NEW.statement_json, '$.previous_checkpoint_sha256') AS TEXT),
                    NEW.issued_at,
                    NEW.statement_json
                WHERE json_extract(NEW.statement_json, '$.previous_checkpoint_sha256') IS NOT NULL;

                INSERT OR IGNORE INTO checkpoint_publication_metadata (
                    checkpoint_seq,
                    publication_schema,
                    merkle_root,
                    published_at,
                    kernel_key,
                    log_tree_size,
                    entry_start_seq,
                    entry_end_seq,
                    previous_checkpoint_sha256
                ) VALUES (
                    NEW.checkpoint_seq,
                    'chio.checkpoint_publication.v1',
                    NEW.merkle_root,
                    NEW.issued_at,
                    NEW.kernel_key,
                    NEW.batch_end_seq,
                    NEW.batch_start_seq,
                    NEW.batch_end_seq,
                    CAST(json_extract(NEW.statement_json, '$.previous_checkpoint_sha256') AS TEXT)
                );
            END;

            CREATE TABLE IF NOT EXISTS capability_lineage (
                capability_id        TEXT PRIMARY KEY,
                subject_key          TEXT NOT NULL,
                issuer_key           TEXT NOT NULL,
                issued_at            INTEGER NOT NULL,
                expires_at           INTEGER NOT NULL,
                grants_json          TEXT NOT NULL,
                delegation_depth     INTEGER NOT NULL DEFAULT 0,
                parent_capability_id TEXT REFERENCES capability_lineage(capability_id)
            );
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_subject
                ON capability_lineage(subject_key);
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_issuer
                ON capability_lineage(issuer_key);
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_issued_at
                ON capability_lineage(issued_at);
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_parent
                ON capability_lineage(parent_capability_id);

            CREATE TABLE IF NOT EXISTS federated_lineage_bridges (
                local_capability_id TEXT PRIMARY KEY REFERENCES capability_lineage(capability_id) ON DELETE CASCADE,
                parent_capability_id TEXT NOT NULL,
                share_id TEXT REFERENCES federated_evidence_shares(share_id)
            );
            CREATE INDEX IF NOT EXISTS idx_federated_lineage_bridges_parent
                ON federated_lineage_bridges(parent_capability_id);

            CREATE TABLE IF NOT EXISTS federated_evidence_shares (
                share_id TEXT PRIMARY KEY,
                manifest_hash TEXT NOT NULL,
                imported_at INTEGER NOT NULL,
                exported_at INTEGER NOT NULL,
                issuer TEXT NOT NULL,
                partner TEXT NOT NULL,
                signer_public_key TEXT NOT NULL,
                require_proofs INTEGER NOT NULL DEFAULT 0,
                query_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_federated_evidence_shares_imported_at
                ON federated_evidence_shares(imported_at);

            CREATE TABLE IF NOT EXISTS federated_share_tool_receipts (
                share_id TEXT NOT NULL REFERENCES federated_evidence_shares(share_id) ON DELETE CASCADE,
                seq INTEGER NOT NULL,
                receipt_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                capability_id TEXT NOT NULL,
                subject_key TEXT,
                issuer_key TEXT,
                raw_json TEXT NOT NULL,
                PRIMARY KEY (share_id, seq),
                UNIQUE (share_id, receipt_id)
            );
            CREATE INDEX IF NOT EXISTS idx_federated_share_receipts_capability
                ON federated_share_tool_receipts(capability_id);
            CREATE INDEX IF NOT EXISTS idx_federated_share_receipts_subject
                ON federated_share_tool_receipts(subject_key);

            CREATE TABLE IF NOT EXISTS federated_share_capability_lineage (
                share_id TEXT NOT NULL REFERENCES federated_evidence_shares(share_id) ON DELETE CASCADE,
                capability_id TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                issuer_key TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                grants_json TEXT NOT NULL,
                delegation_depth INTEGER NOT NULL DEFAULT 0,
                parent_capability_id TEXT,
                PRIMARY KEY (share_id, capability_id)
            );
            CREATE INDEX IF NOT EXISTS idx_federated_share_lineage_capability
                ON federated_share_capability_lineage(capability_id);
            CREATE INDEX IF NOT EXISTS idx_federated_share_lineage_subject
                ON federated_share_capability_lineage(subject_key);
            "#,
        )?;
        ensure_tool_receipt_attribution_columns(&connection)?;
        super::support::ensure_receipt_lineage_statement_columns(&connection)?;
        super::support::drop_transparency_projection_guards(&connection)?;
        let backfill_result = (|| -> Result<(), ReceiptStoreError> {
            backfill_tool_receipt_attribution_columns(&connection)?;
            super::support::backfill_provenance_lineage_tables(&mut connection)?;
            super::support::backfill_claim_receipt_log_entries(&mut connection)?;
            super::support::backfill_checkpoint_transparency_projections(&mut connection)?;
            Ok(())
        })();
        let guard_result = super::support::ensure_transparency_projection_guards(&connection);
        match (backfill_result, guard_result) {
            (Ok(()), Ok(())) => {}
            (Err(error), Ok(())) => return Err(error),
            (Ok(()), Err(error)) => return Err(error),
            (Err(backfill_error), Err(guard_error)) => {
                return Err(ReceiptStoreError::Canonical(format!(
                    "receipt projection backfill failed ({backfill_error}); restoring immutability guards also failed ({guard_error})"
                )));
            }
        }

        drop(connection);

        let manager = SqliteConnectionManager::file(path).with_init(|connection| {
            configure_sqlite_connection(connection).map_err(|error| match error {
                ReceiptStoreError::Sqlite(error) => error,
                other => rusqlite::Error::InvalidParameterName(other.to_string()),
            })
        });
        let pool = Pool::builder()
            .max_size(8)
            .build(manager)
            .map_err(|error| ReceiptStoreError::Pool(error.to_string()))?;

        Ok(Self {
            pool,
            strict_tenant_isolation: std::sync::atomic::AtomicBool::new(true),
        })
    }

    pub fn tool_receipt_count(&self) -> Result<u64, ReceiptStoreError> {
        let count =
            self.connection()?
                .query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
                    row.get::<_, i64>(0)
                })?;
        sqlite_u64(count, "chio_tool_receipts count")
    }

    pub fn child_receipt_count(&self) -> Result<u64, ReceiptStoreError> {
        let count = self.connection()?.query_row(
            "SELECT COUNT(*) FROM chio_child_receipts",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        sqlite_u64(count, "chio_child_receipts count")
    }

    pub(crate) fn load_underwriting_appeals_by_decision(
        &self,
    ) -> Result<BTreeMap<String, Vec<UnderwritingAppealRecord>>, ReceiptStoreError> {
        let mut appeals_by_decision = BTreeMap::new();
        let connection = self.connection()?;
        for appeal in load_underwriting_appeal_rows(&connection)? {
            appeals_by_decision
                .entry(appeal.decision_id.clone())
                .or_insert_with(Vec::new)
                .push(appeal);
        }
        Ok(appeals_by_decision)
    }

    pub fn list_tool_receipts(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        tool_server: Option<&str>,
        tool_name: Option<&str>,
        decision_kind: Option<&str>,
    ) -> Result<Vec<ChioReceipt>, ReceiptStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT seq, raw_json
            FROM chio_tool_receipts
            WHERE (?1 IS NULL OR capability_id = ?1)
              AND (?2 IS NULL OR tool_server = ?2)
              AND (?3 IS NULL OR tool_name = ?3)
              AND (?4 IS NULL OR decision_kind = ?4)
            ORDER BY seq DESC
            LIMIT ?5
            "#,
        )?;
        let rows = statement.query_map(
            params![
                capability_id,
                tool_server,
                tool_name,
                decision_kind,
                limit as i64,
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?;

        rows.map(|row| {
            let (seq, raw_json) = row?;
            decode_verified_chio_receipt(
                &raw_json,
                "persisted tool receipt",
                Some(seq.max(0) as u64),
            )
        })
        .collect()
    }

    /// List all tool receipts attributed to a given subject public key.
    ///
    /// Uses the persisted `subject_key` column when present and falls back to
    /// the capability lineage join for older rows.
    pub fn list_tool_receipts_for_subject(
        &self,
        subject_key: &str,
    ) -> Result<Vec<ChioReceipt>, ReceiptStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT r.seq, r.raw_json
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE COALESCE(r.subject_key, cl.subject_key) = ?1
            ORDER BY r.timestamp ASC, r.seq ASC
            "#,
        )?;
        let rows = statement.query_map(params![subject_key], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;

        rows.map(|row| {
            let (seq, raw_json) = row?;
            decode_verified_chio_receipt(
                &raw_json,
                "persisted tool receipt",
                Some(seq.max(0) as u64),
            )
        })
        .collect()
    }

    pub fn list_tool_receipts_after_seq(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<StoredToolReceipt>, ReceiptStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT seq, raw_json
            FROM chio_tool_receipts
            WHERE seq > ?1
            ORDER BY seq ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![after_seq as i64, limit as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (seq, raw_json) = row?;
            let seq = seq.max(0) as u64;
            Ok(StoredToolReceipt {
                seq,
                receipt: decode_verified_chio_receipt(
                    &raw_json,
                    "persisted tool receipt",
                    Some(seq),
                )?,
            })
        })
        .collect()
    }

    pub fn list_child_receipts(
        &self,
        limit: usize,
        session_id: Option<&str>,
        parent_request_id: Option<&str>,
        request_id: Option<&str>,
        operation_kind: Option<&str>,
        terminal_state: Option<&str>,
    ) -> Result<Vec<ChildRequestReceipt>, ReceiptStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT seq, raw_json
            FROM chio_child_receipts
            WHERE (?1 IS NULL OR session_id = ?1)
              AND (?2 IS NULL OR parent_request_id = ?2)
              AND (?3 IS NULL OR request_id = ?3)
              AND (?4 IS NULL OR operation_kind = ?4)
              AND (?5 IS NULL OR terminal_state = ?5)
            ORDER BY seq DESC
            LIMIT ?6
            "#,
        )?;
        let rows = statement.query_map(
            params![
                session_id,
                parent_request_id,
                request_id,
                operation_kind,
                terminal_state,
                limit as i64,
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?;

        rows.map(|row| {
            let (seq, raw_json) = row?;
            decode_verified_child_receipt(
                &raw_json,
                "persisted child receipt",
                Some(seq.max(0) as u64),
            )
        })
        .collect()
    }

    pub fn list_child_receipts_after_seq(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<StoredChildReceipt>, ReceiptStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT seq, raw_json
            FROM chio_child_receipts
            WHERE seq > ?1
            ORDER BY seq ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![after_seq as i64, limit as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (seq, raw_json) = row?;
            let seq = seq.max(0) as u64;
            Ok(StoredChildReceipt {
                seq,
                receipt: decode_verified_child_receipt(
                    &raw_json,
                    "persisted child receipt",
                    Some(seq),
                )?,
            })
        })
        .collect()
    }

    pub fn import_federated_evidence_share(
        &mut self,
        import: &FederatedEvidenceShareImport,
    ) -> Result<FederatedEvidenceShareSummary, ReceiptStoreError> {
        let imported_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        tx.execute(
            r#"
            INSERT INTO federated_evidence_shares (
                share_id,
                manifest_hash,
                imported_at,
                exported_at,
                issuer,
                partner,
                signer_public_key,
                require_proofs,
                query_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(share_id) DO UPDATE SET
                manifest_hash = excluded.manifest_hash,
                imported_at = excluded.imported_at,
                exported_at = excluded.exported_at,
                issuer = excluded.issuer,
                partner = excluded.partner,
                signer_public_key = excluded.signer_public_key,
                require_proofs = excluded.require_proofs,
                query_json = excluded.query_json
            "#,
            params![
                import.share_id,
                import.manifest_hash,
                imported_at as i64,
                import.exported_at as i64,
                import.issuer,
                import.partner,
                import.signer_public_key,
                if import.require_proofs { 1_i64 } else { 0_i64 },
                import.query_json,
            ],
        )?;

        let lineage_by_capability = import
            .capability_lineage
            .iter()
            .map(|snapshot| (snapshot.capability_id.as_str(), snapshot))
            .collect::<BTreeMap<_, _>>();

        for snapshot in &import.capability_lineage {
            tx.execute(
                r#"
                INSERT INTO federated_share_capability_lineage (
                    share_id,
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                ON CONFLICT(share_id, capability_id) DO UPDATE SET
                    subject_key = excluded.subject_key,
                    issuer_key = excluded.issuer_key,
                    issued_at = excluded.issued_at,
                    expires_at = excluded.expires_at,
                    grants_json = excluded.grants_json,
                    delegation_depth = excluded.delegation_depth,
                    parent_capability_id = excluded.parent_capability_id
                "#,
                params![
                    import.share_id,
                    snapshot.capability_id,
                    snapshot.subject_key,
                    snapshot.issuer_key,
                    snapshot.issued_at as i64,
                    snapshot.expires_at as i64,
                    snapshot.grants_json,
                    snapshot.delegation_depth as i64,
                    snapshot.parent_capability_id,
                ],
            )?;
        }

        for record in &import.tool_receipts {
            let attribution = extract_receipt_attribution(&record.receipt);
            let lineage_subject = lineage_by_capability
                .get(record.receipt.capability_id.as_str())
                .map(|snapshot| snapshot.subject_key.as_str());
            let lineage_issuer = lineage_by_capability
                .get(record.receipt.capability_id.as_str())
                .map(|snapshot| snapshot.issuer_key.as_str());
            tx.execute(
                r#"
                INSERT INTO federated_share_tool_receipts (
                    share_id,
                    seq,
                    receipt_id,
                    timestamp,
                    capability_id,
                    subject_key,
                    issuer_key,
                    raw_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                ON CONFLICT(share_id, seq) DO UPDATE SET
                    receipt_id = excluded.receipt_id,
                    timestamp = excluded.timestamp,
                    capability_id = excluded.capability_id,
                    subject_key = excluded.subject_key,
                    issuer_key = excluded.issuer_key,
                    raw_json = excluded.raw_json
                "#,
                params![
                    import.share_id,
                    record.seq as i64,
                    record.receipt.id,
                    record.receipt.timestamp as i64,
                    record.receipt.capability_id,
                    attribution
                        .subject_key
                        .or_else(|| lineage_subject.map(ToOwned::to_owned)),
                    attribution
                        .issuer_key
                        .or_else(|| lineage_issuer.map(ToOwned::to_owned)),
                    serde_json::to_string(&record.receipt)?,
                ],
            )?;
        }

        tx.commit()?;

        Ok(FederatedEvidenceShareSummary {
            share_id: import.share_id.clone(),
            manifest_hash: import.manifest_hash.clone(),
            imported_at,
            exported_at: import.exported_at,
            issuer: import.issuer.clone(),
            partner: import.partner.clone(),
            signer_public_key: import.signer_public_key.clone(),
            require_proofs: import.require_proofs,
            tool_receipts: import.tool_receipts.len() as u64,
            capability_lineage: import.capability_lineage.len() as u64,
        })
    }

    pub fn get_federated_share_for_capability(
        &self,
        capability_id: &str,
    ) -> Result<Option<(FederatedEvidenceShareSummary, CapabilitySnapshot)>, ReceiptStoreError>
    {
        let row = self
            .connection()?
            .query_row(
                r#"
                SELECT
                    s.share_id,
                    s.manifest_hash,
                    s.imported_at,
                    s.exported_at,
                    s.issuer,
                    s.partner,
                    s.signer_public_key,
                    s.require_proofs,
                    (SELECT COUNT(*) FROM federated_share_tool_receipts r WHERE r.share_id = s.share_id),
                    (SELECT COUNT(*) FROM federated_share_capability_lineage c WHERE c.share_id = s.share_id),
                    l.capability_id,
                    l.subject_key,
                    l.issuer_key,
                    l.issued_at,
                    l.expires_at,
                    l.grants_json,
                    l.delegation_depth,
                    l.parent_capability_id
                FROM federated_share_capability_lineage l
                INNER JOIN federated_evidence_shares s ON s.share_id = l.share_id
                WHERE l.capability_id = ?1
                ORDER BY s.imported_at DESC, s.share_id DESC
                LIMIT 1
                "#,
                params![capability_id],
                |row| {
                    Ok((
                        FederatedEvidenceShareSummary {
                            share_id: row.get::<_, String>(0)?,
                            manifest_hash: row.get::<_, String>(1)?,
                            imported_at: row.get::<_, i64>(2)?.max(0) as u64,
                            exported_at: row.get::<_, i64>(3)?.max(0) as u64,
                            issuer: row.get::<_, String>(4)?,
                            partner: row.get::<_, String>(5)?,
                            signer_public_key: row.get::<_, String>(6)?,
                            require_proofs: row.get::<_, i64>(7)? != 0,
                            tool_receipts: row.get::<_, i64>(8)?.max(0) as u64,
                            capability_lineage: row.get::<_, i64>(9)?.max(0) as u64,
                        },
                        CapabilitySnapshot {
                            capability_id: row.get::<_, String>(10)?,
                            subject_key: row.get::<_, String>(11)?,
                            issuer_key: row.get::<_, String>(12)?,
                            issued_at: row.get::<_, i64>(13)?.max(0) as u64,
                            expires_at: row.get::<_, i64>(14)?.max(0) as u64,
                            grants_json: row.get::<_, String>(15)?,
                            delegation_depth: row.get::<_, i64>(16)?.max(0) as u64,
                            parent_capability_id: row.get::<_, Option<String>>(17)?,
                        },
                    ))
                },
            )
            .optional()?;
        Ok(row)
    }

    pub fn list_federated_share_subject_corpora(
        &self,
        subject_key: &str,
        since: Option<u64>,
        until: Option<u64>,
    ) -> Result<Vec<FederatedShareSubjectCorpus>, ReceiptStoreError> {
        let mut share_ids = self
            .connection()?
            .prepare(
                r#"
                SELECT DISTINCT share_id
                FROM federated_share_tool_receipts
                WHERE subject_key = ?1
                  AND (?2 IS NULL OR timestamp >= ?2)
                  AND (?3 IS NULL OR timestamp <= ?3)
                ORDER BY share_id
                "#,
            )?
            .query_map(
                params![
                    subject_key,
                    since.map(|value| value as i64),
                    until.map(|value| value as i64)
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;

        share_ids.sort();
        let mut results = Vec::new();
        for share_id in share_ids {
            let summary = self
                .connection()?
                .query_row(
                    r#"
                    SELECT
                        share_id,
                        manifest_hash,
                        imported_at,
                        exported_at,
                        issuer,
                        partner,
                        signer_public_key,
                        require_proofs,
                        (SELECT COUNT(*) FROM federated_share_tool_receipts r WHERE r.share_id = s.share_id),
                        (SELECT COUNT(*) FROM federated_share_capability_lineage c WHERE c.share_id = s.share_id)
                    FROM federated_evidence_shares s
                    WHERE share_id = ?1
                    "#,
                    params![share_id],
                    |row| {
                        Ok(FederatedEvidenceShareSummary {
                            share_id: row.get::<_, String>(0)?,
                            manifest_hash: row.get::<_, String>(1)?,
                            imported_at: row.get::<_, i64>(2)?.max(0) as u64,
                            exported_at: row.get::<_, i64>(3)?.max(0) as u64,
                            issuer: row.get::<_, String>(4)?,
                            partner: row.get::<_, String>(5)?,
                            signer_public_key: row.get::<_, String>(6)?,
                            require_proofs: row.get::<_, i64>(7)? != 0,
                            tool_receipts: row.get::<_, i64>(8)?.max(0) as u64,
                            capability_lineage: row.get::<_, i64>(9)?.max(0) as u64,
                        })
                    },
                )?;

            let receipts = self
                .connection()?
                .prepare(
                    r#"
                    SELECT seq, raw_json
                    FROM federated_share_tool_receipts
                    WHERE share_id = ?1
                      AND subject_key = ?2
                      AND (?3 IS NULL OR timestamp >= ?3)
                      AND (?4 IS NULL OR timestamp <= ?4)
                    ORDER BY seq ASC
                    "#,
                )?
                .query_map(
                    params![
                        summary.share_id,
                        subject_key,
                        since.map(|value| value as i64),
                        until.map(|value| value as i64)
                    ],
                    |row| {
                        let raw_json = row.get::<_, String>(1)?;
                        let seq = row.get::<_, i64>(0)?.max(0) as u64;
                        Ok(StoredToolReceipt {
                            seq,
                            receipt: decode_verified_chio_receipt(
                                &raw_json,
                                "federated share tool receipt",
                                Some(seq),
                            )
                            .map_err(|error| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    raw_json.len(),
                                    rusqlite::types::Type::Text,
                                    Box::new(error),
                                )
                            })?,
                        })
                    },
                )?
                .collect::<Result<Vec<_>, _>>()?;

            let capabilities = self
                .connection()?
                .prepare(
                    r#"
                    SELECT
                        capability_id,
                        subject_key,
                        issuer_key,
                        issued_at,
                        expires_at,
                        grants_json,
                        delegation_depth,
                        parent_capability_id
                    FROM federated_share_capability_lineage
                    WHERE share_id = ?1
                      AND (subject_key = ?2 OR issuer_key = ?2)
                    ORDER BY issued_at ASC, capability_id ASC
                    "#,
                )?
                .query_map(params![summary.share_id, subject_key], |row| {
                    Ok(CapabilitySnapshot {
                        capability_id: row.get::<_, String>(0)?,
                        subject_key: row.get::<_, String>(1)?,
                        issuer_key: row.get::<_, String>(2)?,
                        issued_at: row.get::<_, i64>(3)?.max(0) as u64,
                        expires_at: row.get::<_, i64>(4)?.max(0) as u64,
                        grants_json: row.get::<_, String>(5)?,
                        delegation_depth: row.get::<_, i64>(6)?.max(0) as u64,
                        parent_capability_id: row.get::<_, Option<String>>(7)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;

            results.push((summary, receipts, capabilities));
        }

        Ok(results)
    }

    pub fn record_federated_lineage_bridge(
        &mut self,
        local_capability_id: &str,
        parent_capability_id: &str,
        share_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        self.connection()?.execute(
            r#"
            INSERT INTO federated_lineage_bridges (
                local_capability_id,
                parent_capability_id,
                share_id
            ) VALUES (?1, ?2, ?3)
            ON CONFLICT(local_capability_id) DO UPDATE SET
                parent_capability_id = excluded.parent_capability_id,
                share_id = excluded.share_id
            "#,
            params![local_capability_id, parent_capability_id, share_id],
        )?;
        Ok(())
    }

    pub(crate) fn federated_lineage_bridge_parent(
        &self,
        local_capability_id: &str,
    ) -> Result<Option<String>, ReceiptStoreError> {
        self.connection()?
            .query_row(
                r#"
                SELECT parent_capability_id
                FROM federated_lineage_bridges
                WHERE local_capability_id = ?1
                "#,
                params![local_capability_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn get_combined_lineage(
        &self,
        capability_id: &str,
    ) -> Result<Option<chio_kernel::CapabilitySnapshot>, ReceiptStoreError> {
        if let Some(mut snapshot) =
            self.get_lineage(capability_id)
                .map_err(|error| match error {
                    chio_kernel::CapabilityLineageError::ReceiptStore(error) => error,
                    chio_kernel::CapabilityLineageError::Sqlite(error) => {
                        ReceiptStoreError::Sqlite(error)
                    }
                    chio_kernel::CapabilityLineageError::Json(error) => {
                        ReceiptStoreError::Json(error)
                    }
                })?
        {
            if snapshot.parent_capability_id.is_none() {
                snapshot.parent_capability_id =
                    self.federated_lineage_bridge_parent(&snapshot.capability_id)?;
            }
            return Ok(Some(snapshot));
        }
        Ok(self
            .get_federated_share_for_capability(capability_id)?
            .map(|(_, snapshot)| snapshot))
    }

    pub fn get_combined_delegation_chain(
        &self,
        capability_id: &str,
    ) -> Result<Vec<chio_kernel::CapabilitySnapshot>, ReceiptStoreError> {
        let mut chain = Vec::new();
        let mut current = Some(capability_id.to_string());
        let mut seen = BTreeSet::new();

        while let Some(current_capability_id) = current.take() {
            if !seen.insert(current_capability_id.clone()) || chain.len() >= 32 {
                break;
            }
            let Some(snapshot) = self.get_combined_lineage(&current_capability_id)? else {
                break;
            };
            current = snapshot.parent_capability_id.clone();
            chain.push(snapshot);
        }

        chain.reverse();
        Ok(chain)
    }
}
