// OAuth authorization context report, profile metadata, and review pack queries.

use super::*;

impl SqliteReceiptStore {
    pub fn query_authorization_context_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<AuthorizationContextReport, ReceiptStoreError> {
        require_admin_receipt_read_context(
            query.read_context.as_ref(),
            "authorization context report",
        )?;
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();
        let row_limit = query.authorization_limit_or_default();

        let summary_sql = r#"
            SELECT
                COUNT(*),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.approval') = 'object' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_extract(r.raw_json, '$.metadata.governed_transaction.approval.approved') = 1 THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.commerce') = 'object' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.metered_billing') = 'object' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.runtime_assurance') = 'object' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.call_chain') = 'object' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.max_amount') = 'object' THEN 1
                        ELSE 0
                    END
                ), 0)
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE json_type(r.raw_json, '$.metadata.governed_transaction') = 'object'
              AND (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
        "#;

        let (
            matching_receipts,
            approval_receipts,
            approved_receipts,
            commerce_receipts,
            metered_billing_receipts,
            runtime_assurance_receipts,
            _call_chain_receipts,
            max_amount_receipts,
        ) = self.connection()?.query_row(
            summary_sql,
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?.max(0) as u64,
                    row.get::<_, i64>(1)?.max(0) as u64,
                    row.get::<_, i64>(2)?.max(0) as u64,
                    row.get::<_, i64>(3)?.max(0) as u64,
                    row.get::<_, i64>(4)?.max(0) as u64,
                    row.get::<_, i64>(5)?.max(0) as u64,
                    row.get::<_, i64>(6)?.max(0) as u64,
                    row.get::<_, i64>(7)?.max(0) as u64,
                ))
            },
        )?;

        let rows_sql = r#"
            SELECT
                r.seq,
                r.raw_json,
                r.subject_key,
                r.issuer_key,
                cl.subject_key,
                cl.issuer_key,
                r.grant_index,
                cl.grants_json,
                rls.statement_id,
                rls.session_anchor_id
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            LEFT JOIN receipt_lineage_statements rls ON r.receipt_id = rls.receipt_id
            WHERE json_type(r.raw_json, '$.metadata.governed_transaction') = 'object'
              AND (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
            ORDER BY r.timestamp DESC, r.seq DESC
        "#;

        let connection = self.connection()?;
        let mut stmt = connection.prepare(rows_sql)?;
        let rows = stmt.query_map(
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                ))
            },
        )?;

        let mut sender_bound_receipts = 0_u64;
        let mut dpop_bound_receipts = 0_u64;
        let mut runtime_assurance_bound_receipts = 0_u64;
        let mut delegated_sender_bound_receipts = 0_u64;
        let mut call_chain_receipts = 0_u64;
        let mut asserted_call_chain_receipts = 0_u64;
        let mut observed_call_chain_receipts = 0_u64;
        let mut verified_call_chain_receipts = 0_u64;
        let mut session_anchor_receipts = 0_u64;
        let mut request_lineage_receipts = 0_u64;
        let mut receipt_lineage_statement_receipts = 0_u64;
        let mut receipts = Vec::new();
        for row in rows {
            let (
                seq,
                raw_json,
                receipt_subject_key,
                receipt_issuer_key,
                lineage_subject_key,
                lineage_issuer_key,
                persisted_grant_index,
                grants_json,
                persisted_statement_id,
                persisted_session_anchor_id,
            ) = row?;
            let receipt = decode_verified_chio_receipt(
                &raw_json,
                "persisted tool receipt",
                Some(seq.max(0) as u64),
            )?;
            let governed = extract_governed_transaction_metadata(&receipt).ok_or_else(|| {
                ReceiptStoreError::Canonical(format!(
                    "receipt {} is missing governed transaction metadata",
                    receipt.id
                ))
            })?;
            let mut projection = sanitize_governed_transaction_projection(&receipt, &governed);
            apply_persisted_lineage_references(
                &mut projection,
                &PersistedLineageReferences {
                    statement_id: persisted_statement_id,
                    session_anchor_id: persisted_session_anchor_id,
                },
            );
            let attribution = extract_receipt_attribution(&receipt);
            let transaction_context =
                authorization_transaction_context_from_projection(&projection);
            let sender_constraint = derive_authorization_sender_constraint(
                &receipt.id,
                AuthorizationSenderConstraintArgs {
                    tool_server: &receipt.tool_server,
                    tool_name: &receipt.tool_name,
                    receipt_subject_key: receipt_subject_key.as_deref(),
                    receipt_issuer_key: receipt_issuer_key.as_deref(),
                    lineage_subject_key: lineage_subject_key.as_deref(),
                    lineage_issuer_key: lineage_issuer_key.as_deref(),
                    grant_index: attribution
                        .grant_index
                        .or_else(|| persisted_grant_index.map(|value| value.max(0) as u32)),
                    grants_json: grants_json.as_deref(),
                },
                &transaction_context,
            )?;

            let authorization_row = AuthorizationContextRow {
                receipt_id: receipt.id,
                timestamp: receipt.timestamp,
                capability_id: receipt.capability_id,
                subject_key: Some(sender_constraint.subject_key.clone()),
                tool_server: receipt.tool_server,
                tool_name: receipt.tool_name,
                decision: receipt.decision,
                authorization_details: authorization_details_from_governed_metadata(
                    &projection.strong,
                ),
                transaction_context,
                governed_transaction_diagnostics: projection.diagnostics.clone(),
                sender_constraint,
            };
            validate_chio_oauth_authorization_row(&authorization_row)?;
            if let Some(evidence_class) = call_chain_evidence_class(&projection) {
                call_chain_receipts += 1;
                match evidence_class {
                    GovernedProvenanceEvidenceClass::Asserted => {
                        asserted_call_chain_receipts += 1;
                    }
                    GovernedProvenanceEvidenceClass::Observed => {
                        observed_call_chain_receipts += 1;
                    }
                    GovernedProvenanceEvidenceClass::Verified => {
                        verified_call_chain_receipts += 1;
                    }
                }
            }
            if let Some(lineage_references) = lineage_references_from_projection(&projection) {
                if lineage_references.session_anchor_id.is_some() {
                    session_anchor_receipts += 1;
                }
                if lineage_references.request_lineage_id.is_some() {
                    request_lineage_receipts += 1;
                }
                if lineage_references.receipt_lineage_statement_id.is_some() {
                    receipt_lineage_statement_receipts += 1;
                }
            }
            sender_bound_receipts += 1;
            if authorization_row.sender_constraint.proof_required {
                dpop_bound_receipts += 1;
            }
            if authorization_row.sender_constraint.runtime_assurance_bound {
                runtime_assurance_bound_receipts += 1;
            }
            if authorization_row
                .sender_constraint
                .delegated_call_chain_bound
            {
                delegated_sender_bound_receipts += 1;
            }
            if receipts.len() < row_limit {
                receipts.push(authorization_row);
            }
        }

        Ok(AuthorizationContextReport {
            schema: CHIO_OAUTH_AUTHORIZATION_CONTEXT_REPORT_SCHEMA.to_string(),
            profile: ChioOAuthAuthorizationProfile::default(),
            summary: AuthorizationContextSummary {
                matching_receipts,
                returned_receipts: receipts.len() as u64,
                approval_receipts,
                approved_receipts,
                commerce_receipts,
                metered_billing_receipts,
                runtime_assurance_receipts,
                call_chain_receipts,
                asserted_call_chain_receipts,
                observed_call_chain_receipts,
                verified_call_chain_receipts,
                max_amount_receipts,
                sender_bound_receipts,
                dpop_bound_receipts,
                runtime_assurance_bound_receipts,
                delegated_sender_bound_receipts,
                session_anchor_receipts,
                request_lineage_receipts,
                receipt_lineage_statement_receipts,
                truncated: matching_receipts > receipts.len() as u64,
            },
            receipts,
        })
    }

    pub fn authorization_profile_metadata_report(&self) -> ChioOAuthAuthorizationMetadataReport {
        ChioOAuthAuthorizationMetadataReport {
            schema: CHIO_OAUTH_AUTHORIZATION_METADATA_SCHEMA.to_string(),
            generated_at: unix_now(),
            profile: ChioOAuthAuthorizationProfile::default(),
            report_schema: CHIO_OAUTH_AUTHORIZATION_CONTEXT_REPORT_SCHEMA.to_string(),
            discovery: ChioOAuthAuthorizationDiscoveryMetadata {
                protected_resource_metadata_paths: vec![
                    "/.well-known/oauth-protected-resource".to_string(),
                    "/.well-known/oauth-protected-resource/mcp".to_string(),
                ],
                authorization_server_metadata_path_template:
                    "/.well-known/oauth-authorization-server/{issuer-path}".to_string(),
                discovery_informational_only: true,
            },
            support_boundary: ChioOAuthAuthorizationSupportBoundary {
                governed_receipts_authoritative: true,
                hosted_request_time_authorization_supported: true,
                resource_indicator_binding_supported: true,
                sender_constrained_projection: true,
                runtime_assurance_projection: true,
                delegated_call_chain_projection: true,
                generic_token_issuance_supported: false,
                oidc_identity_assertions_supported: false,
                mtls_transport_binding_in_profile: false,
                approval_tokens_runtime_authorization_supported: false,
                capabilities_runtime_authorization_supported: false,
                reviewer_evidence_runtime_authorization_supported: false,
            },
            example_mapping: ChioOAuthAuthorizationExampleMapping {
                authorization_detail_types: vec![
                    "type".to_string(),
                    "locations".to_string(),
                    "actions".to_string(),
                    "purpose".to_string(),
                    "maxAmount".to_string(),
                    "commerce".to_string(),
                    "meteredBilling".to_string(),
                ],
                transaction_context_fields: ChioOAuthAuthorizationProfile::default()
                    .transaction_context_fields,
                sender_constraint_fields: vec![
                    "subjectKey".to_string(),
                    "subjectKeySource".to_string(),
                    "issuerKey".to_string(),
                    "issuerKeySource".to_string(),
                    "matchedGrantIndex".to_string(),
                    "proofRequired".to_string(),
                    "proofType".to_string(),
                    "proofSchema".to_string(),
                    "runtimeAssuranceBound".to_string(),
                    "delegatedCallChainBound".to_string(),
                ],
            },
        }
    }

    pub fn query_authorization_review_pack(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<ChioOAuthAuthorizationReviewPack, ReceiptStoreError> {
        require_admin_receipt_read_context(
            query.read_context.as_ref(),
            "authorization review pack",
        )?;
        let authorization_context = self.query_authorization_context_report(query)?;
        let metadata = self.authorization_profile_metadata_report();
        let mut records = Vec::with_capacity(authorization_context.receipts.len());

        for row in authorization_context.receipts {
            let (seq, raw_json) = self.connection()?.query_row(
                "SELECT seq, raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
                params![row.receipt_id.as_str()],
                |db_row| Ok((db_row.get::<_, i64>(0)?, db_row.get::<_, String>(1)?)),
            )?;
            let signed_receipt = decode_verified_chio_receipt(
                &raw_json,
                "persisted tool receipt",
                Some(seq.max(0) as u64),
            )?;
            let governed_transaction = extract_governed_transaction_metadata(&signed_receipt)
                .ok_or_else(|| {
                    ReceiptStoreError::Canonical(format!(
                        "receipt {} is missing governed transaction metadata",
                        signed_receipt.id
                    ))
                })?;
            let mut projection =
                sanitize_governed_transaction_projection(&signed_receipt, &governed_transaction);
            if let Some(diagnostics) = row.governed_transaction_diagnostics.as_ref() {
                apply_persisted_lineage_references(
                    &mut projection,
                    &PersistedLineageReferences {
                        statement_id: diagnostics
                            .lineage_references
                            .receipt_lineage_statement_id
                            .clone(),
                        session_anchor_id: diagnostics.lineage_references.session_anchor_id.clone(),
                    },
                );
            }
            records.push(ChioOAuthAuthorizationReviewPackRecord {
                receipt_id: row.receipt_id.clone(),
                capability_id: row.capability_id.clone(),
                authorization_context: row,
                governed_transaction: projection.strong,
                governed_transaction_diagnostics: projection.diagnostics,
                signed_receipt,
            });
        }

        Ok(ChioOAuthAuthorizationReviewPack {
            schema: CHIO_OAUTH_AUTHORIZATION_REVIEW_PACK_SCHEMA.to_string(),
            generated_at: unix_now(),
            filters: query.clone(),
            metadata,
            summary: ChioOAuthAuthorizationReviewPackSummary {
                matching_receipts: authorization_context.summary.matching_receipts,
                returned_receipts: records.len() as u64,
                dpop_required_receipts: authorization_context.summary.dpop_bound_receipts,
                runtime_assurance_receipts: authorization_context
                    .summary
                    .runtime_assurance_bound_receipts,
                delegated_call_chain_receipts: authorization_context.summary.call_chain_receipts,
                asserted_call_chain_receipts: authorization_context
                    .summary
                    .asserted_call_chain_receipts,
                observed_call_chain_receipts: authorization_context
                    .summary
                    .observed_call_chain_receipts,
                verified_call_chain_receipts: authorization_context
                    .summary
                    .verified_call_chain_receipts,
                session_anchor_receipts: authorization_context.summary.session_anchor_receipts,
                request_lineage_receipts: authorization_context.summary.request_lineage_receipts,
                receipt_lineage_statement_receipts: authorization_context
                    .summary
                    .receipt_lineage_statement_receipts,
                truncated: authorization_context.summary.truncated,
            },
            records,
        })
    }
}
