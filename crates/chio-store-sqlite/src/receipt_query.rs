use chio_kernel::receipt_query::{ReceiptQuery, ReceiptQueryResult};
use chio_kernel::ReceiptStoreError;

use crate::receipt_store::SqliteReceiptStore;

impl SqliteReceiptStore {
    /// Query tool receipts with multi-filter support and cursor-based pagination.
    ///
    /// Filters are applied with AND semantics. The cursor parameter enables
    /// forward-only pagination using the seq column as a stable cursor.
    ///
    /// The limit is capped at MAX_QUERY_LIMIT. total_count reflects the full
    /// filtered set (no cursor applied), regardless of the page limit.
    pub fn query_receipts(
        &self,
        query: &ReceiptQuery,
    ) -> Result<ReceiptQueryResult, ReceiptStoreError> {
        // Delegate to the impl in receipt_store.rs (which can access the private connection field).
        self.query_receipts_impl(query)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core::crypto::Keypair;
    use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction};
    use chio_kernel::{ReceiptStore, MAX_QUERY_LIMIT};

    use super::*;
    use crate::receipt_store::SqliteReceiptStore;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    fn valid_tool_action(parameters: serde_json::Value) -> ToolCallAction {
        ToolCallAction::from_parameters(parameters).unwrap()
    }

    fn make_receipt_with_metadata(
        id: &str,
        capability_id: &str,
        tool_server: &str,
        tool_name: &str,
        decision: Decision,
        timestamp: u64,
        metadata: Option<serde_json::Value>,
    ) -> ChioReceipt {
        let keypair = Keypair::generate();
        ChioReceipt::sign(
            ChioReceiptBody {
                id: id.to_string(),
                timestamp,
                capability_id: capability_id.to_string(),
                tool_server: tool_server.to_string(),
                tool_name: tool_name.to_string(),
                action: valid_tool_action(serde_json::json!({})),
                decision,
                content_hash: "content-hash".to_string(),
                policy_hash: "policy-hash".to_string(),
                evidence: Vec::new(),
                metadata,
                trust_level: chio_core::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .unwrap()
    }

    /// Build a receipt with given fields. cost populates financial metadata.
    fn make_receipt(
        id: &str,
        capability_id: &str,
        tool_server: &str,
        tool_name: &str,
        decision: Decision,
        timestamp: u64,
        cost: Option<u64>,
    ) -> ChioReceipt {
        let metadata = cost.map(|c| {
            serde_json::json!({
                "financial": {
                    "grant_index": 0u32,
                    "cost_charged": c,
                    "currency": "USD",
                    "budget_remaining": 1000u64,
                    "budget_total": 2000u64,
                    "delegation_depth": 0u32,
                    "root_budget_holder": "root-agent",
                    "settlement_status": "pending"
                }
            })
        });
        make_receipt_with_metadata(
            id,
            capability_id,
            tool_server,
            tool_name,
            decision,
            timestamp,
            metadata,
        )
    }

    #[test]
    fn test_query_no_filters() {
        let path = unique_db_path("rq-no-filters");
        let store = SqliteReceiptStore::open(&path).unwrap();

        for i in 0..5usize {
            let r = make_receipt(
                &format!("r-{i}"),
                "cap-1",
                "shell",
                "bash",
                Decision::Allow,
                100 + i as u64,
                None,
            );
            store.append_chio_receipt(&r).unwrap();
        }

        let result = store
            .query_receipts(&ReceiptQuery {
                limit: 10,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(result.receipts.len(), 5);
        assert_eq!(result.total_count, 5);
        // Results ordered by seq ASC.
        let seqs: Vec<u64> = result.receipts.iter().map(|r| r.seq).collect();
        let mut sorted = seqs.clone();
        sorted.sort();
        assert_eq!(seqs, sorted, "receipts should be ordered by seq ASC");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_filter_capability_id() {
        let path = unique_db_path("rq-cap-id");
        let store = SqliteReceiptStore::open(&path).unwrap();

        store
            .append_chio_receipt(&make_receipt(
                "r-1",
                "cap-A",
                "s",
                "t",
                Decision::Allow,
                100,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-2",
                "cap-B",
                "s",
                "t",
                Decision::Allow,
                101,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-3",
                "cap-A",
                "s",
                "t",
                Decision::Allow,
                102,
                None,
            ))
            .unwrap();

        let result = store
            .query_receipts(&ReceiptQuery {
                capability_id: Some("cap-A".to_string()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(result.receipts.len(), 2);
        assert_eq!(result.total_count, 2);
        for r in &result.receipts {
            assert_eq!(r.receipt.capability_id, "cap-A");
        }

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_filter_tool_server() {
        let path = unique_db_path("rq-tool-server");
        let store = SqliteReceiptStore::open(&path).unwrap();

        store
            .append_chio_receipt(&make_receipt(
                "r-1",
                "cap-1",
                "shell",
                "bash",
                Decision::Allow,
                100,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-2",
                "cap-1",
                "files",
                "read",
                Decision::Allow,
                101,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-3",
                "cap-1",
                "shell",
                "ls",
                Decision::Allow,
                102,
                None,
            ))
            .unwrap();

        let result = store
            .query_receipts(&ReceiptQuery {
                tool_server: Some("shell".to_string()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(result.receipts.len(), 2);
        assert_eq!(result.total_count, 2);
        for r in &result.receipts {
            assert_eq!(r.receipt.tool_server, "shell");
        }

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_filter_tool_name() {
        let path = unique_db_path("rq-tool-name");
        let store = SqliteReceiptStore::open(&path).unwrap();

        store
            .append_chio_receipt(&make_receipt(
                "r-1",
                "cap-1",
                "shell",
                "bash",
                Decision::Allow,
                100,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-2",
                "cap-1",
                "shell",
                "ls",
                Decision::Allow,
                101,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-3",
                "cap-1",
                "shell",
                "bash",
                Decision::Allow,
                102,
                None,
            ))
            .unwrap();

        let result = store
            .query_receipts(&ReceiptQuery {
                tool_name: Some("bash".to_string()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(result.receipts.len(), 2);
        assert_eq!(result.total_count, 2);
        for r in &result.receipts {
            assert_eq!(r.receipt.tool_name, "bash");
        }

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_filter_outcome() {
        let path = unique_db_path("rq-outcome");
        let store = SqliteReceiptStore::open(&path).unwrap();

        store
            .append_chio_receipt(&make_receipt(
                "r-1",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                100,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-2",
                "cap-1",
                "s",
                "t",
                Decision::Deny {
                    reason: "no".to_string(),
                    guard: "G".to_string(),
                },
                101,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-3",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                102,
                None,
            ))
            .unwrap();

        let result = store
            .query_receipts(&ReceiptQuery {
                outcome: Some("allow".to_string()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(result.receipts.len(), 2);
        assert_eq!(result.total_count, 2);
        for r in &result.receipts {
            assert!(r.receipt.is_allowed());
        }

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_filter_time_range_since() {
        let path = unique_db_path("rq-since");
        let store = SqliteReceiptStore::open(&path).unwrap();

        store
            .append_chio_receipt(&make_receipt(
                "r-1",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                100,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-2",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                200,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-3",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                300,
                None,
            ))
            .unwrap();

        let result = store
            .query_receipts(&ReceiptQuery {
                since: Some(200),
                limit: 10,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(
            result.receipts.len(),
            2,
            "since 200 should include timestamps 200 and 300"
        );
        assert_eq!(result.total_count, 2);
        for r in &result.receipts {
            assert!(r.receipt.timestamp >= 200);
        }

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_filter_time_range_until() {
        let path = unique_db_path("rq-until");
        let store = SqliteReceiptStore::open(&path).unwrap();

        store
            .append_chio_receipt(&make_receipt(
                "r-1",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                100,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-2",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                200,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-3",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                300,
                None,
            ))
            .unwrap();

        let result = store
            .query_receipts(&ReceiptQuery {
                until: Some(200),
                limit: 10,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(
            result.receipts.len(),
            2,
            "until 200 should include timestamps 100 and 200"
        );
        assert_eq!(result.total_count, 2);
        for r in &result.receipts {
            assert!(r.receipt.timestamp <= 200);
        }

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_filter_time_range_both() {
        let path = unique_db_path("rq-time-both");
        let store = SqliteReceiptStore::open(&path).unwrap();

        store
            .append_chio_receipt(&make_receipt(
                "r-1",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                100,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-2",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                200,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-3",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                300,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-4",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                400,
                None,
            ))
            .unwrap();

        let result = store
            .query_receipts(&ReceiptQuery {
                since: Some(200),
                until: Some(300),
                limit: 10,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(result.receipts.len(), 2);
        assert_eq!(result.total_count, 2);
        for r in &result.receipts {
            assert!(r.receipt.timestamp >= 200 && r.receipt.timestamp <= 300);
        }

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_filter_cost_range_min() {
        let path = unique_db_path("rq-min-cost");
        let store = SqliteReceiptStore::open(&path).unwrap();

        // No cost (no financial metadata).
        store
            .append_chio_receipt(&make_receipt(
                "r-1",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                100,
                None,
            ))
            .unwrap();
        // cost = 50
        store
            .append_chio_receipt(&make_receipt(
                "r-2",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                101,
                Some(50),
            ))
            .unwrap();
        // cost = 150
        store
            .append_chio_receipt(&make_receipt(
                "r-3",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                102,
                Some(150),
            ))
            .unwrap();

        let result = store
            .query_receipts(&ReceiptQuery {
                min_cost: Some(100),
                limit: 10,
                ..Default::default()
            })
            .unwrap();

        // Only r-3 (cost=150) passes -- r-1 has no metadata, r-2 has cost<100
        assert_eq!(
            result.receipts.len(),
            1,
            "only r-3 with cost=150 should match min_cost=100"
        );
        assert_eq!(result.total_count, 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_filter_cost_range_max() {
        let path = unique_db_path("rq-max-cost");
        let store = SqliteReceiptStore::open(&path).unwrap();

        // No cost (no financial metadata).
        store
            .append_chio_receipt(&make_receipt(
                "r-1",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                100,
                None,
            ))
            .unwrap();
        // cost = 50
        store
            .append_chio_receipt(&make_receipt(
                "r-2",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                101,
                Some(50),
            ))
            .unwrap();
        // cost = 150
        store
            .append_chio_receipt(&make_receipt(
                "r-3",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                102,
                Some(150),
            ))
            .unwrap();

        let result = store
            .query_receipts(&ReceiptQuery {
                max_cost: Some(100),
                limit: 10,
                ..Default::default()
            })
            .unwrap();

        // Only r-2 (cost=50) passes -- r-1 has no metadata, r-3 has cost>100
        assert_eq!(
            result.receipts.len(),
            1,
            "only r-2 with cost=50 should match max_cost=100"
        );
        assert_eq!(result.total_count, 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_filter_cost_range_both() {
        let path = unique_db_path("rq-cost-both");
        let store = SqliteReceiptStore::open(&path).unwrap();

        store
            .append_chio_receipt(&make_receipt(
                "r-1",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                100,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-2",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                101,
                Some(50),
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-3",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                102,
                Some(100),
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-4",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                103,
                Some(200),
            ))
            .unwrap();

        let result = store
            .query_receipts(&ReceiptQuery {
                min_cost: Some(75),
                max_cost: Some(150),
                limit: 10,
                ..Default::default()
            })
            .unwrap();

        // Only r-3 (cost=100) passes the 75..=150 window
        assert_eq!(
            result.receipts.len(),
            1,
            "only r-3 with cost=100 should match 75..=150 window"
        );
        assert_eq!(result.total_count, 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_cursor_pagination() {
        let path = unique_db_path("rq-cursor");
        let store = SqliteReceiptStore::open(&path).unwrap();

        for i in 0..5usize {
            let r = make_receipt(
                &format!("r-{i}"),
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                100 + i as u64,
                None,
            );
            store.append_chio_receipt(&r).unwrap();
        }

        // Get first 2 receipts.
        let page1 = store
            .query_receipts(&ReceiptQuery {
                cursor: None,
                limit: 2,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(page1.receipts.len(), 2);

        let cursor = page1.next_cursor.expect("should have next cursor");

        // Get next page after cursor.
        let page2 = store
            .query_receipts(&ReceiptQuery {
                cursor: Some(cursor),
                limit: 2,
                ..Default::default()
            })
            .unwrap();

        // All seq in page2 must be > cursor.
        for r in &page2.receipts {
            assert!(
                r.seq > cursor,
                "page2 receipt seq {} should be > cursor {}",
                r.seq,
                cursor
            );
        }

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_cursor_pagination_pages() {
        let path = unique_db_path("rq-cursor-pages");
        let store = SqliteReceiptStore::open(&path).unwrap();

        for i in 0..7usize {
            let r = make_receipt(
                &format!("r-{i}"),
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                100 + i as u64,
                None,
            );
            store.append_chio_receipt(&r).unwrap();
        }

        // Paginate through all 7 receipts with page size 3.
        let mut all_seqs = Vec::new();
        let mut cursor = None;

        loop {
            let page = store
                .query_receipts(&ReceiptQuery {
                    cursor,
                    limit: 3,
                    ..Default::default()
                })
                .unwrap();

            for r in &page.receipts {
                all_seqs.push(r.seq);
            }

            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }

        assert_eq!(
            all_seqs.len(),
            7,
            "all 7 receipts should be seen across pages"
        );

        // No duplicates -- seqs are strictly increasing so dedup covers exact duplicates.
        let mut unique = all_seqs.clone();
        unique.dedup();
        assert_eq!(all_seqs, unique, "no duplicate seqs");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_next_cursor_some_when_more() {
        let path = unique_db_path("rq-next-cursor-some");
        let store = SqliteReceiptStore::open(&path).unwrap();

        for i in 0..5usize {
            let r = make_receipt(
                &format!("r-{i}"),
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                100 + i as u64,
                None,
            );
            store.append_chio_receipt(&r).unwrap();
        }

        let result = store
            .query_receipts(&ReceiptQuery {
                limit: 3,
                ..Default::default()
            })
            .unwrap();

        // 5 total, page size 3, so there should be a next_cursor.
        assert_eq!(result.receipts.len(), 3);
        assert!(
            result.next_cursor.is_some(),
            "next_cursor should be Some when results.len() == limit"
        );
        assert_eq!(result.next_cursor.unwrap(), result.receipts[2].seq);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_next_cursor_none_when_last_page() {
        let path = unique_db_path("rq-next-cursor-none");
        let store = SqliteReceiptStore::open(&path).unwrap();

        for i in 0..3usize {
            let r = make_receipt(
                &format!("r-{i}"),
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                100 + i as u64,
                None,
            );
            store.append_chio_receipt(&r).unwrap();
        }

        let result = store
            .query_receipts(&ReceiptQuery {
                limit: 5,
                ..Default::default()
            })
            .unwrap();

        // 3 total, page size 5, so this is the last page.
        assert_eq!(result.receipts.len(), 3);
        assert!(
            result.next_cursor.is_none(),
            "next_cursor should be None when results.len() < limit"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_total_count() {
        let path = unique_db_path("rq-total-count");
        let store = SqliteReceiptStore::open(&path).unwrap();

        for i in 0..10usize {
            let r = make_receipt(
                &format!("r-{i}"),
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                100 + i as u64,
                None,
            );
            store.append_chio_receipt(&r).unwrap();
        }

        // Fetch only 3 receipts but total_count should reflect all 10.
        let result = store
            .query_receipts(&ReceiptQuery {
                limit: 3,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(result.receipts.len(), 3);
        assert_eq!(
            result.total_count, 10,
            "total_count should reflect all matching receipts"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_limit_capped() {
        let path = unique_db_path("rq-limit-capped");
        let store = SqliteReceiptStore::open(&path).unwrap();

        // Insert MAX_QUERY_LIMIT + 10 receipts.
        for i in 0..(MAX_QUERY_LIMIT + 10) {
            let r = make_receipt(
                &format!("r-{i}"),
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                100 + i as u64,
                None,
            );
            store.append_chio_receipt(&r).unwrap();
        }

        // Request more than MAX_QUERY_LIMIT -- should be capped.
        let result = store
            .query_receipts(&ReceiptQuery {
                limit: MAX_QUERY_LIMIT + 100,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(
            result.receipts.len(),
            MAX_QUERY_LIMIT,
            "limit above MAX_QUERY_LIMIT should be capped to MAX_QUERY_LIMIT"
        );

        let _ = std::fs::remove_file(path);
    }

    // ---------------------------------------------------------------------------
    // agent_subject filter tests (Phase 12-02)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_query_agent_subject_filter() {
        let path = unique_db_path("rq-agent-subject");
        let store = SqliteReceiptStore::open(&path).unwrap();

        use chio_core::capability::{
            CapabilityToken, CapabilityTokenBody, ChioScope, Operation, ToolGrant,
        };
        use chio_core::crypto::Keypair;

        let kp_agent1 = Keypair::generate();
        let kp_agent2 = Keypair::generate();
        let kp_issuer = Keypair::generate();

        let make_token_local = |id: &str, subject_kp: &Keypair, issuer_kp: &Keypair| {
            let body = CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer_kp.public_key(),
                subject: subject_kp.public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: "shell".to_string(),
                        tool_name: "bash".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                issued_at: 1000,
                expires_at: 9000,
                delegation_chain: vec![],
            };
            CapabilityToken::sign(body, issuer_kp).expect("sign failed")
        };

        let token1 = make_token_local("cap-agent1", &kp_agent1, &kp_issuer);
        let token2 = make_token_local("cap-agent2", &kp_agent2, &kp_issuer);

        store.record_capability_snapshot(&token1, None).unwrap();
        store.record_capability_snapshot(&token2, None).unwrap();

        // 2 receipts for agent1, 1 for agent2
        store
            .append_chio_receipt(&make_receipt(
                "r-1",
                "cap-agent1",
                "s",
                "t",
                Decision::Allow,
                100,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-2",
                "cap-agent1",
                "s",
                "t",
                Decision::Allow,
                101,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-3",
                "cap-agent2",
                "s",
                "t",
                Decision::Allow,
                102,
                None,
            ))
            .unwrap();

        let agent1_key = kp_agent1.public_key().to_hex();
        let result = store
            .query_receipts(&ReceiptQuery {
                agent_subject: Some(agent1_key),
                limit: 10,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(
            result.receipts.len(),
            2,
            "only agent1 receipts should match"
        );
        assert_eq!(result.total_count, 2);
        for r in &result.receipts {
            assert_eq!(r.receipt.capability_id, "cap-agent1");
        }

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_agent_subject_none_returns_all() {
        let path = unique_db_path("rq-agent-none");
        let store = SqliteReceiptStore::open(&path).unwrap();

        use chio_core::capability::{
            CapabilityToken, CapabilityTokenBody, ChioScope, Operation, ToolGrant,
        };
        use chio_core::crypto::Keypair;

        let kp_agent1 = Keypair::generate();
        let kp_agent2 = Keypair::generate();
        let kp_issuer = Keypair::generate();

        let make_token_local = |id: &str, subject_kp: &Keypair, issuer_kp: &Keypair| {
            let body = CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer_kp.public_key(),
                subject: subject_kp.public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: "shell".to_string(),
                        tool_name: "bash".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                issued_at: 1000,
                expires_at: 9000,
                delegation_chain: vec![],
            };
            CapabilityToken::sign(body, issuer_kp).expect("sign failed")
        };

        let token1 = make_token_local("cap-none-1", &kp_agent1, &kp_issuer);
        let token2 = make_token_local("cap-none-2", &kp_agent2, &kp_issuer);

        store.record_capability_snapshot(&token1, None).unwrap();
        store.record_capability_snapshot(&token2, None).unwrap();

        store
            .append_chio_receipt(&make_receipt(
                "r-1",
                "cap-none-1",
                "s",
                "t",
                Decision::Allow,
                100,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-2",
                "cap-none-2",
                "s",
                "t",
                Decision::Allow,
                101,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-3",
                "cap-none-1",
                "s",
                "t",
                Decision::Allow,
                102,
                None,
            ))
            .unwrap();

        // agent_subject=None should return all 3 receipts
        let result = store
            .query_receipts(&ReceiptQuery {
                agent_subject: None,
                limit: 10,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(
            result.receipts.len(),
            3,
            "no agent_subject filter should return all receipts"
        );
        assert_eq!(result.total_count, 3);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_agent_subject_no_match() {
        let path = unique_db_path("rq-agent-no-match");
        let store = SqliteReceiptStore::open(&path).unwrap();

        store
            .append_chio_receipt(&make_receipt(
                "r-1",
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                100,
                None,
            ))
            .unwrap();

        // Query with a key that does not exist in capability_lineage
        let result = store
            .query_receipts(&ReceiptQuery {
                agent_subject: Some("deadbeef".to_string()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(result.receipts.len(), 0, "no match should return empty");
        assert_eq!(result.total_count, 0);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_agent_subject_with_outcome_filter() {
        let path = unique_db_path("rq-agent-outcome");
        let store = SqliteReceiptStore::open(&path).unwrap();

        use chio_core::capability::{
            CapabilityToken, CapabilityTokenBody, ChioScope, Operation, ToolGrant,
        };
        use chio_core::crypto::Keypair;

        let kp_agent = Keypair::generate();
        let kp_issuer = Keypair::generate();

        let body = CapabilityTokenBody {
            id: "cap-outcome-1".to_string(),
            issuer: kp_issuer.public_key(),
            subject: kp_agent.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            issued_at: 1000,
            expires_at: 9000,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign(body, &kp_issuer).expect("sign failed");
        store.record_capability_snapshot(&token, None).unwrap();

        // 1 allow + 1 deny for the same agent capability
        store
            .append_chio_receipt(&make_receipt(
                "r-1",
                "cap-outcome-1",
                "s",
                "t",
                Decision::Allow,
                100,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-2",
                "cap-outcome-1",
                "s",
                "t",
                Decision::Deny {
                    reason: "no".to_string(),
                    guard: "G".to_string(),
                },
                101,
                None,
            ))
            .unwrap();

        let agent_key = kp_agent.public_key().to_hex();
        let result = store
            .query_receipts(&ReceiptQuery {
                agent_subject: Some(agent_key),
                outcome: Some("allow".to_string()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();

        // Intersection: agent1 AND outcome=allow -> only r-1
        assert_eq!(
            result.receipts.len(),
            1,
            "intersection of agent and outcome=allow should be 1"
        );
        assert_eq!(result.total_count, 1);
        assert!(result.receipts[0].receipt.is_allowed());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_agent_subject_cursor_pagination() {
        let path = unique_db_path("rq-agent-cursor");
        let store = SqliteReceiptStore::open(&path).unwrap();

        use chio_core::capability::{
            CapabilityToken, CapabilityTokenBody, ChioScope, Operation, ToolGrant,
        };
        use chio_core::crypto::Keypair;

        let kp_agent = Keypair::generate();
        let kp_issuer = Keypair::generate();

        let body = CapabilityTokenBody {
            id: "cap-page-1".to_string(),
            issuer: kp_issuer.public_key(),
            subject: kp_agent.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            issued_at: 1000,
            expires_at: 9000,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign(body, &kp_issuer).expect("sign failed");
        store.record_capability_snapshot(&token, None).unwrap();

        // Insert 7 receipts for cap-page-1
        for i in 0..7usize {
            store
                .append_chio_receipt(&make_receipt(
                    &format!("r-page-{i}"),
                    "cap-page-1",
                    "s",
                    "t",
                    Decision::Allow,
                    100 + i as u64,
                    None,
                ))
                .unwrap();
        }

        let agent_key = kp_agent.public_key().to_hex();

        // Paginate with page size 3, collect all seqs
        let mut all_seqs = Vec::new();
        let mut cursor = None;

        loop {
            let page = store
                .query_receipts(&ReceiptQuery {
                    agent_subject: Some(agent_key.clone()),
                    cursor,
                    limit: 3,
                    ..Default::default()
                })
                .unwrap();

            for r in &page.receipts {
                all_seqs.push(r.seq);
            }

            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }

        assert_eq!(
            all_seqs.len(),
            7,
            "all 7 receipts should be seen across pages with agent filter"
        );

        // No duplicates
        let mut unique = all_seqs.clone();
        unique.dedup();
        assert_eq!(all_seqs, unique, "no duplicate seqs");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_cursor_u64_max_returns_empty() {
        // Querying with cursor=u64::MAX means "return receipts with seq > u64::MAX",
        // which is impossible -- the result must always be empty.
        let path = unique_db_path("rq-cursor-u64max");
        let store = SqliteReceiptStore::open(&path).unwrap();

        // Insert a few receipts so the store is non-empty.
        for i in 0..5usize {
            let r = make_receipt(
                &format!("r-max-{i}"),
                "cap-1",
                "s",
                "t",
                Decision::Allow,
                100 + i as u64,
                None,
            );
            store.append_chio_receipt(&r).unwrap();
        }

        let result = store
            .query_receipts(&ReceiptQuery {
                cursor: Some(u64::MAX),
                limit: 10,
                ..Default::default()
            })
            .unwrap();

        assert_eq!(
            result.receipts.len(),
            0,
            "cursor=u64::MAX should return no receipts (no seq can exceed u64::MAX)"
        );
        assert!(
            result.next_cursor.is_none(),
            "next_cursor should be None when result is empty"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_query_combined_filters() {
        let path = unique_db_path("rq-combined");
        let store = SqliteReceiptStore::open(&path).unwrap();

        // cap-A, allow, ts=200
        store
            .append_chio_receipt(&make_receipt(
                "r-1",
                "cap-A",
                "s",
                "t",
                Decision::Allow,
                200,
                None,
            ))
            .unwrap();
        // cap-A, deny, ts=300
        store
            .append_chio_receipt(&make_receipt(
                "r-2",
                "cap-A",
                "s",
                "t",
                Decision::Deny {
                    reason: "no".to_string(),
                    guard: "G".to_string(),
                },
                300,
                None,
            ))
            .unwrap();
        // cap-B, allow, ts=200
        store
            .append_chio_receipt(&make_receipt(
                "r-3",
                "cap-B",
                "s",
                "t",
                Decision::Allow,
                200,
                None,
            ))
            .unwrap();
        // cap-A, allow, ts=100 (before since)
        store
            .append_chio_receipt(&make_receipt(
                "r-4",
                "cap-A",
                "s",
                "t",
                Decision::Allow,
                100,
                None,
            ))
            .unwrap();
        // cap-A, allow, ts=250 -- matches all 3 filters
        store
            .append_chio_receipt(&make_receipt(
                "r-5",
                "cap-A",
                "s",
                "t",
                Decision::Allow,
                250,
                None,
            ))
            .unwrap();

        let result = store
            .query_receipts(&ReceiptQuery {
                capability_id: Some("cap-A".to_string()),
                outcome: Some("allow".to_string()),
                since: Some(150),
                limit: 10,
                ..Default::default()
            })
            .unwrap();

        // r-1 (cap-A, allow, ts=200) and r-5 (cap-A, allow, ts=250) should match.
        assert_eq!(result.receipts.len(), 2);
        assert_eq!(result.total_count, 2);
        for r in &result.receipts {
            assert_eq!(r.receipt.capability_id, "cap-A");
            assert!(r.receipt.is_allowed());
            assert!(r.receipt.timestamp >= 150);
        }

        let _ = std::fs::remove_file(path);
    }
}
