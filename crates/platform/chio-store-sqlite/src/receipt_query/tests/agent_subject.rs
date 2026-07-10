use chio_core::receipt::decision::Decision;
use chio_kernel::receipt_query::ReceiptQuery;
use chio_kernel::ReceiptStore;

use crate::receipt_store::SqliteReceiptStore;

use super::support::{make_receipt, unique_db_path};
#[test]
fn test_query_agent_subject_filter() {
    let path = unique_db_path("rq-agent-subject");
    let store = SqliteReceiptStore::open(&path).unwrap();

    use chio_core::capability::{
        scope::{ChioScope, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
        scope::{ChioScope, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
        scope::{ChioScope, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
        scope::{ChioScope, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
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
                read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
