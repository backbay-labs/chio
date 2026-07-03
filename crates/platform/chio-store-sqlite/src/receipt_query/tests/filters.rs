use chio_core::receipt::decision::Decision;
use chio_kernel::receipt_query::ReceiptQuery;
use chio_kernel::ReceiptStore;

use crate::receipt_store::SqliteReceiptStore;

use super::support::{make_receipt, unique_db_path};
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
