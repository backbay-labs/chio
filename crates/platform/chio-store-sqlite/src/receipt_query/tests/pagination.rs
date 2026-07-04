use chio_core::receipt::decision::Decision;
use chio_kernel::receipt_query::ReceiptQuery;
use chio_kernel::{ReceiptStore, MAX_QUERY_LIMIT};

use crate::receipt_store::SqliteReceiptStore;

use super::support::{make_receipt, unique_db_path};
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
// agent_subject filter tests
// ---------------------------------------------------------------------------

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
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
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
