use super::super::*;
use super::support::*;

fn batch_fixture(
    count: usize,
) -> Result<(tempfile::TempDir, SqliteReceiptStore, Vec<ChioReceipt>), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = SqliteReceiptStore::open(directory.path().join("receipts.sqlite"))?;
    let keypair = receipt_test_keypair();
    let receipts = (0..count)
        .map(|index| {
            sample_receipt_with_keypair(&format!("batch-{index}"), index as u64 + 1, &keypair)
        })
        .collect::<Vec<_>>();
    for receipt in &receipts {
        store.append_chio_receipt(receipt)?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(count as u64, &keypair)?;
    Ok((directory, store, receipts))
}

#[test]
fn receipt_batch_verifies_one_chain_per_page_and_preserves_order_and_misses(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, store, receipts) = batch_fixture(256)?;
    let ids = receipts
        .iter()
        .map(|receipt| receipt.id.as_str())
        .collect::<Vec<_>>();
    let before = checkpoint_chain_read_verifications();
    let loaded = store.load_chio_receipts(&ids)?;
    assert_eq!(checkpoint_chain_read_verifications() - before, 1);
    for (loaded, expected) in loaded.into_iter().zip(&receipts) {
        assert_eq!(
            serde_json::to_value(loaded)?,
            serde_json::to_value(Some(expected))?
        );
    }
    let loaded = store.load_chio_receipts(&[&receipts[2].id, "missing", &receipts[0].id])?;
    assert_eq!(
        serde_json::to_value(loaded)?,
        serde_json::to_value(vec![
            Some(receipts[2].clone()),
            None,
            Some(receipts[0].clone())
        ])?
    );
    assert_eq!(checkpoint_chain_read_verifications() - before, 2);
    assert!(store.load_chio_receipts(&[])?.is_empty());
    assert!(store.load_chio_receipts(&vec![ids[0]; 257]).is_err());
    assert_eq!(checkpoint_chain_read_verifications() - before, 2);
    Ok(())
}

#[test]
fn receipt_batch_rejects_corruption_outside_requested_receipts(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, store, receipts) = batch_fixture(3)?;
    assert!(store
        .load_chio_receipts(&[&receipts[0].id])?
        .first()
        .and_then(Option::as_ref)
        .is_some());
    tamper_claim_log_tool_receipt(&store, &receipts[2].id, |receipt| {
        receipt.tool_name = "forged".to_owned();
    });
    assert!(store.load_chio_receipts(&[&receipts[0].id]).is_err());
    Ok(())
}

#[test]
fn receipt_batch_rejects_changed_point_receipt_after_previous_batch(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, store, receipts) = batch_fixture(2)?;
    assert!(store.load_chio_receipts(&[&receipts[0].id]).is_ok());
    tamper_persisted_tool_receipt(&store, &receipts[0].id, |receipt| {
        receipt.tool_name = "forged".to_owned();
    });
    assert!(store.load_chio_receipts(&[&receipts[0].id]).is_err());
    Ok(())
}

#[test]
fn receipt_batch_keeps_verified_snapshot_during_external_write(
) -> Result<(), Box<dyn std::error::Error>> {
    let (directory, store, receipts) = batch_fixture(2)?;
    let database = directory.path().join("receipts.sqlite");
    let loaded = load_chio_receipt_batch_with_snapshot_hook(&store, &[&receipts[0].id], || {
        let connection = rusqlite::Connection::open(database)?;
        connection.execute_batch("DROP TRIGGER IF EXISTS chio_tool_receipts_reject_update;")?;
        connection.execute(
            "UPDATE chio_tool_receipts SET raw_json = '{}' WHERE receipt_id = ?1",
            [&receipts[0].id],
        )?;
        Ok(())
    })?;
    assert_eq!(
        serde_json::to_value(loaded)?,
        serde_json::to_value(vec![Some(receipts[0].clone())])?
    );
    assert!(store.load_chio_receipts(&[&receipts[0].id]).is_err());
    Ok(())
}

#[test]
fn receipt_batch_rejects_checkpoint_corruption_after_previous_batch(
) -> Result<(), Box<dyn std::error::Error>> {
    let (directory, store, receipts) = batch_fixture(2)?;
    assert!(store.load_chio_receipts(&[&receipts[0].id]).is_ok());
    let connection = rusqlite::Connection::open(directory.path().join("receipts.sqlite"))?;
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    connection.execute("UPDATE kernel_checkpoints SET statement_json = '{}'", [])?;
    assert!(store.load_chio_receipts(&[&receipts[0].id]).is_err());
    Ok(())
}

#[test]
fn receipt_batch_restores_missing_checkpoint_guard_through_writer(
) -> Result<(), Box<dyn std::error::Error>> {
    let (directory, store, receipts) = batch_fixture(2)?;
    let connection = rusqlite::Connection::open(directory.path().join("receipts.sqlite"))?;
    connection.execute_batch("DROP TRIGGER kernel_checkpoints_reject_delete;")?;
    assert!(store.load_chio_receipts(&[&receipts[0].id]).is_ok());
    assert!(connection
        .execute("DELETE FROM kernel_checkpoints", [])
        .is_err());
    Ok(())
}
