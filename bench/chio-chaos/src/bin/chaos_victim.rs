//! Crash-test victim for the SIGKILL-mid-append chaos scenario.
//!
//! Protocol: `chaos_victim <db_path> <ack_path> <max_receipts> <run_nonce>`.
//! Opens the receipt store, then loops: append one receipt,
//! `flush_receipt_writes()` as the durability barrier, and only after a
//! successful flush append an `ack <seq>` line to the ack file (opened
//! O_APPEND, `sync_data` after each line). The ack file is the ground truth of
//! which receipts the store promised were durable; the DB flush happens-before
//! the ack write, so a recovered ack implies a durably-committed receipt.
//!
//! `run_nonce` disambiguates receipt ids across rounds that reuse one store:
//! ids embed the victim pid, and the OS can hand a later round a recycled pid,
//! which would collide with the UNIQUE receipt_id column and read as a
//! pre-kill victim crash.
//!
//! The parent SIGKILLs this process mid-loop. `max_receipts` is sized by the
//! caller so the victim cannot drain its loop before the kill lands.

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use chio_chaos::{ack_line, chaos_receipt};
use chio_store_sqlite::SqliteReceiptStore;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("chaos_victim: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let db_path = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "missing <db_path> argument".to_string())?;
    let ack_path = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "missing <ack_path> argument".to_string())?;
    let max_receipts: u64 = args
        .next()
        .ok_or_else(|| "missing <max_receipts> argument".to_string())?
        .parse()
        .map_err(|error| format!("invalid <max_receipts>: {error}"))?;
    let run_nonce = args
        .next()
        .ok_or_else(|| "missing <run_nonce> argument".to_string())?;

    let store = SqliteReceiptStore::open(&db_path)
        .map_err(|error| format!("open receipt store {}: {error}", db_path.display()))?;
    // O_APPEND so every write lands atomically at end-of-file even as the parent
    // races a kill; a small line write is not torn by SIGKILL.
    let mut ack_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&ack_path)
        .map_err(|error| format!("open ack file {}: {error}", ack_path.display()))?;

    let pid = std::process::id();
    for i in 0..max_receipts {
        let unique = format!("{run_nonce}-{pid}-{i}");
        let receipt = chaos_receipt(&unique, i + 1).map_err(|error| error.to_string())?;
        let seq = store
            .append_chio_receipt_returning_seq(&receipt)
            .map_err(|error| format!("append receipt: {error}"))?;
        // Durability barrier: after this returns, everything appended so far is
        // committed and checkpointed.
        store
            .flush_receipt_writes()
            .map_err(|error| format!("flush receipt writes: {error}"))?;
        // The ack is written only AFTER a successful flush.
        ack_file
            .write_all(ack_line(seq).as_bytes())
            .map_err(|error| format!("append ack line: {error}"))?;
        ack_file
            .sync_data()
            .map_err(|error| format!("sync ack line: {error}"))?;
    }
    Ok(())
}
