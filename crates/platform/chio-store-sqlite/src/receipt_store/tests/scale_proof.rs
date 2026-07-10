use super::super::*;
use super::support::*;

const MEASURED_APPENDS: usize = 200;
const MAX_RATIO: f64 = 4.0;

fn mean_append_nanos_at_history(
    history: usize,
    label: &str,
) -> Result<f64, Box<dyn std::error::Error>> {
    let path = unique_db_path(&format!("chio-scale-{label}"));
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    // Background checkpoints on at the ADR-0008 default batch size, so the
    // measurement covers the full production hot path including checkpoint
    // construction on the writer thread.
    store.enable_background_checkpoints(BackgroundCheckpointSigner {
        keypair: Arc::new(keypair.clone()),
        max_batch: 100,
    })?;

    for i in 0..history {
        let receipt = sample_receipt_with_keypair(
            &format!("rcpt-scale-{label}-seed-{i}"),
            (i + 1) as u64,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    let started = std::time::Instant::now();
    for i in 0..MEASURED_APPENDS {
        let receipt = sample_receipt_with_keypair(
            &format!("rcpt-scale-{label}-measure-{i}"),
            (history + i + 1) as u64,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    let elapsed = started.elapsed();

    let _ = fs::remove_file(&path);
    Ok(elapsed.as_nanos() as f64 / MEASURED_APPENDS as f64)
}

/// Scale proof: per-append cost is batch-bounded (O(b)), not history-bounded.
/// Run explicitly:
///   cargo test -p chio-store-sqlite --release -- --ignored append_scale_proof
#[test]
#[ignore = "scale proof; seeds up to 1e6 receipts, run with --release -- --ignored"]
fn append_scale_proof_is_batch_bounded_across_history_sizes(
) -> Result<(), Box<dyn std::error::Error>> {
    let at_1e3 = mean_append_nanos_at_history(1_000, "1e3")?;
    let at_1e5 = mean_append_nanos_at_history(100_000, "1e5")?;
    let at_1e6 = mean_append_nanos_at_history(1_000_000, "1e6")?;

    println!("append mean ns/op: 1e3={at_1e3:.0} 1e5={at_1e5:.0} 1e6={at_1e6:.0}");
    println!(
        "ratios vs 1e3: 1e5={:.2}x 1e6={:.2}x (RFC target 2x, asserted bound {MAX_RATIO}x)",
        at_1e5 / at_1e3,
        at_1e6 / at_1e3
    );

    assert!(
        at_1e5 / at_1e3 <= MAX_RATIO,
        "append at N=1e5 is {:.2}x of N=1e3 (bound {MAX_RATIO}x): per-append work grew with history",
        at_1e5 / at_1e3
    );
    assert!(
        at_1e6 / at_1e3 <= MAX_RATIO,
        "append at N=1e6 is {:.2}x of N=1e3 (bound {MAX_RATIO}x): per-append work grew with history",
        at_1e6 / at_1e3
    );
    Ok(())
}
