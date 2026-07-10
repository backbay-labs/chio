//! A declared RSS soft ceiling sheds new admissions with Overloaded { Allocation }
//! before the OS OOM-kills the process.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_kernel::MemoryBudgetConfig;

#[test]
fn memory_budget_defaults_are_sane() {
    let b = MemoryBudgetConfig::defaults();
    assert_eq!(b.receipt_mirror_capacity, 4096);
    assert_eq!(b.federation_cache_capacity, 8192);
    assert_eq!(b.federation_cache_idle_ttl_secs, 3600);
    assert_eq!(b.velocity_bucket_cap, 65_536);
    assert_eq!(b.admission_key_cap, 4096);
    assert_eq!(b.journal_entry_cap, 4096);
    assert_eq!(
        b.rss_soft_limit_bytes, None,
        "Stage A ships rss soft limit off"
    );
    assert!(b.rss_sample_interval_secs >= 1);
}
