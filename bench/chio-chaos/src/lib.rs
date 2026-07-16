//! Real fault-injection chaos harness for the Chio receipt store.
//!
//! This crate carries the scenario vocabulary ([`ChaosScenario`]), a typed
//! failure surface ([`ChaosError`]), a deterministic seeded RNG ([`ChaosRng`]),
//! and the workload and invariant primitives the SIGKILL-mid-append crash test
//! drives against a live [`chio_store_sqlite::SqliteReceiptStore`].
//!
//! The durability contract the crash test enforces: the victim process appends
//! a receipt, flushes the store as a durability barrier, and only after a
//! successful flush records an `ack <seq>` line. A recovered ack therefore means
//! the store promised a client that receipt was durable. [`check_durable_acks`]
//! verifies that every such promise survives an arbitrary crash: the acked
//! `entry_seq` is at or below the recovered committed floor and the entry reads
//! back. Fail-closed: a lost or unreadable acknowledged receipt is a typed
//! [`ChaosError::InvariantViolated`].

#![forbid(unsafe_code)]

use std::env::VarError;
use std::path::Path;
use std::time::{Duration, Instant};

use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core_types::receipt::decision::{Decision, ToolCallAction};
use chio_core_types::receipt::kinds::TrustLevel;
use chio_store_sqlite::SqliteReceiptStore;

/// Chaos scenario vocabulary. Each variant names a real fault the harness
/// injects against a live store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChaosScenario {
    KillMinusNineMidAppend,
    SqliteEnospc,
    SigtermDrain,
    RetentionDuringLoad,
    HungToolServer,
    BlockingGuard,
    WedgedWriter,
}

impl ChaosScenario {
    /// Passport case id this scenario exercises (see the whitelist in
    /// crates/platform/chio-transaction-passport/src/runtime_security/artifacts.rs::is_supported_chaos_case).
    pub fn passport_case_id(&self) -> &'static str {
        match self {
            ChaosScenario::KillMinusNineMidAppend | ChaosScenario::SqliteEnospc => {
                "receipt-log-unavailable"
            }
            ChaosScenario::SigtermDrain => "tool-restart-lost-lease-cache",
            ChaosScenario::RetentionDuringLoad => "registry-split-brain",
            ChaosScenario::HungToolServer => "revocation-oracle-unavailable",
            ChaosScenario::BlockingGuard => "policy-reload-during-dispatch",
            ChaosScenario::WedgedWriter => "clock-skew-expiry-bypass",
        }
    }
}

/// Typed failure surface for the chaos harness. Every variant denies; there is
/// no silent-success path.
#[derive(Debug, thiserror::Error)]
pub enum ChaosError {
    #[error("stack boot failed: {0}")]
    Boot(String),
    #[error("fault injection did not take effect: {0}")]
    InjectionNoOp(&'static str),
    #[error("post-fault invariant violated: {0}")]
    InvariantViolated(String),
    #[error("victim process control failed: {0}")]
    Victim(String),
}

/// SplitMix64; the seed is printed in every test so a failure reproduces.
pub struct ChaosRng(u64);

impl ChaosRng {
    pub fn new(seed: u64) -> Self {
        ChaosRng(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform draw in `[lo, hi)`. An empty or inverted span (`hi <= lo`) yields
    /// `lo`, so a caller never divides by a zero span.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + (self.next_u64() % (hi - lo))
    }
}

/// The durable-ack line the victim appends after a successful flush. The
/// checker parses this exact shape; keeping the format in one place binds the
/// producer and the consumer to the same contract.
pub fn ack_line(seq: u64) -> String {
    format!("ack {seq}\n")
}

/// Build a signed workload receipt for the chaos victim. `unique` disambiguates
/// the receipt id across victim processes and loop iterations so the shared
/// receipt store never sees a duplicate id; `timestamp` orders the body.
pub fn chaos_receipt(unique: &str, timestamp: u64) -> Result<ChioReceipt, ChaosError> {
    let keypair = Keypair::generate();
    let action = ToolCallAction::from_parameters(serde_json::json!({ "chaos": unique }))
        .map_err(|error| ChaosError::Boot(format!("build chaos tool action: {error}")))?;
    ChioReceipt::sign(
        ChioReceiptBody {
            id: format!("chaos-rcpt-{unique}"),
            timestamp,
            capability_id: "cap-chaos".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{unique}"),
            policy_hash: "policy-chaos".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .map_err(|error| ChaosError::Boot(format!("sign chaos receipt: {error}")))
}

/// Verify that every acknowledged receipt survived crash recovery, returning the
/// number of acked receipts that verified.
///
/// For each `ack <seq>` line in `ack_path`: the acknowledged `entry_seq` must be
/// at or below the store's recovered committed floor AND the entry must read
/// back. A missing or empty ack file is treated as "no promises made yet" and
/// verifies zero (per-round tolerant: a single crash round may kill the victim
/// before it durably acked anything). A malformed ack line, a promise beyond the
/// committed floor, or a committed but unreadable entry is a fail-closed
/// [`ChaosError::InvariantViolated`].
///
/// The returned count lets a multi-round crash lane prove the run as a whole
/// observed at least one surviving durable ack (see [`require_verified_acks`]),
/// so a run that killed the victim before any ack in every round cannot pass
/// vacuously.
///
/// This is a plain function so the checker-integrity test can attack it
/// directly with a fabricated ack.
pub fn check_durable_acks(
    store: &SqliteReceiptStore,
    ack_path: &Path,
) -> Result<usize, ChaosError> {
    let committed = store
        .latest_committed_entry_seq()
        .map_err(|error| ChaosError::InvariantViolated(format!("read committed floor: {error}")))?;

    let contents = match std::fs::read_to_string(ack_path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            return Err(ChaosError::InvariantViolated(format!(
                "read ack file {}: {error}",
                ack_path.display()
            )))
        }
    };

    let mut verified = 0usize;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let seq = parse_ack_seq(trimmed)?;
        if seq > committed {
            return Err(ChaosError::InvariantViolated(format!(
                "acknowledged receipt entry_seq {seq} exceeds recovered committed floor {committed}"
            )));
        }
        let rows = store
            .receipts_canonical_bytes_range(seq, seq)
            .map_err(|error| {
                ChaosError::InvariantViolated(format!(
                    "read back acknowledged entry_seq {seq}: {error}"
                ))
            })?;
        if rows.is_empty() {
            return Err(ChaosError::InvariantViolated(format!(
                "acknowledged receipt entry_seq {seq} is committed but unreadable after recovery"
            )));
        }
        verified += 1;
    }
    Ok(verified)
}

/// Run-level non-vacuity guard for the crash lanes: a full run that verified zero
/// durable acks across every round proved nothing about durability (the signal
/// only showed a kill landed, never that an acknowledged receipt survived), so it
/// fails closed with [`ChaosError::InjectionNoOp`] rather than passing vacuously.
///
/// Per-round tolerance is preserved because the caller accumulates the
/// [`check_durable_acks`] counts across all rounds and only asserts on the total.
pub fn require_verified_acks(total: usize) -> Result<(), ChaosError> {
    if total == 0 {
        return Err(ChaosError::InjectionNoOp(
            "crash lane verified zero durable acks across all rounds",
        ));
    }
    Ok(())
}

/// Parse a single `ack <seq>` line into its `entry_seq`. A line that does not
/// match the exact producer format is a fail-closed violation, not a silent
/// skip: a garbled durability record must never pass unnoticed.
fn parse_ack_seq(line: &str) -> Result<u64, ChaosError> {
    line.strip_prefix("ack ")
        .and_then(|rest| rest.trim().parse::<u64>().ok())
        .ok_or_else(|| ChaosError::InvariantViolated(format!("malformed ack line: {line:?}")))
}

/// Bound on how long a store may take to seed a verified head before it is
/// considered bricked.
const RECOVERY_HEALTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll interval while waiting for the async verified-head seed to clear.
const HEALTH_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Wait for a store to report a verified, unpoisoned head.
///
/// The commit writer seeds its verified head on its actor thread and starts
/// serving-closed (head-poisoned) until that seed completes, so a store sampled
/// the instant after a reopen (or a reseed under retention) can still report
/// unhealthy. The invariant is that health becomes true within a bounded window,
/// not that it is true on the first sample. A store still unhealthy at the
/// deadline fails closed with a typed [`ChaosError::InvariantViolated`] carrying
/// `context`.
pub fn wait_until_healthy(store: &SqliteReceiptStore, context: &str) -> Result<(), ChaosError> {
    let deadline = Instant::now() + RECOVERY_HEALTH_TIMEOUT;
    loop {
        let health = store
            .receipt_store_health()
            .map_err(|error| ChaosError::InvariantViolated(format!("{context}: {error}")))?;
        if health.healthy {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(ChaosError::InvariantViolated(format!(
                "{context}: store still unhealthy {RECOVERY_HEALTH_TIMEOUT:?} after recovery: {health:?}"
            )));
        }
        std::thread::sleep(HEALTH_POLL_INTERVAL);
    }
}

/// Parse a `CHIO_CHAOS_SEED` value: decimal, or hex when prefixed with `0x`/`0X`.
fn parse_chaos_seed(raw: &str) -> Result<u64, ChaosError> {
    let trimmed = raw.trim();
    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        trimmed.parse::<u64>()
    };
    parsed.map_err(|_| {
        ChaosError::Boot("CHIO_CHAOS_SEED must be a u64 (decimal or 0x-hex)".to_string())
    })
}

/// Read the chaos RNG seed from `CHIO_CHAOS_SEED` (decimal or `0x`-prefixed
/// hex), or `default` if the variable is unset. A set-but-non-unicode value
/// fails closed rather than silently reverting to `default`, so a corrupted knob
/// cannot quietly re-run the fixed schedule.
pub fn chaos_seed(default: u64) -> Result<u64, ChaosError> {
    match std::env::var("CHIO_CHAOS_SEED") {
        Ok(raw) => parse_chaos_seed(&raw),
        Err(VarError::NotPresent) => Ok(default),
        Err(VarError::NotUnicode(_)) => Err(ChaosError::Boot(
            "CHIO_CHAOS_SEED is set but not valid unicode".to_string(),
        )),
    }
}

/// Read the chaos round count from `CHIO_CHAOS_ITERATIONS` (floored at 1), or
/// `default` if the variable is unset. A set-but-non-unicode value fails closed
/// rather than silently reverting to `default`.
pub fn chaos_iterations(default: u64) -> Result<u64, ChaosError> {
    match std::env::var("CHIO_CHAOS_ITERATIONS") {
        Ok(raw) => {
            let parsed: u64 = raw
                .trim()
                .parse()
                .map_err(|_| ChaosError::Boot("CHIO_CHAOS_ITERATIONS must be a u64".to_string()))?;
            Ok(parsed.max(1))
        }
        Err(VarError::NotPresent) => Ok(default),
        Err(VarError::NotUnicode(_)) => Err(ChaosError::Boot(
            "CHIO_CHAOS_ITERATIONS is set but not valid unicode".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    #[test]
    fn rng_is_deterministic_for_a_seed() {
        let mut a = ChaosRng::new(0xC10A_0515);
        let mut b = ChaosRng::new(0xC10A_0515);
        for _ in 0..64 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn rng_range_stays_in_bounds_and_handles_empty_span() {
        let mut rng = ChaosRng::new(1);
        for _ in 0..1_000 {
            let value = rng.range(5, 400);
            assert!((5..400).contains(&value), "draw {value} out of [5, 400)");
        }
        assert_eq!(rng.range(7, 7), 7);
        assert_eq!(rng.range(9, 4), 9);
    }

    #[test]
    fn passport_case_ids_match_the_supported_whitelist() {
        assert_eq!(
            ChaosScenario::KillMinusNineMidAppend.passport_case_id(),
            "receipt-log-unavailable"
        );
        assert_eq!(
            ChaosScenario::SqliteEnospc.passport_case_id(),
            "receipt-log-unavailable"
        );
        assert_eq!(
            ChaosScenario::SigtermDrain.passport_case_id(),
            "tool-restart-lost-lease-cache"
        );
        assert_eq!(
            ChaosScenario::RetentionDuringLoad.passport_case_id(),
            "registry-split-brain"
        );
        assert_eq!(
            ChaosScenario::HungToolServer.passport_case_id(),
            "revocation-oracle-unavailable"
        );
        assert_eq!(
            ChaosScenario::BlockingGuard.passport_case_id(),
            "policy-reload-during-dispatch"
        );
        assert_eq!(
            ChaosScenario::WedgedWriter.passport_case_id(),
            "clock-skew-expiry-bypass"
        );
    }

    #[test]
    fn parse_ack_seq_rejects_malformed_lines() {
        assert_eq!(parse_ack_seq("ack 42").test_unwrap(), 42);
        assert!(parse_ack_seq("ack").is_err());
        assert!(parse_ack_seq("nack 42").is_err());
        assert!(parse_ack_seq("ack twelve").is_err());
    }

    #[test]
    fn check_durable_acks_counts_zero_for_absent_file() {
        let dir = tempfile::tempdir().test_unwrap();
        let db_path = dir.path().join("receipts.sqlite");
        let store = SqliteReceiptStore::open(&db_path).test_unwrap();
        let absent = dir.path().join("does-not-exist.log");
        let verified =
            check_durable_acks(&store, &absent).test_expect("absent ack file must verify zero");
        assert_eq!(
            verified, 0,
            "an absent ack file made no durability promises"
        );
    }

    #[test]
    fn require_verified_acks_rejects_zero_total() {
        assert!(
            matches!(require_verified_acks(0), Err(ChaosError::InjectionNoOp(_))),
            "a run that verified zero durable acks must fail closed"
        );
        assert!(
            require_verified_acks(1).is_ok(),
            "one surviving durable ack clears the non-vacuity guard"
        );
    }
}
