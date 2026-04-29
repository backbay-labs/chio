//! Cross-version replay integration test.
//!
//! Drives the full release-compat matrix end-to-end:
//!
//! 1. Load `release_compat_matrix.toml` via [`CompatMatrix::load`].
//! 2. For every `[[entry]]` at [`CompatLevel::Supported`]: fetch the
//!    bundle (T3 layer), reverify it, and assert the root matches and
//!    no receipt signatures failed.
//! 3. For every `[[entry]]` at [`CompatLevel::BestEffort`]: best-effort
//!    fetch + reverify; failures are logged via `eprintln!` and do NOT
//!    fail the test.
//! 4. Entries at [`CompatLevel::Broken`] are ratchet-excluded by the
//!    loader contract and never reach this code.
//!
//! The full-matrix test is `#[ignore]`d because it depends on:
//!
//! - Live HTTPS to the release CDN (currently `github.com/bb-connor/...`).
//! - Historical tagged-release bundles existing at the URLs the matrix
//!   pins. The placeholder entries in the matrix today (zero / one
//!   sha256, `example`-style URLs) will surface as fetch failures
//!   rather than reverify failures.
//!
//! Run the full suite explicitly with:
//!
//! ```bash
//! cargo test -p chio-replay-gate --test cross_version_replay -- --ignored
//! ```
//!
//! The non-ignored test in this file (`matrix_loads_and_has_at_least_two_entries`)
//! is a fast sanity check that always runs; it asserts the matrix file
//! parses and contains at least the v0.1.0 + v2.0 rows authored in T1.

use std::path::Path;

use chio_replay_gate::cross_version::{
    fetch::fetch_or_cache, reverify::reverify_bundle, CompatLevel, CompatMatrix,
};

/// Path of the matrix TOML, resolved relative to this crate's
/// `CARGO_MANIFEST_DIR` (i.e. `tests/replay/`).
const MATRIX_FILENAME: &str = "release_compat_matrix.toml";

#[test]
fn matrix_loads_and_has_at_least_two_entries() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(MATRIX_FILENAME);
    let matrix = match CompatMatrix::load(&path) {
        Ok(m) => m,
        Err(err) => panic!(
            "release_compat_matrix.toml failed to load from {}: {err}",
            path.display()
        ),
    };
    assert!(
        matrix.entry.len() >= 2,
        "expected at least 2 matrix entries, got {}",
        matrix.entry.len()
    );
    // Sanity-check the schema tag is the one the loader's strict
    // contract demands. (load() already enforces this; the assert is
    // here as a regression guard in case the constant is ever loosened.)
    assert_eq!(
        matrix.schema, "chio.replay.compat/v1",
        "matrix schema must equal chio.replay.compat/v1"
    );
    // Every entry must declare a known compat level.
    for entry in &matrix.entry {
        assert!(
            matches!(
                entry.compat,
                CompatLevel::Supported | CompatLevel::BestEffort | CompatLevel::Broken
            ),
            "entry {} has unrecognized compat level",
            entry.tag
        );
    }
}

/// Live full-matrix run. Skipped by default; opts in via `--ignored`.
///
/// - `Supported` entries MUST reverify cleanly.
/// - `BestEffort` entries are run for telemetry only; failures are
///   logged but do not fail the test.
/// - `Broken` entries are skipped explicitly.
#[ignore]
#[test]
fn cross_version_replay_full_matrix() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(MATRIX_FILENAME);
    let matrix = CompatMatrix::load(&path).unwrap_or_else(|err| {
        panic!("matrix must load: {err}");
    });

    let mut supported_failures: Vec<String> = Vec::new();
    let mut best_effort_failures: Vec<String> = Vec::new();

    for entry in &matrix.entry {
        match entry.compat {
            CompatLevel::Broken => {
                eprintln!("skip(broken): {}", entry.tag);
                continue;
            }
            CompatLevel::Supported => match fetch_or_cache(entry) {
                Ok(bundle) => match reverify_bundle(&bundle, entry) {
                    Ok(report) => {
                        // Supported-tier receipts MUST be signed and verify
                        // cleanly. `receipts_unsigned > 0` covers stub or
                        // malformed receipts whose signature blocks could
                        // not be deserialised - left unchecked, those rows
                        // would silently bypass signature verification and
                        // defeat the supported-tier guarantee.
                        //
                        // `receipts_total == 0` covers an empty bundle: a
                        // tarball that ships zero receipts would otherwise
                        // pass every other check vacuously (no signature
                        // failures, no unsigned receipts, root_match could
                        // even hold for a zero-byte payload). Supported
                        // tags must carry at least one receipt; intentional
                        // zero-receipt fixtures must be downgraded to
                        // `compat = "best_effort"` in the matrix.
                        if !report.root_match
                            || report.receipts_signature_failed > 0
                            || report.receipts_unsigned > 0
                            || report.receipts_total == 0
                        {
                            supported_failures.push(format!(
                                "supported tag {} reverify dirty: root_match={} total={} \
                                 sig_failed={} unsigned={} (recomputed={} bundle={})",
                                entry.tag,
                                report.root_match,
                                report.receipts_total,
                                report.receipts_signature_failed,
                                report.receipts_unsigned,
                                report.recomputed_root_hex,
                                report.bundle_root_hex,
                            ));
                        } else {
                            eprintln!(
                                "ok(supported): {} root_match=true total={} unsigned={}",
                                entry.tag, report.receipts_total, report.receipts_unsigned
                            );
                        }
                    }
                    Err(err) => {
                        supported_failures
                            .push(format!("supported tag {} reverify error: {err}", entry.tag));
                    }
                },
                Err(err) => {
                    supported_failures
                        .push(format!("supported tag {} fetch error: {err}", entry.tag));
                }
            },
            CompatLevel::BestEffort => match fetch_or_cache(entry) {
                Ok(bundle) => match reverify_bundle(&bundle, entry) {
                    Ok(report) => {
                        if !report.root_match || report.receipts_signature_failed > 0 {
                            best_effort_failures.push(format!(
                                "best_effort tag {} reverify dirty (logged, not fatal): \
                                 root_match={} sig_failed={}",
                                entry.tag, report.root_match, report.receipts_signature_failed,
                            ));
                        } else {
                            eprintln!(
                                "ok(best_effort): {} root_match=true total={}",
                                entry.tag, report.receipts_total
                            );
                        }
                    }
                    Err(err) => {
                        best_effort_failures.push(format!(
                            "best_effort tag {} reverify error (logged): {err}",
                            entry.tag
                        ));
                    }
                },
                Err(err) => {
                    best_effort_failures.push(format!(
                        "best_effort tag {} fetch error (logged): {err}",
                        entry.tag
                    ));
                }
            },
        }
    }

    for line in &best_effort_failures {
        eprintln!("WARN {line}");
    }

    assert!(
        supported_failures.is_empty(),
        "supported-tier reverify failures must be empty, got:\n{}",
        supported_failures.join("\n")
    );
}
