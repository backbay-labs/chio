# chio-reputation Architecture Notes

## Module Boundaries

`lib.rs` exposes pure, storage-agnostic reputation scoring over
caller-provided evidence. `model.rs` owns corpus, scorecard, configuration, and
imported-trust data shapes. `score.rs` computes local scorecards from receipts,
capability-lineage records, budget usage, and optional incident reports.
`compare.rs` owns delegation comparisons and imported reputation signal
construction. `feed.rs`, `feeds/`, and `tier.rs` provide deterministic feed
deltas and marketplace tier mapping without depending on arena, conformance,
kernel, or storage crates.

## Trust Boundaries

Receipt-derived local scoring is fail-closed when `ReputationConfig` has no
trusted kernel keys. Callers must pass exact kernel public-key strings before
receipt integrity can contribute to the score. The crate verifies receipt ids,
signatures, action hashes, and trusted kernel keys before accepting receipt
evidence.

Imported reputation signals are the external identity boundary. They combine a
caller-provided local corpus with evidence-share provenance from another
operator. Imported issuer, partner, signer, and share identifiers must be
stable authority strings before the signal can be accepted. The scorecard may
still be computed for diagnostics, but attenuation is only applied when the
imported trust policy accepts the provenance.

## Security And API Constraints

- Keep the crate pure and deterministic. No storage, network, clock, or kernel
  dependencies should enter the scoring path.
- Preserve source-compatible public structs and builders.
- Clamp numeric score inputs to closed score ranges so non-finite or negative
  feed input cannot subtract reputation or inflate a score.
- Treat empty trusted-kernel-key sets as a misconfiguration that filters receipt
  evidence instead of trusting ambient receipts.
- Reject ambiguous imported identity material rather than silently trimming it
  into authority-bearing provenance.

## Completed Material Improvement

`build_imported_reputation_signal` now rejects missing share ids and imported
identity fields with surrounding whitespace or control characters. This keeps
issuer, partner, signer, and share identifiers unambiguous before imported
signals can be accepted or attenuated into a composite reputation score.
