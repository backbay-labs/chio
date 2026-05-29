# Chio Replay Compatibility

Tracks bless events for the deterministic replay corpus
(`tests/replay/goldens/**`) and cross-version compatibility
annotations.

This file is the operator-facing audit surface for the
replay-gate's golden snapshot. Every re-bless of the corpus appends an
entry here in the same commit that updates the goldens; the tests/replay
`.bless-audit.log` is the machine-readable counterpart used by the
`CHIO_BLESS` gate's clause 7 lockstep check.

## Bootstrap entry

- Initial bless of corpus on the replay-goldens bootstrap branch.
- 50 scenarios across 10 families:
  - `allow_metered` (5)
  - `allow_simple` (8)
  - `allow_with_delegation` (6)
  - `deny_expired` (5)
  - `deny_revoked` (4)
  - `deny_scope_mismatch` (6)
  - `guard_rewrite` (6)
  - `replay_attack` (4)
  - `tampered_canonical_json` (3)
  - `tampered_signature` (3)
- Synthesis recipe (matches
  `tests/replay/tests/golden_byte_equivalence.rs`):
  - `receipt = { nonce, scenario, verdict }` (canonical-JSON, sorted
    keys).
  - `checkpoint = { clock, issuer, scenario }` (canonical-JSON, sorted
    keys).
  - `root = SHA-256(canonical(receipt) || canonical(checkpoint))`.
  - First nonce per scenario from `ScenarioDriver::next_nonce()` (fixed
    clock `2026-01-01T00:00:00Z`, counter starts at zero per scenario).
  - Issuer key is the verifying key derived from
    `tests/replay/test-key.seed` (sha256 in
    `tests/replay/test-key.seed.sha256`).
- Test signing key: `tests/replay/test-key.seed` (sha256 pinned in
  `tests/replay/test-key.seed.sha256`).

## Re-bless protocol

See the deterministic-replay and `CHIO_BLESS` gate contract in
`spec/PROTOCOL.md`. A re-bless is required whenever any of the following
changes in a way that affects the on-disk goldens bytes:

- The synthesis recipe (receipt or checkpoint shape, canonical-JSON
  rules, root algorithm).
- The fixed clock or nonce counter origin in
  `tests/replay/src/driver.rs`.
- The signing seed under `tests/replay/test-key.seed`.
- The fixture manifests under `tests/replay/fixtures/**`.

The seven programmatic clauses enforced by
`tests/replay/src/bless.rs` are:

1. `CHIO_BLESS=1` is set in the environment.
2. `BLESS_REASON` is set and non-empty.
3. The current branch is not `main` and not `release/*`.
4. The working tree is clean except for paths under
   `tests/replay/goldens/` and `docs/replay-compat.md`.
5. `stderr` is a TTY (human-attended terminal).
6. `CI` env var is unset or `false` (CI cannot bless).
7. The bless flow appends an audit entry to
   `tests/replay/.bless-audit.log` and the same commit must include
   that audit-log line; the gate refuses if the audit log is dirty
   while the goldens are clean (or vice versa).

The eighth clause (CODEOWNERS review on `tests/replay/goldens/**`) is
enforced by branch protection on the PR side.

Use `scripts/bless-replay-goldens.sh` for the
operator-facing wrapper that drives the binary's `--bless` flag.

## Replay Corpus Stability

Chio has no public cross-version compatibility matrix before the first public
v1 release tag. Replay goldens are pre-release fixtures for the current v1
branch. Internal `v2.x` and `v3.x` milestone labels are not protocol versions
and must not be listed as supported compatibility floors.

Future public tags may add a compatibility matrix after an explicit release
decision.

## Bless history

| date       | branch                          | reason                          |
| ---------- | ------------------------------- | ------------------------------- |
| 2026-04-26 | replay-goldens bootstrap branch | Initial bless of replay corpus. |

## Future Ratchet Rule

After a public v1 release, release engineering may add a tag-based replay
ratchet. Until then, the current branch may destructively rewrite pre-release
goldens when protocol semantics change, provided the bless audit explains the
reason and the vector manifest is refreshed.

### Promoting from best_effort to supported

A `best_effort` row is promoted to `supported` only after the canonical
formats have stabilized for at least one full release cycle and the row
is within the N=5 window. Promotion lands as a single PR titled
`chore(replay): promote vX.Y to supported in release_compat_matrix.toml`.
