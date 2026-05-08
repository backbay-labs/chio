# B3: Anchor-batch Async-only When `require_public_witness=true`

This document is the deep dive for sub-lane B3. It captures the public-witness flag, the sync-path callers, the gate-script algorithm, and the conformance fixture.

## The public-witness flag

`crates/chio-anchor/src/policy.rs` (or wherever `WitnessPolicy` lives) defines:

```rust
pub struct WitnessPolicy {
    pub require_public_witness: bool,
    pub stale_window_seconds: u64,
    // ... other fields ...
}
```

When `require_public_witness=true`, the spec PROTOCOL.md lines 980-993 enumerate five rules. The relevant one for B3 (line 982-984):

> "`require_public_witness: true`, `Witnessed` on the sync path -> reject; use the async verifier path so `AnchorWitnessClient::verify_inclusion` runs."

The async path is `verify_anchor_batch_with_witness_policy_async` at `crates/chio-anchor/src/batch.rs:251-269`. The sync wrapper is `verify_anchor_batch_with_witness_policy` at `crates/chio-anchor/src/batch.rs:227-235`. Today the sync wrapper accepts any policy and produces the right answer for `Pending` and `Stale` but for `Witnessed` it returns "rejected because Witnessed-on-sync-path is not allowed when require_public_witness=true". So the spec rule is structurally honored - but only because of the spec table happens to map sync+Witnessed to reject. There is no compile-time or static guard preventing a producer from constructing the bad policy and calling the sync function.

## Why the existing structural rejection is not enough

The `evaluate_witness_policy` function (called by the sync wrapper at `crates/chio-anchor/src/batch.rs:233`) currently rejects sync+Witnessed under `require_public_witness=true`. So a producer who calls the sync wrapper with the bad policy gets rejected today.

But:

1. The rejection happens at runtime, after structural verify (signature, Merkle re-compute) has already been done. The compute work is wasted.
2. The error returned ("require_public_witness=true requires async verifier") is generic and conflates the rejection reason with the structural-state rejections.
3. Future spec changes could expand the witness states (e.g. `Cached`, `Pinned`) and the sync wrapper's structural rejection is a per-state thing - easy to introduce a new state where the sync wrapper accepts when it should not.
4. **The synthesis (line 35) calls this out**: "Anchor-batch sync path still callable when `require_public_witness=true` contradicts PROTOCOL.md §982-991." The structural rejection means the runtime is correct today but only by accident; the spec MUST is on the routing rule, not on the per-state outcome.

B3 closes this by making the routing-rule explicit: the sync wrapper's first operation is to reject `require_public_witness=true` with a typed `AnchorError::SyncRouteRequiresAdvisoryPolicy`. This makes the routing rule load-bearing and decouples it from the per-state table.

## The sync-path callers

Verified by `grep -rn "verify_anchor_batch_with_witness_policy\b" crates/`. Production callers (non-test, non-async) of the sync wrapper:

(B3.1 ticket includes a full enumeration step. Today the sync wrapper appears to be called primarily from test paths and from `crates/chio-anchor/src/batch.rs:227-235` itself (the function definition). The `02-protocol-realization-engineer.md` line 23 notes the bare sync `verify_anchor_batch` is at `batch.rs:208` and the unit-test path at `batch.rs:361-396`. The full enumeration:

1. `crates/chio-anchor/src/batch.rs:208-215` - bare sync `verify_anchor_batch` (no policy). Used as the root of the verification routine; called by both sync and async wrappers.
2. `crates/chio-anchor/src/batch.rs:227-235` - sync wrapper `verify_anchor_batch_with_witness_policy`. THE FUNCTION B3.2 GATES.
3. `crates/chio-anchor/src/batch.rs:251-269` - async wrapper `verify_anchor_batch_with_witness_policy_async`. Already correct.

Production consumers of the sync wrapper outside `chio-anchor` itself: B3.1 ticket enumerates these by `grep -rn "verify_anchor_batch_with_witness_policy\b"` excluding `*_async`. Expected to be a small set, possibly empty in production paths (the lint script in B3.3 is the future-proofing).

## The gate-script algorithm

`scripts/check-anchor-batch-async-witness.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Find every Rust file in production crates (not under tests/).
mapfile -t FILES < <(find crates/ -name '*.rs' -type f \
    -not -path '*/tests/*' \
    -not -path '*/benches/*' \
    -not -name '*_test.rs')

failures=()
for file in "${FILES[@]}"; do
    # Look for sync-wrapper calls.
    while IFS=':' read -r linenum content; do
        # We have a line with `verify_anchor_batch_with_witness_policy(`.
        # Now scan within +/- 50 lines for `WitnessPolicy {` whose
        # `require_public_witness:` field is set to `true`.
        start=$((linenum - 50))
        end=$((linenum + 50))
        if [[ $start -lt 1 ]]; then start=1; fi

        window=$(sed -n "${start},${end}p" "$file")
        # Heuristic: if there's a WitnessPolicy { ... require_public_witness: true ... }
        # nearby, flag it. False-positives are tolerable; false-negatives are not.
        if grep -q 'require_public_witness:\s*true' <<< "$window"; then
            # Confirm the call we matched is the SYNC variant, not async.
            if [[ ! "$content" =~ verify_anchor_batch_with_witness_policy_async ]]; then
                failures+=("$file:$linenum: sync wrapper called with require_public_witness=true nearby")
            fi
        fi
    done < <(grep -n -P 'verify_anchor_batch_with_witness_policy\s*\(' "$file" | grep -v '_async')
done

if (( ${#failures[@]} > 0 )); then
    echo "anchor-batch async-witness gate FAILED:"
    for f in "${failures[@]}"; do echo "  $f"; done
    exit 1
fi
exit 0
```

The script's contract (R3 BLOCKER #2 fix - honest reframing):

- **Tolerated**: false-positives (e.g., `WitnessPolicy { require_public_witness: false, ... }` near a sync call - the script flags this conservatively, but the policy is fine; reviewer judges).
- **Tolerated** (REVISED per R3): false-negatives. The grep-window heuristic CANNOT guarantee zero false-negatives. Counter-examples that produce false negatives include (a) `WitnessPolicy` constructed in a separate function from where the sync wrapper is called (50-line window does not span function boundaries reliably), (b) `WitnessPolicy` deserialized from JSON or YAML (literal `require_public_witness: true` is in a config file, not in Rust source), (c) `WitnessPolicy` built via builder/setter syntax (`WitnessPolicy::default().require_public_witness(true)` does not match the regex), (d) cross-crate calls where the producer and consumer live in different crates. **The runtime gate at `crates/chio-anchor/src/batch.rs:227-235` is the load-bearing defense** (the actual spec MUST enforcement); the lint exists ONLY to give developers fast feedback on the obvious cases (literal struct-init syntax in the same file as the sync wrapper call).
- **Idempotent**: running the script repeatedly returns the same exit code.

Implementation polish (regex tightening, multi-line policy struct support) is a B3.3 PR detail. **A future trj6 ticket may upgrade this to AST-based analysis (e.g. `syn`-parsed call-graph traversal in a Cargo `xtask`) for a true static guarantee, but that is OUT OF SCOPE for release work.** Lane B3's contract is honest: the runtime gate is the MUST enforcement; the lint is documentation.

## The conformance fixture

Path: `crates/chio-conformance/tests/anchor_batch_sync_path_rejected_under_public_witness.rs`.

The fixture must EXERCISE the production sync-wrapper call site (not a mock) and must FAIL when B3.2 is reverted (the early-return removed).

**Fixture structure**:

```rust
//! W2.3 negative conformance test: anchor-batch sync routing under public witness.
//!
//! Threat: a producer constructs WitnessPolicy { require_public_witness: true, ... }
//! and calls the SYNC verifier. PROTOCOL.md §6.4.1 (post-B3.4) says this MUST be
//! rejected at runtime. The fixture exercises the production sync wrapper at
//! `crates/chio-anchor/src/batch.rs:227-235` and asserts the runtime rejection.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_anchor::{
    build_anchor_batch, verify_anchor_batch_with_witness_policy,
    AnchorBatchWitness, AnchorBatchWitnessKind, AnchorError, WitnessPolicy,
};
use chio_core::hashing::Hash;
use chio_core::Keypair;

fn build_witnessed_batch(kp: &Keypair) -> chio_anchor::AnchorBatch {
    // Same shape as anchor_batch_forged_root_rejected.rs:32-45 but with a
    // Witnessed state instead of Pending.
    let checkpoint_ids = vec![
        "ckpt-1700000000".to_string(),
        "ckpt-1700000060".to_string(),
        "ckpt-1700000120".to_string(),
        "ckpt-1700000180".to_string(),
    ];
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:placeholder".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let mut batch = build_anchor_batch(checkpoint_ids, witness, 1_700_000_000, kp).unwrap();
    // Promote the witness state to Witnessed for this fixture.
    batch.body.witness_state = chio_anchor::WitnessState::Witnessed {
        receipt_id: "rekor-receipt-001".to_string(),
        observed_at: 1_700_000_000,
    };
    batch
}

#[test]
fn sync_wrapper_rejects_require_public_witness_true() {
    let kp = Keypair::generate();
    let batch = build_witnessed_batch(&kp);

    let policy = WitnessPolicy {
        require_public_witness: true,
        stale_window_seconds: 600,
    };

    let now = 1_700_000_010_i64;
    let result = verify_anchor_batch_with_witness_policy(&batch, &policy, now);
    let err = result.expect_err("sync wrapper MUST reject require_public_witness=true");
    match err {
        AnchorError::SyncRouteRequiresAdvisoryPolicy => {}
        other => panic!("expected SyncRouteRequiresAdvisoryPolicy, got: {other:?}"),
    }
}

#[test]
fn sync_wrapper_accepts_advisory_policy() {
    let kp = Keypair::generate();
    let batch = build_witnessed_batch(&kp);

    let policy = WitnessPolicy {
        require_public_witness: false,  // advisory mode; sync route is fine.
        stale_window_seconds: 600,
    };

    let now = 1_700_000_010_i64;
    let result = verify_anchor_batch_with_witness_policy(&batch, &policy, now);
    result.expect("advisory-mode sync route should still work");
}
```

The first test case exercises the rejection. The second exercises that advisory mode (the supported sync use case) is preserved.

**Reverse-test (Evidence Gate close bar)**: revert B3.2 on a draft branch (remove the early-return). Run `cargo test -p chio-conformance --test anchor_batch_sync_path_rejected_under_public_witness`; the first sub-test FAILS because the sync function now reaches the structural verify and returns either Ok or a different error. Record this in the B3.5 PR description.

## Why this design satisfies the Evidence Gate

- **Enforced call site**: `crates/chio-anchor/src/batch.rs:227-235` early-returns the typed error per B3.2.
- **Spec MUST citation**: PROTOCOL.md §6.4.1 normative paragraph added per B3.4.
- **Signed negative conformance test**: the fixture exercises the real sync-wrapper function (not a mock; not a near-copy) and FAILS when the gate is removed.

The lint script (`scripts/check-anchor-batch-async-witness.sh`) is best-effort fast-feedback documentation, NOT a soundness guarantee. False-negatives are tolerated because the runtime gate at `batch.rs:227-235` is the load-bearing defense; the lint exists to give developers fast feedback on the obvious cases (literal `WitnessPolicy { require_public_witness: true, ... }` near a sync wrapper call in the same file). Cross-file or builder-pattern policy construction is acknowledged out of scope for the lint; the runtime gate fires regardless.

## Out of scope for B3

- Restricting `verify_anchor_batch` (the bare sync function at `crates/chio-anchor/src/batch.rs:208-215`) is NOT in B3 because that function does not take a policy. The lint script's contract is "sync wrapper + nearby `require_public_witness=true`"; calls to `verify_anchor_batch` directly are out of the lint's scope. The spec rule applies via the wrapper because that is where the policy is materialized.
- Caching layer changes (the `previously_verified_witnesses: &VerifiedWitnessCache` parameter on the async function at `crates/chio-anchor/src/batch.rs:256`) are unaffected by B3.
- The five rejection criteria in the W2.3 negative-conformance suite at PROTOCOL.md lines 994-1018 (forged root, mis-ordered audit path, etc.) are already covered by `crates/chio-conformance/tests/anchor_batch_*_rejected.rs` - those fixtures stay green.
