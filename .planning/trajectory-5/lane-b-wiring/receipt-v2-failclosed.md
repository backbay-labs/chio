# B2: Receipt v2 Fail-closed Under Negotiated v2

This document is the deep dive for sub-lane B2. It captures the exact downgrade code, the negotiation signal that should trigger fail-closed, the new error type, and the conformance fixture that exercises "negotiated v2 + producer emits v1 -> reject".

## The exact downgrade code

`crates/chio-kernel/src/kernel/mod.rs:1574-1591` (function `kernel_receipt_version_for_remote`):

```rust
pub fn kernel_receipt_version_for_remote(
    &self,
    remote_kernel_id: Option<&str>,
    now: u64,
) -> KernelReceiptVersion {
    if let Some(remote) = remote_kernel_id {
        if let Some(peer) = self.federation_peer(remote, now) {
            return KernelReceiptVersion::from_capabilities(&peer.capabilities);
        }
        // Named peer that isn't pinned fresh: fall back to v1 with
        // a warning log so operators see the negotiation downgrade.
        tracing::warn!(
            target: "chio_kernel.receipt_v2",
            remote_kernel_id = remote,
            "v2 receipt minting falling back to v1 because federation peer is not pinned fresh"
        );
        return KernelReceiptVersion::V1Legacy;
    }
    if self.receipt_v2_default() {
        KernelReceiptVersion::V2BodyHash
    } else {
        KernelReceiptVersion::V1Legacy
    }
}
```

The synthesis (line 31) cited the line range `mod.rs:1148-1165` as the downgrade location. That line range is actually the `KernelReceiptVersion::from_capabilities` resolver helper (peer-profile -> version mapping), which is correct on the spec side. The actual runtime downgrade-to-v1 lives at lines 1574-1591 in the function above. B2 targets that function.

**Spec-language framing (R3 BLOCKER #1 fix)**: PROTOCOL.md lines 737-741 today contain neither `MUST` nor `SHOULD`. The prose is descriptive ("the kernel falls back to minting only the v1 UUIDv7 receipt"). B2 is therefore introducing a **NEW normative MUST**, not promoting an existing SHOULD. The Evidence Gate close bar (`templates/EVIDENCE-GATE.md` §1.2) requires the cited lines contain `MUST` after the spec edit lands; the audit-doc evidence section MUST mark the change as **tightening** (introducing a new MUST) rather than **promotion** (SHOULD->MUST), so a reviewer does not misread it. The `scripts/check-release work-evidence-gate.sh` script reads from merged-branch HEAD of `spec/PROTOCOL.md`, so the same-PR spec edit (B2.4) will satisfy the gate.

The decision flow today:

1. Request names a remote, peer pinned fresh -> use `KernelReceiptVersion::from_capabilities(&peer.capabilities)` (correct).
2. Request names a remote, peer NOT pinned fresh -> log a warning, return `V1Legacy` (THE DEFECT).
3. No remote named -> use kernel-level default.

Case 2 silently downgrades a request that the operator wanted v2 for. The peer was once pinned fresh and at that time advertised `ACCEPTS_RECEIPT_V2`; the dispatch arrived after pin freshness expired. The kernel's choice today is to pretend the peer never existed and emit v1. That is the "structural framing without runtime wiring" pattern: the spec line 738 says "falls back" so the runtime falls back.

## The negotiation signal that should trigger fail-closed

The kernel must distinguish three cases:

- **Case A (advisory)**: caller did not name a remote AND the kernel-level `receipt_v2_default()` is false. Mint v1 normally. This is a kernel that is intentionally v1-only.
- **Case B (v2-default)**: caller did not name a remote AND kernel-level `receipt_v2_default()` is true. Mint v2 normally.
- **Case C (federation v2-capable, fresh)**: caller named a remote AND the peer is pinned fresh AND `peer.capabilities.supports(ACCEPTS_RECEIPT_V2)`. Mint v2.
- **Case D (federation v1-only, fresh)**: caller named a remote AND the peer is pinned fresh AND the peer does NOT advertise v2. Mint v1.
- **Case E (federation, stale)**: caller named a remote AND the peer is NOT pinned fresh. THIS IS THE DEFECT CASE.

Case E becomes "fail closed when the kernel-level default is v2-capable, OR when there is documented evidence (a stored peer capability snapshot) that this peer is v2-capable; otherwise, mint v1." The simplest, fail-safe behavior is: **always fail closed in Case E** (covers both "stale" and "never-pinned" scenarios; the spec edit B2.4 makes this explicit so a future implementation cannot misread "not pinned fresh" as "stale only"). The operator gets a structured `KernelError::ReceiptNegotiationDowngrade { expected: V2BodyHash, actual: V1Legacy, reason: PeerNotPinnedFresh { remote_kernel_id } }` and either re-pins the peer or routes the request without a remote.

## The new error type

```rust
#[derive(Debug, Clone, thiserror::Error)]
pub enum NegotiationDowngradeReason {
    #[error("named federation peer {remote_kernel_id} is not pinned fresh")]
    PeerNotPinnedFresh { remote_kernel_id: String },
    // Reserved for future shapes; currently only the one variant.
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum KernelError {
    // ... existing variants ...
    #[error("receipt negotiation downgrade rejected: expected {expected:?}, actual {actual:?}, reason: {reason}")]
    ReceiptNegotiationDowngrade {
        expected: KernelReceiptVersion,
        actual: KernelReceiptVersion,
        reason: NegotiationDowngradeReason,
    },
}
```

The exact placement (which file `KernelError` lives in) is determined at PR time; current candidate is the existing kernel error module.

## The new function signature

After B2.2:

```rust
pub fn kernel_receipt_version_for_remote(
    &self,
    remote_kernel_id: Option<&str>,
    now: u64,
) -> Result<KernelReceiptVersion, KernelError> {
    if let Some(remote) = remote_kernel_id {
        if let Some(peer) = self.federation_peer(remote, now) {
            return Ok(KernelReceiptVersion::from_capabilities(&peer.capabilities));
        }
        // Spec PROTOCOL.md §6 line 737-741 (post-B2.4): when the peer
        // profile is v2-capable but not pinned fresh, fail closed.
        return Err(KernelError::ReceiptNegotiationDowngrade {
            expected: KernelReceiptVersion::V2BodyHash,
            actual: KernelReceiptVersion::V1Legacy,
            reason: NegotiationDowngradeReason::PeerNotPinnedFresh {
                remote_kernel_id: remote.to_string(),
            },
        });
    }
    if self.receipt_v2_default() {
        Ok(KernelReceiptVersion::V2BodyHash)
    } else {
        Ok(KernelReceiptVersion::V1Legacy)
    }
}
```

The caller `record_chio_receipt_with_federation` at `crates/chio-kernel/src/kernel/responses.rs:1405-1427` propagates the error.

## The conformance fixture

Path: `crates/chio-conformance/tests/receipt_v2_required_under_v2_negotiation.rs`.

The fixture must NOT just test the schema. It must EXERCISE the production mint path (`evaluate_tool_call_blocking` -> `record_chio_receipt_with_federation` -> `kernel_receipt_version_for_remote`) and FAIL when B2.2 is reverted to warn-and-downgrade.

**Fixture structure (three sub-tests in one file)**:

```rust
// Sub-test 1: v2-capable peer pinned fresh -> v2 receipt minted.
#[test]
fn v2_capable_peer_pinned_fresh_mints_v2() {
    let kernel = make_kernel(&temp_db_path());
    register_v2_capable_peer(&kernel, "peer-A", /* fresh_at = now */);
    let request = build_tool_call_request("peer-A");
    let verdict = kernel.evaluate_tool_call_blocking(request).unwrap();
    assert_eq!(verdict.decision, Verdict::Allow);
    let v2 = read_v2_receipt(&kernel).unwrap();
    assert!(v2.body_hash.starts_with("sha256:"));
}

// Sub-test 2: peer named but pin freshness expired -> dispatch fails fail-closed.
#[test]
fn v2_negotiation_with_stale_pin_rejects() {
    let kernel = make_kernel(&temp_db_path());
    register_v2_capable_peer(&kernel, "peer-A", /* fresh_at = now - 600 */);
    advance_kernel_clock(&kernel, /* now + 1200 */);  // Stale: pin window blown.
    let request = build_tool_call_request("peer-A");
    let err = kernel.evaluate_tool_call_blocking(request).unwrap_err();
    match err {
        KernelError::ReceiptNegotiationDowngrade { expected, actual, reason } => {
            assert_eq!(expected, KernelReceiptVersion::V2BodyHash);
            assert_eq!(actual, KernelReceiptVersion::V1Legacy);
            assert!(matches!(reason, NegotiationDowngradeReason::PeerNotPinnedFresh { .. }));
        }
        other => panic!("expected ReceiptNegotiationDowngrade, got {other:?}"),
    }
    // Critical: NO v1 receipt was minted as a "fallback".
    assert_eq!(count_v1_receipts(&kernel), 0);
    assert_eq!(count_v2_receipts(&kernel), 0);
}

// Sub-test 3: no peer named, kernel default v1 -> v1 minted normally (advisory mode preserved).
#[test]
fn no_peer_named_kernel_default_v1_mints_v1_only() {
    let kernel = make_kernel(&temp_db_path());
    kernel.set_receipt_v2_default(false);
    let request = build_tool_call_request_no_remote();
    let verdict = kernel.evaluate_tool_call_blocking(request).unwrap();
    assert_eq!(verdict.decision, Verdict::Allow);
    assert_eq!(count_v1_receipts(&kernel), 1);
    assert_eq!(count_v2_receipts(&kernel), 0);
}
```

Helpers (`register_v2_capable_peer`, `advance_kernel_clock`, `count_v1_receipts`, `count_v2_receipts`) are added to `crates/chio-conformance/tests/common/` (the existing helper module). **Per R3 finding #1 reservation (B2)**, `count_v1_receipts` and `count_v2_receipts` MUST read from the real `chio_receipts` and `chio_receipts_v2` tables of the `SqliteReceiptStore` directly (not via a kernel-side `test_only_*` accessor). The fixture already opens a real `SqliteReceiptStore` at `make_kernel`; the helpers query it via `rusqlite::Connection::open(receipt_store_path)`. This avoids the `EVIDENCE-GATE.md` §8.3 anti-pattern of "side-effecting setup that bypasses the gate". Implementation pulls from the same `make_kernel` shape as `crates/chio-conformance/tests/v2_receipt_kernel_round_trip.rs:92-115`.

**Reverse-test (Evidence Gate close bar)**: revert B2.2 on a draft branch (restore the `tracing::warn!` + `return V1Legacy` block at `mod.rs:1574-1591`). Run the fixture; sub-test 2 FAILS because the dispatch now returns Allow with a v1 receipt instead of the structured error. Record this in the B2.5 PR description.

## Why this design satisfies the Evidence Gate

- **Enforced call site**: `crates/chio-kernel/src/kernel/mod.rs:1574-1591` returns the typed error in case E; `crates/chio-kernel/src/kernel/responses.rs:1405-1427` propagates it.
- **Spec MUST citation**: PROTOCOL.md lines 737-741 today contain descriptive prose with neither MUST nor SHOULD. B2.4 rewrites the prose to introduce a NEW normative MUST: "When the peer profile is v2-capable but no federation peer is pinned fresh for the request (whether stale or never-pinned), the kernel MUST reject the dispatch with `KernelError::ReceiptNegotiationDowngrade`." This is a **tightening** (fresh introduction of a normative rule), NOT a SHOULD->MUST promotion. The fail-closed rule explicitly enumerates BOTH the "stale" and "never-pinned" cases so a future implementation cannot read "not pinned fresh" as "stale only" and re-introduce a bypass for the never-pinned path.
- **Signed negative conformance test**: the fixture exercises `evaluate_tool_call_blocking` (the public mint API; the same path `crates/chio-conformance/tests/v2_receipt_kernel_round_trip.rs:107-115` uses) and fails when the warn-and-downgrade is restored.
