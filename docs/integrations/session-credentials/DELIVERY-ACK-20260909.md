# Retained outcome delivery acknowledgement

The original session credential candidate fenced pending and uncertain kernel
calls. It released that fence when the kernel stored a verified completion,
before the HTTP response reached its caller. A proxy could therefore discard
the complete response while the caller still believed the outcome unknown.
Erasing the guest journal and changing the request ID then escaped the caller's
local uncertainty fence. The new owner state is `completed_unacknowledged`.

New request IDs remain blocked until the caller explicitly acknowledges the
original verified result. The owner returns an unpredictable challenge bound to
the exact request hash, receipt ID and result hash in `_meta.chioDelivery`.
`chio/acknowledge` accepts that binding only for the credential's retained
session. The caller must durably save and verify the original result before
acknowledging. Exact request replay returns the stored response without invoking
the resource. A stale acknowledgement cannot clear a later pending operation.
Credential rotation, kernel restart and guest journal removal preserve the
owner fence. Legacy completed records without a delivery proof fail closed;
they are not silently migrated to acknowledged status.

The candidate was built from source
`8501b0058dfcbccd858ae2cdeda82948fb1e9a08`; equivalent root code is `31c28d05c3`.
Binary SHA256:
`0e683f6f7cc8f21816b10641e3c18fba2dd1445fbcd28752cd3260d8ac5edb5a`.
Audited filesystem image:
`sha256:188cb84d5d0bb4063d4ce5a3b9c3832445a5acda5604911cda80a9136d1850a0`.

All **34 real kernel/resource cases passed**, with zero skips. The lost-response
case consumed the complete upstream response, closed the downstream socket,
removed only the disposable guest journal, and attempted new request IDs.
Independent resource observations showed one original write and no subsequent
write before recovery. Rotation and restart preserved this barrier. Exact replay,
trusted receipt/result verification and acknowledgement restored useful work.
Five substituted acknowledgement fields were refused. The prior authority,
budget, expiry, revocation, hidden-tool and missing-session cases also ran.

Remote library tests passed 54/54. Final clippy and CLI build passed; the initial
needless-borrow lint error and aggregate import-format failure are retained.
Formatting was corrected before the immutable final build. Raw observations,
the exact runner and hashes are in
[evidence/20260909-ack-run1](evidence/20260909-ack-run1/SHA256SUMS).

This is shared kernel qualification. Host packages must implement durable save
before acknowledgement and pass their own I01-I08 cases on the matching build.
The candidate is not published or accepted as a six-host delivery. Confidence
is high for the recorded tests; complete host acceptance remains unresolved.
