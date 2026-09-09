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


## Terminal tool errors

A subsequent clean-installed Codex run supplied an out-of-root resource path.
The filesystem server returned a known tool error, signed as a completed
admission with the exact result hash. The previous owner implementation
withheld delivery acknowledgement solely because the MCP result had
`isError: true`, causing the bridge to retain an unknown-outcome fence.

Source `d8c5f53705173e614a853bad6c0a85acfdf1212b` removes that incorrect
classification. A signed terminal tool result may be acknowledged while
retaining its error flag. It is never promoted to successful work. Pending,
unverified, malformed or unsigned results remain fenced. Exact replay retains
the original error without dispatching again.

Binary SHA256 `33dd1dea21a4ca5ecddeab4f30f6b06b0b90c513f0987aef552b0633d9da1e25`
passed **38 actual kernel/resource cases**, zero skips. The four new cases
observed the known error, refusal of a new call before acknowledgement, exact
error replay, and useful work after durable verification and acknowledgement.
The regression test failed before the fix; all 55 remote library tests and
clippy passed afterward. Exact build/source identity, raw tests, runner and
independent dispatch log are in [20260909-tool-error-ack](evidence/20260909-tool-error-ack/SHA256SUMS).
Host-specific qualification against this artifact remains required.
