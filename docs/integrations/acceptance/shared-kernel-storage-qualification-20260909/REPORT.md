# Shared actual kernel storage qualification

Three storage cutpoints passed against the real kernel and immutable Docker resource. This is shared owner qualification, not real-host acceptance. Each host must execute its own cutpoint and retain its own evidence.

## Identities

- Kernel source: `d8c5f53705173e614a853bad6c0a85acfdf1212b`.
- Immutable binary: `/tmp/chio-tool-error-ack-candidate-20260909/chio-33dd1dea21a4`.
- Binary SHA256: `33dd1dea21a4ca5ecddeab4f30f6b06b0b90c513f0987aef552b0633d9da1e25`.
- Resource image: `sha256:188cb84d5d0bb4063d4ce5a3b9c3832445a5acda5604911cda80a9136d1850a0`.
- Exact owner commands, selected policy, scoped public session bindings, helper hashes and independent observations are retained per case. Private credentials and database files remain only in the separate operator owners.

## Executed cases

| Case | Actual failure | Observed effects | Retained state after retries and restart |
|---|---|---|---|
| operator-before-r2 | Admission SQLite write lock before request | 0 | No admission operation/outcome; signed delegated call and latch fenced |
| operator-after-admission-r1 | Admission/outcome SQLite write lock after actual resource reply | 1 | dispatch_committed initially, then outcome_unknown_after_dispatch on restart; signed delegated fence |
| operator-after-receipt-r1 | Receipt SQLite append timeout after actual resource reply | 1 | Admission operation, terminal projection and outcome completed; ordinary receipt unavailable to caller; signed delegated fence |

All three locks used a separate real SQLite connection with `BEGIN IMMEDIATE` and ended with `ROLLBACK`. No row, schema, database clock, or kernel code was changed. Before-effect failure was injected only after successful session preparation. For both post-effect cases, the genuine resource reply was held using the existing stdio barrier. The independent read-only observer and append-before-dispatch resource audit established the effect before the SQLite transaction was acquired. Only then was the genuine reply released to the kernel.

The before-admission response was a signed kernel denial with reason `durable admission failed: admission operation store is unavailable: database is locked`; the execution client conservatively reported unknown/verified. Independent observation established zero effects.

The after-admission response carried the same text as an MCP error without receipt evidence, and the client reported unknown/unverified. The effect occurred once, while durable admission could not store its result. Startup reconciled dispatch_committed to outcome_unknown_after_dispatch.

The after-receipt response was `receipt persistence failed: sqlite receipt commit append timed out after 5000ms`. The client reported unknown/unverified and received no delivery acknowledgement. This is an unresolved caller outcome even though the durable admission owner already retained the completed operation and outcome. It must not be relabeled an externally prevented action.

For all three, fresh execution client instances retried the same request and attempted a new request after fault removal and/or kernel restart. The same request returned the retained unresolved error; the new request was refused by the pending/uncertain-call fence. Final independent audit counts remained 0/1/1, with no additional target files. Both persisted delegated call and latch signatures verified against each owner's pinned kernel public key; their state was fenced and they contained no delivery acknowledgement.

## Positive control and retained failed preparation

`operator-before-r1` first completed a useful write and verified its receipt. The qualification driver then incorrectly passed only the delivery object to `acknowledge`, whose contract expects the complete verified outcome. Its acknowledgement was refused. Consequently this first attempted before-admission test hit the existing unacknowledged-call fence before admission. It is **not counted** as a storage failure test. The raw attempt is retained, and the clean new owner `operator-before-r2` supplies the counted pre-admission case.

The corrected driver replayed the original positive request, received the same retained completed result, durably wrote that result, and acknowledged the full outcome successfully. Independent audit still had exactly one write. The initial driver and corrected driver are both retained. A first snapshot attempt on the rejected owner failed locally while JSON encoding SQLite BLOB values; the helper now encodes those values as explicit hexadecimal bytes. The incomplete local snapshot remains in `/tmp`, outside this valid JSON evidence bundle.

## Signing boundary and limits

See `integrations/required-agents/qualification/STORAGE-FAULTS.md` for exact source references. Ordinary hosted MCP receipt signing uses an in-memory software Ed25519 primitive with no recoverable crypto error branch. It does not select an external signer or the optional signing queue. No actual primitive-signing outage is claimed. Receipt construction, canonicalization, semantic binding and persistence are separate fallible operations; these cases directly exercised actual admission and receipt persistence failures.

No normal agent profile was touched. Every owner used a newly created state directory, database set, ports 58506-58509 and separate named Docker volumes. Owners and evidence volumes are preserved for reconciliation. Locks are released. The test-only stdio barrier is absent from ordinary supported delivery configuration.
