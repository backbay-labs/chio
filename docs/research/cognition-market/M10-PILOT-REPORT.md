# M10 Single-Operator Pilot Report

## Verdict

The M10 product exit passed on candidate
`f279cb866be54380f68f018c60d4d5322ba5accd`. The pilot used the installed
`chio` binary, one deployable local operator, and distinct scoped seller and
buyer credentials. It did not give either agent the global service token.

This is a local single-operator result. It is not evidence for cross-operator
fair exchange, stochastic research markets, auctions, or public hosted demand.

## Workload and outcomes

The seller admitted ten distinct verified fixes over ten failing-to-passing Git
revision pairs. The corpus covered bounds, stable ordering, remainder handling,
boolean parsing, median calculation, retry caps, zero denominators,
case-insensitive headers, secret redaction, and retry classification.

- Findings admitted: 10
- Purchases captured: 5
- Durable purchase jobs: 5
- Durable terminals: 5
- Duplicate captures: 0
- Pilot failures: 0
- Client coverage: four Python purchases and one TypeScript purchase
- Admission time: 1,968 ms minimum, 2,012 ms median, 2,500 ms maximum
- Recorded normal purchase time: 2,664 ms minimum, 2,877 ms median,
  2,933 ms maximum

Every buyer retrieved a public proof, passed it through the Rust reference
verifier, purchased the Finding, verified the signed purchase terminal and
payload commitment, decoded the verified-fix payload, and wrote the patch
without applying it to a source workspace.

## Restart and replay

The qualifier observed a durable purchase job before its terminal, stopped the
operator process at that active boundary, killed it, and restarted from the
same profile and databases. Retrying the exact buyer request recovered one
captured terminal. A second exact replay returned the same result and terminal
digest set. The measured delta was one job, one terminal, and one capture.

After all five purchases, another exact replay left both the five terminal
digests and the capture count unchanged.

The qualifier also repeated `operator init` with the exact deployment request.
The private operator profile, scoped client credentials, public client profile,
and completion marker remained byte-for-byte identical.

## Challenge, retraction, and tamper controls

The buyer filed one controlled evidence-invalid challenge against a purchased
Finding. The scoped seller then issued a voluntary retraction. An immediate
status read returned an inclusion proof for the retracted Finding, including
across the status-clock edge that previously caused a one-second rollback
failure.

The qualifier then removed the locally persisted retraction result to simulate
a crash after status publication. The retry reused the exact persisted intent
bytes and returned the same retraction terminal.

The qualifier also altered signed Finding material in a retrieved proof bundle.
Both the Rust reference verifier and the TypeScript SDK boundary rejected it.
It separately corrupted the signed purchase record and the Rust buyer boundary
rejected that terminal. Python separately exercises altered-proof and terminal
verification boundaries in its SDK test suite.

## Release hardening

The requalified candidate also closes the final deployment review findings:

- Seller test commands receive a self-contained Git clone copied into a private
  size-capped tmpfs plus required read-only runtimes, never the operator profile
  or state tree. They have no network, a cleared environment, bounded output,
  PID and user namespaces, a five-minute deadline, and hard memory, CPU,
  process, descriptor, file-size, and writable-volume limits.
- Source repositories are copied without hard links into operator-owned state.
  Operator initialization requires an explicit approved repository root, and
  seller ingress rejects canonical paths and symbolic links that escape it.
  Git hooks, system and global configuration, credentials, and external
  protocol helpers are disabled before checkout. Clone and checkout staging is
  bounded by a five-minute deadline, an 8 GiB aggregate ceiling, one million
  entries, and a per-file limit. Patch generation has its own five-minute
  deadline and output ceiling. Published repository identity removes URL
  credentials, query strings, and fragments. Failed staging removes its
  partial clone, and completed package files publish atomically.
- Bundle, encrypted payload, and proof bytes are durable before activation.
  Retraction intent bytes are durable before submission, and pre-dispatch
  purchase failures release both reservation exposure and any reserved slot.
  A prepared job without a reservation revalidates current market policy, while
  a completed paid replay verifies proof liveness at its authenticated terminal
  time. Purchase-job retention is capped at 10,000 rows, failing new requests
  closed while preserving exact replay at capacity.
- Seller client credentials contain no market signing seed. Buyer SDKs require
  a search predicate, bind purchase identities to the credential's payer key,
  use bounded request deadlines and response streams, and verify the signed
  purchase record and reveal commitment before returning a patch. The public
  operator route rejects omitted or mismatched payer identities before purchase
  execution.
  Seller SDKs treat repositories as operator-side absolute coordinates and do
  not require those paths to exist on the buyer or seller client host.
- Python and TypeScript status calls use the Rust verifier with the profile's
  pinned status authority, service bond, freshness window, and durable rollback
  floor. Challenge helpers authenticate the purchase terminal again before
  deriving evidence.
- Seller request validation and the HTTP body cap cover the same complete
  canonical request surface. Seller prices cannot exceed the operator's 450-unit
  backed sale exposure, and operator profiles reject an ephemeral listen port.
  The qualifier refuses a dirty worktree before it records the exact candidate
  SHA.

## Reproduction

Run from a built candidate:

```bash
cargo build -p chio-cli
./scripts/qualify-cognition-market-pilot.py
```

The full per-run report is written to
`target/cognition-market-pilot/report.json`. The committed privacy-safe
aggregate is [M10-PILOT-REPORT.json](./M10-PILOT-REPORT.json).
