# M10 Single-Operator Pilot Report

## Verdict

The M10 product exit passed on candidate
`ef6caa70d656d311399e509f74460e1981db19a3`. The qualifier built the `chio`
binary from that clean candidate before starting the workload. The pilot used
one deployable local operator and distinct scoped seller and buyer credentials.
It did not give either agent the global service token.

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
- Admission time: 1,952 ms minimum, 2,009 ms median, 2,081 ms maximum
- Recorded normal purchase time: 2,660 ms minimum, 2,812 ms median,
  2,960 ms maximum

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
It separately reconstructed the actual payer-bound purchase request and first
verified its authentic terminal successfully. After corrupting the signed
purchase record, the Rust buyer boundary rejected that same terminal. Python
separately exercises altered-proof and terminal verification boundaries in its
SDK test suite.

## Release hardening

The requalified candidate also closes the final deployment review findings:

- Seller test commands receive a self-contained Git clone copied into a private
  size-capped tmpfs plus required read-only toolchains, never the operator
  profile, state tree, Cargo registry, or Git dependency cache. Offline
  dependencies must be vendored in the repository. Tests have no network, a
  cleared environment, bounded output, PID and user namespaces, and one
  five-minute aggregate deadline shared by source Git reads, staging, baseline
  and candidate tests, and patch generation. Cgroup v2 enforces hard aggregate
  memory, swap, and process limits across each test descendant tree;
  process-local CPU, memory, process, descriptor, and file-size rlimits remain
  defense in depth, and the writable volume is size-capped. Unix-only cgroup
  file-descriptor wiring is target-gated so the CLI remains buildable on
  Windows.
- Source repositories are copied without hard links into operator-owned state.
  Operator initialization requires an explicit approved repository root, and
  seller ingress rejects canonical paths and symbolic links that escape it.
  Source Git reads and the initial clone run in a filesystem namespace exposing
  only that approved root. A full non-local transfer prevents worktree,
  common-directory, config-include, or alternate-object metadata from retaining
  access to operator-readable paths outside it.
  Git hooks, system and global configuration, credentials, and external
  protocol helpers are disabled before checkout. Clone and checkout staging is
  bounded by a five-minute deadline, a 1 GiB aggregate ceiling, 75,000
  entries, and a per-file limit. Patch generation has its own five-minute
  deadline and output ceiling. Published repository identity removes URL
  credentials, query strings, and fragments. Failed staging removes its
  partial clone, and completed package files publish atomically. Seller
  submission and retraction retention is capped at 256 jobs combined. Reports,
  packages, the complete operator SQLite allocation, and outstanding
  worst-case payload, bundle, and proof claims share one 8 GiB ceiling. The
  full transient staging budget plus publication and database headroom is
  durably reserved before a new job is accepted, then consumed only after all
  three artifacts exist under the admitted Finding identity. The file tree is
  also capped at 100,000 entries. Revision and published repository-identity
  lookups use the same timed, output-bounded process-group runner as patch
  generation.
- Live seller admission and scheduled `operator tick` reconciliation share one
  cross-process operator lock. Submission and retraction also share one
  non-queued blocking lane, so overlapping work receives a retryable HTTP 503
  before it can consume unbounded blocking-pool capacity. Tick reports each
  terminal-safe failed admission and continues reconciling later jobs.
- Bundle, encrypted payload, and proof bytes are durable before activation.
  Retraction intent bytes are durable before submission, and pre-dispatch
  purchase failures release both reservation exposure and any reserved slot.
  A prepared job without a reservation revalidates current market policy and
  rejects an expired signed ask before reserving funds, while a completed paid
  replay verifies proof liveness at its authenticated terminal time. An open
  or slot-reserved purchase that expires across restart moves to a durable
  expired state and returns a stable rejection instead of an endless pending
  response. A crash after terminal-capacity reservation but before the market
  reservation releases that claim when the prepared ask expires. A successful
  pre-dispatch cleanup records a stable rejection, so its released reservation
  cannot become an endless pending retry. Expired slot-reserved work first
  selects the exact payment through its governed intent binding, releases a
  hold or refunds a capture exactly once, and only then closes the reservation.
  Legacy held payments gain that binding either on exact authorization replay
  or through the durable payment journal's request and operation identity. A
  crash between payment reversal and expiry safely replays the same terminal
  payment action.
  Purchase-job retention is capped at 10,000 rows, failing new requests closed
  while preserving exact replay at capacity. Retained public terminal bodies
  have a transactionally enforced 256 MiB aggregate ceiling. Each request
  durably reserves its maximum terminal footprint before the market reservation
  can open or payment can run, and terminal insertion consumes that claim in
  the same transaction. Capacity exhaustion therefore returns a retryable
  response with no reservation and no charge.
- Status-floor lock guards explicitly unlock before close, so an immediate
  sequential retry can read a retraction retained by a rejected rollback.
- Seller client credentials contain no market signing seed. Buyer SDKs require
  a search predicate, bind purchase identities to the credential's payer key,
  use bounded response streams and an absolute wall-clock deadline covering
  the complete HTTP response rather than only periods of network inactivity,
  and verify the signed purchase record and reveal commitment before returning
  either a generic purchase result or a decoded patch. The public
  operator route rejects omitted or mismatched payer identities before purchase
  execution.
  Seller SDKs treat repositories as operator-side absolute coordinates and do
  not require those paths to exist on the buyer or seller client host.
- Purchase execution uses one non-queued blocking lane rather than a Tokio
  worker. Public proof reads and egress use a separate one-response lane with
  64 KiB chunks and a 30-second absolute deadline, so slow or concurrent public
  requests cannot accumulate unbounded proof work or retained bundles.
- Python and TypeScript status calls use the Rust verifier with the profile's
  pinned status authority, service bond, freshness window, and durable rollback
  floor. Challenge helpers authenticate the purchase terminal again before
  deriving evidence. Challenge policy lookup streams one retained bundle at a
  time and stops at the first digest match instead of materializing the store.
- Seller request validation and the HTTP body cap cover the same complete
  canonical request surface. Seller prices cannot exceed the operator's 450-unit
  backed sale exposure, and operator profiles reject an ephemeral listen port.
  The qualifier refuses a dirty worktree, builds `target/debug/chio` itself,
  and rejects alternate binary paths before it records the exact candidate
  SHA.

## Reproduction

Run from a clean candidate:

```bash
./scripts/qualify-cognition-market-pilot.py
```

The full per-run report is written to
`target/cognition-market-pilot/report.json`. The committed privacy-safe
aggregate is [M10-PILOT-REPORT.json](./M10-PILOT-REPORT.json).
