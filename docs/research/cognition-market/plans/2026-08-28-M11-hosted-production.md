# M11 Hosted Production Execution

Status: dark hosted implementation. Public multi-tenant activation is not part
of this branch. Promotion is blocked until the code, PostgreSQL, KVM, and
authenticated network qualifications pass on the exact deployed release
commit and the signed canary decision is `promote`.

## Objective

Move the qualified single-operator cognition market from a local pilot to a
tenant-isolated hosted service without weakening its signed-artifact,
settlement, challenge, status, or replay guarantees.

## Production boundary

M11 admits one canonical `chio.finding.hosted-operator-profile.v1` before any listener,
database, payment rail, signer, or worker starts. The profile requires:

- a public HTTPS endpoint and exactly one edge mode: native TLS 1.3 with
  last-known-good certificate reload, or an authenticated loopback trusted
  proxy with a closed `Forwarded` contract;
- pinned Chio capability authorities, exact deployment, tenant, role, action,
  target, and body bindings, plus durable bounded DPoP replay state;
- action-scoped 256-bit API keys whose HMAC verifiers are protected by an
  environment-referenced deployment pepper, with signed issue and revocation
  receipts;
- distinct non-superuser PostgreSQL runtime and worker roles, each bound to a
  separate secret reference, with forced row-level security;
- distinct remote-custody keys for all 19 market, kernel, and worker roles;
- complete ACP authorize, capture, release, refund, and state paths;
- a strict HTTPS live bond-observation endpoint with separate dispatch and
  reconciliation reads;
- a strict HTTPS impairment-publisher endpoint whose bearer credential is
  resolved from an environment reference and whose egress namespace is derived
  from the deployment identity;
- digest-pinned Firecracker and jailer binaries and guest images;
- a unique non-root UID/GID pair for every concurrent microVM;
- explicit tenant authentication methods, principal roles, queue,
  concurrency, and spend ceilings;
- canary thresholds and an explicit rollback window.

Authentication never falls through from one failed credential type to another.
The profile contains environment-variable names, never secret values or local
signing seeds. `chio finding operator validate-hosted --profile <path>` opens
the profile and referenced files without following symlinks, verifies modes
and image digests, resolves bounded secret references, validates native TLS or
trusted-proxy material, preflights every remote key pin, and constructs the
authentication and worker configurations.

The shipped server executable accepts only the trusted-proxy edge mode and a
loopback listener. The proxy peer, one exact `Forwarded` header, and a private
proxy token are mandatory before routing. Native TLS remains a validated
profile capability for other hosted consumers, but this deployment does not
silently switch between edge modes.

## Durable execution

The hosted store sets `chio.tenant_id` transaction-locally for every scoped
operation and relies on forced PostgreSQL row-level security as a second
boundary. The RLS-protected tenant registry binds concurrency, queue, and
monthly spend ceilings to the exact deployed configuration revision. Worker
startup refuses any profile-to-registry drift. Job admission is linearized by
a tenant advisory lock and counts only nonterminal queued work against the
tenant ceiling while preserving a separate total-retention ceiling. Claims use
`FOR UPDATE SKIP LOCKED`, enforce the durable tenant concurrency ceiling, carry
expiring worker leases, and reject stale workers at completion. Monthly spend
reservations are tenant-serialized and assigned to the UTC calendar month
derived from trusted admission time, so callers cannot select a weaker bucket.
They are exact-replay stable and terminally committed or released; committed
gross spend cannot be released. A bounded
retry budget ends in the terminal `exhausted` state, which is never claimable
again.

Every cognition-market aggregate family also has an append-only PostgreSQL
journal. Findings, listings, admissions, purchases and terminals, failed
deliveries, challenges and outcomes, liabilities, appeals, penalties,
enforcement, settlement, status epochs, and audit rounds share a closed kind
vocabulary. Each tenant-scoped event advances an optimistic revision fence,
binds its canonical payload and predecessor in a domain-separated digest, and
updates the head in the same transaction. Event identifiers replay only for
the exact immutable event. Reads verify canonical payloads, event digests, and
the complete predecessor chain before returning history.

Firecracker jobs use a unique jail and cgroup. The worker verifies source
images while copying them into the jail, configures a read-only root drive,
omits all network interfaces, retains Firecracker's default seccomp policy,
sets PID, memory, CPU, file-size, and file-descriptor limits, and exchanges
bounded canonical control frames and bounded content frames over virtio-vsock.
Repository and input bytes are loaded only from an opaque, tenant-derived
namespace in the root-owned local CAS after their declared sizes and SHA-256
digests are verified. Output bytes are streamed back into the same tenant
namespace with create-new temporary files, verified before an atomic
no-replace link, and synced before the signed result can complete.
Result identity and request digest bindings are rechecked before durable
completion. The VM, jail, and cgroup are removed before the result is accepted.

The installed `chio-finding-worker` daemon is the only production queue
consumer. It refuses relative or non-canonical profiles, verifies that the
running executable is the exact profile-pinned worker binary, preflights the
remote worker signer, every Firecracker asset, `/dev/kvm`, the non-superuser
PostgreSQL role, and each enabled tenant before claiming a lease. Claims are
bounded by both host capacity and each tenant's configured concurrency. A
SIGINT or SIGTERM stops new scans after the current bounded batch finishes.
The continuous daemon opens a fail-closed PostgreSQL circuit after three
consecutive failed scans, emits a closed unready report, and allows one
half-open trial after 30 seconds. A successful trial resets readiness. The
one-shot diagnostic remains fail-fast so automation cannot mistake a skipped
scan for a successful qualification.
Run one diagnostic pass with:

```bash
chio-finding-worker \
  --profile /etc/chio/finding-hosted.json \
  --worker-id worker:production-1 \
  --once
```

## Custody and settlement

Challenge outcomes, enforcement artifacts, penalties, purchase reservations,
purchase terminals, failed-delivery terminals, and status epochs accept a
`SigningBackend`. Local-key constructors remain compatibility helpers for
tests and non-hosted deployments. Hosted startup loads remote HTTP or Vault
Transit signers. The remote service must return the exact handle, key version,
algorithm, and public key at preflight, and every returned signature is
verified locally over the exact canonical bytes.

ACP transport rejects production cleartext, redirects, unbounded responses,
and response binding changes. Every financial terminal path has an explicit
remote operation and replay-stable identity. Enforcement dispatch uses the
profile-pinned impairment publisher. Its request binds the exact canonical
intent and prepared call, and its response binds the request digest. DNS is
pinned during construction, redirects and proxies are disabled, non-public
destinations are rejected, and reconciliation remains authoritative over any
publisher claim.

The live bond observer receives only the verified enforcement and snapshot
identity needed to re-read chain finality and operator qualification. Fresh
dispatch and reconciliation use separate operations. Responses bind the exact
canonical request digest, and malformed, stale, unavailable, or ambiguous
state never qualifies an impairment.

## Release decision

The canary observation is a canonical envelope signed by the profile-pinned
audit authority and binds the artifact digest and configuration revision. Its
v2 body carries exact start and end timestamps, and evaluation rejects an
untrusted signer, an invalid signature, inconsistent or future-dated times, or
a window more than five minutes old. It rolls back on a short observation
window, missing replicas, excessive error rate, latency, or queue age, or any
signature failure, payment ambiguity, tenant-isolation violation,
durable-integrity failure, or worker-isolation failure. Operators evaluate it
with:

```bash
chio finding operator evaluate-canary \
  --profile /etc/chio/finding-hosted.json \
  --observation /var/lib/chio/canary-observation.json
```

## Qualification

The ordinary hosted CI lane qualifies code, PostgreSQL 16.6, forced RLS,
remote custody, settlement transports, the worker boundary, RustSec and
duplicate-dependency policy, cargo-vet attestations, the hosted server, both
hosted SDKs, and deployment contracts without making a production readiness
claim. Code-only is the safe default; the explicit flag is retained for CI
readability:

```bash
scripts/qualify-cognition-market-hosted.sh --code-only
```

KVM boundary qualification uses an explicit mode on a dedicated root-owned KVM
runner. The runner must provision the canonical private hosted
profile, its secrets and assets, one isolated worker canary job, and a bounded
canary observation through `CHIO_FINDING_HOSTED_PROFILE`,
`CHIO_FINDING_CANARY_OBSERVATION`, and `CHIO_FINDING_WORKER_ID`. The profile
must pin the exact release-mode worker built from the checked-out candidate.
The gate requires that worker to claim and complete exactly one real
Firecracker job with no retry or rejection, then requires `evaluate-canary` to
return `promote` for that bounded worker canary only:

```bash
scripts/qualify-cognition-market-hosted.sh --kvm-boundary
```

Both modes emit per-gate logs, checksums, and a signed exact-candidate manifest
under `target/release-qualification/`. The KVM boundary workflow additionally
applies and verifies keyless Sigstore signatures over both the KVM sub-manifest
and the final hosted manifest that binds every gate plus the KVM manifest
digest. Neither mode claims network qualification, production readiness, or
promotion readiness. Those fields remain false. A separate manual workflow
runs the authenticated network canary against the dark deployment and emits
its own signed exact-candidate manifest:

```bash
scripts/qualify-cognition-market-network.sh
```

That canary proves only seller publication, later exact replay, exact buyer
resolution, bounded catalog discovery, and authenticated non-visibility from a
distinct enabled tenant using that tenant's own buyer credential. It does not
upgrade the hosted v2 report or make a
public-traffic claim. Full workspace build, test, Clippy, format, and release CI
remain mandatory before deployment.
Each qualification script immediately re-verifies the emitted envelope against
the checked-out commit and tree, `Cargo.lock`, canonical manifest bytes, every
artifact digest and byte count, and the exact checksum file before reporting
success. The embedded signature provides internal integrity; only the
KVM boundary workflow's separately verified Sigstore identity supplies external
provenance.

## Explicit residual boundary

M11 does not enable the conditional M7 cross-organization escrow design. The
hosted profile's ACP rail remains the admitted single-operator settlement
boundary. A Firecracker guest image is part of the trusted release artifact.
The worker verifies its digest and requires the guest supervisor to bind exact
in-guest cgroup-v2 process and `RLIMIT_NOFILE` ceilings into every accepted
result. The real-KVM canary verifies that contract, but does not establish
arbitrary guest semantic correctness.

This branch ships a dark hosted listener, typed and signature-validating
PostgreSQL domain journals, resumable SQLite import, tenant-scoped catalog
reads, authenticated SDK clients, and immutable Kubernetes and KVM deployment
contracts. SQLite remains local-only and is never mounted into either hosted
production role. `/v1/findings/publish` preserves the raw signed Finding
contract used by existing clients.

The generic hosted event endpoint admits only immutable artifact ingress for
listings, kernel-authenticated deliveries, buyer challenges, seller verified
fixes, seller voluntary retractions, and operator penalties. Admission,
allocation, purchase, reveal, failed-delivery, adjudication, liability, appeal,
purchase-terminal, enforcement, settlement, status publication, and audit
writes are internal-only outputs of their atomic coordinators. This split keeps
the HTTP boundary from bypassing authority checks, payment journaling, recovery,
or multi-record state transitions.

Catalog reads suppress sticky voluntary and enforcement-pending retractions.
A status epoch stores a signed sparse-map root but the hosted PostgreSQL profile
does not yet retain per-Finding sparse proofs. Once an epoch exists, catalog
reads therefore quarantine the requested page instead of guessing liveness.
Public and customer traffic remains forbidden. Activation requires exact-release
code, PostgreSQL, KVM, and network evidence plus a separately reviewed traffic
promotion. M7 bilateral escrow, auctions, and usage-gated stochastic R&D remain
outside M11.
