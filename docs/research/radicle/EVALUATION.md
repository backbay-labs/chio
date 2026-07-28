# Radicle evaluation: consolidated findings

- Status: Complete (2026-07-25)
- Decision: [../../adr/ADR-0018-radicle-carrier-not-authority.md](../../adr/ADR-0018-radicle-carrier-not-authority.md)
- Follow-on program: [../../architecture/transparency/README.md](../../architecture/transparency/README.md)
- Method: ten parallel agents across two waves; three hands-on experiments
  (dependency build spike, two-node Collaborative Object round trip, six-node
  equivocation-suppression experiment on Radicle 1.9.1)

This document records what was tested and what was found, including the results
that contradicted the initial framing. It is evidence, not advocacy. Claims that
were checked empirically are marked *verified*; claims from reading source or
specification are marked *read*.

## 1. What Radicle is

Radicle (implementation codename Heartwood) is peer-to-peer code collaboration
built on git. Node identities are Ed25519 keys expressed as `did:key` (NIDs).
Repositories have a Repository Identifier (RID) and an identity document naming
delegates and a signature threshold. Peers replicate by gossip, each writing
under its own namespace (`refs/namespaces/<NID>/...`) and signing a
`refs/rad/sigrefs` attestation over its ref set. Issues and patches are
Collaborative Objects (COBs): CRDTs stored as git objects, merged by a
type-specific evaluator. Transport is Noise XK over TCP. Git integration is via
a `git-remote-rad` helper.

The design is genuinely good at what it targets: no central forge, no account,
strong offline behavior, and an identity model where the repository, not a
hosting provider, is the root of trust.

## 2. Findings that contradicted the initial framing

Recorded first because they were raised early and confidently, and were wrong.

**Licensing is not a blocker.** *Verified* against the crates.io API: every
heartwood crate is `MIT OR Apache-2.0`, satisfying the `deny.toml` allow-list,
and all are published on crates.io, satisfying `unknown-git = "deny"` without a
new `allow-git` entry. The GPL components (`radicle-httpd`, `radicle-explorer`)
are separate web-UI products, not core protocol crates. The early objection that
Radicle was copyleft-encumbered and git-only was incorrect.

**The `deny.toml` license gate has a real blind spot, just not the one
alleged.** *Verified:* `cargo deny check licenses` reports `licenses ok` for a
tree that statically links 5.5 MB of vendored
GPL-2.0-with-linking-exception libgit2 C sources, because the gate reads crate
metadata (`MIT OR Apache-2.0`) and cannot see vendored C. The linking exception
makes this legally fine. The hygiene problem is that a green run tells a
reviewer something false about what is in the binary. Tracked as a standalone
finding in ADR-0018.

## 3. The dependency spike

*Verified* against the real workspace.

**The full `radicle` crate cannot be added, at all.** `radicle` 0.25.1 depends
non-optionally on `sqlite` 0.37, whose `sqlite3-src` declares
`links = "sqlite3"`. Chio uses `rusqlite`, which brings `libsqlite3-sys`,
declaring the same `links` value. Cargo enforces `links` uniqueness across the
entire workspace resolve, so this is a hard resolver error, not a warning or a
duplicate-version lint. Twelve crates across the kernel, receipt store, control
plane, pheromone runtime, and CLI depend on `rusqlite`, so the collision cannot
be quarantined in a leaf crate, and no feature flag avoids it. This single fact
forces any Radicle integration out-of-process.

**`radicle-cob` alone does resolve.** It adds 44 packages and about 14.5
seconds to a clean build, and requires 6 `[[bans.skip]]` waivers, all for
Windows-only duplicate crates. It pulls `git2` with vendored libgit2 (see
above). Buildable, but not taken.

## 4. The equivocation experiment

Six isolated localhost nodes on Radicle 1.9.1, fully disconnected from the
public network, publishing realistic `KernelCheckpointBody` JSON with real
Ed25519 signatures over canonical JSON. Verdict: **partially confirmed**, with
one decisive limit.

**What held.** Cross-namespace evidence proved indestructible under every
attack attempted: force-push, direct namespace deletion, `rad clean`,
`rad block`, flipping the repository to private, and killing the origin node.
A brand-new node joining afterward, connected only to a third-party seeder,
with both original parties confirmed offline, still received both halves and
detected the fork. Pushing to another peer's namespace is refused for deletion.
Both conflicting bodies carried valid signatures from the same kernel key, so
what the seeder ends up holding is a transferable proof of misbehavior rather
than merely two differing files.

**The limit that matters.** Radicle preserves what distinct peers *published*;
it does not make a seeder republish what it *saw*. A passive seeder mirrors only
the publisher's namespace, and a force-push there *verified* cleanly erases the
prior checkpoint from every replica's ref graph, with no warning to the network
and full removal after `git gc --prune=now`. So the property is really:

> Once two distinct Radicle peers have each published a conflicting checkpoint
> under their own keys, neither can destroy the other's copy, and the conflict
> propagates to every `--scope all` seeder and onward to parties who join later,
> surviving the disappearance of both originals.

Getting there requires a non-colluding party that actively re-publishes under
its own key, monitors mandated to `--scope all` (the supported and common
`--scope followed` never receives the fork and reported "no equivocation
detected"), and preferably the COB layout. Canonicalization also hides the fork
from a plain `git clone`, which takes only `refs/heads/*`; detection is strictly
opt-in.

**COBs detect conflicts automatically.** With checkpoints published as
operations on a custom COB type, Radicle's DAG merge unioned both peers'
operations and surfaced the conflict in materialized state via `rad cob show`,
with no cross-namespace scan. This is the better layout if the carrier is ever
built.

**Operational surprises worth recording.** Custom COB types exec an undocumented
external helper resolved from `PATH` by the last typename segment, failing with
a misleading `io: No such file or directory` and no backtrace; replication
succeeds while evaluation hard-fails on any node lacking the helper. Pushing to
another peer's namespace reports `Everything up-to-date` and exits 0 while
silently redirecting to your own namespace. Making a repository private is
self-defeating as suppression, because the node stops announcing and the
sanitizing change never reaches seeders that already have the public copy.
`radicle-httpd` is absent from the 1.9.1 release tarball.

## 5. Why Radicle does not fit the federation transport

*Read* against `chio-federation-transport-iroh`. Three of four lanes do not fit:
bilateral DSSE co-signing is an interactive request/response handshake and
Radicle has no RPC; revocation live-push needs latency bounded by the freshness
window, against eventually consistent gossip; pheromone batches are
per-recipient unicast while Radicle's replication unit is an entire repository
visible to all seeders. Only archival catch-up fits, and iroh-blobs already
covers it. Adoption would also lose the accept-time `EndpointHooks` admission
gate and inherit a second issuer-signed directory to operate.

## 6. Why Radicle cannot carry authority

Radicle node identities are Ed25519-only, structurally: the NID doubles as the
Noise XK static Diffie-Hellman key, so the identity type is pinned by the
transport handshake. Chio's `ReceiptCryptoFloor::PqRequired` rejects
classical-only signatures, and a conformance test guards the downgrade path.
Any design admitting Radicle delegate signatures as authority would weaken the
crypto floor precisely for deployments that set it highest. The same reasoning
eliminated Sigsum as a witness substrate and selected C2SP, whose
`tlog-cosignature` specification now defines ML-DSA-44.

## 7. The reframing

The evaluation began as "should Chio adopt Radicle" and ended as "what closes
the section 6.5 publication and anti-equivocation gap." The decisive finding is
that the gap is mostly not a substrate problem. Publication makes equivocation
discoverable by a party who looks and who retained the contradiction; witness
cosigning makes it unpresentable to any verifier who checks the quorum, offline.
Section 6.5 names the stronger property.

Working backward from that surfaced three standalone defects in Chio itself,
including a function named `verify_checkpoint_consistency_proof` that performs
a structural equality check and places no cryptographic constraint on tree
growth. Those defects, and the ordered plan to close the gate, are the subject
of the transparency program document. Chio also already owns a stronger
anti-equivocation primitive than a peer-to-peer git network in
`crates/economy/chio-anchor/`, which publishes checkpoint roots to an on-chain
registry supplying the total order Radicle deliberately does not.
