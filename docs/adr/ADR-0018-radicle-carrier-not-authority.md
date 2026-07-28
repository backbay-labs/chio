# ADR-0018: Radicle Is A Carrier, Never An Authority (Adoption Deferred)

- Status: Accepted (decision recorded 2026-07-25; adoption deferred, not scheduled)
- Decision owner: trust and federation lane
- Companion evaluation: [../research/radicle/EVALUATION.md](../research/radicle/EVALUATION.md)
- Companion spec (deferred, build only if triggered): [../research/radicle/CARRIER-SPEC.md](../research/radicle/CARRIER-SPEC.md)
- Related: ADR-0014 (iroh federation transport), ADR-0008 (checkpoint trigger strategy), `spec/PROTOCOL.md` section 6.5
- Supersedes: nothing

## Context

The Radicle protocol (peer-to-peer git collaboration: Ed25519 node identities,
`did:key`, repository identity documents with delegate thresholds, gossip
replication, and CRDT Collaborative Objects) was proposed for integration into
Chio. A ten-agent evaluation was run across two waves, including three hands-on
experiments: a dependency build spike against the real workspace, a two-node
custom Collaborative Object round trip, and a six-node equivocation-suppression
experiment. The consolidated evidence is in the companion evaluation document.

The evaluation was initially framed as "should Chio adopt Radicle." It resolved
into a different and more useful question: "what closes the publication and
anti-equivocation gap that `spec/PROTOCOL.md` section 6.5 documents against
itself." Radicle turned out to be one candidate answer to that question, and
not the strongest one.

## Decision

Four rulings, in decreasing order of confidence.

**1. Radicle is rejected as an authority, permanently and on structural
grounds.** No Radicle node identity may be a Chio principal. No Radicle
delegate signature, delegate threshold, ref signature, commit signature, or
Collaborative Object merge outcome may be an input to any Chio accept decision.
This is forced rather than chosen: Radicle identities are Ed25519-only because
the node id doubles as the Noise XK static Diffie-Hellman key, while
`ReceiptCryptoFloor::PqRequired`
(`crates/core/chio-core-types/src/receipt/crypto_floor.rs`) rejects
classical-only signatures and
`crates/tooling/chio-conformance/tests/threats/pq_signature_downgrade.rs`
guards the downgrade path. Admitting Radicle authority would silently weaken
the crypto floor for exactly the deployments that set it highest.

**2. The full `radicle` crate is rejected as an in-process dependency, on
empirical grounds.** It does not resolve. `radicle` 0.25.1 depends
non-optionally on `sqlite` 0.37, whose `sqlite3-src` declares
`links = "sqlite3"`, colliding with the `libsqlite3-sys` that `rusqlite`
brings in. Twelve crates spanning the kernel, receipt store, control plane,
pheromone runtime, and CLI depend on `rusqlite`, and Cargo enforces `links`
uniqueness across the whole workspace resolve, so the collision cannot be
quarantined behind a leaf crate. No feature flag avoids it. Any future Radicle
work is therefore out-of-process by necessity, not by preference.

**3. Radicle adoption as a publication carrier is deferred, not rejected.** The
narrow carrier design is sound and the evaluation validated its central
mechanism experimentally. It is deferred because it is not on the critical path
for anything Chio has committed to (see ruling 4), and because taking it on now
would add an operational surface (seed topology, a second gossip mesh, node key
custody, config drift) in exchange for a property Chio cannot yet make use of.
The trigger conditions for revisiting are listed below.

**4. The `transparency_preview` cap is not substrate-blocked, and closing it is
the actual work.** Most required correctness work is internal to Chio and
identical regardless of where checkpoints are published. The earlier 80 to 85
percent estimate is withdrawn because registry schema names do not map
one-to-one to independent commitment work. The transparency program document
(`docs/architecture/transparency/README.md`) is the authoritative plan and
takes priority over any carrier work.

If a carrier is later built, it is bound by these invariants, which are
normative and not subject to revision inside a carrier implementation:

- **Carrier, never authority.** The only thing that makes a published
  checkpoint authoritative is the Chio kernel signature inside the published
  blob, verified against a key pinned out of band.
- **Absence is never evidence.** A missing path means unknown, never
  "does not exist" and never "not revoked".
- **Withholding degrades to denial.** A stale head denies past the freshness
  window. Unavailability is never a silent accept.
- **Sibling adapter, no surgery.** `chio-kernel` and `chio-federation` are not
  modified, mirroring the seam ADR-0014 established for iroh.

## Rationale

**Licensing was not the blocker, contrary to the initial concern.** Every
heartwood crate is `MIT OR Apache-2.0` and published on crates.io, satisfying
both the `deny.toml` allow-list and the `unknown-git = "deny"` source policy
without modification. This is recorded because the objection was raised early
and loudly, and it is wrong.

**The stronger property is witness cosigning, not replication.** Publication
makes equivocation discoverable by a party who goes looking and who has
retained the contradicting artifact. Witness cosigning makes equivocation
unpresentable to a verifier who checks the quorum, offline, from the artifact
alone. Section 6.5 names the stronger property. The C2SP `tlog-witness` and
`tlog-cosignature` specifications define ML-DSA-44 cosignatures, making the
standards-track option the only evaluated candidate with a post-quantum
cosignature. This does not yet satisfy Chio's `PqRequired` floor, which uses a
classical plus ML-DSA-65 hybrid, and the current checkpoint signer is
Ed25519-only. Stage 4 therefore includes an explicit witness-algorithm policy
and checkpoint-signing migration. Sigsum is hard-wired to Ed25519 and fails
the same floor Radicle fails.

**The experiment partially confirmed the Radicle thesis and found its limit.**
Cross-namespace evidence proved genuinely indestructible: force-push, namespace
deletion, `rad clean`, `rad block`, flipping the repository to private, and
killing the origin node all failed to remove a conflicting checkpoint from
third-party seeders, and a node joining afterward with both original parties
offline still detected the fork. But Radicle preserves what distinct peers
published, not what a seeder saw. A passive seeder mirrors only the publisher's
namespace, and a force-push there cleanly erases the prior checkpoint from every
replica. Permanence therefore requires at least one non-colluding party to
actively re-publish under its own key, plus `--scope all` on every monitor
(`--scope followed` is supported, common, and never receives the fork).
Canonicalization also hides the fork from a plain `git clone`.

**Chio already owns a stronger anti-equivocation primitive than a p2p git
network.** `crates/economy/chio-anchor/` publishes checkpoint roots to an
on-chain EVM root registry, which supplies the total order that Radicle
deliberately does not.

## Consequences

**Accepted.**

- Chio does not gain peer-to-peer publication in this cycle. The evidence
  distribution path stays operator-mediated, which is an accurate reflection of
  what Chio can currently prove and is already correctly bounded by the section
  6.5 claim cap.
- If the carrier is built later, the layout work in the companion spec is
  substrate-agnostic through its first two stages, so nothing is wasted.

**Rejected alternatives.**

- *Radicle as a replacement for the iroh federation transport.* Three of four
  federation lanes do not fit: bilateral DSSE co-signing is an interactive
  request/response handshake and Radicle has no RPC, revocation live-push needs
  latency bounded by the freshness window, and pheromone batches are per-recipient
  unicast while Radicle's replication unit is a whole repository. Only the
  archival catch-up lane fits. Adopting it would also lose the accept-time
  `EndpointHooks` admission gate and inherit a second issuer-signed directory.
- *Radicle Collaborative Objects for the checkpoint chain.* A CRDT converges
  divergent writes; fork detection requires conflicts to survive. The
  experiment confirmed COBs surface conflicts automatically in merged state,
  which is genuinely useful, and it confirmed they require a helper binary on
  every interpreting node, where replication succeeds but evaluation
  hard-fails. Whether `radicle-httpd` exposes them was NOT tested: it was
  absent from the 1.9.1 release tarball, so its ref filtering remains an open
  question in the carrier spec rather than experimental evidence.
- *In-process `radicle-cob` alone.* It resolves and builds (44 new packages,
  +14.5s on a clean build, 6 Windows-only `[[bans.skip]]` waivers), but it
  statically links 5.5 MB of vendored libgit2 while `cargo deny check licenses`
  reports `licenses ok`. Not taken, and see the standalone finding below.

**Triggers to revisit.** Revisit if any two hold: a named requirement that is
specifically git-shaped and that TUF cannot express; the transparency program
reaches the point where publication is the remaining blocker; a customer or
partner asks for Radicle by name with a budget line; Radicle stabilizes its
crate API at 1.0 with a published support policy; or a maintained, write-capable
HTTP API returns to the core stack.

**Standalone finding, independent of this decision.** `cargo deny check
licenses` passes `libgit2-sys` as `MIT OR Apache-2.0` from crate metadata while
it vendors GPL-2.0-with-linking-exception C sources. The linking exception makes
this legally fine, but the gate reads metadata only and structurally cannot
surface it, so a reviewer seeing a green run would reasonably conclude no
copyleft is present. If any vendored-C dependency is ever adopted, `deny.toml`
needs an explicit pinned `[[licenses.exceptions]]` naming the vendored license.
