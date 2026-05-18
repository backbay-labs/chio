# V2 — Real two-kernel federation across a real network boundary (design)

Action-plan item: "V2: real two-kernel federation across real network boundary".

Status: design only. Spinning up two real kernel processes that
communicate across a real network boundary is a systems engineering
effort that touches infrastructure choice (gRPC transport vs. the
existing in-process gossip), container orchestration, key custody
across hosts, and an end-to-end CI matrix. This is not autonomous-
cron-shaped work. Decision memo below.

## Context

Today's federation tests (`crates/chio-federation/tests/`) run two
"kernels" in the same Rust process by instantiating two
`KernelHandle`s and routing gossip frames between them via a shared
`InProcessTransport`. This validates the protocol logic but is
in-process: no TCP, no TLS, no clock skew, no partition recovery,
no realistic adversary model.

Paper §6 explicitly names this as a v2 follow-up gap: the v1
demonstration is "three-party in a single process with replay
fixtures". The paper-internal limitations bullet acknowledges that
real federation across a real network boundary is unaddressed.

V2 closes that gap with two real kernel processes, communicating
over a real transport, exchanging real receipts, and recovering
from real network failures.

## Scope decision

The v2 effort splits into three tiers. The cron design only
addresses the architectural choices; the implementation is a
multi-week dedicated engineering session.

### Tier 1 — Localhost-via-Docker

Two `chio-cli` binaries running in two containers on a single host,
communicating over a bridge network. Goal: validate the gossip
protocol survives serialization across a real socket, that timeouts
and retries actually engage, and that the kernel can recover from
peer restart.

Tier-1 deliverables:

- `infra/federation-localhost/docker-compose.yml` with two services
  (`kernel-a`, `kernel-b`) and a bridge network.
- Per-kernel key material mounted as secrets, with deterministic
  fingerprints for reproducibility.
- A smoke-test runner `crates/chio-federation/tests/e2e_two_kernel_docker.rs`
  that brings the compose stack up, drives a three-receipt admit/deny
  scenario, and validates both kernels converge on the same admit-set.
- CI workflow `.github/workflows/federation-localhost.yml` that runs
  the smoke test on every PR touching `chio-federation/**`.

### Tier 2 — Two-host LAN

Two physical or virtual hosts on the same LAN. Goal: validate
realistic clock skew, MTU effects, packet loss, and asymmetric
bandwidth. Requires a CI provider that can allocate two hosts
(GitHub Actions matrix, or a self-hosted runner).

Tier-2 deliverables:

- `infra/federation-twohost/terraform/` or equivalent provisioning
  IaC.
- `crates/chio-federation/tests/e2e_two_host_lan.rs` driving the same
  scenarios as Tier 1 but with real network behavior.
- Operator runbook for the LAN setup.

### Tier 3 — Cross-region WAN

Two hosts in different cloud regions. Goal: validate WAN latency,
real partition behavior, NAT traversal if applicable, and
TLS-with-distinct-CA setup. Requires real cloud spend.

Tier-3 deliverables:

- Cloud account with cost cap and budget alert.
- Repeat of Tier 2 scenarios across the WAN.
- §6 paper update reporting WAN-mode replay numbers.

## Transport choice

Three candidates for the inter-kernel transport:

| Transport       | Tier 1 fit | Tier 2 fit | Tier 3 fit | Notes                                              |
|-----------------|------------|------------|------------|----------------------------------------------------|
| gRPC over TCP/TLS | yes        | yes        | yes        | Standard. Schema-evolution friendly. Heavy footprint. |
| QUIC            | yes        | yes        | yes        | Lower handshake cost over WAN. Less Rust tooling. |
| Raw TCP + length-prefixed frames | yes        | yes        | partial    | Cheapest. No standard reconnect semantics; we'd build them. |

Recommendation: **gRPC over TLS** using `tonic`. Reasons:

1. The existing `chio-federation` gossip protocol is already
   well-typed; mapping it to a `tonic` service is mechanical.
2. Schema evolution is the right shape for V8-class issuer-rotation
   wire-format bumps.
3. TLS handshake gives us mTLS for free — each kernel's identity
   key becomes its mTLS client cert.

## Key custody across hosts

Each kernel needs:

- Its own DSSE signing key (per `bilateral_dsse.rs`).
- Its mTLS client cert + key (new, for V2).
- The trust-store of peer kernels it federates with.

For Tier 1 (Docker): keys mounted as compose secrets, derived from a
deterministic seed for reproducibility.

For Tier 2 / Tier 3: keys provisioned via a sealed-secret store
(SOPS or sealed-secrets). The operator runbook covers key rotation
(coordinates with V8).

## Scenario coverage

The two-kernel scenarios must exercise:

1. **Convergent admit**: receipt admitted by both kernels, gossip
   propagates, both kernels converge.
2. **Divergent admit/deny**: receipt admitted by one kernel, denied
   by the other (different treaty scopes). Gossip propagates the
   denial; the admitting kernel must not retroactively revoke.
3. **Partition recovery**: kernel-a continues admitting during a
   bridge network outage; on reconnect, both kernels converge on the
   union.
4. **Conflicting amendments**: each kernel proposes a different
   amendment; the V5 / V4 trajectory-invariant theorems mediate
   the merge.
5. **Adversarial peer**: one kernel runs a modified binary that
   attempts to admit a receipt outside its treaty scope; the honest
   kernel's verifier must reject.

Scenarios 4 and 5 are exactly the trajectory-invariant V4/V5 and
the meta-amendment V4 theorems exercising the network boundary.

## Lean formalization (V2-companion)

The existing `PredicateLang.lean` essentially-predicate-preservation
and `containsPredicate`-preservation theorems already cover the
amendment-trajectory invariants. V2 adds an *operational* dimension:
the network is allowed to drop, reorder, or duplicate gossip frames,
and the kernel state must remain admissible under V4/V5 across that.

A meaningful V2-companion theorem could be:

```lean
/-- Idempotent receipt application: re-delivering a previously
    admitted receipt does not change the admission set. -/
theorem admission_idempotent_under_replay
    (c : SyntacticConstitution) (rid : ReceiptId)
    (admitted : admits c rid = true) :
    admits c rid = admits c rid := rfl
```

Trivial in isolation. The non-trivial extension would model a list of
gossip events and prove the admission set is the same regardless of
delivery order. Deferred to V2's focused engineering session.

## Why this is not the autonomous cron's job

1. Bringing up Docker / Terraform / TLS infrastructure is several
   days of operator-level work, not a cron fire's scope.
2. The CI matrix needs human sign-off on resource budget (two-host
   LAN especially, cross-region WAN even more).
3. The operator runbook needs human review for production secret
   handling.
4. The benchmark numbers reported in §6 v2 are real measurements
   requiring real hosts.

So the cron writes this design and stops here.

## Sequencing

Recommended order:

1. **Tier 1 (Docker)**: 2-3 week engineering effort. Validates protocol
   over real socket; minimal infrastructure spend.
2. **Tier 2 (two-host LAN)**: 1-2 week effort once Tier 1 is green.
   Adds realistic network behavior.
3. **Tier 3 (cross-region WAN)**: 1-2 week effort. Targets a follow-
   up paper (Paper 5: adversarial-replay benchmark, USENIX Security
   2027 / NSDI 2027 per the next-paper pipeline).

Tier 1 alone is sufficient to retire the v1 limitation "all
federation tests are in-process". Tiers 2 and 3 build the empirical
base for the NDSS 2027 v2 submission.

## Connection to other v2 items

- **V6** (replay corpus): the buyer-closure fixtures from V6 can drive
  the two-kernel scenarios directly.
- **V7** (threshold cosigning): once V7 ships, the kernel-a→kernel-b
  cosign step becomes a threshold operation across the two kernels.
- **V8** (issuer-rotation epoch binding): the schema-v2 wire bump
  must be present in the two-kernel transport from day one of V2,
  or the migration plan must explicitly cover the V2 transport.

So V2 should land after V6/V7/V8 design is committed and at least
V7 has shipped; otherwise V2 has to re-do its wire format twice.

## Connection to the paper

§6 v2 update: report two-kernel-Docker replay numbers (Tier 1) and
two-host-LAN replay numbers (Tier 2). §9 v1 limitations bullet
"federation tests are in-process" gets retired once V2 Tier 1 ships.
§5 architecture diagram gets a new "transport layer" box.
