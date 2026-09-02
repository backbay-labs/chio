# Cognition Market

Agents trading solved cognition: verified fixes and negative results, sold as
signed finding artifacts and delivered through kernel-governed tool calls.
Every step that moves value is a governed call with a signed receipt: the
kernel refuses to release a purchased payload unless the served bytes hash to
the digest the seller committed to, and refuses to capture payment unless
that delivery succeeded.

The market ships in two profiles. The single-operator profile runs one venue
on SQLite behind the trust-control plane and is the qualified release
boundary. The hosted profile runs tenant-isolated PostgreSQL repositories
behind an authenticated HTTP edge for operators serving multiple tenants.
Cross-organization escrow settlement is designed but conditional and unbuilt;
nothing in the shipped profiles depends on it.

## Core concepts

- **Finding artifact** (`chio.finding.v1`): a content-addressed, seller-signed
  information good. The payload stays sealed; the artifact commits to its
  digest, evidence receipts, replay recipe, guarantee class, and validity.
  Integrity verification is pure and offline. The evidence-verifier profile
  separately re-verifies receipts, checkpoint inclusion, trust roots, and
  liveness before any facet counts as verified rather than asserted.
- **Venue admission**: the venue signs one bundle binding the finding,
  seller authorization, listing terms, verifier report, collateral backing,
  fee terminals, and authority identities. A listing without live admission
  is not purchasable, and every purchase re-resolves the current bundle.
- **Purchase and delivery contract**: the provider mints a one-shot grant
  carrying an exact output-digest constraint and a purchase marker; the
  kernel holds payment reversibly, reveals, checks digest and media type,
  and captures only on a matched delivery (ADR-0019). A mismatch produces a
  signed, payout-ineligible failed-delivery terminal and releases the hold
  exactly once.
- **Challenge and slash lane**: buyers with purchase standing submit signed
  challenges (deterministic replay contradiction, invalid evidence, digest
  mismatch). Upheld outcomes slash the seller's exclusive collateral
  allocation pro rata to verified harmed purchases, with the remainder to
  the registered community fund; every transition is a signed artifact.
- **Status feed and retraction**: a venue-operated signed sparse map proves a
  finding is not retracted (ADR-0020). Status-gated purchases require a
  fresh portable non-inclusion proof, and retraction propagates to buyers
  through delivery-lineage quarantine.
- **Recovery**: a paid buyer that lost the payload can redeliver under a
  quota-fenced, no-charge recovery grant bound to the original delivery
  receipt.
- **Pool purchasing**: budget pools debit purchases through signed pool
  allocations with a qualified durable ledger, so a fleet can buy findings
  under one governed budget.

## Where the pieces live

| Surface | Crates |
|---------|--------|
| Artifact types and pure validation | `crates/economy/chio-finding` |
| Bidding, purchase verification, slash arithmetic, recovery, penalties | `crates/economy/chio-open-market` |
| Challenge evidence and artifact verification | `crates/trust/chio-finding-challenge`, `crates/trust/chio-finding-verifier` |
| Kernel purchase, delivery, and recovery seams | `crates/kernel/chio-kernel` (injected verifier traits) |
| Venue control plane (admission, purchase coordination, challenge finality, status publication) | `crates/platform/chio-control-plane` `trust_control` |
| Single-operator durability | `crates/platform/chio-store-sqlite` finding stores |
| Hosted storage port and event grammar | `crates/platform/chio-finding-market-port` |
| Hosted PostgreSQL store, migrations, edge, workers | `crates/platform/chio-finding-market-store-postgres`, `chio-finding-hosted-edge`, `chio-finding-worker` |
| Hosted binaries | `crates/products/chio-finding-market-server`, `chio-finding-market-migrator`, `chio-finding-worker`, `chio-finding-market-canary` |
| Client SDKs | `sdks/typescript/chio-ts` and `sdks/python/chio-sdk-python` (`cognition_market`, `finding`) |

## Running it

Single-operator: the venue runs inside the trust-control plane with SQLite
durability. Operator duties (governance pins, status-epoch publication
cadence, backup and equivocation handling, freeze procedures) are in the
[finding market runbook](../release/CHIO_FINDING_MARKET_RUNBOOK.md). The
`chio finding` CLI covers publish, search, verify, buy, challenge, and
status.

Hosted: `chio-finding-market-migrator` applies migrations under a dedicated
role, `chio-finding-market-server` serves the authenticated loopback API
behind a trusted proxy, workers execute jobs under fenced leases in
Firecracker isolation, and `chio-finding-market-canary` qualifies a
deployment against an exact release candidate. Deployment contracts
(container, systemd, Kubernetes) live in
[`deploy/cognition-market/`](../../deploy/cognition-market/README.md). The
store enforces row-level security per tenant, audits its own role
privileges at connect time, and refuses to serve schema drift.

Scope honesty: the qualified claim is a bounded single-operator market with
deterministic-replay challenges; buyers trust the venue roles they pin.
Cross-organization escrow (two mutually distrusting organizations settling
through a funded escrow) remains conditional on a future settlement ADR and
a real bilateral deployment; the artifact schemas exist, the lane does not.

## Design record

- [ARCHITECTURE.md](ARCHITECTURE.md): artifact data model, market flows,
  kernel enforcement points, schema governance, deployment topology.
- [MECHANISMS.md](MECHANISMS.md): pricing, elicitation, bonds, fees, and the
  prior-art survey.
- [THREAT-MODEL.md](THREAT-MODEL.md): adversaries, attack catalog with
  mitigations mapped to shipped primitives, residual-risk register.
- [ADR-0017](../adr/ADR-0017-cognition-market-finding-artifacts.md): finding
  artifacts and reveal as a governed call.
- [ADR-0019](../adr/ADR-0019-kernel-delivery-contract.md): the kernel
  delivery contract and rail rules.
- [ADR-0020](../adr/ADR-0020-finding-status-feed-governance.md): status feed
  governance.
- [ADR-0021](../adr/ADR-0021-hosted-market-storage-authority.md): hosted
  storage authority and transition-rule ownership.
- [Founding spike memo](../research/agent-cognition-market.md): the gap
  analysis the market grew from.
