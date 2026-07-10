# Reliability program: series index and phased remediation roadmap

- Status: Living index (wave-3 reliability program)
- Date: 2026-07-04
- Scope: the 13 RFCs and 2 program plans in this directory

This directory is the actionable output of the multi-wave infrastructure
readiness review (2026-07-03). The review read Chio against the framing of the
Ubicloud article "PostgreSQL and the OOM Killer": a system under overload or
partial failure must fail early, locally, and gracefully, not by process death
or unbounded growth; strict overcommit (refusing work you cannot account for)
beats optimistic admission followed by a kill. Every document here converts a
verified set of findings into a buildable specification: current code cited by
file and line, proposed types with real signatures, fail-closed error paths,
and a test plan.

Each RFC header carries a "Closes findings" line pointing at this README. The
coverage matrix in section 5 is the authoritative finding-to-owner mapping.
The underlying review artifact is not checked into the repository; each RFC's
motivation section restates the evidence it depends on, re-verified against
the current tree at authoring time.

## 1. The five lenses

The review, and therefore this series, evaluates every subsystem against five
lenses. Each RFC states which lenses it serves.

- L1 Fail early, local, graceful. Overload and faults must surface as typed,
  fail-closed denials at the point of admission, not as process death,
  unbounded queues, or hangs. (RFC-0001, RFC-0004, RFC-0010, RFC-0012)
- L2 Known blast radius. When a component dies mid-operation, the effect of
  the partial work must be bounded, receipted, and recoverable. (RFC-0002,
  RFC-0003, RFC-0007, RFC-0013)
- L3 Trustworthy accounting. Internal accounting (receipts, budgets, health
  surfaces, metrics) must be correct or loudly broken; an instrument that can
  lie is worse than no instrument. (RFC-0006, RFC-0008, RFC-0009, RFC-0011)
- L4 Predictable budgets. Time, memory, and money have explicit, configured
  budgets with a defined behavior at exhaustion. (RFC-0001, RFC-0004,
  RFC-0011, RFC-0013)
- L5 Durable recovery. Restart from any crash point converges to a consistent,
  auditable state without operator archaeology. (RFC-0003, RFC-0005,
  RFC-0006, RFC-0007)

The two PLAN documents provide the acceptance machinery for all five lenses:
PLAN-load-chaos supplies the measured load, soak, and fault-injection
harnesses; PLAN-formal-methods supplies the model-checked and proof-backed
invariants.

## 2. Document index

| Id | Title | Closes findings | Extends ADR | Depends on | Buildability |
| --- | --- | --- | --- | --- | --- |
| [RFC-0001](./RFC-0001-hot-path-deadlines.md) | Hot-path deadlines and watchdogs | F01, F07 (with RFC-0006), F14 (with RFC-0011) | ADR-0006, ADR-0013 | RFC-0002 | ready |
| [RFC-0002](./RFC-0002-unconditional-post-admission-unwind.md) | Unconditional post-admission unwind | F02, F08 | ADR-0003, ADR-0006 | none | ready |
| [RFC-0003](./RFC-0003-dispatch-intent-journal.md) | Durable dispatch-intent journal | F04, F31, F70 (with RFC-0013) | ADR-0008, ADR-0013 | RFC-0006 | ready |
| [RFC-0004](./RFC-0004-bounded-memory-enomem-analog.md) | Bounded-memory architecture and the ENOMEM analog | F03, F06, F10, F12, F21, F25, F38, F39, F63 (with RFC-0010) | none | none | ready |
| [RFC-0005](./RFC-0005-durable-by-default-wiring.md) | Durable-by-default store wiring and schema versioning | F19, F26, F60, F62, F64, F65 | ADR-0004, ADR-0013 | none | ready |
| [RFC-0006](./RFC-0006-storage-hot-path.md) | Storage hot path: incremental verification, background checkpoints, single writer | F07, F22, F28, F29 | ADR-0008, ADR-0013 | none | ready |
| [RFC-0007](./RFC-0007-retention-without-bricking.md) | Retention and compaction that preserve the append invariant | F23, F24, F30 | ADR-0008 | RFC-0006 | minor-gaps |
| [RFC-0008](./RFC-0008-task-supervision-honest-health.md) | Task supervision and health surfaces that cannot lie | F09, F13, F27, F59, F84 | ADR-0009 | RFC-0001, RFC-0002, RFC-0009 | ready |
| [RFC-0009](./RFC-0009-observability-alerting-wiring.md) | Observability and alerting wiring | F57, F58, F75, F77, F78, F79, F80, F81, F82, F83 | ADR-0009 | none | minor-gaps |
| [RFC-0010](./RFC-0010-graceful-shutdown-server-hygiene.md) | Graceful shutdown, drain, and server hygiene | F11, F61, F63 (with RFC-0004) | none | RFC-0001 | minor-gaps |
| [RFC-0011](./RFC-0011-control-plane-replication-soundness.md) | Control-plane replication soundness | F14, F15, F16, F20 | ADR-0006 | none | ready |
| [RFC-0012](./RFC-0012-federation-transport-hardening.md) | Federation transport hardening | F33, F34, F35, F36, F37 | ADR-0014 | RFC-0001, RFC-0003 | ready |
| [RFC-0013](./RFC-0013-money-path-durability.md) | Money-path durability | F68, F69, F70, F71, F72, F73, F74 | ADR-0006, ADR-0015 | RFC-0003 | ready |
| [PLAN-load-chaos](./PLAN-load-soak-chaos-program.md) | Load, soak, and chaos program | F49, F50, F51, F53, F54, F55, F56 (F52 with PLAN-formal-methods) | none | RFC-0004, RFC-0006 | minor-gaps |
| [PLAN-formal-methods](./PLAN-formal-methods-program.md) | Formal-methods program | F41, F42, F43, F44, F45, F46, F47, F48, F52 | none | RFC-0002, RFC-0003, RFC-0011 | ready |

"Buildability" reflects the authoring-time self-assessment: "ready" means the
document is implementable as written; "minor-gaps" means the document names
specific decisions or discovery an implementer must resolve (each such
document lists them explicitly in its risks or open-questions section).

## 3. Dependency graph

Six documents have no prerequisites and can start immediately:

- RFC-0002 (unwind) and RFC-0006 (storage hot path) are the keystones; between
  them they gate seven other documents.
- RFC-0004 (bounded memory, the memory keystone), RFC-0005 (durable wiring),
  RFC-0009 (observability), and RFC-0011 (control-plane replication) are
  independent roots.

Sequencing, as a prerequisite list (a document may begin once everything on
its right has landed):

```
RFC-0002  <- (none)                          keystone: unwind
RFC-0006  <- (none)                          keystone: storage hot path
RFC-0004  <- (none)                          keystone: bounded memory
RFC-0005  <- (none)
RFC-0009  <- (none)
RFC-0011  <- (none)

RFC-0001  <- RFC-0002
RFC-0003  <- RFC-0006
RFC-0007  <- RFC-0006

RFC-0008  <- RFC-0001, RFC-0002, RFC-0009
RFC-0010  <- RFC-0001
RFC-0012  <- RFC-0001, RFC-0003
RFC-0013  <- RFC-0003

PLAN-load-chaos      <- RFC-0004, RFC-0006
PLAN-formal-methods  <- RFC-0002, RFC-0003, RFC-0011
```

As a fan-out view of the keystones:

```
RFC-0002 (unwind)
  +-- RFC-0001 (deadlines)
  |     +-- RFC-0010 (shutdown/drain)
  |     +-- RFC-0012 (federation transport; also needs RFC-0003)
  |     +-- RFC-0008 (supervision; also needs RFC-0009)
  +-- PLAN-formal-methods (also needs RFC-0003, RFC-0011)

RFC-0006 (storage hot path)
  +-- RFC-0003 (intent journal)
  |     +-- RFC-0013 (money path)
  |     +-- RFC-0012 (federation transport; also needs RFC-0001)
  +-- RFC-0007 (retention)
  +-- PLAN-load-chaos (also needs RFC-0004)
```

Notes for the scheduler:

- RFC-0002 must land before RFC-0001: the deadline arm in
  `async_evaluation_core.rs` reuses the unwind markers RFC-0002 introduces.
  Both RFCs edit the same arms; the sequencing is mandatory, not advisory.
- RFC-0007 is derived against RFC-0006's writer-actor shape (single writer
  commands, `seed_verified_head`, audit demotion). If RFC-0006 changes during
  review, RFC-0007 sections 4-6 must be re-derived before implementation.
- RFC-0004 is the memory keystone: every bounded-collection change and the
  `KernelError::Overloaded` ENOMEM analog land there, and PLAN-load-chaos's
  soak assertions consume its `SizeProbe` surface.
- RFC-0009's shared emission runtime (its part A) is a soft prerequisite for
  every document that adds metrics; only RFC-0008 takes it as a hard
  dependency.

## 4. Phased roadmap

Phases are ordered by risk retired per unit effort. A phase may begin before
the previous one fully lands, subject to the dependency graph above. Effort
figures are rough single-implementer estimates; much of Phase 2 parallelizes.

### Phase 0: stop the bleeding (est. 3-5 weeks)

Closes the three critical findings (F02, F57, F60) and the reproduced
retention brick (F23). Everything here is either dependency-free or gated
only on RFC-0006, which is itself dependency-free.

| Work item | Findings closed |
| --- | --- |
| RFC-0002 (unconditional unwind) | F02 (critical), F08 |
| RFC-0005 (durable-by-default wiring) | F60 (critical), F19, F26, F62, F64, F65 |
| RFC-0006 (storage hot path) | F07, F22, F28, F29 |
| RFC-0007 (retention without bricking) | F23 (brick, reproduced), F24, F30 |
| RFC-0009, alert-pack slice only (parts A and B) | F57 (critical), F77 |

Phase 0 exit: no silent receipt loss on drop paths, no ephemeral-by-default
receipt or revocation stores in production wiring, receipt append cost is
O(1), retention can no longer brick a store on reopen, and the p0/p1 alert
pack fires from real emission sites.

### Phase 1: durability, bounded memory, deadlines, honest supervision (est. 4-6 weeks)

Closes the effect-before-receipt crash window, bounds every hot-path memory
structure, puts budgets on every hot-path wait, and makes health surfaces
unable to report healthy while dead.

| Work item | Findings closed |
| --- | --- |
| RFC-0001 (hot-path deadlines) | F01 (plus the RFC-0001 half of F14) |
| RFC-0003 (dispatch-intent journal) | F04, F31 (F70 groundwork; closed in Phase 2 by RFC-0013) |
| RFC-0004 (bounded memory, ENOMEM analog) | F03, F06, F10, F12, F21, F25, F38, F39, F63 |
| RFC-0008 (task supervision, honest health) | F09, F13, F27, F59, F84 |
| RFC-0010 (graceful shutdown, server hygiene) | F11, F61 (F63 systemd half) |

Phase 1 exit: a crash at any point between admission and receipt commit is
reconciled at boot, no unbounded in-process collection remains on a governed
path, a hung guard or tool server cannot pin the kernel, and a dead receipt
writer denies at the door instead of accepting evidence-less side effects.

### Phase 2: control plane, federation, money path, observability depth (est. 2-3 months, parallelizable)

Closes the distributed-systems and payments findings and replaces testing
theater with measured harnesses and model-checked protocols.

| Work item | Findings closed |
| --- | --- |
| RFC-0011 (control-plane replication soundness) | F14, F15, F16, F20 |
| RFC-0012 (federation transport hardening) | F33, F34, F35, F36, F37 |
| RFC-0013 (money-path durability) | F68, F69, F70, F71, F72, F73, F74 |
| RFC-0009, remainder (SIEM delivery, OTEL retry, scrape routes, serve mode) | F58, F75, F78, F79, F80, F81, F82, F83 |
| PLAN-load-chaos (measured load, soak, chaos harnesses) | F49, F50, F51, F53, F54, F55, F56 |
| PLAN-formal-methods (gates, specs, seam tests) | F41, F42, F43, F44, F45, F46, F47, F48, F52 |

The two PLAN documents should start their cheap workstreams (CI gate wiring,
stale-label fixes, loom lanes) as soon as Phase 0 lands; their harness-backed
acceptance runs are what certify Phases 0 and 1 as actually done, so treating
them as continuous programs rather than a trailing phase is recommended.

## 5. Coverage matrix

76 finding ids are owned by this series. Every id has exactly one primary
owner; five are shared with a named supporting document. No finding in the
required set is unowned.

| Finding | Primary owner | Also touched by |
| --- | --- | --- |
| F01 | RFC-0001 | |
| F02 | RFC-0002 | |
| F03 | RFC-0004 | |
| F04 | RFC-0003 | |
| F06 | RFC-0004 | |
| F07 | RFC-0006 (checkpoint off the write lock) | RFC-0001 (bounded append, writer watchdog) |
| F08 | RFC-0002 | |
| F09 | RFC-0008 | |
| F10 | RFC-0004 | |
| F11 | RFC-0010 | |
| F12 | RFC-0004 | |
| F13 | RFC-0008 | |
| F14 | RFC-0011 (progress-driven quorum wait) | RFC-0001 (outer timeout bound) |
| F15 | RFC-0011 | |
| F16 | RFC-0011 | |
| F19 | RFC-0005 | |
| F20 | RFC-0011 | |
| F21 | RFC-0004 | |
| F22 | RFC-0006 | |
| F23 | RFC-0007 | |
| F24 | RFC-0007 | |
| F25 | RFC-0004 | |
| F26 | RFC-0005 | |
| F27 | RFC-0008 | |
| F28 | RFC-0006 | |
| F29 | RFC-0006 | |
| F30 | RFC-0007 | |
| F31 | RFC-0003 | |
| F33 | RFC-0012 | |
| F34 | RFC-0012 | |
| F35 | RFC-0012 | |
| F36 | RFC-0012 | |
| F37 | RFC-0012 | |
| F38 | RFC-0004 | |
| F39 | RFC-0004 | |
| F41 | PLAN-formal-methods | |
| F42 | PLAN-formal-methods | |
| F43 | PLAN-formal-methods | |
| F44 | PLAN-formal-methods | |
| F45 | PLAN-formal-methods | |
| F46 | PLAN-formal-methods | |
| F47 | PLAN-formal-methods | |
| F48 | PLAN-formal-methods | |
| F49 | PLAN-load-chaos | |
| F50 | PLAN-load-chaos | |
| F51 | PLAN-load-chaos | |
| F52 | PLAN-formal-methods (loom lane spec) | PLAN-load-chaos (nightly execution) |
| F53 | PLAN-load-chaos | |
| F54 | PLAN-load-chaos | |
| F55 | PLAN-load-chaos | |
| F56 | PLAN-load-chaos | |
| F57 | RFC-0009 | |
| F58 | RFC-0009 | |
| F59 | RFC-0008 | |
| F60 | RFC-0005 | |
| F61 | RFC-0010 | |
| F62 | RFC-0005 | |
| F63 | RFC-0004 (memory/OOM OS guidance) | RFC-0010 (systemd restart and grace window) |
| F64 | RFC-0005 | |
| F65 | RFC-0005 | |
| F68 | RFC-0013 | |
| F69 | RFC-0013 | |
| F70 | RFC-0013 (payment journal, idempotency contract) | RFC-0003 (dispatch-intent groundwork) |
| F71 | RFC-0013 | |
| F72 | RFC-0013 | |
| F73 | RFC-0013 | |
| F74 | RFC-0013 | |
| F75 | RFC-0009 | |
| F77 | RFC-0009 | |
| F78 | RFC-0009 | |
| F79 | RFC-0009 | |
| F80 | RFC-0009 | |
| F81 | RFC-0009 | |
| F82 | RFC-0009 | |
| F83 | RFC-0009 | |
| F84 | RFC-0008 | |

Checklist for the tracker: when a shared finding is closed, the primary owner
closes it; the supporting document's contribution is verified as part of that
close. In particular, record F63 against RFC-0004 (not RFC-0010) and F70
against RFC-0013 (not RFC-0003), per the split each pair of documents states.

## 6. How this series connects to existing documents

- ADRs extended. The series extends eight accepted ADRs rather than replacing
  them: [ADR-0003](../../adr/ADR-0003-nested-flow-model.md) (nested flow
  model), [ADR-0004](../../adr/ADR-0004-first-receipt-backend.md) (first
  receipt backend), [ADR-0006](../../adr/ADR-0006-monetary-budget-semantics.md)
  (monetary budget semantics),
  [ADR-0008](../../adr/ADR-0008-checkpoint-trigger-strategy.md) (checkpoint
  trigger strategy), [ADR-0009](../../adr/ADR-0009-siem-isolation.md) (SIEM
  isolation), [ADR-0013](../../adr/ADR-0013-async-receipt-durability.md)
  (async receipt durability),
  [ADR-0014](../../adr/ADR-0014-iroh-federation-transport.md) (iroh federation
  transport), and
  [ADR-0015](../../adr/ADR-0015-predeclared-escrow-circuit-breakers.md)
  (predeclared escrow circuit breakers). Where an RFC changes behavior an ADR
  documents (for example RFC-0006's flush semantics against ADR-0013), the
  RFC calls the change out explicitly for sign-off.
- Review artifact. Finding ids (F01-F84) refer to the wave-3 infrastructure
  readiness review of 2026-07-03. The review artifact itself is not in-tree;
  each RFC restates and re-verifies the evidence it uses, so the RFCs are
  self-contained. Ids absent from the matrix above (F05, F17, F18, F32, F40,
  F66, F67, F76) were resolved, reclassified, or descoped during review
  triage and are intentionally not owned by this series.
- Acceptance tests. [PLAN-load-chaos](./PLAN-load-soak-chaos-program.md)
  provides the measured load, soak, and fault-injection harnesses that
  certify the L1/L4 budget claims and the L2/L5 crash-recovery claims;
  [PLAN-formal-methods](./PLAN-formal-methods-program.md) provides the
  model-checked invariants (receipt lifecycle, budget replication quorum) and
  proof-gate CI wiring that certify the L3 accounting claims. An RFC is done
  when its own test plan passes and the relevant PLAN harness exercises it.
- Posture. Every design in this series follows the workspace fail-closed
  rule: errors deny access, invalid configuration rejects at load time, and
  signed payloads use canonical JSON (RFC 8785).

## 7. Documentation index

This README should be linked from [docs/README.md](../../README.md) under the
architecture section so the reliability program is discoverable from the
documentation root.
