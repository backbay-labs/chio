# Concepts Chio Should Steal from Clawdstrike

The endpoint sensor project carries a vocabulary that Chio's formal
model gestures at but does not name. The receipt log is a singular
abstract object; sensor health is implicit; deception is absent;
per-field disclosure is folded into a single BBS projection; and the
response side of the amendment cycle has no separate term. Each gap
below is a place where a precise primitive already exists nearby and
can be lifted into Chio's Lean model and the §3-§9 prose without
overclaiming. The proposals are graded on what they add to the
substrate as a formal object, not on what they recover as engineering.
Risk-of-overclaim is named for each.

## The 7 concepts ranked by value to Chio

### 1. Sensor-state attestation embedded in every receipt

**What chio is missing.** §3 treats receipts as signed verdicts; the
kernel is assumed honest, fully sensing, and not dropping events. §4's
threat model names hostile agents and hostile peer polities but never a
sensor that was off, degraded, or dropping at decision time. An honest
kernel that lost a sensor mid-decision is indistinguishable in the log
from one that did not.

**Lean shape.** Add to `PredicateLang.lean` a `SensorAttestation`
structure with fields `providers`, `degradedSet`, `droppedEvents`,
`deadlineMisses`, plus new `AtomTag` constructors `sensorAttested`,
`sensorDegradedAbsent`, `dropCountAtMost`. The receipt-level admission
test mechanically enforces these through the existing
`containsPredicate_implies_satisfied` bridge.

**New paragraph (§3, Receipts).** Receipts also bind the kernel's
sensing posture: which providers were active, which were degraded,
which dropped events at the captured timestamp. The binding makes
silent-sensor degradation a constitutional event rather than an
operator-side log gap. A constitution may name minimum sensor coverage
as a non-amendable predicate.

**Theorem that becomes statable.** *Receipts admitted under a
sensor-attesting constitution are jointly auditable as decisions and
as sensing postures.* The hostile-sensor-loss scenario reduces to a
constitutional-ratchet step already governed by V4 and V5.

**Overclaim risk.** A reviewer notes the attestation is self-reported
by the same kernel that controls the decision; if it lies, no theorem
catches it. Honest answer: this is a strict strengthening because
previously the hostile kernel did not have to lie at all. The receipt
now carries a falsifiable signed statement, which is the precondition
for any out-of-band sensor-coverage auditor to disagree with it.

### 2. Causal-graph receipt history

**What chio is missing.** §4 trace semantics gives `\sigma` as a linear
sequence `<(r_0,E_0,d_0), ..., (r_n,E_n,d_n)>`. The only relation
between receipts is index order. A polity cannot locally name "the
receipt that authorised the receipt that wrote the file the next
receipt deleted" without an external query layer.

**Lean shape.** A new file `formal/lean4/Chio/Chio/Treaty/CausalHistory.lean`
with `inductive NodeKind` (host, user, session, agent, workload,
approval, process, file, network, dns, packageScript, credential,
download, extension, policyDecision, tool, deceptionArtifact, other),
`inductive EdgeKind` (spawned, executed, read, wrote, authorizedBy,
madeDecision, temporalNext, touchedHoney, related, and the rest), a
`CausalEdge` structure, and a `CausalHistory` structure of receipts
and edges.

**New paragraph (§4, Trace semantics).** A polity's history is not a
linear sequence of admission decisions but a typed graph: nodes range
over hosts, users, sessions, agents, workloads, processes, files,
network endpoints, credentials, policy decisions, and tool
invocations; edges range over authorisation, spawn, execution, read,
write, decision, and temporal-next. Admission is closed under
reachability.

**Theorem that becomes statable.** `accountability_closure`: *for
every admitted receipt, every receipt reachable via authorisation or
spawn edges is either admitted or carries a denial receipt; there is
no orphan act.*

**Overclaim risk.** A reviewer might say the DAG is a transcription
choice, not a structural property. The defense: promoting `\sigma` to
a DAG forces acyclicity, closure, and authorisation-binding to be
named theorems instead of expository remarks. The "treaty composition
across more than two participants" caveat in §4 partly reduces to "we
have no graph semantics for the history"; this primitive closes that
gap.

### 3. Tripwire predicates

**What chio is missing.** The model is monotone in evidence: more
evidence cannot turn admission into denial unless the constitution
holds a negative predicate. Negative predicates are syntactically
expressible (`neg`) but the model has no notion of an atom whose mere
triggering collapses any chain of capability attenuation to deny,
regardless of how many delegated witnesses claim otherwise.

**Lean shape.** In `PredicateLang.lean`, add an `AtomTag` constructor
`tripwireUntouched (honeyId : String)` and a `TripwireSet` structure
with a monotonic-expansion invariant. The theorem
`tripwire_admission_collapses_attenuation` says: for any capability
chain, if a receipt records a touch of any honey in the set, the chain
cannot admit it.

**New paragraph (§3, Capabilities).** A constitution may declare a set
of tripwire predicates: atoms whose violation collapses any chain of
capability attenuation to denial, independent of which parent
capability the offending receipt claims. The tripwire set expands
monotonically; once a tripwire is named, no amendment may unname it
without the meta-stability discipline in §4. Tripwires are the
syntactic counterpart of facts that are denied by construction rather
than by evaluation.

**Theorem that becomes statable.** *Touching a tripwire is denied by
every refining constitution; no admission lattice can re-admit it.* A
fixed-point property: tripwires sit at the bottom of the admission
lattice as fixed minimal denials under backward-refinement.

**Overclaim risk.** Nothing prevents a constitution from omitting
tripwires; if it does, no theorem applies. True, and that is the
right reading: a tripwire is an *optional* substrate primitive that,
when used, lets a polity prove a collapse-to-deny property.

### 4. The receipt-family taxonomy

**What chio is missing.** §3 treats receipts as singular.
`treaty_admission_iff_predicate_intersection` quantifies over one
abstract receipt. In a real polity, a policy decision is a different
artifact from an evidence-bundle manifest is a different artifact from
a sensor-state attestation is a different artifact from a
response-rollback acknowledgement. The current Predicate ADT cannot
say "this predicate constrains only sensor-state receipts."

**Lean shape.** Add `inductive ReceiptFamily` (seventeen variants:
sensorState, providerDegradation, observation, policyDecision,
policyDelta, graphSlice, detection, simulation, responseRequest,
responseExecution, responseRollback, responseAcknowledgement,
deceptionMaterialization, deceptionCleanup, deceptionRotation,
evidenceBundleManifest, privacyReport) and a `FamilyPredicate`
structure pairing a family tag with a `Predicate`. `admitsByFamily`
projects the predicate list onto the requested family.

**New paragraph (§3, Receipts).** Receipts are typed. A constitution
decomposes into per-family predicates, and admission of a receipt
depends only on its family's predicates. Sensor-state attestations,
policy deltas, graph slices, response executions, response rollbacks,
response acknowledgements, deception materialisations, and privacy
reports are each their own kind. The audit surface is the typed family
roster rather than a single flat predicate list.

**Theorem that becomes statable.** `family_separation`: *for
constitution `c`, family `F`, and receipt `r` of family `F`, the
admission of `r` is decided by the projection of `c.predicates` onto
`F` alone.*

**Overclaim risk.** A reviewer might say this is bookkeeping. Today's
model has no way to express "sensor-state predicates do not constrain
evidence-bundle receipts"; the family-separation theorem names that
constraint as structural. It is the same expressive shape as
ladder-floor stability.

### 5. Bounded executive action with mandatory TTL and rollback

**What chio is missing.** §4 amendments have a refinement obligation;
the runtime admission decision has a denial obligation. Neither
describes the *positive* response side: when an admitted constitution
authorises an enforcement act, the act must have a finite lifetime, a
rollback executor, and an acknowledgement receipt. The paper has no
theorem about response acts at all. The asymmetry is the most
pointed gap in §4: the input side of constitutional change is
mechanised, the output side is asserted.

**Lean shape.** A new file
`formal/lean4/Chio/Chio/Treaty/ExecutiveAction.lean` with a
`BoundedAction` structure (`actionId`, `ttlSeconds`, `rollbackRef`,
`ackReceipt`, `ttlPositive : ttlSeconds > 0`, plus typed rollbackRef
referencing a ResponseRollback-family receipt). An `enactAction`
constructor cannot type-check without these witnesses.

**New paragraph (§3, Trust ladder).** Receipt-backed and above modes
authorise bounded executive actions: every authorised act carries a
positive TTL, a rollback executor reference, and an acknowledgement
obligation that lands inside the same polity's history. An unbounded
act is not constructible.

**Theorem that becomes statable.**
`bounded_executive_action_safety_requires_ttl_and_rollback`: *every
admitted enforcement action terminates within its declared TTL or
carries a rollback receipt closing it.* This is the runtime-side
counterpart of the amendment lifecycle.

**Overclaim risk.** A reviewer would say TTL is a runtime
configuration parameter, not a theorem subject. The defense: the
amendment side already has the same shape (`ConstitutionalDelta`
carries `proofTerm`); promoting `BoundedAction` to a structure that
*cannot be constructed* without a TTL and rollback puts the response
side at the same type-level discipline.

### 6. Privacy-mode lattice and per-field redaction class

**What chio is missing.** §3 describes BBS selective disclosure as a
per-statement projection. The model names neither a per-field
disclosure policy nor a lattice of disclosure modes.

**Lean shape.** Add `inductive RedactionClass` (hashOnly, metadataOnly,
redacted, rawArtifactPermitted, localOnly) and `inductive PrivacyMode`
(localOnly, hashesFeatures, summaryWithReceipts, rawArtifactPermitted)
with a rank function. `redactionClassPermitted` decides whether a
field's class is admissible at the given mode.

**New paragraph (§3, Selective disclosure).** Disclosure is
two-layered. Each evidence field carries a redaction class: hash-only,
metadata-only, redacted, raw-artifact-permitted, or local-only. The
polity sets a privacy mode ordered by rank; the mode is a structural
floor on which field classes the BBS projection may include. The
projection is verifier-checkable as a total function of the field
roster and the mode; no free-form redaction is admissible.

**Theorem that becomes statable.** `projection_minimality`: *the BBS
projection at mode `m` includes exactly the fields whose redaction
class is permitted under `m`; no more, no less.* Composability under
boundary hops follows by rank monotonicity.

**Overclaim risk.** A reviewer notes that BBS already enforces field
minimality cryptographically. True, but the lattice gives a
*policy-side* statement that today is informal: the polity names its
privacy-mode floor in the constitution, and a foreign verifier
admitting at a lower mode becomes a constitutional event.

### 7. Empirical-replay obligation alongside syntactic refinement

**What chio is missing.** `amendment_admissible_iff_backward_refinement`
discharges the syntactic obligation. It says nothing about the
empirical question: which already-admitted historical receipts the
new constitution now denies, and which causal subgraphs lose admitted
ancestors. A constitution that refines purely syntactically may still
drop substantial real history without naming what fell out.

**Lean shape.** In `PredicateLang.lean`, add `replayImpact (kPrev
kNext : SyntacticConstitution) (history : List ReceiptId) : List
ReceiptId × List ReceiptId` returning the pair (still-admitted,
now-denied). A new theorem
`refinement_implies_empty_admit_widening` connects syntactic
refinement to per-receipt impact lists.

**New paragraph (§4, Amendments).** Backward refinement is a syntactic
obligation: it asks whether every receipt the new constitution admits
is also admitted by the old. The empirical counterpart asks which
already-admitted receipts the new constitution now denies, and which
causal subgraphs lose admitted ancestors as a result. The two
obligations compose: refinement guarantees no widening, replay
produces an audit trail of intentional narrowing named per receipt.

**Theorem that becomes statable.**
`amendment_admissible_under_named_history`: *an amendment is
admissible iff it satisfies both backward refinement and an empirical
replay obligation that names which receipts in the declared history
window are now denied.*

**Overclaim risk.** A reviewer would say replay is engineering, not
theory. The defense: the replay theorem is not about *running* the
simulation; it is about the *shape of the discharge*. The proof tree
for an amendment then has two components: a refinement witness and an
impact-report witness, both receipt-bound.

---

## What chio loses if it does not steal these

A hostile reviewer would sustain four complaints against the current
paper:

1. **The threat model is sensor-blind.** §4's adversary controls the
   agent, malforms arguments, replays treaties. The adversary cannot
   turn off the kernel's sensors mid-decision and have receipts look
   identical. Without SensorState, the model has no language for the
   distinction.

2. **The history is suspiciously linear.** §4's trace `\sigma` is a
   sequence. Real polities have causal relations between admitted
   acts. The "Conflict semantics" limitation partly admits this; the
   causal-graph primitive lets the model say *what* is reachable from
   any admitted authorisation edge.

3. **The amendment cycle is half-modelled.** Refinement is the
   guarantee on the input side. There is no theorem on the output
   side about the bounded acts a constitution authorises. The
   bounded-executive-action structure makes the wrap a type-level
   invariant rather than an asserted operational discipline.

4. **Selective disclosure is one-dimensional.** The §3 paragraph
   describes BBS as a per-statement projection. The redaction-class
   plus privacy-mode lattice gives a per-field policy with a
   verifiable rank-floor.

Tripwires, family taxonomy, and empirical replay are expressive
strengthenings rather than gap-closures; without them the paper is
not less correct, but the proof inventory has fewer named properties
for an auditor to point to.

## What the steal looks like at the Lean level

`PredicateLang.lean` gains four extensions:

- New `AtomTag` constructors: `sensorAttested`,
  `sensorDegradedAbsent`, `dropCountAtMost`, `tripwireUntouched`,
  plus `redactionClassPermitted`.
- New `ReceiptFamily` enum and a parameterised `FamilyPredicate`
  structure with a `family_separation` theorem.
- New `PrivacyMode` and `RedactionClass` enums with rank ordering and
  a `projection_minimality` theorem.
- A `replayImpact` function and the
  `refinement_implies_empty_admit_widening` theorem.

Two new files land in `formal/lean4/Chio/Chio/Treaty/`:

- `CausalHistory.lean`: `NodeKind`, `EdgeKind`, `CausalEdge`,
  `CausalHistory`, and the `accountability_closure` theorem.
- `ExecutiveAction.lean`: the `BoundedAction` structure with type-level
  TTL-and-rollback invariants and the
  `bounded_executive_action_safety` theorem.

`Intersection.lean` is left unchanged; the four existing theorems are
unaffected.

## What the steal looks like at the paper level

§3 (Substrate) gains paragraphs on sensor-state attestation,
tripwires, and the privacy-mode lattice. The trust-ladder paragraph
gains a sentence on receipt-backed-and-above authorising bounded
executive actions.

§4 (Model) gains a typed-history paragraph, a bounded-executive-action
paragraph, and an empirical-replay paragraph.

§9 retires or rewrites four limitation bullets. "Override authority
for false negatives" is partly absorbed by bounded executive action;
"Operational observability" is partly absorbed by sensor-state
attestation; "Conflict semantics" gains a graph-level statement; the
downstream "Trajectory invariants for amendment" obligation named in
§4 is partly discharged by the empirical-replay theorem.

The assumption ledger gains one row: *receipts carry truthful
sensor-state attestations*, residual risk: *a kernel that lies about
its own sensors collapses sensor-state to one-of-one trust,
recoverable only by out-of-band sensor coverage audit.* Two rows may
be removed: the implicit "receipts are sequential" assumption
(replaced by the typed graph) and "response acts are wrapped in TTL by
operational discipline" (replaced by
`bounded_executive_action_safety`).

## The single highest-leverage steal

**Concept 5: bounded executive action with type-level TTL and
rollback.**

The amendment side of the admission cycle is type-conditioned:
`enactAmendment` requires a `ConstitutionalDelta` carrying a
refinement witness. The response side is informally constrained: §3
says destructive actions require receipt-backed mode and above, but no
Lean structure enforces that an authorised act carries a TTL or a
rollback receipt. The asymmetry is the most pointed gap in §4's model:
the input side of constitutional change is mechanised, the output
side is asserted.

Lifting `BoundedAction` into the Lean model closes the asymmetry.
`bounded_executive_action_safety_requires_ttl_and_rollback` becomes
the response-side counterpart of
`amendment_admissible_iff_backward_refinement`: both are type-level
invariants on the constructors of admission acts. The paper gains a
single named claim - "every admitted enforcement terminates within
its TTL or carries a rollback receipt" - that closes a structural
hole rather than adding expressive vocabulary.

Of the seven concepts, this is the only one where the gap is *named
by the current paper itself*: §9 lists "override authority for false
negatives" and "operational observability" as limits, both downstream
of the missing response-side type discipline. Closing this gap
retires limitations in addition to adding theorems, which is the
highest-leverage shape a single primitive can take.
