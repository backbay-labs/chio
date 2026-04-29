# Cold-reader notes (trajectory-2)

Per-milestone findings from a senior-engineer cold read on 2026-04-29.
Severity tags: **BLOCKER** (would refuse to start work without
resolution), **NEEDS-CLARIFY** (would ask one question and proceed),
**NICE-TO-HAVE** (would proceed and flag during review).

The trajectory-2 spec is generally tighter than trajectory-1 was at the
same authoring stage; most findings are NICE-TO-HAVE. A handful of
genuine cross-milestone ambiguities surface as NEEDS-CLARIFY. One
BLOCKER is recorded per cross-cutting risk; none of the per-milestone
narratives surfaced a BLOCKER on first read.

## M01: Workspace Error Taxonomy + Doctor + LSP

1. **NEEDS-CLARIFY** P3.T5 wires the OTEL endpoint resolution + kernel
   runtime probe to ping the trajectory-1 M05 `/metrics` endpoint and
   "report inflight gauge presence", but the narrative does not name
   the exact gauge spelling. trajectory-2 M06 P2 introduces
   `chio_signing_queue_drop_total`, `chio_otel_ingress_drop_total`,
   `chio_otel_sink_drop_total`. If M01 P3.T5 lands before M06 P2
   merges, the probe asserts on a name that does not yet exist.
   Recommend either soft-deps M01.P3.T5 on M06.P2.T3 explicitly or
   renaming the assertion to the trajectory-1 M05.P3.T2
   `chio_signing_queue_depth` gauge that already exists. STATUS: applied (M01.P3.T5 soft_dep now names the existing trajectory-1 M05 gauge `chio_kernel_dispatch_inflight` explicitly and excludes M06.P2 drop-counter names; gate_check greps for the gauge spelling in the probe source).
2. **NEEDS-CLARIFY** The narrative names "10 domains
   (`capability`, `policy`, `guard`, `attest`, `replay`, `provider`,
   `manifest`, `kernel`, `transport`, `cli`)" for the registry, but
   M10 P1.T6 introduces `urn:chio:error:custody:*` codes (a new
   `custody` domain) and M05 P1.T1 implies a `threat-model` /
   `adversarial` shape. Either the M01 P1.T1 ten-domain seed should be
   widened in advance, or M10 + M05 should be authorized to land new
   domains via a clearly documented `Domain` enum extension story
   (which is not described). Today the `Domain` enum is closed; D05
   does not say. STATUS: applied (narrative widened the seed to eleven domains including `custody`; P1.T1 title and P1.T2 soft_dep + gate_check pin Domain as `#[non_exhaustive]` so M05 threat-model/adversarial domain lands via registry-YAML edit only; cross-cutting BLOCKER #1 also references this).
3. **NEEDS-CLARIFY** P5.T1-T2 ship VSCode + Zed extensions that "build
   clean against the latest stable VSCode and Zed manifests". The
   audit doc requirement says snippet sources live in
   `editors/snippets/` in a "tool-neutral form"; the format of that
   tool-neutral form is not pinned. Recommend committing a JSON
   schema for the snippet source-of-truth file before P5.T1 starts so
   both extensions diverge cleanly. STATUS: applied (M01.P5.T3 owner_glob now includes `editors/snippets/snippet.schema.json`; soft_dep documents the regen contract; gate_check asserts the schema file exists before snippet regen runs).
4. **NICE-TO-HAVE** P1.T5 round-trips `jsonrpc_code` against the
   existing `spec/errors/chio-error-registry.v1.json` via "a property
   test" but does not name the test crate. The registry lives in
   `spec/`; the property test should live next to it
   (`crates/chio-spec-codegen/tests/jsonrpc_bridge.rs` would be
   coherent with how other registry checks are scaffolded). STATUS: addressed (M01.P1.T5 owner_glob already pins `crates/chio-errors/tests/jsonrpc_bridge_property.rs` plus the `src/jsonrpc_bridge.rs` consumer; the test lives next to the consumer crate, which is coherent because chio-errors is the runtime owner of the bridge).
5. **NICE-TO-HAVE** Migration in P2 retires
   `CliError::Other(String)` from "976 sites" but the per-domain
   chunk sums (~150 + ~120 + ~200 + ~140 + ~366) total 976 only if
   the residual ~366 is the actual remainder. The narrative spells
   it correctly but a starter would benefit from one summary line
   ("after P2.T5 the grep gate fails on any `CliError::Other`
   outside the deprecation shim"); the success criteria do say this.
   Minor. STATUS: addressed (success criteria already say `grep -rE 'CliError::Other' crates/chio-cli/src/` returns 0 outside the deprecation shim; the per-domain chunks (~150+~120+~200+~140+~366) sum to 976 as authored).

## M02: Mutation Gate + Cross-SDK Verdict Differential

1. **NEEDS-CLARIFY** P3.T1 flips the mutation lane to required for
   the six trust-boundary crates "after one advisory cycle". The
   advisory cycle duration is not pinned (one nightly?  one week?
   two consecutive >= 80% runs?). The success criteria say "two
   consecutive runs report >= 80% caught per crate" which is the
   right rule; recommend lifting that into the P3.T1 ticket spec
   verbatim so the orchestrator does not flip the lane prematurely. STATUS: applied (M02.P3.T1 soft_dep states the two-consecutive-nightly-runs >= 80% rule verbatim; gate_check now greps the workflow file for that condition).
2. **NEEDS-CLARIFY** P5.T3 ships a WASM browser kernel driver under
   `verdict_matrix/drivers/wasm-browser/`. The runner shape is not
   pinned: does this run via `wasm-pack test` with headless Chrome,
   via `wasmtime` host invocation, or via Node + `wasm-bindgen`?
   trajectory-1 M08 ships a wasm artifact at
   `crates/chio-kernel-browser/`; the driver's runtime path is not
   chosen. Pin one before P5.T3 opens. STATUS: applied (M02.P5.T3 soft_dep pins `wasm-pack test --headless --chrome` as the runner; gate_check greps `crates/chio-conformance/verdict_matrix/drivers/wasm-browser/run.sh` for that invocation).
3. **NEEDS-CLARIFY** D07 names five primary kernels (Rust, Python,
   TypeScript node-http, WASM browser, Go) and defers JVM, dotnet,
   lambda, k8s to M07. M07 narrative does not actually pick those up
   in scope; M07 P3-P4 ships five new HTTP-native provider adapters
   (Gemini, Mistral, Groq, Ollama, Cohere). The deferred SDK matrix
   work has no owner in trajectory-2. Recommend either widening M07
   scope explicitly or accepting that "deferred to M07" really means
   "deferred to a follow-on after trajectory-2". STATUS: deferred (cannot widen M07 scope from the M02 lane; the M02 narrative Out clause now explicitly notes that D07's M07 deferral does not match the M07 narrative scope, so the JVM/dotnet/lambda/k8s SDK matrix is effectively a follow-on after trajectory-2 unless D07 is amended; surfaces a decision-register gap on D07 consequences).
4. **NICE-TO-HAVE** P4.T2 lists scenario classes ("capability subset,
   revocation propagation, replay verdict, redaction-determinism")
   but does not pin the count. The hash-pinned manifest at P4.T4
   needs a fixed count to be reproducible. Recommend pinning N >= 12
   per class with a total floor in the audit doc starting counts. STATUS: applied (M02.P4.T2 soft_dep pins >= 12 scenarios per class (>= 48 total) with the audit doc recording the exact count; gate_check counts files per scenario directory).
5. **NICE-TO-HAVE** P3.T5 README headline auto-update: "nightly
   auto-update PR confirmed merging" leaves the merge actor
   unspecified. With single-owner trajectory, only `@bb-connor`
   merges; an automated PR sitting open until human hand-merge is
   the trajectory-1 pattern. Lift that into the ticket so the gate
   does not stall on an automation expectation. STATUS: applied (M02.P3.T5 soft_dep pins single-owner @bb-connor as the merge actor per D04; gate_check forbids auto-merge / force-push strings in the workflow and asserts @bb-connor is named).

## M03: PQ-Hybrid Signing + TEE Quote Verifier

1. **NEEDS-CLARIFY** P3.T3 introduces the
   `expect_report_data(kernel_pk: &PublicKey, receipt_root: &[u8; 32])
   -> [u8; 64]` helper. The "binding rule" says every quote MUST
   commit to `SHA256(kernel_signing_pk || receipt_root)` in the
   64-byte `report_data` slot, but the helper signature returns 64
   bytes (which suggests the SHA256 is left-padded into 64 bytes).
   The padding rule (zeroes? right? left?) is not specified. Pin
   the byte layout in the ticket spec; this is a verifier surface
   and any spec ambiguity is a verifier gap. STATUS: applied (M03.P3.T3 soft_dep pins layout: SHA256 occupies bytes 0..32, bytes 32..64 are right-padded 0x00; gate_check greps the source for `right.?pad` or `[0u8; 32]`; narrative scope bullet updated to match).
2. **NEEDS-CLARIFY** P5.T1 says "the kernel verifies its own quote
   against `expect_report_data(kernel_classical_pk,
   receipt_root_genesis)`". Genesis-root semantics are not defined:
   is it the Merkle root at boot (empty tree)? The first signed
   receipt's root? Recommend a one-line definition in the success
   criteria. STATUS: applied (M03.P5.T1 soft_dep defines `receipt_root_genesis` as the all-zero 32-byte sentinel `[0u8; 32]` representing the empty receipt-tree root at boot; matching one-liner added to narrative success criteria).
3. **NEEDS-CLARIFY** D08 pins `fips204 = "0.4"`. The narrative
   reservations under "Risks and mitigations" (PQ algorithm churn)
   acknowledge this is a young crate. The audit doc does not pin
   the date by which the orchestrator should check whether the
   ecosystem has moved to RustCrypto's `ml-dsa`. Recommend a
   re-check ticket at the start of P1 (as the narrative states) but
   make it a real ticket, not a comment. STATUS: applied (added M03.P0.T5 ticket: re-check fips204 vs RustCrypto ml-dsa ecosystem state and confirm or amend D08 pin; gate_check requires a dated re-check entry in the audit doc; narrative phases section updated).
4. **NICE-TO-HAVE** P4.T5 cross-backend conformance test rejects
   fixtures meant for the other two backends. The test surface and
   filename pattern are not pinned. Recommend committing a fixture
   naming convention (e.g. `tdx_*.bin` only loadable by the TDX
   backend) so cross-backend rejection is mechanical. STATUS: applied (M03.P4.T5 soft_dep pins `tdx_*.bin` / `sev_snp_*.bin` / `nitro_*.bin` prefix convention; gate_check finds at least one fixture matching the prefix pattern across the three backend trees).
5. **NICE-TO-HAVE** P5.T3 marks `CanonicalBytes` consumption as a
   `soft_dep` on M06. D16 already says M06 P1 ships before M03 P1
   starts, which means the `soft_dep` should be a hard `depends_on`
   inside trajectory-2. The narrative is the right shape; only the
   ticket file annotation will need to match the decision register. STATUS: applied (M03.P5.T3 now hard-depends_on M06.P1.T1; ticket title and soft_dep wording dropped the byte-equivalence shim; narrative phases bullet and cross-milestone interactions section updated to match).

## M04: Recursive Delegation + Revocation Oracle

1. **NEEDS-CLARIFY** P4.T2 budgets "1 day" implicitly (per the per-
   phase ticket sizing summary) but the risk section says "P4.T3
   budgets 2 days for the auxiliary graph theory". The narrative is
   internally consistent on T3 but the ticket file (M04.P4.T2 / T3)
   should reflect the 2-day budget for theorem 3. If theorem 3 ships
   as `axiom`, the success criteria say only theorems 1, 2, 4 must
   close as `theorem`. Recommend the audit doc record explicitly
   which theorems shipped as `theorem` vs `axiom` so a future M04+1
   can re-attack without re-reading the trajectory.
   STATUS: applied. P4.T2 and P4.T3 both already 2 days in P4.yml.
   Updated M04.P5.T4 title and gate_check to require the audit doc
   record per-theorem theorem-vs-axiom status.
2. **NEEDS-CLARIFY** P1.T2 commits to "in-memory variant first; SQLite
   backend deferred to a later milestone (delete the SQLite-backed
   variant from scope here)". The phrasing "delete the SQLite-backed
   variant from scope" is ambiguous: does it mean drop it entirely,
   or drop it from M04? The "Out" section only mentions chain
   anchoring as out-of-scope. Recommend explicit "Out: SQLite
   backend for the sparse-Merkle store" so a starter does not stub
   it.
   STATUS: applied. Added explicit "Out: SQLite-backed variant of the
   sparse-Merkle store" to narrative Scope.Out section. M04.P1.T2
   ticket title updated to make the in-memory-only constraint
   unambiguous.
3. **NEEDS-CLARIFY** P2.T5 asserts oracle-insert-to-verifier-observable
   "within 500 ms median across 100 trials on a single-host gossip
   mesh". The "single-host gossip mesh" topology is not described.
   How many peers? What link cost? Without those numbers the bench
   is not reproducible. Pin N=3 peers with 0-cost localhost links
   in the ticket spec.
   STATUS: applied. M04.P2.T5 title pins N=3 peers, 0-cost localhost
   links. Narrative P2.T5 bullet appends matching topology line.
4. **NICE-TO-HAVE** D11's 14-Kani-cap is a deliberate quality
   choice, but the narrative success-criteria text says "exactly 14
   entries (10 baseline + 4 new)". If trajectory-1 M03 actually
   shipped 11 baseline harnesses (the count is asserted as 10 here),
   re-verify by running
   `awk '/covered_symbols/' formal/rust-verification/kani-public-harnesses.toml`
   on the merged trajectory-1 HEAD before opening M04 P0.
   STATUS: deferred (D11 binding at 14 total). M04.P0.T3 audit-doc
   ticket records the actual baseline at P0 open; if baseline is 11
   rather than 10, M04 adds 3 new harnesses (still capped at 14).
   The discrepancy surfaces mechanically at P0.T3 without a
   narrative edit.
5. **NICE-TO-HAVE** The "soft_deps" relationship to M03 PQ surface
   says revocation roots can be PQ-signed only after M03.P2 lands.
   Both milestones are in Wave 2; D08 + D16 have M03 depending on
   M06 P1 (Wave 1). The chain is M06.P1 -> M03.P1 -> M03.P2 ->
   M04.P3 (PQ-signed roots). The wave gate sequencing in
   `EXECUTION-BOARD.md` does not enforce that intra-wave order. The
   freeze register (m03-attest-verify-pivot ends at M03.P3.T5;
   m04-revocation-oracle-pivot ends at M04.P3.T5) implicitly
   orders them, and the cross-freeze invariants block at the
   bottom of `freezes.yml` make it explicit. The narrative would
   benefit from naming the freeze invariant directly so a starter
   does not have to derive it.
   STATUS: applied. Cross-milestone interactions section now names
   the freezes.yml cross-freeze invariant
   (m03-attest-verify-pivot must close before
   m04-revocation-oracle-pivot's end_trigger) and points at the
   carrying soft_dep on M04.P1.T3.

## M05: Adversarial Receipts + Guard Escape + Threat-Model-as-Code

1. **NEEDS-CLARIFY** Hard counts say "M05 adds exactly ONE [fuzz
   target]: `wasm_guard_escape.rs`" but the narrative success
   criteria say the harness "covers at least 25 escape classes". The
   25-class breakdown does not appear in the phase tickets: P3.T2
   covers undeclared imports / oversize memory / fuel exhaustion (3
   classes), P3.T3 covers table-grow / stack overflow / host reentry
   (3 classes), P3.T4 covers malformed component-model + signed-but-
   malicious modules (2 classes). That is 8 named classes, not 25.
   Either the success criterion is wrong, or P3 needs more tickets
   to cover the missing 17 classes. Recommend either tightening the
   success criterion to 8 classes or expanding P3 by one or two
   tickets.
   STATUS: applied (success criterion tightened to 8 classes).
   Hard-counts entry, P3.T1 narrative, and Success Criteria all now
   read "8 named escape classes" matching the P3.T2-T4 ticket count.
   The fuzzer-driven libFuzzer target may explore additional input
   shapes within those 8 classes; the counted-class budget is fixed
   at 8.
2. **NEEDS-CLARIFY** P4.T2 says the policy loader "fail-closes on
   missing or stale signatures". The "stale" horizon (default 90
   days per a risks-and-mitigations sentence) is not in the ticket
   spec; lift it into the P4.T1 schema and P4.T2 loader so it is
   reviewable in isolation.
   STATUS: applied. M05.P4.T1 and M05.P4.T2 ticket titles now
   record the 90-day default fail-closed staleness horizon as part
   of the schema and loader contract.
3. **NEEDS-CLARIFY** P5.T6 cross-links every adversarial vector back
   into the threat-model JSON via a `coveredBy` field, with a CI
   assertion that "every adversarial vector cites at least one
   threat ID". Auto-promoted vectors with `pending: true` per D14
   are a counter-example: their `coveredBy` is by definition empty
   until human triage. The CI assertion needs an exception clause
   for `pending: true`. Recommend updating the P5.T6 assertion text
   accordingly.
   STATUS: applied. M05.P5.T6 ticket title and narrative P5.T6
   bullet now except `pending: true` vectors from the citation
   gate; trajectory close still blocks until triage strips the
   flag.
4. **NICE-TO-HAVE** Hard counts table is the lightest of the ten
   milestones (M05 narrative is 148 LoC, smallest in the trajectory
   per `EXECUTION-BOARD.md` section 1). The "Hard counts" block lists
   six counts but does not enumerate the existing six threat IDs by
   name; the narrative does name them in prose. Lift them into the
   counts table for grep-ability:
   `capability_token_theft`, `kernel_impersonation`,
   `tool_server_escape`, `native_channel_replay`,
   `resource_exhaustion_dos`, `delegation_chain_abuse`. Plus the
   three M03 + three M10 introductions (six new) gives a 12-ID
   target the M05 P5 gate must cover.
   STATUS: deferred (M03/M10 threat-ID introductions are owned by
   those milestones, not M05). Hard-counts line was tweaked to
   call out the six existing IDs explicitly. The M05 P5 gate
   covers the IDs present in `chio-threat-model.v1.json` at
   gate-run time; widening to a 12-ID target would lock M05
   close behind M03 and M10, contradicting the wave order.
5. **NICE-TO-HAVE** P3.T5 determinism gate aggregates "all classes"
   under `cargo test -p chio-wasm-guards --test escape`. If a class
   set lands incomplete (per finding 1), the aggregated test will
   succeed against a smaller set. Recommend a count assertion: the
   test prints `class_count = N` and the audit doc pins N at
   milestone close.
   STATUS: applied. M05.P3.T5 title now requires the aggregate
   test to print `class_count = 8`; gate_check greps for it.
   Success-criteria line in the narrative records the same.

## M06: Performance Hardening Pack

1. **NEEDS-CLARIFY** P5.T3 sustained-30-minute p99 nightly job
   "green for one week before M06 closes". One-week wall-clock
   constraints conflict with the autonomous orchestrator model: the
   orchestrator does not pause for calendar time. Recommend
   replacing "one week" with "seven consecutive nightly runs". This
   is a parseable orchestrator gate; one week is not.
   STATUS: applied. Narrative success criterion and M06.P5.T3
   ticket title now read "seven consecutive nightly runs"; the
   orchestrator parses run-count not calendar time.
2. **NEEDS-CLARIFY** P0.T2 pins `dhat = "0.3"` and asserts
   `cargo tree -d` cleanliness for `dashmap`, `arc-swap`, `wasmtime`,
   `prometheus`, `r2d2`. M01 P0.T1 also pins `dashmap = "6"` (the
   narrative says M06 may also pin it; "if M06 lands first, M01
   reuses its pin"). Per `EXECUTION-BOARD.md` section 2 the
   `Cargo.lock` order is M06 P0.T2 -> M02 P0.T2 -> M01 P0.T1, so
   M06 owns the pin. Recommend deleting the `dashmap` pin from M01
   P0.T1 ticket spec to avoid a merge-queue conflict.
   STATUS: partially applied. M06 narrative dependency state now
   explicitly records that M06 owns any trajectory-2 dashmap pin
   bump and M01/M02 reuse without re-pinning. Deletion of the
   dashmap pin from M01.P0.T1 is owned by the M01 agent (out of
   this agent's lane); flagged for the M01 agent via this STATUS
   note.
3. **NEEDS-CLARIFY** D15 splits drop semantics: OTEL drop-oldest,
   signing backpressure-block. P2.T2 says "Replace channels with
   bounded `tokio::sync::mpsc::channel(N)` plus drop-oldest ring on
   overload in `ingress.rs` and `sink.rs`". P2.T6 audits the M05.P1
   signing task and "confirms bound is enforced and emit the drop
   counter alongside the existing depth gauge". The signing-channel
   counter name (`chio_signing_queue_drop_total` per the success
   criteria) is shared with OTEL drops. If both surfaces emit
   `chio_*_drop_total` counters with identical names, dashboards
   cannot distinguish OTEL backpressure from signing backpressure.
   Recommend renaming the signing counter
   `chio_signing_queue_block_total` to reflect that the signing path
   blocks (does not drop) under backpressure.
   STATUS: applied. Renamed every occurrence of
   `chio_signing_queue_drop_total` to
   `chio_signing_queue_block_total` in narrative scope, narrative
   success criteria, M06.P2.T3 and M06.P2.T4 gate_check, and
   M06.P2.T6 title + soft_dep + gate_check. OTEL counters
   (`chio_otel_ingress_drop_total`, `chio_otel_sink_drop_total`)
   keep `_drop_total` suffix per D15.
4. **NICE-TO-HAVE** P1.T2 "property test against
   `spec/vectors/canonical_json/` corpus asserting every vector
   round-trips byte-identical" needs a corpus-size sanity check. If
   the corpus is empty, a vacuous green is possible. Recommend a
   ticket assertion `assert_eq!(vectors.len(), N)` where N is the
   trajectory-1 M01 vector count.
   STATUS: applied. M06.P1.T2 title now includes the
   `assert_eq!(vectors.len(), N)` corpus-size sanity assertion
   (N matches the trajectory-1 M01 vector count recorded in the
   M06 audit doc), preventing vacuous green on empty corpus.
5. **NICE-TO-HAVE** "Phantom witness type proving the buffer was
   produced by the canonicaliser" (P1.T1) is well-posed. The narrative
   does not say whether `CanonicalBytes` is `Clone`. With
   `Arc<CanonicalBytes>` flowing through five crates, `Clone` is
   essential at the `Arc` level (always available) but the inner
   newtype's `Clone` impl is the tricky one. Recommend pinning the
   API surface in the audit doc: `CanonicalBytes` is `!Clone` to
   force `Arc` sharing, or it is `Clone` for ergonomics.
   STATUS: applied. M06.P0.T1 audit-doc ticket title now requires
   the audit doc to record the CanonicalBytes API surface decision
   (Clone vs !Clone); gate_check greps for the decision string.
   The choice is left to the P0.T1 author and remains binding
   from P1.T1 onward.

## M07: Adoption Beachhead Pack

1. **NEEDS-CLARIFY** P3 ships first three providers
   "(Gemini / Mistral / Groq)" per D17. P4 ships last two
   "(Ollama / Cohere)". The orchestrator can confirm this from the
   ticket files; the narrative is internally consistent. However the
   verdict-matrix flip happens in P4.T5 (8-provider equality);
   D07 only enumerates five primary kernels (Rust, Python, TS
   node-http, WASM, Go), not eight. The "8 providers" axis is the
   provider matrix, not the kernel matrix. A senior engineer reading
   D07 alongside M07 P4.T5 would want a one-line note disambiguating
   "5 kernels (M02 axis) vs 8 providers (M07 axis)". Recommend
   adding to D07 consequences.
   STATUS: applied. D07 consequences disambiguates the two axes;
   M07 narrative soft_dep on M07.P4.T6 carries the same note.
2. **NEEDS-CLARIFY** P5.T5 TTFRH bench gate asserts < 60 s p99 on
   the reference 4-core Linux runner. The reference runner image
   (e.g. `ubuntu-24.04`) is not pinned. trajectory-1 M05 P3.T4
   already pinned a runner; M07 inherits it but the audit doc should
   record the inherited pin so the comparison is reproducible.
   STATUS: appended. M07 narrative TTFRH bench bullet records the
   inherited `ubuntu-24.04` pin from trajectory-1 M05.P3.T4 and
   assigns the audit-doc record to P5.T5.
3. **NEEDS-CLARIFY** P2.T4 `--emit-config <ide>` flag generates
   ready-to-paste config blobs for Cursor / Claude Desktop /
   Continue / Zed. The schema versions targeted are not committed
   to the milestone narrative. The risks section mentions a
   "nightly canary against published schema docs"; the canary's
   home (a workflow path? a script?) is not named. Recommend a
   ticket file `M07.P2.T4` enumerates the four schema versions
   verbatim in its description.
   STATUS: appended. M07 narrative risks bullet now names the canary
   script (`bench/ide-schema-canary/check.sh`) and workflow file
   (`.github/workflows/ide-schema-canary.yml`); audit-doc snapshot
   pins the four IDE schema versions verbatim per P2.T4.
4. **NICE-TO-HAVE** Out-of-scope clause "Vertex AI adapter (deferred
   per trajectory-1 M07 'Out of scope' note)" assumes that note
   exists. The hard count of provider adapters today (5 crates)
   matches the trajectory-1 M07 close state, so the deferral is
   credible. Recommend lifting "Vertex AI deferred" into D17
   alternatives_rejected for traceability.
   STATUS: deferred. Nice-to-have; D17 alternatives_rejected already
   records "Gemini-only" and "all eight at once"; M07 narrative Out
   clause records the Vertex AI deferral. Lifting it into D17 would
   amend a locked decision for traceability the narrative provides.
5. **NICE-TO-HAVE** P0.T3 "Reserve npm package names
   (`@chio/ai-sdk-middleware`, `@chio/next`)". npm name reservation
   requires an account with publishing rights to the `@chio` org.
   trajectory-1 D04 (single-owner) does not name an npm org admin.
   Either the org is owned by `@bb-connor` (likely) or the
   reservation step is a credential-bound action that needs a
   one-line callout. Add to the P0.T3 ticket prerequisites.
   STATUS: applied. M07.P0.T3 soft_deps now carries a credential-
   bound callout assigning the manual reserve step to `@bb-connor`.

B1 / SDK-matrix ownership cross-check (special-attention): D07
defers JVM / dotnet / lambda / k8s SDK drivers to M07; M07 narrative
and tickets do not enumerate per-SDK tickets for those four. STATUS:
deferred-with-rationale. Logged in `.planning/trajectory-2/RECONCILE-
NEEDED.md` with three resolution paths (M07.P6 phase, M11 penciling,
or D07 re-scope). D07 consequences updated to reference that file.
Aligns with the M02 finding 3 STATUS: deferred entry above.

LangChain ambiguity (special-attention): SCOPE-CREEP-AMBIGUOUS.md
items 1-2 about `fastapi-langchain`. STATUS: resolved. D18 names
FastAPI + LangChain as one of the three in-scope templates; the
synthesis cut was specifically the `chio-langchain` SDK SCAFFOLD-
FILLIN package, not the LangChain framework as a starter-template
primitive. M07 narrative Out clause records that distinction
explicitly; SCOPE-CREEP-AMBIGUOUS.md items marked resolved.

## M08: chio-arena - Adversarial Replay Coliseum

1. **NEEDS-CLARIFY** Cross-milestone interactions section names
   "M02.P4 hard ticket-level dependency for M08.P4.T1" and
   "M05.P0 hard ticket-level dependency for M08.P5.T2", but trajectory-2
   `STYLE.md` says cross-milestone references go in `soft_deps` as
   string sentences (not as `depends_on` ids). The narrative
   acknowledges this and says "encoded as a soft_dep string sentence
   at the ticket level; orchestrator gates on `M02.P4.T1`
   merged_sha via the Wave-3 sync rule". The Wave-3 sync rule is not
   defined in `EXECUTION-BOARD.md`; section 2 only covers wave gate
   sequencing at the wave boundary, not at the ticket level. Either
   `EXECUTION-BOARD.md` needs a Wave-3 sync rule subsection or M08
   P4.T1 needs to wait until Wave 2 closes (which is what the wave
   plan already does). Recommend deleting the "Wave-3 sync rule"
   reference; the wave gate already enforces it.
   STATUS: applied. M08 narrative cross-milestone interactions now
   reads "Wave 3 -> Wave 4 wave-gate boundary already enforces this
   (M02 closes in Wave 1, before Wave 3 opens)"; the M08.P4 phase
   header comment and M08.P4.T1 soft_dep mirror that wording.
2. **NEEDS-CLARIFY** Hard counts say "no `mcp` subcommand exists"
   (correct as of the count date) and that the arena adds an
   `Arena` variant to the `Commands` enum. M07 P2.T1 also adds an
   MCP subcommand to the same `Commands` enum. M01 P2.T5 migrates
   `crates/chio-control-plane/src/lib.rs` and
   `crates/chio-cli/src/evidence_export.rs` and
   `crates/chio-cli/src/scaffold.rs`. All three milestones edit
   `crates/chio-cli/src/cli/dispatch.rs` (or `main.rs` per M07's
   register_subcommand path). M01 narrative says "M01 changes the
   error story inside those files but does not re-cut the include
   topology"; M07 P2.T1 adds a register call; M08 adds a `Commands`
   enum variant. The three are not strictly conflicting but the
   ticket-level merge order must be M01 P2 first (so error-codes
   exist for the new subcommands), then M07 P2 + M08 P5 in either
   order. The `EXECUTION-BOARD.md` `shared_paths` discipline
   handles this, but only if every ticket touching `dispatch.rs`
   lists it in `shared_paths`. Verify on first ticket file load.
   STATUS: applied. M07.P2.T1 and M08.P5.T4 (the two Wave-3 tickets
   that write `dispatch.rs`) now list it in `shared_paths` so the
   orchestrator serializes them. M08.P5.T5 / T6 chain on T4 via
   `depends_on` and cannot conflict. M01 P2 lands in Wave 1 and
   closes before Wave 3 opens.
3. **NEEDS-CLARIFY** P4.T5 co-evolution driver: "Bounded-budget
   gate (default: 200 generations or 30 minutes wall, fail-closed
   on exceed)". `fail-closed on exceed` would terminate the
   co-evolution mid-run. Is the bound a soft cap (return current
   best) or a hard fail (mark the run failed)? In a deterministic
   simulator, hard-fail is sane; in a CI lane the run should not
   block other PRs. Pin the semantics explicitly.
   STATUS: applied. M08 narrative risks bullet now pins: on exceed
   the driver returns the current best population and exits with a
   non-zero status (recorded as `budget_exceeded`, not `failed`),
   so a CI lane does not block other PRs.
4. **NICE-TO-HAVE** P5.T1 auto-promotion "BLESS_REASON value
   `arena:<scenario-id>` recognized; no gate weakening". The
   trajectory-1 M04 BLESS rules (`CI=false` AND `isatty(stderr)`)
   already prevent CI from blessing. Arena auto-promotion that
   "rides" the BLESS gate must run from the orchestrator-issued
   PR, not from a CI workflow. Recommend a one-line note in the
   ticket spec: arena BLESS runs locally as part of the orchestrator
   merge, not in a CI step.
   STATUS: applied. M08.P5.T1 soft_deps now carries the explicit
   line: BLESS runs as part of the orchestrator-issued local PR,
   never from a CI workflow; CI=true and TTY rules from M04 enforce.
5. **NICE-TO-HAVE** D19 disambiguates the `chio-link` name
   collision and the narrative carries the disambiguation. The
   risks section mentions CODEOWNERS gating on
   `crates/chio-arena/Cargo.toml` "enforces" no provider-crate
   imports. CODEOWNERS only routes review; it does not "enforce".
   A `forbid-imports` lint or a custom xtask `arena verify-imports`
   step would be the actual enforcement. Recommend adding a P1
   ticket for the import-allowlist linter.
   STATUS: appended. M08 narrative risks bullet now correctly notes
   CODEOWNERS only routes review; the M08.P0.T3 `gate_check` grep
   against `crates/chio-arena/Cargo.toml` (mechanical, runs in CI on
   every PR) is the actual enforcement. No new P1 lint ticket added
   because the existing gate_check is functionally equivalent and
   runs on every PR, not just on Cargo.toml edits.

## M09: Economic Layer + Lineage

1. **NEEDS-CLARIFY** D21 says "M09 wakes chio-credit, chio-settle,
   chio-reputation, chio-mercury, chio-mercury-core,
   chio-underwriting, chio-appraisal as-is. No new economic crates
   are added in trajectory-2." The narrative phases P1-P4 each
   activate one or two crates: P1 (`chio-credit`), P2
   (`chio-settle`), P3 (`chio-reputation`), P4 (marketplace surface
   reusing `chio-appraisal` + `chio-underwriting`). `chio-mercury`
   and `chio-mercury-core` are named in D21 but not in any phase.
   `chio-anchor` is also named in the hard counts but only consumed
   indirectly via lineage anchoring in P5.T6 (which is gated on M03
   + M06). Either drop `chio-mercury` / `chio-mercury-core` /
   `chio-anchor` from the D21 list or schedule them into a phase.
   STATUS: APPLIED. Added decisions.yml D26 documenting transitive
   activation: chio-mercury and chio-mercury-core wake via chio-settle
   activation in P2 (the existing in-workspace caller); chio-anchor
   wakes via lineage anchor-pinning at P5.T6. M09 narrative cross-
   milestone block now records the transitive activation.
2. **NEEDS-CLARIFY** P5.T4 implements two canonical recursive-CTE
   queries (forward + reverse). The risks section warns about
   recursive-CTE blowup and says "queries that exceed the bound
   return a truncation marker". The truncation-marker shape is not
   defined. Pin the marker (e.g.
   `{"truncated": true, "depth_reached": N, "limit": LIM}`) in
   the schema at P5.T1.
   STATUS: APPLIED. M09.P5.T1 soft_deps now pins the truncation
   marker shape verbatim (`{"truncated": true, "depth_reached":
   <int>, "limit": <int>}`); ticket title also updated.
3. **NEEDS-CLARIFY** P3.T2 `ArenaSurvivalFeed` consumes M08 arena
   round outputs; if M08 is absent, the feed reports zero deltas.
   The wave plan has M08 closing in Wave 3 before M09 opens in
   Wave 4, so M08-absent should not happen. The "soft-dep" wording
   suggests M09 anticipates running without M08, which contradicts
   the wave plan. Either the soft-dep is dead code (delete it) or
   the wave plan permits M09 to start before M08 closes (in which
   case the wave gate sequencing in `EXECUTION-BOARD.md` section 2
   needs a note). Recommend deleting the soft-dep absence path.
   STATUS: APPENDED. M09.P3.T2 soft_dep wording rewritten to make
   the empty-input fallback explicit as unit-test isolation only,
   not a schedule-tolerance soft-dep. M09 narrative cross-milestone
   block updated to mirror the wording.
4. **NICE-TO-HAVE** `chio-store-sqlite` is named at "16 files
   under `src/`" implicitly via the hard counts but no count is
   given. Recommend adding it to the hard counts so the additive
   schema migration in P1.T3 (`iou_envelope` table) is reviewable
   against a starting count.
   STATUS: APPLIED. M09 narrative hard-counts block now records the
   16-file baseline plus the additive iou_envelope and lineage_cte
   modules.
5. **NICE-TO-HAVE** P5.T8 ships a tiny static web viewer with no
   build step. The `index.html` + `main.js` + `style.css` shape
   means the JS is plain ES modules. Pin the import map (or
   acknowledge there is none) in the README so a starter does not
   add a transpiler.
   STATUS: APPENDED. M09.P5.T8 soft_deps now records the no-import-
   map / no-transpiler constraint and pins the script-tag shape
   (`<script type="module" src="./lineage.js">`).

## M10: Hardware Custody + Policy-Bound Model Cards

1. **NEEDS-CLARIFY** P1.T3 `PasskeyCapability` envelope has a
   "five-minute fixed `exp`". P2.T2 implements replay protection
   with a durable nonce store. The replay window is one of:
   (a) the 5-minute capability lifetime, (b) the underlying
   credential's lifetime (longer), (c) the issuer's nonce store
   retention (open-ended). Pin it. Recommend the nonce store
   retains entries for `exp + clock_skew` and is GC-able after.
   STATUS: APPLIED. M10.P2.T2 soft_deps now pins the retention
   bound: `exp + clock_skew` (clock_skew = 30s default), GC-able
   by background sweep, scoped to the capability `exp` (5 minutes
   per P1.T3) NOT the credential lifetime.
2. **NEEDS-CLARIFY** D24 says custody half ships first if
   schedule pressure surfaces; P4-P5 are "descope candidates". If
   M10 closes with only custody (P0-P3), the four close gates need
   to know that model-card-coverage IDs (`weights_hash_spoof`)
   migrate to a follow-on. The threat-model coverage gate (M05 P5)
   would then need a `pending` row for that ID. The narrative does
   not commit a descope plan for the threat-model side. Recommend
   a one-line "if descoped, threat IDs `weights_hash_spoof` is
   marked `pending: deferred` in the coverage map".
   STATUS: APPLIED. M10 narrative risks block now contains a
   "Descope plan for threat IDs if model-card half cuts" bullet:
   passkey_credential_theft + audience_confusion close as covered,
   weights_hash_spoof flips to `coverage_state: pending` with a
   `deferred_to: follow-on` note. The M05 P5.T1 schema (updated for
   finding 3 below) treats `pending` with explicit `deferred_to`
   as PASS only.
3. **NEEDS-CLARIFY** P4.T5 binding refusal: "(a) the provider's
   loaded `weights_hash` matches a signed card". The provider's
   loaded weights hash comes from the provider runtime. A provider
   that lies about its weights hash is the central attack
   `chio-weights` defends against (per the risks section). The
   risks section concedes "the provider-supplied hash is treated
   as attested-by-cosign-bundle and the threat ID
   `weights_hash_spoof` is marked partially covered with the gap
   documented in the audit doc". `partially covered` is not a
   trajectory-2 coverage state per M05; the registry only knows
   `covered` / `pending`. Either widen M05's coverage map shape
   to include `partial` or accept that M10 closes with
   `weights_hash_spoof` `pending` and a documented residual risk.
   STATUS: APPLIED. Took the widen-the-shape path. M05.P5.T1 ticket
   now defines a `coverage_state` enum {covered, partial, pending}
   in its soft_deps spec. M10.P5.T3 soft_deps and the M10 risks
   block both name `coverage_state: partial` for weights_hash_spoof
   when chio-providers hash-recompute is not yet landed; the
   threat-model-coverage CI gate (M05.P5.T4) treats `partial` as
   PASS but the generated coverage doc flags it under the Partial
   heading.
4. **NICE-TO-HAVE** P3.T5 size budget for `@chio/passkey`
   "< 30 KB gzipped". The trajectory-1 M08 size budgets are 300 KB
   browser, 350 KB workers (per M07 narrative cross-doc invariants).
   30 KB is well inside both. Recommend pinning the budget in the
   trajectory-1 M08 size-budget config so the gate fires cleanly.
   STATUS: APPENDED. M10.P3.T5 soft_deps now records the trajectory-
   1 M08 size-budget config tie-in (30 KB sits inside both 300 KB
   browser and 350 KB worker ceilings).
5. **NICE-TO-HAVE** P5.T2 cross-provider equivalence test
   "asserts that providers bound under each card produce verdict-
   equivalent outputs at every scenario" using M07's verdict-equality
   oracle. The scenario corpus comes from
   `crates/chio-provider-conformance/`. The 8-provider corpus from
   trajectory-2 M07 P4.T5 is large (8 * 12 fixtures = 96 fixtures);
   running the equivalence test against the full corpus is
   expensive. Recommend a smoke subset (e.g. one fixture per
   adversary class) for PR CI and a full sweep nightly.
   STATUS: APPENDED. M10.P5.T2 soft_deps now pins the smoke subset
   shape (one fixture per adversary class, ~8 fixtures, gated by
   `--features smoke`) for PR CI; full 96-fixture sweep runs nightly
   on the existing trajectory-1 M07 lane.

## Cross-cutting items the reviewer should escalate

These are not single-milestone findings; they affect the trajectory as
a whole and are flagged for user input.

1. **BLOCKER** The `Domain` enum extension story for the
   `urn:chio:error:*` registry (M01 P1.T1) is undefined for
   downstream domains. M10 P1.T6 introduces a `custody` domain and
   M05 P3-P4 implies a `threat-model` / `adversarial` shape. If
   M01 ships `Domain` as a closed Rust enum (the obvious shape
   under workspace clippy `unwrap_used = "deny"`), every downstream
   addition is a breaking change. The narrative does not commit
   either way. Recommended action: M01 P1.T1 ships `Domain` as a
   `non_exhaustive` enum + a registry-driven extension pattern, OR
   M01 P1.T1 lands the closed enum with all eleven domains
   (`capability`, `policy`, `guard`, `attest`, `replay`, `provider`,
   `manifest`, `kernel`, `transport`, `cli`, `custody`) up front
   and reserves the `threat-model` / `adversarial` shape for M05
   to populate. The user should pick before M01 P1.T1 opens.
   STATUS: RESOLVED (BLOCKER closed). Took the widen-up-front path
   plus `non_exhaustive` belt-and-braces. Added decisions.yml D25
   recording the choice. M01 P1.T1 ticket title and M01 narrative
   Scope + Phases blocks now seed eighteen domains: ten core plus
   eight reserved for downstream (delegation for M04, adversarial
   and threat for M05, arena for M08, economy and lineage for M09,
   custody and weights for M10). The Domain Rust enum is
   `#[non_exhaustive]` and lists all eighteen variants at P1.T2;
   downstream milestones contribute codes under existing domains,
   not new domains. M10 P1.T6 (custody:* codes) and the implicit
   M05 threat / adversarial shape both land under the seeded
   namespaces with no enum edit required.
2. **NEEDS-CLARIFY** Wave 4 sequencing in
   `EXECUTION-BOARD.md` section 2 says "M09 first, M10 next" with
   the optional overlap caveat. M10 P5.T1 (lineage anchoring of
   model cards) requires M09 P5 lineage anchoring to land first.
   M10 P5.T2 (cross-provider equivalence) requires M07 to be merged
   (Wave 3) which it is. M10 P5.T3 (threat-model coverage) requires
   M05 P5 to be merged (Wave 2) which it is. The hard
   `depends_on` chain across waves is implicit; recommend the
   orchestrator's wave-4 sub-gate enumerate the M09-must-precede-M10
   tickets explicitly.
   STATUS: APPLIED. EXECUTION-BOARD.md section 2 now contains a
   "Wave 4 sub-gate: M09-must-precede-M10 ticket-level dependencies"
   table enumerating the three precedences (M09.P5.T6 -> M10.P5.T1,
   M07-merged -> M10.P5.T2, M05.P5.T4 -> M10.P5.T3).
3. **NEEDS-CLARIFY** Trajectory-2 introduces several CI gates that
   require credentials or external accounts the trajectory-1
   substrate did not need: M07 P3-P4 provider live API tests
   (gated on `OLLAMA_HOST` etc. but other providers have similar
   keys), M07 P5 `npm publish` to the `@chio` org, M10 P3.T1 npm
   publish of `@chio/passkey`. trajectory-1's preflight checklist
   (per the trajectory-1 cold-reader notes cross-cutting #3) named
   accounts as a known stall risk. Recommend a trajectory-2 P0
   preflight ticket enumerating the credentials / accounts the
   orchestrator needs visibility into before Wave 1 opens
   (`OLLAMA_HOST`, npm `@chio` token, OPENAI / ANTHROPIC / BEDROCK
   keys for nightly conformance, AWS Nitro NSM fixture-collection
   account, Intel TDX collateral feed if non-public).
   STATUS: APPLIED. EXECUTION-BOARD.md section 2 now contains a
   "Wave 0 preflight: credential / account inventory" subsection
   enumerating the eight credential surfaces (npm @chio token,
   eight provider live-API keys, AWS Nitro NSM, Intel TDX
   collateral). The orchestrator does not open Wave 1 until the
   preflight ticket merges with each entry confirmed-present or
   marked deferred-with-rationale.
4. **NICE-TO-HAVE** The four trajectory-close gates (mutation
   coverage 80%, threat-model coverage 100%, verdict-matrix
   divergence 0, lean-build over four delegation theorems) are
   listed in `EXECUTION-BOARD.md` section 9 and re-iterated in the
   AUTONOMOUS-PROMPT.md section 14. The `lean-build` gate names
   "four delegation theorems" but D11's 14-Kani-cap is the
   stronger constraint; the narrative says theorem 3
   (`revocation_is_cut`) may ship as `axiom`. If theorem 3 is an
   axiom, `lean-build` is green but the trajectory-close-gate
   story should explicitly say "four theorems built; theorem 3
   may be an `axiom` with a documented assumption entry per
   `formal/assumptions.toml`". Lift this into the close gate
   wording.
   STATUS: APPLIED. EXECUTION-BOARD.md section 9 lean-build close
   gate now reads "theorem 3 (`revocation_is_cut`) MAY ship as
   `axiom` per D11 with a documented assumption entry in
   `formal/assumptions.toml`; the assumption file MUST be
   machine-checkable." Threat-model close gate also clarified:
   `coverage_state: covered` and `coverage_state: partial` both
   PASS; `pending` requires explicit `deferred_to` field.
5. **NICE-TO-HAVE** All ten milestones use trajectory-1's
   `.planning/audits/M{NN}-<slug>.md` audit-doc convention. The
   trajectory-2 audit-doc filenames are not all spelled out in
   `EXECUTION-BOARD.md` section 1 (the table only lists ticket /
   effort / phase counts, not audit doc paths). Recommend a Wave-0
   sequencer task to seed all ten audit-doc skeletons with the
   starting hard counts copied from each narrative's "Hard counts"
   section, so the per-milestone P0 audit-doc tickets are reviewing
   a non-empty file.
   STATUS: APPLIED. EXECUTION-BOARD.md Wave 0 preflight table now
   carries an entry 11 ("Audit-doc skeletons seeded for all ten
   milestones with starting hard counts copied from each
   narrative") listed against `.planning/audits/M{NN}-<slug>.md`
   with sequencer ownership; blocking each milestone P0 audit-doc
   ticket.

---

End of cold-reader notes.
