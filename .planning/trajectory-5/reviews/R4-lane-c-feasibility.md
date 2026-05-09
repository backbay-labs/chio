# R4 - Lane C Demo Feasibility Review

**Reviewer role:** Wave 2 Reviewer, Trajectory 5
**Date:** 2026-05-07
**Scope:** Lane C ("one forcing demo") - can the chiodome bilateral demo
actually compose end-to-end with current code in 4 weeks, or does it
collapse into a vanity demo?
**Posture:** Vision Strategist's most ruthless internal critic. The demo
has to be REAL, or it falsifies nothing (and Lane B closes on its own
fixtures with the trj4 pattern repeating).

---

## Executive summary

Lane C is the most strategically attractive lane in release work: a genuine
forcing function that detects partial Lane B enforcement is the only
mechanism release work has against the trj4 closeout pattern. The Vision
Strategist's slice (`debate/06-vision-strategist-chiodome.md` §2) is
real, the spec corpus is real, the bilateral primitive
(`crates/chio-federation/src/bilateral.rs` lines 41-100) is real, the
KB MCP stack at `ops/knowledge-base/` is real.

But the Lane C plan as written has a load-bearing flaw that the W1
agent self-flagged but underrated: the existing `CoSigningBody` signing
surface is NOT the spec section 6 PAE-over-Statement signing surface,
and the proposed "Option A: ship two co-existing signatures" satisfies
neither §6 nor the §7 17-step verifier semantics in any strict reading.
That is the central BLOCKER. Several MAJOR findings cluster around it
(KB MCP transport mismatch, missing chiodos-ladder Rust primitives, CLI
extension scope inflation, BBS+ dependency tree absence, four-week
timeline assuming zero Lane B slip).

I count **2 BLOCKERs, 6 MAJORs, 4 MINORs, 3 OBSERVATIONs** below. The
demo is shippable in 4 weeks ONLY if (a) finding #1 is resolved by
narrowing the bounded claim instead of inflating Option A, (b)
finding #2 is resolved by narrowing the KB MCP wrapping pattern to
match what `chio mcp serve` actually does, and (c) Lane B's three
primitives are credibly green by week 0 of Lane C. If Lane B slips by
even one week, Lane C cannot close in release work without dropping C5
(selective disclosure) entirely.

**Verdict: CONDITIONAL PASS with mandatory revisions before W3.**

---

## Findings

### Finding 1 [BLOCKER]: DSSE/Ed25519 signing scheme - "Option A" does not satisfy spec §6

**The W1 agent's diagnosis is correct but the conclusion is wrong.**

`crates/chio-federation/src/bilateral.rs:41-77` defines `CoSigningBody`
with fields `{schema, receipt_canonical_json, org_a_kernel_id,
org_b_kernel_id}`. `DualSignedReceipt::verify` at `bilateral.rs:108-124`
verifies Ed25519 signatures over `canonical_bytes(CoSigningBody)`, i.e.
canonical JSON of the four-field body. **That message preimage is not
in any sense "the DSSE PAE over a canonical-JSON in-toto Statement".**

`spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6 lines 338-353 is
explicit: signing is Ed25519 over

```
"DSSEv1" SP LEN("application/vnd.in-toto+json") SP "application/vnd.in-toto+json"
         SP LEN(statement_bytes) SP statement_bytes
```

where `statement_bytes` is canonical-JSON of the in-toto v1 Statement
carrying the §5 predicate body (which itself contains
`tool_server_a/b`, `capability_lease_ref`, `policy_evaluation_summary`,
all 14 required fields). Section 6 also pins `keyid =
sha256_hex(passport_pubkey)` and binds the keyid to
`pred.tool_server_*.passport_key_fingerprint` (§7 step 8).

**The two preimages share zero bytes in common.** `CoSigningBody` does
not even contain `tool_name`, `tool_args_hash`, or any of the fourteen
predicate fields. Nothing the kernel signs today commits to the
predicate body the verifier checks against §5.

#### Why "Option A" fails spec §6 strictly

`bilateral-cosign-flow.md` lines 79-110 proposes "two co-existing
signatures":

> 1. The existing `CoSigningBody`-scoped signature, kept on the
> `DualSignedReceipt` for backward compatibility.
> 2. The new PAE-scoped signature, kept in the DSSE envelope.

This buys you:
- A DSSE envelope whose two signatures DO satisfy §6's PAE binding.
- A separate `DualSignedReceipt` whose signatures satisfy nothing in §6.

The §7 17-step verifier never inspects the `CoSigningBody` signatures.
It only checks the DSSE envelope (steps 1-12) plus auxiliary resolution
(steps 7, 14-16). So if Option A produces both, the spec verifier is
honored as long as you ONLY hand it the DSSE envelope. The
`DualSignedReceipt` becomes spec-irrelevant decoration.

**This is acceptable IF the bounded-claim language acknowledges it.**
It is NOT acceptable as currently written, because:

- `release-bar.md` line 71-79 claims:
  > A cross-kernel `refund.execute` invocation produces a
  > `DualSignedReceipt` AND a DSSE envelope conforming to spec §6.

  The "AND" implies the `DualSignedReceipt` is part of the spec
  conformance, not a deprecated artifact. It is not.

- `architecture.md` line 162-174 ("CoSigningBody (artifact #3)") frames
  the dual-signed receipt as artifact #3 in the spec story. There is
  no spec story for it: the spec corpus only knows DSSE envelopes and
  receipt bodies.

- `bilateral-cosign-flow.md` line 105 says "Option A; we do not change
  the signing surface of code that already works." But the existing
  `CoSigningBody` signing surface is not "code that already works"
  with respect to spec §6. It is code that exists, that pre-dates the
  spec, and that the spec does not validate.

#### Why "Option A" weakens the §7 verifier guarantee

§7 step 8 ties the DSSE `keyid` to
`pred.tool_server_*.passport_key_fingerprint`. The W1 plan's adapter
(`bilateral_dsse.rs::build_envelope_from_dual_signed`,
`bilateral-cosign-flow.md` lines 202-236) signs the PAE with the same
`Keypair` that signed `CoSigningBody`. **The two signatures do not
commit to the same predicate body**, so §7 step 13 (verdicts agree;
joint_disposition consistent) and step 14 (lease resolution) bind to
the predicate body that ONLY the DSSE signature covers.

If an attacker can obtain the `CoSigningBody` signatures alone (e.g.
via the existing federation transport logged before the DSSE adapter
ran), they cannot forge a §7-conformant envelope -- but they CAN
present a `DualSignedReceipt` that the existing `verify` at
`bilateral.rs:108` accepts, and the demo's "spec conformance" does not
catch that the receipt was signed under the legacy scheme. The release
notes claim spec conformance; if a third party sees only the
`DualSignedReceipt` they are looking at a non-spec artifact under a
spec-conformant banner.

#### Recommended fix

Two options, in order of preference:

1. **Promote DSSE-conformant signing to Lane B as a fourth primitive
   (B4).** The proposed lane title:

   > B4: DSSE-conformant bilateral signing replaces or wraps
   > `DualSignedReceipt::verify` so the production hot path emits
   > only spec-§6 envelopes for cross-org invocations.

   This is the right structural cut: B-lanes are about hot-path
   wiring per the synthesis; the existing `CoSigningBody` signing
   surface IS hot-path code (`crates/chio-federation/src/bilateral.rs`
   is in `chio-federation`, on the federation hot path). It is
   exactly the structural-framing-without-wiring anti-pattern
   (EVIDENCE-GATE.md §2.4) to claim §6 conformance via an adapter that
   bolts on alongside non-conformant code.

   Concrete B4 ticket shape (proposed):
   - B4.1: Replace `DualSignedReceipt::verify` with verification
     against PAE bytes of the §5-shaped predicate. The legacy
     `CoSigningBody` signing surface is kept only for tests;
     production emits PAE signatures.
   - B4.2: Negative conformance fixture in
     `crates/chio-conformance/tests/cross_org_dsse_negative.rs`
     where a `DualSignedReceipt` signed under the legacy scheme is
     rejected by the federation verifier (i.e. receiver-side
     enforcement).
   - B4.3: Spec MUST citation:
     `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6 lines 338-353
     (PAE) and §7 step 11-12 (signature verification).

   Effort: L (3-6 days). Lane B's budget is 6 weeks; B4 fits.

   Lane C then becomes a verifier-side and adapter-side wiring task,
   not a "ship two signatures" papering-over.

2. **Narrow the bounded-claim language so the existing
   `DualSignedReceipt` is explicitly NOT a spec §6 artifact.**

   Replace `release-bar.md` lines 67-79 with text approximately:

   > A cross-kernel `refund.execute` invocation produces:
   > - A legacy `DualSignedReceipt`
   >   (`crates/chio-federation/src/bilateral.rs:93`) carrying two
   >   Ed25519 signatures over the four-field `CoSigningBody`. This
   >   artifact predates `CHIODOS_BILATERAL_COSIGN_INVOCATION.md`
   >   v0.1 and is NOT a spec §6 conformant envelope.
   > - A new spec-§6 conformant DSSE envelope per
   >   `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6, signed by
   >   the same passport keypairs over different message bytes
   >   (DSSE PAE over the canonical-JSON in-toto Statement
   >   carrying the §5 predicate body).
   > - The two artifacts share a passport keypair but commit to
   >   different message preimages. The `DualSignedReceipt` is
   >   retained only for backward compatibility with existing
   >   federation tests; spec conformance is asserted only of the
   >   DSSE envelope.

   And add a corresponding row under "What this release DOES NOT
   CLAIM":

   > 13. **The legacy `DualSignedReceipt` is not a spec §6
   >     artifact.** Verifiers seeking §6 conformance MUST verify
   >     the DSSE envelope; they MUST NOT rely on the
   >     `DualSignedReceipt`'s built-in `verify` for §6 semantics.
   >     A future minor release will replace the legacy signing
   >     surface; this release does not.

#### Is 4 weeks realistic to land BOTH signatures + verifier hook + conformance fixture?

If we adopt option 1 (promote to B4), Lane B picks up ~L effort which
fits within Lane B's 6-week budget but only if Lane B started week 0.
Lane B's existing budget is allocated to three primitives; adding a
fourth without adding a week effectively borrows from the architectural
prerequisite (`ToolServer` -> `async_trait` migration) which is itself
estimated at ~1500-2000 LOC and has R1 risk attached
(`RISK-REGISTER.md` R1).

Realistic timeline if we promote to B4:
- B4 added to Lane B: +1 week to Lane B (now 7 weeks).
- Lane C's C2 simplifies: it consumes B4's PAE-conformant signing
  surface, builds the DSSE envelope shape on top, and writes the
  17-step verifier.
- C2 effort drops from L+L+M = ~10 days to L+M = ~7 days.

Net: release work ship date slips by ~1 week (from synthesis 8-week max to
~9 weeks). That is acceptable.

If we adopt option 2 (narrow the claim instead):
- 4 weeks is realistic.
- Bounded-claim discipline is preserved.
- The cost is that the "spec compliance" claim only attaches to the
  DSSE envelope, not to the dual-signed receipt. The release notes
  must say so explicitly.

**Recommended: option 1. Option 2 is acceptable as a fallback if Lane B
review concludes B4 is too much for the release work budget.**

---

### Finding 2 [BLOCKER]: KB MCP transport mismatch - `chio mcp serve` wraps stdio, KB MCP serves HTTP

**Direct contradiction between the plan and the runtime CLI shape.**

`kb-mcp-integration.md` line 18-30 says `chio mcp serve --policy` will
"wrap the local KB MCP gateway at `:8111/mcp/`". planning docs release work-C3.2
says:

> `chio mcp serve --policy
> examples/chiodome-bilateral/policies/refund-policy.yaml -- chio-kb-mcp`
> spawns the KB MCP gateway as the wrapped command and proxies
> successfully.

`crates/chio-cli/src/cli/types.rs:1032-1034` defines the `Serve`
subcommand:

```rust
/// The wrapped MCP server command and its arguments.
#[arg(trailing_var_arg = true, required = true)]
command: Vec<String>,
```

i.e. `chio mcp serve` wraps a **stdio MCP server subprocess**. It does
not (cannot) connect to an HTTP server URL. The KB MCP at
`:8111/mcp/` is HTTP (`ops/knowledge-base/README.md` lines 11, 36, 156)
not stdio.

The W1 plan implicitly assumes a binary named `chio-kb-mcp` that
exposes stdio. There is no such binary in the tree:

```
$ ls ops/knowledge-base/
DOGFOOD-REVIEW.md  Dockerfile.kb-mcp  README.md  chio_kb  config
docker-compose.yml  eval  postgres  pyproject.toml  seeds  tests  uv.lock
```

The KB MCP is a Docker-compose Python service exposing HTTP.

#### Three valid resolutions

A. **Use `mcp-remote` as the stdio shim.** The KB README already
   documents this pattern (`ops/knowledge-base/README.md` line 143):

   ```json
   "args": ["mcp-remote", "http://localhost:8111/mcp/"]
   ```

   `chio mcp serve --policy ... -- npx -y mcp-remote http://localhost:8111/mcp/`
   would compose. This adds an external Node.js dependency (npx,
   mcp-remote npm package) to the smoke. The example becomes
   "chio governs an mcp-remote shim that bridges to a local HTTP MCP."
   The bounded claim narrows: it is not "chio mcp serve over the KB
   MCP" directly, it is "chio mcp serve over an mcp-remote stdio
   bridge to the KB MCP HTTP endpoint."

B. **Use `chio mcp serve-http` (the HTTP edge variant).**
   `crates/chio-cli/src/cli/types.rs:1037-1175` defines `ServeHttp`,
   but it ALSO wraps a stdio `command: Vec<String>` (line 1174). So
   the same problem: it doesn't dial an HTTP upstream, it spawns a
   stdio subprocess and exposes an HTTP edge. This option is not
   actually different at the wrapping layer.

C. **Stand up a stdio adapter as part of the example.** Write
   `examples/chiodome-bilateral/src/bin/kb-stdio-bridge.rs` that
   exposes a stdio MCP server which proxies tools/list and tools/call
   to the HTTP KB MCP. Then `chio mcp serve --policy ... -- target/debug/kb-stdio-bridge`
   wraps that. This is the smallest cleanly-scoped fix, but the
   bridge is real new code on the demo's critical path.

**Recommended: option A (mcp-remote shim).** The README already
canonicalizes this pattern. The bounded-claim text in
`kb-mcp-integration.md` "Bounded-claim discipline" §2 should add:

> The smoke uses `mcp-remote` as a stdio<->HTTP bridge to the KB
> MCP. The composition does not validate the HTTP MCP transport
> layer end-to-end; it validates `chio mcp serve` plus the bridge.
> Direct HTTP MCP wrapping is not yet supported and is out of
> scope for v0.1.0-bounded-chiodome.

Without this fix, release work-C3.2 acceptance ("`tools/list` over the wrapped
edge returns at least the KB tools") is impossible to satisfy on the
day Lane C tags.

#### Patch

`kb-mcp-integration.md` lines 31-67: replace the topology diagram and
the "simplest configuration" paragraph with the mcp-remote-bridge
shape.

planning docs release work-C3.2: change the wrapped command to
`-- npx -y mcp-remote http://localhost:8111/mcp/` and add a
prerequisite bullet "Node.js / npx available in the smoke container".

---

### Finding 3 [MAJOR]: Cross-lane dependency reality - depends-on fields are present but Lane B ticket IDs are aliased, not anchored

planning docs lines 9-13 introduces aliases:

```
- LB-CAP = Lane B single-entry capability verifier
- LB-RV2 = Lane B receipt-v2 hot-path fail-closed
- LB-AB  = Lane B anchor-batch async-only when public witness required
- LB-AT  = Lane B `ToolServer` -> `async_trait` migration
```

These are descriptive labels, not ticket IDs from
`.planning/trajectory-5/lane-b-wiring/`. Sampled five Lane C tickets:

- **release work-C1.2** depends on `release work-C1.1, LB-AT`
- **release work-C1.4** depends on `LB-AT`
- **release work-C2.4** depends on `release work-C2.3, LB-CAP`
- **release work-C3.3** depends on `LB-RV2`
- **release work-C4.2** depends on `release work-C4.1, LB-AB`

I verified `.planning/trajectory-5/lane-b-wiring/` does exist, but the
plan does NOT reference its ticket IDs. The Lane B ticket IDs
(presumably release work-B1.x..B4.x) are not cited anywhere in Lane C. So when
Lane B reorganizes (e.g., merges two B1 tickets), Lane C has nothing to
update.

Two fixes:
- Cite Lane B ticket IDs verbatim in `depends-on` fields. Lane B's
  planning docs should be the source of truth.
- Add a cross-reference table at the top of Lane C planning docs that
  maps `LB-CAP` -> `release work-B1.x` (specific) for the version of Lane B
  current as of W1 close.

**Patch:** Add a section at top of planning docs after the alias list:

```
**Cross-reference (W1 snapshot):**

| Alias | Maps to (Lane B ticket) |
|---|---|
| LB-CAP | release work-B1.[N] |
| LB-RV2 | release work-B2.[N] |
| LB-AB  | release work-B3.[N] |
| LB-AT  | release work-B0.[N] |

(Updated when Lane B planning docs revises.)
```

#### Could Lane C work begin earlier on stubs?

Yes, partially. C1 (architecture, scenario script, kernel handshake) is
mostly composable today: `chio-federation::trust_establishment` is a
working primitive (`crates/chio-federation/src/trust_establishment.rs`,
verified `FEDERATION_HANDSHAKE_SCHEMA` exists at line 47). C1.1 and
C1.2 can land week 0 of Lane C with no Lane B dependency.

C2 (DSSE adapter) cannot start until B4 lands (Finding 1) or Lane B
explicitly waives DSSE conformance and Lane C ships under option 2's
narrowed bounded claim. The plan as written does not capture this; W1
should add a note: "C2.1 may scaffold against a stub B4; C2.4
acceptance gates on real B4."

C3 (KB MCP integration) cannot land its receipt-emission acceptance
until LB-RV2 (receipt v2 hot path) is wired; the receipt sink hooks
into the kernel hot path. Without LB-RV2, the kernel silently
downgrades and the example fixtures lie about v2 emission.

C4 (receipt explain) can begin early on synthetic fixtures, then
re-target real fixtures once C2 and C3 land.

C5 (zk feature) is independent (per the plan; this is correct).

C6 (release) is the last step.

The plan's W1-W4 sequencing is sane modulo Finding 1/2; the
depends-on aliases need to be anchored to real Lane B IDs.

---

### Finding 4 [MAJOR]: Bounded-claim discipline - `release-bar.md` overclaims spec §6 conformance via the `AND`

See Finding 1 for the underlying issue. The specific overclaim:

`release-bar.md` line 71-79:
> A cross-kernel `refund.execute` invocation produces a
> `DualSignedReceipt` (`crates/chio-federation/src/bilateral.rs:93`)
> AND a DSSE envelope conforming to
> `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` section 6 (under the
> chio-namespaced predicateType `chio.bilateral-cosign-invocation.v1`,
> per spec section 3 lines 97-103 mandate).

The "AND" structure implies both artifacts conform to §6. They don't.
Only the DSSE envelope does.

**The auditor view (selective disclosure) bounded language is honest:**
`selective-disclosure.md` lines 148-189 frames the BBS+ proof as a
"local proof, not a transparency-log artefact" and explicitly says it
is "not consensus-grade" (line 167). That is the right tone. The
bilateral cosign claim should match it.

**Compare to v3.18 RELEASE_AUDIT.md / PROJECT.md baseline:** the v3.18
language explicitly enumerates what is and is not consensus-grade,
distributed-linearizable, and transparency-log-anchored. The chiodome
release notes do the same in the "What this release DOES NOT CLAIM"
section (lines 105-171), but the affirmative claims block (lines
62-103) drops the qualifier. The asymmetry is the overclaim.

**Auditor view, separately:** `selective-disclosure.md` line 161-163
correctly describes the auditor view as a local proof. This is good.
It does NOT overclaim transparency-log or consensus properties. Honest.

**Patch:**

`release-bar.md` line 71: replace "AND a DSSE envelope" with "and a
distinct DSSE envelope (with different message preimages from the
DualSignedReceipt; only the DSSE envelope is the spec §6 conformant
artifact)".

Add to lines 105-171 a new "What this release DOES NOT CLAIM" item 13
per Finding 1's recommended text.

---

### Finding 5 [MAJOR]: KB MCP integration realism - missing chiodos-ladder Rust primitive, policy YAML format mismatch

#### Sub-finding 5a: chiodos-ladder is not a Rust primitive

`PLAN.md` C1.3 says:

> Build the minimal `chio.chiodos-ladder.v1` manifest for each side
> (domain `financial`, one action class `refund.execute` shaped like
> `settle.rollback` from `spec/CHIODOS_LADDER.md` section 5.2), and
> emit the `chio.chiodos-ladder-intersection.v1` artefact per
> `spec/CHIODOS_LADDER.md` section 6.1. **No new spec text.**

I searched for any Rust implementation of chiodos-ladder primitives:

```
$ grep -rln "chiodos" crates/
(no output)
$ grep -rln "ladder\|chiodos.ladder" crates/ | grep -v test | grep -v examples
(no output)
```

There is no Rust code that constructs, validates, signs, or
intersects a `chio.chiodos-ladder.v1` manifest. The spec exists at
`spec/CHIODOS_LADDER.md` (verified). The codebase has zero
implementation. The plan's "no new spec text" framing hides "all-new
implementation".

This is a non-trivial scope. Re-reading `spec/CHIODOS_LADDER.md`
section 2-6.1 (which I did not load fully in this review pass), the
ladder includes domain manifests, action class declarations,
intersection rules, signed pinning, etc. Even the minimal version is
~200-400 LOC of new Rust schema work plus signing/verification.

`PLAN.md` C1.3 effort is rated **M** (1-3 days). For a primitive that
does not exist in code today, even a minimal implementation closer to
**L** (3-6 days) seems realistic.

**Patch:**

- `PLAN.md` C1.3: re-rate effort to L. Add explicit acknowledgment
  that this is NEW Rust code (in `architecture.md` "Crates touched"
  table the row should change from "No - consumes existing schema"
  to "Yes - new minimal ladder primitive in `examples/chiodome-bilateral`
  or a new tiny crate `chio-chiodos-ladder-min`").

- planning docs release work-C1.3: split into release work-C1.3a (manifest types and
  schema) and release work-C1.3b (intersection emit + signing).

- Consider whether Lane C should depend on a Lane B item "B5: chiodos
  ladder minimal Rust primitive" or whether the demo accepts an
  example-local implementation. The latter is fine for v0.1
  bounded-chiodome, but bounded-claim text should say so:

  > The chiodos-ladder primitive used in the demo is an
  > example-local minimal implementation
  > (`examples/chiodome-bilateral/src/ladder.rs`). It is sufficient
  > for the demo's pinned-intersection use case but is NOT a
  > production-grade ladder primitive. A production
  > `chio-chiodos-ladder` crate is deferred to trj6.

#### Sub-finding 5b: Policy YAML format does not match HushSpec

`kb-mcp-integration.md` line 73-110 specifies a policy file:

```yaml
version: 1
policy_id: chiodome-bilateral-refund-v1
default_decision: deny
allow_rules:
  - id: refund-execute-bounded
    match:
      tool_name: refund.execute
    conditions:
      - kind: amount_minor_max
        value: 25000
      - kind: co_sign_required
      - kind: receipt_v2_required
      - kind: anchor_required
        anchor: chio-anchor
```

`examples/policies/canonical-hushspec.yaml` (the canonical Chio policy
format) uses HushSpec keys: `hushspec`, `name`, `description`,
`rules.{forbidden_paths,path_allowlist,secret_patterns,patch_integrity,shell_commands,tool_access}`.

I grepped for the proposed keys:

```
$ grep -rn "amount_minor_max\|allow_rules\|default_decision" crates/
crates/chio-policy/src/evaluate/tests.rs:665:    fn generated_glob_compile_errors_fail_closed_for_allow_rules() {
```

**The proposed policy schema is fictional.** None of the conditions
(`amount_minor_max`, `co_sign_required`, `receipt_v2_required`,
`anchor_required`) exist as HushSpec keys.

This is the structural-framing-without-wiring anti-pattern verbatim:
the example YAML reads convincing, but `chio check --policy` would
reject it (or worse, accept an empty policy and grant nothing,
making the demo's "deny over-cap refund" test pass for the wrong
reason).

**Patch:**

- planning docs release work-C3.1 acceptance ("`chio check --policy <yaml>`
  returns success") MUST be the first thing executed by the smoke;
  if it fails, the entire policy block needs to be re-cast in HushSpec
  shape.

- `kb-mcp-integration.md` MUST replace the policy YAML with a
  HushSpec-shaped one. The `tool_access` rule can express
  `refund.execute` allow; the `amount_minor_max` cap will need to
  be enforced at the kernel hot path or a separate guard, not in the
  policy YAML, because HushSpec does not have an amount cap primitive.

- This forces a real choice: either (a) the demo's amount cap is
  enforced by the chiodos-ladder intersection logic (where the
  `partition_fallback.blast_radius_cap.amount_minor` lives in
  `spec/CHIODOS_LADDER.md` §5.2), in which case the demo's deny path
  is "ladder-driven"; or (b) the cap is enforced by a custom guard
  registered for the demo, in which case the demo grows a small
  WASM guard. Option (a) is cleaner; option (b) requires guard
  authoring (Phases 384-385 territory).

This is a real, schedule-affecting decision the W1 plan does not make.
The reviewer's recommendation: option (a), because it forces the demo
to actually exercise the chiodos-ladder primitive that the bounded
claim promises (and Sub-finding 5a's effort estimate already accounts
for some of this work).

---

### Finding 6 [MAJOR]: Selective disclosure (zk feature) - BBS+ dependency tree absent, R6 mitigation soft

`selective-disclosure.md` line 14-19 names the dependencies:

```toml
[features]
default = []
zk = ["dep:bbs", "dep:bls12_381", "dep:anoncreds-rs"]
```

Spec §3 (`spec/CHIODOS_SELECTIVE_DISCLOSURE.md` lines 79-95) pins:
- `bbs-2023` cryptosuite (W3C CR Draft, not Recommendation)
- `draft-irtf-cfrg-bbs-signatures-10` over BLS12-381
- AnonCreds v2 `RangeStatement` for `cmp` proofs

I checked the workspace Cargo.toml/Cargo.lock for these crates:

```
$ grep -n "bbs\|anoncreds\|bls12_381" Cargo.toml Cargo.lock
(no output)
```

**No existing dependency tree.** Specifically:
- `bbs` is not a published crate name on crates.io with this exact
  ciphersuite. The closest are `bbs-plus`, `bbs_signatures`,
  `bbs-fixtures-generator` (multiple research-grade implementations).
  None ship `bbs-2023` cryptosuite production-quality.
- `bls12_381` is real (zkcrypto). Adoption: medium. MSRV impact: real.
- `anoncreds-rs` is the Hyperledger AnonCreds v2 crate. AnonCreds v2
  itself was specified late 2024-2025; the Rust binding's
  `RangeStatement` API is publicly available but the crate has its
  own large dependency tree (zk-snark-friendly curves, etc.).

#### R6 mitigation as currently written

`RISK-REGISTER.md` R6 says:
- `zk` feature off by default.
- CI runs the zk-feature build in a dedicated workflow job.
- "If the dep weight forces a MSRV bump, accept it as a documented
  constraint of release work OR drop C4 from the demo."

The R6 mitigation as written is soft; it does not commit to a
specific Cargo dep choice. The W1 Lane C agent has not validated
that the proposed dep set even compiles together against the current
chio MSRV.

#### What's the right thing to do?

Two patterns:

A. **Pick a research-grade BBS+ crate (e.g.,
   `docknetwork/crypto/bbs_plus` or `crypto-tools/bbs-rs`) and accept
   the cryptosuite gap.** Land a fixture-only implementation that
   matches `bbs-2023` ciphersuite parameters but is not a full W3C
   CR-conformant implementation. Bounded claim narrows further.
   Estimated effort: L+L (5-10 days). MSRV impact: usually 1.70+.

B. **Drop C5 from v0.1.0-bounded-chiodome.** Ship the demo as five
   artifacts (no auditor view) with a release-notes section
   explaining that the BBS+ feature gate is deferred. Pick it back up
   in v0.2.0-bounded-chiodome.

Given release work already bound the timeline and given the demo's primary
strategic value is the bilateral cosign envelope (not the BBS+
proof), option B is safer. The BBS+ feature is the only sub-lane
where Lane B does not provide forcing-function enforcement
(`selective-disclosure.md` lines 192-209), so dropping it does not
change the demo's "Lane B canary" behavior.

#### R6 mitigation patch

Update `RISK-REGISTER.md` R6 mitigation to add:

> - If the chosen BBS+ crate cannot ship `bbs-2023` cryptosuite
>   parameters within the release work window, drop C4 from the v0.1.0
>   tag and ship a v0.2.0-bounded-chiodome later. Bounded-claim
>   text already calls out the auditor view as optional; release
>   the demo without it rather than ship a research-grade
>   pseudo-conformant proof.
>
> - Wave 1 W1 deliverable: produce a
>   `crates/chio-zk-receipts/Cargo.toml` skeleton committing to a
>   specific BBS+ crate version. If the skeleton does not compile
>   against the current MSRV, escalate to Wave 2 immediately.

#### Auditor view bounded-claim language - already mostly correct

`selective-disclosure.md` lines 148-189 lists six explicit non-claims.
This is the right model. Two improvements:

- Item 6 (W3C CR-stage caveat) should be promoted to the headline
  paragraph of the bounded claim, not item 6 of seven.
- Add an item: "The auditor view fixture's BBS+ implementation may
  not be cryptographically conformant with the eventual `bbs-2023`
  W3C Recommendation; verifiers MUST treat the fixture as
  illustrative until a Recommendation-grade implementation lands."

---

### Finding 7 [MAJOR]: End-to-end composition - critical step gaps not currently captured as Lane C tickets

I walked through one full demo run mentally:

```
Agent
  -> kernel A
     [LB-AT: ToolServer async_trait]
     [LB-CAP: verify_capability_full single-entry]
     [LB-RV2: receipt v2 fail-closed]
  -> bilateral cosign (Ed25519 + DSSE)
     [Finding 1: existing CoSigningBody is not §6 conformant]
  -> kernel B
     [LB-AT, LB-CAP, LB-RV2 again]
  -> tool execution (refund.execute against KB MCP via stdio bridge)
     [Finding 2: stdio bridge not in plan]
  -> DualSignedReceipt
     [bilateral.rs:93 - exists]
  -> DSSE envelope (bilateral_dsse.rs - NEW)
     [Finding 1 fix required]
  -> anchor checkpoint
     [LB-AB: anchor-batch async-only when public witness required]
     [build_anchor_inclusion_proof needs SignedWeb3IdentityBinding +
      KernelCheckpoint - not trivial to construct in the demo]
  -> auditor view via selective disclosure
     [Finding 6: BBS+ deps]
```

**Step gaps not captured as Lane C tickets:**

**Step gap 7a:** `build_anchor_inclusion_proof`
(`crates/chio-anchor/src/lib.rs:178-200`) takes parameters
`(receipt, inclusion: &ReceiptInclusionProof, checkpoint:
&KernelCheckpoint, chain_anchor: Option<Web3ChainAnchorRecord>,
binding: SignedWeb3IdentityBinding)`. Constructing
`SignedWeb3IdentityBinding` and `KernelCheckpoint` in a demo example
is non-trivial. Existing examples either use mocked binding fixtures
or wire up the full anchor batch sub-system. The W1 plan
(`architecture.md` line 207-218) hand-waves: "The demo runs against
`LocalDevnetDeployment` (no live RPC)" but says nothing about how the
binding is produced.

This is captured in release work-C4.2 (anchor inclusion in explain output) at
effort M, but not as a separate "produce anchor inclusion proof in
the orchestrator" ticket. **Add release work-C2.8** (or equivalent):

```
### release work-C2.8 - Anchor inclusion proof emission

- Scope: Construct the kernel checkpoint, signed web3 identity
  binding, and call build_anchor_inclusion_proof to emit
  artifact #5. Use LocalDevnetDeployment for the chain anchor
  field.
- Files: examples/chiodome-bilateral/src/anchor.rs;
  examples/chiodome-bilateral/fixtures/anchor-inclusion.json.
- Effort: M
- Depends on: release work-C2.7, LB-AB
- Acceptance: anchor-inclusion.json validates under
  validate_anchor_inclusion_proof and verify_anchor_inclusion_proof.
```

**Step gap 7b:** `chio receipt explain` extension (release work-C4.1) is rated
M. Reading
`crates/chio-cli/src/cli/trust_commands.rs:2629-2715`,
`explain_receipt_value` only handles `ChioReceiptV2` and legacy
`ChioReceipt`. Adding handlers for `DualSignedReceipt`,
`BilateralCoSignInvocationStatement` (DSSE-wrapped), and
`AnchorInclusionProof` is at minimum:
- DSSE envelope decoding logic (Base64, in-toto Statement parse)
- New JSON output schema for bilateral chains
- Snapshot stability for CI
- Decision/explain semantics for the joint disposition

Effort more like L (3-5 days). Re-rate.

**Step gap 7c:** The W1 plan's `build_envelope_from_dual_signed`
adapter (`bilateral-cosign-flow.md` lines 202-235) takes
`org_a_keypair` and `org_b_keypair` as arguments. In the demo's
two-kernel topology, the org_a kernel owns one keypair and the org_b
kernel owns the other. The "in-process" `InProcessCoSigner`
(`bilateral.rs:216`) holds Org A's keypair directly. But Org B's
keypair has to be available to sign the PAE bytes too, which means
either Org B signs separately and Org A does not have access, OR the
demo cheats and runs both keypairs in one process.

The cleanest cut is: each kernel signs its own PAE, then they
exchange signatures (the existing `CoSigningRequest`/`Response` pattern
generalised). This means the DSSE envelope construction is not a
single function but a two-step exchange. The plan as written doesn't
capture this. **Add a clarifying paragraph to
`bilateral-cosign-flow.md`** about the bilateral signing protocol
(who signs what, when, in what order).

---

### Finding 8 [MAJOR]: 17-step verifier - steps 7 and 14 are not free, and Lane C plan is fuzzy on whether they integrate with Lane B

Spec §7 lists 17 verification steps. The W1 plan
(`bilateral-cosign-flow.md` lines 250-273) tabulates them and notes
which are "have it" vs "new":

- Step 7: subject digest equals canonical-JSON SHA-256 of resolved
  receipt body. Plan says "adapter; receipt resolution comes from a
  `ReceiptStore` trait passed in".

I verified `chio-kernel::receipt_store::ReceiptStore` exists
(`crates/chio-kernel/src/lib.rs:396-397` re-exports it). Good. But the
adapter has to call into `ReceiptStore::get(receipt_id)` from
`crates/chio-federation`, which means the adapter (in
`chio-federation`) needs a dependency on `chio-kernel` (or on a
trait re-exported in a third crate). If `chio-kernel` already depends
on `chio-federation`, this creates a cycle. Worth checking.

- Step 14: capability lease resolves; not expired. Plan says "uses
  Lane B's lease-expiry path". The lease-expiry path is in
  `chio-kernel-core::verify_capability_full`
  (`crates/chio-kernel/src/kernel/mod.rs:4047`). For the §7 verifier
  in `chio-federation`, this is again a cross-crate call. Either the
  verifier reaches into the kernel (unusual) or the kernel emits
  pre-validated lease state into the federation envelope (adds
  surface area).

**Both step 7 and step 14 raise architectural questions that the
plan does not resolve.** They are noted in
`bilateral-cosign-flow.md` "Required Lane B invariants" but only
in narrative form. The implementation cut (cycle? extract into a
third crate? emit pre-validated state?) is not chosen.

**Patch:** Extend `bilateral-cosign-flow.md` with an
"Architecture cut for cross-crate calls" section that picks one of:

A. New crate `chio-cosign-verifier` that depends on both
   `chio-kernel-core` and `chio-federation` and hosts the §7
   verifier. Lane C ships this crate.

B. The §7 verifier lives in `chio-federation` but takes trait objects
   for `ReceiptStore` and `CapabilityVerifier` so it doesn't pull in
   `chio-kernel` directly. Lane C ships the trait definitions; the
   demo wires `chio-kernel`'s implementations.

C. The §7 verifier lives in `chio-kernel`, which already depends on
   `chio-federation` (via re-exports). Lane C grows `chio-kernel`'s
   surface, which works against synthesis line 366-367 ("we do not
   refactor kernel/mod.rs beyond Lane B's `ToolServer` work").

Recommended: option B. Cleanest and matches the existing pattern
(`ReceiptStore` is already a trait).

---

### Finding 9 [MINOR]: `chio receipt explain` readiness - tickets exist but understated

The Productization paper called `chio receipt explain` "fundamental"
(`debate/05-productization-sdk-champion.md` Gap 2 line 50). The Lane C
tickets address it (release work-C4.1 .. C4.4) but the effort allocation is
S/M/M/S = ~6 days for what the productization paper considers a
debugging-story-grade feature.

Reading `trust_commands.rs:2629-2715`, the existing implementation:
- Handles single v1 or v2 receipt
- Returns a flat JSON
- Does not chain or graph

For bilateral chain explanation:
- Multiple receipt entities (kernel A receipt, kernel B receipt,
  DualSignedReceipt body, DSSE envelope, AnchorInclusionProof)
- Cross-references between them (subject digest, parent IDs, anchor
  inclusion)
- A useful "explain" walks the graph

This is closer to a small CLI tree-renderer. M effort is plausible but
tight. Add (or clarify in release work-C4.1):

- Acceptance: explain output for a bilateral chain shows EVERY
  intermediary receipt by short ID, with parent->child arrows.
- Acceptance: explain output's "policy verdict disagreement" is
  surfaced as a top-level diagnostic when present.

**Patch:** Bump release work-C4.1 effort from M to L. Re-allocate budget from
release work-C4.4 (S - the doc page) by combining with release work-C4.3 (snapshot
test) at the end.

---

### Finding 10 [MAJOR]: Forcing-function operationalization - no continuous CI hook in plan; catches regressions only at PR-time

The R4 mitigation in `RISK-REGISTER.md` lines 168-174 says:

> Lane C tickets are scheduled to START before Lane B closes, so demo
> smoke-tests run continuously against in-progress Lane B work.

planning docs release work-C6.2 adds `chio-demo-smoke` as a CI required check
on PRs:

> Add a CI workflow that runs `examples/chiodome-bilateral/smoke.sh`
> on every PR; gate on green.

PR-time gating catches regressions at merge time, but not earlier.
The synthesis frames Lane C as a "forcing function for Lanes A and B";
the forcing function is most effective when it runs continuously,
not just at PR boundaries.

**Patch:** Add release work-C6.6:

```
### release work-C6.6 - Continuous chiodome demo workflow

- Scope: Add `.github/workflows/chiodome-demo-continuous.yml` that
  runs the smoke nightly on `main` AND on every push to any Lane B
  branch (using path filters: `crates/chio-kernel/**`,
  `crates/chio-anchor/**`, `crates/chio-federation/**`,
  `crates/chio-conformance/**`).
- Files: .github/workflows/chiodome-demo-continuous.yml
- Effort: S
- Depends on: release work-C6.2
- Acceptance: workflow runs nightly; failures open an issue with
  the matching commit SHA; green for 7 consecutive nights before
  the v0.1.0-bounded-chiodome tag goes out.
```

This is the "forcing-function-as-CI-hook" the templates agent's R4
sketched. Without it, Lane B partial-enforcement bugs that the demo
would catch only get caught at the worst possible time (the day
before tag).

---

### Finding 11 [MINOR]: Demo fixture as evidence - reproducibility unclear

planning docs release work-C6.3 says:

> Two consecutive `./smoke.sh && build-tarball.sh` runs produce
> byte-identical tarballs (or document the fields that vary -
> timestamps).

This caveats reproducibility with "or document". The demo's receipts
contain Unix timestamps, UUIDs, and signing nonces. **Documenting the
varying fields is not enough**; the smoke needs to either:

A. Pin all sources of nondeterminism (`SOURCE_DATE_EPOCH`,
   deterministic UUID derivation, deterministic signing where
   possible) and produce byte-identical outputs.

B. Capture reproducibility via JSON-schema diff: two runs are
   "diff-stable" if they produce isomorphic JSON modulo the
   specific allow-list of varying fields.

Option B is cheaper. **Patch:** add a `tools/diff-stable.py` (or Rust
binary) under the example crate that compares two fixture
directories modulo allowed-varying fields, and call it from
`smoke.sh` step 5.

The release tag's tarball is then "diff-stable across runs", not
"byte-identical".

---

### Finding 12 [MINOR]: Mock receipts vs real receipts - need explicit assertion in CI

`README.md` lines 116-118 says:

> Mock receipts. Receipts MUST be produced by the production kernel
> through its real call sites; fixtures are captured outputs, not
> hand-written templates.

This is the right rule but it has no automated enforcement. A
contributor who writes `#[serde_json]!({"receipt_id": "rcpt-fake",
...})` in a fixture file would pass CI silently.

**Patch:** Add to release work-C6.2 acceptance: the `chio-demo-smoke` CI
workflow MUST run a check that every fixture under
`examples/chiodome-bilateral/fixtures/` was produced by the smoke run
in the same workflow run (e.g. via mtime check, or by deleting all
fixtures before the smoke and asserting the smoke regenerated them).

---

### Finding 13 [MINOR]: Predicate URI - in-toto canonical is reserved; chio fallback is mandated

`release-bar.md` lines 145-153 correctly notes the URI mandate:

> Predicate type is the chio-namespaced fallback. The envelope's
> `predicateType` is `chio.bilateral-cosign-invocation.v1`, not the
> proposed `https://in-toto.io/attestation/bilateral-cosign-invocation/v1`.

Spec §3 lines 79-85 confirms this. Good.

`bilateral-cosign-flow.md` lines 116-126 implementation also uses
`BILATERAL_COSIGN_INVOCATION_SCHEMA = "chio.bilateral-cosign-invocation.v1"`.
Good.

This is correct as written. Note for the W1 author: when the in-toto
WG accepts the URI, the chio fallback MUST still be emitted per spec
§3 ("Verifiers MUST treat the two as semantically equivalent within a
single deployment but MUST NOT silently rewrite one into the other").
The W1 plan handles this correctly. No patch.

---

### Finding 14 [OBSERVATION]: Ticket count is appropriate for the lane scope

W1 plan ships 30 tickets (planning docs lines 422-431) where the
templates target was "14-22 tickets". The W1 author justifies the
overshoot:

> The list is intentionally fine-grained because each ticket maps
> to one composable primitive and one fixture; collapsing tickets
> together would lose the auditability the synthesis demands.
> Reviewers may merge adjacent S-tickets at execution time.

That justification is sound. EVIDENCE-GATE.md per-ticket discipline
benefits from finer granularity. No patch.

---

### Finding 15 [OBSERVATION]: Out-of-scope language is honest

`README.md` lines 102-118 enumerates seven out-of-scope items
(no new spec drafts, no Web3 live, no three-vendor, no pheromone, no
ladder amendment, no mock receipts) that match the synthesis verbatim
and the Vision Strategist concessions. This is the right tone and the
right list. No patch.

---

### Finding 16 [OBSERVATION]: Forcing-function spec language could be tightened to make Lane B/C bidirectional

`README.md` lines 130-180 is excellent on the Lane C -> Lane B
forcing direction. There is a corresponding direction that is
weaker: Lane B's three negative conformance fixtures
(`crates/chio-conformance/tests/`) need to import Lane C's fixture
paths (Lane C ship-bar item 6 says so).

This is captured in the ship bar but not in any specific Lane B
ticket I could verify. Recommend Lane B's W2 review confirms the
fixtures actually import the demo paths. (Out of scope for this
review; flagging for the Lane B reviewer.)

---

## Summary Table

| # | Finding | Severity |
|---|---|---|
| 1 | DSSE/Ed25519 signing scheme - Option A insufficient | BLOCKER |
| 2 | KB MCP transport mismatch (stdio vs HTTP) | BLOCKER |
| 3 | Cross-lane depends-on aliases not anchored to Lane B IDs | MAJOR |
| 4 | release-bar.md `AND` overclaims spec §6 conformance | MAJOR |
| 5 | chiodos-ladder Rust primitive missing; policy YAML format mismatch | MAJOR |
| 6 | BBS+ feature dep tree absent; R6 mitigation soft | MAJOR |
| 7 | End-to-end composition gaps not captured as tickets | MAJOR |
| 8 | 17-step verifier cross-crate calls (steps 7, 14) unresolved | MAJOR |
| 9 | `chio receipt explain` extension underestimated | MINOR |
| 10 | Forcing-function CI hook missing | MAJOR |
| 11 | Demo fixture reproducibility hand-waved | MINOR |
| 12 | Mock-receipt detection has no automated check | MINOR |
| 13 | Predicate URI handling - already correct | MINOR (no patch) |
| 14 | Ticket count over target - justified | OBSERVATION |
| 15 | Out-of-scope list is honest | OBSERVATION |
| 16 | Lane B->C fixture imports unverified | OBSERVATION |

**Counts: 2 BLOCKER, 6 MAJOR, 4 MINOR, 4 OBSERVATION (one MINOR was
no-patch-needed).**

---

## Open Questions

1. **Lane B's Wave 1 review will determine whether B4 (DSSE signing)
   fits in release work.** If it doesn't, Lane C must adopt Finding 1
   option 2 (narrow the bounded claim). The Lane C plan needs an
   explicit branch on this.

2. **Does `chio-kernel` already depend on `chio-federation`?** This
   determines whether the §7 verifier in `chio-federation` can call
   into kernel-resident receipt resolution without a cycle. Wave 1
   Lane C work should answer this in the first day.

3. **Will the smoke run in CI without a Docker daemon (for the KB
   MCP stack)?** If not, the CI workflow needs Docker-in-Docker or
   a separate kb-up service container. `chio-demo-smoke` viability
   in GitHub Actions runners is not validated.

4. **Is the `mcp-remote` shim acceptable for v0.1.0-bounded-chiodome,
   or does the bounded claim require direct HTTP wrapping?** If the
   latter, finding 2 forces a `chio mcp serve-http-upstream`
   feature, which is meaningful new code.

5. **Does Lane B explicitly accept that B4 (DSSE signing) is its
   responsibility, or does Lane B insist this is a Lane C concern?**
   The reviewer for Lane B should be looped in.

6. **What is the W3C BBS+ Recommendation timeline?** If
   Recommendation lands during release work, the bounded-claim language
   updates; if it doesn't, item 6 of `selective-disclosure.md`
   stays put.

---

## Verdict

**CONDITIONAL PASS with mandatory revisions before W3 of Lane C.**

The Lane C plan is structurally sound and the forcing-function
purpose is correctly identified. But three issues prevent the demo
from being REAL as currently scoped:

1. The DSSE signing scheme (Finding 1) must either be promoted to a
   Lane B primitive (preferred) or the bounded claim must explicitly
   disclaim §6 conformance for the legacy `DualSignedReceipt`. The
   "Option A: ship two co-existing signatures" framing as written is
   structural-framing-without-wiring (EVIDENCE-GATE.md §2.4) and
   would let release work ship a "spec-conformant" tag whose primary
   artifact (`DualSignedReceipt`) is not spec-conformant.

2. The KB MCP transport mismatch (Finding 2) makes the
   user-surface story incoherent. `chio mcp serve` does not wrap
   HTTP MCP servers; the plan implicitly requires that, OR a stdio
   bridge that the plan doesn't specify.

3. The chiodos-ladder primitive (Finding 5) is described as
   "consume existing" but does not exist in code. The demo cannot
   compose what isn't there.

If the W1 author addresses Findings 1-2 by W3 of Lane C with the
recommended patches (option 1 promotion to B4, mcp-remote bridge,
HushSpec-shaped policy YAML, explicit chiodos-ladder example-local
implementation), the demo is shippable in 4 weeks (with possible
1-week release work ship-date slip from B4 promotion).

If Finding 6 (BBS+ deps) cannot be resolved by W2 of Lane C, drop
C5 entirely and ship five-artifact v0.1.0-bounded-chiodome instead
of six. This is consistent with R6 escalation criteria.

If Lane B slips by more than 1 week, Lane C cannot close in release work
window without dropping at least one sub-lane. Recommend the
fallback be C5 (auditor view) since it is the only sub-lane where
Lane B does not provide forcing-function enforcement.

The auditor view bounded-claim language
(`selective-disclosure.md` lines 148-189) is the right model for
all bounded claims in this lane. Apply the same discipline to the
bilateral cosign claim in `release-bar.md`.

The forcing-function CI hook (Finding 10) is non-negotiable. If
Lane B regresses without continuous chiodome smoke catching it,
release work closes with the trj4 pattern repeating. Add the workflow
unconditionally.

**Re-review at end of W1.** After W1 author addresses the BLOCKERs
in writing, re-evaluate whether the trajectory is on a 4-week +
1-week-buffer window. If the BLOCKERs are not resolved by mid-W1,
escalate to the synthesis owner: Lane C may need to be re-scoped to
"prove the bilateral primitives compose" without the spec-§6 DSSE
claim, which is a significantly weaker ship bar but a deliverable
one.
