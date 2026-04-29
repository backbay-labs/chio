# Cold-reader notes

Per-milestone findings from a senior-engineer cold read on 2026-04-25.
Severity tags: **BLOCKER** (would refuse to start work without resolution),
**NEEDS-CLARIFY** (would ask one question and proceed), **NICE-TO-HAVE**
(would proceed and flag during review).

## M01: Spec/Codegen/Conformance

1. **NEEDS-CLARIFY** P3.T6 says "Run all 17 Python framework adapter test
   suites against the regenerated `chio-sdk-python`". The 17 adapters are
   named in the "Why now" section, but there is no enumerated CI matrix
   confirming each one runs. A senior engineer would want to see a workspace
   `uv run --all-packages pytest` invocation or a per-adapter listing in the
   workflow YAML before declaring P3.T6 done.
2. **NEEDS-CLARIFY** P5.T5 introduces `json-schema-diff` as the breaking-
   change bot but does not name the crate or pin a version. Likely
   `json-schema-diff` exists on crates.io, but a cold reader would not know
   which (there are several with similar names).
3. **NICE-TO-HAVE** The "Migration story" in Phase 1 lists `models_legacy.py`
   as a one-cycle preservation, but M01+1 deletion is implied rather than
   ticketed. Add a follow-up TODO entry pointing at the deletion PR.
4. **NICE-TO-HAVE** The exit test for Phase 4 includes `cargo install
   chio-conformance --version 0.1.0`, which depends on a successful publish.
   The exit test would be more cleanly worded as "after the first published
   `0.1.0`" so reviewers do not block on the exit test before the crate
   actually ships.
5. **NICE-TO-HAVE** P1.T7's deprecation header format mentions "swap `//`
   for `#` in Python" but `models.py` is not the only Python file that gets
   the header (the framework adapters do not get headers, but a future M01+1
   may); a single source-of-truth `scripts/header-stamp.txt` plus a
   `--language python|rust|ts|go` flag would prevent header-format drift
   later.

## M02: Fuzzing post-PR-13

1. **BLOCKER** Phase 0 says "P0.T1 - confirm PR #13 status `MERGED` via `gh
   pr view 13`; if not, no Phase 1 work begins." This is a hard sequencing
   constraint, but `02-fuzzing-post-pr13.md` does not name an owner or an
   ETA for PR #13 review. A senior engineer would want to know: who is
   currently shepherding PR #13, and what is blocking its merge?
2. **NEEDS-CLARIFY** The `dudect` harness exit criterion says "two
   consecutive sub-threshold runs". Does that mean two consecutive
   nightlies, or two runs back-to-back on the same nightly? The doc reads
   ambiguously between Phase 3's "two consecutive runs" rule and the
   3-month dashboard target "30 days < 4.5".
3. **NEEDS-CLARIFY** The crash-triage automation (P4.T1) opens GitHub
   issues with attached reproducer files <= 4 KiB or upload as gist. A
   senior engineer would want to know: what authentication does the gist
   upload use? GitHub Actions tokens cannot create gists by default.
4. **NICE-TO-HAVE** The mutation-testing per-crate skip lists are referenced
   but the exact skip patterns are not committed inline. Phase 3 task 1
   lands them, but a reviewer would benefit from at least one example skip
   pattern in this doc so the per-crate lists are consistent in shape.
5. **NICE-TO-HAVE** P2.T6 (structure-aware mutator) mentions `>= 2x
   distinct-coverage-edges per CPU-second` as expected effect. The 2x is
   not a hard exit criterion; if the mutator only achieves 1.3x, does the
   task still close green? Recommend either making 2x a soft target or
   firming it into a measurable gate.

## M03: Capability algebra properties

1. **BLOCKER** Phase 3 task 7 lands `formal/OWNERS.md` with `TBD-primary`
   and `TBD-backup` slots. The Wave 1 decision (locked) defers the slot
   names to the user. M03 cannot fully close until those slots are filled.
   A senior engineer would want a named pair before Phase 3 Apalache work
   stalls on the lack of an on-call.
2. **NEEDS-CLARIFY** The exit criterion "At least one entry in
   `formal/assumptions.toml` is narrowed: `ASSUME-SQLITE-ATOMICITY`" does
   not state the exact text of the new ASSUME nor the discharge mechanism
   inline. The doc says it is recorded as a `RETIRED-` block in
   `formal/assumptions.toml` and as a row in `formal/proof-manifest.toml`,
   but a starter cannot draft the new ASSUME entry without reading the
   current text. Recommend committing the verbatim before/after diff in
   the doc.
3. **NEEDS-CLARIFY** The CI runtime budget says "PR job total wall-clock
   target: 25 min on the single CI runner image (locked in Wave 1
   decision 6)." Decision 6 in the README locks Apalache `0.50.x` and
   names "single CI runner image" but does not say which image (`ubuntu-
   latest`? a custom image with Apalache pre-baked?). Recommend recording
   the runner image SHA explicitly here.
4. **NICE-TO-HAVE** The 18-invariant list is named in full but the
   Generator strategies they depend on are merely "reused from
   `formal/diff-tests/src/generators.rs`". A cold reader would prefer a
   one-line note per invariant naming the strategy used (e.g.
   `arb_normalized_scope`, `arb_grant_chain`).
5. **NICE-TO-HAVE** The Apalache module sketch is verbatim and compiles in
   `0.50.x`, but the cfg file `MCRevocationPropagation.cfg` referenced in
   the phase task list does not have its constants set inline. Recommend
   adding `CONSTANTS PROCS = 1..4 CAPS = 1..8 DEPTH_MAX = 4` as a sample
   cfg.

## M04: Deterministic replay

1. **NEEDS-CLARIFY** The 50-fixture list under `tests/replay/fixtures/`
   names ten families, but the `chio-replay-gate` workflow does not say
   which family is the smallest reviewable smoke (probably `allow_simple`
   01-02). Recommend naming the smoke set explicitly so a starter can
   stand the gate up against two fixtures and grow from there.
2. **NEEDS-CLARIFY** The `--bless` gate logic includes "isatty(stderr)"
   as a check. CI runners typically have isatty false; this works as a
   programmatic guard, but a cold reader might wonder about a developer
   running the bless from inside a `tmux` pane piped through `tee` (also
   not a TTY). The correct rule is `isatty(stderr) AND CI=false`, which
   the doc does say, but the redundancy reads as a contradiction.
3. **NEEDS-CLARIFY** The cross-version policy file lists `compat =
   "broken"` as a state but the `release-tagged.yml` automation that
   appends new tags only writes `compat = "supported"`. How does a row
   transition from `supported` to `best_effort` to `broken`? Recommend
   adding a "Lifecycle of a compat row" subsection.
4. **NICE-TO-HAVE** The differential test in Phase 6 covers Rust vs TS.
   Python and JVM are explicitly out of scope. A cold reader might wonder
   why TS gets the priority; the doc says "TypeScript follows once the
   gate is green" but does not justify the choice. Add one sentence.

## M05: Async kernel real

1. **BLOCKER** The freeze-window enforcement triple (branch protection +
   CODEOWNERS + Slack template) demanded an `@chio/m05-freeze` GitHub
   team in earlier drafts. The current trajectory uses a single-owner
   model: the freeze is enforced via branch ruleset + path restriction +
   `m05-freeze-guard` required check (PRs touching frozen paths must
   begin with `[M05]`); the human-side reviewer gate routes to
   `@bb-connor`. No GitHub team is required.
2. **NEEDS-CLARIFY** P0.T2 says "`cargo tree -p chio-kernel -d` must show
   single tokio". A senior engineer would want to know: is this the
   exit-test command, or merely a status check? Recommend adding it to
   the Phase 0 exit test verbatim.
3. **NEEDS-CLARIFY** The bench gate uses `criterion-compare-action (or
   equivalent)`. There are several actions with similar names; pin
   exactly one in this doc.
4. **NICE-TO-HAVE** The 12 bench paths each have an SLO p99 listed in a
   table. The reference 4-core Linux runner is named, but the runner
   image (e.g. `ubuntu-22.04`) is not. Pin it explicitly so cold-reader
   benches are reproducible.
5. **NICE-TO-HAVE** The deprecation timeline says "Release N+2: legacy-
   sync deleted." Without a calendar, this is loose. Recommend pegging it
   to a release-tag event (e.g. "the second tag after the M05 merge").

## M06: WASM guard platform

1. **NEEDS-CLARIFY** The Phase 1 verbatim WIT file pins
   `chio:guard@0.2.0`, but the `bindgen!` macro calls
   `world = "chio:guard/guard@0.2.0"`. The slash form (`guard/guard`)
   is the world-import path, not the package version. A cold reader
   familiar with `wit-bindgen` would want a one-line comment confirming
   that the macro syntax is correct against `wasmtime` 25.x or 26.x
   (the version matters; the syntax shifted in 25.x).
2. **NEEDS-CLARIFY** The OCI artifact schema names media types like
   `application/vnd.chio.guard.v2+wasm`. Are these media types registered
   with IANA, or are they private? OCI 1.1 referrers fallback semantics
   depend on the registry advertising support; recommend documenting the
   private/registered status.
3. **NEEDS-CLARIFY** The Phase 3 canary harness requires "byte-identical
   verdict bytes for all 32 fixtures" before swap. What about the case
   where a guard's intended behavior is to deny a fixture that the prior
   epoch allowed (a tightening release)? The doc reads as if any
   verdict change blocks the swap, which would forbid intentional
   tightening. Recommend a follow-up note on the rebless flow.
4. **NICE-TO-HAVE** The Grafana dashboard JSON path
   (`docs/guards/dashboards/guard-platform.json`) is committed but the
   datasource UID is implementation-dependent. Recommend a comment in the
   JSON or a sidecar README explaining how to wire it to a Prom datasource
   on first import.
5. **NICE-TO-HAVE** The "rollback storyboard" PagerDuty service is
   `chio-runtime`. If the project does not yet have a PagerDuty contract,
   this is aspirational. Either label it as such or provide an alternative
   (issue-only, email).

## M07: Provider-native adapters

1. **NEEDS-CLARIFY** The Bedrock adapter ships with `config/iam_principals
   .toml` "signed with the same Sigstore tooling M09 lands". M09 is
   independent of M07 in the dependency graph. If M07 starts before M09
   completes Phase 3, what does the signing path look like? Recommend a
   bridge note saying the file is loaded unsigned in the dev path until
   M09's `chio-attest-verify` is available, gated on a feature flag.
2. **NEEDS-CLARIFY** The conformance harness needs 36 fixture sessions
   total. Are these recorded against real provider keys, or are they
   reconstructed from public docs? The doc says `provider-conformance-
   live.yml` runs nightly against real keys. A starter would want to know
   how the fixture is captured the FIRST time (manual recording, key
   rotation policy).
3. **NEEDS-CLARIFY** Verdict latency budgets: OpenAI/Anthropic at 250ms
   p99, Bedrock at 500ms p99 due to "cold AWS SDK init plus IMDS / STS".
   Once warm, do all three converge to 250ms? The doc says steady-state
   should match but the budget stays at 500ms. A starter would want
   either a single budget for warm or two budgets per adapter (cold /
   warm).
4. **NICE-TO-HAVE** The Anthropic computer-use beta is gated behind a
   cargo feature. Are downstream consumers expected to opt in via cargo
   feature, or via runtime config? A cargo feature implies a recompile;
   for a SaaS deployment that swaps providers without rebuild, runtime
   config is the right granularity.
5. **NICE-TO-HAVE** The cross-provider demo at `examples/cross-provider-
   policy/` is described as the "audit-evidence artifact". Recommend a
   one-line success criterion (e.g. "the three printed receipts differ
   only in `provenance.{provider, request_id, principal}` per byte
   comparison via `jd`").

## M08: Browser/Edge SDK

1. **NEEDS-CLARIFY** Phase 3 (delegated signing) is hard-deferred behind a
   trust-boundary review. The review template is committed, but the
   security owner of record is not named. A starter would want to know
   who signs off (could be `formal-verification` per M03, or a separate
   security role).
2. **NEEDS-CLARIFY** The `@vercel/edge` runtime simulator is named as
   the conformance runner. Is this a published npm package, or a local
   shim? Recommend a one-line install command in the workflow.
3. **NEEDS-CLARIFY** The size budget gate says "300 KB gzipped browser,
   < 350 KB gzipped Workers SDK contribution". Does "SDK contribution"
   mean the wasm + JS glue, or the wasm alone? The phrasing is ambiguous.
4. **NICE-TO-HAVE** The Phase 4 jco spike has four success criteria
   including "Size of the jco-emitted bundle is within +/- 15% of the
   wasm-pack `--target web` bundle". A senior engineer would want to
   know: which side wins on the +15% case (smaller is better, larger is
   tolerated)? Recommend wording it as `<= +15%`.
5. **NICE-TO-HAVE** The demo banner snapshot test (NEW sub-task) uses
   Playwright. The conformance matrix already runs Playwright for
   `browser`. Recommend reusing the Playwright runner from the
   conformance job rather than spinning up a second one.

## M09: Supply-chain attestation

1. **NEEDS-CLARIFY** The `cargo-vet` import set includes
   `https://raw.githubusercontent.com/google/supply-chain/main/audits.toml`.
   That URL exists but is owned by Google's "supply-chain" repo (not
   `google/chromium-review-supply-chain` or any of the other
   Google-affiliated feeds). A cold reader would want explicit confirmation
   that this is the correct upstream and that Google maintains it.
2. **NEEDS-CLARIFY** The reproducible-build comparator pins Builder B at
   `ubuntu-22.04` but Builder A at `ubuntu-latest`. As of 2026 `ubuntu-
   latest` is `ubuntu-24.04`. Do we want determinism across major OS
   versions, or only across runner instances on the same OS? Recommend
   pinning both builders to the same OS, with a separate "future-OS
   smoke" lane.
3. **NEEDS-CLARIFY** The `chio-attest-verify` trait surface uses
   `non_exhaustive` on `AttestError`. M02's fuzz harness catches panics
   only; how does it surface "future variant added" cases? Recommend a
   fuzz target assertion that the result is `Ok` or `Err`, not panic.
4. **NICE-TO-HAVE** The verification recipe step 4 uses `syft attest
   verify`. Step 3 uses `slsa-verifier verify-artifact`. These are two
   different binaries the consumer must install. Recommend consolidating
   under the new `chio attest verify` subcommand (NEW sub-task) so the
   consumer recipe is `cargo install chio-cli && chio attest verify ...`.
5. **NICE-TO-HAVE** The cargo-vet import section in the README
   (Wave 1 decision 1 baseline corpus) says "five upstream feeds" but the
   M09 doc lists four (Mozilla, Bytecode Alliance, Google, ZcashFoundation).
   Reconcile to four, or name the fifth.

## M10: Tee/Replay harness

1. **BLOCKER** Phase 1 task 5 says "Wire mandatory M06 redactor pass via
   the `chio:guards/redact@0.1.0` host call". M06 reserves the namespace
   only; M10 ships the concrete world. If M10 starts before M06 closes,
   the namespace is unreserved and the host call cannot be wired. A
   starter would want to confirm: does Phase 1 of M10 block on M06 Phase
   1 task 1 (`wit/chio-guards-redact/world.wit` placeholder commit)?
2. **NEEDS-CLARIFY** The frame schema `ts` field is "RFC3339 UTC timestamp
   with millisecond precision". The OTel `gen_ai.usage.input_tokens`
   attribute is an int. A senior engineer would want to know: are span
   attributes propagated from the frame, or recomputed downstream? If
   the latter, we need a column in the OTel attribute lock saying
   "derived from frame field X".
3. **NEEDS-CLARIFY** The bless graduation runbook says "Weekly review
   SLA. The integrations track reviews capture batches every Tuesday at
   14:00 UTC." This is a process commitment without an owner. Who
   facilitates the weekly review meeting?
4. **NEEDS-CLARIFY** The chio-tee-corpus GitHub release artifacts are
   pulled via `scripts/pull_tee_corpus.py`. The Python script is named
   but its dependencies (`requests`, `tomli`?) and Python version are
   not. Recommend pinning Python `>= 3.11` and using stdlib only.
5. **NICE-TO-HAVE** The OTel attribute lock says `gen_ai.tool.call.id`
   is "unbounded" and "NEVER metric label". The cardinality test
   (`crates/chio-kernel/tests/otel_cardinality.rs`) presumably enforces
   this. Recommend a one-line note saying the test fails if any
   attribute in the deny-list appears as a metric label, with the deny-
   list verbatim.
6. **NICE-TO-HAVE** The frame `tenant_sig` field uses base64-standard
   (the regex allows `+/=`). The receipt pipeline uses base64-url
   elsewhere. Confirming both is fine, but a cold reader would want a
   one-line note explaining why (probably: ed25519 sig is opaque bytes,
   choice is arbitrary, base64-standard wins on JSON tooling).

## Cross-cutting items the reviewer should escalate

These are not single-milestone findings; they affect the trajectory as a
whole and are flagged for user input.

1. **BLOCKER** Wave 1 decision 7 leaves `formal/OWNERS.md` slot
   assignment to the user. Until the user fills the two GitHub handles,
   M03 cannot fully close, and any subsequent Apalache regression has no
   on-call to route through. Recommended action: user lists two handles
   (one primary, one backup) before M03 Phase 3 starts.
2. **NEEDS-CLARIFY** The trajectory does not name a release-engineering
   owner who flips the `releases.toml` `cycle_end_tag` for M02 (decision
   12). Without that automation, the mutation-testing gate stays
   advisory forever. Recommended: name the owner when M02 Phase 3 lands.
3. **NEEDS-CLARIFY** Several milestones (M02 OSS-Fuzz, M07 live API,
   M09 PyPI/npm publish) depend on accounts and credentials the project
   does not yet have. A pre-flight checklist of accounts (GitHub Org
   admin, OSS-Fuzz contact, AWS sandbox account, OpenAI / Anthropic /
   Bedrock API keys, npm org) would prevent mid-execution stalls.
4. **NICE-TO-HAVE** All ten milestones use cargo workspace conventions
   (`crates/*`). M01 P3.T2 ships a Python package; M08 P1 ships TS
   packages. The cross-language toolchain assumes `bun install`, `uv sync`,
   and Cargo all work in a single `make` invocation. Recommend a top-
   level `make all` target as part of M01 Phase 4.
